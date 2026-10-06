using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Testing;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using System.Security.Claims;
using WinOpenID.Tests.UserDirectory;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace WinOpenID.Tests;

// Authorization requests after the validation: Windows authentication, directory search and claims of the authorization code
public class WinOpenIDServerHandlerAuthorizationTests
{
    private const string ClientId = "client";
    private const string RedirectUri = "https://client.example/callback";
    private const string UserName = @"EXAMPLE\maria";

    private readonly FakeLoggerProvider loggerProvider = new();
    private readonly FakeDirectory userDirectory = new();
    private readonly FakeAuthenticationService authenticationService = new();

    private WinOpenIDServerHandler CreateHandler(string domain = null)
    {
        var serverOptions = new WinOpenIDOptions
        {
            Domain = domain,
            Clients = new()
            {
                [ClientId] = new WinOpenIDClientOptions { RedirectUris = [RedirectUri], Scopes = [Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.Phone, Scopes.Roles], Audiences = ["api", "other-api"] }
            }
        };
        return new WinOpenIDServerHandler(Options.Create(serverOptions), userDirectory, new LoggerFactory([loggerProvider]));
    }

    // Principal created by the Negotiate authentication (a WindowsPrincipal on Windows)
    private static ClaimsPrincipal CreateWindowsUser(string sid, string name = UserName)
    {
        List<Claim> claims = [new Claim(ClaimTypes.Name, name)];
        if (sid != null)
        {
            claims.Add(new Claim(ClaimTypes.PrimarySid, sid));
        }
        return new ClaimsPrincipal(new ClaimsIdentity(claims, NegotiateDefaults.AuthenticationScheme));
    }

    private async Task<HandleAuthorizationRequestContext> HandleAsync(string scope, string clientId = ClientId, string domain = null, bool withHttpRequest = true)
    {
        var request = new OpenIddictRequest { ClientId = clientId, RedirectUri = RedirectUri, Scope = scope, ResponseType = ResponseTypes.Code };
        var transaction = new OpenIddictServerTransaction { Request = request, Options = new OpenIddictServerOptions(), Logger = NullLogger.Instance };

        if (withHttpRequest)
        {
            var httpContext = new DefaultHttpContext
            {
                RequestServices = new ServiceCollection().AddSingleton<IAuthenticationService>(authenticationService).BuildServiceProvider()
            };
            transaction.Properties[typeof(HttpRequest).FullName] = new WeakReference<HttpRequest>(httpContext.Request);
        }

        var context = new HandleAuthorizationRequestContext(transaction);
        await ((IOpenIddictServerHandler<HandleAuthorizationRequestContext>)CreateHandler(domain)).HandleAsync(context);
        return context;
    }

    private static Claim AssertSingleClaim(ClaimsPrincipal principal, string type, string value, params string[] destinations)
    {
        Claim claim = Assert.Single(principal.Claims, claim => claim.Type == type);
        Assert.Equal(value, claim.Value);
        Assert.Equal(destinations.Order(), claim.GetDestinations().Order());
        return claim;
    }

    [Fact]
    public async Task WithoutHttpRequest_IsRejected()
    {
        HandleAuthorizationRequestContext context = await HandleAsync("openid", withHttpRequest: false);

        Assert.True(context.IsRejected);
        Assert.Equal(Errors.ServerError, context.Error);
        Assert.Empty(userDirectory.Calls);
    }

    [Fact]
    public async Task WithoutWindowsUser_ChallengesNegotiate()
    {
        HandleAuthorizationRequestContext context = await HandleAsync("openid");

        Assert.Equal([NegotiateDefaults.AuthenticationScheme], authenticationService.Challenges);
        Assert.True(context.IsRequestHandled);
        Assert.False(context.IsRejected);
        Assert.Null(context.Principal);
        Assert.Empty(userDirectory.Calls);
    }

    [Fact]
    public async Task WithUnauthenticatedIdentity_ChallengesNegotiate()
    {
        authenticationService.User = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.PrimarySid, FakeDirectory.CompleteUser.Sid)]));

        HandleAuthorizationRequestContext context = await HandleAsync("openid");

        Assert.Equal([NegotiateDefaults.AuthenticationScheme], authenticationService.Challenges);
        Assert.True(context.IsRequestHandled);
        Assert.Empty(userDirectory.Calls);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("S-1-5-21-1000-2000-3000-9999")]
    public async Task UserNotFound_IsRejectedAndAudited(string sid)
    {
        authenticationService.User = CreateWindowsUser(sid);

        HandleAuthorizationRequestContext context = await HandleAsync("openid");

        Assert.True(context.IsRejected);
        Assert.Equal(Errors.AccessDenied, context.Error);
        Assert.Null(context.Principal);
        Assert.Equal([(sid, false)], userDirectory.Calls);

        FakeLogRecord record = Assert.Single(loggerProvider.Collector.GetSnapshot());
        Assert.Equal(WinOpenIDServerHandler.AuditCategory, record.Category);
        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Contains(UserName, record.Message);
        Assert.Contains(ClientId, record.Message);
        if (sid != null)
        {
            Assert.Contains(sid, record.Message);
        }
    }

    [Fact]
    public async Task UnknownClient_IsRejected()
    {
        authenticationService.User = CreateWindowsUser(FakeDirectory.CompleteUser.Sid);

        HandleAuthorizationRequestContext context = await HandleAsync("openid", clientId: "unknown");

        Assert.True(context.IsRejected);
        Assert.Equal(Errors.InvalidClient, context.Error);
        Assert.Null(context.Principal);
    }

    [Fact]
    public async Task OpenIdScope_AddsOnlyTheIdentityClaims()
    {
        authenticationService.User = CreateWindowsUser(FakeDirectory.CompleteUser.Sid);

        HandleAuthorizationRequestContext context = await HandleAsync("openid");

        Assert.False(context.IsRejected);
        ClaimsPrincipal principal = context.Principal;
        Assert.NotNull(principal);

        // Without domain, the subject is the SID
        AssertSingleClaim(principal, Claims.Subject, FakeDirectory.CompleteUser.Sid);
        AssertSingleClaim(principal, Claims.Username, UserName, Destinations.AccessToken, Destinations.IdentityToken);
        AssertSingleClaim(principal, Claims.PreferredUsername, UserName, Destinations.AccessToken, Destinations.IdentityToken);
        Assert.Equal([Scopes.OpenId], principal.GetScopes());
        Assert.Equal(["api", "other-api"], principal.GetResources());

        string[] profileClaims = [Claims.Name, Claims.GivenName, Claims.FamilyName, WinOpenIDClaims.EmployeeId, Claims.Email, Claims.EmailVerified,
            Claims.PhoneNumber, Claims.PhoneNumberVerified, Claims.Role];
        Assert.DoesNotContain(principal.Claims, claim => profileClaims.Contains(claim.Type));

        // The groups are only loaded for the roles scope
        Assert.Equal([(FakeDirectory.CompleteUser.Sid, false)], userDirectory.Calls);
    }

    [Fact]
    public async Task WithDomain_SubjectIsTheObjectGuid()
    {
        authenticationService.User = CreateWindowsUser(FakeDirectory.CompleteUser.Sid);

        HandleAuthorizationRequestContext context = await HandleAsync("openid", domain: "example.com");

        AssertSingleClaim(context.Principal, Claims.Subject, FakeDirectory.CompleteUser.Guid.ToString());
    }

    [Fact]
    public async Task ProfileScope_AddsTheProfileClaims()
    {
        authenticationService.User = CreateWindowsUser(FakeDirectory.CompleteUser.Sid);

        HandleAuthorizationRequestContext context = await HandleAsync("openid profile");

        AssertSingleClaim(context.Principal, Claims.Name, "Maria da Silva", Destinations.IdentityToken);
        AssertSingleClaim(context.Principal, Claims.GivenName, "Maria", Destinations.IdentityToken);
        AssertSingleClaim(context.Principal, Claims.FamilyName, "da Silva", Destinations.IdentityToken);
        AssertSingleClaim(context.Principal, WinOpenIDClaims.EmployeeId, "12345", Destinations.IdentityToken);
    }

    [Fact]
    public async Task EmailAndPhoneScopes_AddVerifiedClaims()
    {
        authenticationService.User = CreateWindowsUser(FakeDirectory.CompleteUser.Sid);

        HandleAuthorizationRequestContext context = await HandleAsync("openid email phone");

        AssertSingleClaim(context.Principal, Claims.Email, "maria@example.com", Destinations.IdentityToken);
        AssertSingleClaim(context.Principal, Claims.EmailVerified, "True", Destinations.IdentityToken);
        AssertSingleClaim(context.Principal, Claims.PhoneNumber, "+55 11 5555-0100", Destinations.IdentityToken);
        AssertSingleClaim(context.Principal, Claims.PhoneNumberVerified, "True", Destinations.IdentityToken);
    }

    [Fact]
    public async Task RolesScope_AddsTheGroups()
    {
        authenticationService.User = CreateWindowsUser(FakeDirectory.CompleteUser.Sid);

        HandleAuthorizationRequestContext context = await HandleAsync("openid roles");

        Claim[] roles = [.. context.Principal.Claims.Where(claim => claim.Type == Claims.Role)];
        Assert.Equal(["Domain Users", "Developers"], roles.Select(role => role.Value));
        Assert.All(roles, role => Assert.Equal([Destinations.IdentityToken], role.GetDestinations()));
        Assert.Equal([(FakeDirectory.CompleteUser.Sid, true)], userDirectory.Calls);
    }

    [Fact]
    public async Task UserWithoutOptionalAttributes_OnlyGetsTheIdentityClaims()
    {
        authenticationService.User = CreateWindowsUser(FakeDirectory.MinimalUser.Sid, @"MACHINE\user");

        HandleAuthorizationRequestContext context = await HandleAsync("openid profile email phone roles");

        Assert.False(context.IsRejected);
        Assert.Equal(
            [Claims.PreferredUsername, Claims.Subject, Claims.Username],
            context.Principal.Claims.Select(claim => claim.Type).Where(type => !type.StartsWith("oi_")).Order());
    }

    [Fact]
    public async Task IssuedCode_IsAudited()
    {
        authenticationService.User = CreateWindowsUser(FakeDirectory.CompleteUser.Sid);

        await HandleAsync("openid profile");

        FakeLogRecord record = Assert.Single(loggerProvider.Collector.GetSnapshot());
        Assert.Equal(WinOpenIDServerHandler.AuditCategory, record.Category);
        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Contains(UserName, record.Message);
        Assert.Contains(FakeDirectory.CompleteUser.Sid, record.Message);
        Assert.Contains(ClientId, record.Message);
        Assert.Contains(RedirectUri, record.Message);
        Assert.Contains("scopes: openid profile", record.Message);
        Assert.Contains("audiences: api other-api", record.Message);
    }

    // Authentication service of the HTTP context: returns the configured user and records the challenges
    private class FakeAuthenticationService : IAuthenticationService
    {
        public ClaimsPrincipal User { get; set; }

        public List<string> Challenges { get; } = [];

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string scheme)
            => Task.FromResult(User == null ? AuthenticateResult.NoResult() : AuthenticateResult.Success(new AuthenticationTicket(User, scheme)));

        public Task ChallengeAsync(HttpContext context, string scheme, AuthenticationProperties properties)
        {
            Challenges.Add(scheme);
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        }

        public Task ForbidAsync(HttpContext context, string scheme, AuthenticationProperties properties)
            => throw new NotSupportedException();

        public Task SignInAsync(HttpContext context, string scheme, ClaimsPrincipal principal, AuthenticationProperties properties)
            => throw new NotSupportedException();

        public Task SignOutAsync(HttpContext context, string scheme, AuthenticationProperties properties)
            => throw new NotSupportedException();
    }
}
