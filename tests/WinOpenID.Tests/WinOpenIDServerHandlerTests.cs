using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Testing;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using System.Net;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace WinOpenID.Tests;

public class WinOpenIDServerHandlerTests
{
    private const string ClientId = "client";
    private const string RedirectUri = "https://client.example/callback";

    private readonly FakeLoggerProvider loggerProvider = new();
    private readonly WinOpenIDServerHandler handler;

    public WinOpenIDServerHandlerTests()
    {
        var serverOptions = new WinOpenIDOptions
        {
            Clients = new()
            {
                [ClientId] = new WinOpenIDClientOptions { RedirectUris = [RedirectUri], Scopes = [Scopes.OpenId, Scopes.Profile], Audiences = ["api"] }
            }
        };
        handler = new WinOpenIDServerHandler(Options.Create(serverOptions), new FakeUserDirectory(), new LoggerFactory([loggerProvider]));
    }

    private static OpenIddictServerTransaction CreateTransaction(OpenIddictRequest request, HttpContext httpContext = null)
    {
        var transaction = new OpenIddictServerTransaction
        {
            Request = request,
            Options = new OpenIddictServerOptions(),
            Logger = NullLogger.Instance
        };

        // Attach the HTTP request the same way OpenIddict.Server.AspNetCore does
        if (httpContext != null)
        {
            transaction.Properties[typeof(HttpRequest).FullName] = new WeakReference<HttpRequest>(httpContext.Request);
        }

        return transaction;
    }

    private async Task<ValidateAuthorizationRequestContext> ValidateAuthorizationAsync(string clientId, string redirectUri, string scope)
    {
        var request = new OpenIddictRequest { ClientId = clientId, RedirectUri = redirectUri, Scope = scope, ResponseType = ResponseTypes.Code };
        var context = new ValidateAuthorizationRequestContext(CreateTransaction(request));
        await ((IOpenIddictServerHandler<ValidateAuthorizationRequestContext>)handler).HandleAsync(context);
        return context;
    }

    private async Task<ValidateTokenRequestContext> ValidateTokenAsync(string grantType, string clientId, string redirectUri)
    {
        var request = new OpenIddictRequest { GrantType = grantType, ClientId = clientId, RedirectUri = redirectUri, Code = "code" };
        var context = new ValidateTokenRequestContext(CreateTransaction(request));
        await ((IOpenIddictServerHandler<ValidateTokenRequestContext>)handler).HandleAsync(context);
        return context;
    }

    [Fact]
    public void Constructor_RejectsNullArguments()
    {
        Assert.Throws<ArgumentNullException>(() => new WinOpenIDServerHandler(null, new FakeUserDirectory(), NullLoggerFactory.Instance));
        Assert.Throws<ArgumentNullException>(() => new WinOpenIDServerHandler(Options.Create(new WinOpenIDOptions()), null, NullLoggerFactory.Instance));
        Assert.Throws<ArgumentNullException>(() => new WinOpenIDServerHandler(Options.Create(new WinOpenIDOptions()), new FakeUserDirectory(), null));
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_AcceptsRegisteredClient()
    {
        ValidateAuthorizationRequestContext context = await ValidateAuthorizationAsync(ClientId, RedirectUri, "openid profile");

        Assert.False(context.IsRejected);
    }

    [Theory]
    [InlineData("unknown", RedirectUri, "openid", Errors.InvalidClient)]
    [InlineData(null, RedirectUri, "openid", Errors.InvalidClient)]
    [InlineData(ClientId, "https://evil.example/callback", "openid", Errors.InvalidRequest)]
    [InlineData(ClientId, "https://client.example/callback/", "openid", Errors.InvalidRequest)]
    [InlineData(ClientId, RedirectUri, "openid email", Errors.InvalidScope)]
    [InlineData(ClientId, RedirectUri, "openid roles", Errors.InvalidScope)]
    public async Task ValidateAuthorizationRequest_RejectsInvalidRequests(string clientId, string redirectUri, string scope, string error)
    {
        ValidateAuthorizationRequestContext context = await ValidateAuthorizationAsync(clientId, redirectUri, scope);

        Assert.True(context.IsRejected);
        Assert.Equal(error, context.Error);
    }

    [Theory]
    [InlineData(RedirectUri)]
    [InlineData(null)]
    public async Task ValidateTokenRequest_AcceptsAuthorizationCodeGrant(string redirectUri)
    {
        ValidateTokenRequestContext context = await ValidateTokenAsync(GrantTypes.AuthorizationCode, ClientId, redirectUri);

        Assert.False(context.IsRejected);
    }

    [Theory]
    [InlineData(GrantTypes.ClientCredentials, ClientId, RedirectUri, Errors.UnsupportedGrantType)]
    [InlineData(GrantTypes.Password, ClientId, RedirectUri, Errors.UnsupportedGrantType)]
    [InlineData(GrantTypes.RefreshToken, ClientId, RedirectUri, Errors.UnsupportedGrantType)]
    [InlineData(GrantTypes.AuthorizationCode, "unknown", RedirectUri, Errors.InvalidClient)]
    [InlineData(GrantTypes.AuthorizationCode, ClientId, "https://evil.example/callback", Errors.InvalidGrant)]
    public async Task ValidateTokenRequest_RejectsInvalidRequests(string grantType, string clientId, string redirectUri, string error)
    {
        ValidateTokenRequestContext context = await ValidateTokenAsync(grantType, clientId, redirectUri);

        Assert.True(context.IsRejected);
        Assert.Equal(error, context.Error);
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_LogsRejectedRequests()
    {
        var request = new OpenIddictRequest { ClientId = ClientId, RedirectUri = RedirectUri, Scope = "openid email" };
        var context = new ApplyAuthorizationResponseContext(CreateTransaction(request))
        {
            Response = new OpenIddictResponse { Error = Errors.InvalidScope, ErrorDescription = "Not allowed." }
        };

        await ((IOpenIddictServerHandler<ApplyAuthorizationResponseContext>)handler).HandleAsync(context);

        FakeLogRecord record = Assert.Single(loggerProvider.Collector.GetSnapshot());
        Assert.Equal(WinOpenIDServerHandler.AuditCategory, record.Category);
        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Contains(ClientId, record.Message);
        Assert.Contains(Errors.InvalidScope, record.Message);
        Assert.Contains("openid email", record.Message);
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_DoesNotLogSuccessfulResponses()
    {
        var context = new ApplyAuthorizationResponseContext(CreateTransaction(new OpenIddictRequest { ClientId = ClientId }))
        {
            Response = new OpenIddictResponse { Code = "code" }
        };

        await ((IOpenIddictServerHandler<ApplyAuthorizationResponseContext>)handler).HandleAsync(context);

        Assert.Empty(loggerProvider.Collector.GetSnapshot());
    }

    [Fact]
    public async Task ApplyTokenResponse_LogsRejectedRequests()
    {
        var request = new OpenIddictRequest { ClientId = ClientId, GrantType = GrantTypes.AuthorizationCode };
        var context = new ApplyTokenResponseContext(CreateTransaction(request))
        {
            Response = new OpenIddictResponse { Error = Errors.InvalidGrant, ErrorDescription = "Expired code." }
        };

        await ((IOpenIddictServerHandler<ApplyTokenResponseContext>)handler).HandleAsync(context);

        FakeLogRecord record = Assert.Single(loggerProvider.Collector.GetSnapshot());
        Assert.Equal(WinOpenIDServerHandler.AuditCategory, record.Category);
        Assert.Equal(LogLevel.Warning, record.Level);
        Assert.Contains(Errors.InvalidGrant, record.Message);
        Assert.Contains(GrantTypes.AuthorizationCode, record.Message);
    }

    [Fact]
    public async Task ApplyTokenResponse_DoesNotLogSuccessfulResponses()
    {
        var context = new ApplyTokenResponseContext(CreateTransaction(new OpenIddictRequest { ClientId = ClientId }))
        {
            Response = new OpenIddictResponse { AccessToken = "token" }
        };

        await ((IOpenIddictServerHandler<ApplyTokenResponseContext>)handler).HandleAsync(context);

        Assert.Empty(loggerProvider.Collector.GetSnapshot());
    }

    [Fact]
    public async Task HandleTokenRequest_LogsIssuedTokensWithoutTheTokens()
    {
        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
        identity.AddClaim(Claims.Subject, "S-1-5-21-1");
        identity.AddClaim(Claims.PreferredUsername, @"DOMAIN\user");
        identity.SetScopes(Scopes.OpenId, Scopes.Profile);
        identity.SetResources("api");

        var request = new OpenIddictRequest { ClientId = ClientId, GrantType = GrantTypes.AuthorizationCode, Code = "secret-code", CodeVerifier = "secret-verifier" };
        var context = new HandleTokenRequestContext(CreateTransaction(request)) { Principal = new ClaimsPrincipal(identity) };

        await ((IOpenIddictServerHandler<HandleTokenRequestContext>)handler).HandleAsync(context);

        FakeLogRecord record = Assert.Single(loggerProvider.Collector.GetSnapshot());
        Assert.Equal(WinOpenIDServerHandler.AuditCategory, record.Category);
        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Contains(@"DOMAIN\user", record.Message);
        Assert.Contains("S-1-5-21-1", record.Message);
        Assert.Contains(ClientId, record.Message);
        Assert.Contains("openid profile", record.Message);
        Assert.Contains("api", record.Message);
        Assert.DoesNotContain("secret", record.Message);
    }

    [Fact]
    public async Task HandleTokenRequest_WithoutPrincipal_DoesNotLog()
    {
        var context = new HandleTokenRequestContext(CreateTransaction(new OpenIddictRequest { ClientId = ClientId }));

        await ((IOpenIddictServerHandler<HandleTokenRequestContext>)handler).HandleAsync(context);

        Assert.Empty(loggerProvider.Collector.GetSnapshot());
    }

    [Theory]
    [InlineData("::ffff:203.0.113.10", "203.0.113.10:51234")]
    [InlineData("203.0.113.10", "203.0.113.10:51234")]
    [InlineData("2001:db8::1", "[2001:db8::1]:51234")]
    public async Task AuditLog_IncludesRemoteEndpoint(string remoteAddress, string expected)
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Connection.RemoteIpAddress = IPAddress.Parse(remoteAddress);
        httpContext.Connection.RemotePort = 51234;

        var context = new ApplyTokenResponseContext(CreateTransaction(new OpenIddictRequest { ClientId = ClientId }, httpContext))
        {
            Response = new OpenIddictResponse { Error = Errors.InvalidGrant }
        };

        await ((IOpenIddictServerHandler<ApplyTokenResponseContext>)handler).HandleAsync(context);

        FakeLogRecord record = Assert.Single(loggerProvider.Collector.GetSnapshot());
        Assert.Contains($"remote: {expected}", record.Message);
    }
}
