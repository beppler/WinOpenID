using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;
using WinOpenID.Tests.UserDirectory;
using WinOpenID.UserDirectory;

namespace WinOpenID.Tests;

// Runs the server in memory with a test client and keys generated for the tests
public class WinOpenIDFactory : WebApplicationFactory<Program>
{
    public const string ClientId = "test-client";
    public const string RedirectUri = "https://client.example/callback";
    public const string ClientOrigin = "https://client.example";
    public const string Issuer = "https://localhost/";

    // Headers that make the test Negotiate handler authenticate a Windows user
    public const string UserSidHeader = "X-Test-User-Sid";
    public const string UserNameHeader = "X-Test-User-Name";

    public FakeLoggerProvider LoggerProvider { get; } = new();

    public FakeDirectory UserDirectory { get; } = new();

    public string EncryptionKey { get; } = TestKeys.CreateEncryptionKey();

    public string SigningKey { get; } = TestKeys.CreateSigningKey();

    public WinOpenIDFactory()
    {
        ClientOptions.BaseAddress = new Uri("https://localhost");
        ClientOptions.AllowAutoRedirect = false;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // "Testing" doesn't load appsettings.Development.json
        builder.UseEnvironment("Testing");

        // UseSetting makes the values visible while Program.cs registers OpenIddict (before the application is built)
        builder.UseSetting("Server:Issuer", Issuer);
        builder.UseSetting($"Server:Clients:{ClientId}:RedirectUris:0", RedirectUri);
        builder.UseSetting($"Server:Clients:{ClientId}:Scopes:0", "openid");
        builder.UseSetting($"Server:Clients:{ClientId}:Scopes:1", "profile");
        builder.UseSetting($"Server:Clients:{ClientId}:Scopes:2", "roles");
        builder.UseSetting($"Server:Clients:{ClientId}:Audiences:0", "api");
        builder.UseSetting("Server:EncryptionKeys:0", EncryptionKey);
        builder.UseSetting("Server:SigningKeys:0", SigningKey);

        builder.ConfigureServices(services =>
        {
            services.AddSingleton<ILoggerProvider>(LoggerProvider);
            // The Negotiate handler requires Kestrel or IIS: replace it with one that authenticates the user of the test headers
            services.PostConfigure<AuthenticationOptions>(options =>
                options.SchemeMap[NegotiateDefaults.AuthenticationScheme].HandlerType = typeof(TestNegotiateHandler));
        });

        builder.ConfigureTestServices(services => services.AddSingleton<IDirectory>(UserDirectory));
    }

    public IReadOnlyList<FakeLogRecord> GetAuditLog()
        => [.. LoggerProvider.Collector.GetSnapshot().Where(record => record.Category == WinOpenIDServerHandler.AuditCategory)];

    private class TestNegotiateHandler(IOptionsMonitor<NegotiateOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : AuthenticationHandler<NegotiateOptions>(options, logger, encoder)
    {
        // Claims of the Windows identity used by the server: the login name and the SID
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            string sid = Request.Headers[UserSidHeader];
            if (string.IsNullOrEmpty(sid))
            {
                return Task.FromResult(AuthenticateResult.NoResult());
            }

            var identity = new ClaimsIdentity(
                [new Claim(ClaimTypes.Name, Request.Headers[UserNameHeader].ToString()), new Claim(ClaimTypes.PrimarySid, sid)], Scheme.Name);
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name)));
        }

        // Same response as the Negotiate handler when the browser hasn't sent the Windows credentials yet
        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.StatusCode = StatusCodes.Status401Unauthorized;
            Response.Headers.WWWAuthenticate = NegotiateDefaults.AuthenticationScheme;
            return Task.CompletedTask;
        }
    }
}
