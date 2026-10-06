using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;

namespace WinOpenID.Tests;

// Runs the server in memory with a test client and keys generated for the tests
public class WinOpenIDFactory : WebApplicationFactory<Program>
{
    public const string ClientId = "test-client";
    public const string RedirectUri = "https://client.example/callback";
    public const string ClientOrigin = "https://client.example";
    public const string Issuer = "https://localhost/";

    public FakeLoggerProvider LoggerProvider { get; } = new();

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
        builder.UseSetting($"Server:Clients:{ClientId}:Audiences:0", "api");
        builder.UseSetting("Server:EncryptionKeys:0", TestKeys.CreateEncryptionKey());
        builder.UseSetting("Server:SigningKeys:0", TestKeys.CreateSigningKey());

        builder.ConfigureServices(services =>
        {
            services.AddSingleton<ILoggerProvider>(LoggerProvider);
            // The Negotiate handler requires Kestrel or IIS: replace it with one where the user is never authenticated
            services.PostConfigure<AuthenticationOptions>(options =>
                options.SchemeMap[NegotiateDefaults.AuthenticationScheme].HandlerType = typeof(UnauthenticatedHandler));
        });
    }

    public IReadOnlyList<FakeLogRecord> GetAuditLog()
        => [.. LoggerProvider.Collector.GetSnapshot().Where(record => record.Category == WinOpenIDServerHandler.AuditCategory)];

    private class UnauthenticatedHandler(IOptionsMonitor<NegotiateOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : AuthenticationHandler<NegotiateOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            => Task.FromResult(AuthenticateResult.NoResult());

        // Same response as the Negotiate handler when the browser hasn't sent the Windows credentials yet
        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.StatusCode = StatusCodes.Status401Unauthorized;
            Response.Headers.WWWAuthenticate = NegotiateDefaults.AuthenticationScheme;
            return Task.CompletedTask;
        }
    }
}
