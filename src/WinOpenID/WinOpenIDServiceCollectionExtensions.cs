using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace WinOpenID;

// Based on: https://github.com/auroris/OpenIddict-WindowsAuth
public static class WinOpenIDServiceCollectionExtensions
{
    public static IServiceCollection AddWinOpenId(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<WinOpenIDOptions>(configuration.GetSection(WinOpenIDOptions.Server));

        // Attach OpenIddict with a ton of options
        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.UseAspNetCore();

                options.EnableDegradedMode(); // We'll handle protocol stuff ourselves; don't want user stores or such

                // This OpenIddict server is stateless; however, make sure IIS doesn't dispose of the application too often (ie, via app pool recycles or shut downs due to inactivity)
                options.AddEphemeralSigningKey()
                       .AddEphemeralEncryptionKey();

                // TODO: find a better way to use configuration here
                var serverOptions = configuration.GetSection(WinOpenIDOptions.Server).Get<WinOpenIDOptions>();

                if (!serverOptions.EncryptAccessToken)
                    options.DisableAccessTokenEncryption();

                options.SetAuthorizationEndpointUris("/connect/authorize")
                       .SetTokenEndpointUris("/connect/token");

                options.AllowAuthorizationCodeFlow()
                       .RequireProofKeyForCodeExchange()
                       .AllowImplicitFlow();

                // Tell OpenIddict that we support these scopes
                options.RegisterScopes(Scopes.OpenId, Scopes.Email, Scopes.Profile, Scopes.Roles);

                // Tell OpenIddict that we support these claims
                options.RegisterClaims(
                    Claims.Name, Claims.Username, Claims.PreferredUsername, Claims.GivenName, Claims.FamilyName,
                    Claims.Email, Claims.EmailVerified, Claims.PhoneNumber, Claims.PhoneNumberVerified, Claims.Role,
                    WinOpenIDClaims.EmployeeId, WinOpenIDClaims.UniqueName
                );

                // Event handler for validating authorization requests
                options.AddEventHandler<ValidateAuthorizationRequestContext>(builder => builder.UseSingletonHandler<WinOpenIDServerHandler>());

                // Event handler for authorization requests
                options.AddEventHandler<HandleAuthorizationRequestContext>(builder => builder.UseSingletonHandler<WinOpenIDServerHandler>());

                // Event handler for validating token requests
                options.AddEventHandler<ValidateTokenRequestContext>(builder => builder.UseSingletonHandler<WinOpenIDServerHandler>());
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        return services;
    }
}
