using Microsoft.Extensions.Options;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace WinOpenID;

public static class WinOpenIDExtensions
{
    // Based on: https://github.com/auroris/OpenIddict-WindowsAuth
    public static IServiceCollection AddWinOpenId(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<WinOpenIDOptions>(configuration.GetSection(WinOpenIDOptions.Server));

        // Attach OpenIddict with a ton of options
        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.UseAspNetCore();

                options.EnableDegradedMode(); // We'll handle protocol stuff ourselves; don't want user stores or such

                // TODO: find a better way to use configuration here
                var serverOptions = configuration.GetSection(WinOpenIDOptions.Server).Get<WinOpenIDOptions>();

                options.AddEphemeralEncryptionKey();

                if (!serverOptions.EncryptAccessToken)
                {
                    options.DisableAccessTokenEncryption();
                }

                if (serverOptions.SigningKeys.Length == 0)
                    options.AddEphemeralSigningKey();
                else
                    options.AddSigningKeys(serverOptions.GetSigningKeys());

                options.SetAuthorizationEndpointUris("/connect/authorize")
                       .SetTokenEndpointUris("/connect/token");

                options.AllowAuthorizationCodeFlow()
                       .RequireProofKeyForCodeExchange();

                // Tell OpenIddict that we support these scopes
                options.RegisterScopes(Scopes.OpenId, Scopes.Email, Scopes.Profile, Scopes.Phone, Scopes.Roles);

                // Tell OpenIddict that we support these claims
                options.RegisterClaims(
                    Claims.Name, Claims.Username, Claims.PreferredUsername, Claims.GivenName, Claims.FamilyName,
                    Claims.Email, Claims.EmailVerified, Claims.PhoneNumber, Claims.PhoneNumberVerified, Claims.Role,
                    WinOpenIDClaims.EmployeeId
                );

                options.Configure(openIddictOptions =>
                {
                    // Prompt configuration is not supported
                    openIddictOptions.PromptValues.Clear();
                    openIddictOptions.PromptValues.Add(PromptValues.None);

                    // Clients are public (PKCE only): the server doesn't authenticate them
                    openIddictOptions.ClientAuthenticationMethods.Clear();
                    openIddictOptions.ClientAuthenticationMethods.Add("none");

                    // Only accept S256 for PKCE: "plain" exposes the code verifier in the authorization request
                    openIddictOptions.CodeChallengeMethods.Clear();
                    openIddictOptions.CodeChallengeMethods.Add(CodeChallengeMethods.Sha256);
                });

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
