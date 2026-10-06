using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using WinOpenID.UserDirectory;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace WinOpenID;

public static class WinOpenIDExtensions
{
    // Based on: https://github.com/auroris/OpenIddict-WindowsAuth
    public static IServiceCollection AddWinOpenId(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<WinOpenIDOptions>(configuration.GetSection(WinOpenIDOptions.Server));

        // Directory where the users authenticated by Windows are searched
        services.TryAddSingleton<IDirectory, WindowsDirectory>();

        // Attach OpenIddict with a ton of options
        services.AddOpenIddict()
            .AddServer(options =>
            {
                options.UseAspNetCore();

                options.EnableDegradedMode(); // We'll handle protocol stuff ourselves; don't want user stores or such

                // TODO: find a better way to use configuration here
                var serverOptions = configuration.GetSection(WinOpenIDOptions.Server).Get<WinOpenIDOptions>();

                options
                    .AddEncryptionKeys(serverOptions.GetEncryptionKeys())
                    .AddSigningKeys(serverOptions.GetSigningKeys());

                if (!serverOptions.EncryptAccessToken)
                {
                    options.DisableAccessTokenEncryption();
                }

                // A fixed issuer prevents a forged Host header from changing the discovery document and the tokens
                if (serverOptions.Issuer != null)
                {
                    options.SetIssuer(serverOptions.Issuer);
                }

                options.SetAuthorizationEndpointUris("/connect/authorize")
                       .SetTokenEndpointUris("/connect/token");

                options.AllowAuthorizationCodeFlow()
                       .RequireProofKeyForCodeExchange();

                // In degraded mode there is no token storage, so an authorization code can't be revoked after use
                // and may be redeemed again until it expires: keep its lifetime short (the default is 5 minutes)
                options.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(1));

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
                    // The prompt parameter is not supported: Windows authentication can't force a new login
                    openIddictOptions.PromptValues.Clear();

                    // Clients are public (PKCE only): the server doesn't authenticate them
                    openIddictOptions.ClientAuthenticationMethods.Clear();
                    openIddictOptions.ClientAuthenticationMethods.Add("none");

                    // Only accept S256 for PKCE: "plain" exposes the code verifier in the authorization request
                    openIddictOptions.CodeChallengeMethods.Clear();
                    openIddictOptions.CodeChallengeMethods.Add(CodeChallengeMethods.Sha256);

                    // Only the authorization code flow is supported: "fragment" is a leftover from the implicit flow
                    openIddictOptions.ResponseModes.Clear();
                    openIddictOptions.ResponseModes.Add(ResponseModes.Query);
                    openIddictOptions.ResponseModes.Add(ResponseModes.FormPost);
                });

                // Event handler for validating authorization requests
                options.AddEventHandler<ValidateAuthorizationRequestContext>(builder => builder.UseSingletonHandler<WinOpenIDServerHandler>());

                // Event handler for authorization requests
                options.AddEventHandler<HandleAuthorizationRequestContext>(builder => builder.UseSingletonHandler<WinOpenIDServerHandler>());

                // Event handler for validating token requests
                options.AddEventHandler<ValidateTokenRequestContext>(builder => builder.UseSingletonHandler<WinOpenIDServerHandler>());

                // Event handler for token requests (only logs the issued tokens: OpenIddict handles the code redemption)
                options.AddEventHandler<HandleTokenRequestContext>(builder => builder.UseSingletonHandler<WinOpenIDServerHandler>());

                // Event handlers to generate audit information
                options.AddEventHandler<ApplyAuthorizationResponseContext>(builder => builder.UseSingletonHandler<WinOpenIDServerHandler>().SetOrder(int.MinValue));
                options.AddEventHandler<ApplyTokenResponseContext>(builder => builder.UseSingletonHandler<WinOpenIDServerHandler>().SetOrder(int.MinValue));
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        return services;
    }
}
