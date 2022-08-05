using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;
using System.Security.Principal;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace WinOpenID;

// Based on: https://github.com/auroris/OpenIddict-WindowsAuth
public static class WinOpenIDExtensions
{
    public static IServiceCollection AddWinOpenId(this IServiceCollection services, WinOpenIDOptions serverOptions)
    {
        services.AddCors();

        // Attach OpenIddict with a ton of options
        services.AddOpenIddict().AddServer(options =>
        {
            options.UseAspNetCore();

            options.EnableDegradedMode(); // We'll handle protocol stuff ourselves; don't want user stores or such

            // This OpenIddict server is stateless; however, make sure IIS doesn't dispose of the application too often (ie, via app pool recycles or shut downs due to inactivity)
            options.AddEphemeralSigningKey()
                   .AddEphemeralEncryptionKey();

            if (!serverOptions.EncryptAccessToken)
                options.DisableAccessTokenEncryption();

            options.SetAuthorizationEndpointUris("/connect/authorize")
                   .SetTokenEndpointUris("/connect/token");

            options.AllowAuthorizationCodeFlow()
                   .AllowImplicitFlow();

            // Tell OpenIddict that we support these scopes
            options.RegisterScopes(Scopes.OpenId, Scopes.Email, Scopes.Profile, Scopes.Roles);

            // Tell OpenIddict that we support these claims
            options.RegisterClaims(
                Claims.Name, Claims.Username, Claims.PreferredUsername, Claims.GivenName, Claims.FamilyName,
                Claims.Email, Claims.EmailVerified, Claims.PhoneNumber, Claims.PhoneNumberVerified, Claims.Role,
                WinOpenIDClaims.EmployeeId, WinOpenIDClaims.UniqueName
            );

            // Event handler for validating token requests
            options.AddEventHandler<ValidateTokenRequestContext>(builder =>
                builder.UseInlineHandler(context => default) // I accept all context.ClientId's, so just carry on.
            );

            // Event handler for validating authorization requests
            options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    // Verification: I accept all context.ClientId's, but do check to see if the context.RedirectUri is proper
                    foreach (string host in serverOptions.AllowedHosts)
                    {
                        if (context.RedirectUri.StartsWith(host, StringComparison.InvariantCultureIgnoreCase))
                        {
                            return default;
                        }
                    }

                    // Fall-through: URL was not proper.
                    context.Reject(error: Errors.InvalidClient, description: "The specified 'redirect_uri' is not valid for this client application.");
                    return default;
                }));

            // Event handler for authorization requests
            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(async context =>
                {
                    // Get the HTTP request
                    HttpRequest request = context.Transaction.GetHttpRequest();
                    if (request == null)
                    {
                        context.Reject(error: Errors.ServerError, "Request information cannot be retrieved.");
                        return;
                    }

                    // Try to get the authentication of the current session via Windows Authentication
                    AuthenticateResult result = await request.HttpContext.AuthenticateAsync(NegotiateDefaults.AuthenticationScheme);
                    if (result?.Principal is not WindowsPrincipal)
                    {
                        // Run Windows authentication
                        await request.HttpContext.ChallengeAsync(NegotiateDefaults.AuthenticationScheme);
                        context.HandleRequest();
                        return;
                    }

                    // If we're authenticated using Windows authentication, build an Identity with Claims;
                    ClaimsIdentity identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);

                    // Set the directory service to the active directory domain or machine 
                    using PrincipalContext directoryService = serverOptions.UseDomain
                        ? new PrincipalContext(ContextType.Domain, serverOptions.Domain)
                        : new PrincipalContext(ContextType.Machine);

                    // Get information about the user
                    UserPrincipal user = UserPrincipal.FindByIdentity(directoryService, result.Principal.FindFirstValue(ClaimTypes.Name));

                    if (user == null)
                    {
                        context.Reject(error: Errors.InvalidGrant, description: "User is not found.");
                        return;
                    }

                    // Attach basic id if requested
                    if (context.Request.HasScope(Scopes.OpenId))
                    {
                        // Add the name identifier claim; this is the user's unique identifier
                        string subject = serverOptions.UseDomain
                            ? user.Guid.ToString()
                            : user.Sid.Value;
                        identity.AddClaim(Claims.Subject, subject, Destinations.AccessToken);
                    }

                    // Attach email address if requested
                    if (context.Request.HasScope(Scopes.Email))
                    {
                        // Add the user's email address
                        if (user.EmailAddress != null)
                        {
                            identity.AddClaim(Claims.Email, user.EmailAddress, Destinations.IdentityToken);
                            identity.AddClaim(new Claim(Claims.EmailVerified, "true", ClaimValueTypes.Boolean).SetDestinations(Destinations.IdentityToken));
                        }
                    }

                    // Attach profile stuff if requested
                    if (context.Request.HasScope(Scopes.Profile))
                    {
                        // Add the account's friendly name
                        identity.AddClaim(Claims.Name, user.DisplayName, Destinations.IdentityToken);

                        // Add the user name
                        identity.AddClaim(Claims.Username, user.Name, Destinations.AccessToken, Destinations.IdentityToken);

                        // Add the user name
                        identity.AddClaim(Claims.PreferredUsername, user.Name, Destinations.AccessToken, Destinations.IdentityToken);

                        // Add the user's windows username (uniquename)
                        string uniqueName = user.Sid.Translate(typeof(NTAccount)).Value;
                        identity.AddClaim(WinOpenIDClaims.UniqueName, uniqueName, Destinations.AccessToken, Destinations.IdentityToken);

                        // Add the user's name
                        if (user.GivenName != null) { identity.AddClaim(Claims.GivenName, user.GivenName, Destinations.IdentityToken); }
                        if (user.Surname != null) { identity.AddClaim(Claims.FamilyName, user.Surname, Destinations.IdentityToken); }

                        // Add the employee id number
                        if (user.EmployeeId != null) { identity.AddClaim(WinOpenIDClaims.EmployeeId, user.EmployeeId, Destinations.AccessToken, Destinations.IdentityToken); }
                    }

                    // Attach phone number if requested
                    if (context.Request.HasScope(Scopes.Phone))
                    {
                        // Telephone 
                        if (user.VoiceTelephoneNumber != null)
                        {
                            identity.AddClaim(Claims.PhoneNumber, user.VoiceTelephoneNumber, Destinations.IdentityToken);
                            identity.AddClaim(new Claim(Claims.PhoneNumberVerified, "true", ClaimValueTypes.Boolean).SetDestinations(Destinations.IdentityToken));
                        }
                    }

                    // Attach roles if requested
                    if (context.Request.HasScope(Scopes.Roles))
                    {
                        // Get and assign the group claims
                        foreach (Principal group in user.GetGroups())
                        {
                            if (group.Name != null)
                            {
                                identity.AddClaim(Claims.Role, group.Name, Destinations.IdentityToken);
                            }
                        }
                    }

                    // Attach the principal to the authorization context, so that an OpenID Connect response
                    // with an authorization code can be generated by the OpenIddict server services.
                    context.Principal = new ClaimsPrincipal(identity);
                }));
        })
        .AddValidation(options =>
        {
            options.UseLocalServer();
            options.UseAspNetCore();
        });

        return services;
    }
}
