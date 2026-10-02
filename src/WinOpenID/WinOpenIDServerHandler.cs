using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;
using System.Security.Principal;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace WinOpenID;

// Based on: https://github.com/auroris/OpenIddict-WindowsAuth
public class WinOpenIDServerHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>, IOpenIddictServerHandler<HandleAuthorizationRequestContext>, IOpenIddictServerHandler<ValidateTokenRequestContext>
{
    private readonly WinOpenIDOptions serverOptions;

    public WinOpenIDServerHandler(IOptions<WinOpenIDOptions> serverOptions)
    {
        this.serverOptions = serverOptions?.Value ?? throw new ArgumentNullException(nameof(serverOptions));
    }

    // Event handler for validating authorization requests
    ValueTask IOpenIddictServerHandler<ValidateAuthorizationRequestContext>.HandleAsync(ValidateAuthorizationRequestContext context)
    {
        // Verification: I accept all context.ClientId's, but do check to see if the context.RedirectUri is proper
        if (!serverOptions.IsAllowedRedirectUri(context.RedirectUri))
        {
            context.Reject(error: Errors.InvalidRequest, description: "The specified 'redirect_uri' is not valid for this client application.");
        }

        return default;
    }

    // Event handler for authorization requests
    async ValueTask IOpenIddictServerHandler<HandleAuthorizationRequestContext>.HandleAsync(HandleAuthorizationRequestContext context)
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
            // The client asked for a silent login, so don't challenge the user
            if (context.Request.HasPromptValue(PromptValues.None))
            {
                context.Reject(error: Errors.LoginRequired, description: "The user is not logged in.");
                return;
            }

            // Run Windows authentication
            await request.HttpContext.ChallengeAsync(NegotiateDefaults.AuthenticationScheme);
            context.HandleRequest();
            return;
        }

        // If we're authenticated using Windows authentication, build an Identity with Claims;
        ClaimsIdentity identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);

        // Set the directory service to the active directory domain or machine 
        using PrincipalContext directoryService = serverOptions.UseDomain
            ? new PrincipalContext(ContextType.Domain, serverOptions.Domain)
            : new PrincipalContext(ContextType.Machine);

        // Get information about the user
        UserPrincipal user = UserPrincipal.FindByIdentity(directoryService, result.Principal.FindFirstValue(ClaimTypes.Name));

        if (user == null)
        {
            context.Reject(error: Errors.AccessDenied, description: "User is not found.");
            return;
        }

        // Add the name identifier claim; this is the user's unique identifier
        string subject = serverOptions.UseDomain
            ? user.Guid.ToString()
            : user.Sid.Value;
        identity.AddClaim(Claims.Subject, subject);

        // Add the user's email address
        if (user.EmailAddress != null)
        {
            identity.AddClaim(Claims.Email, user.EmailAddress);
            identity.AddClaim(Claims.EmailVerified, true);
        }

        if (context.Request.HasScope(Scopes.Profile))
        {
            // Add the account's friendly name
            identity.AddClaim(Claims.Name, user.DisplayName);

            // Add the user name
            identity.AddClaim(Claims.Username, user.Name);

            // Add the user name
            identity.AddClaim(Claims.PreferredUsername, user.Name);

            // Add the user's windows username (uniquename)
            string uniqueName = user.Sid.Translate(typeof(NTAccount)).Value;
            identity.AddClaim(WinOpenIDClaims.UniqueName, uniqueName);

            // Add the user's name
            if (user.GivenName != null) { identity.AddClaim(Claims.GivenName, user.GivenName); }
            if (user.Surname != null) { identity.AddClaim(Claims.FamilyName, user.Surname); }

            // Add the employee id number
            if (user.EmployeeId != null) { identity.AddClaim(WinOpenIDClaims.EmployeeId, user.EmployeeId); }
        }

        if (context.Request.HasScope(Scopes.Phone))
        {
            // Telephone 
            if (user.VoiceTelephoneNumber != null)
            {
                identity.AddClaim(Claims.PhoneNumber, user.VoiceTelephoneNumber);
                identity.AddClaim(Claims.PhoneNumberVerified, true);
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
                    identity.AddClaim(Claims.Role, group.Name);
                }
            }
        }

        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(context.Request.GetScopes());
        principal.SetDestinations((_) => [Destinations.AccessToken, Destinations.IdentityToken]);

        // Attach the principal to the authorization context, so that an OpenID Connect response
        // with an authorization code can be generated by the OpenIddict server services.
        context.Principal = principal;
    }

    // Event handler for validating token requests
    ValueTask IOpenIddictServerHandler<ValidateTokenRequestContext>.HandleAsync(ValidateTokenRequestContext context)
    {
        // I accept all context.ClientId's, but only the authorization code grant is supported
        if (!context.Request.IsAuthorizationCodeGrantType())
        {
            context.Reject(error: Errors.UnsupportedGrantType, description: "The specified 'grant_type' is not supported.");
            return default;
        }

        // Defense in depth: OpenIddict already binds the code to its redirect_uri, but check the whitelist again
        if (context.Request.RedirectUri != null && !serverOptions.IsAllowedRedirectUri(context.Request.RedirectUri))
        {
            context.Reject(error: Errors.InvalidGrant, description: "The specified 'redirect_uri' is not valid for this client application.");
        }

        return default;
    }
}
