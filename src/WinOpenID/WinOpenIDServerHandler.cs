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
        if (result?.Principal is not WindowsPrincipal { Identity: WindowsIdentity windowsIdentity })
        {
            // Run Windows authentication
            await request.HttpContext.ChallengeAsync(NegotiateDefaults.AuthenticationScheme);
            context.HandleRequest();
            return;
        }

        // Set the directory service to the active directory domain or machine 
        using PrincipalContext directoryService = serverOptions.UseDomain
            ? new PrincipalContext(ContextType.Domain, serverOptions.Domain)
            : new PrincipalContext(ContextType.Machine);

        // Search by SID as SID is unique (user names can clash on trusted domains)
        SecurityIdentifier userSid = windowsIdentity.User;
        using UserPrincipal userInfo = userSid == null ? null : UserPrincipal.FindByIdentity(directoryService, IdentityType.Sid, userSid.Value);

        // Defense in depth: make sure the account found is the authenticated one
        if (userInfo == null || userInfo.Sid != userSid)
        {
            context.Reject(error: Errors.AccessDenied, description: "User is not found.");
            return;
        }

        // We're authenticated using Windows authentication, build an Identity with Claims;
        ClaimsIdentity identity = new(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        identity.SetScopes(context.Request.GetScopes());

        // Add the name identifier claim; this is the user's unique identifier
        string subject = serverOptions.UseDomain ? userInfo.Guid.ToString() : userInfo.Sid.Value;
        identity.AddClaim(Claims.Subject, subject);

        // Add the user´s login name
        identity.AddClaim(new Claim(Claims.Username, windowsIdentity.Name).SetDestinations([Destinations.AccessToken, Destinations.IdentityToken]));
        identity.AddClaim(new Claim(Claims.PreferredUsername, windowsIdentity.Name).SetDestinations([Destinations.AccessToken, Destinations.IdentityToken]));

        // Add user's profile fields
        if (context.Request.HasScope(Scopes.Profile))
        {
            // Add the account's friendly name
            if (userInfo.DisplayName != null)
            {
                identity.AddClaim(new Claim(Claims.Name, userInfo.DisplayName).SetDestinations([Destinations.IdentityToken]));
            }

            // Add the user's given and sur names
            if (userInfo.GivenName != null)
            { 
                identity.AddClaim(new Claim(Claims.GivenName, userInfo.GivenName).SetDestinations([Destinations.IdentityToken])); 
            }
            if (userInfo.Surname != null)
            { 
                identity.AddClaim(new Claim(Claims.FamilyName, userInfo.Surname).SetDestinations([Destinations.IdentityToken])); 
            }

            // Add the user's employee id number
            if (userInfo.EmployeeId != null)
            { 
                identity.AddClaim(new Claim(WinOpenIDClaims.EmployeeId, userInfo.EmployeeId).SetDestinations([Destinations.IdentityToken])); 
            }
        }

        if (context.Request.HasScope(Scopes.Profile) && userInfo.EmailAddress != null)
        {
            // Add the user's email address
            identity.AddClaim(new Claim(Claims.Email, userInfo.EmailAddress).SetDestinations([Destinations.IdentityToken]));
            identity.AddClaim(new Claim(Claims.EmailVerified, true.ToString()).SetDestinations([Destinations.IdentityToken]));
        }

        if (context.Request.HasScope(Scopes.Phone) && userInfo.VoiceTelephoneNumber != null)
        {
            // Add user's phone number
            identity.AddClaim(new Claim(Claims.PhoneNumber, userInfo.VoiceTelephoneNumber).SetDestinations([Destinations.IdentityToken]));
            identity.AddClaim(new Claim(Claims.PhoneNumberVerified, true.ToString()).SetDestinations([Destinations.IdentityToken]));
        }

        // Add user's roles (from user groups)
        if (context.Request.HasScope(Scopes.Roles))
        {
            using PrincipalSearchResult<Principal> groups = userInfo.GetAuthorizationGroups();
            identity.AddClaims(
                groups.Select(group => new Claim(Claims.Role, group.Name).SetDestinations([Destinations.IdentityToken]))
            );
        }

        var principal = new ClaimsPrincipal(identity);

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
