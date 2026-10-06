using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using System.Net;
using System.Security.Claims;
using WinOpenID.UserDirectory;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace WinOpenID;

// Based on: https://github.com/auroris/OpenIddict-WindowsAuth
// Also logs the issued authorization codes and tokens and the rejected requests. Codes, tokens and keys are never logged.
public class WinOpenIDServerHandler : IOpenIddictServerHandler<ValidateAuthorizationRequestContext>, IOpenIddictServerHandler<HandleAuthorizationRequestContext>, IOpenIddictServerHandler<ValidateTokenRequestContext>,
    IOpenIddictServerHandler<HandleTokenRequestContext>, IOpenIddictServerHandler<ApplyAuthorizationResponseContext>, IOpenIddictServerHandler<ApplyTokenResponseContext>
{
    public const string AuditCategory = "WinOpenID.Audit";

    private readonly WinOpenIDOptions serverOptions;
    private readonly IDirectory directory;
    private readonly ILogger auditLogger;

    public WinOpenIDServerHandler(IOptions<WinOpenIDOptions> serverOptions, IDirectory directory, ILoggerFactory loggerFactory)
    {
        this.serverOptions = serverOptions?.Value ?? throw new ArgumentNullException(nameof(serverOptions));
        this.directory = directory ?? throw new ArgumentNullException(nameof(directory));
        ArgumentNullException.ThrowIfNull(loggerFactory);
        auditLogger = loggerFactory.CreateLogger(AuditCategory);
    }

    // Event handler for validating authorization requests
    ValueTask IOpenIddictServerHandler<ValidateAuthorizationRequestContext>.HandleAsync(ValidateAuthorizationRequestContext context)
    {
        // Clients are public, so the client_id is trusted because the code is only sent to its registered redirect URIs
        if (!serverOptions.TryGetClient(context.ClientId, out WinOpenIDClientOptions client))
        {
            context.Reject(error: Errors.InvalidClient, description: "The specified 'client_id' is not valid.");
            return default;
        }

        if (!client.IsAllowedRedirectUri(context.RedirectUri))
        {
            context.Reject(error: Errors.InvalidRequest, description: "The specified 'redirect_uri' is not valid for this client application.");
            return default;
        }

        if (!context.Request.GetScopes().All(client.IsAllowedScope))
        {
            context.Reject(error: Errors.InvalidScope, description: "The specified 'scope' is not allowed for this client application.");
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
        if (result?.Principal is not { Identity.IsAuthenticated: true } authenticatedUser)
        {
            // Run Windows authentication
            await request.HttpContext.ChallengeAsync(NegotiateDefaults.AuthenticationScheme);
            context.HandleRequest();
            return;
        }

        // The Windows identity provides the user's SID and login name as claims
        string userName = authenticatedUser.Identity.Name;
        string userSid = authenticatedUser.FindFirst(ClaimTypes.PrimarySid)?.Value;

        // Search by SID as SID is unique (user names can clash on trusted domains)
        DirectoryUser userInfo = await directory.FindBySidAsync(userSid, includeGroups: context.Request.HasScope(Scopes.Roles), context.CancellationToken);
        if (userInfo == null)
        {
            auditLogger.LogWarning(
                "User {UserName} ({Sid}) authenticated by Windows was not found in the directory, client {ClientId} (remote: {RemoteEndpoint}).",
                userName, userSid, context.ClientId, GetRemoteEndpoint(context));
            context.Reject(error: Errors.AccessDenied, description: "User is not found.");
            return;
        }

        // The client was checked when the request was validated
        if (!serverOptions.TryGetClient(context.ClientId, out WinOpenIDClientOptions client))
        {
            context.Reject(error: Errors.InvalidClient, description: "The specified 'client_id' is not valid.");
            return;
        }

        // We're authenticated using Windows authentication, build an Identity with Claims;
        ClaimsIdentity identity = new(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        identity.SetScopes(context.Request.GetScopes());

        // The resources become the audiences (aud) of the access token
        identity.SetResources(client.Audiences);

        // Add the name identifier claim; this is the user's unique identifier
        string subject = serverOptions.UseDomain ? userInfo.Guid.ToString() : userInfo.Sid;
        identity.AddClaim(Claims.Subject, subject);

        // Add the user´s login name
        identity.AddClaim(new Claim(Claims.Username, userName).SetDestinations([Destinations.AccessToken, Destinations.IdentityToken]));
        identity.AddClaim(new Claim(Claims.PreferredUsername, userName).SetDestinations([Destinations.AccessToken, Destinations.IdentityToken]));

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

        if (context.Request.HasScope(Scopes.Email) && userInfo.EmailAddress != null)
        {
            // Add the user's email address
            identity.AddClaim(new Claim(Claims.Email, userInfo.EmailAddress).SetDestinations([Destinations.IdentityToken]));
            identity.AddClaim(new Claim(Claims.EmailVerified, true.ToString()).SetDestinations([Destinations.IdentityToken]));
        }

        if (context.Request.HasScope(Scopes.Phone) && userInfo.PhoneNumber != null)
        {
            // Add user's phone number
            identity.AddClaim(new Claim(Claims.PhoneNumber, userInfo.PhoneNumber).SetDestinations([Destinations.IdentityToken]));
            identity.AddClaim(new Claim(Claims.PhoneNumberVerified, true.ToString()).SetDestinations([Destinations.IdentityToken]));
        }

        // Add user's roles (from user groups)
        if (context.Request.HasScope(Scopes.Roles))
        {
            identity.AddClaims(
                userInfo.Groups.Select(group => new Claim(Claims.Role, group).SetDestinations([Destinations.IdentityToken]))
            );
        }

        var principal = new ClaimsPrincipal(identity);

        // Attach the principal to the authorization context, so that an OpenID Connect response
        // with an authorization code can be generated by the OpenIddict server services.
        context.Principal = principal;

        if (auditLogger.IsEnabled(LogLevel.Information))
        {
            auditLogger.LogInformation(
                "Authorization code issued to {UserName} ({Subject}) for client {ClientId} (redirect_uri: {RedirectUri}, scopes: {Scopes}, audiences: {Audiences}, remote: {RemoteEndpoint}).",
                userName, subject, context.ClientId, context.Request.RedirectUri,
                string.Join(' ', principal.GetScopes()), string.Join(' ', principal.GetResources()), GetRemoteEndpoint(context));
        }
    }

    // Event handler for validating token requests
    ValueTask IOpenIddictServerHandler<ValidateTokenRequestContext>.HandleAsync(ValidateTokenRequestContext context)
    {
        // Only the authorization code grant is supported
        if (!context.Request.IsAuthorizationCodeGrantType())
        {
            context.Reject(error: Errors.UnsupportedGrantType, description: "The specified 'grant_type' is not supported.");
            return default;
        }

        // OpenIddict already checks that the code is redeemed by the client it was issued to
        if (!serverOptions.TryGetClient(context.ClientId, out WinOpenIDClientOptions client))
        {
            context.Reject(error: Errors.InvalidClient, description: "The specified 'client_id' is not valid.");
            return default;
        }

        // Defense in depth: OpenIddict already binds the code to its redirect_uri, but check the client's list again
        if (context.Request.RedirectUri != null && !client.IsAllowedRedirectUri(context.Request.RedirectUri))
        {
            context.Reject(error: Errors.InvalidGrant, description: "The specified 'redirect_uri' is not valid for this client application.");
        }

        return default;
    }

    // Rejected authorization requests, by this server's handlers or by OpenIddict itself
    ValueTask IOpenIddictServerHandler<ApplyAuthorizationResponseContext>.HandleAsync(ApplyAuthorizationResponseContext context)
    {
        if (context.Response?.Error != null)
        {
            auditLogger.LogWarning(
                "Authorization request rejected for client {ClientId}: {Error} - {ErrorDescription} (redirect_uri: {RedirectUri}, scopes: {Scopes}, remote: {RemoteEndpoint}).",
                context.Request?.ClientId, context.Response.Error, context.Response.ErrorDescription,
                context.Request?.RedirectUri, context.Request?.Scope, GetRemoteEndpoint(context));
        }

        return default;
    }

    // Rejected token requests (expired or invalid code, invalid PKCE verifier, unknown client etc.)
    ValueTask IOpenIddictServerHandler<ApplyTokenResponseContext>.HandleAsync(ApplyTokenResponseContext context)
    {
        if (context.Response?.Error != null && auditLogger.IsEnabled(LogLevel.Information))
        {
            auditLogger.LogWarning(
                "Token request rejected for client {ClientId}: {Error} - {ErrorDescription} (grant_type: {GrantType}, remote: {RemoteEndpoint}).",
                context.Request?.ClientId, context.Response.Error, context.Response.ErrorDescription,
                context.Request?.GrantType, GetRemoteEndpoint(context));
        }

        return default;
    }

    // Code redeemed for tokens: in degraded mode, OpenIddict attaches the principal extracted from the code before this handler
    ValueTask IOpenIddictServerHandler<HandleTokenRequestContext>.HandleAsync(HandleTokenRequestContext context)
    {
        if (context.Principal != null && auditLogger.IsEnabled(LogLevel.Information))
        {
            auditLogger.LogInformation(
                "Tokens issued to {UserName} ({Subject}) for client {ClientId} (scopes: {Scopes}, audiences: {Audiences}, remote: {RemoteEndpoint}).",
                context.Principal.GetClaim(Claims.PreferredUsername), context.Principal.GetClaim(Claims.Subject), context.Request?.ClientId,
                string.Join(' ', context.Principal.GetScopes()), string.Join(' ', context.Principal.GetResources()), GetRemoteEndpoint(context));
        }

        return default;
    }

    // IP and port of the client: with carrier-grade NAT, several users share the same public IP using different port ranges
    private static string GetRemoteEndpoint(BaseContext context)
    {
        ConnectionInfo connection = context.Transaction.GetHttpRequest()?.HttpContext.Connection;
        if (connection?.RemoteIpAddress == null)
        {
            return null;
        }

        // Dual-stack sockets report IPv4 clients as IPv4-mapped IPv6 addresses (::ffff:203.0.113.10)
        IPAddress address = connection.RemoteIpAddress.IsIPv4MappedToIPv6 ? connection.RemoteIpAddress.MapToIPv4() : connection.RemoteIpAddress;

        // IPEndPoint formats IPv6 addresses between brackets, e.g. [2001:db8::1]:51234
        return new IPEndPoint(address, connection.RemotePort).ToString();
    }
}
