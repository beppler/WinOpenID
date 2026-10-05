using OpenIddict.Abstractions;

namespace WinOpenID;

public class WinOpenIDClientOptions
{
    // Scopes that can be allowed to a client
    private static readonly string[] SupportedScopes = [
        OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.Email, OpenIddictConstants.Scopes.Profile,
        OpenIddictConstants.Scopes.Phone, OpenIddictConstants.Scopes.Roles
    ];

    private string[] allowedCorsOrigins = [];
    private string[] redirectUris = [];

    public string[] RedirectUris
    {
        get => redirectUris;
        set
        {
            if (value == null)
            {
                allowedCorsOrigins = [];
                redirectUris = [];
                return;
            }
            Uri[] uris = [.. value.Select(ParseRedirectUri)];
            allowedCorsOrigins = [.. uris.Select(NormalizeOrigin)];
            redirectUris = [.. uris.Select(NormalizeRedirectUri)];
        }
    }

    public string[] GetAllowedCorsOrigins() => allowedCorsOrigins;

    // Check if the redirect_uri exactly matches one of the RedirectUris (RFC 9700, section 4.1.3)
    public bool IsAllowedRedirectUri(string redirectUri)
    {
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out Uri uri))
        {
            return false;
        }

        string address = NormalizeRedirectUri(uri);
        return redirectUris.Any(allowed => string.Equals(address, allowed, StringComparison.Ordinal));
    }

    // Audiences (APIs) of the access tokens issued to the client: an API can accept tokens from several clients
    private string[] audiences = [];
    public string[] Audiences
    {
        get => audiences;
        set
        {
            value ??= [];

            if (value.Any(string.IsNullOrWhiteSpace))
            {
                throw new ArgumentException("The audiences of a client must not be empty.");
            }

            audiences = value;
        }
    }

    private string[] scopes = [];
    public string[] Scopes
    {
        get => scopes;
        set
        {
            value ??= [];

            string unsupported = value.FirstOrDefault(scope => !SupportedScopes.Contains(scope, StringComparer.Ordinal));
            if (unsupported != null)
            {
                throw new ArgumentException($"The scope '{unsupported}' is not supported (supported scopes: {string.Join(", ", SupportedScopes)}).");
            }

            scopes = value;
        }
    }

    public bool IsAllowedScope(string scope)
        => scopes.Contains(scope, StringComparer.Ordinal);

    private static string NormalizeOrigin(Uri uri)
        => uri.GetLeftPart(UriPartial.Authority);

    // AbsoluteUri only normalizes the scheme, host, default port and escaping: path and query are compared as is
    private static string NormalizeRedirectUri(Uri uri)
        => uri.AbsoluteUri;

    // Redirect URIs must be absolute, without fragment and use HTTPS (HTTP is only allowed on loopback addresses)
    private static Uri ParseRedirectUri(string value)
    {
        Uri uri = new(value, UriKind.Absolute);

        if (uri.Scheme != Uri.UriSchemeHttps && !(uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback))
        {
            throw new ArgumentException($"The redirect URI '{value}' must use HTTPS (HTTP is only allowed on loopback addresses).");
        }

        if (!string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ArgumentException($"The redirect URI '{value}' must not contain a fragment.");
        }

        return uri;
    }
}
