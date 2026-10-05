using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace WinOpenID;

public class WinOpenIDOptions
{
    public const string Server = nameof(Server);

    private string[] allowedCorsOrigins = [];
    private string[] allowedRedirectUris = [];

    public string[] AllowedRedirectUris {
        get => allowedRedirectUris;
        set
        {
            if (value == null)
            {
                allowedCorsOrigins = [];
                allowedRedirectUris = [];
                return;
            }
            Uri[] uris = [.. value.Select(ParseRedirectUri)];
            allowedCorsOrigins = [.. uris.Select(NormalizeOrigin)];
            allowedRedirectUris = [.. uris.Select(NormalizeRedirectUri)];
        }
    }

    public string[] GetAllowedCorsOrigins() => allowedCorsOrigins;

    // Check if the redirect_uri exactly matches one of the AllowedRedirectUris (RFC 9700, section 4.1.3)
    public bool IsAllowedRedirectUri(string redirectUri)
    {
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out Uri uri))
        {
            return false;
        }

        string address = NormalizeRedirectUri(uri);
        return allowedRedirectUris.Any(allowed => string.Equals(address, allowed, StringComparison.Ordinal));
    }

    public Uri Issuer { get; set; }

    private string[] encryptionKeys = [];
    public string[] EncryptionKeys
    {
        get => encryptionKeys;
        set { encryptionKeys = value ?? []; }
    }

    public IEnumerable<SymmetricSecurityKey> GetEncryptionKeys()
    {
        return encryptionKeys.Select(value => new SymmetricSecurityKey(Convert.FromBase64String(value)));
    }

    private string[] signingKeys = [];
    public string[] SigningKeys
    {
        get => signingKeys;
        set => signingKeys = value ?? [];
    }


    public IEnumerable<ECDsaSecurityKey> GetSigningKeys()
    {
        return signingKeys.Select(value =>
        {
            var key = ECDsa.Create();
            key.ImportECPrivateKey(Convert.FromBase64String(value), out int _);
            return new ECDsaSecurityKey(key);
        });
    }

    public string Domain { get; set; }

    public bool EncryptAccessToken { get; set; } = true;

    public bool UseDomain => !string.IsNullOrWhiteSpace(Domain);

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
