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
            allowedCorsOrigins = [.. value.Select(x => NormalizeOrigin(new Uri(x)))];
            allowedRedirectUris = [.. value.Select(x => NormalizeRedirectUri(new Uri(x)))];
        }
    }

    public string[] GetAllowedCorsOrigins() => allowedCorsOrigins;

    // Check if the scheme, server and path of the redirect_uri are whitelisted on AllowedHosts
    public bool IsAllowedRedirectUri(string redirectUri)
    {
        if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out Uri uri))
        {
            return false;
        }

        string address = NormalizeRedirectUri(uri);
        return allowedRedirectUris.Any(allowed => string.Equals(address, allowed, StringComparison.OrdinalIgnoreCase));
    }

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

    private static string NormalizeRedirectUri(Uri uri)
        => uri.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.Unescaped);
}
