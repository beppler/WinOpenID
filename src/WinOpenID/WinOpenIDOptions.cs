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

    public string Domain { get; set; }

    public bool EncryptAccessToken { get; set; } = true;

    public bool UseDomain => !string.IsNullOrWhiteSpace(Domain);

    private static string NormalizeOrigin(Uri uri)
        => uri.GetLeftPart(UriPartial.Authority);

    private static string NormalizeRedirectUri(Uri uri)
        => uri.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.Unescaped);
}
