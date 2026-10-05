using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace WinOpenID;

public class WinOpenIDOptions
{
    public const string Server = nameof(Server);

    private Dictionary<string, WinOpenIDClientOptions> clients = new(StringComparer.Ordinal);
    public Dictionary<string, WinOpenIDClientOptions> Clients
    {
        get => clients;
        set => clients = value ?? new(StringComparer.Ordinal);
    }

    public bool TryGetClient(string clientId, out WinOpenIDClientOptions client)
    {
        if (string.IsNullOrEmpty(clientId))
        {
            client = null;
            return false;
        }

        return clients.TryGetValue(clientId, out client) && client != null;
    }

    public string[] GetAllowedCorsOrigins()
        => [.. clients.Values.Where(client => client != null).SelectMany(client => client.GetAllowedCorsOrigins()).Distinct(StringComparer.Ordinal)];

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

    public bool EncryptAccessToken { get; set; } = true;

    public string Domain { get; set; }

    public bool UseDomain => !string.IsNullOrWhiteSpace(Domain);
}
