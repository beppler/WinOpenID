using System.Security.Cryptography;

namespace WinOpenID.Tests;

// Keys generated for the tests, in the same format of the configuration (Base64)
internal static class TestKeys
{
    public static string CreateEncryptionKey()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    public static string CreateSigningKey()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        return Convert.ToBase64String(key.ExportECPrivateKey());
    }
}
