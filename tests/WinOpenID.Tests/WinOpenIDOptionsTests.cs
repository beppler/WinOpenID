namespace WinOpenID.Tests;

public class WinOpenIDOptionsTests
{
    private static WinOpenIDClientOptions CreateClient(params string[] redirectUris)
        => new() { RedirectUris = redirectUris };

    [Fact]
    public void Clients_Null_IsEmpty()
    {
        var options = new WinOpenIDOptions { Clients = null };

        Assert.Empty(options.Clients);
        Assert.False(options.TryGetClient("client", out _));
    }

    [Fact]
    public void TryGetClient_FindsRegisteredClient()
    {
        WinOpenIDClientOptions client = CreateClient("https://client.example/callback");
        var options = new WinOpenIDOptions { Clients = new() { ["client"] = client } };

        Assert.True(options.TryGetClient("client", out WinOpenIDClientOptions found));
        Assert.Same(client, found);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("unknown")]
    [InlineData("CLIENT")]
    [InlineData("empty")]
    public void TryGetClient_RejectsUnknownClients(string clientId)
    {
        var options = new WinOpenIDOptions
        {
            Clients = new() { ["client"] = CreateClient("https://client.example/callback"), ["empty"] = null }
        };

        Assert.False(options.TryGetClient(clientId, out WinOpenIDClientOptions client));
        Assert.Null(client);
    }

    [Fact]
    public void GetAllowedCorsOrigins_CombinesClientsWithoutDuplicates()
    {
        var options = new WinOpenIDOptions
        {
            Clients = new()
            {
                ["a"] = CreateClient("https://a.example/callback", "https://shared.example/a"),
                ["b"] = CreateClient("https://shared.example/b"),
                ["empty"] = null
            }
        };

        Assert.Equal(["https://a.example", "https://shared.example"], options.GetAllowedCorsOrigins());
    }

    [Fact]
    public void Keys_Null_AreEmpty()
    {
        var options = new WinOpenIDOptions { EncryptionKeys = null, SigningKeys = null };

        Assert.Empty(options.EncryptionKeys);
        Assert.Empty(options.GetEncryptionKeys());
        Assert.Empty(options.SigningKeys);
        Assert.Empty(options.GetSigningKeys());
    }

    [Fact]
    public void GetEncryptionKeys_DecodesBase64Keys()
    {
        var options = new WinOpenIDOptions { EncryptionKeys = [TestKeys.CreateEncryptionKey(), TestKeys.CreateEncryptionKey()] };

        Assert.All(options.GetEncryptionKeys(), key => Assert.Equal(256, key.KeySize));
        Assert.Equal(2, options.GetEncryptionKeys().Count());
    }

    [Fact]
    public void GetSigningKeys_ImportsEcPrivateKeys()
    {
        var options = new WinOpenIDOptions { SigningKeys = [TestKeys.CreateSigningKey()] };

        var key = Assert.Single(options.GetSigningKeys());
        Assert.Equal(384, key.KeySize);
        Assert.NotNull(key.ECDsa.ExportParameters(includePrivateParameters: true).D);
    }

    [Fact]
    public void GetKeys_RejectInvalidBase64()
    {
        var options = new WinOpenIDOptions { EncryptionKeys = ["not base64!"], SigningKeys = ["not base64!"] };

        Assert.Throws<FormatException>(() => options.GetEncryptionKeys().ToList());
        Assert.Throws<FormatException>(() => options.GetSigningKeys().ToList());
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData(" ", false)]
    [InlineData("my.ad.domain.com", true)]
    public void UseDomain_DependsOnDomain(string domain, bool expected)
    {
        var options = new WinOpenIDOptions { Domain = domain };

        Assert.Equal(expected, options.UseDomain);
    }

    [Fact]
    public void EncryptAccessToken_IsEnabledByDefault()
    {
        Assert.True(new WinOpenIDOptions().EncryptAccessToken);
    }
}
