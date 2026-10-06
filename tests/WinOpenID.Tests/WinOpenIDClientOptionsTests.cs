namespace WinOpenID.Tests;

public class WinOpenIDClientOptionsTests
{
    [Theory]
    [InlineData("https://client.example/callback")]
    [InlineData("http://127.0.0.1:5000/callback")]
    [InlineData("http://[::1]:5000/callback")]
    [InlineData("http://localhost:5000/callback")]
    public void RedirectUris_AcceptsHttpsAndLoopbackHttp(string redirectUri)
    {
        var client = new WinOpenIDClientOptions { RedirectUris = [redirectUri] };

        Assert.Equal([new Uri(redirectUri).AbsoluteUri], client.RedirectUris);
    }

    [Theory]
    [InlineData("http://client.example/callback")]
    [InlineData("ftp://client.example/callback")]
    [InlineData("https://client.example/callback#fragment")]
    public void RedirectUris_RejectsInsecureSchemesAndFragments(string redirectUri)
    {
        var client = new WinOpenIDClientOptions();

        Assert.Throws<ArgumentException>(() => client.RedirectUris = [redirectUri]);
    }

    [Fact]
    public void RedirectUris_RejectsRelativeUris()
    {
        var client = new WinOpenIDClientOptions();

        Assert.Throws<UriFormatException>(() => client.RedirectUris = ["callback"]);
    }

    [Fact]
    public void RedirectUris_Null_ClearsRedirectUrisAndCorsOrigins()
    {
        var client = new WinOpenIDClientOptions { RedirectUris = ["https://client.example/callback"] };

        client.RedirectUris = null;

        Assert.Empty(client.RedirectUris);
        Assert.Empty(client.GetAllowedCorsOrigins());
    }

    [Fact]
    public void GetAllowedCorsOrigins_ReturnsNormalizedOrigins()
    {
        var client = new WinOpenIDClientOptions
        {
            RedirectUris = ["https://CLIENT.example:443/callback?x=1", "https://other.example:8443/callback", "http://localhost:5000/callback"]
        };

        Assert.Equal(["https://client.example", "https://other.example:8443", "http://localhost:5000"], client.GetAllowedCorsOrigins());
    }

    [Theory]
    [InlineData("https://client.example/callback")]
    [InlineData("https://CLIENT.EXAMPLE/callback")]
    [InlineData("https://client.example:443/callback")]
    public void IsAllowedRedirectUri_AcceptsEquivalentUris(string redirectUri)
    {
        var client = new WinOpenIDClientOptions { RedirectUris = ["https://client.example/callback"] };

        Assert.True(client.IsAllowedRedirectUri(redirectUri));
    }

    [Theory]
    [InlineData("https://client.example/callback/")]
    [InlineData("https://client.example/CALLBACK")]
    [InlineData("https://client.example/callback?x=1")]
    [InlineData("https://client.example:8443/callback")]
    [InlineData("http://client.example/callback")]
    [InlineData("https://evil.example/callback")]
    [InlineData("/callback")]
    [InlineData("not a uri")]
    [InlineData("")]
    [InlineData(null)]
    public void IsAllowedRedirectUri_RejectsOtherUris(string redirectUri)
    {
        var client = new WinOpenIDClientOptions { RedirectUris = ["https://client.example/callback"] };

        Assert.False(client.IsAllowedRedirectUri(redirectUri));
    }

    [Fact]
    public void Audiences_Null_IsEmpty()
    {
        var client = new WinOpenIDClientOptions { Audiences = null };

        Assert.Empty(client.Audiences);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(null)]
    public void Audiences_RejectsEmptyValues(string audience)
    {
        var client = new WinOpenIDClientOptions();

        Assert.Throws<ArgumentException>(() => client.Audiences = ["api", audience]);
    }

    [Fact]
    public void Scopes_Null_IsEmpty()
    {
        var client = new WinOpenIDClientOptions { Scopes = null };

        Assert.Empty(client.Scopes);
    }

    [Theory]
    [InlineData("offline_access")]
    [InlineData("address")]
    [InlineData("OpenID")]
    public void Scopes_RejectsUnsupportedScopes(string scope)
    {
        var client = new WinOpenIDClientOptions();

        Assert.Throws<ArgumentException>(() => client.Scopes = ["openid", scope]);
    }

    [Fact]
    public void IsAllowedScope_OnlyAcceptsConfiguredScopes()
    {
        var client = new WinOpenIDClientOptions { Scopes = ["openid", "profile", "email", "phone", "roles"] };
        var restricted = new WinOpenIDClientOptions { Scopes = ["openid"] };

        Assert.True(client.IsAllowedScope("roles"));
        Assert.True(restricted.IsAllowedScope("openid"));
        Assert.False(restricted.IsAllowedScope("profile"));
        Assert.False(restricted.IsAllowedScope("OPENID"));
    }
}
