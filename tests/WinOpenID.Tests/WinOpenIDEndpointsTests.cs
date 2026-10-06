using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Text.Json;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace WinOpenID.Tests;

public class WinOpenIDEndpointsTests : IClassFixture<WinOpenIDFactory>
{
    // PKCE S256 challenge of the verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" (RFC 7636, appendix B)
    private const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private readonly WinOpenIDFactory factory;
    private readonly HttpClient client;

    public WinOpenIDEndpointsTests(WinOpenIDFactory factory)
    {
        this.factory = factory;
        client = factory.CreateClient();
        factory.LoggerProvider.Collector.Clear();
    }

    private static string AuthorizeUri(Dictionary<string, string> overrides = null)
    {
        var parameters = new Dictionary<string, string>
        {
            [Parameters.ClientId] = WinOpenIDFactory.ClientId,
            [Parameters.RedirectUri] = WinOpenIDFactory.RedirectUri,
            [Parameters.ResponseType] = ResponseTypes.Code,
            [Parameters.Scope] = "openid profile",
            [Parameters.State] = "state",
            [Parameters.Nonce] = "nonce",
            [Parameters.CodeChallenge] = CodeChallenge,
            [Parameters.CodeChallengeMethod] = CodeChallengeMethods.Sha256
        };

        foreach ((string name, string value) in overrides ?? [])
        {
            if (value == null)
            {
                parameters.Remove(name);
            }
            else
            {
                parameters[name] = value;
            }
        }

        return QueryHelpers.AddQueryString("/connect/authorize", parameters);
    }

    private static async Task<JsonElement> ReadJsonAsync(HttpResponseMessage response)
        => JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    private static string[] ReadStrings(JsonElement element, string name)
        => [.. element.GetProperty(name).EnumerateArray().Select(item => item.GetString())];

    // OpenIddict returns the errors of the validation of authorization requests as a plain-text document,
    // without redirecting to the client application (the redirect_uri is only trusted after the validation)
    private static async Task<string> GetPlainTextErrorAsync(HttpResponseMessage response, HttpStatusCode statusCode = HttpStatusCode.BadRequest)
    {
        Assert.Equal(statusCode, response.StatusCode);
        Assert.Null(response.Headers.Location);
        string content = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return content.Split('\n').Select(line => line.Trim()).Single(line => line.StartsWith("error:"))["error:".Length..];
    }

    private void AssertAuditWarning(string error)
    {
        Assert.Contains(factory.GetAuditLog(), record => record.Level == LogLevel.Warning && record.Message.Contains(error));
    }

    [Fact]
    public async Task Root_RedirectsToDiscoveryDocument()
    {
        HttpResponseMessage response = await client.GetAsync("/", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal(".well-known/openid-configuration/", response.Headers.Location?.OriginalString);
    }

    [Fact]
    public async Task DiscoveryDocument_AdvertisesOnlySupportedFeatures()
    {
        HttpResponseMessage response = await client.GetAsync("/.well-known/openid-configuration", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        JsonElement document = await ReadJsonAsync(response);
        Assert.Equal(WinOpenIDFactory.Issuer, document.GetProperty(Metadata.Issuer).GetString());
        Assert.Equal("https://localhost/connect/authorize", document.GetProperty(Metadata.AuthorizationEndpoint).GetString());
        Assert.Equal("https://localhost/connect/token", document.GetProperty(Metadata.TokenEndpoint).GetString());
        Assert.Equal([CodeChallengeMethods.Sha256], ReadStrings(document, Metadata.CodeChallengeMethodsSupported));
        Assert.Equal([ResponseModes.FormPost, ResponseModes.Query], ReadStrings(document, Metadata.ResponseModesSupported).Order());
        Assert.Equal([ResponseTypes.Code], ReadStrings(document, Metadata.ResponseTypesSupported));
        Assert.Contains(GrantTypes.AuthorizationCode, ReadStrings(document, Metadata.GrantTypesSupported));
        Assert.DoesNotContain(GrantTypes.Implicit, ReadStrings(document, Metadata.GrantTypesSupported));
        Assert.Equal(["none"], ReadStrings(document, Metadata.TokenEndpointAuthMethodsSupported));
        Assert.Equal(
            [Scopes.Email, Scopes.OpenId, Scopes.Phone, Scopes.Profile, Scopes.Roles],
            ReadStrings(document, Metadata.ScopesSupported).Order());
        Assert.False(document.TryGetProperty(Metadata.PromptValuesSupported, out JsonElement prompts) && prompts.GetArrayLength() > 0);
    }

    [Fact]
    public async Task DiscoveryDocument_PublishesSigningKeys()
    {
        HttpResponseMessage response = await client.GetAsync("/.well-known/jwks", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        JsonElement key = Assert.Single((await ReadJsonAsync(response)).GetProperty("keys").EnumerateArray());
        Assert.Equal("EC", key.GetProperty("kty").GetString());
        Assert.False(key.TryGetProperty("d", out _));
    }

    [Fact]
    public async Task Authorize_UnknownClient_IsRejected()
    {
        HttpResponseMessage response = await client.GetAsync(
            AuthorizeUri(new() { [Parameters.ClientId] = "unknown" }), TestContext.Current.CancellationToken);

        Assert.Equal(Errors.InvalidClient, await GetPlainTextErrorAsync(response, HttpStatusCode.Unauthorized));
        AssertAuditWarning(Errors.InvalidClient);
    }

    [Theory]
    [InlineData("https://evil.example/callback")]
    [InlineData("https://client.example/callback/")]
    [InlineData("https://client.example/callback?x=1")]
    public async Task Authorize_UnregisteredRedirectUri_IsRejected(string redirectUri)
    {
        HttpResponseMessage response = await client.GetAsync(
            AuthorizeUri(new() { [Parameters.RedirectUri] = redirectUri }), TestContext.Current.CancellationToken);

        Assert.Equal(Errors.InvalidRequest, await GetPlainTextErrorAsync(response));
        AssertAuditWarning(Errors.InvalidRequest);
    }

    [Fact]
    public async Task Authorize_ScopeNotAllowedForClient_IsRejected()
    {
        HttpResponseMessage response = await client.GetAsync(
            AuthorizeUri(new() { [Parameters.Scope] = "openid email" }), TestContext.Current.CancellationToken);

        Assert.Equal(Errors.InvalidScope, await GetPlainTextErrorAsync(response));
        AssertAuditWarning(Errors.InvalidScope);
    }

    [Fact]
    public async Task Authorize_WithoutPkce_IsRejected()
    {
        HttpResponseMessage response = await client.GetAsync(
            AuthorizeUri(new() { [Parameters.CodeChallenge] = null, [Parameters.CodeChallengeMethod] = null }), TestContext.Current.CancellationToken);

        Assert.Equal(Errors.InvalidRequest, await GetPlainTextErrorAsync(response));
        AssertAuditWarning(Errors.InvalidRequest);
    }

    [Fact]
    public async Task Authorize_PlainPkce_IsRejected()
    {
        HttpResponseMessage response = await client.GetAsync(
            AuthorizeUri(new() { [Parameters.CodeChallengeMethod] = CodeChallengeMethods.Plain }), TestContext.Current.CancellationToken);

        Assert.Equal(Errors.InvalidRequest, await GetPlainTextErrorAsync(response));
    }

    [Theory]
    [InlineData(Parameters.ResponseType, ResponseTypes.Token)]
    [InlineData(Parameters.ResponseType, "code id_token")]
    [InlineData(Parameters.ResponseMode, ResponseModes.Fragment)]
    public async Task Authorize_UnsupportedResponseTypeOrMode_IsRejected(string parameter, string value)
    {
        HttpResponseMessage response = await client.GetAsync(
            AuthorizeUri(new() { [parameter] = value }), TestContext.Current.CancellationToken);

        Assert.NotEmpty(await GetPlainTextErrorAsync(response));
        Assert.Contains(factory.GetAuditLog(), record => record.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task Authorize_PromptParameter_IsRejected()
    {
        HttpResponseMessage response = await client.GetAsync(
            AuthorizeUri(new() { [Parameters.Prompt] = "login" }), TestContext.Current.CancellationToken);

        Assert.NotEmpty(await GetPlainTextErrorAsync(response));
    }

    [Theory]
    [InlineData(GrantTypes.ClientCredentials)]
    [InlineData(GrantTypes.Password)]
    [InlineData(GrantTypes.RefreshToken)]
    public async Task Token_UnsupportedGrantType_IsRejected(string grantType)
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            [Parameters.GrantType] = grantType,
            [Parameters.ClientId] = WinOpenIDFactory.ClientId,
            [Parameters.Username] = "user",
            [Parameters.Password] = "password",
            [Parameters.RefreshToken] = "token"
        });

        HttpResponseMessage response = await client.PostAsync("/connect/token", content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(Errors.UnsupportedGrantType, (await ReadJsonAsync(response)).GetProperty(Parameters.Error).GetString());
        AssertAuditWarning(Errors.UnsupportedGrantType);
    }

    [Fact]
    public async Task Token_InvalidCode_IsRejected()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            [Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [Parameters.ClientId] = WinOpenIDFactory.ClientId,
            [Parameters.RedirectUri] = WinOpenIDFactory.RedirectUri,
            [Parameters.Code] = "invalid-code",
            [Parameters.CodeVerifier] = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        });

        HttpResponseMessage response = await client.PostAsync("/connect/token", content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(Errors.InvalidGrant, (await ReadJsonAsync(response)).GetProperty(Parameters.Error).GetString());
        // The audit handler runs before OpenIddict replaces the internal "invalid_token" error by "invalid_grant"
        AssertAuditWarning("The specified authorization code is invalid.");
        Assert.DoesNotContain(factory.GetAuditLog(), record => record.Message.Contains("invalid-code"));
    }

    [Fact]
    public async Task Token_UnknownClient_IsRejected()
    {
        var content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            [Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [Parameters.ClientId] = "unknown",
            [Parameters.Code] = "invalid-code",
            [Parameters.CodeVerifier] = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        });

        HttpResponseMessage response = await client.PostAsync("/connect/token", content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        AssertAuditWarning("unknown");
    }

    [Fact]
    public async Task Cors_AllowsRegisteredOrigins()
    {
        HttpResponseMessage response = await SendPreflightAsync(WinOpenIDFactory.ClientOrigin);

        Assert.Equal([WinOpenIDFactory.ClientOrigin], response.Headers.GetValues("Access-Control-Allow-Origin"));
    }

    [Theory]
    [InlineData("https://evil.example")]
    [InlineData("http://client.example")]
    [InlineData("https://client.example:8443")]
    public async Task Cors_RejectsOtherOrigins(string origin)
    {
        HttpResponseMessage response = await SendPreflightAsync(origin);

        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    private Task<HttpResponseMessage> SendPreflightAsync(string origin)
    {
        var request = new HttpRequestMessage(HttpMethod.Options, "/connect/token");
        request.Headers.Add("Origin", origin);
        request.Headers.Add("Access-Control-Request-Method", "POST");
        return client.SendAsync(request, TestContext.Current.CancellationToken);
    }
}
