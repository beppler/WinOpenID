using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Security.Claims;
using System.Text.Json;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace WinOpenID.Tests;

public class WinOpenIDEndpointsTests : IClassFixture<WinOpenIDFactory>
{
    // PKCE S256 challenge of the verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" (RFC 7636, appendix B)
    private const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string CodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    private const string UserName = @"EXAMPLE\maria";

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

    private Task<HttpResponseMessage> AuthorizeAsWindowsUserAsync(string sid, Dictionary<string, string> overrides = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, AuthorizeUri(overrides));
        request.Headers.Add(WinOpenIDFactory.UserSidHeader, sid);
        request.Headers.Add(WinOpenIDFactory.UserNameHeader, UserName);
        return client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private Task<HttpResponseMessage> RedeemCodeAsync(string code, string codeVerifier = CodeVerifier)
        => client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            [Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [Parameters.ClientId] = WinOpenIDFactory.ClientId,
            [Parameters.RedirectUri] = WinOpenIDFactory.RedirectUri,
            [Parameters.Code] = code,
            [Parameters.CodeVerifier] = codeVerifier
        }), TestContext.Current.CancellationToken);

    private static Dictionary<string, StringValues> ParseRedirect(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Uri location = response.Headers.Location;
        Assert.Equal(WinOpenIDFactory.RedirectUri, location.GetLeftPart(UriPartial.Path));
        return QueryHelpers.ParseQuery(location.Query);
    }

    // Validates the signature, issuer, audience and lifetime of a token issued by the server
    private async Task<ClaimsIdentityResult> ValidateTokenAsync(string token, string audience)
    {
        var keys = new WinOpenIDOptions { SigningKeys = [factory.SigningKey], EncryptionKeys = [factory.EncryptionKey] };
        TokenValidationResult result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = WinOpenIDFactory.Issuer,
            ValidAudience = audience,
            IssuerSigningKeys = keys.GetSigningKeys(),
            TokenDecryptionKeys = keys.GetEncryptionKeys()
        });
        Assert.True(result.IsValid, result.Exception?.Message);
        return new ClaimsIdentityResult(result.ClaimsIdentity);
    }

    private sealed record ClaimsIdentityResult(ClaimsIdentity Identity)
    {
        public string Get(string type) => Assert.Single(Identity.FindAll(type)).Value;

        public string[] GetAll(string type) => [.. Identity.FindAll(type).Select(claim => claim.Value)];
    }

    [Fact]
    public async Task AuthorizationCodeFlow_IssuesTokensWithTheDirectoryClaims()
    {
        // Authorization request authenticated by Windows: the code is returned to the client application
        HttpResponseMessage response = await AuthorizeAsWindowsUserAsync(FakeUserDirectory.CompleteUser.Sid, new() { [Parameters.Scope] = "openid profile roles" });

        var query = ParseRedirect(response);
        Assert.Equal("state", query[Parameters.State]);
        string code = query[Parameters.Code];
        Assert.False(string.IsNullOrEmpty(code));
        Assert.Contains(factory.GetAuditLog(), record => record.Level == LogLevel.Information && record.Message.StartsWith("Authorization code issued"));

        // Code redeemed with the PKCE verifier
        response = await RedeemCodeAsync(code);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        JsonElement tokens = await ReadJsonAsync(response);
        Assert.Equal("Bearer", tokens.GetProperty(Parameters.TokenType).GetString());
        Assert.Equal("openid profile roles", tokens.GetProperty(Parameters.Scope).GetString());
        Assert.False(tokens.TryGetProperty(Parameters.RefreshToken, out _));
        Assert.Contains(factory.GetAuditLog(), record => record.Level == LogLevel.Information && record.Message.StartsWith("Tokens issued"));

        // The identity token is for the client application and has the profile claims
        ClaimsIdentityResult idToken = await ValidateTokenAsync(tokens.GetProperty(Parameters.IdToken).GetString(), WinOpenIDFactory.ClientId);
        Assert.Equal(FakeUserDirectory.CompleteUser.Sid, idToken.Get(Claims.Subject));
        Assert.Equal(UserName, idToken.Get(Claims.PreferredUsername));
        Assert.Equal("Maria da Silva", idToken.Get(Claims.Name));
        Assert.Equal("12345", idToken.Get(WinOpenIDClaims.EmployeeId));
        Assert.Equal(["Domain Users", "Developers"], idToken.GetAll(Claims.Role));
        Assert.Equal("nonce", idToken.Get(Claims.Nonce));

        // The access token (encrypted) is for the APIs and only has the identity claims
        ClaimsIdentityResult accessToken = await ValidateTokenAsync(tokens.GetProperty(Parameters.AccessToken).GetString(), "api");
        Assert.Equal(FakeUserDirectory.CompleteUser.Sid, accessToken.Get(Claims.Subject));
        Assert.Equal(UserName, accessToken.Get(Claims.PreferredUsername));
        Assert.Equal(WinOpenIDFactory.ClientId, accessToken.Get(Claims.ClientId));
        Assert.Empty(accessToken.GetAll(Claims.Name));
        Assert.Empty(accessToken.GetAll(Claims.Role));
    }

    [Fact]
    public async Task AuthorizationCodeFlow_WrongCodeVerifier_IsRejected()
    {
        HttpResponseMessage response = await AuthorizeAsWindowsUserAsync(FakeUserDirectory.CompleteUser.Sid);
        string code = ParseRedirect(response)[Parameters.Code];

        response = await RedeemCodeAsync(code, codeVerifier: "wrong-verifier-wrong-verifier-wrong-verifier-123");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(Errors.InvalidGrant, (await ReadJsonAsync(response)).GetProperty(Parameters.Error).GetString());
    }

    [Fact]
    public async Task Authorize_WindowsUserNotInDirectory_IsDenied()
    {
        HttpResponseMessage response = await AuthorizeAsWindowsUserAsync("S-1-5-21-1000-2000-3000-9999");

        Assert.Equal(Errors.AccessDenied, ParseRedirect(response)[Parameters.Error]);
        Assert.Contains(factory.GetAuditLog(), record => record.Level == LogLevel.Warning && record.Message.Contains("was not found in the directory"));
    }

    [Fact]
    public async Task Authorize_ValidRequestWithoutWindowsUser_ChallengesNegotiate()
    {
        HttpResponseMessage response = await client.GetAsync(AuthorizeUri(), TestContext.Current.CancellationToken);

        // The authorization code is only issued after the Windows authentication
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(["Negotiate"], response.Headers.WwwAuthenticate.Select(header => header.Scheme));
        Assert.Null(response.Headers.Location);
        Assert.Empty(factory.GetAuditLog());
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
