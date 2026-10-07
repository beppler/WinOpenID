# WinOpenID

[Português](README.md) | **English**

Simple OpenID Connect server with Windows integrated authentication.

WinOpenID uses [OpenIddict](https://documentation.openiddict.com/) in *degraded mode* (no database: clients are registered in the configuration itself and users come from the directory) to issue OpenID Connect tokens from Windows integrated authentication (Negotiate: Kerberos/NTLM).

User data (name, e-mail, phone, groups etc.) is retrieved from Active Directory or from the machine's local accounts through `System.DirectoryServices.AccountManagement`.

## Requirements

- Windows (the project targets `net10.0-windows`).
- [.NET 10 SDK](https://dotnet.microsoft.com/download).
- Windows authentication enabled on the web server: Kestrel (already configured via `AddNegotiate()`), IIS or IIS Express (see `src/WinOpenID/Properties/launchSettings.json`).
- To use domain accounts, the machine must be joined to the Active Directory domain.

## Running

```shell
dotnet run --project src/WinOpenID
```

The `WinOpenID` profile listens on `https://localhost:5001` and `http://localhost:5000`, with `ASPNETCORE_ENVIRONMENT=Development`. There is also an `IIS Express` profile.

The root address (`/`) redirects to the OpenID Connect discovery document.

## Endpoints

| Endpoint | Description |
|---|---|
| `/.well-known/openid-configuration` | OpenID Connect discovery document. |
| `/.well-known/jwks` | Public keys used to validate the token signatures. |
| `/connect/authorize` | Authorization endpoint: authenticates the user via Windows and issues the *authorization code*. |
| `/connect/token` | Token endpoint: exchanges the *authorization code* for the tokens. |

## Supported flow

- Only **Authorization Code** with **mandatory PKCE**, accepting only the `S256` method (the `plain` method is rejected).
- Clients are public, without client authentication (`client_secret`), but they must be registered in `Clients`. Since the *authorization code* is only delivered to the redirect URIs registered for the `client_id`, the `client_id` in the tokens identifies the application. See [Clients](#clients).
- The *authorization code* is valid for only 1 minute. Since the server has no database, it cannot record that a code has already been used, and the same code can be exchanged for tokens more than once within that period (PKCE requires the *code verifier* on each exchange).
- The `prompt` parameter is not supported: Windows integrated authentication does not allow forcing a new login nor guaranteeing authentication without user interaction. Clients must not send it.
- The *implicit flow* and the other *grant types* (`client_credentials`, `password`, `refresh_token` etc.) are not supported.

## Scopes and claims

The supported scopes are `openid`, `profile`, `email`, `phone` and `roles`. Each client can only request the scopes allowed in its registration, including `openid`. The issued claims depend on the requested scopes:

| Scope | Claims | Token |
|---|---|---|
| *(always)* | `sub`, `username`, `preferred_username` | ID token and access token |
| `profile` | `name`, `given_name`, `family_name`, `employee_id` | ID token |
| `email` | `email`, `email_verified` | ID token |
| `phone` | `phone_number`, `phone_number_verified` | ID token |
| `roles` | `role` (one for each of the user's security groups, including nested groups) | ID token |

Claims whose corresponding attribute is empty in the directory (for example, a user without a display name or without a phone number) are not issued.

## Configuration

The server options are in the `Server` section of the ASP.NET Core configuration. They are usually defined in the `appsettings.json` / `appsettings.{Environment}.json` files, but can be provided by any standard configuration source, such as environment variables or the command line:

```shell
# Environment variables (arrays use the index as the key)
set AllowedHosts=identity.example.com
set Server__Domain=my.ad.domain.com
set Server__Issuer=https://identity.example.com/
set Server__Clients__app__RedirectUris__0=https://app.example.com/callback
set Server__Clients__app__Scopes__0=openid
set Server__Clients__app__Scopes__1=profile
set Server__Clients__app__Audiences__0=https://api.example.com
set Server__SigningKeys__0=MIGkAgEBBDD...
set Server__EncryptionKeys__0=q2Vx...

# Command line
dotnet WinOpenID.dll --Server:Domain=my.ad.domain.com
```

### Options

| Option | Type | Default | Description |
|---|---|---|---|
| `Clients` | `object` | `{}` | Registered clients, keyed by `client_id`, with the redirect URIs and allowed scopes of each one. See [Clients](#clients). |
| `Domain` | `string` | *(empty)* | Active Directory domain where users are looked up. If empty, the machine's local accounts are used. |
| `EncryptionKeys` | `string[]` | `[]` | **Required.** Symmetric keys used to encrypt the tokens. See [Encryption keys](#encryption-keys). |
| `EncryptAccessToken` | `bool` | `true` | Whether the *access token* should be encrypted. With `false`, the *access token* is issued as a signed-only JWT, which can be read and validated by third-party APIs. |
| `Issuer` | `Uri` | *(empty)* | Public address of the server, used as the `iss` of the tokens and as the base of the discovery document URLs. Recommended in production. See [Issuer and allowed hosts](#issuer-and-allowed-hosts). |
| `SigningKeys` | `string[]` | `[]` | **Required.** ECDSA private keys used to sign the tokens. See [Signing keys](#signing-keys). |

### Clients

Each client is registered in `Clients`, using the `client_id` as the key (the comparison is case-sensitive):

```json
{
  "Server": {
    "Clients": {
      "app": {
        "RedirectUris": [ "https://app.example.com/callback" ],
        "Scopes": [ "openid", "profile", "roles" ],
        "Audiences": [ "https://api.example.com" ]
      }
    }
  }
}
```

| Option | Type | Default | Description |
|---|---|---|---|
| `RedirectUris` | `string[]` | `[]` | Redirect URIs (`redirect_uri`) allowed for the client. |
| `Scopes` | `string[]` | `[]` | Scopes the client can request, among `openid`, `profile`, `email`, `phone` and `roles`. Without `openid`, the client does not receive the ID token. An unsupported scope prevents the server from starting. |
| `Audiences` | `string[]` | `[]` | Audiences (`aud`) of the *access tokens* issued to the client, usually the identifiers of the APIs it accesses. See [Access token audience](#access-token-audience). |

Requests with an unregistered `client_id` are rejected with `invalid_client`, and requests with scopes not allowed for the client, with `invalid_scope`.

#### Access token audience

A client's *access token* is issued with the `aud` claim containing all the audiences in `Audiences`. Without configured audiences, the *access token* is issued without `aud`. The ID token always has the `client_id` as `aud`, as defined by OpenID Connect.

The same API can be authorized for several clients: just include its identifier in the `Audiences` of each one. Each API must validate its own audience and accept only *access tokens*, rejecting ID tokens. For example, with ASP.NET Core's `JwtBearer`:

```csharp
builder.Services.AddAuthentication().AddJwtBearer(options =>
{
    options.Authority = "https://identity.example.com/";
    options.Audience = "https://api.example.com";
    options.TokenValidationParameters.ValidTypes = ["at+jwt"];
});
```

The *access token* has `typ` `at+jwt` in its header and the ID token, `JWT`. This example assumes `EncryptAccessToken` set to `false`; with an encrypted *access token*, the API needs the encryption key, and OpenIddict validation (`AddValidation` with `AddAudiences`) is the simplest path.

#### Redirect URIs and CORS

A request is only accepted if the provided `redirect_uri` is exactly equal to one of the URIs in the client's `RedirectUris`, as required by the [OAuth 2.0 Security BCP (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700) and OAuth 2.1. The comparison includes the path and the *query string* and is case-sensitive in the path; only the scheme and the host are compared case-insensitively, and the default port is ignored. For example, with `https://app.example.com/callback` configured:

- `https://app.example.com/callback` and `https://APP.example.com:443/callback` are accepted;
- `https://app.example.com/callback?x=1`, `https://app.example.com/Callback`, `https://app.example.com/callback/` and `http://app.example.com/callback` are rejected.

If a client needs parameters in the redirect URI, the full URI, with the *query string*, must be configured. This prevents an attacker from appending parameters to the `redirect_uri` to try to divert the *authorization code* through the application's callback page.

The configured URIs must be absolute, cannot have a fragment (`#...`) and must use `https`; `http` is only accepted on *loopback* addresses (`localhost`, `127.0.0.1`, `[::1]`). An invalid URI prevents the server from starting.

The origins (scheme, host and port) of the URIs of all clients are also allowed in CORS for `GET` and `POST` requests, allowing SPA applications to access the token endpoint, the discovery document and the public key set (JWKS).

### Issuer and allowed hosts

When `Issuer` is not configured, OpenIddict infers the issuer from the `Host` header of each request. A request with a forged `Host` makes the discovery document advertise endpoints on another server and changes the `iss` of the issued tokens. In production, configure the public address of the server:

```json
{
  "AllowedHosts": "identity.example.com",
  "Server": {
    "Issuer": "https://identity.example.com/"
  }
}
```

As an additional layer, the ASP.NET Core `AllowedHosts` option (outside the `Server` section) causes requests whose `Host` is not in the list to be rejected with `400 Bad Request`. It accepts multiple hosts separated by `;` and subdomain wildcards (`*.example.com`), and ignores the port. Without the option, or with `*`, any host is accepted. See [Host filtering](https://learn.microsoft.com/aspnet/core/fundamentals/servers/kestrel/host-filtering).

`appsettings.Development.json` allows only `localhost` and does not define `Issuer`, so that the `WinOpenID` and `IIS Express` profiles work on their respective ports.

### Domain and user identifier

The `Domain` option defines where the authenticated user's data is looked up and also the value of the `sub` claim:

| `Domain` | User source | `sub` value |
|---|---|---|
| empty | Machine's local accounts | User SID |
| set | Active Directory of the given domain | User object GUID in AD |

The authenticated user is located by their SID, not by name. Therefore, they must belong to the configured domain (or be a local machine account, when `Domain` is empty). Users from other domains, even trusted ones, and domain users when `Domain` is empty are rejected with `access_denied`.


### Signing keys

The `SigningKeys` keys are elliptic curve (ECDSA) private keys in EC format (SEC 1, DER) encoded in Base64. They can be generated, for example, with:

```shell
openssl ecparam -name secp384r1 -genkey -noout -outform DER | openssl base64 -A
```

```powershell
# PowerShell 7 or later (Windows PowerShell 5.1 does not have ExportECPrivateKey)
[Convert]::ToBase64String([Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP384).ExportECPrivateKey())
```

The examples use the P-384 curve. The P-256 and P-521 curves are also accepted, named `prime256v1` and `secp521r1` in OpenSSL and `nistP256` and `nistP521` in .NET.

More than one key can be provided for rotation: the first one is used to sign new tokens and all of them are published at `/.well-known/jwks`, so tokens signed with previous keys remain valid.

### Encryption keys

The `EncryptionKeys` keys are Base64-encoded symmetric keys of 256 bits (32 bytes). They protect the *authorization code* and, when `EncryptAccessToken` is `true`, the *access token*. They can be generated, for example, with:

```shell
openssl rand -base64 32
```

```powershell
[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

As with the signing keys, the first key is used for encryption and the others are used only for decryption, allowing rotation.

### Required keys

At least one key must be configured in `SigningKeys` and one in `EncryptionKeys`, otherwise the server raises a configuration error.

Since the keys are fixed, issued tokens remain valid after restarts and can be shared across multiple server instances.

> **Warning:** the keys in `appsettings.Development.json` are public and are meant for development only. In production, generate new keys and keep them out of version control (environment variables, *user secrets*, secret vault etc.). The `appsettings.*.json` files are not copied on publish (`CopyToPublishDirectory="Never"` in `WinOpenID.csproj`).

### Configuration example

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Warning"
    }
  },
  "AllowedHosts": "identity.example.com",
  "Server": {
    "Clients": {
      "app": {
        "RedirectUris": [ "https://app.example.com/callback" ],
        "Scopes": [ "openid", "profile", "roles" ],
        "Audiences": [ "https://api.example.com" ]
      }
    },
    "Domain": "my.ad.domain.com",
    "Issuer": "https://identity.example.com/",
    "SigningKeys": [
      "<Base64 ECDSA key>"
    ],
    "EncryptionKeys": [
      "<Base64 32-byte symmetric key>"
    ],
    "EncryptAccessToken": true
  }
}
```

The `Logging` section follows the [standard ASP.NET Core logging configuration](https://learn.microsoft.com/aspnet/core/fundamentals/logging/).

### Auditing

The server logs issuances and rejections under the `WinOpenID.Audit` log category:

| Event | Level | Fields |
|---|---|---|
| *Authorization code* issued | `Information` | user, `sub`, `client_id`, `redirect_uri`, scopes, audiences, source IP and port |
| Tokens issued (*authorization code* exchange) | `Information` | user, `sub`, `client_id`, scopes, audiences, source IP and port |
| Authorization request rejected | `Warning` | `client_id`, `redirect_uri`, scopes, `error`, `error_description`, source IP and port |
| Token request rejected | `Warning` | `client_id`, `grant_type`, `error`, `error_description`, source IP and port |
| User authenticated by Windows not found in the directory | `Warning` | Windows name, SID, `client_id`, source IP and port |

The source address is logged with the port (for example `203.0.113.10:51234` or `[2001:db8::1]:51234`), because many internet service providers share the same public IP among several customers (CGNAT), distinguishing them by port range. To identify a customer in these cases, the provider usually requires the IP, the port and the exact time of the connection, so the logging provider must record the time of each event. If the server is behind a reverse proxy or load balancer, the logged address is the proxy's, unless the [Forwarded Headers Middleware](https://learn.microsoft.com/aspnet/core/host-and-deploy/proxy-load-balancer) is configured; and even then the port is only available if the proxy forwards it.

Rejections include both those made by WinOpenID (unregistered client, `redirect_uri` or scope not allowed) and those made by OpenIddict (expired *authorization code*, invalid *code verifier* etc.). Since the same *authorization code* can be exchanged more than once within its validity period, two token issuance events for the same user and client less than 1 minute apart may indicate code reuse. *Authorization codes*, tokens, *code verifiers* and keys are never logged.

The category can be enabled in production without enabling the other logs at `Information`:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Warning",
      "WinOpenID.Audit": "Information"
    }
  }
}
```

In IIS and in the Windows service the console output is discarded. On Windows, ASP.NET Core already registers the *EventLog* provider, which by default writes only `Warning` or above to the *Application* log in Event Viewer (in the Windows service, with the `WinOpenID` source; see [Windows service](#windows-service)). To also write the issuance events:

```json
{
  "Logging": {
    "EventLog": {
      "LogLevel": {
        "WinOpenID.Audit": "Information"
      }
    }
  }
}
```

Any other logging provider compatible with ASP.NET Core can also be used.

> **Warning:** audit logs contain personal data (login name, IP address and port) and must follow the organization's data retention and protection policy.

## Deployment

The server can be deployed in two ways:

- **Windows service**: the executable itself, with Kestrel, runs as a service and serves the HTTPS requests directly. It does not depend on IIS.
- **IIS**: the server runs inside an IIS *Application Pool*, which handles HTTPS and Windows authentication.

In both cases, use the server's public address in `Issuer` and `AllowedHosts` (see [Issuer and allowed hosts](#issuer-and-allowed-hosts)) and configure the keys, the clients and `Domain` before starting the server.

### Publishing

```shell
dotnet publish src/WinOpenID -c Release -o C:\WinOpenID
```

The publish folder contains `WinOpenID.exe`, `WinOpenID.dll` and `appsettings.json`, and the target server needs the [ASP.NET Core Runtime 10](https://dotnet.microsoft.com/download) (on IIS, the *Hosting Bundle*, which already includes it). To not depend on the installed runtime, publish with `-r win-x64 --self-contained`.

The `appsettings.{Environment}.json` files are not published, so that an update does not overwrite the production configuration. Without the `ASPNETCORE_ENVIRONMENT` variable, the environment is `Production`, so the production configuration (clients, `Issuer`, `Domain`, keys etc.) can be kept in an `appsettings.Production.json` created directly in the server folder, or in environment variables.

> **Warning:** if the keys are kept in a file, restrict access to it to administrators and to the account that runs the server. For example, with the SIDs of the *Administrators* and *SYSTEM* groups, which do not depend on the Windows language:
>
> ```cmd
> icacls C:\WinOpenID\appsettings.Production.json /inheritance:r /grant:r *S-1-5-32-544:F *S-1-5-18:F "<server account>:R"
> ```

### Kerberos and browsers

Windows authentication tries Kerberos first and, if that fails, uses NTLM. For Kerberos to work with the server's public name (for example `identity.example.com`), the `HTTP/identity.example.com` SPN must be registered on the account that validates the tickets:

| Account | Where to register the SPN |
|---|---|
| gMSA or domain account | On the account itself: `setspn -S HTTP/identity.example.com DOMAIN\WinOpenID$` |
| Virtual account (`NT SERVICE\...`), `NETWORK SERVICE` or `ApplicationPoolIdentity` | On the computer account: `setspn -S HTTP/identity.example.com DOMAIN\SERVER$` |

When the public name is the computer's own name, the `HOST/` SPN the computer already has is enough for the accounts in the second row. Each SPN can only be registered on one account (`-S` checks for duplicates), and the client requests the ticket by the name typed in the URL, not by the name a DNS alias (`CNAME`) resolves to; so prefer an `A` record for the public name. To check, on a workstation logged on to the domain: `klist get HTTP/identity.example.com`.

Browsers only send Windows credentials automatically to trusted sites. In Edge and Chrome, add the server address to the *Local intranet* zone (through group policy, in *Site to Zone Assignment List*) or to the `AuthServerAllowlist` policy; in Firefox, to the `network.negotiate-auth.trusted-uris` preference. Otherwise, the browser prompts for user name and password.

### Windows service

In this mode, the server uses the executable folder as the content root, from which the `appsettings*.json` files are read, and tells Windows when it has finished starting and when it must stop.

**Service account.** Use a [gMSA (*group Managed Service Account*)](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview) or, more simply, the service's virtual account (`NT SERVICE\WinOpenID`), which accesses the network as the computer account. Both can query Active Directory without a configured password. Avoid `LocalSystem`, which has too many privileges, and `LOCAL SERVICE`, which accesses the network anonymously and cannot query AD. The account needs read and execute permission on the server folder.

**HTTPS.** The certificate is read from the computer's certificate store, through the Kestrel configuration in `appsettings.Production.json`:

```json
{
  "Kestrel": {
    "Endpoints": {
      "Https": {
        "Url": "https://*:443",
        "Certificate": {
          "Subject": "identity.example.com",
          "Store": "My",
          "Location": "LocalMachine"
        }
      }
    }
  }
}
```

The service account needs read permission on the certificate's private key: in `certlm.msc`, *Personal* → *Certificates* → right-click the certificate → *All Tasks* → *Manage Private Keys*. See the other options in [Configure endpoints for Kestrel](https://learn.microsoft.com/aspnet/core/fundamentals/servers/kestrel/endpoints).

**Installation.** In a PowerShell running as administrator:

```powershell
# Create the service with automatic start
New-Service -Name WinOpenID -DisplayName "WinOpenID" -BinaryPathName "C:\WinOpenID\WinOpenID.exe" -StartupType Automatic

# Set the service account: the virtual account...
sc.exe config WinOpenID obj= "NT SERVICE\WinOpenID"
# ...or a gMSA (no password; the trailing $ is part of the name)
sc.exe config WinOpenID obj= "DOMAIN\WinOpenID$"

# Create the event log source used by the service (see Auditing)
[System.Diagnostics.EventLog]::CreateEventSource("WinOpenID", "Application")

# Open the port in the firewall
New-NetFirewallRule -DisplayName "WinOpenID (HTTPS)" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow

Start-Service WinOpenID
```

A gMSA also needs the *Log on as a service* right (`secpol.msc` → *Local Policies* → *User Rights Assignment*), which is granted automatically only when the account is set through the *Services* console. If the service does not start, the errors are in the *Application* log in Event Viewer.

**Updating.** Stop the service, replace the files in the folder (`appsettings.Production.json` is not part of the publish output and is preserved) and start the service again:

```powershell
Stop-Service WinOpenID
Copy-Item -Path \\build\WinOpenID\* -Destination C:\WinOpenID -Recurse -Force   # folder with the new published version
Start-Service WinOpenID
```

To remove the service, use `Stop-Service WinOpenID` and `sc.exe delete WinOpenID`.

### Hosting on IIS

**Prerequisites.** Install IIS with the Windows authentication feature and, after it, the .NET 10 [ASP.NET Core Hosting Bundle](https://learn.microsoft.com/aspnet/core/host-and-deploy/iis/hosting-bundle). On Windows Server:

```powershell
Install-WindowsFeature Web-Server, Web-Windows-Auth -IncludeManagementTools
```

If the *Hosting Bundle* is installed before IIS, repair the installation afterwards. After installing it, restart IIS with `net stop was /y` and `net start w3svc`.

**Application Pool and site.** Publish the server to a folder on the server (for example `C:\inetpub\WinOpenID`); publishing already generates the `web.config` with the ASP.NET Core module. Then create an *Application Pool* with no managed code and the site:

```cmd
%windir%\system32\inetsrv\appcmd add apppool /name:WinOpenID /managedRuntimeVersion:""
%windir%\system32\inetsrv\appcmd add site /name:WinOpenID /physicalPath:C:\inetpub\WinOpenID /bindings:https/*:443:identity.example.com
%windir%\system32\inetsrv\appcmd set app "WinOpenID/" /applicationPool:WinOpenID
```

In IIS Manager, edit the site's `https` binding to select the certificate (and enable SNI, if there is more than one site on port 443).

**Authentication.** Enable Windows authentication on the site and keep anonymous authentication enabled: the token, discovery and public keys endpoints are anonymous, and the server only asks for Windows authentication on the authorization endpoint, which IIS then performs:

```cmd
%windir%\system32\inetsrv\appcmd set config "WinOpenID" -section:system.webServer/security/authentication/windowsAuthentication /enabled:true /commit:apphost
```

**Pool identity.** The default identity (`ApplicationPoolIdentity`) accesses the network as the computer account and can query Active Directory. It needs read permission on the site folder (`IIS AppPool\WinOpenID`). If the pool uses a gMSA or domain account, the SPN must be registered on that account (see [Kerberos and browsers](#kerberos-and-browsers)) and IIS must validate the tickets with the pool credentials:

```cmd
%windir%\system32\inetsrv\appcmd set config "WinOpenID" -section:system.webServer/security/authentication/windowsAuthentication /useAppPoolCredentials:true /commit:apphost
```

**Keys.** On IIS 10 or later, the keys can be configured without application files, as *Application Pool* environment variables. They are stored in `applicationHost.config`, outside the application folder, and only that pool's process receives them. For example, for a pool named `WinOpenID`:

```cmd
%windir%\system32\inetsrv\appcmd set config -section:system.applicationHost/applicationPools ^
  /+"[name='WinOpenID'].environmentVariables.[name='Server__SigningKeys__0',value='MIGkAgEBBDD...']" /commit:apphost

%windir%\system32\inetsrv\appcmd set config -section:system.applicationHost/applicationPools ^
  /+"[name='WinOpenID'].environmentVariables.[name='Server__EncryptionKeys__0',value='q2Vx...']" /commit:apphost
```

For rotation, add the other keys with the indexes `__1`, `__2` etc. The configuration can also be done through IIS Manager: *Configuration Editor* → `system.applicationHost/applicationPools` → the pool's `environmentVariables`.

After changing the variables, recycle the *Application Pool*. The values are stored in plain text in `applicationHost.config`, which by default can only be read by administrators. Avoid using system environment variables: they are visible to every process on the machine and are only read by IIS after an `iisreset`.

**Updating.** The server files are locked while the pool is running. Before copying the new version, create an `app_offline.htm` file in the site folder (IIS shuts the server down and responds with that file) and remove it at the end, or stop the *Application Pool* during the copy.

## Testing

The server can be tested with the [OpenID Connect Debugger](https://oidcdebugger.com/debug):

1. Start the server in the `Development` environment (the `oidcdebugger` client, with the URI `https://oidcdebugger.com/debug`, is already registered in `appsettings.Development.json`).
2. Enter `https://localhost:5001/connect/authorize` as the *Authorize URI*, `oidcdebugger` as the *Client ID* and the `openid` scope (and, optionally, `profile email phone roles`).
3. Select the `code` *response type* and enable PKCE with the `S256` method.
4. After authenticating, use the *authorization code* and the *code verifier* to obtain the tokens at `https://localhost:5001/connect/token`.

The contents of signed tokens can be inspected at [jwt.io](https://jwt.io/).

### Automated tests

The unit and integration tests (xUnit v3) are in `tests/WinOpenID.Tests` and can be run with:

```shell
dotnet test
```

The integration tests run the server in memory with a client and keys generated for the test and cover the whole flow, from the *authorization code* to the tokens. Windows authentication is simulated and the directory is replaced by a fake one (`IDirectory`), so the actual search in Active Directory or in the local accounts (`WindowsDirectory`) is still tested manually as described above.

To measure code coverage (of the `WinOpenID` assembly only, as set in `tests/WinOpenID.Tests/coverage.settings.xml`) and generate an HTML report at `coverage-report/index.html`:

```shell
dotnet test -- --coverage --coverage-output-format cobertura --coverage-output coverage.cobertura.xml --coverage-settings tests/WinOpenID.Tests/coverage.settings.xml
dotnet tool restore
dotnet reportgenerator -reports:TestResults/coverage.cobertura.xml -targetdir:coverage-report
```

## Credits and license

Based on [OpenIddict-WindowsAuth](https://github.com/auroris/OpenIddict-WindowsAuth). Distributed under the terms of the license described in [LICENSE](LICENSE).
