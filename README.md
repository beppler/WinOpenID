# WinOpenID

Servidor OpenID Connect simples com autenticação integrada do Windows.

O WinOpenID usa o [OpenIddict](https://documentation.openiddict.com/) em *degraded mode* (sem banco de dados, sem cadastro de clientes ou usuários) para emitir tokens OpenID Connect a partir da autenticação integrada do Windows (Negotiate: Kerberos/NTLM). Os dados do usuário (nome, e-mail, telefone, grupos etc.) são obtidos do Active Directory ou das contas locais da máquina por meio de `System.DirectoryServices.AccountManagement`.

## Requisitos

- Windows (o projeto tem como alvo `net10.0-windows`).
- [.NET 10 SDK](https://dotnet.microsoft.com/download).
- Autenticação Windows habilitada no servidor web: Kestrel (já configurado via `AddNegotiate()`), IIS ou IIS Express (veja `src/WinOpenID/Properties/launchSettings.json`).
- Para usar contas de domínio, a máquina deve fazer parte do domínio do Active Directory.

## Executando

```shell
dotnet run --project src/WinOpenID
```

O perfil `WinOpenID` escuta em `https://localhost:5001` e `http://localhost:5000`, com `ASPNETCORE_ENVIRONMENT=Development`. Também há um perfil `IIS Express`.

O endereço raiz (`/`) redireciona para o documento de descoberta do OpenID Connect.

## Endpoints

| Endpoint | Descrição |
|---|---|
| `/.well-known/openid-configuration` | Documento de descoberta (*discovery*) do OpenID Connect. |
| `/.well-known/jwks` | Chaves públicas usadas para validar a assinatura dos tokens. |
| `/connect/authorize` | Endpoint de autorização: autentica o usuário via Windows e emite o *authorization code*. |
| `/connect/token` | Endpoint de token: troca o *authorization code* pelos tokens. |

## Fluxo suportado

- Somente **Authorization Code** com **PKCE obrigatório**, aceitando apenas o método `S256` (o método `plain` é recusado).
- Os clientes são públicos: qualquer `client_id` é aceito e não há autenticação de cliente (`client_secret`). O controle de acesso é feito pela lista de URIs de retorno permitidas (`AllowedRedirectUris`).
- O parâmetro `prompt` não é suportado: a autenticação integrada do Windows não permite forçar um novo login nem garantir uma autenticação sem interação com o usuário. Os clientes não devem enviá-lo.
- O *implicit flow* e os demais *grant types* (`client_credentials`, `password`, `refresh_token` etc.) não são suportados.

## Escopos e claims

Os escopos suportados são `openid`, `profile`, `email`, `phone` e `roles`. As claims emitidas dependem dos escopos solicitados:

| Escopo | Claims | Token |
|---|---|---|
| *(sempre)* | `sub`, `username`, `preferred_username` | ID token e access token |
| `profile` | `name`, `given_name`, `family_name`, `employee_id` | ID token |
| `profile` | `email`, `email_verified` | ID token |
| `phone` | `phone_number`, `phone_number_verified` | ID token |
| `roles` | `role` (uma para cada grupo de segurança do usuário, incluindo grupos aninhados) | ID token |

Claims cujo atributo correspondente esteja vazio no diretório (por exemplo, usuário sem nome de exibição ou sem telefone) não são emitidas.

## Configuração

As opções do servidor ficam na seção `Server` da configuração do ASP.NET Core. Normalmente são definidas nos arquivos `appsettings.json` / `appsettings.{Ambiente}.json`, mas podem ser informadas por qualquer fonte de configuração padrão, como variáveis de ambiente ou linha de comando:

```shell
# Variáveis de ambiente (arrays usam o índice como chave)
set AllowedHosts=identity.example.com
set Server__Domain=my.ad.domain.com
set Server__Issuer=https://identity.example.com/
set Server__AllowedRedirectUris__0=https://app.example.com/callback
set Server__SigningKeys__0=MIGkAgEBBDD...
set Server__EncryptionKeys__0=q2Vx...

# Linha de comando
dotnet WinOpenID.dll --Server:Domain=my.ad.domain.com
```

### Opções

| Opção | Tipo | Padrão | Descrição |
|---|---|---|---|
| `AllowedRedirectUris` | `string[]` | `[]` | URIs de retorno (`redirect_uri`) permitidas. Veja [URIs de retorno e CORS](#uris-de-retorno-e-cors). |
| `Domain` | `string` | *(vazio)* | Domínio do Active Directory onde os usuários são pesquisados. Se vazio, são usadas as contas locais da máquina. |
| `EncryptionKeys` | `string[]` | `[]` | **Obrigatório.** Chaves simétricas usadas para criptografar os tokens. Veja [Chaves de criptografia](#chaves-de-criptografia). |
| `EncryptAccessToken` | `bool` | `true` | Indica se o *access token* deve ser criptografado. Com `false`, o *access token* é emitido como um JWT apenas assinado, que pode ser lido e validado por APIs de terceiros. |
| `Issuer` | `Uri` | *(vazio)* | Endereço público do servidor, usado como `iss` dos tokens e como base das URLs do documento de descoberta. Recomendado em produção. Veja [Issuer e hosts permitidos](#issuer-e-hosts-permitidos). |
| `SigningKeys` | `string[]` | `[]` | **Obrigatório.** Chaves privadas ECDSA usadas para assinar os tokens. Veja [Chaves de assinatura](#chaves-de-assinatura). |

### URIs de retorno e CORS

Uma requisição só é aceita se o `redirect_uri` informado corresponder a uma das URIs de `AllowedRedirectUris`. A comparação considera esquema, servidor, porta e caminho, sem diferenciar maiúsculas de minúsculas; a *query string* e o fragmento são ignorados. Por exemplo, com `https://app.example.com/callback` configurado:

- `https://app.example.com/callback?x=1` é aceito;
- `https://app.example.com/outro` e `http://app.example.com/callback` são recusados.

As origens (esquema, servidor e porta) dessas mesmas URIs também são liberadas no CORS para requisições `GET` e `POST`, permitindo que aplicações SPA acessem o endpoint de token, o documento de descoberta e o conjunto de chaves públicas (JWKS).

### Issuer e hosts permitidos

Quando `Issuer` não é configurado, o OpenIddict deduz o issuer a partir do cabeçalho `Host` de cada requisição. Uma requisição com um `Host` forjado faz o documento de descoberta anunciar endpoints em outro servidor e muda o `iss` dos tokens emitidos. Em produção, configure o endereço público do servidor:

```json
{
  "AllowedHosts": "identity.example.com",
  "Server": {
    "Issuer": "https://identity.example.com/"
  }
}
```

Como camada adicional, a opção `AllowedHosts` do ASP.NET Core (fora da seção `Server`) faz com que requisições cujo `Host` não esteja na lista sejam recusadas com `400 Bad Request`. Ela aceita vários hosts separados por `;` e curingas de subdomínio (`*.example.com`), e não considera a porta. Sem a opção, ou com `*`, qualquer host é aceito. Veja [Host filtering](https://learn.microsoft.com/aspnet/core/fundamentals/servers/kestrel/host-filtering).

O `appsettings.Development.json` libera apenas `localhost` e não define `Issuer`, para que os perfis `WinOpenID` e `IIS Express` funcionem nas suas respectivas portas.

### Domínio e identificador do usuário

A opção `Domain` define onde os dados do usuário autenticado são pesquisados e também o valor da claim `sub`:

| `Domain` | Origem dos usuários | Valor de `sub` |
|---|---|---|
| vazio | Contas locais da máquina | SID do usuário |
| preenchido | Active Directory do domínio informado | GUID do objeto do usuário no AD |

O usuário autenticado é localizado pelo seu SID, e não pelo nome. Por isso, ele precisa pertencer ao domínio configurado (ou ser uma conta local da máquina, quando `Domain` está vazio). Usuários de outros domínios, mesmo que confiáveis, e usuários de domínio quando `Domain` está vazio são recusados com `access_denied`.

### Chaves de criptografia

As chaves de `EncryptionKeys` são chaves simétricas codificadas em Base64, com 256 bits (32 bytes). Elas protegem o *authorization code* e, quando `EncryptAccessToken` é `true`, o *access token*. Podem ser geradas, por exemplo, com:

```shell
openssl rand -base64 32
```

```powershell
[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

Assim como nas chaves de assinatura, a primeira chave é usada para criptografar e as demais servem apenas para descriptografar, permitindo a rotação.

### Chaves de assinatura

As chaves de `SigningKeys` são chaves privadas de curva elíptica (ECDSA) no formato EC (SEC 1, DER) codificadas em Base64. Elas podem ser geradas com o script `scripts/signkeygen.cs`:

```shell
dotnet scripts/signkeygen.cs
dotnet scripts/signkeygen.cs --curve nistP256
```

A opção `--curve` (ou `-c`) aceita `nistP256`, `nistP384` (padrão) e `nistP521`.

É possível informar mais de uma chave para fazer a rotação: a primeira é usada para assinar novos tokens e todas são publicadas em `/.well-known/jwks`, de forma que tokens assinados com chaves anteriores continuam válidos.

### Chaves obrigatórias

O servidor não usa chaves efêmeras: é necessário configurar ao menos uma chave em `SigningKeys` e uma em `EncryptionKeys`, caso contrário o OpenIddict gera um erro de configuração. Como as chaves são fixas, os tokens emitidos continuam válidos após reinicializações e podem ser compartilhados entre múltiplas instâncias do servidor.

> **Atenção:** as chaves presentes em `appsettings.Development.json` são públicas e servem apenas para desenvolvimento. Em produção, gere novas chaves e mantenha-as fora do controle de versão (variáveis de ambiente, *user secrets*, cofre de segredos etc.). Os arquivos `appsettings.*.json` não são copiados na publicação (`CopyToPublishDirectory="Never"` em `WinOpenID.csproj`).

### Exemplo de configuração

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Warning"
    }
  },
  "AllowedHosts": "identity.example.com",
  "Server": {
    "AllowedRedirectUris": [
      "https://app.example.com/callback"
    ],
    "Domain": "my.ad.domain.com",
    "Issuer": "https://identity.example.com/",
    "SigningKeys": [
      "<chave ECDSA em Base64 gerada com scripts/signkeygen.cs>"
    ],
    "EncryptionKeys": [
      "<chave simétrica de 32 bytes em Base64>"
    ],
    "EncryptAccessToken": true
  }
}
```

A seção `Logging` segue a [configuração padrão de logs do ASP.NET Core](https://learn.microsoft.com/aspnet/core/fundamentals/logging/).

### Hospedagem no IIS

No IIS 10 ou superior, as chaves podem ser configuradas sem arquivos da aplicação, como variáveis de ambiente do *Application Pool*. Elas ficam gravadas no `applicationHost.config`, fora da pasta da aplicação, e só o processo daquele pool as recebe. Por exemplo, para um pool chamado `WinOpenID`:

```cmd
%windir%\system32\inetsrv\appcmd set config -section:system.applicationHost/applicationPools ^
  /+"[name='WinOpenID'].environmentVariables.[name='Server__SigningKeys__0',value='MIGkAgEBBDD...']" /commit:apphost

%windir%\system32\inetsrv\appcmd set config -section:system.applicationHost/applicationPools ^
  /+"[name='WinOpenID'].environmentVariables.[name='Server__EncryptionKeys__0',value='q2Vx...']" /commit:apphost
```

Para a rotação, adicione as demais chaves com os índices `__1`, `__2` etc. Também é possível fazer a configuração pelo IIS Manager: *Configuration Editor* → `system.applicationHost/applicationPools` → `environmentVariables` do pool.

Depois de alterar as variáveis, recicle o *Application Pool*. Os valores ficam em texto puro no `applicationHost.config`, que por padrão só pode ser lido por administradores. Evite usar variáveis de ambiente do sistema: elas ficam visíveis para todos os processos da máquina e só são lidas pelo IIS depois de um `iisreset`.

## Testando

Para testar o servidor pode ser usado o [OpenID Connect Debugger](https://oidcdebugger.com/debug):

1. Inicie o servidor no ambiente `Development` (as URIs `https://oidcdebugger.com/debug` e `https://jwt.io/` já estão liberadas em `appsettings.Development.json`).
2. Informe `https://localhost:5001/connect/authorize` como *Authorize URI*, qualquer valor como *Client ID* e o escopo `openid` (e, opcionalmente, `profile phone roles`).
3. Selecione o *response type* `code` e habilite o PKCE com o método `S256`.
4. Após a autenticação, use o *authorization code* e o *code verifier* para obter os tokens em `https://localhost:5001/connect/token`.

O conteúdo dos tokens assinados pode ser inspecionado em [jwt.io](https://jwt.io/).

## Créditos e licença

Baseado em [OpenIddict-WindowsAuth](https://github.com/auroris/OpenIddict-WindowsAuth). Distribuído sob os termos da licença descrita em [LICENSE](LICENSE).
