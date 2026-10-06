# WinOpenID

**Português** | [English](README.en.md)

Servidor OpenID Connect simples com autenticação integrada do Windows.

O WinOpenID usa o [OpenIddict](https://documentation.openiddict.com/) em *degraded mode* (sem banco de dados: os clientes são cadastrados na própria configuração e os usuários vêm do diretório) para emitir tokens OpenID Connect a partir da autenticação integrada do Windows (Negotiate: Kerberos/NTLM).

Os dados do usuário (nome, e-mail, telefone, grupos etc.) são obtidos do Active Directory ou das contas locais da máquina por meio de `System.DirectoryServices.AccountManagement`.

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
- Os clientes são públicos, sem autenticação de cliente (`client_secret`), mas precisam estar cadastrados em `Clients`. Como o *authorization code* só é entregue nas URIs de retorno cadastradas para o `client_id`, o `client_id` dos tokens identifica a aplicação. Veja [Clientes](#clientes).
- O *authorization code* é válido por apenas 1 minuto. Como o servidor não tem banco de dados, ele não consegue registrar que um código já foi usado, e o mesmo código pode ser trocado por tokens mais de uma vez dentro desse prazo (o PKCE exige o *code verifier* em cada troca).
- O parâmetro `prompt` não é suportado: a autenticação integrada do Windows não permite forçar um novo login nem garantir uma autenticação sem interação com o usuário. Os clientes não devem enviá-lo.
- O *implicit flow* e os demais *grant types* (`client_credentials`, `password`, `refresh_token` etc.) não são suportados.

## Escopos e claims

Os escopos suportados são `openid`, `profile`, `email`, `phone` e `roles`. Cada cliente só pode solicitar os escopos permitidos no seu cadastro, inclusive o `openid`. As claims emitidas dependem dos escopos solicitados:

| Escopo | Claims | Token |
|---|---|---|
| *(sempre)* | `sub`, `username`, `preferred_username` | ID token e access token |
| `profile` | `name`, `given_name`, `family_name`, `employee_id` | ID token |
| `email` | `email`, `email_verified` | ID token |
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
set Server__Clients__app__RedirectUris__0=https://app.example.com/callback
set Server__Clients__app__Scopes__0=openid
set Server__Clients__app__Scopes__1=profile
set Server__Clients__app__Audiences__0=https://api.example.com
set Server__SigningKeys__0=MIGkAgEBBDD...
set Server__EncryptionKeys__0=q2Vx...

# Linha de comando
dotnet WinOpenID.dll --Server:Domain=my.ad.domain.com
```

### Opções

| Opção | Tipo | Padrão | Descrição |
|---|---|---|---|
| `Clients` | `object` | `{}` | Clientes cadastrados, indexados pelo `client_id`, com as URIs de retorno e os escopos permitidos de cada um. Veja [Clientes](#clientes). |
| `Domain` | `string` | *(vazio)* | Domínio do Active Directory onde os usuários são pesquisados. Se vazio, são usadas as contas locais da máquina. |
| `EncryptionKeys` | `string[]` | `[]` | **Obrigatório.** Chaves simétricas usadas para criptografar os tokens. Veja [Chaves de criptografia](#chaves-de-criptografia). |
| `EncryptAccessToken` | `bool` | `true` | Indica se o *access token* deve ser criptografado. Com `false`, o *access token* é emitido como um JWT apenas assinado, que pode ser lido e validado por APIs de terceiros. |
| `Issuer` | `Uri` | *(vazio)* | Endereço público do servidor, usado como `iss` dos tokens e como base das URLs do documento de descoberta. Recomendado em produção. Veja [Issuer e hosts permitidos](#issuer-e-hosts-permitidos). |
| `SigningKeys` | `string[]` | `[]` | **Obrigatório.** Chaves privadas ECDSA usadas para assinar os tokens. Veja [Chaves de assinatura](#chaves-de-assinatura). |

### Clientes

Cada cliente é cadastrado em `Clients`, usando o `client_id` como chave (a comparação diferencia maiúsculas de minúsculas):

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

| Opção | Tipo | Padrão | Descrição |
|---|---|---|---|
| `RedirectUris` | `string[]` | `[]` | URIs de retorno (`redirect_uri`) permitidas para o cliente. |
| `Scopes` | `string[]` | `[]` | Escopos que o cliente pode solicitar, entre `openid`, `profile`, `email`, `phone` e `roles`. Sem `openid`, o cliente não recebe o ID token. Um escopo não suportado impede a inicialização do servidor. |
| `Audiences` | `string[]` | `[]` | Audiências (`aud`) dos *access tokens* emitidos para o cliente, normalmente os identificadores das APIs que ele acessa. Veja [Audiência do access token](#audiência-do-access-token). |

Requisições com um `client_id` não cadastrado são recusadas com `invalid_client`, e requisições com escopos não permitidos para o cliente, com `invalid_scope`.

#### Audiência do access token

O *access token* de um cliente é emitido com a claim `aud` contendo todas as audiências de `Audiences`. Sem audiências configuradas, o *access token* é emitido sem `aud`. O ID token sempre tem o `client_id` como `aud`, como define o OpenID Connect.

Uma mesma API pode ser autorizada para vários clientes: basta incluir o identificador dela em `Audiences` de cada um. Cada API deve validar a própria audiência e aceitar apenas *access tokens*, recusando ID tokens. Por exemplo, com o `JwtBearer` do ASP.NET Core:

```csharp
builder.Services.AddAuthentication().AddJwtBearer(options =>
{
    options.Authority = "https://identity.example.com/";
    options.Audience = "https://api.example.com";
    options.TokenValidationParameters.ValidTypes = ["at+jwt"];
});
```

O *access token* tem `typ` `at+jwt` no cabeçalho e o ID token, `JWT`. Esse exemplo pressupõe `EncryptAccessToken` igual a `false`; com o *access token* criptografado, a API precisa da chave de criptografia, e a validação do OpenIddict (`AddValidation` com `AddAudiences`) é o caminho mais simples.

#### URIs de retorno e CORS

Uma requisição só é aceita se o `redirect_uri` informado for exatamente igual a uma das URIs de `RedirectUris` do cliente, como exigem o [OAuth 2.0 Security BCP (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700) e o OAuth 2.1. A comparação inclui o caminho e a *query string* e diferencia maiúsculas de minúsculas no caminho; apenas o esquema e o servidor são comparados sem diferenciar maiúsculas, e a porta padrão é desconsiderada. Por exemplo, com `https://app.example.com/callback` configurado:

- `https://app.example.com/callback` e `https://APP.example.com:443/callback` são aceitos;
- `https://app.example.com/callback?x=1`, `https://app.example.com/Callback`, `https://app.example.com/callback/` e `http://app.example.com/callback` são recusados.

Se um cliente precisar de parâmetros na URI de retorno, a URI completa, com a *query string*, deve ser configurada. Isso impede que um atacante acrescente parâmetros ao `redirect_uri` para tentar desviar o *authorization code* a partir da página de retorno da aplicação.

As URIs configuradas devem ser absolutas, não podem ter fragmento (`#...`) e devem usar `https`; `http` só é aceito em endereços de *loopback* (`localhost`, `127.0.0.1`, `[::1]`). Uma URI inválida impede a inicialização do servidor.

As origens (esquema, servidor e porta) das URIs de todos os clientes também são liberadas no CORS para requisições `GET` e `POST`, permitindo que aplicações SPA acessem o endpoint de token, o documento de descoberta e o conjunto de chaves públicas (JWKS).

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


### Chaves de assinatura

As chaves de `SigningKeys` são chaves privadas de curva elíptica (ECDSA) no formato EC (SEC 1, DER) codificadas em Base64. Podem ser geradas, por exemplo, com:

```shell
openssl ecparam -name secp384r1 -genkey -noout -outform DER | openssl base64 -A
```

```powershell
# PowerShell 7 ou superior (o Windows PowerShell 5.1 não tem ExportECPrivateKey)
[Convert]::ToBase64String([Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP384).ExportECPrivateKey())
```

Os exemplos usam a curva P-384. Também são aceitas as curvas P-256 e P-521, que no OpenSSL se chamam `prime256v1` e `secp521r1` e no .NET, `nistP256` e `nistP521`.

É possível informar mais de uma chave para fazer a rotação: a primeira é usada para assinar novos tokens e todas são publicadas em `/.well-known/jwks`, de forma que tokens assinados com chaves anteriores continuam válidos.

### Chaves de criptografia

As chaves de `EncryptionKeys` são chaves simétricas codificadas em Base64, com 256 bits (32 bytes). Elas protegem o *authorization code* e, quando `EncryptAccessToken` é `true`, o *access token*. Podem ser geradas, por exemplo, com:

```shell
openssl rand -base64 32
```

```powershell
[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

Assim como nas chaves de assinatura, a primeira chave é usada para criptografar e as demais servem apenas para descriptografar, permitindo a rotação.

### Chaves obrigatórias

É necessário configurar ao menos uma chave em `SigningKeys` e uma em `EncryptionKeys`, caso contrário o servidor gera um erro de configuração.

Como as chaves são fixas, os tokens emitidos continuam válidos após reinicializações e podem ser compartilhados entre múltiplas instâncias do servidor.

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
      "<chave ECDSA em Base64>"
    ],
    "EncryptionKeys": [
      "<chave simétrica de 32 bytes em Base64>"
    ],
    "EncryptAccessToken": true
  }
}
```

A seção `Logging` segue a [configuração padrão de logs do ASP.NET Core](https://learn.microsoft.com/aspnet/core/fundamentals/logging/).

### Auditoria

O servidor registra as emissões e as recusas na categoria de log `WinOpenID.Audit`:

| Evento | Nível | Campos |
|---|---|---|
| *Authorization code* emitido | `Information` | usuário, `sub`, `client_id`, `redirect_uri`, escopos, audiências, IP e porta de origem |
| Tokens emitidos (troca do *authorization code*) | `Information` | usuário, `sub`, `client_id`, escopos, audiências, IP e porta de origem |
| Requisição de autorização recusada | `Warning` | `client_id`, `redirect_uri`, escopos, `error`, `error_description`, IP e porta de origem |
| Requisição de token recusada | `Warning` | `client_id`, `grant_type`, `error`, `error_description`, IP e porta de origem |
| Usuário autenticado pelo Windows não encontrado no diretório | `Warning` | nome Windows, SID, `client_id`, IP e porta de origem |

O endereço de origem é registrado com a porta (por exemplo `203.0.113.10:51234` ou `[2001:db8::1]:51234`), porque muitos provedores de acesso compartilham o mesmo IP público entre vários clientes (CGNAT), diferenciando-os pela faixa de portas. Para identificar um cliente nesses casos, o provedor costuma exigir o IP, a porta e o horário exato da conexão, então o provedor de log deve registrar o horário de cada evento. Se o servidor estiver atrás de um proxy reverso ou balanceador de carga, o endereço registrado é o do proxy, a menos que o [Forwarded Headers Middleware](https://learn.microsoft.com/aspnet/core/host-and-deploy/proxy-load-balancer) esteja configurado; e mesmo assim só há porta se o proxy a encaminhar.

As recusas incluem tanto as feitas pelo WinOpenID (cliente não cadastrado, `redirect_uri` ou escopo não permitido) quanto as do OpenIddict (*authorization code* expirado, *code verifier* inválido etc.). Como o mesmo *authorization code* pode ser trocado mais de uma vez dentro do prazo de validade, dois eventos de tokens emitidos para o mesmo usuário e cliente em menos de 1 minuto podem indicar o reaproveitamento de um código. *Authorization codes*, tokens, *code verifiers* e chaves nunca são registrados.

A categoria pode ser habilitada em produção sem habilitar os demais logs em `Information`:

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

No IIS a saída do console é descartada. No Windows, o ASP.NET Core já registra o provedor *EventLog*, que por padrão grava apenas `Warning` ou acima no *Application* do Visualizador de Eventos. Para gravar também os eventos de emissão:

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

Também é possível usar qualquer outro provedor de log compatível com o ASP.NET Core.

> **Atenção:** os registros de auditoria contêm dados pessoais (nome de login, endereço IP e porta) e devem seguir a política de retenção e de proteção de dados da organização.

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

1. Inicie o servidor no ambiente `Development` (o cliente `oidcdebugger`, com a URI `https://oidcdebugger.com/debug`, já está cadastrado em `appsettings.Development.json`).
2. Informe `https://localhost:5001/connect/authorize` como *Authorize URI*, `oidcdebugger` como *Client ID* e o escopo `openid` (e, opcionalmente, `profile email phone roles`).
3. Selecione o *response type* `code` e habilite o PKCE com o método `S256`.
4. Após a autenticação, use o *authorization code* e o *code verifier* para obter os tokens em `https://localhost:5001/connect/token`.

O conteúdo dos tokens assinados pode ser inspecionado em [jwt.io](https://jwt.io/).

## Créditos e licença

Baseado em [OpenIddict-WindowsAuth](https://github.com/auroris/OpenIddict-WindowsAuth). Distribuído sob os termos da licença descrita em [LICENSE](LICENSE).
