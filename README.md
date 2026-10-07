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

No IIS e no serviço do Windows a saída do console é descartada. No Windows, o ASP.NET Core já registra o provedor *EventLog*, que por padrão grava apenas `Warning` ou acima no *Application* do Visualizador de Eventos (no serviço do Windows, com a origem `WinOpenID`; veja [Serviço do Windows](#serviço-do-windows)). Para gravar também os eventos de emissão:

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

## Implantação

O servidor pode ser implantado de duas formas:

- **Serviço do Windows**: o próprio executável, com o Kestrel, roda como um serviço e atende as requisições HTTPS diretamente. Não depende do IIS.
- **IIS**: o servidor roda dentro de um *Application Pool* do IIS, que cuida do HTTPS e da autenticação Windows.

Em ambos os casos, use o endereço público do servidor em `Issuer` e `AllowedHosts` (veja [Issuer e hosts permitidos](#issuer-e-hosts-permitidos)) e configure as chaves, os clientes e o `Domain` antes de iniciar o servidor.

### Publicação

```shell
dotnet publish src/WinOpenID -c Release -o C:\WinOpenID
```

A pasta de publicação contém o `WinOpenID.exe`, o `WinOpenID.dll` e o `appsettings.json`, e o servidor de destino precisa do [ASP.NET Core Runtime 10](https://dotnet.microsoft.com/download) (no IIS, o *Hosting Bundle*, que já o inclui). Para não depender do runtime instalado, publique com `-r win-x64 --self-contained`.

Os arquivos `appsettings.{Ambiente}.json` não são publicados, para que uma atualização não sobrescreva a configuração de produção. Sem a variável `ASPNETCORE_ENVIRONMENT`, o ambiente é `Production`, então a configuração de produção (clientes, `Issuer`, `Domain`, chaves etc.) pode ficar em um `appsettings.Production.json` criado diretamente na pasta do servidor, ou em variáveis de ambiente.

> **Atenção:** se as chaves ficarem em um arquivo, restrinja o acesso a ele aos administradores e à conta que executa o servidor. Por exemplo, com os SIDs dos grupos *Administradores* e *SYSTEM*, que não dependem do idioma do Windows:
>
> ```cmd
> icacls C:\WinOpenID\appsettings.Production.json /inheritance:r /grant:r *S-1-5-32-544:F *S-1-5-18:F "<conta do servidor>:R"
> ```

### Kerberos e navegadores

A autenticação Windows tenta primeiro o Kerberos e, se não conseguir, usa o NTLM. Para o Kerberos funcionar com o nome público do servidor (por exemplo `identity.example.com`), o SPN `HTTP/identity.example.com` deve estar registrado na conta que valida os tickets:

| Conta | Onde registrar o SPN |
|---|---|
| gMSA ou conta de domínio | Na própria conta: `setspn -S HTTP/identity.example.com DOMINIO\WinOpenID$` |
| Conta virtual (`NT SERVICE\...`), `NETWORK SERVICE` ou `ApplicationPoolIdentity` | Na conta do computador: `setspn -S HTTP/identity.example.com DOMINIO\SERVIDOR$` |

Quando o nome público é o próprio nome do computador, o SPN `HOST/` que o computador já tem é suficiente para as contas da segunda linha. Cada SPN só pode estar registrado em uma conta (o `-S` verifica duplicidades), e o cliente pede o ticket pelo nome digitado na URL, e não pelo nome de um alias DNS (`CNAME`) resolvido; por isso, prefira um registro `A` para o nome público. Para conferir, em uma estação autenticada no domínio: `klist get HTTP/identity.example.com`.

Os navegadores só enviam as credenciais do Windows automaticamente para sites confiáveis. No Edge e no Chrome, inclua o endereço do servidor na zona *Intranet local* (por política de grupo, em *Site to Zone Assignment List*) ou na política `AuthServerAllowlist`; no Firefox, na preferência `network.negotiate-auth.trusted-uris`. Caso contrário, o navegador pede usuário e senha.

### Serviço do Windows

Nesse modo, o servidor usa a pasta do executável como diretório de conteúdo, de onde são lidos os arquivos `appsettings*.json`, e informa ao Windows quando terminou de iniciar e quando deve parar.

**Conta do serviço.** Use uma [gMSA (*group Managed Service Account*)](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview) ou, de forma mais simples, a conta virtual do serviço (`NT SERVICE\WinOpenID`), que acessa a rede como a conta do computador. Ambas conseguem consultar o Active Directory sem senha configurada. Evite `LocalSystem`, que tem privilégios demais, e `LOCAL SERVICE`, que acessa a rede anonimamente e não consegue consultar o AD. A conta precisa de permissão de leitura e execução na pasta do servidor.

**HTTPS.** O certificado é lido do repositório de certificados do computador, pela configuração do Kestrel no `appsettings.Production.json`:

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

A conta do serviço precisa de permissão de leitura na chave privada do certificado: no `certlm.msc`, *Pessoal* → *Certificados* → botão direito no certificado → *Todas as Tarefas* → *Gerenciar Chaves Privadas*. Veja as demais opções em [Configure endpoints for Kestrel](https://learn.microsoft.com/aspnet/core/fundamentals/servers/kestrel/endpoints).

**Instalação.** Em um PowerShell como administrador:

```powershell
# Cria o serviço com início automático
New-Service -Name WinOpenID -DisplayName "WinOpenID" -BinaryPathName "C:\WinOpenID\WinOpenID.exe" -StartupType Automatic

# Define a conta do serviço: a conta virtual...
sc.exe config WinOpenID obj= "NT SERVICE\WinOpenID"
# ...ou uma gMSA (sem senha; o $ no final faz parte do nome)
sc.exe config WinOpenID obj= "DOMINIO\WinOpenID$"

# Cria a origem do log de eventos usada pelo serviço (veja Auditoria)
[System.Diagnostics.EventLog]::CreateEventSource("WinOpenID", "Application")

# Libera a porta no firewall
New-NetFirewallRule -DisplayName "WinOpenID (HTTPS)" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow

Start-Service WinOpenID
```

Uma gMSA também precisa do direito *Fazer logon como um serviço* (`secpol.msc` → *Políticas Locais* → *Atribuição de direitos de usuário*), concedido automaticamente apenas quando a conta é definida pelo console *Serviços*. Se o serviço não iniciar, os erros ficam no log *Application* do Visualizador de Eventos.

**Atualização.** Pare o serviço, substitua os arquivos da pasta (o `appsettings.Production.json` não faz parte da publicação e é preservado) e inicie o serviço novamente:

```powershell
Stop-Service WinOpenID
Copy-Item -Path \\build\WinOpenID\* -Destination C:\WinOpenID -Recurse -Force   # pasta com a nova versão publicada
Start-Service WinOpenID
```

Para remover o serviço, use `Stop-Service WinOpenID` e `sc.exe delete WinOpenID`.

### Hospedagem no IIS

**Pré-requisitos.** Instale o IIS com o recurso de autenticação Windows e, depois dele, o [ASP.NET Core Hosting Bundle](https://learn.microsoft.com/aspnet/core/host-and-deploy/iis/hosting-bundle) do .NET 10. No Windows Server:

```powershell
Install-WindowsFeature Web-Server, Web-Windows-Auth -IncludeManagementTools
```

Se o *Hosting Bundle* for instalado antes do IIS, repare a instalação depois. Após instalá-lo, reinicie o IIS com `net stop was /y` e `net start w3svc`.

**Application Pool e site.** Publique o servidor em uma pasta do servidor (por exemplo `C:\inetpub\WinOpenID`); a publicação já gera o `web.config` com o módulo do ASP.NET Core. Depois crie um *Application Pool* sem código gerenciado e o site:

```cmd
%windir%\system32\inetsrv\appcmd add apppool /name:WinOpenID /managedRuntimeVersion:""
%windir%\system32\inetsrv\appcmd add site /name:WinOpenID /physicalPath:C:\inetpub\WinOpenID /bindings:https/*:443:identity.example.com
%windir%\system32\inetsrv\appcmd set app "WinOpenID/" /applicationPool:WinOpenID
```

No IIS Manager, edite o *binding* `https` do site para selecionar o certificado (e habilitar o SNI, se houver mais de um site na porta 443).

**Autenticação.** Habilite a autenticação Windows no site e mantenha a anônima habilitada: os endpoints de token, de descoberta e de chaves públicas são anônimos, e o servidor só pede a autenticação Windows no endpoint de autorização, que o IIS então executa:

```cmd
%windir%\system32\inetsrv\appcmd set config "WinOpenID" -section:system.webServer/security/authentication/windowsAuthentication /enabled:true /commit:apphost
```

**Identidade do pool.** A identidade padrão (`ApplicationPoolIdentity`) acessa a rede como a conta do computador e consegue consultar o Active Directory. Ela precisa de permissão de leitura na pasta do site (`IIS AppPool\WinOpenID`). Se o pool usar uma gMSA ou conta de domínio, o SPN deve ser registrado nessa conta (veja [Kerberos e navegadores](#kerberos-e-navegadores)) e o IIS deve validar os tickets com as credenciais do pool:

```cmd
%windir%\system32\inetsrv\appcmd set config "WinOpenID" -section:system.webServer/security/authentication/windowsAuthentication /useAppPoolCredentials:true /commit:apphost
```

**Chaves.** No IIS 10 ou superior, as chaves podem ser configuradas sem arquivos da aplicação, como variáveis de ambiente do *Application Pool*. Elas ficam gravadas no `applicationHost.config`, fora da pasta da aplicação, e só o processo daquele pool as recebe. Por exemplo, para um pool chamado `WinOpenID`:

```cmd
%windir%\system32\inetsrv\appcmd set config -section:system.applicationHost/applicationPools ^
  /+"[name='WinOpenID'].environmentVariables.[name='Server__SigningKeys__0',value='MIGkAgEBBDD...']" /commit:apphost

%windir%\system32\inetsrv\appcmd set config -section:system.applicationHost/applicationPools ^
  /+"[name='WinOpenID'].environmentVariables.[name='Server__EncryptionKeys__0',value='q2Vx...']" /commit:apphost
```

Para a rotação, adicione as demais chaves com os índices `__1`, `__2` etc. Também é possível fazer a configuração pelo IIS Manager: *Configuration Editor* → `system.applicationHost/applicationPools` → `environmentVariables` do pool.

Depois de alterar as variáveis, recicle o *Application Pool*. Os valores ficam em texto puro no `applicationHost.config`, que por padrão só pode ser lido por administradores. Evite usar variáveis de ambiente do sistema: elas ficam visíveis para todos os processos da máquina e só são lidas pelo IIS depois de um `iisreset`.

**Atualização.** Os arquivos do servidor ficam bloqueados enquanto o pool está em execução. Antes de copiar a nova versão, crie um arquivo `app_offline.htm` na pasta do site (o IIS encerra o servidor e responde com esse arquivo) e remova-o ao final, ou pare o *Application Pool* durante a cópia.

## Testando

Para testar o servidor pode ser usado o [OpenID Connect Debugger](https://oidcdebugger.com/debug):

1. Inicie o servidor no ambiente `Development` (o cliente `oidcdebugger`, com a URI `https://oidcdebugger.com/debug`, já está cadastrado em `appsettings.Development.json`).
2. Informe `https://localhost:5001/connect/authorize` como *Authorize URI*, `oidcdebugger` como *Client ID* e o escopo `openid` (e, opcionalmente, `profile email phone roles`).
3. Selecione o *response type* `code` e habilite o PKCE com o método `S256`.
4. Após a autenticação, use o *authorization code* e o *code verifier* para obter os tokens em `https://localhost:5001/connect/token`.

O conteúdo dos tokens assinados pode ser inspecionado em [jwt.io](https://jwt.io/).

### Testes automatizados

Os testes unitários e de integração (xUnit v3) ficam em `tests/WinOpenID.Tests` e podem ser executados com:

```shell
dotnet test
```

Os testes de integração sobem o servidor em memória com um cliente e chaves gerados para o teste e cobrem o fluxo completo, do *authorization code* aos tokens. A autenticação Windows é simulada e o diretório é substituído por um falso (`IDirectory`), então a busca real no Active Directory ou nas contas locais (`WindowsDirectory`) continua sendo testada manualmente como descrito acima.

Para medir a cobertura de código (apenas do assembly `WinOpenID`, conforme `tests/WinOpenID.Tests/coverage.settings.xml`) e gerar um relatório HTML em `coverage-report/index.html`:

```shell
dotnet test -- --coverage --coverage-output-format cobertura --coverage-output coverage.cobertura.xml --coverage-settings tests/WinOpenID.Tests/coverage.settings.xml
dotnet tool restore
dotnet reportgenerator -reports:TestResults/coverage.cobertura.xml -targetdir:coverage-report
```

## Créditos e licença

Baseado em [OpenIddict-WindowsAuth](https://github.com/auroris/OpenIddict-WindowsAuth). Distribuído sob os termos da licença descrita em [LICENSE](LICENSE).
