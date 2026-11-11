# Aster

## O que é o Aster?

Uma aplicação de autenticação em PHP com cadastro, login, verificação em duas etapas (TOTP) e login social opcional por Google e GitHub. SQLite é o banco padrão; MySQL também é suportado.

## O que preciso instalar?

- PHP 8.1 ou superior.
- `pdo_sqlite` para o banco padrão ou `pdo_mysql` para MySQL.
- `openssl` para a proteção dos segredos TOTP.
- `allow_url_fopen` habilitado somente se for usar login OAuth.

Não há dependências JavaScript ou pacotes externos para instalar.

## Como iniciar localmente no Windows?

No PowerShell, na pasta do projeto, execute:

```powershell
$phpRoot = Split-Path (Get-Command php).Source
php -d "extension_dir=$phpRoot\ext" -d extension=pdo_sqlite -d extension=openssl -S 127.0.0.1:8000
```

Abra `http://127.0.0.1:8000`. Se as extensões já estiverem habilitadas no PHP, também pode iniciar com `php -S 127.0.0.1:8000`.

O SQLite e a chave local do autenticador são criados em `%LOCALAPPDATA%\AsterLogin\`, fora da pasta pública. Para usar outro arquivo de banco, configure `AUTH_DB_PATH`. O esquema local é migrado automaticamente na primeira execução.

## Como configurar Google ou GitHub?

Crie um cliente OAuth no provedor e cadastre a URL de retorno correspondente:

```text
Google: https://SEU-DOMINIO/?oauth_callback=google
GitHub: https://SEU-DOMINIO/?oauth_callback=github
```

Para desenvolvimento local, use `http://127.0.0.1:8000/?oauth_callback=google` ou `http://127.0.0.1:8000/?oauth_callback=github`. HTTP é permitido apenas em loopback; em produção, use HTTPS.

Defina as variáveis no ambiente do servidor, sem gravar segredos no repositório:

```text
AUTH_OAUTH_GOOGLE_CLIENT_ID=...
AUTH_OAUTH_GOOGLE_CLIENT_SECRET=...
AUTH_OAUTH_GOOGLE_REDIRECT_URI=https://SEU-DOMINIO/?oauth_callback=google
AUTH_OAUTH_GITHUB_CLIENT_ID=...
AUTH_OAUTH_GITHUB_CLIENT_SECRET=...
AUTH_OAUTH_GITHUB_REDIRECT_URI=https://SEU-DOMINIO/?oauth_callback=github
```

Escopos necessários: Google `openid email profile`; GitHub `read:user user:email`. O OAuth exige `allow_url_fopen` e e-mail confirmado. Sem as três variáveis de um provedor, seu botão permanece desativado. O fluxo valida `state`, usa PKCE e mantém a etapa 2FA quando a conta já a exige.

## Como habilitar MySQL?

1. Crie o banco e execute [schema.sql](./schema.sql).
2. Configure `AUTH_DB_DRIVER=mysql`, `AUTH_DB_HOST`, `AUTH_DB_PORT`, `AUTH_DB_NAME`, `AUTH_DB_USER` e `AUTH_DB_PASSWORD`.
3. Configure `AUTH_APP_KEY` antes de ativar TOTP. Gere uma chave com:

   ```powershell
   php -r "echo base64_encode(random_bytes(32)), PHP_EOL;"
   ```

`AUTH_APP_KEY` também pode ser definida no SQLite para substituir a chave local. Guarde-a com segurança e não a altere: sem a chave original, os segredos TOTP armazenados não podem ser descriptografados.

## Como usar a verificação em duas etapas?

Entre na conta, abra **Segurança** e configure um aplicativo compatível com TOTP de seis dígitos a cada 30 segundos. Confirme com o código gerado e guarde os oito códigos de recuperação; cada um só pode ser usado uma vez.

Ao entrar, informe o código do autenticador ou um código de recuperação. Para desativar TOTP, contas com senha pedem senha e código atual; contas criadas somente por OAuth pedem o código atual.

## Como executar os testes?

```powershell
$phpRoot = Split-Path (Get-Command php).Source
php -d "extension_dir=$phpRoot\ext" -d extension=pdo_sqlite -d extension=openssl tests\security_test.php
```

Os testes cobrem vetores TOTP, cifra de segredos, códigos de recuperação, estado/PKCE OAuth e associação de contas.

## O que está incluído na interface?

Tema claro/escuro, navegação responsiva, login social opcional e animações de fundo e títulos. O cursor é o padrão do sistema. Não há fonte, framework ou imagem carregados de serviços externos.

## Onde estão os arquivos principais?

- `index.php`: página, banco de dados e operações de autenticação.
- `app/security.php`: sessões, TOTP, cifra e recuperação.
- `app/oauth.php`: fluxos Google/GitHub.
- `assets/css/app.css`: estilos e temas.
- `schema.sql`: esquema MySQL.
- `tests/security_test.php`: testes automatizados.
