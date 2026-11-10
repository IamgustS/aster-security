# login seguro #


Uma tela responsiva de login e criação de conta em PHP. Por padrão, os dados ficam em um banco SQLite fora da pasta pública do site; MySQL também está disponível como opção.

2 semanas em Desenvolvimento pegando como base um parte de codigo do projeto WedTech e fazendo a sua melhoria na parte de login e segurança do usuario.

## Requisitos

- PHP 8.1 ou superior com `pdo_sqlite` (modo padrão) ou `pdo_mysql` e `openssl` para a verificação em duas etapas.
- Servidor web configurado para servir esta pasta por HTTPS em produção.

## Configuração

### Início rápido com SQLite

1. Inicie o servidor local. Se `pdo_sqlite` não estiver habilitado no seu `php.ini`, carregue a extensão no comando:

   ```powershell
   $phpRoot = Split-Path (Get-Command php).Source
   php -d "extension_dir=$phpRoot\ext" -d extension=pdo_sqlite -d extension=openssl -S 127.0.0.1:8000
   ```

2. Acesse `http://127.0.0.1:8000`. O banco é criado automaticamente em `%LOCALAPPDATA%\AsterLogin\users.sqlite`, fora da pasta pública. Para escolher outro arquivo, defina `AUTH_DB_PATH`.

A chave local usada para proteger segredos do autenticador fica em `%LOCALAPPDATA%\AsterLogin\totp.key`. Faça backup dela junto do banco em local privado: sem essa chave, os autenticadores configurados não poderão ser recuperados.

### MySQL opcional

1. Crie o banco e as tabelas executando `schema.sql` com um usuário MySQL autorizado a criar o banco.
2. Gere uma chave de aplicação exclusiva para este ambiente e configure as variáveis de ambiente antes de iniciar o PHP. Guarde `AUTH_APP_KEY` em um gerenciador de segredos; não a publique nem a altere depois de ativar autenticadores.

   ```text
   AUTH_APP_KEY=chave-base64-de-32-bytes
   AUTH_DB_DRIVER=mysql
   AUTH_DB_HOST=127.0.0.1
   AUTH_DB_PORT=3306
   AUTH_DB_NAME=login_app
   AUTH_DB_USER=seu_usuario
   AUTH_DB_PASSWORD=sua_senha
   ```

3. Inicie o servidor PHP localmente. Se `pdo_mysql` não estiver habilitado no `php.ini`, carregue a extensão:

   ```powershell
   $phpRoot = Split-Path (Get-Command php).Source
   $env:AUTH_APP_KEY = 'chave-base64-de-32-bytes'
   $env:AUTH_DB_DRIVER = 'mysql'
   $env:AUTH_DB_HOST = '127.0.0.1'
   $env:AUTH_DB_NAME = 'login_app'
   $env:AUTH_DB_USER = 'seu_usuario'
   $env:AUTH_DB_PASSWORD = 'sua_senha'
   php -d "extension_dir=$phpRoot\ext" -d extension=pdo_mysql -d extension=openssl -S 127.0.0.1:8000
   ```

Para produção, use HTTPS e não exponha arquivos de configuração ou credenciais no diretório público.
Gere uma chave Base64 de 32 bytes com `php -r "echo base64_encode(random_bytes(32)), PHP_EOL;"`. Em produção atrás de um proxy HTTPS, defina `AUTH_FORCE_SECURE_COOKIE=1` somente quando o proxy encaminhar exclusivamente conexões TLS.

## Verificação em duas etapas

1. Entre na conta e selecione **Configurar verificação em 2 etapas**.
2. No aplicativo autenticador, adicione uma chave TOTP manual usando o segredo exibido. Configure o padrão de 6 dígitos a cada 30 segundos e confirme com o código atual.
3. Guarde os oito códigos de recuperação mostrados após a ativação. Cada código funciona uma única vez e não pode ser recuperado pela aplicação.
4. Nos próximos acessos, informe sua senha e depois o código do autenticador ou um código de recuperação.

Os segredos TOTP são cifrados com AES-256-GCM; códigos de recuperação são armazenados apenas como hashes. O sistema migra automaticamente bancos SQLite locais já existentes. Para MySQL existente, a aplicação também acrescenta as colunas e tabelas necessárias ao conectar; o `schema.sql` atualizado pode ser usado em novas instalações.

Sessões expiram após 30 minutos sem atividade ou 12 horas no máximo. A configuração e desativação do autenticador exigem sessão autenticada e proteção CSRF; a desativação também pede senha e um código atual.

## Proteções incluídas

- Hash de senha com `password_hash()` e verificação com `password_verify()`. Argon2id é usado quando disponível; caso contrário, o PHP escolhe o algoritmo padrão.
- Consultas PDO preparadas e modo de prepares nativos.
- Token CSRF validado com comparação segura em todos os formulários, inclusive sair.
- Cookies de sessão `HttpOnly`, `SameSite=Lax` e `Secure` sob HTTPS; modo estrito de sessão e regeneração do ID após autenticação.
- Bloqueio por 15 minutos após 5 falhas por conta/IP e limite adicional de 20 falhas por IP. Os identificadores guardados na tabela de tentativas são hashes, não endereços IP ou e-mails em texto.
- Mensagens genéricas para credenciais inválidas e conta duplicada, para reduzir enumeração de contas.

## Interface

- Layout responsivo branco e roxo, marca Aster em texto e campos em formato pílula.
- Fundo translúcido com bolhas animadas, indicador de envio e confirmação verde ao entrar.
- Tipografia Manrope carregada do Google Fonts, com fontes do sistema como alternativa.
- As animações respeitam a preferência de movimento reduzido do sistema.

## Testes

Execute os testes das funções TOTP, cifra de segredos e códigos de recuperação com:

```powershell
php tests/security_test.php
```

## Estrutura do projeto

```text
assets/
  css/app.css       # estilos divididos em seções
index.php           # interface e operações de autenticação
schema.sql          # tabelas MySQL
README.md
```

O `.gitignore` exclui configurações locais, credenciais e bancos de desenvolvimento. O projeto usa PHP e precisa de uma hospedagem compatível; GitHub Pages não executa PHP.
