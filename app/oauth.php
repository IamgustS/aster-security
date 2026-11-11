<?php
declare(strict_types=1);

const OAUTH_PROVIDERS = ['google', 'github'];

// Validate provider settings before exposing an active sign-in button.
function getOAuthProviderConfig(string $provider): ?array
{
    if (!in_array($provider, OAUTH_PROVIDERS, true)) {
        return null;
    }

    $prefix = strtoupper($provider);
    $clientId = getenv("AUTH_OAUTH_{$prefix}_CLIENT_ID");
    $clientSecret = getenv("AUTH_OAUTH_{$prefix}_CLIENT_SECRET");
    $redirectUri = getenv("AUTH_OAUTH_{$prefix}_REDIRECT_URI");

    if (
        $clientId === false || $clientId === ''
        || $clientSecret === false || $clientSecret === ''
        || $redirectUri === false || $redirectUri === ''
    ) {
        return null;
    }

    $parts = parse_url($redirectUri);
    if (
        !is_array($parts)
        || !isset($parts['scheme'], $parts['host'])
        || !in_array(strtolower($parts['scheme']), ['https', 'http'], true)
        || (strtolower($parts['scheme']) !== 'https' && !in_array(strtolower($parts['host']), ['localhost', '127.0.0.1', '[::1]'], true))
        || isset($parts['user'])
        || isset($parts['pass'])
        || isset($parts['fragment'])
    ) {
        return null;
    }

    return [
        'client_id' => $clientId,
        'client_secret' => $clientSecret,
        'redirect_uri' => $redirectUri,
    ];
}

// OAuth authorization uses expiring state and PKCE, consumed only after state matches.
function createOAuthStateToken(int $byteCount = 32): string
{
    return rtrim(strtr(base64_encode(random_bytes($byteCount)), '+/', '-_'), '=');
}

function createOAuthAuthorizationUrl(string $provider, array $config): string
{
    $state = createOAuthStateToken();
    $verifier = createOAuthStateToken(48);
    $_SESSION['oauth_transactions'][$provider] = [
        'state' => $state,
        'verifier' => $verifier,
        'expires_at' => time() + 600,
    ];

    $parameters = [
        'client_id' => $config['client_id'],
        'redirect_uri' => $config['redirect_uri'],
        'response_type' => 'code',
        'scope' => $provider === 'google' ? 'openid email profile' : 'read:user user:email',
        'state' => $state,
        'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
        'code_challenge_method' => 'S256',
    ];

    $endpoint = $provider === 'google'
        ? 'https://accounts.google.com/o/oauth2/v2/auth'
        : 'https://github.com/login/oauth/authorize';

    return $endpoint . '?' . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
}

function consumeOAuthTransaction(string $provider, string $state): ?string
{
    $transaction = $_SESSION['oauth_transactions'][$provider] ?? null;

    if (
        !is_array($transaction)
        || !isset($transaction['state'], $transaction['verifier'], $transaction['expires_at'])
        || !is_string($transaction['state'])
        || !is_string($transaction['verifier'])
    ) {
        unset($_SESSION['oauth_transactions'][$provider]);
        return null;
    }

    if ((int) $transaction['expires_at'] < time()) {
        unset($_SESSION['oauth_transactions'][$provider]);
        return null;
    }

    if ($state === '' || !hash_equals($transaction['state'], $state)) {
        return null;
    }

    unset($_SESSION['oauth_transactions'][$provider]);
    return $transaction['verifier'];
}

// Send bounded HTTPS requests and reject transport or response errors.
function requestOAuthJson(string $url, array $headers, ?array $form = null): array
{
    $options = [
        'http' => [
            'method' => $form === null ? 'GET' : 'POST',
            'header' => implode("\r\n", $headers),
            'ignore_errors' => true,
            'timeout' => 12,
            'protocol_version' => 1.1,
        ],
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
        ],
    ];
    if ($form !== null) {
        $options['http']['header'] .= "\r\nContent-Type: application/x-www-form-urlencoded";
        $options['http']['content'] = http_build_query($form, '', '&', PHP_QUERY_RFC3986);
    }

    $context = stream_context_create($options);
    $response = @file_get_contents($url, false, $context);
    $status = 0;
    foreach ($http_response_header ?? [] as $header) {
        if (preg_match('/^HTTP\/\S+\s+([0-9]{3})/', $header, $matches)) {
            $status = (int) $matches[1];
        }
    }
    if ($response === false || $status < 200 || $status >= 300) {
        throw new RuntimeException('O provedor de login não respondeu como esperado.');
    }

    $data = json_decode($response, true);
    if (!is_array($data)) {
        throw new RuntimeException('O provedor de login retornou uma resposta inválida.');
    }

    return $data;
}

// Exchange the one-time authorization code and retrieve a verified provider identity.
function exchangeOAuthCode(string $provider, array $config, string $code, string $verifier): array
{
    $headers = ['Accept: application/json'];
    if ($provider === 'github') {
        $headers[] = 'User-Agent: AsterLogin';
    }

    $tokenEndpoint = $provider === 'google'
        ? 'https://oauth2.googleapis.com/token'
        : 'https://github.com/login/oauth/access_token';
    $token = requestOAuthJson($tokenEndpoint, $headers, [
        'client_id' => $config['client_id'],
        'client_secret' => $config['client_secret'],
        'code' => $code,
        'redirect_uri' => $config['redirect_uri'],
        'grant_type' => 'authorization_code',
        'code_verifier' => $verifier,
    ]);
    $accessToken = $token['access_token'] ?? null;
    if (!is_string($accessToken) || $accessToken === '') {
        throw new RuntimeException('O provedor de login não autorizou a solicitação.');
    }

    $apiHeaders = [
        'Accept: application/vnd.github+json',
        'Authorization: Bearer ' . $accessToken,
    ];
    if ($provider === 'google') {
        $profile = requestOAuthJson('https://openidconnect.googleapis.com/v1/userinfo', [
            'Accept: application/json',
            'Authorization: Bearer ' . $accessToken,
        ]);
        if (($profile['email_verified'] ?? false) !== true) {
            throw new RuntimeException('O provedor não confirmou o endereço de e-mail.');
        }

        return [
            'subject' => $profile['sub'] ?? null,
            'email' => $profile['email'] ?? null,
        ];
    }

    $profile = requestOAuthJson('https://api.github.com/user', $apiHeaders);
    $email = null;
    $emails = requestOAuthJson('https://api.github.com/user/emails?per_page=100', $apiHeaders);
    foreach ($emails as $entry) {
        if (
            is_array($entry)
            && is_string($entry['email'] ?? null)
            && ($entry['verified'] ?? false) === true
            && ($entry['primary'] ?? false) === true
        ) {
            $email = $entry['email'];
            break;
        }
    }

    return [
        'subject' => isset($profile['id']) ? (string) $profile['id'] : null,
        'email' => $email,
    ];
}

// Link verified provider identities to local accounts or create OAuth-only accounts.
function findOrCreateOAuthUser(PDO $pdo, string $provider, array $identity): array
{
    $subject = $identity['subject'] ?? null;
    $email = $identity['email'] ?? null;
    if (
        !is_string($subject) || $subject === '' || strlen($subject) > 255
        || !is_string($email) || strlen($email) > 254
        || !filter_var($email, FILTER_VALIDATE_EMAIL)
    ) {
        throw new RuntimeException('A conta do provedor não tem um e-mail confirmado disponível.');
    }
    $email = strtolower(trim($email));

    try {
        $pdo->beginTransaction();
        $statement = $pdo->prepare(
            'SELECT users.id, users.email, users.totp_enabled, users.oauth_only
             FROM oauth_identities
             JOIN users ON users.id = oauth_identities.user_id
             WHERE oauth_identities.provider = :provider
               AND oauth_identities.subject = :subject
             LIMIT 1'
        );
        $statement->execute(['provider' => $provider, 'subject' => $subject]);
        $user = $statement->fetch();
        if ($user) {
            $pdo->commit();
            return $user;
        }

        $statement = $pdo->prepare(
            'SELECT id, email, totp_enabled, oauth_only FROM users WHERE email = :email LIMIT 1'
        );
        $statement->execute(['email' => $email]);
        $user = $statement->fetch();
        if (!$user) {
            $algorithm = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
            $statement = $pdo->prepare(
                'INSERT INTO users (email, password_hash, oauth_only) VALUES (:email, :password_hash, 1)'
            );
            $statement->execute([
                'email' => $email,
                'password_hash' => password_hash(bin2hex(random_bytes(32)), $algorithm),
            ]);
            $user = [
                'id' => (int) $pdo->lastInsertId(),
                'email' => $email,
                'totp_enabled' => 0,
                'oauth_only' => 1,
            ];
        }

        $statement = $pdo->prepare(
            'INSERT INTO oauth_identities (user_id, provider, subject)
             VALUES (:user_id, :provider, :subject)'
        );
        $statement->execute([
            'user_id' => $user['id'],
            'provider' => $provider,
            'subject' => $subject,
        ]);
        $pdo->commit();

        return $user;
    } catch (PDOException $exception) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        if ($exception->getCode() === '23000') {
            $statement = $pdo->prepare(
                'SELECT users.id, users.email, users.totp_enabled, users.oauth_only
                 FROM oauth_identities
                 JOIN users ON users.id = oauth_identities.user_id
                 WHERE oauth_identities.provider = :provider
                   AND oauth_identities.subject = :subject
                 LIMIT 1'
            );
            $statement->execute(['provider' => $provider, 'subject' => $subject]);
            $existingUser = $statement->fetch();
            if ($existingUser) {
                return $existingUser;
            }
        }
        throw $exception;
    } catch (RuntimeException $exception) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $exception;
    }
}

// Route OAuth start/callback requests and hand successful sign-ins to the session flow.
function handleOAuthRequest(PDO $pdo): ?string
{
    $provider = $_GET['oauth_start'] ?? $_GET['oauth_callback'] ?? '';
    if (!is_string($provider)) {
        return null;
    }
    if (!in_array($provider, OAUTH_PROVIDERS, true)) {
        return null;
    }

    $config = getOAuthProviderConfig($provider);
    if ($config === null) {
        return 'O login por ' . ucfirst($provider) . ' ainda não está configurado neste servidor.';
    }

    if (isset($_GET['oauth_start'])) {
        redirectOAuth(createOAuthAuthorizationUrl($provider, $config));
    }

    $state = is_string($_GET['state'] ?? null) ? $_GET['state'] : '';
    $verifier = consumeOAuthTransaction($provider, $state);
    if ($verifier === null) {
        return 'A verificação do login expirou ou não é válida. Tente novamente.';
    }
    if (isset($_GET['error'])) {
        return 'O login por ' . ucfirst($provider) . ' foi cancelado ou recusado.';
    }

    $code = is_string($_GET['code'] ?? null) ? $_GET['code'] : '';
    if ($code === '' || strlen($code) > 2048) {
        return 'A verificação do login expirou ou não é válida. Tente novamente.';
    }

    try {
        $identity = exchangeOAuthCode($provider, $config, $code, $verifier);
        $user = findOrCreateOAuthUser($pdo, $provider, $identity);
    } catch (RuntimeException $exception) {
        error_log('Falha no login OAuth (' . $provider . '): ' . $exception->getMessage());
        return 'Não foi possível concluir o login por ' . ucfirst($provider) . '. Tente novamente.';
    }

    if ((int) $user['totp_enabled'] === 1) {
        session_regenerate_id(true);
        unset($_SESSION['user'], $_SESSION['oauth_transactions']);
        $_SESSION['pending_2fa_user_id'] = (int) $user['id'];
        $_SESSION['pending_2fa_email'] = (string) $user['email'];
        $_SESSION['pending_2fa_expires'] = time() + TWO_FACTOR_CHALLENGE_LIMIT;
        $_SESSION['_started_at'] = time();
        $_SESSION['_last_activity'] = time();
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        redirect('./');
    }

    completeAuthentication($user);
}

function redirectOAuth(string $url): never
{
    header('Location: ' . $url, true, 302);
    exit;
}
