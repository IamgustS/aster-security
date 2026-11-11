<?php
declare(strict_types=1);

require __DIR__ . '/../app/security.php';
require __DIR__ . '/../app/oauth.php';

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

// Verify the RFC vectors and the single-use/replay behavior of TOTP.
$secret = encodeBase32('12345678901234567890');
check(
    $secret === 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
    'Base32 encoding does not match the RFC 4648 vector.'
);
check(
    decodeBase32($secret) === '12345678901234567890',
    'Base32 decoding does not restore the original secret.'
);

$vectors = [
    59 => '287082',
    1111111109 => '081804',
    1111111111 => '050471',
    1234567890 => '005924',
    2000000000 => '279037',
];
foreach ($vectors as $timestamp => $expected) {
    check(
        getTotpCode($secret, intdiv($timestamp, 30)) === $expected,
        'TOTP code does not match the RFC 6238 vector at ' . $timestamp . '.'
    );
}

$currentCounter = intdiv(time(), 30);
$currentCode = getTotpCode($secret, $currentCounter);
check(
    verifyTotpCode($secret, $currentCode, $currentCounter - 1) === $currentCounter,
    'The current TOTP code should be accepted once.'
);
check(
    verifyTotpCode($secret, $currentCode, $currentCounter) === null,
    'A previously used TOTP counter should be rejected.'
);

// Verify authenticated encryption and recovery-code format/normalization.
$key = random_bytes(32);
$encrypted = encryptTotpSecret($secret, $key);
check(
    decryptTotpSecret($encrypted, $key) === $secret,
    'The encrypted TOTP secret did not decrypt correctly.'
);
$payload = base64_decode($encrypted, true);
$payload[28] = chr(ord($payload[28]) ^ 1);
$tamperedWasRejected = false;
try {
    decryptTotpSecret(base64_encode($payload), $key);
} catch (RuntimeException) {
    $tamperedWasRejected = true;
}
check($tamperedWasRejected, 'Tampered TOTP ciphertext was not rejected.');

$codes = createRecoveryCodes();
check(count($codes) === 8 && count(array_unique($codes)) === 8, 'Recovery codes must be unique.');
foreach ($codes as $code) {
    check(
        strlen($code) === 32 && normalizeRecoveryCode($code) === $code,
        'A generated recovery code has an invalid format.'
    );
}
check(
    normalizeRecoveryCode(substr($codes[0], 0, 16) . '-' . substr($codes[0], 16)) === $codes[0],
    'Recovery code formatting should tolerate a separator.'
);

// Verify OAuth PKCE, state handling, provider configuration, and account linking.
$_SESSION = [];
$oauthUrl = createOAuthAuthorizationUrl('google', [
    'client_id' => 'client-id',
    'client_secret' => 'client-secret',
    'redirect_uri' => 'http://127.0.0.1:8000/?oauth_callback=google',
]);
$oauthTransaction = $_SESSION['oauth_transactions']['google'];
$authorizationParameters = [];
parse_str((string) parse_url($oauthUrl, PHP_URL_QUERY), $authorizationParameters);
check(
    str_starts_with($oauthUrl, 'https://accounts.google.com/')
    && ($authorizationParameters['code_challenge_method'] ?? null) === 'S256'
    && hash_equals(
        rtrim(strtr(base64_encode(hash('sha256', $oauthTransaction['verifier'], true)), '+/', '-_'), '='),
        (string) ($authorizationParameters['code_challenge'] ?? '')
    ),
    'OAuth authorization must use the provider endpoint and PKCE S256.'
);
check(
    consumeOAuthTransaction('google', 'incorrect-state') === null
    && isset($_SESSION['oauth_transactions']['google']),
    'An invalid OAuth state must not consume the pending valid transaction.'
);
check(
    consumeOAuthTransaction('google', $oauthTransaction['state']) === $oauthTransaction['verifier'],
    'A valid OAuth state should be consumed once.'
);
check(
    consumeOAuthTransaction('google', $oauthTransaction['state']) === null,
    'A consumed OAuth state must not be reusable.'
);
check(getOAuthProviderConfig('unknown') === null, 'Unknown OAuth providers must not be configured.');

$oauthEnvironmentKeys = [
    'AUTH_OAUTH_GOOGLE_CLIENT_ID' => getenv('AUTH_OAUTH_GOOGLE_CLIENT_ID'),
    'AUTH_OAUTH_GOOGLE_CLIENT_SECRET' => getenv('AUTH_OAUTH_GOOGLE_CLIENT_SECRET'),
    'AUTH_OAUTH_GOOGLE_REDIRECT_URI' => getenv('AUTH_OAUTH_GOOGLE_REDIRECT_URI'),
];
putenv('AUTH_OAUTH_GOOGLE_CLIENT_ID=test-client');
putenv('AUTH_OAUTH_GOOGLE_CLIENT_SECRET=test-secret');
putenv('AUTH_OAUTH_GOOGLE_REDIRECT_URI=http://127.0.0.1:8000/?oauth_callback=google');
check(
    getOAuthProviderConfig('google') !== null,
    'A complete loopback OAuth configuration should be accepted for local development.'
);
putenv('AUTH_OAUTH_GOOGLE_REDIRECT_URI=http://example.test/?oauth_callback=google');
check(
    getOAuthProviderConfig('google') === null,
    'OAuth redirect URIs over plain HTTP must be restricted to loopback hosts.'
);
foreach ($oauthEnvironmentKeys as $key => $value) {
    if ($value === false) {
        putenv($key);
    } else {
        putenv($key . '=' . $value);
    }
}

$oauthDatabase = new PDO('sqlite::memory:', null, null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);
$oauthDatabase->exec(
    'CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email VARCHAR(254) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        oauth_only INTEGER NOT NULL DEFAULT 0,
        totp_enabled INTEGER NOT NULL DEFAULT 0
    )'
);
$oauthDatabase->exec(
    'CREATE TABLE oauth_identities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        provider VARCHAR(32) NOT NULL,
        subject VARCHAR(255) NOT NULL,
        UNIQUE (provider, subject),
        UNIQUE (user_id, provider)
    )'
);
$googleUser = findOrCreateOAuthUser($oauthDatabase, 'google', [
    'subject' => 'google-subject-1',
    'email' => 'new-user@example.test',
]);
$sameGoogleUser = findOrCreateOAuthUser($oauthDatabase, 'google', [
    'subject' => 'google-subject-1',
    'email' => 'new-user@example.test',
]);
check(
    $googleUser['id'] === $sameGoogleUser['id']
    && (int) $googleUser['oauth_only'] === 1,
    'Repeated OAuth sign-ins should resolve to the same local account.'
);
$githubUser = findOrCreateOAuthUser($oauthDatabase, 'github', [
    'subject' => 'github-subject-1',
    'email' => 'new-user@example.test',
]);
check(
    $googleUser['id'] === $githubUser['id'],
    'Verified identities from different providers with the same email should link to one account.'
);
$oauthDatabase->exec(
    "INSERT INTO users (email, password_hash) VALUES ('local-user@example.test', 'existing-hash')"
);
$linkedLocalUser = findOrCreateOAuthUser($oauthDatabase, 'google', [
    'subject' => 'google-subject-2',
    'email' => 'local-user@example.test',
]);
check(
    (int) $linkedLocalUser['oauth_only'] === 0,
    'Linking an OAuth identity must not remove password confirmation from an existing account.'
);

echo "Security tests passed.\n";
