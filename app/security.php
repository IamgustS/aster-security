<?php
declare(strict_types=1);

const SESSION_IDLE_LIMIT = 1800;
const SESSION_ABSOLUTE_LIMIT = 43200;
const TWO_FACTOR_CHALLENGE_LIMIT = 300;

// Session configuration and expiry enforcement.
function startSecureSession(): void
{
    $secureCookie = (
        isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'
    ) || getenv('AUTH_FORCE_SECURE_COOKIE') === '1';

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.gc_maxlifetime', (string) SESSION_ABSOLUTE_LIMIT);
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $secureCookie,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();

    $now = time();
    $lastActivity = (int) ($_SESSION['_last_activity'] ?? $now);
    $startedAt = (int) ($_SESSION['_started_at'] ?? $now);
    if (
        $now - $lastActivity > SESSION_IDLE_LIMIT
        || $now - $startedAt > SESSION_ABSOLUTE_LIMIT
    ) {
        $_SESSION = [];
        session_regenerate_id(true);
        $_SESSION['notice'] = 'Sua sessão expirou. Entre novamente para continuar.';
        $now = time();
    }

    $_SESSION['_started_at'] ??= $now;
    $_SESSION['_last_activity'] = $now;
}

// Base32 and RFC 6238 TOTP primitives used by authenticator apps.
function encodeBase32(string $bytes): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $buffer = 0;
    $bits = 0;
    $encoded = '';

    for ($index = 0, $length = strlen($bytes); $index < $length; $index++) {
        $buffer = ($buffer << 8) | ord($bytes[$index]);
        $bits += 8;
        while ($bits >= 5) {
            $bits -= 5;
            $encoded .= $alphabet[($buffer >> $bits) & 31];
        }
    }

    if ($bits > 0) {
        $encoded .= $alphabet[($buffer << (5 - $bits)) & 31];
    }

    return $encoded;
}

function decodeBase32(string $encoded): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $buffer = 0;
    $bits = 0;
    $decoded = '';

    foreach (str_split(strtoupper(str_replace(' ', '', $encoded))) as $character) {
        $value = strpos($alphabet, $character);
        if ($value === false) {
            throw new InvalidArgumentException('O segredo do autenticador é inválido.');
        }
        $buffer = ($buffer << 5) | $value;
        $bits += 5;
        if ($bits >= 8) {
            $bits -= 8;
            $decoded .= chr(($buffer >> $bits) & 255);
        }
    }

    return $decoded;
}

function getTotpCode(string $secret, int $counter): string
{
    $key = decodeBase32($secret);
    $message = pack('N2', intdiv($counter, 4294967296), $counter % 4294967296);
    $digest = hash_hmac('sha1', $message, $key, true);
    $offset = ord($digest[19]) & 15;
    $binary = (
        ((ord($digest[$offset]) & 127) << 24)
        | ((ord($digest[$offset + 1]) & 255) << 16)
        | ((ord($digest[$offset + 2]) & 255) << 8)
        | (ord($digest[$offset + 3]) & 255)
    );

    return str_pad((string) ($binary % 1000000), 6, '0', STR_PAD_LEFT);
}

function verifyTotpCode(string $secret, string $code, int $lastCounter = -1): ?int
{
    if (!preg_match('/\A[0-9]{6}\z/', $code)) {
        return null;
    }

    $currentCounter = intdiv(time(), 30);
    for ($counter = max(0, $currentCounter - 1); $counter <= $currentCounter + 1; $counter++) {
        if ($counter > $lastCounter && hash_equals(getTotpCode($secret, $counter), $code)) {
            return $counter;
        }
    }

    return null;
}

// Protect TOTP secrets at rest and provision a stable per-installation key.
function encryptTotpSecret(string $secret, string $key): string
{
    $nonce = random_bytes(12);
    $tag = '';
    $ciphertext = openssl_encrypt(
        $secret,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $nonce,
        $tag
    );
    if ($ciphertext === false) {
        throw new RuntimeException('Não foi possível proteger o segredo do autenticador.');
    }

    return base64_encode($nonce . $tag . $ciphertext);
}

function decryptTotpSecret(string $encrypted, string $key): string
{
    $payload = base64_decode($encrypted, true);
    if ($payload === false || strlen($payload) < 29) {
        throw new RuntimeException('O segredo do autenticador armazenado é inválido.');
    }

    $secret = openssl_decrypt(
        substr($payload, 28),
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        substr($payload, 0, 12),
        substr($payload, 12, 16)
    );
    if ($secret === false) {
        throw new RuntimeException('Não foi possível ler o segredo do autenticador.');
    }

    return $secret;
}

function getTotpEncryptionKey(string $driver, string $databasePath): string
{
    if (!function_exists('openssl_encrypt') || !function_exists('openssl_decrypt')) {
        throw new RuntimeException('Ative a extensão OpenSSL do PHP para usar o autenticador.');
    }

    $configuredKey = getenv('AUTH_APP_KEY');
    if ($configuredKey !== false && $configuredKey !== '') {
        $decodedKey = base64_decode($configuredKey, true);
        if ($decodedKey === false || strlen($decodedKey) !== 32) {
            throw new RuntimeException('AUTH_APP_KEY deve ser uma chave Base64 de 32 bytes.');
        }

        return $decodedKey;
    }

    if ($driver !== 'sqlite' || $databasePath === ':memory:') {
        throw new RuntimeException('Configure AUTH_APP_KEY antes de ativar o autenticador.');
    }

    $keyPath = dirname($databasePath) . DIRECTORY_SEPARATOR . 'totp.key';
    if (is_file($keyPath)) {
        $key = file_get_contents($keyPath);
    } else {
        $key = random_bytes(32);
        $handle = @fopen($keyPath, 'x');
        if ($handle === false) {
            if (!is_file($keyPath)) {
                throw new RuntimeException('Não foi possível salvar a chave do autenticador.');
            }
            $key = file_get_contents($keyPath);
        } else {
            $written = fwrite($handle, $key);
            fflush($handle);
            fclose($handle);
            if ($written !== 32) {
                throw new RuntimeException('Não foi possível salvar a chave do autenticador.');
            }
            @chmod($keyPath, 0600);
        }
    }

    if ($key === false || strlen($key) !== 32) {
        throw new RuntimeException('A chave local do autenticador é inválida.');
    }

    return $key;
}

// One-time backup codes are random, normalized, and stored as hashes by the caller.
function createRecoveryCodes(): array
{
    return array_map(
        static fn (): string => strtoupper(bin2hex(random_bytes(16))),
        range(1, 8)
    );
}

function normalizeRecoveryCode(string $code): ?string
{
    $normalized = strtoupper((string) preg_replace('/[\s-]+/', '', $code));

    return preg_match('/\A[A-F0-9]{32}\z/', $normalized) ? $normalized : null;
}
