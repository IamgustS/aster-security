CREATE DATABASE IF NOT EXISTS login_app
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE login_app;

-- Accounts include local-password and OAuth-only identities plus optional TOTP state.
CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    email VARCHAR(254) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    oauth_only TINYINT(1) NOT NULL DEFAULT 0,
    totp_secret VARCHAR(255) NULL,
    totp_pending_secret VARCHAR(255) NULL,
    totp_enabled TINYINT(1) NOT NULL DEFAULT 0,
    totp_last_counter BIGINT NOT NULL DEFAULT -1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY users_email_unique (email)
) ENGINE=InnoDB;

-- One-time recovery tokens and hashed login throttling buckets.
CREATE TABLE IF NOT EXISTS recovery_codes (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    code_hash CHAR(64) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY recovery_codes_user_hash (user_id, code_hash),
    CONSTRAINT recovery_codes_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS login_attempts (
    bucket_key CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    failures SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    window_started DATETIME NOT NULL,
    locked_until DATETIME NULL,
    PRIMARY KEY (bucket_key),
    KEY login_attempts_locked_until (locked_until)
) ENGINE=InnoDB;

-- External provider identities are unique per provider and local user.
CREATE TABLE IF NOT EXISTS oauth_identities (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    provider VARCHAR(32) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY oauth_provider_subject_unique (provider, subject),
    UNIQUE KEY oauth_user_provider_unique (user_id, provider),
    CONSTRAINT oauth_identity_user_fk
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;
