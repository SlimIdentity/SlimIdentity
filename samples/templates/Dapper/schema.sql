-- SlimIdentity sample schema (PostgreSQL). Adapt types for SQL Server / SQLite.
-- Only the tables of the capabilities you register are needed.

CREATE TABLE users (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 varchar(256) NOT NULL,
    normalized_email      varchar(256) NOT NULL UNIQUE,
    password_hash         text         NOT NULL DEFAULT '',
    security_stamp        varchar(64)  NOT NULL,
    is_active             boolean      NOT NULL DEFAULT true,
    email_confirmed       boolean      NOT NULL DEFAULT false,
    failed_login_attempts int          NOT NULL DEFAULT 0,
    lockout_end_utc       timestamptz  NULL,
    failed_second_factor_attempts int  NOT NULL DEFAULT 0,
    second_factor_lockout_end_utc timestamptz NULL,
    two_factor_enabled    boolean      NOT NULL DEFAULT false,
    password_change_required boolean   NOT NULL DEFAULT false,
    totp_secret           text         NULL,   -- ISlimTwoFactorStore; already encrypted by SlimIdentity
    last_2fa_code_at      bigint       NULL,   -- ISlimTwoFactorStore replay protection (unix milliseconds)
    last_2fa_challenge_at bigint       NULL,   -- ISlimTwoFactorStore single-use sign-in challenge (unix milliseconds)
    -- business columns belong to you:
    display_name          text         NULL
);

CREATE TABLE user_roles (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role    varchar(64) NOT NULL,
    PRIMARY KEY (user_id, role)
);

-- ISlimRefreshTokenStore
CREATE TABLE refresh_tokens (
    token_hash char(64)    PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);
CREATE INDEX ix_refresh_tokens_user ON refresh_tokens(user_id);

-- ISlimSessionStore
CREATE TABLE user_sessions (
    id                     char(32)     PRIMARY KEY,
    user_id                uuid         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mode                   varchar(16)  NOT NULL,
    authentication_method  varchar(32)  NOT NULL,
    impersonator_id        text         NULL,
    created_utc            timestamptz  NOT NULL,
    last_seen_utc          timestamptz  NOT NULL,
    expires_utc            timestamptz  NOT NULL,
    user_agent             varchar(256) NULL,   -- personal data: drop the column if you do not need it
    ip_address             varchar(45)  NULL    -- personal data: drop the column if you do not need it
);
CREATE INDEX ix_user_sessions_user ON user_sessions(user_id);
CREATE INDEX ix_user_sessions_expires ON user_sessions(expires_utc);  -- cleanup: DELETE ... WHERE expires_utc < now()

-- ISlimTwoFactorStore
CREATE TABLE recovery_codes (
    user_id   uuid     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash char(64) NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);

-- ISlimExternalLoginStore
CREATE TABLE external_logins (
    provider     varchar(64)  NOT NULL,
    provider_key varchar(256) NOT NULL,
    user_id      uuid         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (provider, provider_key)
);
CREATE INDEX ix_external_logins_user ON external_logins(user_id);

-- ISlimPasskeyStore (credential ids may be up to 1023 bytes: keyed by their SHA-256)
CREATE TABLE passkeys (
    credential_id_hash bytea        PRIMARY KEY,
    credential_id      bytea        NOT NULL,
    user_id            uuid         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key         bytea        NOT NULL,
    sign_count         bigint       NOT NULL DEFAULT 0,
    backup_eligible    boolean      NOT NULL DEFAULT false,   -- may be synced – fixed for the passkey
    backed_up          boolean      NOT NULL DEFAULT false,   -- currently synced – updated at every sign-in
    user_handle        bytea,                                 -- WebAuthn user handle (random, at most 64 bytes)
    last_challenge_at  bigint       NULL,
    name               varchar(64)  NOT NULL,
    created_utc        timestamptz  NOT NULL,
    last_used_utc      timestamptz  NULL
);
CREATE INDEX ix_passkeys_user ON passkeys(user_id);

-- ISlimApiKeyStore
CREATE TABLE api_keys (
    key_hash   char(64)    PRIMARY KEY,   -- SlimApiKeys.Hash(key)
    client_id  varchar(64) NOT NULL,
    scopes     text[]      NOT NULL DEFAULT '{}',
    expires_at timestamptz NULL,
    revoked    boolean     NOT NULL DEFAULT false
);
