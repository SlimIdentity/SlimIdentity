-- SlimIdentity sample schema (PostgreSQL). Adapt types for SQL Server / SQLite.

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
    two_factor_enabled    boolean      NOT NULL DEFAULT false,
    -- business columns belong to you:
    display_name          text         NULL
);

CREATE TABLE user_roles (
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role    varchar(64) NOT NULL,
    PRIMARY KEY (user_id, role)
);

CREATE TABLE refresh_tokens (
    token_hash char(64)    PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);
CREATE INDEX ix_refresh_tokens_user ON refresh_tokens(user_id);
