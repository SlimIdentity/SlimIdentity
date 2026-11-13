// SlimIdentity sample – Dapper (plain SQL, PostgreSQL via Npgsql). Schema: schema.sql
// Packages: Dapper, Npgsql   (for Native AOT use Dapper.AOT or hand-written ADO.NET mapping)
//
//   builder.Services.AddSingleton(NpgsqlDataSource.Create(connectionString));
//   builder.Services.AddSlimIdentity(...)
//       .AddUserStore<DapperUserStore>()
//       .AddRefreshTokenStore<DapperRefreshTokenStore>()
//       .AddSessionStore<DapperSessionStore>()
//       .AddTwoFactorStore<DapperTwoFactorStore>()
//       .AddExternalLoginStore<DapperExternalLoginStore>()
//       .AddPasskeyStore<DapperPasskeyStore>()             // package SlimIdentity.Passkeys
//       .AddApiKeyStore<DapperApiKeyStore>();

using System.Security.Claims;
using Dapper;
using Npgsql;
using SlimIdentity;

namespace MyApp.Data;

public sealed class DapperUserStore(NpgsqlDataSource db) : ISlimUserStore
{
    private const string Columns = """
        id::text               AS Id,
        email                  AS Email,
        password_hash          AS PasswordHash,
        security_stamp         AS SecurityStamp,
        is_active              AS IsActive,
        email_confirmed        AS EmailConfirmed,
        failed_login_attempts  AS FailedLoginAttempts,
        lockout_end_utc        AS LockoutEndUtc,
        failed_second_factor_attempts AS FailedSecondFactorAttempts,
        second_factor_lockout_end_utc AS SecondFactorLockoutEndUtc,
        two_factor_enabled     AS TwoFactorEnabled,
        password_change_required AS PasswordChangeRequired
        """;

    public async Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        return await c.QuerySingleOrDefaultAsync<SlimUser>(new CommandDefinition(
            $"SELECT {Columns} FROM users WHERE normalized_email = @e", new { e = email.Trim().ToUpperInvariant() }, cancellationToken: ct));
    }

    public async Task<SlimUser?> FindByIdAsync(string userId, CancellationToken ct)
    {
        if (!Guid.TryParse(userId, out var id)) return null;
        await using var c = await db.OpenConnectionAsync(ct);
        return await c.QuerySingleOrDefaultAsync<SlimUser>(new CommandDefinition(
            $"SELECT {Columns} FROM users WHERE id = @id", new { id }, cancellationToken: ct));
    }

    public async Task<SlimUser?> CreateAsync(SlimNewUser newUser, CancellationToken ct)
    {
        var (email, passwordHash) = (newUser.Email, newUser.PasswordHash);
        await using var c = await db.OpenConnectionAsync(ct);
        // ON CONFLICT: a concurrent registration with the same address yields no row → null (UNIQUE on normalized_email).
        // With a registration profile (newUser.Profile): open a transaction, insert the profile with the returned id in it
        // only if a row came back, then commit – account and profile together or not at all.
        return await c.QuerySingleOrDefaultAsync<SlimUser>(new CommandDefinition($"""
            INSERT INTO users (email, normalized_email, password_hash, security_stamp)
            VALUES (@email, @normalized, @hash, @stamp)
            ON CONFLICT (normalized_email) DO NOTHING
            RETURNING {Columns}
            """,
            new { email, normalized = email.ToUpperInvariant(), hash = passwordHash, stamp = SlimUser.NewSecurityStamp() },
            cancellationToken: ct));
    }

    // ---- sign-in bookkeeping: narrow, atomic statements (never write back a whole, possibly outdated user)

    // Reserves an attempt before it is checked. The row lock serializes parallel attempts across all instances:
    // exactly one reaches the threshold, every later one sees the lockout.
    public async Task<SlimAttemptReservation?> TryBeginAttemptAsync(SlimUser user, SlimAttemptRequest attempt, CancellationToken ct)
    {
        var (counter, end) = AttemptColumns(attempt.Factor);
        await using var c = await db.OpenConnectionAsync(ct);
        await using var tx = await c.BeginTransactionAsync(ct);
        var current = await c.QuerySingleOrDefaultAsync<AttemptState>(new CommandDefinition(
            $"SELECT {counter} AS Count, {end} AS LockoutEnd FROM users WHERE id = @id::uuid FOR UPDATE",
            new { id = user.Id }, tx, cancellationToken: ct));
        if (current is null) return null;   // deleted during the sign-in
        if (attempt.IsLockedOut(current.LockoutEnd)) return SlimAttemptReservation.LockedOut(current.LockoutEnd!.Value);

        var count = current.Count + 1;
        await c.ExecuteAsync(new CommandDefinition(
            $"UPDATE users SET {counter} = @count, {end} = @newEnd WHERE id = @id::uuid",
            new { id = user.Id, count, newEnd = attempt.NextLockoutEnd(count, current.LockoutEnd) }, tx, cancellationToken: ct));
        await tx.CommitAsync(ct);
        return SlimAttemptReservation.Reserved(count);
    }

    private sealed record AttemptState(int Count, DateTimeOffset? LockoutEnd);

    public async Task ResetFailedAttemptsAsync(SlimUser user, SlimAttemptFactor factor, CancellationToken ct)
    {
        var (counter, end) = AttemptColumns(factor);
        await using var c = await db.OpenConnectionAsync(ct);
        await c.ExecuteAsync(new CommandDefinition(
            $"UPDATE users SET {counter} = 0, {end} = NULL WHERE id = @id::uuid",
            new { id = user.Id }, cancellationToken: ct));
    }

    private static (string Counter, string End) AttemptColumns(SlimAttemptFactor factor) =>
        factor == SlimAttemptFactor.Password
            ? ("failed_login_attempts", "lockout_end_utc")
            : ("failed_second_factor_attempts", "second_factor_lockout_end_utc");

    // conditional: a password change in the meantime wins over the transparent rehash
    public async Task UpdatePasswordHashAsync(SlimUser user, string currentHash, string newHash, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        await c.ExecuteAsync(new CommandDefinition(
            "UPDATE users SET password_hash = @newHash WHERE id = @id::uuid AND password_hash = @currentHash",
            new { id = user.Id, currentHash, newHash }, cancellationToken: ct));
    }

    // compare-and-set on the whole stamp: a change based on an outdated copy is never written back over a newer one
    public async Task<bool> UpdateSecurityStateAsync(SlimUser user, string expectedStamp, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        return await c.ExecuteAsync(new CommandDefinition("""
            UPDATE users SET
                password_hash = @PasswordHash,
                security_stamp = @SecurityStamp,
                email_confirmed = @EmailConfirmed,
                two_factor_enabled = @TwoFactorEnabled,
                password_change_required = @PasswordChangeRequired
            WHERE id = @Id::uuid AND COALESCE(security_stamp, '') = @expectedStamp
            """, new
            {
                user.Id, user.PasswordHash, user.SecurityStamp, user.EmailConfirmed, user.TwoFactorEnabled,
                user.PasswordChangeRequired, expectedStamp,
            }, cancellationToken: ct)) == 1;
    }

    // compare-and-set: a concurrent password or 2FA change is never written back over
    public async Task<bool> UpdateSecurityStampAsync(SlimUser user, string expectedStamp, string newStamp, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        return await c.ExecuteAsync(new CommandDefinition(
            "UPDATE users SET security_stamp = @newStamp WHERE id = @id::uuid AND security_stamp = @expectedStamp",
            new { id = user.Id, expectedStamp, newStamp }, cancellationToken: ct)) == 1;
    }

    public async Task<SlimEmailUpdateResult> UpdateEmailAsync(SlimUser user, string newEmail, string expectedStamp, string newStamp, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        try
        {
            // the UNIQUE constraint on normalized_email decides – no check-then-act race
            return await c.ExecuteAsync(new CommandDefinition("""
                UPDATE users SET email = @newEmail, normalized_email = @normalized, email_confirmed = TRUE, security_stamp = @newStamp
                WHERE id = @id::uuid AND COALESCE(security_stamp, '') = @expectedStamp
                """,
                new { id = user.Id, newEmail, normalized = newEmail.ToUpperInvariant(), expectedStamp, newStamp }, cancellationToken: ct)) == 1
                ? SlimEmailUpdateResult.Updated
                : SlimEmailUpdateResult.StampChanged;
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            return SlimEmailUpdateResult.EmailTaken;
        }
    }

    public async Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        var roles = await c.QueryAsync<string>(new CommandDefinition(
            "SELECT role FROM user_roles WHERE user_id = @id::uuid", new { id = user.Id }, cancellationToken: ct));
        return roles.Select(r => new Claim(ClaimTypes.Role, r)).ToList();
    }
}

public sealed class DapperRefreshTokenStore(NpgsqlDataSource db) : ISlimRefreshTokenStore
{
    public async Task StoreRefreshTokenAsync(string userId, string tokenHash, DateTimeOffset expiresAt, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        await c.ExecuteAsync(new CommandDefinition(
            "INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (@tokenHash, @userId::uuid, @expiresAt)",
            new { tokenHash, userId, expiresAt }, cancellationToken: ct));
    }

    public async Task<string?> ValidateAndConsumeRefreshTokenAsync(string tokenHash, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        // DELETE ... RETURNING is atomic: a token can be consumed exactly once
        return await c.QuerySingleOrDefaultAsync<string?>(new CommandDefinition(
            "DELETE FROM refresh_tokens WHERE token_hash = @tokenHash AND expires_at > now() RETURNING user_id::text",
            new { tokenHash }, cancellationToken: ct));
    }
}

/// <summary>Server-side sessions. Delete expired rows periodically: DELETE FROM user_sessions WHERE expires_utc &lt; now().</summary>
public sealed class DapperSessionStore(NpgsqlDataSource db) : ISlimSessionStore
{
    private const string Columns = """
        id                    AS Id,
        user_id::text         AS UserId,
        mode                  AS Mode,
        authentication_method AS AuthenticationMethod,
        impersonator_id       AS ImpersonatorId,
        created_utc           AS CreatedUtc,
        last_seen_utc         AS LastSeenUtc,
        expires_utc           AS ExpiresUtc,
        user_agent            AS UserAgent,
        ip_address            AS IpAddress
        """;

    public async Task CreateAsync(SlimSession session, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        await c.ExecuteAsync(new CommandDefinition("""
            INSERT INTO user_sessions (id, user_id, mode, authentication_method, impersonator_id,
                                       created_utc, last_seen_utc, expires_utc, user_agent, ip_address)
            VALUES (@Id, @UserId::uuid, @Mode, @AuthenticationMethod, @ImpersonatorId,
                    @CreatedUtc, @LastSeenUtc, @ExpiresUtc, @UserAgent, @IpAddress)
            """, session, cancellationToken: ct));
    }

    public async Task<SlimSession?> FindAsync(string sessionId, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        return await c.QuerySingleOrDefaultAsync<SlimSession>(new CommandDefinition(
            $"SELECT {Columns} FROM user_sessions WHERE id = @sessionId", new { sessionId }, cancellationToken: ct));
    }

    public async Task<IReadOnlyCollection<SlimSession>> ListAsync(string userId, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        var rows = await c.QueryAsync<SlimSession>(new CommandDefinition(
            $"SELECT {Columns} FROM user_sessions WHERE user_id = @userId::uuid AND expires_utc > now()", new { userId }, cancellationToken: ct));
        return rows.ToList();
    }

    public async Task TouchAsync(string sessionId, DateTimeOffset lastSeenUtc, DateTimeOffset expiresUtc, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        await c.ExecuteAsync(new CommandDefinition(
            "UPDATE user_sessions SET last_seen_utc = @lastSeenUtc, expires_utc = @expiresUtc WHERE id = @sessionId",
            new { sessionId, lastSeenUtc, expiresUtc }, cancellationToken: ct));
    }

    public async Task RevokeAsync(string sessionId, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        await c.ExecuteAsync(new CommandDefinition("DELETE FROM user_sessions WHERE id = @sessionId", new { sessionId }, cancellationToken: ct));
    }

    public async Task RevokeAllAsync(string userId, string? exceptSessionId, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        await c.ExecuteAsync(new CommandDefinition(
            "DELETE FROM user_sessions WHERE user_id = @userId::uuid AND (@exceptSessionId::text IS NULL OR id <> @exceptSessionId)",
            new { userId, exceptSessionId }, cancellationToken: ct));
    }
}

public sealed class DapperTwoFactorStore(NpgsqlDataSource db) : ISlimTwoFactorStore
{
    public async Task<string?> GetTotpSecretAsync(SlimUser user, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        return await c.QuerySingleOrDefaultAsync<string?>(new CommandDefinition(
            "SELECT totp_secret FROM users WHERE id = @id::uuid", new { id = user.Id }, cancellationToken: ct));
    }

    // the value arrives already encrypted by SlimIdentity (Data Protection) – store it as is
    public async Task SetTotpSecretAsync(SlimUser user, string protectedSecret, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        await c.ExecuteAsync(new CommandDefinition(
            "UPDATE users SET totp_secret = @secret WHERE id = @id::uuid",
            new { id = user.Id, secret = string.IsNullOrEmpty(protectedSecret) ? null : protectedSecret }, cancellationToken: ct));
    }

    // atomic compare-and-set: a 2FA code (time step) is accepted at most once
    public async Task<bool> TryMarkCodeUsedAsync(SlimUser user, long usedAt, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        return await c.ExecuteAsync(new CommandDefinition("""
            UPDATE users SET last_2fa_code_at = @usedAt
            WHERE id = @id::uuid AND (last_2fa_code_at IS NULL OR last_2fa_code_at < @usedAt)
            """, new { id = user.Id, usedAt }, cancellationToken: ct)) == 1;
    }

    // same compare-and-set on a separate column: a sign-in challenge completes at most one sign-in
    public async Task<bool> TryMarkChallengeUsedAsync(SlimUser user, long issuedAt, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        return await c.ExecuteAsync(new CommandDefinition("""
            UPDATE users SET last_2fa_challenge_at = @issuedAt
            WHERE id = @id::uuid AND (last_2fa_challenge_at IS NULL OR last_2fa_challenge_at < @issuedAt)
            """, new { id = user.Id, issuedAt }, cancellationToken: ct)) == 1;
    }

    public async Task StoreRecoveryCodesAsync(SlimUser user, IEnumerable<string> hashedCodes, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        await using var tx = await c.BeginTransactionAsync(ct);
        await c.ExecuteAsync(new CommandDefinition(
            "DELETE FROM recovery_codes WHERE user_id = @id::uuid", new { id = user.Id }, tx, cancellationToken: ct));
        await c.ExecuteAsync(new CommandDefinition(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES (@id::uuid, @hash)",
            hashedCodes.Select(h => new { id = user.Id, hash = h }), tx, cancellationToken: ct));
        await tx.CommitAsync(ct);
    }

    public async Task<bool> ValidateAndConsumeRecoveryCodeAsync(SlimUser user, string hashedCode, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        // atomic: only one parallel request can delete the row
        return await c.ExecuteAsync(new CommandDefinition(
            "DELETE FROM recovery_codes WHERE user_id = @id::uuid AND code_hash = @hashedCode",
            new { id = user.Id, hashedCode }, cancellationToken: ct)) == 1;
    }
}

public sealed class DapperExternalLoginStore(NpgsqlDataSource db, ISlimUserStore users) : ISlimExternalLoginStore
{
    public async Task<SlimUser?> FindByExternalLoginAsync(string provider, string providerKey, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        var userId = await c.QuerySingleOrDefaultAsync<string?>(new CommandDefinition(
            "SELECT user_id::text FROM external_logins WHERE provider = @provider AND provider_key = @providerKey",
            new { provider, providerKey }, cancellationToken: ct));
        return userId is null ? null : await users.FindByIdAsync(userId, ct);
    }

    public async Task LinkExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        await c.ExecuteAsync(new CommandDefinition(
            "INSERT INTO external_logins (provider, provider_key, user_id) VALUES (@provider, @providerKey, @userId::uuid)",
            new { provider, providerKey, userId }, cancellationToken: ct));
    }

    public async Task RemoveExternalLoginsAsync(string userId, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        await c.ExecuteAsync(new CommandDefinition(
            "DELETE FROM external_logins WHERE user_id = @userId::uuid", new { userId }, cancellationToken: ct));
    }

    public async Task<IReadOnlyList<SlimExternalLogin>> GetExternalLoginsAsync(string userId, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        var rows = await c.QueryAsync<(string Provider, string ProviderKey)>(new CommandDefinition(
            "SELECT provider, provider_key FROM external_logins WHERE user_id = @userId::uuid ORDER BY provider, provider_key",
            new { userId }, cancellationToken: ct));
        return rows.Select(r => new SlimExternalLogin(r.Provider, r.ProviderKey)).ToList();
    }

    public async Task<bool> RemoveExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        return await c.ExecuteAsync(new CommandDefinition(
            "DELETE FROM external_logins WHERE user_id = @userId::uuid AND provider = @provider AND provider_key = @providerKey",
            new { userId, provider, providerKey }, cancellationToken: ct)) > 0;
    }
}

public sealed class DapperApiKeyStore(NpgsqlDataSource db) : ISlimApiKeyStore
{
    public async Task<IReadOnlyCollection<Claim>?> ValidateApiKeyAsync(string keyHash, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        var key = await c.QuerySingleOrDefaultAsync<(string ClientId, string[] Scopes)?>(new CommandDefinition("""
            SELECT client_id, scopes FROM api_keys
            WHERE key_hash = @keyHash AND NOT revoked AND (expires_at IS NULL OR expires_at > now())
            """, new { keyHash }, cancellationToken: ct));
        if (key is not { } k) return null;

        var claims = new List<Claim> { new(SlimClaimTypes.UserId, $"client:{k.ClientId}") };
        claims.AddRange(k.Scopes.Select(s => new Claim("scope", s)));
        return claims;
    }
}

public sealed class DapperPasskeyStore(NpgsqlDataSource db) : ISlimPasskeyStore
{
    private const string Columns = """
        credential_id AS CredentialId, user_id::text AS UserId, public_key AS PublicKey, sign_count AS SignCount,
        last_challenge_at AS LastChallengeAt, name AS Name, created_utc AS CreatedUtc, last_used_utc AS LastUsedUtc,
        backup_eligible AS BackupEligible, backed_up AS BackedUp
        """;

    private sealed record Row(byte[] CredentialId, string UserId, byte[] PublicKey, long SignCount, long? LastChallengeAt,
        string Name, DateTime CreatedUtc, DateTime? LastUsedUtc, bool BackupEligible, bool BackedUp);

    private static byte[] Hash(byte[] credentialId) => System.Security.Cryptography.SHA256.HashData(credentialId);

    public async Task<IReadOnlyList<SlimPasskey>> GetPasskeysAsync(string userId, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        var rows = await c.QueryAsync<Row>(new CommandDefinition(
            $"SELECT {Columns} FROM passkeys WHERE user_id = @userId::uuid ORDER BY created_utc", new { userId }, cancellationToken: ct));
        return rows.Select(Map).ToList();
    }

    public async Task<SlimPasskey?> FindPasskeyAsync(byte[] credentialId, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        var row = await c.QuerySingleOrDefaultAsync<Row>(new CommandDefinition(
            $"SELECT {Columns} FROM passkeys WHERE credential_id_hash = @hash", new { hash = Hash(credentialId) }, cancellationToken: ct));
        return row is not null && row.CredentialId.AsSpan().SequenceEqual(credentialId) ? Map(row) : null;
    }

    public async Task<bool> AddPasskeyAsync(SlimPasskey p, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        return await c.ExecuteAsync(new CommandDefinition("""
            INSERT INTO passkeys (credential_id_hash, credential_id, user_id, public_key, sign_count, last_challenge_at, name, created_utc,
                                  last_used_utc, backup_eligible, backed_up)
            VALUES (@hash, @CredentialId, @UserId::uuid, @PublicKey, @SignCount, @LastChallengeAt, @Name, @CreatedUtc,
                    @LastUsedUtc, @BackupEligible, @BackedUp)
            ON CONFLICT (credential_id_hash) DO NOTHING
            """, new
            {
                hash = Hash(p.CredentialId), p.CredentialId, p.UserId, p.PublicKey, SignCount = (long)p.SignCount,
                p.LastChallengeAt, p.Name, p.CreatedUtc, p.LastUsedUtc, p.BackupEligible, p.BackedUp,
            }, cancellationToken: ct)) == 1;
    }

    public async Task<bool> TryRecordUseAsync(byte[] credentialId, uint expectedSignCount, uint signCount, long challengeIssuedAt, DateTimeOffset usedUtc, bool backedUp, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        return await c.ExecuteAsync(new CommandDefinition("""
            UPDATE passkeys SET sign_count = @signCount, last_challenge_at = @challengeIssuedAt, last_used_utc = @usedUtc, backed_up = @backedUp
            WHERE credential_id_hash = @hash AND sign_count = @expected
              AND (last_challenge_at IS NULL OR last_challenge_at < @challengeIssuedAt)
            """, new { hash = Hash(credentialId), expected = (long)expectedSignCount, signCount = (long)signCount, challengeIssuedAt, usedUtc, backedUp },
            cancellationToken: ct)) == 1;
    }

    public async Task<bool> RenamePasskeyAsync(string userId, byte[] credentialId, string name, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        return await c.ExecuteAsync(new CommandDefinition(
            "UPDATE passkeys SET name = @name WHERE credential_id_hash = @hash AND user_id = @userId::uuid",
            new { name, hash = Hash(credentialId), userId }, cancellationToken: ct)) == 1;
    }

    public async Task<bool> RemovePasskeyAsync(string userId, byte[] credentialId, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        return await c.ExecuteAsync(new CommandDefinition(
            "DELETE FROM passkeys WHERE credential_id_hash = @hash AND user_id = @userId::uuid",
            new { hash = Hash(credentialId), userId }, cancellationToken: ct)) == 1;
    }

    public async Task RemovePasskeysAsync(string userId, CancellationToken ct)
    {
        if (!Guid.TryParse(userId, out _)) return;
        await using var c = await db.OpenConnectionAsync(ct);
        await c.ExecuteAsync(new CommandDefinition(
            "DELETE FROM passkeys WHERE user_id = @userId::uuid", new { userId }, cancellationToken: ct));
    }

    private static SlimPasskey Map(Row r) => new()
    {
        UserId = r.UserId, CredentialId = r.CredentialId, PublicKey = r.PublicKey, SignCount = (uint)r.SignCount,
        LastChallengeAt = r.LastChallengeAt, Name = r.Name, BackupEligible = r.BackupEligible, BackedUp = r.BackedUp,
        CreatedUtc = new DateTimeOffset(DateTime.SpecifyKind(r.CreatedUtc, DateTimeKind.Utc)),
        LastUsedUtc = r.LastUsedUtc is { } used ? new DateTimeOffset(DateTime.SpecifyKind(used, DateTimeKind.Utc)) : null,
    };
}
