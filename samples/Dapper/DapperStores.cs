// SlimIdentity sample – Dapper (plain SQL, PostgreSQL via Npgsql). Schema: schema.sql
// Packages: Dapper, Npgsql
//
//   builder.Services.AddSingleton(NpgsqlDataSource.Create(connectionString));
//   builder.Services.AddSlimIdentity(...)
//       .AddUserStore<DapperUserStore>()
//       .AddRefreshTokenStore<DapperRefreshTokenStore>();

using System.Security.Claims;
using SlimIdentity;
using SlimIdentity.Abstractions;
using Dapper;
using Npgsql;

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
        two_factor_enabled     AS TwoFactorEnabled
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

    public async Task<SlimUser> CreateAsync(string email, string passwordHash, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        return await c.QuerySingleAsync<SlimUser>(new CommandDefinition($"""
            INSERT INTO users (email, normalized_email, password_hash, security_stamp)
            VALUES (@email, @normalized, @hash, @stamp)
            RETURNING {Columns}
            """,
            new { email, normalized = email.ToUpperInvariant(), hash = passwordHash, stamp = SlimUser.NewSecurityStamp() },
            cancellationToken: ct));
    }

    public async Task UpdateSecurityStateAsync(SlimUser user, CancellationToken ct)
    {
        await using var c = await db.OpenConnectionAsync(ct);
        await c.ExecuteAsync(new CommandDefinition("""
            UPDATE users SET
                password_hash = @PasswordHash,
                security_stamp = @SecurityStamp,
                email_confirmed = @EmailConfirmed,
                failed_login_attempts = @FailedLoginAttempts,
                lockout_end_utc = @LockoutEndUtc,
                two_factor_enabled = @TwoFactorEnabled
            WHERE id = @Id::uuid
            """, user, cancellationToken: ct));
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
