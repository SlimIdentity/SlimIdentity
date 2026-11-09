// SlimIdentity sample – EF Core implementations of all store interfaces.
//
// Registration:
//   builder.Services.AddDbContextFactory<AppDbContext>(o => o.UseNpgsql(cs));   // also registers the scoped AppDbContext
//   builder.Services.AddScoped<IdentityDb>();
//   builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))
//       .AddUserStore<EfCoreUserStore>()
//       .AddRefreshTokenStore<EfCoreRefreshTokenStore>()
//       .AddTwoFactorStore<EfCoreTwoFactorStore>()
//       .AddExternalLoginStore<EfCoreExternalLoginStore>()
//       .AddApiKeyStore<EfCoreApiKeyStore>()
//       .AddSessionStore<EfCoreSessionStore>()
//       .AddPasskeyStore<EfCorePasskeyStore>()           // package SlimIdentity.Passkeys; relying party: Links.BaseUrl or AddPasskeys(o => …)
//       .AddEmailSender<MailKitEmailSender>();

using System.Data.Common;
using System.Security.Claims;
using SlimIdentity;
using Microsoft.EntityFrameworkCore;

namespace MyApp.Data;

public sealed class EfCoreUserStore(IdentityDb identity) : ISlimUserStore
{
    private readonly AppDbContext db = identity.Db;

    public async Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct)
    {
        var normalized = email.Trim().ToUpperInvariant();
        var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.NormalizedEmail == normalized, ct);
        return user is null ? null : Map(user);
    }

    public async Task<SlimUser?> FindByIdAsync(string userId, CancellationToken ct)
    {
        if (!Guid.TryParse(userId, out var id)) return null;
        var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id, ct);
        return user is null ? null : Map(user);
    }

    public async Task<SlimUser?> CreateAsync(SlimNewUser newUser, CancellationToken ct)
    {
        var user = new AppUser
        {
            Email = newUser.Email,
            NormalizedEmail = newUser.Email.ToUpperInvariant(),
            PasswordHash = newUser.PasswordHash,
            SecurityStamp = SlimUser.NewSecurityStamp(),
        };
        // registration profile (ISlimRegistrationProfile / ISlimAuthManager.RegisterAsync): copy it into the entity or
        // attach related entities here – the SaveChanges below writes them together with the account
        // if (newUser.Profile is SignUpProfile p) user.DisplayName = p.Name;
        db.Users.Add(user);
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // unique index on NormalizedEmail: a concurrent registration took the address – any other error is rethrown
            db.Entry(user).State = EntityState.Detached;
            if (await IsEmailTakenAsync(user.NormalizedEmail, null, ct)) return null;
            throw;
        }
        return Map(user);
    }

    private Task<bool> IsEmailTakenAsync(string normalizedEmail, Guid? exceptUserId, CancellationToken ct) =>
        db.Users.AsNoTracking().AnyAsync(u => u.NormalizedEmail == normalizedEmail && u.Id != exceptUserId, ct);

    // ---- sign-in bookkeeping: narrow, atomic updates (never write back a whole, possibly outdated user)

    public async Task<int> IncrementFailedLoginAttemptsAsync(SlimUser user, CancellationToken ct)
    {
        var id = Guid.Parse(user.Id);
        // portable compare-and-set loop (with raw SQL: UPDATE … SET failed = failed + 1 … RETURNING failed)
        while (true)
        {
            var current = await db.Users.AsNoTracking().Where(u => u.Id == id).Select(u => u.FailedLoginAttempts).FirstAsync(ct);
            var updated = await db.Users.Where(u => u.Id == id && u.FailedLoginAttempts == current)
                .ExecuteUpdateAsync(s => s.SetProperty(u => u.FailedLoginAttempts, current + 1), ct);
            if (updated == 1) return current + 1;
        }
    }

    public Task SetLockoutEndAsync(SlimUser user, DateTimeOffset? lockoutEndUtc, CancellationToken ct)
    {
        var id = Guid.Parse(user.Id);
        return db.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s.SetProperty(u => u.LockoutEndUtc, lockoutEndUtc), ct);
    }

    public Task ResetFailedLoginAttemptsAsync(SlimUser user, CancellationToken ct)
    {
        var id = Guid.Parse(user.Id);
        return db.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(u => u.FailedLoginAttempts, 0)
            .SetProperty(u => u.LockoutEndUtc, (DateTimeOffset?)null), ct);
    }

    // conditional: a password change in the meantime wins over the transparent rehash
    public Task UpdatePasswordHashAsync(SlimUser user, string currentHash, string newHash, CancellationToken ct)
    {
        var id = Guid.Parse(user.Id);
        return db.Users.Where(u => u.Id == id && u.PasswordHash == currentHash)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.PasswordHash, newHash), ct);
    }

    public async Task UpdateSecurityStateAsync(SlimUser user, CancellationToken ct)
    {
        var id = Guid.Parse(user.Id);
        // Only security columns are touched – business data stays untouched.
        await db.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s
            .SetProperty(u => u.PasswordHash, user.PasswordHash)
            .SetProperty(u => u.SecurityStamp, user.SecurityStamp)
            .SetProperty(u => u.EmailConfirmed, user.EmailConfirmed)
            .SetProperty(u => u.FailedLoginAttempts, user.FailedLoginAttempts)
            .SetProperty(u => u.LockoutEndUtc, user.LockoutEndUtc)
            .SetProperty(u => u.TwoFactorEnabled, user.TwoFactorEnabled)
            .SetProperty(u => u.PasswordChangeRequired, user.PasswordChangeRequired), ct);
    }

    public async Task<bool> UpdateEmailAsync(SlimUser user, string newEmail, CancellationToken ct)
    {
        var id = Guid.Parse(user.Id);
        var normalized = newEmail.ToUpperInvariant();
        try
        {
            // the unique index on NormalizedEmail decides – no check-then-act race
            return await db.Users.Where(u => u.Id == id).ExecuteUpdateAsync(s => s
                .SetProperty(u => u.Email, newEmail)
                .SetProperty(u => u.NormalizedEmail, normalized), ct) == 1;
        }
        catch (DbException)
        {
            // ExecuteUpdate bypasses SaveChanges: the provider's own exception arrives (PostgresException, SqlException, …),
            // not DbUpdateException. Report "taken" only if the unique index really is the reason.
            if (await IsEmailTakenAsync(normalized, id, ct)) return false;
            throw;
        }
    }

    public async Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct)
    {
        var id = Guid.Parse(user.Id);
        var data = await db.Users.AsNoTracking()
            .Where(u => u.Id == id)
            .Select(u => new { u.TenantId, u.DisplayName, Roles = u.Roles.Select(r => r.Role).ToList() })
            .FirstAsync(ct);

        // groups resolved to permissions – one claim per permission code (keep them short: they travel with every request)
        var permissions = await db.GroupMembers.AsNoTracking()
            .Where(m => m.UserId == id)
            .Join(db.GroupPermissions, m => m.GroupId, p => p.GroupId, (_, p) => p.Permission)
            .Distinct()
            .ToListAsync(ct);

        var claims = new List<Claim> { new("tenant_id", data.TenantId.ToString()) };
        if (data.DisplayName is not null) claims.Add(new Claim("name", data.DisplayName));
        claims.AddRange(data.Roles.Select(r => new Claim(ClaimTypes.Role, r)));
        claims.AddRange(permissions.Select(p => new Claim("permission", p)));
        return claims;
    }

    private static SlimUser Map(AppUser u) => new()
    {
        Id = u.Id.ToString(),
        Email = u.Email,
        PasswordHash = u.PasswordHash,
        SecurityStamp = u.SecurityStamp,
        IsActive = u.IsActive,
        EmailConfirmed = u.EmailConfirmed,
        FailedLoginAttempts = u.FailedLoginAttempts,
        LockoutEndUtc = u.LockoutEndUtc,
        TwoFactorEnabled = u.TwoFactorEnabled,
        PasswordChangeRequired = u.PasswordChangeRequired,
    };
}

public sealed class EfCoreRefreshTokenStore(IdentityDb identity, TimeProvider time) : ISlimRefreshTokenStore
{
    private readonly AppDbContext db = identity.Db;

    public async Task StoreRefreshTokenAsync(string userId, string tokenHash, DateTimeOffset expiresAt, CancellationToken ct)
    {
        db.RefreshTokens.Add(new RefreshToken { TokenHash = tokenHash, UserId = Guid.Parse(userId), ExpiresAt = expiresAt });
        await db.SaveChangesAsync(ct);
    }

    public async Task<string?> ValidateAndConsumeRefreshTokenAsync(string tokenHash, CancellationToken ct)
    {
        var token = await db.RefreshTokens.AsNoTracking().FirstOrDefaultAsync(t => t.TokenHash == tokenHash, ct);
        if (token is null) return null;

        // atomic consume: only the request that actually deletes the row wins (protects against parallel replays)
        var deleted = await db.RefreshTokens.Where(t => t.TokenHash == tokenHash).ExecuteDeleteAsync(ct);
        return deleted == 1 && token.ExpiresAt > time.GetUtcNow() ? token.UserId.ToString() : null;
    }
}

public sealed class EfCoreTwoFactorStore(IdentityDb identity) : ISlimTwoFactorStore
{
    private readonly AppDbContext db = identity.Db;

    public async Task<string?> GetTotpSecretAsync(SlimUser user, CancellationToken ct)
    {
        var id = Guid.Parse(user.Id);
        return await db.Users.Where(u => u.Id == id).Select(u => u.TotpSecret).FirstOrDefaultAsync(ct);
    }

    // the value arrives already encrypted by SlimIdentity (Data Protection) – store it as is
    public async Task SetTotpSecretAsync(SlimUser user, string protectedSecret, CancellationToken ct)
    {
        var id = Guid.Parse(user.Id);
        await db.Users.Where(u => u.Id == id)
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.TotpSecret, string.IsNullOrEmpty(protectedSecret) ? null : protectedSecret), ct);
    }

    // atomic compare-and-set: a 2FA code (time step) is accepted at most once
    public async Task<bool> TryMarkCodeUsedAsync(SlimUser user, long usedAt, CancellationToken ct)
    {
        var id = Guid.Parse(user.Id);
        return await db.Users
            .Where(u => u.Id == id && (u.LastTwoFactorCodeAt == null || u.LastTwoFactorCodeAt < usedAt))
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.LastTwoFactorCodeAt, usedAt), ct) == 1;
    }

    // same compare-and-set on a separate column: a sign-in challenge completes at most one sign-in
    public async Task<bool> TryMarkChallengeUsedAsync(SlimUser user, long issuedAt, CancellationToken ct)
    {
        var id = Guid.Parse(user.Id);
        return await db.Users
            .Where(u => u.Id == id && (u.LastTwoFactorChallengeAt == null || u.LastTwoFactorChallengeAt < issuedAt))
            .ExecuteUpdateAsync(s => s.SetProperty(u => u.LastTwoFactorChallengeAt, issuedAt), ct) == 1;
    }

    public async Task StoreRecoveryCodesAsync(SlimUser user, IEnumerable<string> hashedCodes, CancellationToken ct)
    {
        var id = Guid.Parse(user.Id);
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await db.RecoveryCodes.Where(c => c.UserId == id).ExecuteDeleteAsync(ct);
        db.RecoveryCodes.AddRange(hashedCodes.Select(h => new RecoveryCode { UserId = id, CodeHash = h }));
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
    }

    public async Task<bool> ValidateAndConsumeRecoveryCodeAsync(SlimUser user, string hashedCode, CancellationToken ct)
    {
        var id = Guid.Parse(user.Id);
        return await db.RecoveryCodes.Where(c => c.UserId == id && c.CodeHash == hashedCode).ExecuteDeleteAsync(ct) == 1;
    }
}

public sealed class EfCoreExternalLoginStore(IdentityDb identity, ISlimUserStore users) : ISlimExternalLoginStore
{
    private readonly AppDbContext db = identity.Db;

    public async Task<SlimUser?> FindByExternalLoginAsync(string provider, string providerKey, CancellationToken ct)
    {
        var links = await db.ExternalLogins.AsNoTracking()
            .Where(l => l.Provider == provider && l.ProviderKey == providerKey).ToListAsync(ct);
        // exact comparison in memory: a case-insensitive collation (SQL Server's default) must not match "Alice" for "alice"
        var link = links.FirstOrDefault(l => l.Provider == provider && l.ProviderKey == providerKey);
        return link is null ? null : await users.FindByIdAsync(link.UserId.ToString(), ct);
    }

    public async Task LinkExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct)
    {
        db.ExternalLogins.Add(new ExternalLogin { Provider = provider, ProviderKey = providerKey, UserId = Guid.Parse(userId) });
        await db.SaveChangesAsync(ct);
    }

    public Task RemoveExternalLoginsAsync(string userId, CancellationToken ct)
    {
        var id = Guid.Parse(userId);
        return db.ExternalLogins.Where(l => l.UserId == id).ExecuteDeleteAsync(ct);
    }

    public async Task<IReadOnlyList<SlimExternalLogin>> GetExternalLoginsAsync(string userId, CancellationToken ct)
    {
        var id = Guid.Parse(userId);
        return await db.ExternalLogins.AsNoTracking().Where(l => l.UserId == id)
            .OrderBy(l => l.Provider).ThenBy(l => l.ProviderKey)
            .Select(l => new SlimExternalLogin(l.Provider, l.ProviderKey)).ToListAsync(ct);
    }

    public async Task<bool> RemoveExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct)
    {
        var id = Guid.Parse(userId);
        // exact (case-sensitive) key: compare in memory, the database collation may ignore case
        var keys = await db.ExternalLogins.AsNoTracking().Where(l => l.UserId == id && l.Provider == provider).Select(l => l.ProviderKey).ToListAsync(ct);
        if (!keys.Contains(providerKey, StringComparer.Ordinal)) return false;
        return await db.ExternalLogins.Where(l => l.UserId == id && l.Provider == provider && l.ProviderKey == providerKey).ExecuteDeleteAsync(ct) > 0;
    }
}

/// <summary>Server-side sessions (per-device logout, "your devices" list). Clean up expired rows periodically.</summary>
public sealed class EfCoreSessionStore(IdentityDb identity) : ISlimSessionStore
{
    private readonly AppDbContext db = identity.Db;

    public async Task CreateAsync(SlimSession session, CancellationToken ct)
    {
        db.Sessions.Add(new UserSession
        {
            Id = session.Id, UserId = Guid.Parse(session.UserId), Mode = session.Mode,
            AuthenticationMethod = session.AuthenticationMethod, ImpersonatorId = session.ImpersonatorId,
            CreatedUtc = session.CreatedUtc, LastSeenUtc = session.LastSeenUtc, ExpiresUtc = session.ExpiresUtc,
            UserAgent = session.UserAgent,
            IpAddress = session.IpAddress, // personal data – drop it here if you do not need it
        });
        await db.SaveChangesAsync(ct);
    }

    public async Task<SlimSession?> FindAsync(string sessionId, CancellationToken ct) =>
        await db.Sessions.AsNoTracking().FirstOrDefaultAsync(s => s.Id == sessionId, ct) is { } s ? ToSlim(s) : null;

    public async Task<IReadOnlyCollection<SlimSession>> ListAsync(string userId, CancellationToken ct)
    {
        var id = Guid.Parse(userId);
        return (await db.Sessions.AsNoTracking().Where(s => s.UserId == id).ToListAsync(ct)).Select(ToSlim).ToList();
    }

    public Task TouchAsync(string sessionId, DateTimeOffset lastSeenUtc, DateTimeOffset expiresUtc, CancellationToken ct) =>
        db.Sessions.Where(s => s.Id == sessionId).ExecuteUpdateAsync(s => s
            .SetProperty(x => x.LastSeenUtc, lastSeenUtc)
            .SetProperty(x => x.ExpiresUtc, expiresUtc), ct);

    public Task RevokeAsync(string sessionId, CancellationToken ct) =>
        db.Sessions.Where(s => s.Id == sessionId).ExecuteDeleteAsync(ct);

    public Task RevokeAllAsync(string userId, string? exceptSessionId, CancellationToken ct)
    {
        var id = Guid.Parse(userId);
        return db.Sessions.Where(s => s.UserId == id && s.Id != exceptSessionId).ExecuteDeleteAsync(ct);
    }

    // mapped in memory: Guid.ToString() inside a query is translated by the database – SQL Server and SQLite return
    // upper case, which would no longer match the user id SlimIdentity compares with
    private static SlimSession ToSlim(UserSession s) => new()
    {
        Id = s.Id, UserId = s.UserId.ToString(), Mode = s.Mode, AuthenticationMethod = s.AuthenticationMethod,
        ImpersonatorId = s.ImpersonatorId, CreatedUtc = s.CreatedUtc, LastSeenUtc = s.LastSeenUtc,
        ExpiresUtc = s.ExpiresUtc, UserAgent = s.UserAgent, IpAddress = s.IpAddress,
    };
}

public sealed class EfCoreApiKeyStore(IdentityDb identity, TimeProvider time) : ISlimApiKeyStore
{
    private readonly AppDbContext db = identity.Db;

    public async Task<IReadOnlyCollection<Claim>?> ValidateApiKeyAsync(string keyHash, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        var key = await db.ApiKeys.AsNoTracking()
            .FirstOrDefaultAsync(k => k.KeyHash == keyHash && !k.Revoked && (k.ExpiresAt == null || k.ExpiresAt > now), ct);
        if (key is null) return null;

        var claims = new List<Claim> { new(SlimClaimTypes.UserId, $"client:{key.ClientId}") };
        claims.AddRange(key.Scopes.Select(s => new Claim("scope", s)));
        return claims;
    }
}

/// <summary>
/// The stores' own AppDbContext per request – never the scoped one your endpoints use: a store's SaveChanges would
/// otherwise save your pending changes along with its own.
/// </summary>
public sealed class IdentityDb(IDbContextFactory<AppDbContext> factory) : IDisposable
{
    private AppDbContext? _db;
    public AppDbContext Db => _db ??= factory.CreateDbContext();
    public void Dispose() => _db?.Dispose();
}

/// <summary>Passkeys (WebAuthn). Credential ids are keyed by their SHA-256 – they may exceed index size limits.</summary>
public sealed class EfCorePasskeyStore(IdentityDb identity) : ISlimPasskeyStore
{
    private readonly AppDbContext db = identity.Db;

    private static byte[] Hash(byte[] credentialId) => System.Security.Cryptography.SHA256.HashData(credentialId);

    public async Task<IReadOnlyList<SlimPasskey>> GetPasskeysAsync(string userId, CancellationToken ct)
    {
        var id = Guid.Parse(userId);
        var rows = await db.Passkeys.AsNoTracking().Where(p => p.UserId == id).ToListAsync(ct);
        return rows.OrderBy(p => p.CreatedUtc).Select(Map).ToList();   // in memory: SQLite cannot order by DateTimeOffset
    }

    public async Task<SlimPasskey?> FindPasskeyAsync(byte[] credentialId, CancellationToken ct)
    {
        var hash = Hash(credentialId);
        var row = await db.Passkeys.AsNoTracking().FirstOrDefaultAsync(p => p.CredentialIdHash == hash, ct);
        return row is not null && row.CredentialId.AsSpan().SequenceEqual(credentialId) ? Map(row) : null;
    }

    public async Task<bool> AddPasskeyAsync(SlimPasskey passkey, CancellationToken ct)
    {
        var hash = Hash(passkey.CredentialId);
        if (await db.Passkeys.AnyAsync(p => p.CredentialIdHash == hash, ct)) return false;
        var row = new UserPasskey
        {
            CredentialIdHash = hash, CredentialId = passkey.CredentialId, UserId = Guid.Parse(passkey.UserId), PublicKey = passkey.PublicKey,
            SignCount = passkey.SignCount, LastChallengeAt = passkey.LastChallengeAt, Name = passkey.Name,
            CreatedUtc = passkey.CreatedUtc, LastUsedUtc = passkey.LastUsedUtc,
        };
        db.Passkeys.Add(row);
        try
        {
            await db.SaveChangesAsync(ct);
            return true;
        }
        catch (DbUpdateException)
        {
            db.Entry(row).State = EntityState.Detached;   // registered concurrently (primary key)
            if (await db.Passkeys.AnyAsync(p => p.CredentialIdHash == hash, ct)) return false;
            throw;
        }
    }

    // compare-and-set in one statement: same counter AND a newer challenge than the last one used
    public async Task<bool> TryRecordUseAsync(byte[] credentialId, uint expectedSignCount, uint signCount, long challengeIssuedAt, DateTimeOffset usedUtc, CancellationToken ct)
    {
        var hash = Hash(credentialId);
        long expected = expectedSignCount, next = signCount;
        return await db.Passkeys
            .Where(p => p.CredentialIdHash == hash && p.SignCount == expected && (p.LastChallengeAt == null || p.LastChallengeAt < challengeIssuedAt))
            .ExecuteUpdateAsync(s => s
                .SetProperty(p => p.SignCount, next)
                .SetProperty(p => p.LastChallengeAt, challengeIssuedAt)
                .SetProperty(p => p.LastUsedUtc, usedUtc), ct) == 1;
    }

    public async Task<bool> RenamePasskeyAsync(string userId, byte[] credentialId, string name, CancellationToken ct)
    {
        var (id, hash) = (Guid.Parse(userId), Hash(credentialId));
        return await db.Passkeys.Where(p => p.UserId == id && p.CredentialIdHash == hash).ExecuteUpdateAsync(s => s.SetProperty(p => p.Name, name), ct) == 1;
    }

    public async Task<bool> RemovePasskeyAsync(string userId, byte[] credentialId, CancellationToken ct)
    {
        var (id, hash) = (Guid.Parse(userId), Hash(credentialId));
        return await db.Passkeys.Where(p => p.UserId == id && p.CredentialIdHash == hash).ExecuteDeleteAsync(ct) == 1;
    }

    public async Task RemovePasskeysAsync(string userId, CancellationToken ct)
    {
        if (!Guid.TryParse(userId, out var id)) return;
        await db.Passkeys.Where(p => p.UserId == id).ExecuteDeleteAsync(ct);
    }

    private static SlimPasskey Map(UserPasskey p) => new()
    {
        UserId = p.UserId.ToString(), CredentialId = p.CredentialId, PublicKey = p.PublicKey, SignCount = (uint)p.SignCount,
        LastChallengeAt = p.LastChallengeAt, Name = p.Name, CreatedUtc = p.CreatedUtc, LastUsedUtc = p.LastUsedUtc,
    };
}
