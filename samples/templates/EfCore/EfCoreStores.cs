// SlimIdentity sample – EF Core implementations of all store interfaces.
//
// Registration:
//   builder.Services.AddDbContext<AppDbContext>(o => o.UseNpgsql(cs));
//   builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))
//       .AddUserStore<EfCoreUserStore>()
//       .AddRefreshTokenStore<EfCoreRefreshTokenStore>()
//       .AddTwoFactorStore<EfCoreTwoFactorStore>()
//       .AddExternalLoginStore<EfCoreExternalLoginStore>()
//       .AddApiKeyStore<EfCoreApiKeyStore>()
//       .AddSessionStore<EfCoreSessionStore>()
//       .AddEmailSender<MailKitEmailSender>();

using System.Security.Claims;
using SlimIdentity;
using Microsoft.EntityFrameworkCore;

namespace MyApp.Data;

public sealed class EfCoreUserStore(AppDbContext db) : ISlimUserStore
{
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

    public async Task<SlimUser?> CreateAsync(string email, string passwordHash, CancellationToken ct)
    {
        var user = new AppUser
        {
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            PasswordHash = passwordHash,
            SecurityStamp = SlimUser.NewSecurityStamp(),
        };
        db.Users.Add(user);
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // unique index on NormalizedEmail: a concurrent registration took the address
            db.Entry(user).State = EntityState.Detached;
            return null;
        }
        return Map(user);
    }

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
            .SetProperty(u => u.TwoFactorEnabled, user.TwoFactorEnabled), ct);
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
        catch (DbUpdateException)
        {
            return false;
        }
    }

    public async Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct)
    {
        var id = Guid.Parse(user.Id);
        var data = await db.Users.AsNoTracking()
            .Where(u => u.Id == id)
            .Select(u => new { u.TenantId, u.DisplayName, Roles = u.Roles.Select(r => r.Role).ToList() })
            .FirstAsync(ct);

        var claims = new List<Claim> { new("tenant_id", data.TenantId.ToString()) };
        if (data.DisplayName is not null) claims.Add(new Claim("name", data.DisplayName));
        claims.AddRange(data.Roles.Select(r => new Claim(ClaimTypes.Role, r)));
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
    };
}

public sealed class EfCoreRefreshTokenStore(AppDbContext db, TimeProvider time) : ISlimRefreshTokenStore
{
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

public sealed class EfCoreTwoFactorStore(AppDbContext db) : ISlimTwoFactorStore
{
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

public sealed class EfCoreExternalLoginStore(AppDbContext db, ISlimUserStore users) : ISlimExternalLoginStore
{
    public async Task<SlimUser?> FindByExternalLoginAsync(string provider, string providerKey, CancellationToken ct)
    {
        var link = await db.ExternalLogins.AsNoTracking()
            .FirstOrDefaultAsync(l => l.Provider == provider && l.ProviderKey == providerKey, ct);
        return link is null ? null : await users.FindByIdAsync(link.UserId.ToString(), ct);
    }

    public async Task LinkExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct)
    {
        db.ExternalLogins.Add(new ExternalLogin { Provider = provider, ProviderKey = providerKey, UserId = Guid.Parse(userId) });
        await db.SaveChangesAsync(ct);
    }
}

/// <summary>Server-side sessions (per-device logout, "your devices" list). Clean up expired rows periodically.</summary>
public sealed class EfCoreSessionStore(AppDbContext db) : ISlimSessionStore
{
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
        await db.Sessions.AsNoTracking().Where(s => s.Id == sessionId).Select(ToSlim).FirstOrDefaultAsync(ct);

    public async Task<IReadOnlyCollection<SlimSession>> ListAsync(string userId, CancellationToken ct)
    {
        var id = Guid.Parse(userId);
        return await db.Sessions.AsNoTracking().Where(s => s.UserId == id).Select(ToSlim).ToListAsync(ct);
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

    private static readonly System.Linq.Expressions.Expression<Func<UserSession, SlimSession>> ToSlim = s => new SlimSession
    {
        Id = s.Id, UserId = s.UserId.ToString(), Mode = s.Mode, AuthenticationMethod = s.AuthenticationMethod,
        ImpersonatorId = s.ImpersonatorId, CreatedUtc = s.CreatedUtc, LastSeenUtc = s.LastSeenUtc,
        ExpiresUtc = s.ExpiresUtc, UserAgent = s.UserAgent, IpAddress = s.IpAddress,
    };
}

public sealed class EfCoreApiKeyStore(AppDbContext db, TimeProvider time) : ISlimApiKeyStore
{
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
