using System.Data.Common;
using System.Linq.Expressions;

namespace SlimIdentity.EntityFrameworkCore;

/// <summary>Optional: creates new user entities (register, external login, invitation) – e.g. to set a tenant or defaults.</summary>
public interface ISlimUserFactory<out TUser>
{
    /// <summary>A new, not yet tracked user entity; SlimIdentity sets the address, hash and security fields afterwards.</summary>
    TUser Create();
}

/// <summary>Optional: the host claims (roles, tenant, …) of a user, added to every cookie and token.</summary>
public interface ISlimUserClaimsProvider<in TUser>
{
    /// <summary>Claims for <paramref name="user"/> (the tracked-free entity as stored).</summary>
    Task<IReadOnlyCollection<Claim>> GetClaimsAsync(TUser user, CancellationToken ct);
}

/// <summary>Shared helpers of the stores.</summary>
internal static class SlimEf
{
    public static string KeyToString<TKey>(TKey key) => key switch
    {
        Guid g => g.ToString("D"),                       // lower case, independent of the database's text conversion
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => key?.ToString() ?? string.Empty,
    };

    public static bool TryParseKey<TKey>(string? value, out TKey key) where TKey : IParsable<TKey> =>
        TKey.TryParse(value, CultureInfo.InvariantCulture, out key!);

    /// <summary><c>x =&gt; x.{property} == value</c> as a parameterized expression (works for every key type).</summary>
    public static Expression<Func<T, bool>> Equal<T, TValue>(string property, TValue value)
    {
        var x = Expression.Parameter(typeof(T), "x");
        var holder = Expression.Property(Expression.Constant(new Holder<TValue>(value)), nameof(Holder<TValue>.Value));
        return Expression.Lambda<Func<T, bool>>(Expression.Equal(Expression.Property(x, property), holder), x);
    }

    private sealed record Holder<TValue>(TValue Value);
}

/// <summary><see cref="ISlimUserStore"/> on your user entity.</summary>
public class SlimEfUserStore<TContext, TUser, TKey>(SlimEfContext<TContext> context, IServiceProvider services) : ISlimUserStore
    where TContext : DbContext
    where TUser : class, ISlimUserEntity<TKey>, new()
    where TKey : IEquatable<TKey>, IParsable<TKey>
{
    private readonly TContext db = context.Db;

    private const string Failed = nameof(ISlimUserEntity<TKey>.FailedLoginAttempts);

    /// <summary>The users of the context.</summary>
    protected DbSet<TUser> Users => db.Set<TUser>();

    /// <inheritdoc />
    public async Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(email);
        var normalized = Normalize(email);
        var user = await Users.AsNoTracking().FirstOrDefaultAsync(
            SlimEf.Equal<TUser, string>(nameof(ISlimUserEntity<TKey>.NormalizedEmail), normalized), ct).ConfigureAwait(false);
        return user is null ? null : Map(user);
    }

    /// <inheritdoc />
    public async Task<SlimUser?> FindByIdAsync(string userId, CancellationToken ct) =>
        await FindEntityAsync(userId, ct).ConfigureAwait(false) is { } user ? Map(user) : null;

    /// <summary>The stored entity (not tracked), or null.</summary>
    protected async Task<TUser?> FindEntityAsync(string userId, CancellationToken ct) =>
        SlimEf.TryParseKey<TKey>(userId, out var key)
            ? await Users.AsNoTracking().FirstOrDefaultAsync(ById(key), ct).ConfigureAwait(false)
            : null;

    /// <inheritdoc />
    public async Task<SlimUser?> CreateAsync(string email, string passwordHash, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(email);
        var user = services.GetService<ISlimUserFactory<TUser>>()?.Create() ?? new TUser();
        user.Email = email;
        user.NormalizedEmail = Normalize(email);
        user.PasswordHash = passwordHash ?? string.Empty;
        user.SecurityStamp = SlimUser.NewSecurityStamp();
        user.IsActive = true;
        Users.Add(user);
        try
        {
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }
        catch (DbUpdateException)
        {
            // unique index on NormalizedEmail: a concurrent registration took the address – anything else is rethrown
            db.Entry(user).State = EntityState.Detached;
            if (await IsEmailTakenAsync(user.NormalizedEmail, default, ct).ConfigureAwait(false)) return null;
            throw;
        }
        db.Entry(user).State = EntityState.Detached;
        return Map(user);
    }

    /// <inheritdoc />
    public Task UpdateSecurityStateAsync(SlimUser user, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(user);
        return Update(user).ExecuteUpdateAsync(s => s
            .SetProperty(u => EF.Property<string>(u, nameof(ISlimUserEntity<TKey>.PasswordHash)), user.PasswordHash)
            .SetProperty(u => EF.Property<string>(u, nameof(ISlimUserEntity<TKey>.SecurityStamp)), user.SecurityStamp)
            .SetProperty(u => EF.Property<bool>(u, nameof(ISlimUserEntity<TKey>.EmailConfirmed)), user.EmailConfirmed)
            .SetProperty(u => EF.Property<int>(u, Failed), user.FailedLoginAttempts)
            .SetProperty(u => EF.Property<DateTimeOffset?>(u, nameof(ISlimUserEntity<TKey>.LockoutEndUtc)), user.LockoutEndUtc)
            .SetProperty(u => EF.Property<bool>(u, nameof(ISlimUserEntity<TKey>.TwoFactorEnabled)), user.TwoFactorEnabled)
            .SetProperty(u => EF.Property<bool>(u, nameof(ISlimUserEntity<TKey>.PasswordChangeRequired)), user.PasswordChangeRequired), ct);
    }

    /// <inheritdoc />
    public async Task<int> IncrementFailedLoginAttemptsAsync(SlimUser user, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(user);
        // portable compare-and-set loop: no lost update, on every provider
        while (true)
        {
            var current = await Update(user).Select(u => EF.Property<int>(u, Failed)).FirstAsync(ct).ConfigureAwait(false);
            var updated = await Update(user).Where(u => EF.Property<int>(u, Failed) == current)
                .ExecuteUpdateAsync(s => s.SetProperty(u => EF.Property<int>(u, Failed), current + 1), ct).ConfigureAwait(false);
            if (updated == 1) return current + 1;
        }
    }

    /// <inheritdoc />
    public Task SetLockoutEndAsync(SlimUser user, DateTimeOffset? lockoutEndUtc, CancellationToken ct) =>
        Update(user).ExecuteUpdateAsync(s => s
            .SetProperty(u => EF.Property<DateTimeOffset?>(u, nameof(ISlimUserEntity<TKey>.LockoutEndUtc)), lockoutEndUtc), ct);

    /// <inheritdoc />
    public Task ResetFailedLoginAttemptsAsync(SlimUser user, CancellationToken ct) =>
        Update(user).ExecuteUpdateAsync(s => s
            .SetProperty(u => EF.Property<int>(u, Failed), 0)
            .SetProperty(u => EF.Property<DateTimeOffset?>(u, nameof(ISlimUserEntity<TKey>.LockoutEndUtc)), (DateTimeOffset?)null), ct);

    /// <inheritdoc />
    public Task UpdatePasswordHashAsync(SlimUser user, string currentHash, string newHash, CancellationToken ct) =>
        Update(user).Where(u => EF.Property<string>(u, nameof(ISlimUserEntity<TKey>.PasswordHash)) == currentHash)
            .ExecuteUpdateAsync(s => s.SetProperty(u => EF.Property<string>(u, nameof(ISlimUserEntity<TKey>.PasswordHash)), newHash), ct);

    /// <inheritdoc />
    public async Task<bool> UpdateEmailAsync(SlimUser user, string newEmail, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(newEmail);
        var normalized = Normalize(newEmail);
        try
        {
            // the unique index decides – no check-then-act race
            return await Update(user).ExecuteUpdateAsync(s => s
                .SetProperty(u => EF.Property<string>(u, nameof(ISlimUserEntity<TKey>.Email)), newEmail)
                .SetProperty(u => EF.Property<string>(u, nameof(ISlimUserEntity<TKey>.NormalizedEmail)), normalized), ct).ConfigureAwait(false) == 1;
        }
        catch (DbException)
        {
            // ExecuteUpdate bypasses SaveChanges: the provider's own exception arrives, not DbUpdateException
            if (await IsEmailTakenAsync(normalized, Key(user), ct).ConfigureAwait(false)) return false;
            throw;
        }
    }

    /// <inheritdoc />
    public virtual async Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (services.GetService<ISlimUserClaimsProvider<TUser>>() is not { } provider) return [];
        var entity = await FindEntityAsync(user.Id, ct).ConfigureAwait(false);
        return entity is null ? [] : await provider.GetClaimsAsync(entity, ct).ConfigureAwait(false);
    }

    /// <summary>Maps the entity to SlimIdentity's transfer object.</summary>
    protected static SlimUser Map(TUser u)
    {
        ArgumentNullException.ThrowIfNull(u);
        return new SlimUser
        {
            Id = SlimEf.KeyToString(u.Id), Email = u.Email, PasswordHash = u.PasswordHash, SecurityStamp = u.SecurityStamp,
            IsActive = u.IsActive, EmailConfirmed = u.EmailConfirmed, FailedLoginAttempts = u.FailedLoginAttempts,
            LockoutEndUtc = u.LockoutEndUtc, TwoFactorEnabled = u.TwoFactorEnabled, PasswordChangeRequired = u.PasswordChangeRequired,
        };
    }

    private static string Normalize(string email) => email.Trim().ToUpperInvariant();

    private static Expression<Func<TUser, bool>> ById(TKey key) => SlimEf.Equal<TUser, TKey>(nameof(ISlimUserEntity<TKey>.Id), key);

    private static TKey Key(SlimUser user) =>
        SlimEf.TryParseKey<TKey>(user?.Id, out var key) ? key : throw new ArgumentException($"'{user?.Id}' is not a valid user id.", nameof(user));

    private IQueryable<TUser> Update(SlimUser user) => Users.Where(ById(Key(user)));

    private async Task<bool> IsEmailTakenAsync(string normalized, TKey? exceptId, CancellationToken ct)
    {
        var query = Users.AsNoTracking().Where(SlimEf.Equal<TUser, string>(nameof(ISlimUserEntity<TKey>.NormalizedEmail), normalized));
        var ids = await query.Select(u => EF.Property<TKey>(u, nameof(ISlimUserEntity<TKey>.Id))).ToListAsync(ct).ConfigureAwait(false);
        return ids.Any(id => exceptId is null || !id.Equals(exceptId));
    }
}

/// <summary><see cref="ISlimTwoFactorStore"/>: secret and markers on the user entity, codes in <c>SlimRecoveryCodes</c>.</summary>
public class SlimEfTwoFactorStore<TContext, TUser, TKey>(SlimEfContext<TContext> context) : ISlimTwoFactorStore
    where TContext : DbContext
    where TUser : class, ISlimUserEntity<TKey>
    where TKey : IEquatable<TKey>, IParsable<TKey>
{
    private readonly TContext db = context.Db;

    private const string Secret = nameof(ISlimUserEntity<TKey>.TotpSecret);
    private const string CodeAt = nameof(ISlimUserEntity<TKey>.LastTwoFactorCodeAt);
    private const string ChallengeAt = nameof(ISlimUserEntity<TKey>.LastTwoFactorChallengeAt);

    private DbSet<SlimRecoveryCodeEntity<TKey>> Codes => db.Set<SlimRecoveryCodeEntity<TKey>>();

    /// <inheritdoc />
    public Task<string?> GetTotpSecretAsync(SlimUser user, CancellationToken ct) =>
        User(user).Select(u => EF.Property<string?>(u, Secret)).FirstOrDefaultAsync(ct);

    /// <inheritdoc />
    public Task SetTotpSecretAsync(SlimUser user, string protectedSecret, CancellationToken ct) =>
        User(user).ExecuteUpdateAsync(s => s.SetProperty(u => EF.Property<string?>(u, Secret),
            string.IsNullOrEmpty(protectedSecret) ? null : protectedSecret), ct);

    /// <inheritdoc />
    public async Task<bool> TryMarkCodeUsedAsync(SlimUser user, long usedAt, CancellationToken ct) =>
        await User(user).Where(u => EF.Property<long?>(u, CodeAt) == null || EF.Property<long?>(u, CodeAt) < usedAt)
            .ExecuteUpdateAsync(s => s.SetProperty(u => EF.Property<long?>(u, CodeAt), usedAt), ct).ConfigureAwait(false) == 1;

    /// <inheritdoc />
    public async Task<bool> TryMarkChallengeUsedAsync(SlimUser user, long issuedAt, CancellationToken ct) =>
        await User(user).Where(u => EF.Property<long?>(u, ChallengeAt) == null || EF.Property<long?>(u, ChallengeAt) < issuedAt)
            .ExecuteUpdateAsync(s => s.SetProperty(u => EF.Property<long?>(u, ChallengeAt), issuedAt), ct).ConfigureAwait(false) == 1;

    /// <inheritdoc />
    public Task StoreRecoveryCodesAsync(SlimUser user, IEnumerable<string> hashedCodes, CancellationToken ct)
    {
        var key = Key(user);
        var hashes = hashedCodes?.ToList() ?? [];
        // one transaction; through the execution strategy, so it also works with retrying strategies (EnableRetryOnFailure)
        return db.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
        {
            await using var tx = await db.Database.BeginTransactionAsync(ct).ConfigureAwait(false);
            await Codes.Where(SlimEf.Equal<SlimRecoveryCodeEntity<TKey>, TKey>(nameof(SlimRecoveryCodeEntity<TKey>.UserId), key))
                .ExecuteDeleteAsync(ct).ConfigureAwait(false);
            Codes.AddRange(hashes.Select(h => new SlimRecoveryCodeEntity<TKey> { UserId = key, CodeHash = h }));
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
            await tx.CommitAsync(ct).ConfigureAwait(false);
            db.ChangeTracker.Clear();
        });
    }

    /// <inheritdoc />
    public async Task<bool> ValidateAndConsumeRecoveryCodeAsync(SlimUser user, string hashedCode, CancellationToken ct) =>
        await Codes.Where(SlimEf.Equal<SlimRecoveryCodeEntity<TKey>, TKey>(nameof(SlimRecoveryCodeEntity<TKey>.UserId), Key(user)))
            .Where(c => c.CodeHash == hashedCode)
            .ExecuteDeleteAsync(ct).ConfigureAwait(false) == 1;

    private IQueryable<TUser> User(SlimUser user) =>
        db.Set<TUser>().Where(SlimEf.Equal<TUser, TKey>(nameof(ISlimUserEntity<TKey>.Id), Key(user)));

    private static TKey Key(SlimUser user) =>
        SlimEf.TryParseKey<TKey>(user?.Id, out var key) ? key : throw new ArgumentException($"'{user?.Id}' is not a valid user id.", nameof(user));
}

/// <summary><see cref="ISlimRefreshTokenStore"/> on <c>SlimRefreshTokens</c>.</summary>
public class SlimEfRefreshTokenStore<TContext, TKey>(SlimEfContext<TContext> context, TimeProvider time) : ISlimRefreshTokenStore
    where TContext : DbContext
    where TKey : IEquatable<TKey>, IParsable<TKey>
{
    private readonly TContext db = context.Db;

    private DbSet<SlimRefreshTokenEntity<TKey>> Tokens => db.Set<SlimRefreshTokenEntity<TKey>>();

    /// <inheritdoc />
    public async Task StoreRefreshTokenAsync(string userId, string tokenHash, DateTimeOffset expiresAt, CancellationToken ct)
    {
        if (!SlimEf.TryParseKey<TKey>(userId, out var key)) throw new ArgumentException($"'{userId}' is not a valid user id.", nameof(userId));
        Tokens.Add(new SlimRefreshTokenEntity<TKey> { TokenHash = tokenHash, UserId = key, ExpiresAt = expiresAt });
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        db.ChangeTracker.Clear();
    }

    /// <inheritdoc />
    public async Task<string?> ValidateAndConsumeRefreshTokenAsync(string tokenHash, CancellationToken ct)
    {
        var token = await Tokens.AsNoTracking().FirstOrDefaultAsync(t => t.TokenHash == tokenHash, ct).ConfigureAwait(false);
        if (token is null) return null;

        // atomic: only the request that actually deletes the row wins (parallel replays lose)
        var deleted = await Tokens.Where(t => t.TokenHash == tokenHash).ExecuteDeleteAsync(ct).ConfigureAwait(false);
        return deleted == 1 && token.ExpiresAt > time.GetUtcNow() ? SlimEf.KeyToString(token.UserId) : null;
    }
}

/// <summary><see cref="ISlimSessionStore"/> on <c>SlimSessions</c>.</summary>
public class SlimEfSessionStore<TContext, TKey>(SlimEfContext<TContext> context, SlimEntityFrameworkOptions options) : ISlimSessionStore
    where TContext : DbContext
    where TKey : IEquatable<TKey>, IParsable<TKey>
{
    private readonly TContext db = context.Db;

    private DbSet<SlimSessionEntity<TKey>> Sessions => db.Set<SlimSessionEntity<TKey>>();

    /// <inheritdoc />
    public async Task CreateAsync(SlimSession session, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (!SlimEf.TryParseKey<TKey>(session.UserId, out var key)) throw new ArgumentException("Invalid user id.", nameof(session));
        Sessions.Add(new SlimSessionEntity<TKey>
        {
            Id = session.Id, UserId = key, Mode = session.Mode, AuthenticationMethod = session.AuthenticationMethod,
            ImpersonatorId = session.ImpersonatorId, CreatedUtc = session.CreatedUtc, LastSeenUtc = session.LastSeenUtc,
            ExpiresUtc = session.ExpiresUtc,
            UserAgent = options.StoreClientInfo ? session.UserAgent : null,
            IpAddress = options.StoreClientInfo ? session.IpAddress : null,
        });
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        db.ChangeTracker.Clear();
    }

    /// <inheritdoc />
    public async Task<SlimSession?> FindAsync(string sessionId, CancellationToken ct) =>
        await Sessions.AsNoTracking().FirstOrDefaultAsync(s => s.Id == sessionId, ct).ConfigureAwait(false) is { } s ? Map(s) : null;

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<SlimSession>> ListAsync(string userId, CancellationToken ct) =>
        SlimEf.TryParseKey<TKey>(userId, out var key)
            ? (await Sessions.AsNoTracking().Where(ByUser(key)).ToListAsync(ct).ConfigureAwait(false)).Select(Map).ToList()
            : [];

    /// <inheritdoc />
    public Task TouchAsync(string sessionId, DateTimeOffset lastSeenUtc, DateTimeOffset expiresUtc, CancellationToken ct) =>
        Sessions.Where(s => s.Id == sessionId).ExecuteUpdateAsync(s => s
            .SetProperty(x => x.LastSeenUtc, lastSeenUtc)
            .SetProperty(x => x.ExpiresUtc, expiresUtc), ct);

    /// <inheritdoc />
    public Task RevokeAsync(string sessionId, CancellationToken ct) =>
        Sessions.Where(s => s.Id == sessionId).ExecuteDeleteAsync(ct);

    /// <inheritdoc />
    public Task RevokeAllAsync(string userId, string? exceptSessionId, CancellationToken ct)
    {
        if (!SlimEf.TryParseKey<TKey>(userId, out var key)) return Task.CompletedTask;
        var query = Sessions.Where(ByUser(key));
        if (exceptSessionId is not null) query = query.Where(s => s.Id != exceptSessionId);
        return query.ExecuteDeleteAsync(ct);
    }

    private static Expression<Func<SlimSessionEntity<TKey>, bool>> ByUser(TKey key) =>
        SlimEf.Equal<SlimSessionEntity<TKey>, TKey>(nameof(SlimSessionEntity<TKey>.UserId), key);

    // mapped in memory: a database-side Guid → text conversion may differ in case from the user id
    private static SlimSession Map(SlimSessionEntity<TKey> s) => new()
    {
        Id = s.Id, UserId = SlimEf.KeyToString(s.UserId), Mode = s.Mode, AuthenticationMethod = s.AuthenticationMethod,
        ImpersonatorId = s.ImpersonatorId, CreatedUtc = s.CreatedUtc, LastSeenUtc = s.LastSeenUtc, ExpiresUtc = s.ExpiresUtc,
        UserAgent = s.UserAgent, IpAddress = s.IpAddress,
    };
}

/// <summary><see cref="ISlimExternalLoginStore"/> on <c>SlimExternalLogins</c>.</summary>
public class SlimEfExternalLoginStore<TContext, TKey>(SlimEfContext<TContext> context, ISlimUserStore users) : ISlimExternalLoginStore
    where TContext : DbContext
    where TKey : IEquatable<TKey>, IParsable<TKey>
{
    private readonly TContext db = context.Db;

    private DbSet<SlimExternalLoginEntity<TKey>> Logins => db.Set<SlimExternalLoginEntity<TKey>>();

    /// <inheritdoc />
    public async Task<SlimUser?> FindByExternalLoginAsync(string provider, string providerKey, CancellationToken ct)
    {
        var links = await Logins.AsNoTracking().Where(l => l.Provider == provider && l.ProviderKey == providerKey).ToListAsync(ct).ConfigureAwait(false);
        // exact comparison in memory: a case-insensitive collation (SQL Server's default) must not match "Alice" for "alice"
        var link = links.FirstOrDefault(l => string.Equals(l.Provider, provider, StringComparison.Ordinal)
                                             && string.Equals(l.ProviderKey, providerKey, StringComparison.Ordinal));
        return link is null ? null : await users.FindByIdAsync(SlimEf.KeyToString(link.UserId), ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task LinkExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct)
    {
        if (!SlimEf.TryParseKey<TKey>(userId, out var key)) throw new ArgumentException($"'{userId}' is not a valid user id.", nameof(userId));
        Logins.Add(new SlimExternalLoginEntity<TKey> { UserId = key, Provider = provider, ProviderKey = providerKey });
        await db.SaveChangesAsync(ct).ConfigureAwait(false);
        db.ChangeTracker.Clear();
    }

    /// <inheritdoc />
    public Task RemoveExternalLoginsAsync(string userId, CancellationToken ct) =>
        SlimEf.TryParseKey<TKey>(userId, out var key)
            ? Logins.Where(SlimEf.Equal<SlimExternalLoginEntity<TKey>, TKey>(nameof(SlimExternalLoginEntity<TKey>.UserId), key)).ExecuteDeleteAsync(ct)
            : Task.CompletedTask;
}
