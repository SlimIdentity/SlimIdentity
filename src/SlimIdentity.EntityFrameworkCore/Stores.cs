using System.Data.Common;
using System.Linq.Expressions;

namespace SlimIdentity.EntityFrameworkCore;

/// <summary>
/// Optional: creates new user entities (registration, external login) – sets a tenant, defaults and the registration
/// profile. Required as soon as accounts are created with a <see cref="SlimNewUser.Profile"/>.
/// </summary>
/// <example><code>
/// public sealed class AppUsers : ISlimUserFactory&lt;AppUser&gt;
/// {
///     public AppUser Create(SlimNewUser user) => user.Profile is SignUpProfile p
///         ? new AppUser { DisplayName = p.Name, Company = new Company { Name = p.Company } }   // saved together
///         : new AppUser();
/// }
/// </code></example>
public interface ISlimUserFactory<out TUser>
{
    /// <summary>
    /// A new, not yet tracked user entity for <paramref name="user"/>. Copy what you need from
    /// <see cref="SlimNewUser.Profile"/> into it – related entities set as navigation properties are inserted in the same
    /// <c>SaveChanges</c>, so account and profile are created together or not at all. SlimIdentity sets the address,
    /// hash and security fields afterwards.
    /// </summary>
    TUser Create(SlimNewUser user);
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

    /// <summary>Saves and clears the change tracker – also when saving fails, so nothing leaks into the next call.</summary>
    public static async Task SaveAndClearAsync(DbContext db, CancellationToken ct)
    {
        try
        {
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            db.ChangeTracker.Clear();
        }
    }
}

/// <summary><see cref="ISlimUserStore"/> on your user entity.</summary>
public class SlimEfUserStore<TContext, TUser, TKey>(SlimEfContext<TContext> context, IServiceProvider services) : ISlimUserStore
    where TContext : DbContext
    where TUser : class, ISlimUserEntity<TKey>, new()
    where TKey : IEquatable<TKey>, IParsable<TKey>
{
    private readonly TContext db = context.Db;

    private const int MaxAttemptRetries = 20;

    private static (string Counter, string End) AttemptColumns(SlimAttemptFactor factor) => factor switch
    {
        SlimAttemptFactor.Password => (nameof(ISlimUserEntity<TKey>.FailedLoginAttempts), nameof(ISlimUserEntity<TKey>.LockoutEndUtc)),
        SlimAttemptFactor.SecondFactor => (nameof(ISlimUserEntity<TKey>.FailedSecondFactorAttempts), nameof(ISlimUserEntity<TKey>.SecondFactorLockoutEndUtc)),
        _ => throw new ArgumentOutOfRangeException(nameof(factor)),
    };

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
    public async Task<SlimUser?> CreateAsync(SlimNewUser newUser, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(newUser);
        ArgumentNullException.ThrowIfNull(newUser.Email);
        var factory = services.GetService<ISlimUserFactory<TUser>>();
        if (factory is null && newUser.Profile is not null)
            throw new InvalidOperationException(
                $"SlimIdentity: a registration profile ({newUser.Profile.GetType().Name}) needs an ISlimUserFactory<{typeof(TUser).Name}> " +
                "that writes it – otherwise it would be lost.");
        var user = factory?.Create(newUser) ?? new TUser();
        user.Email = newUser.Email;
        user.NormalizedEmail = Normalize(newUser.Email);
        user.PasswordHash = newUser.PasswordHash ?? string.Empty;
        user.EmailConfirmed = newUser.EmailConfirmed;
        user.SecurityStamp = SlimUser.NewSecurityStamp();
        user.IsActive = true;
        context.BeforeWrite();
        Users.Add(user);   // with whatever the factory attached (profile entities): one SaveChanges, one transaction
        try
        {
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
        }
        catch (DbUpdateException)
        {
            // unique index on NormalizedEmail: a concurrent registration took the address – anything else is rethrown.
            // Nothing was written; forget the account and its profile entities (the store's own context).
            db.ChangeTracker.Clear();
            if (await IsEmailTakenAsync(user.NormalizedEmail, default, ct).ConfigureAwait(false)) return null;
            throw;
        }
        finally
        {
            db.ChangeTracker.Clear();   // also after any other error: nothing leaks into the next call on this context
        }
        return Map(user);
    }

    /// <inheritdoc />
    public async Task<bool> UpdateSecurityStateAsync(SlimUser user, string expectedStamp, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(expectedStamp);
        return await WithStamp(user, expectedStamp).ExecuteUpdateAsync(s => s
            .SetProperty(u => EF.Property<string>(u, nameof(ISlimUserEntity<TKey>.PasswordHash)), user.PasswordHash)
            .SetProperty(u => EF.Property<string>(u, nameof(ISlimUserEntity<TKey>.SecurityStamp)), user.SecurityStamp)
            .SetProperty(u => EF.Property<bool>(u, nameof(ISlimUserEntity<TKey>.EmailConfirmed)), user.EmailConfirmed)
            .SetProperty(u => EF.Property<bool>(u, nameof(ISlimUserEntity<TKey>.TwoFactorEnabled)), user.TwoFactorEnabled)
            .SetProperty(u => EF.Property<bool>(u, nameof(ISlimUserEntity<TKey>.PasswordChangeRequired)), user.PasswordChangeRequired), ct)
            .ConfigureAwait(false) == 1;
    }

    /// <summary>The user row, only while its stamp is <paramref name="expectedStamp"/> (a missing stamp counts as empty).</summary>
    private IQueryable<TUser> WithStamp(SlimUser user, string expectedStamp) =>
        Update(user).Where(u => (EF.Property<string?>(u, nameof(ISlimUserEntity<TKey>.SecurityStamp)) ?? "") == expectedStamp);

    /// <inheritdoc />
    public async Task<SlimAttemptReservation?> TryBeginAttemptAsync(SlimUser user, SlimAttemptRequest attempt, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(attempt);
        var (counter, end) = AttemptColumns(attempt.Factor);
        // portable compare-and-set loop: no lost update and exactly one attempt reaches the threshold, on every provider
        for (var i = 0; i < MaxAttemptRetries; i++)
        {
            var state = await Update(user)
                .Select(u => new { Count = EF.Property<int>(u, counter), End = EF.Property<DateTimeOffset?>(u, end) })
                .FirstOrDefaultAsync(ct).ConfigureAwait(false);
            if (state is null) return null;   // deleted during the sign-in
            if (attempt.IsLockedOut(state.End)) return SlimAttemptReservation.LockedOut(state.End!.Value);

            int oldCount = state.Count, newCount = oldCount + 1;
            DateTimeOffset? oldEnd = state.End, newEnd = attempt.NextLockoutEnd(newCount, oldEnd);
            var updated = await Update(user)
                .Where(u => EF.Property<int>(u, counter) == oldCount && EF.Property<DateTimeOffset?>(u, end) == oldEnd)
                .ExecuteUpdateAsync(s => s
                    .SetProperty(u => EF.Property<int>(u, counter), newCount)
                    .SetProperty(u => EF.Property<DateTimeOffset?>(u, end), newEnd), ct).ConfigureAwait(false);
            if (updated == 1) return SlimAttemptReservation.Reserved(newCount);
        }
        return null;   // permanent contention: the attempt is not checked
    }

    /// <inheritdoc />
    public Task ResetFailedAttemptsAsync(SlimUser user, SlimAttemptFactor factor, CancellationToken ct)
    {
        var (counter, end) = AttemptColumns(factor);
        return Update(user).ExecuteUpdateAsync(s => s
            .SetProperty(u => EF.Property<int>(u, counter), 0)
            .SetProperty(u => EF.Property<DateTimeOffset?>(u, end), (DateTimeOffset?)null), ct);
    }

    /// <inheritdoc />
    public Task UpdatePasswordHashAsync(SlimUser user, string currentHash, string newHash, CancellationToken ct) =>
        Update(user).Where(u => EF.Property<string>(u, nameof(ISlimUserEntity<TKey>.PasswordHash)) == currentHash)
            .ExecuteUpdateAsync(s => s.SetProperty(u => EF.Property<string>(u, nameof(ISlimUserEntity<TKey>.PasswordHash)), newHash), ct);

    /// <inheritdoc />
    public async Task<bool> UpdateSecurityStampAsync(SlimUser user, string expectedStamp, string newStamp, CancellationToken ct) =>
        await Update(user).Where(u => EF.Property<string>(u, nameof(ISlimUserEntity<TKey>.SecurityStamp)) == expectedStamp)
            .ExecuteUpdateAsync(s => s.SetProperty(u => EF.Property<string>(u, nameof(ISlimUserEntity<TKey>.SecurityStamp)), newStamp), ct)
            .ConfigureAwait(false) == 1;

    /// <inheritdoc />
    public async Task<SlimEmailUpdateResult> UpdateEmailAsync(SlimUser user, string newEmail, string expectedStamp, string newStamp, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(newEmail);
        ArgumentNullException.ThrowIfNull(expectedStamp);
        ArgumentNullException.ThrowIfNull(newStamp);
        var normalized = Normalize(newEmail);
        try
        {
            // the unique index decides – no check-then-act race
            var updated = await WithStamp(user, expectedStamp).ExecuteUpdateAsync(s => s
                .SetProperty(u => EF.Property<string>(u, nameof(ISlimUserEntity<TKey>.Email)), newEmail)
                .SetProperty(u => EF.Property<string>(u, nameof(ISlimUserEntity<TKey>.NormalizedEmail)), normalized)
                .SetProperty(u => EF.Property<bool>(u, nameof(ISlimUserEntity<TKey>.EmailConfirmed)), true)
                .SetProperty(u => EF.Property<string>(u, nameof(ISlimUserEntity<TKey>.SecurityStamp)), newStamp), ct).ConfigureAwait(false);
            return updated == 1 ? SlimEmailUpdateResult.Updated : SlimEmailUpdateResult.StampChanged;
        }
        catch (DbException)
        {
            // ExecuteUpdate bypasses SaveChanges: the provider's own exception arrives, not DbUpdateException
            if (await IsEmailTakenAsync(normalized, Key(user), ct).ConfigureAwait(false)) return SlimEmailUpdateResult.EmailTaken;
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
            LockoutEndUtc = u.LockoutEndUtc, FailedSecondFactorAttempts = u.FailedSecondFactorAttempts,
            SecondFactorLockoutEndUtc = u.SecondFactorLockoutEndUtc,
            TwoFactorEnabled = u.TwoFactorEnabled, PasswordChangeRequired = u.PasswordChangeRequired,
        };
    }

    private static string Normalize(string email) => email.Trim().ToUpperInvariant();

    private static Expression<Func<TUser, bool>> ById(TKey key) => SlimEf.Equal<TUser, TKey>(nameof(ISlimUserEntity<TKey>.Id), key);

    private static TKey Key(SlimUser user) =>
        SlimEf.TryParseKey<TKey>(user?.Id, out var key) ? key : throw new ArgumentException($"'{user?.Id}' is not a valid user id.", nameof(user));

    private IQueryable<TUser> Update(SlimUser user) => context.Writing(Users).Where(ById(Key(user)));

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
        context.Writing(User(user)).ExecuteUpdateAsync(s => s.SetProperty(u => EF.Property<string?>(u, Secret),
            string.IsNullOrEmpty(protectedSecret) ? null : protectedSecret), ct);

    /// <inheritdoc />
    public async Task<bool> TryMarkCodeUsedAsync(SlimUser user, long usedAt, CancellationToken ct) =>
        await context.Writing(User(user)).Where(u => EF.Property<long?>(u, CodeAt) == null || EF.Property<long?>(u, CodeAt) < usedAt)
            .ExecuteUpdateAsync(s => s.SetProperty(u => EF.Property<long?>(u, CodeAt), usedAt), ct).ConfigureAwait(false) == 1;

    /// <inheritdoc />
    public async Task<bool> TryMarkChallengeUsedAsync(SlimUser user, long issuedAt, CancellationToken ct) =>
        await context.Writing(User(user)).Where(u => EF.Property<long?>(u, ChallengeAt) == null || EF.Property<long?>(u, ChallengeAt) < issuedAt)
            .ExecuteUpdateAsync(s => s.SetProperty(u => EF.Property<long?>(u, ChallengeAt), issuedAt), ct).ConfigureAwait(false) == 1;

    /// <inheritdoc />
    public Task StoreRecoveryCodesAsync(SlimUser user, IEnumerable<string> hashedCodes, CancellationToken ct)
    {
        var key = Key(user);
        var hashes = hashedCodes?.ToList() ?? [];
        context.BeforeWrite();
        // one transaction; through the execution strategy, so it also works with retrying strategies (EnableRetryOnFailure)
        return db.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
        {
            try
            {
                await using var tx = await db.Database.BeginTransactionAsync(ct).ConfigureAwait(false);
                await Codes.Where(SlimEf.Equal<SlimRecoveryCodeEntity<TKey>, TKey>(nameof(SlimRecoveryCodeEntity<TKey>.UserId), key))
                    .ExecuteDeleteAsync(ct).ConfigureAwait(false);
                Codes.AddRange(hashes.Select(h => new SlimRecoveryCodeEntity<TKey> { UserId = key, CodeHash = h }));
                await db.SaveChangesAsync(ct).ConfigureAwait(false);
                await tx.CommitAsync(ct).ConfigureAwait(false);
            }
            finally
            {
                db.ChangeTracker.Clear();   // a retry starts clean; a failure leaves nothing behind
            }
        });
    }

    /// <inheritdoc />
    public async Task<bool> ValidateAndConsumeRecoveryCodeAsync(SlimUser user, string hashedCode, CancellationToken ct) =>
        await context.Writing(Codes).Where(SlimEf.Equal<SlimRecoveryCodeEntity<TKey>, TKey>(nameof(SlimRecoveryCodeEntity<TKey>.UserId), Key(user)))
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
        context.BeforeWrite();
        Tokens.Add(new SlimRefreshTokenEntity<TKey> { TokenHash = tokenHash, UserId = key, ExpiresAt = expiresAt });
        await SlimEf.SaveAndClearAsync(db, ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<string?> ValidateAndConsumeRefreshTokenAsync(string tokenHash, CancellationToken ct)
    {
        var token = await Tokens.AsNoTracking().FirstOrDefaultAsync(t => t.TokenHash == tokenHash, ct).ConfigureAwait(false);
        if (token is null) return null;

        // atomic: only the request that actually deletes the row wins (parallel replays lose)
        var deleted = await context.Writing(Tokens).Where(t => t.TokenHash == tokenHash).ExecuteDeleteAsync(ct).ConfigureAwait(false);
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
        context.BeforeWrite();
        Sessions.Add(new SlimSessionEntity<TKey>
        {
            Id = session.Id, UserId = key, Mode = session.Mode, AuthenticationMethod = session.AuthenticationMethod,
            ImpersonatorId = session.ImpersonatorId, CreatedUtc = session.CreatedUtc, LastSeenUtc = session.LastSeenUtc,
            ExpiresUtc = session.ExpiresUtc,
            UserAgent = options.StoreClientInfo ? session.UserAgent : null,
            IpAddress = options.StoreClientInfo ? session.IpAddress : null,
        });
        await SlimEf.SaveAndClearAsync(db, ct).ConfigureAwait(false);
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
        context.Writing(Sessions).Where(s => s.Id == sessionId).ExecuteUpdateAsync(s => s
            .SetProperty(x => x.LastSeenUtc, lastSeenUtc)
            .SetProperty(x => x.ExpiresUtc, expiresUtc), ct);

    /// <inheritdoc />
    public Task RevokeAsync(string sessionId, CancellationToken ct) =>
        context.Writing(Sessions).Where(s => s.Id == sessionId).ExecuteDeleteAsync(ct);

    /// <inheritdoc />
    public Task RevokeAllAsync(string userId, string? exceptSessionId, CancellationToken ct)
    {
        if (!SlimEf.TryParseKey<TKey>(userId, out var key)) return Task.CompletedTask;
        var query = context.Writing(Sessions).Where(ByUser(key));
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
        context.BeforeWrite();
        Logins.Add(new SlimExternalLoginEntity<TKey> { UserId = key, Provider = provider, ProviderKey = providerKey });
        await SlimEf.SaveAndClearAsync(db, ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public Task RemoveExternalLoginsAsync(string userId, CancellationToken ct) =>
        SlimEf.TryParseKey<TKey>(userId, out var key)
            ? context.Writing(Logins).Where(SlimEf.Equal<SlimExternalLoginEntity<TKey>, TKey>(nameof(SlimExternalLoginEntity<TKey>.UserId), key)).ExecuteDeleteAsync(ct)
            : Task.CompletedTask;

    /// <inheritdoc />
    public async Task<IReadOnlyList<SlimExternalLogin>> GetExternalLoginsAsync(string userId, CancellationToken ct)
    {
        if (!SlimEf.TryParseKey<TKey>(userId, out var key)) return [];
        return await Logins.AsNoTracking()
            .Where(SlimEf.Equal<SlimExternalLoginEntity<TKey>, TKey>(nameof(SlimExternalLoginEntity<TKey>.UserId), key))
            .OrderBy(l => l.Provider).ThenBy(l => l.ProviderKey)
            .Select(l => new SlimExternalLogin(l.Provider, l.ProviderKey))
            .ToListAsync(ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<bool> RemoveExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct)
    {
        if (!SlimEf.TryParseKey<TKey>(userId, out var key)) return false;
        // candidates by user and provider, the key compared exactly in memory (case-sensitive, like FindByExternalLoginAsync)
        var candidates = await Logins.AsNoTracking()
            .Where(SlimEf.Equal<SlimExternalLoginEntity<TKey>, TKey>(nameof(SlimExternalLoginEntity<TKey>.UserId), key))
            .Where(l => l.Provider == provider)
            .Select(l => l.ProviderKey)
            .ToListAsync(ct).ConfigureAwait(false);
        if (!candidates.Contains(providerKey, StringComparer.Ordinal)) return false;

        return await context.Writing(Logins)
            .Where(SlimEf.Equal<SlimExternalLoginEntity<TKey>, TKey>(nameof(SlimExternalLoginEntity<TKey>.UserId), key))
            .Where(l => l.Provider == provider && l.ProviderKey == providerKey)
            .ExecuteDeleteAsync(ct).ConfigureAwait(false) > 0;
    }
}

/// <summary><see cref="ISlimPasskeyStore"/> on the <c>SlimPasskeys</c> table.</summary>
public class SlimEfPasskeyStore<TContext, TKey>(SlimEfContext<TContext> context) : ISlimPasskeyStore
    where TContext : DbContext
    where TKey : IEquatable<TKey>, IParsable<TKey>
{
    private readonly TContext db = context.Db;

    private DbSet<SlimPasskeyEntity<TKey>> Passkeys => db.Set<SlimPasskeyEntity<TKey>>();

    private static byte[] Hash(byte[] credentialId) => System.Security.Cryptography.SHA256.HashData(credentialId);

    private static System.Linq.Expressions.Expression<Func<SlimPasskeyEntity<TKey>, bool>> OfUser(TKey key) =>
        SlimEf.Equal<SlimPasskeyEntity<TKey>, TKey>(nameof(SlimPasskeyEntity<TKey>.UserId), key);

    /// <inheritdoc />
    public async Task<IReadOnlyList<SlimPasskey>> GetPasskeysAsync(string userId, CancellationToken ct)
    {
        if (!SlimEf.TryParseKey<TKey>(userId, out var key)) return [];
        var rows = await Passkeys.AsNoTracking().Where(OfUser(key)).ToListAsync(ct).ConfigureAwait(false);
        return [.. rows.OrderBy(p => p.CreatedUtc).Select(Map)];   // in memory: SQLite cannot order by DateTimeOffset
    }

    /// <inheritdoc />
    public async Task<SlimPasskey?> FindPasskeyAsync(byte[] credentialId, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(credentialId);
        var hash = Hash(credentialId);
        var row = await Passkeys.AsNoTracking().FirstOrDefaultAsync(p => p.CredentialIdHash == hash, ct).ConfigureAwait(false);
        return row is not null && row.CredentialId.AsSpan().SequenceEqual(credentialId) ? Map(row) : null;
    }

    /// <inheritdoc />
    public async Task<bool> AddPasskeyAsync(SlimPasskey passkey, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(passkey);
        if (!SlimEf.TryParseKey<TKey>(passkey.UserId, out var key)) throw new ArgumentException($"'{passkey.UserId}' is not a valid user id.", nameof(passkey));
        var hash = Hash(passkey.CredentialId);
        if (await Passkeys.AnyAsync(p => p.CredentialIdHash == hash, ct).ConfigureAwait(false)) return false;

        var entity = new SlimPasskeyEntity<TKey>
        {
            CredentialIdHash = hash, CredentialId = passkey.CredentialId, UserId = key, PublicKey = passkey.PublicKey,
            SignCount = passkey.SignCount, LastChallengeAt = passkey.LastChallengeAt, Name = passkey.Name,
            BackupEligible = passkey.BackupEligible, BackedUp = passkey.BackedUp, UserHandle = passkey.UserHandle,
            CreatedUtc = passkey.CreatedUtc, LastUsedUtc = passkey.LastUsedUtc,
        };
        context.BeforeWrite();
        Passkeys.Add(entity);
        try
        {
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
            return true;
        }
        catch (DbUpdateException)
        {
            // registered concurrently (primary key) – anything else is rethrown
            db.Entry(entity).State = EntityState.Detached;
            if (await Passkeys.AnyAsync(p => p.CredentialIdHash == hash, ct).ConfigureAwait(false)) return false;
            throw;
        }
        finally
        {
            db.ChangeTracker.Clear();
        }
    }

    /// <inheritdoc />
    public async Task<bool> TryRecordUseAsync(byte[] credentialId, uint expectedSignCount, uint signCount, long challengeIssuedAt, DateTimeOffset usedUtc, bool backedUp, CancellationToken ct)
    {
        var hash = Hash(credentialId);
        long expected = expectedSignCount, next = signCount;
        return await context.Writing(Passkeys)
            .Where(p => p.CredentialIdHash == hash && p.SignCount == expected && (p.LastChallengeAt == null || p.LastChallengeAt < challengeIssuedAt))
            .ExecuteUpdateAsync(s => s
                .SetProperty(p => p.SignCount, next)
                .SetProperty(p => p.LastChallengeAt, challengeIssuedAt)
                .SetProperty(p => p.LastUsedUtc, usedUtc)
                .SetProperty(p => p.BackedUp, backedUp), ct).ConfigureAwait(false) == 1;
    }

    /// <inheritdoc />
    public async Task<bool> RenamePasskeyAsync(string userId, byte[] credentialId, string name, CancellationToken ct)
    {
        if (!SlimEf.TryParseKey<TKey>(userId, out var key)) return false;
        var hash = Hash(credentialId);
        return await context.Writing(Passkeys).Where(OfUser(key)).Where(p => p.CredentialIdHash == hash)
            .ExecuteUpdateAsync(s => s.SetProperty(p => p.Name, name), ct).ConfigureAwait(false) == 1;
    }

    /// <inheritdoc />
    public async Task<bool> RemovePasskeyAsync(string userId, byte[] credentialId, CancellationToken ct)
    {
        if (!SlimEf.TryParseKey<TKey>(userId, out var key)) return false;
        var hash = Hash(credentialId);
        return await context.Writing(Passkeys).Where(OfUser(key)).Where(p => p.CredentialIdHash == hash).ExecuteDeleteAsync(ct).ConfigureAwait(false) == 1;
    }

    /// <inheritdoc />
    public async Task RemovePasskeysAsync(string userId, CancellationToken ct)
    {
        if (!SlimEf.TryParseKey<TKey>(userId, out var key)) return;
        await context.Writing(Passkeys).Where(OfUser(key)).ExecuteDeleteAsync(ct).ConfigureAwait(false);
    }

    private static SlimPasskey Map(SlimPasskeyEntity<TKey> p) => new()
    {
        UserId = SlimEf.KeyToString(p.UserId), CredentialId = p.CredentialId, PublicKey = p.PublicKey, SignCount = (uint)p.SignCount,
        LastChallengeAt = p.LastChallengeAt, Name = p.Name, CreatedUtc = p.CreatedUtc, LastUsedUtc = p.LastUsedUtc,
        BackupEligible = p.BackupEligible, BackedUp = p.BackedUp, UserHandle = p.UserHandle,
    };
}

/// <summary>
/// <see cref="ISlimSharedState"/> on the table <c>SlimSharedState</c>: single-use markers through the primary key,
/// counters through a compare-and-set update. Expired rows are taken over in place and deleted now and then.
/// </summary>
public class SlimEfSharedState<TContext>(SlimEfContext<TContext> context, TimeProvider time) : ISlimSharedState
    where TContext : DbContext
{
    private const int MaxAttempts = 50;
    private const int CleanupOneIn = 100;

    private DbSet<SlimSharedStateEntity> Entries => context.Db.Set<SlimSharedStateEntity>();

    /// <inheritdoc />
    public async Task<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(key);
        var now = time.GetUtcNow().ToUnixTimeMilliseconds();
        var expires = expiresAt.ToUnixTimeMilliseconds();
        await CleanupSometimesAsync(now, ct).ConfigureAwait(false);

        // an expired marker is taken over atomically – only one caller's update matches
        if (await context.Writing(Entries).Where(e => e.Key == key && e.ExpiresAt <= now)
                .ExecuteUpdateAsync(s => s.SetProperty(e => e.ExpiresAt, expires).SetProperty(e => e.Count, 0L), ct).ConfigureAwait(false) == 1)
            return true;
        return await TryInsertAsync(key, 0, expires, ct).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<long> IncrementAsync(string key, TimeSpan window, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(key);
        for (var attempt = 0; attempt < MaxAttempts; attempt++)
        {
            var now = time.GetUtcNow().ToUnixTimeMilliseconds();
            var end = now + (long)window.TotalMilliseconds;
            var current = await Entries.AsNoTracking().Where(e => e.Key == key)
                .Select(e => new { e.Count, e.ExpiresAt }).FirstOrDefaultAsync(ct).ConfigureAwait(false);
            if (current is null)
            {
                if (await TryInsertAsync(key, 1, end, ct).ConfigureAwait(false)) return 1;
                continue;
            }

            var (count, expires) = current.ExpiresAt > now ? (current.Count + 1, current.ExpiresAt) : (1L, end);
            if (await context.Writing(Entries)
                    .Where(e => e.Key == key && e.Count == current.Count && e.ExpiresAt == current.ExpiresAt)
                    .ExecuteUpdateAsync(s => s.SetProperty(e => e.Count, count).SetProperty(e => e.ExpiresAt, expires), ct).ConfigureAwait(false) == 1)
                return count;
        }
        throw new InvalidOperationException($"SlimIdentity: the counter could not be updated after {MaxAttempts} attempts (heavy contention).");
    }

    private async Task<bool> TryInsertAsync(string key, long count, long expiresAt, CancellationToken ct)
    {
        var db = context.Db;
        var entity = new SlimSharedStateEntity { Key = key, Count = count, ExpiresAt = expiresAt };
        context.BeforeWrite();
        Entries.Add(entity);
        try
        {
            await db.SaveChangesAsync(ct).ConfigureAwait(false);
            return true;
        }
        catch (DbUpdateException)
        {
            // inserted concurrently (primary key) – anything else is rethrown
            db.Entry(entity).State = EntityState.Detached;
            if (await Entries.AsNoTracking().AnyAsync(e => e.Key == key, ct).ConfigureAwait(false)) return false;
            throw;
        }
        finally
        {
            db.ChangeTracker.Clear();
        }
    }

    private Task CleanupSometimesAsync(long now, CancellationToken ct) =>
        System.Security.Cryptography.RandomNumberGenerator.GetInt32(CleanupOneIn) == 0
            ? context.Writing(Entries).Where(e => e.ExpiresAt <= now).ExecuteDeleteAsync(ct)
            : Task.CompletedTask;
}