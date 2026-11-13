using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace SlimIdentity.Tests.Infrastructure;

public sealed class TestUserStore : ISlimUserStore
{
    private readonly ConcurrentDictionary<string, SlimUser> _users = new();
    private readonly ConcurrentDictionary<string, string[]> _roles = new();

    public SlimUser Seed(string email, string? password, params string[] roles) => SeedWithId(Guid.NewGuid().ToString(), email, password, roles);

    /// <summary>A user with a chosen id – e.g. the same id in two tenant stores.</summary>
    public SlimUser SeedWithId(string id, string email, string? password, params string[] roles)
    {
        var user = new SlimUser { Id = id, Email = email, EmailConfirmed = true };
        if (password is not null) user.PasswordHash = new PasswordHasher<SlimUser>().HashPassword(user, password);
        _users[user.Id] = user;
        _roles[user.Id] = roles;
        return Clone(user);
    }

    /// <summary>Snapshot of the persisted state (tests inspect lockout, stamp, …).</summary>
    public SlimUser Get(string email) => Clone(_users.Values.Single(u => string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase)));

    public void SetActive(string userId, bool active) => _users[userId].IsActive = active;

    /// <summary>Snapshot of all persisted users.</summary>
    public IReadOnlyList<SlimUser> All => _users.Values.Select(Clone).ToList();

    /// <summary>Simulates a password change by another request (new hash, new stamp).</summary>
    public void ChangePassword(string userId, string password)
    {
        var stored = _users[userId];
        lock (stored)
        {
            stored.PasswordHash = new PasswordHasher<SlimUser>().HashPassword(stored, password);
            stored.SecurityStamp = SlimUser.NewSecurityStamp();
        }
    }

    public Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct) =>
        Task.FromResult(_users.Values.FirstOrDefault(u => string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase)) is { } u ? Clone(u) : null);

    public Task<SlimUser?> FindByIdAsync(string userId, CancellationToken ct) =>
        Task.FromResult(_users.TryGetValue(userId, out var u) ? Clone(u) : null);

    /// <summary>Called between the "exists?" lookup and the insert of <see cref="CreateAsync"/> (race simulation).</summary>
    public Action<string>? BeforeCreate { get; set; }

    /// <summary>Called by <see cref="TryBeginAttemptAsync"/> before it reserves (race simulation).</summary>
    public Action<string>? BeforeAttempt { get; set; }

    /// <summary>The profiles passed to <see cref="CreateAsync"/>, by user id.</summary>
    public ConcurrentDictionary<string, object?> Profiles { get; } = new();

    public Task<SlimUser?> CreateAsync(SlimNewUser newUser, CancellationToken ct)
    {
        var (email, passwordHash) = (newUser.Email, newUser.PasswordHash);
        BeforeCreate?.Invoke(email);
        lock (_users)
        {
            // unique index on the e-mail address
            if (_users.Values.Any(u => string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase)))
                return Task.FromResult<SlimUser?>(null);
            var user = new SlimUser { Id = Guid.NewGuid().ToString(), Email = email, PasswordHash = passwordHash, EmailConfirmed = newUser.EmailConfirmed };
            _users[user.Id] = user;
            _roles[user.Id] = [];
            Profiles[user.Id] = newUser.Profile;
            return Task.FromResult<SlimUser?>(Clone(user));
        }
    }

    public Task<SlimAttemptReservation?> TryBeginAttemptAsync(SlimUser user, SlimAttemptRequest attempt, CancellationToken ct)
    {
        BeforeAttempt?.Invoke(user.Id);
        if (!_users.TryGetValue(user.Id, out var stored)) return Task.FromResult<SlimAttemptReservation?>(null);
        lock (stored)
        {
            var end = stored.LockoutEndOf(attempt.Factor);
            if (attempt.IsLockedOut(end)) return Task.FromResult<SlimAttemptReservation?>(SlimAttemptReservation.LockedOut(end!.Value));
            var count = (attempt.Factor == SlimAttemptFactor.Password ? stored.FailedLoginAttempts : stored.FailedSecondFactorAttempts) + 1;
            stored.SetAttempts(attempt.Factor, count, attempt.NextLockoutEnd(count, end));
            return Task.FromResult<SlimAttemptReservation?>(SlimAttemptReservation.Reserved(count));
        }
    }

    public Task ResetFailedAttemptsAsync(SlimUser user, SlimAttemptFactor factor, CancellationToken ct)
    {
        var stored = _users[user.Id];
        lock (stored) stored.SetAttempts(factor, 0, null);
        return Task.CompletedTask;
    }

    /// <summary>Test setup: sets counter and lockout end of a factor directly.</summary>
    public void SetAttempts(string userId, SlimAttemptFactor factor, int failedAttempts, DateTimeOffset? lockoutEndUtc)
    {
        var stored = _users[userId];
        lock (stored) stored.SetAttempts(factor, failedAttempts, lockoutEndUtc);
    }

    public Task UpdatePasswordHashAsync(SlimUser user, string currentHash, string newHash, CancellationToken ct)
    {
        var stored = _users[user.Id];
        lock (stored) if (stored.PasswordHash == currentHash) stored.PasswordHash = newHash;
        return Task.CompletedTask;
    }

    public Task<bool> UpdateSecurityStateAsync(SlimUser user, string expectedStamp, CancellationToken ct)
    {
        if (!_users.TryGetValue(user.Id, out var stored)) return Task.FromResult(false);
        lock (stored)
        {
            if ((stored.SecurityStamp ?? string.Empty) != expectedStamp) return Task.FromResult(false);
            stored.PasswordHash = user.PasswordHash;
            stored.SecurityStamp = user.SecurityStamp;
            stored.EmailConfirmed = user.EmailConfirmed;
            stored.TwoFactorEnabled = user.TwoFactorEnabled;
            stored.PasswordChangeRequired = user.PasswordChangeRequired;
            return Task.FromResult(true);
        }
    }

    /// <summary>Test setup: writes the security state regardless of the stored stamp.</summary>
    public Task UpdateSecurityStateAsync(SlimUser user, CancellationToken ct)
    {
        var stored = _users[user.Id];
        lock (stored) return UpdateSecurityStateAsync(user, stored.SecurityStamp ?? string.Empty, ct);
    }

    public Task<bool> UpdateSecurityStampAsync(SlimUser user, string expectedStamp, string newStamp, CancellationToken ct)
    {
        if (!_users.TryGetValue(user.Id, out var stored)) return Task.FromResult(false);
        lock (stored)
        {
            if (stored.SecurityStamp != expectedStamp) return Task.FromResult(false);
            stored.SecurityStamp = newStamp;
            return Task.FromResult(true);
        }
    }

    public Task<SlimEmailUpdateResult> UpdateEmailAsync(SlimUser user, string newEmail, string expectedStamp, string newStamp, CancellationToken ct)
    {
        lock (_users)
        {
            if (_users.Values.Any(u => u.Id != user.Id && string.Equals(u.Email, newEmail, StringComparison.OrdinalIgnoreCase)))
                return Task.FromResult(SlimEmailUpdateResult.EmailTaken);
            if (!_users.TryGetValue(user.Id, out var stored)) return Task.FromResult(SlimEmailUpdateResult.StampChanged);
            lock (stored)
            {
                if ((stored.SecurityStamp ?? string.Empty) != expectedStamp) return Task.FromResult(SlimEmailUpdateResult.StampChanged);
                (stored.Email, stored.EmailConfirmed, stored.SecurityStamp) = (newEmail, true, newStamp);
                return Task.FromResult(SlimEmailUpdateResult.Updated);
            }
        }
    }

    /// <summary>Calls of <see cref="GetClaimsAsync"/> – claims must only be reloaded when they changed.</summary>
    public int ClaimsLoads => Volatile.Read(ref _claimsLoads);
    private int _claimsLoads;

    public void SetRoles(string userId, params string[] roles) => _roles[userId] = roles;

    public Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct) => CountedClaims(user);

    private Task<IReadOnlyCollection<Claim>> CountedClaims(SlimUser user)
    {
        Interlocked.Increment(ref _claimsLoads);
        return LoadClaims(user);
    }

    private Task<IReadOnlyCollection<Claim>> LoadClaims(SlimUser user) =>
        Task.FromResult<IReadOnlyCollection<Claim>>(
            (_roles.TryGetValue(user.Id, out var roles) ? roles : []).Select(r => new Claim(ClaimTypes.Role, r)).ToList());

    private static SlimUser Clone(SlimUser u) => new()
    {
        Id = u.Id, Email = u.Email, PasswordHash = u.PasswordHash, SecurityStamp = u.SecurityStamp,
        IsActive = u.IsActive, EmailConfirmed = u.EmailConfirmed, FailedLoginAttempts = u.FailedLoginAttempts,
        LockoutEndUtc = u.LockoutEndUtc, FailedSecondFactorAttempts = u.FailedSecondFactorAttempts,
        SecondFactorLockoutEndUtc = u.SecondFactorLockoutEndUtc,
        TwoFactorEnabled = u.TwoFactorEnabled, PasswordChangeRequired = u.PasswordChangeRequired,
    };
}

/// <summary>A host-registered shared state (in memory – shared between test instances by registering one object).</summary>
public sealed class TestSharedState(TimeProvider time) : ISlimSharedState
{
    private readonly SlimIdentity.Services.SlimMemorySharedState _inner = new(time);

    public Task<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken ct) => _inner.TryAddAsync(key, expiresAt, ct);

    public Task<long> IncrementAsync(string key, TimeSpan window, CancellationToken ct) => _inner.IncrementAsync(key, window, ct);
}

public sealed class TestRefreshTokenStore(TimeProvider time) : ISlimRefreshTokenStore
{
    private readonly ConcurrentDictionary<string, (string UserId, DateTimeOffset ExpiresAt)> _tokens = new();

    public Task StoreRefreshTokenAsync(string userId, string tokenHash, DateTimeOffset expiresAt, CancellationToken ct)
    {
        _tokens[tokenHash] = (userId, expiresAt);
        return Task.CompletedTask;
    }

    public Task<string?> ValidateAndConsumeRefreshTokenAsync(string tokenHash, CancellationToken ct) =>
        Task.FromResult(_tokens.TryRemove(tokenHash, out var t) && t.ExpiresAt > time.GetUtcNow() ? t.UserId : null);
}

public sealed class TestSessionStore : ISlimSessionStore
{
    private readonly ConcurrentDictionary<string, SlimSession> _sessions = new();

    public int Count => _sessions.Count;

    public Task CreateAsync(SlimSession session, CancellationToken ct) { _sessions[session.Id] = session; return Task.CompletedTask; }

    public Task<SlimSession?> FindAsync(string sessionId, CancellationToken ct) =>
        Task.FromResult(_sessions.TryGetValue(sessionId, out var s) ? s : null);

    public Task<IReadOnlyCollection<SlimSession>> ListAsync(string userId, CancellationToken ct) =>
        Task.FromResult<IReadOnlyCollection<SlimSession>>(_sessions.Values.Where(s => s.UserId == userId).ToList());

    public Task TouchAsync(string sessionId, DateTimeOffset lastSeenUtc, DateTimeOffset expiresUtc, CancellationToken ct)
    {
        if (_sessions.TryGetValue(sessionId, out var s)) { s.LastSeenUtc = lastSeenUtc; s.ExpiresUtc = expiresUtc; }
        return Task.CompletedTask;
    }

    public Task RevokeAsync(string sessionId, CancellationToken ct) { _sessions.TryRemove(sessionId, out _); return Task.CompletedTask; }

    public Task RevokeAllAsync(string userId, string? exceptSessionId, CancellationToken ct)
    {
        foreach (var s in _sessions.Values.Where(s => s.UserId == userId && s.Id != exceptSessionId).ToList())
            _sessions.TryRemove(s.Id, out _);
        return Task.CompletedTask;
    }
}

public sealed class TestTwoFactorStore : ISlimTwoFactorStore
{
    private readonly ConcurrentDictionary<string, string> _secrets = new();
    private readonly ConcurrentDictionary<string, HashSet<string>> _recovery = new();
    private readonly ConcurrentDictionary<string, long> _lastCodeUse = new();
    private readonly ConcurrentDictionary<string, long> _lastChallengeUse = new();

    public Task<bool> TryMarkChallengeUsedAsync(SlimUser user, long issuedAt, CancellationToken ct)
    {
        lock (_lastChallengeUse)
        {
            if (_lastChallengeUse.TryGetValue(user.Id, out var last) && last >= issuedAt) return Task.FromResult(false);
            _lastChallengeUse[user.Id] = issuedAt;
            return Task.FromResult(true);
        }
    }

    /// <summary>The value exactly as persisted (tests verify it is encrypted).</summary>
    public string? RawSecret(string userId) => _secrets.TryGetValue(userId, out var s) ? s : null;

    /// <summary>The persisted recovery-code hashes.</summary>
    public IReadOnlyCollection<string> RecoveryHashes(string userId) => _recovery.TryGetValue(userId, out var c) ? c.ToArray() : [];

    public Task<string?> GetTotpSecretAsync(SlimUser user, CancellationToken ct) =>
        Task.FromResult(_secrets.TryGetValue(user.Id, out var s) && s.Length > 0 ? s : null);

    public Task SetTotpSecretAsync(SlimUser user, string protectedSecret, CancellationToken ct) { _secrets[user.Id] = protectedSecret; return Task.CompletedTask; }

    public Task<bool> TryMarkCodeUsedAsync(SlimUser user, long usedAt, CancellationToken ct)
    {
        lock (_lastCodeUse)
        {
            if (_lastCodeUse.TryGetValue(user.Id, out var last) && last >= usedAt) return Task.FromResult(false);
            _lastCodeUse[user.Id] = usedAt;
            return Task.FromResult(true);
        }
    }

    public Task StoreRecoveryCodesAsync(SlimUser user, IEnumerable<string> hashedCodes, CancellationToken ct)
    {
        _recovery[user.Id] = hashedCodes.ToHashSet();
        return Task.CompletedTask;
    }

    public Task<bool> ValidateAndConsumeRecoveryCodeAsync(SlimUser user, string hashedCode, CancellationToken ct)
    {
        if (!_recovery.TryGetValue(user.Id, out var codes)) return Task.FromResult(false);
        lock (codes) return Task.FromResult(codes.Remove(hashedCode));
    }
}

public sealed record SentMail(string Kind, string To, string Payload)
{
    public SlimEmailContext? Context { get; init; }
    /// <summary>The link of a mail that carries a code and a link (registration).</summary>
    public string? Link { get; init; }
}

/// <summary>Records all mails; tests wait for them because most are sent by the background queue.</summary>
public sealed class CapturingEmailSender : ISlimEmailSender
{
    private readonly ConcurrentQueue<SentMail> _mails = new();

    public IReadOnlyCollection<SentMail> Mails => _mails.ToArray();

    public Task SendVerificationEmailAsync(SlimEmailContext context, string email, string code, string link, CancellationToken ct)
    {
        _mails.Enqueue(new SentMail("verification", email, code) { Context = context, Link = link });
        return Task.CompletedTask;
    }
    public Task SendPasswordResetEmailAsync(SlimEmailContext context, string email, string link, CancellationToken ct) => Add(context, "password-reset", email, link);
    public Task SendTwoFactorCodeAsync(SlimEmailContext context, string email, string code, CancellationToken ct) => Add(context, "two-factor", email, code);
    public Task SendEmailVerificationCodeAsync(SlimEmailContext context, string email, string code, CancellationToken ct) => Add(context, "verification-code", email, code);
    public Task SendEmailChangeConfirmationAsync(SlimEmailContext context, string newEmail, string link, CancellationToken ct) => Add(context, "email-change", newEmail, link);
    public Task SendEmailChangedNotificationAsync(SlimEmailContext context, string oldEmail, string newEmail, CancellationToken ct) => Add(context, "email-changed", oldEmail, newEmail);
    public Task SendAccountExistsEmailAsync(SlimEmailContext context, string email, CancellationToken ct) => Add(context, "account-exists", email, "");
    public Task SendLockoutNotificationEmailAsync(SlimEmailContext context, string email, DateTimeOffset lockoutEndUtc, CancellationToken ct) =>
        Add(context, "lockout", email, lockoutEndUtc.ToString("O"));

    private Task Add(SlimEmailContext context, string kind, string to, string payload)
    {
        _mails.Enqueue(new SentMail(kind, to, payload) { Context = context });
        return Task.CompletedTask;
    }

    public async Task<SentMail> WaitForAsync(string kind, string to, TimeSpan? timeout = null)
    {
        var deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(5));
        while (DateTime.UtcNow < deadline)
        {
            if (_mails.LastOrDefault(m => m.Kind == kind && string.Equals(m.To, to, StringComparison.OrdinalIgnoreCase)) is { } mail)
                return mail;
            await Task.Delay(20);
        }
        throw new TimeoutException($"No '{kind}' mail to {to} was sent.");
    }
}
