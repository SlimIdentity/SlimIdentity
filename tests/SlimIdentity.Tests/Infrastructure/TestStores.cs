using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace SlimIdentity.Tests.Infrastructure;

public sealed class TestUserStore : ISlimUserStore
{
    private readonly ConcurrentDictionary<string, SlimUser> _users = new();
    private readonly ConcurrentDictionary<string, string[]> _roles = new();

    public SlimUser Seed(string email, string? password, params string[] roles)
    {
        var user = new SlimUser { Id = Guid.NewGuid().ToString(), Email = email, EmailConfirmed = true };
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

    /// <summary>Called by <see cref="IncrementFailedLoginAttemptsAsync"/> before it counts (race simulation).</summary>
    public Action<string>? BeforeFailedAttempt { get; set; }

    public Task<SlimUser?> CreateAsync(string email, string passwordHash, CancellationToken ct)
    {
        BeforeCreate?.Invoke(email);
        lock (_users)
        {
            // unique index on the e-mail address
            if (_users.Values.Any(u => string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase)))
                return Task.FromResult<SlimUser?>(null);
            var user = new SlimUser { Id = Guid.NewGuid().ToString(), Email = email, PasswordHash = passwordHash };
            _users[user.Id] = user;
            _roles[user.Id] = [];
            return Task.FromResult<SlimUser?>(Clone(user));
        }
    }

    public Task<int> IncrementFailedLoginAttemptsAsync(SlimUser user, CancellationToken ct)
    {
        BeforeFailedAttempt?.Invoke(user.Id);
        var stored = _users[user.Id];
        lock (stored) return Task.FromResult(++stored.FailedLoginAttempts);
    }

    public Task SetLockoutEndAsync(SlimUser user, DateTimeOffset? lockoutEndUtc, CancellationToken ct)
    {
        var stored = _users[user.Id];
        lock (stored) stored.LockoutEndUtc = lockoutEndUtc;
        return Task.CompletedTask;
    }

    public Task ResetFailedLoginAttemptsAsync(SlimUser user, CancellationToken ct)
    {
        var stored = _users[user.Id];
        lock (stored) { stored.FailedLoginAttempts = 0; stored.LockoutEndUtc = null; }
        return Task.CompletedTask;
    }

    public Task UpdatePasswordHashAsync(SlimUser user, string currentHash, string newHash, CancellationToken ct)
    {
        var stored = _users[user.Id];
        lock (stored) if (stored.PasswordHash == currentHash) stored.PasswordHash = newHash;
        return Task.CompletedTask;
    }

    public Task UpdateSecurityStateAsync(SlimUser user, CancellationToken ct)
    {
        var stored = _users[user.Id];
        stored.PasswordHash = user.PasswordHash;
        stored.SecurityStamp = user.SecurityStamp;
        stored.EmailConfirmed = user.EmailConfirmed;
        stored.FailedLoginAttempts = user.FailedLoginAttempts;
        stored.LockoutEndUtc = user.LockoutEndUtc;
        stored.TwoFactorEnabled = user.TwoFactorEnabled;
        return Task.CompletedTask;
    }

    public Task<bool> UpdateEmailAsync(SlimUser user, string newEmail, CancellationToken ct)
    {
        lock (_users)
        {
            if (_users.Values.Any(u => u.Id != user.Id && string.Equals(u.Email, newEmail, StringComparison.OrdinalIgnoreCase)))
                return Task.FromResult(false);
            _users[user.Id].Email = newEmail;
            return Task.FromResult(true);
        }
    }

    public Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct) =>
        Task.FromResult<IReadOnlyCollection<Claim>>(
            (_roles.TryGetValue(user.Id, out var roles) ? roles : []).Select(r => new Claim(ClaimTypes.Role, r)).ToList());

    private static SlimUser Clone(SlimUser u) => new()
    {
        Id = u.Id, Email = u.Email, PasswordHash = u.PasswordHash, SecurityStamp = u.SecurityStamp,
        IsActive = u.IsActive, EmailConfirmed = u.EmailConfirmed, FailedLoginAttempts = u.FailedLoginAttempts,
        LockoutEndUtc = u.LockoutEndUtc, TwoFactorEnabled = u.TwoFactorEnabled,
    };
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

public sealed record SentMail(string Kind, string To, string Payload);

/// <summary>Records all mails; tests wait for them because most are sent by the background queue.</summary>
public sealed class CapturingEmailSender : ISlimEmailSender
{
    private readonly ConcurrentQueue<SentMail> _mails = new();

    public IReadOnlyCollection<SentMail> Mails => _mails.ToArray();

    public Task SendVerificationEmailAsync(string email, string link, CancellationToken ct) => Add("verification", email, link);
    public Task SendPasswordResetEmailAsync(string email, string link, CancellationToken ct) => Add("password-reset", email, link);
    public Task SendTwoFactorCodeAsync(string email, string code, CancellationToken ct) => Add("two-factor", email, code);
    public Task SendEmailChangeConfirmationAsync(string newEmail, string link, CancellationToken ct) => Add("email-change", newEmail, link);
    public Task SendEmailChangedNotificationAsync(string oldEmail, string newEmail, CancellationToken ct) => Add("email-changed", oldEmail, newEmail);
    public Task SendAccountExistsEmailAsync(string email, CancellationToken ct) => Add("account-exists", email, "");
    public Task SendLockoutNotificationEmailAsync(string email, DateTimeOffset lockoutEndUtc, CancellationToken ct) =>
        Add("lockout", email, lockoutEndUtc.ToString("O"));

    private Task Add(string kind, string to, string payload)
    {
        _mails.Enqueue(new SentMail(kind, to, payload));
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
