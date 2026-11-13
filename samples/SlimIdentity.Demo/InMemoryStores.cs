using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using SlimIdentity;
using SlimIdentity.Security;

namespace SlimIdentity.Demo;

/// <summary>
/// Demo persistence – everything lives in memory and is lost on restart.
/// For real projects see /samples (EF Core, Dapper).
/// </summary>
public sealed class InMemoryUserStore : ISlimUserStore
{
    private readonly ConcurrentDictionary<string, SlimUser> _users = new();
    private readonly ConcurrentDictionary<string, string[]> _roles = new();

    public InMemoryUserStore(DemoSettings settings)
    {
        var hasher = new PasswordHasher<SlimUser>();
        Seed(hasher, "admin@demo.local", settings.AdminPassword, ["Admin"]);
        Seed(hasher, "user@demo.local", settings.UserPassword, []);
    }

    private void Seed(PasswordHasher<SlimUser> hasher, string email, string password, string[] roles)
    {
        var user = new SlimUser { Id = Guid.NewGuid().ToString(), Email = email, EmailConfirmed = true };
        user.PasswordHash = hasher.HashPassword(user, password);
        _users[user.Id] = user;
        _roles[user.Id] = roles;
    }

    public IEnumerable<SlimUser> All => _users.Values.Select(Clone);

    public Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct) =>
        Task.FromResult(_users.Values.FirstOrDefault(u => string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase)) is { } u ? Clone(u) : null);

    public Task<SlimUser?> FindByIdAsync(string userId, CancellationToken ct) =>
        Task.FromResult(_users.TryGetValue(userId, out var u) ? Clone(u) : null);

    public Task<SlimUser?> CreateAsync(SlimNewUser newUser, CancellationToken ct)
    {
        var (email, passwordHash) = (newUser.Email, newUser.PasswordHash);
        lock (_users)
        {
            // "unique index": null if the address is taken (e.g. by a concurrent registration)
            if (_users.Values.Any(u => string.Equals(u.Email, email, StringComparison.OrdinalIgnoreCase)))
                return Task.FromResult<SlimUser?>(null);
            var user = new SlimUser { Id = Guid.NewGuid().ToString(), Email = email, PasswordHash = passwordHash };
            _users[user.Id] = user;
            _roles[user.Id] = [];
            return Task.FromResult<SlimUser?>(Clone(user));
        }
    }

    // sign-in bookkeeping: reserve an attempt atomically before it is checked (never write back a whole, possibly outdated user)
    public Task<SlimAttemptReservation?> TryBeginAttemptAsync(SlimUser user, SlimAttemptRequest attempt, CancellationToken ct)
    {
        if (!_users.TryGetValue(user.Id, out var stored)) return Task.FromResult<SlimAttemptReservation?>(null);
        lock (stored)
        {
            var password = attempt.Factor == SlimAttemptFactor.Password;
            var end = password ? stored.LockoutEndUtc : stored.SecondFactorLockoutEndUtc;
            if (attempt.IsLockedOut(end)) return Task.FromResult<SlimAttemptReservation?>(SlimAttemptReservation.LockedOut(end!.Value));
            var count = (password ? stored.FailedLoginAttempts : stored.FailedSecondFactorAttempts) + 1;
            var newEnd = attempt.NextLockoutEnd(count, end);
            if (password) (stored.FailedLoginAttempts, stored.LockoutEndUtc) = (count, newEnd);
            else (stored.FailedSecondFactorAttempts, stored.SecondFactorLockoutEndUtc) = (count, newEnd);
            return Task.FromResult<SlimAttemptReservation?>(SlimAttemptReservation.Reserved(count));
        }
    }

    public Task ResetFailedAttemptsAsync(SlimUser user, SlimAttemptFactor factor, CancellationToken ct)
    {
        var stored = _users[user.Id];
        lock (stored)
        {
            if (factor == SlimAttemptFactor.Password) (stored.FailedLoginAttempts, stored.LockoutEndUtc) = (0, null);
            else (stored.FailedSecondFactorAttempts, stored.SecondFactorLockoutEndUtc) = (0, null);
        }
        return Task.CompletedTask;
    }

    public Task UpdatePasswordHashAsync(SlimUser user, string currentHash, string newHash, CancellationToken ct)
    {
        var stored = _users[user.Id];
        lock (stored) if (stored.PasswordHash == currentHash) stored.PasswordHash = newHash;
        return Task.CompletedTask;
    }

    // persists the security fields only, and only while the stamp is unchanged (contract of ISlimUserStore)
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

    // compare-and-set on the stamp only (contract of ISlimUserStore)
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

    public Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct)
    {
        var claims = new List<Claim> { new("tenant_id", "demo") };
        if (_roles.TryGetValue(user.Id, out var roles))
            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));
        return Task.FromResult<IReadOnlyCollection<Claim>>(claims);
    }

    /// <summary>Demo admin helper: ban / unban.</summary>
    public void SetActive(string userId, bool active)
    {
        if (_users.TryGetValue(userId, out var u)) { u.IsActive = active; u.SecurityStamp = SlimUser.NewSecurityStamp(); }
    }

    private static SlimUser Clone(SlimUser u) => new()
    {
        Id = u.Id, Email = u.Email, PasswordHash = u.PasswordHash, SecurityStamp = u.SecurityStamp,
        IsActive = u.IsActive, EmailConfirmed = u.EmailConfirmed, FailedLoginAttempts = u.FailedLoginAttempts,
        LockoutEndUtc = u.LockoutEndUtc, FailedSecondFactorAttempts = u.FailedSecondFactorAttempts,
        SecondFactorLockoutEndUtc = u.SecondFactorLockoutEndUtc,
        TwoFactorEnabled = u.TwoFactorEnabled, PasswordChangeRequired = u.PasswordChangeRequired,
    };
}

public sealed class InMemoryRefreshTokenStore(TimeProvider time) : ISlimRefreshTokenStore
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

public sealed class InMemoryTwoFactorStore : ISlimTwoFactorStore
{
    private readonly ConcurrentDictionary<string, string> _secrets = new();   // encrypted by SlimIdentity
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

    public Task<string?> GetTotpSecretAsync(SlimUser user, CancellationToken ct) =>
        Task.FromResult(_secrets.TryGetValue(user.Id, out var s) && s.Length > 0 ? s : null);

    public Task SetTotpSecretAsync(SlimUser user, string protectedSecret, CancellationToken ct)
    {
        _secrets[user.Id] = protectedSecret;
        return Task.CompletedTask;
    }

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

public sealed class InMemoryExternalLoginStore(ISlimUserStore users) : ISlimExternalLoginStore
{
    private readonly ConcurrentDictionary<(string Provider, string Key), string> _links = new();

    public async Task<SlimUser?> FindByExternalLoginAsync(string provider, string providerKey, CancellationToken ct) =>
        _links.TryGetValue((provider, providerKey), out var userId) ? await users.FindByIdAsync(userId, ct) : null;

    public Task LinkExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct)
    {
        // unique per provider + key, like a unique index: a taken identity is never moved to another account
        if (!_links.TryAdd((provider, providerKey), userId) && _links[(provider, providerKey)] != userId)
            throw new InvalidOperationException("This external identity is already linked to another account.");
        return Task.CompletedTask;
    }

    public Task RemoveExternalLoginsAsync(string userId, CancellationToken ct)
    {
        foreach (var link in _links.Where(l => l.Value == userId).ToList()) _links.TryRemove(link.Key, out _);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<SlimExternalLogin>> GetExternalLoginsAsync(string userId, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<SlimExternalLogin>>(_links.Where(l => l.Value == userId)
            .Select(l => new SlimExternalLogin(l.Key.Item1, l.Key.Item2))
            .OrderBy(l => l.Provider, StringComparer.Ordinal).ThenBy(l => l.ProviderKey, StringComparer.Ordinal).ToList());

    public Task<bool> RemoveExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct) =>
        Task.FromResult(((ICollection<KeyValuePair<(string, string), string>>)_links)
            .Remove(new KeyValuePair<(string, string), string>((provider, providerKey), userId)));
}

public sealed class InMemorySessionStore : ISlimSessionStore
{
    private readonly ConcurrentDictionary<string, SlimSession> _sessions = new();

    public Task CreateAsync(SlimSession session, CancellationToken ct)
    {
        _sessions[session.Id] = session;
        return Task.CompletedTask;
    }

    public Task<SlimSession?> FindAsync(string sessionId, CancellationToken ct) =>
        Task.FromResult(_sessions.TryGetValue(sessionId, out var s) ? s : null);

    public Task<IReadOnlyCollection<SlimSession>> ListAsync(string userId, CancellationToken ct) =>
        Task.FromResult<IReadOnlyCollection<SlimSession>>(_sessions.Values.Where(s => s.UserId == userId).ToList());

    public Task TouchAsync(string sessionId, DateTimeOffset lastSeenUtc, DateTimeOffset expiresUtc, CancellationToken ct)
    {
        if (_sessions.TryGetValue(sessionId, out var s)) { s.LastSeenUtc = lastSeenUtc; s.ExpiresUtc = expiresUtc; }
        return Task.CompletedTask;
    }

    public Task RevokeAsync(string sessionId, CancellationToken ct)
    {
        _sessions.TryRemove(sessionId, out _);
        return Task.CompletedTask;
    }

    public Task RevokeAllAsync(string userId, string? exceptSessionId, CancellationToken ct)
    {
        foreach (var s in _sessions.Values.Where(s => s.UserId == userId && s.Id != exceptSessionId).ToList())
            _sessions.TryRemove(s.Id, out _);
        return Task.CompletedTask;
    }
}

/// <summary>One demo key: <c>X-API-Key: demo-key-123</c>.</summary>
/// <summary>Passkeys in memory – atomic where the contract demands it (unique ids, single use per challenge).</summary>
public sealed class InMemoryPasskeyStore : ISlimPasskeyStore
{
    private readonly ConcurrentDictionary<string, SlimPasskey> _keys = new(StringComparer.Ordinal);
    private static string Key(byte[] credentialId) => Convert.ToHexString(credentialId);

    public Task<IReadOnlyList<SlimPasskey>> GetPasskeysAsync(string userId, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<SlimPasskey>>([.. _keys.Values.Where(p => p.UserId == userId).OrderBy(p => p.CreatedUtc).Select(Copy)]);

    public Task<SlimPasskey?> FindPasskeyAsync(byte[] credentialId, CancellationToken ct) =>
        Task.FromResult(_keys.TryGetValue(Key(credentialId), out var p) ? Copy(p) : null);

    public Task<bool> AddPasskeyAsync(SlimPasskey passkey, CancellationToken ct) =>
        Task.FromResult(_keys.TryAdd(Key(passkey.CredentialId), Copy(passkey)));

    public Task<bool> TryRecordUseAsync(byte[] credentialId, uint expectedSignCount, uint signCount, long challengeIssuedAt,
        DateTimeOffset usedUtc, bool backedUp, CancellationToken ct)
    {
        if (!_keys.TryGetValue(Key(credentialId), out var p)) return Task.FromResult(false);
        lock (p)
        {
            if (p.SignCount != expectedSignCount || p.LastChallengeAt >= challengeIssuedAt) return Task.FromResult(false);
            (p.SignCount, p.LastChallengeAt, p.LastUsedUtc, p.BackedUp) = (signCount, challengeIssuedAt, usedUtc, backedUp);
            return Task.FromResult(true);
        }
    }

    public Task<bool> RenamePasskeyAsync(string userId, byte[] credentialId, string name, CancellationToken ct)
    {
        if (!_keys.TryGetValue(Key(credentialId), out var p) || p.UserId != userId) return Task.FromResult(false);
        lock (p) p.Name = name;
        return Task.FromResult(true);
    }

    public Task<bool> RemovePasskeyAsync(string userId, byte[] credentialId, CancellationToken ct) =>
        Task.FromResult(_keys.TryGetValue(Key(credentialId), out var p) && p.UserId == userId
            && _keys.TryRemove(new KeyValuePair<string, SlimPasskey>(Key(credentialId), p)));

    public Task RemovePasskeysAsync(string userId, CancellationToken ct)
    {
        foreach (var (key, p) in _keys)
            if (p.UserId == userId) _keys.TryRemove(key, out _);
        return Task.CompletedTask;
    }

    private static SlimPasskey Copy(SlimPasskey p) => new()
    {
        UserId = p.UserId, CredentialId = p.CredentialId, PublicKey = p.PublicKey, SignCount = p.SignCount,
        UserHandle = p.UserHandle, BackupEligible = p.BackupEligible, BackedUp = p.BackedUp, LastChallengeAt = p.LastChallengeAt, Name = p.Name,
        CreatedUtc = p.CreatedUtc, LastUsedUtc = p.LastUsedUtc,
    };
}

public sealed class InMemoryApiKeyStore : ISlimApiKeyStore
{
    private static readonly string DemoKeyHash = SlimApiKeys.Hash("demo-key-123");

    public Task<IReadOnlyCollection<Claim>?> ValidateApiKeyAsync(string keyHash, CancellationToken ct) =>
        Task.FromResult<IReadOnlyCollection<Claim>?>(keyHash == DemoKeyHash
            ? new[] { new Claim(SlimClaimTypes.UserId, "client:reporting-service"), new Claim(SlimClaimTypes.Role, "M2M") }
            : null);
}

/// <summary>Prints mails to the console and drops them into the playground's fake mailbox.</summary>
public sealed class ConsoleEmailSender(DemoMailbox mailbox) : ISlimEmailSender
{
    public Task SendVerificationEmailAsync(SlimEmailContext context, string email, string verificationTokenOrLink, CancellationToken ct) =>
        Write("Verify your e-mail", email, verificationTokenOrLink);

    public Task SendPasswordResetEmailAsync(SlimEmailContext context, string email, string resetTokenOrLink, CancellationToken ct) =>
        Write("Reset your password", email, resetTokenOrLink);

    public Task SendTwoFactorCodeAsync(SlimEmailContext context, string email, string code, CancellationToken ct) =>
        Write("Your sign-in code", email, code);

    public Task SendEmailChangeConfirmationAsync(SlimEmailContext context, string newEmail, string confirmationTokenOrLink, CancellationToken ct) =>
        Write("Confirm your new e-mail address", newEmail, confirmationTokenOrLink);

    public Task SendEmailChangedNotificationAsync(SlimEmailContext context, string oldEmail, string newEmail, CancellationToken ct) =>
        Write("Your e-mail address was changed", oldEmail, $"The sign-in address of your account is now {newEmail}. Not you? Contact support.");

    public Task SendAccountExistsEmailAsync(SlimEmailContext context, string email, CancellationToken ct) =>
        Write("You already have an account", email, "Someone tried to register with your address. Forgot your password? Use /auth/forgot-password.");

    public Task SendLockoutNotificationEmailAsync(SlimEmailContext context, string email, DateTimeOffset lockoutEndUtc, CancellationToken ct) =>
        Write("Your account was temporarily locked", email, $"Too many failed sign-ins. Locked until {lockoutEndUtc:u}. Not you? Change your password.");

    private Task Write(string subject, string to, string body)
    {
        mailbox.Deliver(to, subject, body);
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"""

            ===== MAIL ==========================================
            To:      {to}
            Subject: {subject}
            {body}
            =====================================================
            """);
        Console.ResetColor();
        return Task.CompletedTask;
    }
}
