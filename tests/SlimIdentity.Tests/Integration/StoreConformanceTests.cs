using System.Collections.Concurrent;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Testing;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>SlimIdentity.Testing against the in-memory test stores – and proof that it catches broken stores.</summary>
public sealed class StoreConformanceTests
{
    [Fact]
    public async Task Test_stores_honour_all_contracts()
    {
        await using var services = new ServiceCollection()
            .AddSingleton(TimeProvider.System)
            .AddSingleton<ISlimUserStore, TestUserStore>()
            .AddSingleton<ISlimTwoFactorStore, TestTwoFactorStore>()
            .AddSingleton<ISlimRefreshTokenStore, TestRefreshTokenStore>()
            .AddSingleton<ISlimSessionStore, TestSessionStore>()
            .AddSingleton<ISlimExternalLoginStore, TestExternalLoginStore>()
            .AddSingleton<ISlimPasskeyStore, TestPasskeyStore>()
            .AddSingleton<ISlimApiKeyStore>(new HashedApiKeyStore(ValidKey.Hash))
            .AddSingleton<ISlimSharedState, TestSharedState>()
            .BuildServiceProvider();

        var report = await SlimStoreConformance.VerifyAsync(services, new SlimConformanceOptions { ApiKey = ValidKey.Key });

        Assert.All(new[] { nameof(ISlimUserStore), nameof(ISlimTwoFactorStore), nameof(ISlimRefreshTokenStore), nameof(ISlimSessionStore), nameof(ISlimExternalLoginStore), nameof(ISlimPasskeyStore), nameof(ISlimApiKeyStore), nameof(ISlimSharedState) },
            store => Assert.Contains(report.Results, r => r.Store == store));
    }

    [Fact]
    public async Task A_naive_store_is_reported_with_the_violated_rules()
    {
        await using var services = new ServiceCollection().AddSingleton<ISlimUserStore, NaiveUserStore>().BuildServiceProvider();

        var ex = await Assert.ThrowsAsync<SlimStoreConformanceException>(() => SlimStoreConformance.VerifyAsync(services));
        var failed = ex.Report.Failures.Select(f => f.Rule).ToList();

        Assert.Contains(failed, r => r.Contains("case-insensitively"));
        Assert.Contains(failed, r => r.Contains("taken address"));
        Assert.Contains(failed, r => r.Contains("parallel registrations"));
        Assert.Contains(failed, r => r.Contains("reserves parallel attempts atomically"));
        Assert.Contains(failed, r => r.Contains("separate attempt counters"));
        Assert.Contains(failed, r => r.Contains("never writes the attempt counters"));
        Assert.Contains(failed, r => r.Contains("never overwrites the password hash"));
        Assert.Contains(failed, r => r.Contains("only if the hash is unchanged"));
        Assert.Contains(failed, r => r.Contains("only the stamp and only if it is unchanged"));
        Assert.Contains(failed, r => r.Contains("only while the whole stamp is unchanged"));
        Assert.Contains(failed, r => r.Contains("exactly one wins"));
        Assert.Contains(failed, r => r.Contains("confirmation and stamp in one step"));
        Assert.Contains(failed, r => r.Contains("beyond ASCII"));
        Assert.Contains(failed, r => r.Contains("leaves IsActive and the address alone"));
        Assert.Contains(failed, r => r.Contains("write nothing else"));
        Assert.Contains(failed, r => r.Contains("new spelling of the own address"));
        Assert.Contains(failed, r => r.Contains("parallel e-mail changes"));
        Assert.Contains("fix:", ex.Message);
        Assert.Contains(ex.Report.Results, r => r.Passed);   // the correct parts are still reported as passed
    }

    [Fact]
    public async Task Naive_capability_stores_are_reported_with_the_violated_rules()
    {
        await using var services = new ServiceCollection()
            .AddSingleton(TimeProvider.System)
            .AddSingleton<ISlimUserStore, TestUserStore>()
            .AddSingleton<ISlimTwoFactorStore, NaiveTwoFactorStore>()
            .AddSingleton<ISlimRefreshTokenStore, NaiveRefreshTokenStore>()
            .AddSingleton<ISlimSessionStore, NaiveSessionStore>()
            .AddSingleton<ISlimExternalLoginStore, NaiveExternalLoginStore>()
            .AddSingleton<ISlimPasskeyStore, NaivePasskeyStore>()
            .AddSingleton<ISlimApiKeyStore>(new PrefixApiKeyStore(ValidKey.Hash))
            .AddSingleton<ISlimSharedState, NaiveSharedState>()
            .BuildServiceProvider();

        var ex = await Assert.ThrowsAsync<SlimStoreConformanceException>(() =>
            SlimStoreConformance.VerifyAsync(services, new SlimConformanceOptions { ApiKey = ValidKey.Key }));
        var failed = ex.Report.Failures.Select(f => $"{f.Store}: {f.Rule}").ToList();

        Assert.All(ex.Report.Results.Where(r => r.Store == nameof(ISlimUserStore)), r => Assert.True(r.Passed, r.Rule));
        string[] expected =
        [
            "ISlimTwoFactorStore: a recovery code is accepted once even under parallel requests",
            "ISlimTwoFactorStore: TryMarkCodeUsedAsync accepts a value once even under parallel requests",
            "ISlimTwoFactorStore: TryMarkChallengeUsedAsync accepts a value once even under parallel requests",
            "ISlimTwoFactorStore: codes and challenges are tracked independently",
            "ISlimRefreshTokenStore: expired refresh tokens are not returned",
            "ISlimRefreshTokenStore: a refresh token is consumed once even under parallel requests",
            "ISlimSessionStore: TouchAsync updates last-seen and expiry",
            "ISlimSessionStore: revoked sessions are gone – one, all, or all but the current",
            "ISlimExternalLoginStore: provider keys are compared case-sensitively",
            "ISlimExternalLoginStore: an external identity stays linked to its first user",
            "ISlimExternalLoginStore: RemoveExternalLoginAsync removes exactly one link of its user",
            "ISlimPasskeyStore: a credential id is registered once",
            "ISlimPasskeyStore: TryRecordUseAsync is single use and compare-and-set",
            "ISlimPasskeyStore: a challenge is single use even when the counter stays 0 (synced passkeys)",
            "ISlimApiKeyStore: unknown and malformed key hashes are rejected",
            "ISlimApiKeyStore: a valid key returns its owner – and only for its exact hash",
            "ISlimSharedState: an expired marker counts as absent",
            "ISlimSharedState: a marker is added once even under parallel requests",
            "ISlimSharedState: a counter restarts at 1 after its window",
            "ISlimSharedState: a counter loses no increment under parallel requests",
        ];
        Assert.All(expected, rule => Assert.Contains(rule, failed));
    }

    private static readonly (string Key, string Hash) ValidKey = SlimApiKeys.Generate();

    private sealed class HashedApiKeyStore(string validHash) : ISlimApiKeyStore
    {
        public Task<IReadOnlyCollection<Claim>?> ValidateApiKeyAsync(string keyHash, CancellationToken ct) =>
            Task.FromResult<IReadOnlyCollection<Claim>?>(keyHash == validHash ? [new Claim(SlimClaimTypes.UserId, "client:conformance")] : null);
    }

    /// <summary>
    /// The kind of store that "works" in every manual test: exact-match lookup, check-then-insert, read-modify-write
    /// bookkeeping that writes the whole user back, unconditional rehash.
    /// </summary>
    private sealed class NaiveUserStore : ISlimUserStore
    {
        private readonly ConcurrentDictionary<string, SlimUser> _users = new();

        public Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct) =>
            Task.FromResult(_users.Values.FirstOrDefault(u => u.Email == email) is { } u ? Copy(u) : null);

        public Task<SlimUser?> FindByIdAsync(string userId, CancellationToken ct) =>
            Task.FromResult(_users.TryGetValue(userId, out var u) ? Copy(u) : null);

        public async Task<SlimUser?> CreateAsync(SlimNewUser newUser, CancellationToken ct)
        {
            var (email, passwordHash) = (newUser.Email, newUser.PasswordHash);
            if (await FindByEmailAsync(email, ct) is not null) return null;
            await Task.Delay(5, ct);   // the gap between "check" and "insert"
            var user = new SlimUser { Id = Guid.NewGuid().ToString(), Email = email, PasswordHash = passwordHash };
            _users[user.Id] = user;
            return Copy(user);
        }

        public Task<bool> UpdateSecurityStateAsync(SlimUser user, string expectedStamp, CancellationToken ct)
        {
            var copy = Copy(user);   // ignores expectedStamp
            if (_users.TryGetValue(user.Id, out var existing)) copy.Email = existing.Email;
            _users[user.Id] = copy;
            return Task.FromResult(true);
        }

        public Task<bool> UpdateSecurityStampAsync(SlimUser user, string expectedStamp, string newStamp, CancellationToken ct)
        {
            _users[user.Id].SecurityStamp = newStamp;   // ignores expectedStamp
            return Task.FromResult(true);
        }

        public async Task<SlimAttemptReservation?> TryBeginAttemptAsync(SlimUser user, SlimAttemptRequest attempt, CancellationToken ct)
        {
            var current = (await FindByIdAsync(user.Id, ct))!;
            if (attempt.IsLockedOut(current.LockoutEndUtc)) return SlimAttemptReservation.LockedOut(current.LockoutEndUtc!.Value);
            await Task.Delay(5, ct);
            user.FailedLoginAttempts = current.FailedLoginAttempts + 1;   // one counter for every factor
            user.LockoutEndUtc = attempt.NextLockoutEnd(user.FailedLoginAttempts, current.LockoutEndUtc);
            await UpdateSecurityStateAsync(user, string.Empty, ct);   // writes back the whole (outdated) user
            return SlimAttemptReservation.Reserved(user.FailedLoginAttempts);
        }

        public Task ResetFailedAttemptsAsync(SlimUser user, SlimAttemptFactor factor, CancellationToken ct)
        {
            user.FailedLoginAttempts = 0;
            user.LockoutEndUtc = null;
            return UpdateSecurityStateAsync(user, string.Empty, ct);
        }

        public Task UpdatePasswordHashAsync(SlimUser user, string currentHash, string newHash, CancellationToken ct)
        {
            user.PasswordHash = newHash;   // ignores currentHash
            return UpdateSecurityStateAsync(user, string.Empty, ct);   // writes back the whole (outdated) user
        }

        public async Task<SlimEmailUpdateResult> UpdateEmailAsync(SlimUser user, string newEmail, string expectedStamp, string newStamp, CancellationToken ct)
        {
            // ignores expectedStamp; checks before writing and counts the own row as "taken"
            if (_users.Values.Any(u => string.Equals(u.Email, newEmail, StringComparison.OrdinalIgnoreCase))) return SlimEmailUpdateResult.EmailTaken;
            await Task.Delay(5, ct);
            (_users[user.Id].Email, _users[user.Id].SecurityStamp) = (newEmail, newStamp);
            return SlimEmailUpdateResult.Updated;
        }

        public Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct) =>
            Task.FromResult<IReadOnlyCollection<Claim>>([]);

        private static SlimUser Copy(SlimUser u) => new()
        {
            Id = u.Id, Email = u.Email, PasswordHash = u.PasswordHash, SecurityStamp = u.SecurityStamp, IsActive = u.IsActive,
            EmailConfirmed = u.EmailConfirmed, FailedLoginAttempts = u.FailedLoginAttempts, LockoutEndUtc = u.LockoutEndUtc,
            TwoFactorEnabled = u.TwoFactorEnabled,
        };
    }

    private sealed class PrefixApiKeyStore(string validHash) : ISlimApiKeyStore
    {
        public Task<IReadOnlyCollection<Claim>?> ValidateApiKeyAsync(string keyHash, CancellationToken ct) =>   // LIKE @hash + '%'
            Task.FromResult<IReadOnlyCollection<Claim>?>(validHash.StartsWith(keyHash, StringComparison.Ordinal) ? [new Claim(SlimClaimTypes.UserId, "client:conformance")] : null);
    }

    /// <summary>Check-then-delete recovery codes; one shared, check-then-set column for code and challenge.</summary>
    private sealed class NaiveTwoFactorStore : ISlimTwoFactorStore
    {
        private readonly ConcurrentDictionary<string, string> _secrets = new();
        private readonly ConcurrentDictionary<string, List<string>> _codes = new();
        private readonly ConcurrentDictionary<string, long> _lastUsed = new();

        public Task<string?> GetTotpSecretAsync(SlimUser user, CancellationToken ct) => Task.FromResult(_secrets.TryGetValue(user.Id, out var s) ? s : null);

        public Task SetTotpSecretAsync(SlimUser user, string protectedSecret, CancellationToken ct)
        {
            if (protectedSecret.Length == 0) _secrets.TryRemove(user.Id, out _);
            else _secrets[user.Id] = protectedSecret;
            return Task.CompletedTask;
        }

        public Task StoreRecoveryCodesAsync(SlimUser user, IEnumerable<string> hashedCodes, CancellationToken ct)
        {
            _codes[user.Id] = hashedCodes.ToList();
            return Task.CompletedTask;
        }

        public async Task<bool> ValidateAndConsumeRecoveryCodeAsync(SlimUser user, string hashedCode, CancellationToken ct)
        {
            if (!_codes.TryGetValue(user.Id, out var codes) || !codes.Contains(hashedCode)) return false;
            await Task.Delay(5, ct);
            lock (codes) codes.Remove(hashedCode);
            return true;
        }

        public Task<bool> TryMarkCodeUsedAsync(SlimUser user, long usedAt, CancellationToken ct) => MarkAsync(user, usedAt, ct);

        public Task<bool> TryMarkChallengeUsedAsync(SlimUser user, long issuedAt, CancellationToken ct) => MarkAsync(user, issuedAt, ct);

        private async Task<bool> MarkAsync(SlimUser user, long value, CancellationToken ct)
        {
            if (_lastUsed.TryGetValue(user.Id, out var last) && last >= value) return false;
            await Task.Delay(5, ct);
            _lastUsed[user.Id] = value;
            return true;
        }
    }

    /// <summary>No expiry check; check-then-delete.</summary>
    private sealed class NaiveRefreshTokenStore : ISlimRefreshTokenStore
    {
        private readonly ConcurrentDictionary<string, string> _tokens = new();

        public Task StoreRefreshTokenAsync(string userId, string tokenHash, DateTimeOffset expiresAt, CancellationToken ct)
        {
            _tokens[tokenHash] = userId;
            return Task.CompletedTask;
        }

        public async Task<string?> ValidateAndConsumeRefreshTokenAsync(string tokenHash, CancellationToken ct)
        {
            if (!_tokens.TryGetValue(tokenHash, out var userId)) return null;
            await Task.Delay(5, ct);
            _tokens.TryRemove(tokenHash, out _);
            return userId;
        }
    }

    /// <summary>No expiry; check-then-insert and read-add-write.</summary>
    private sealed class NaiveSharedState : ISlimSharedState
    {
        private readonly ConcurrentDictionary<string, long> _entries = new();

        public async Task<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken ct)
        {
            if (_entries.ContainsKey(key)) return false;
            await Task.Delay(5, ct);
            _entries[key] = 0;
            return true;
        }

        public async Task<long> IncrementAsync(string key, TimeSpan window, CancellationToken ct)
        {
            var count = _entries.GetValueOrDefault(key) + 1;
            await Task.Delay(5, ct);
            _entries[key] = count;
            return count;
        }
    }

    /// <summary>TouchAsync upserts; RevokeAllAsync ignores the excepted session.</summary>
    private sealed class NaiveSessionStore : ISlimSessionStore
    {
        private readonly ConcurrentDictionary<string, SlimSession> _sessions = new();
        private readonly ConcurrentDictionary<string, SlimSession> _ever = new();

        public Task CreateAsync(SlimSession session, CancellationToken ct)
        {
            _sessions[session.Id] = _ever[session.Id] = session;
            return Task.CompletedTask;
        }

        public Task<SlimSession?> FindAsync(string sessionId, CancellationToken ct) => Task.FromResult(_sessions.TryGetValue(sessionId, out var s) ? s : null);

        public Task<IReadOnlyCollection<SlimSession>> ListAsync(string userId, CancellationToken ct) =>
            Task.FromResult<IReadOnlyCollection<SlimSession>>(_sessions.Values.Where(s => s.UserId == userId).ToList());

        public Task TouchAsync(string sessionId, DateTimeOffset lastSeenUtc, DateTimeOffset expiresUtc, CancellationToken ct)
        {
            var session = _ever[sessionId];
            session.LastSeenUtc = lastSeenUtc;
            session.ExpiresUtc = expiresUtc;
            _sessions[sessionId] = session;
            return Task.CompletedTask;
        }

        public Task RevokeAsync(string sessionId, CancellationToken ct)
        {
            _sessions.TryRemove(sessionId, out _);
            return Task.CompletedTask;
        }

        public Task RevokeAllAsync(string userId, string? exceptSessionId, CancellationToken ct)
        {
            foreach (var s in _sessions.Values.Where(s => s.UserId == userId).ToList()) _sessions.TryRemove(s.Id, out _);
            return Task.CompletedTask;
        }
    }

    /// <summary>Case-insensitive keys (like SQL Server's default collation); linking upserts.</summary>
    private sealed class NaiveExternalLoginStore(ISlimUserStore users) : ISlimExternalLoginStore
    {
        private readonly ConcurrentDictionary<string, (string UserId, string Provider, string Key)> _links = new(StringComparer.OrdinalIgnoreCase);

        public async Task<SlimUser?> FindByExternalLoginAsync(string provider, string providerKey, CancellationToken ct) =>
            _links.TryGetValue($"{provider}|{providerKey}", out var link) ? await users.FindByIdAsync(link.UserId, ct) : null;

        public Task LinkExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct)
        {
            _links[$"{provider}|{providerKey}"] = (userId, provider, providerKey);
            return Task.CompletedTask;
        }

        public Task RemoveExternalLoginsAsync(string userId, CancellationToken ct)
        {
            foreach (var l in _links.Where(l => l.Value.UserId == userId).ToList()) _links.TryRemove(l.Key, out _);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<SlimExternalLogin>> GetExternalLoginsAsync(string userId, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<SlimExternalLogin>>(_links.Values.Where(l => l.UserId == userId).Select(l => new SlimExternalLogin(l.Provider, l.Key)).ToList());

        public Task<bool> RemoveExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct) =>
            Task.FromResult(_links.TryRemove($"{provider}|{providerKey}", out _));   // ignores the owner
    }

    /// <summary>Check-then-insert; TryRecordUseAsync reads, waits and writes without a challenge check.</summary>
    private sealed class NaivePasskeyStore : ISlimPasskeyStore
    {
        private readonly ConcurrentDictionary<string, SlimPasskey> _keys = new();
        private static string Key(byte[] id) => Convert.ToHexString(id);

        public Task<IReadOnlyList<SlimPasskey>> GetPasskeysAsync(string userId, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<SlimPasskey>>(_keys.Values.Where(p => p.UserId == userId).ToList());

        public Task<SlimPasskey?> FindPasskeyAsync(byte[] credentialId, CancellationToken ct) =>
            Task.FromResult(_keys.TryGetValue(Key(credentialId), out var p) ? p : null);

        public async Task<bool> AddPasskeyAsync(SlimPasskey passkey, CancellationToken ct)
        {
            if (_keys.ContainsKey(Key(passkey.CredentialId))) return false;
            await Task.Delay(5, ct);
            _keys[Key(passkey.CredentialId)] = passkey;
            return true;
        }

        public async Task<bool> TryRecordUseAsync(byte[] credentialId, uint expectedSignCount, uint signCount, long challengeIssuedAt, DateTimeOffset usedUtc, bool backedUp, CancellationToken ct)
        {
            if (!_keys.TryGetValue(Key(credentialId), out var p) || p.SignCount != expectedSignCount) return false;
            await Task.Delay(5, ct);
            (p.SignCount, p.LastChallengeAt, p.LastUsedUtc, p.BackedUp) = (signCount, challengeIssuedAt, usedUtc, backedUp);
            return true;
        }

        public Task<bool> RenamePasskeyAsync(string userId, byte[] credentialId, string name, CancellationToken ct)
        {
            if (!_keys.TryGetValue(Key(credentialId), out var p) || p.UserId != userId) return Task.FromResult(false);
            p.Name = name;
            return Task.FromResult(true);
        }

        public Task RemovePasskeysAsync(string userId, CancellationToken ct)
        {
            foreach (var (id, p) in _keys) if (p.UserId == userId) _keys.TryRemove(id, out _);
            return Task.CompletedTask;
        }

        public Task<bool> RemovePasskeyAsync(string userId, byte[] credentialId, CancellationToken ct) =>
            Task.FromResult(_keys.TryGetValue(Key(credentialId), out var p) && p.UserId == userId && _keys.TryRemove(Key(credentialId), out _));
    }
}
