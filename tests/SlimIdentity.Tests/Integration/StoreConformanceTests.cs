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
            .BuildServiceProvider();

        var report = await SlimStoreConformance.VerifyAsync(services, new SlimConformanceOptions { ApiKey = ValidKey.Key });

        Assert.All(new[] { nameof(ISlimUserStore), nameof(ISlimTwoFactorStore), nameof(ISlimRefreshTokenStore), nameof(ISlimSessionStore), nameof(ISlimExternalLoginStore), nameof(ISlimPasskeyStore), nameof(ISlimApiKeyStore) },
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
        Assert.Contains("fix:", ex.Message);
        Assert.Contains(ex.Report.Results, r => r.Passed);   // the correct parts are still reported as passed
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
            _users[user.Id].PasswordHash = newHash;   // ignores currentHash
            return Task.CompletedTask;
        }

        public Task<SlimEmailUpdateResult> UpdateEmailAsync(SlimUser user, string newEmail, string expectedStamp, string newStamp, CancellationToken ct)
        {
            (_users[user.Id].Email, _users[user.Id].SecurityStamp) = (newEmail, newStamp);   // ignores expectedStamp and other accounts
            return Task.FromResult(SlimEmailUpdateResult.Updated);
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
}
