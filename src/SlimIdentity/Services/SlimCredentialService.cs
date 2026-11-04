using Microsoft.AspNetCore.Identity;
using SlimIdentity.Abstractions;

namespace SlimIdentity.Services;

internal enum SlimPasswordCheck { Failed, Success, SuccessRehashNeeded }

/// <summary>
/// Password verification (PasswordHasher or <see cref="ISlimCustomPasswordValidator"/>), timing-attack
/// mitigation via dummy hashing, lockout bookkeeping and transparent rehashing.
/// </summary>
internal sealed class SlimCredentialService(
    IPasswordHasher<SlimUser> hasher,
    ISlimUserStore store,
    IOptions<SlimIdentityOptions> options,
    TimeProvider time,
    IServiceProvider services,
    ILogger<SlimCredentialService> logger)
{
    private static readonly SlimUser DummyUser = new() { Id = "slim-dummy", Email = "dummy@invalid" };
    private static string? s_dummyHash;

    public string HashPassword(SlimUser user, string password) => hasher.HashPassword(user, password);

    /// <summary>Burns the same CPU time as a real verification (unknown user, register with existing e-mail, …).</summary>
    public void BurnDummyHash(string? password)
    {
        s_dummyHash ??= hasher.HashPassword(DummyUser, Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)));
        hasher.VerifyHashedPassword(DummyUser, s_dummyHash, password ?? string.Empty);
    }

    public async Task<SlimPasswordCheck> VerifyPasswordAsync(SlimUser user, string? password, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(password) || password.Length > options.Value.Password.MaximumLength)
            return SlimPasswordCheck.Failed;

        var custom = services.GetService<ISlimCustomPasswordValidator>();
        if (custom is not null)
            return await custom.ValidateAsync(user, password, ct) ? SlimPasswordCheck.Success : SlimPasswordCheck.Failed;

        if (string.IsNullOrEmpty(user.PasswordHash))
        {
            BurnDummyHash(password); // external-only user: keep timing constant
            return SlimPasswordCheck.Failed;
        }

        try
        {
            return hasher.VerifyHashedPassword(user, user.PasswordHash, password) switch
            {
                PasswordVerificationResult.Success => SlimPasswordCheck.Success,
                PasswordVerificationResult.SuccessRehashNeeded => SlimPasswordCheck.SuccessRehashNeeded,
                _ => SlimPasswordCheck.Failed,
            };
        }
        catch (FormatException ex)
        {
            logger.LogWarning(ex, "SlimIdentity: stored password hash of user {UserId} is malformed.", user.Id);
            return SlimPasswordCheck.Failed;
        }
    }

    /// <summary>Counts a failed attempt. Returns true if the account is now locked.</summary>
    public async Task<bool> RegisterFailureAsync(SlimUser user, CancellationToken ct)
    {
        var lockout = options.Value.Lockout;
        if (!lockout.Enabled) return false;

        user.FailedLoginAttempts++;
        var locked = false;
        if (user.FailedLoginAttempts >= lockout.MaxFailedAttempts)
        {
            user.LockoutEndUtc = time.GetUtcNow() + lockout.Duration;
            user.FailedLoginAttempts = 0;
            locked = true;
            logger.LogWarning("SlimIdentity: user {UserId} locked out until {LockoutEnd}.", user.Id, user.LockoutEndUtc);
        }
        await store.UpdateSecurityStateAsync(user, ct);
        return locked;
    }

    /// <summary>
    /// Resets lockout counters (unless <paramref name="resetLockout"/> is false) and rehashes outdated hashes.
    /// </summary>
    public async Task RegisterSuccessAsync(SlimUser user, string? password, bool rehash, bool resetLockout, CancellationToken ct)
    {
        var dirty = false;
        if (resetLockout && (user.FailedLoginAttempts != 0 || user.LockoutEndUtc is not null))
        {
            user.FailedLoginAttempts = 0;
            user.LockoutEndUtc = null;
            dirty = true;
        }
        if (rehash && !string.IsNullOrEmpty(password))
        {
            user.PasswordHash = hasher.HashPassword(user, password);
            dirty = true;
            logger.LogInformation("SlimIdentity: password hash of user {UserId} upgraded.", user.Id);
        }
        if (dirty) await store.UpdateSecurityStateAsync(user, ct);
    }

    /// <summary>Sets a new password, rotates the stamp and clears lockout state (does not persist).</summary>
    public void ApplyNewPassword(SlimUser user, string newPassword)
    {
        user.PasswordHash = hasher.HashPassword(user, newPassword);
        user.SecurityStamp = SlimUser.NewSecurityStamp();
        user.FailedLoginAttempts = 0;
        user.LockoutEndUtc = null;
    }
}
