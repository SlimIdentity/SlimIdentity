using Microsoft.AspNetCore.Identity;

namespace SlimIdentity.Services;

internal enum SlimPasswordCheck { Failed, Success, SuccessRehashNeeded }

/// <summary>
/// Password verification (PasswordHasher or <see cref="ISlimCustomPasswordValidator"/>), timing-attack
/// mitigation via dummy hashing, lockout bookkeeping and transparent rehashing.
/// </summary>
internal sealed class SlimCredentialService(
    IPasswordHasher<SlimUser> hasher,
    ISlimUserStore store,
    SlimEmailDispatcher mail,
    SlimMetrics metrics,
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
            Log.MalformedPasswordHash(logger, ex, user.Id);
            return SlimPasswordCheck.Failed;
        }
    }

    /// <summary>
    /// Re-confirms the password of an authenticated user (2FA changes, e-mail change, …) with lockout bookkeeping.
    /// Returns <c>null</c> on success, otherwise the error result (423 or 400 <c>invalid_password</c>).
    /// </summary>
    public async Task<IResult?> ConfirmPasswordAsync(SlimUser user, string? password, HttpContext http, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        if (user.IsLockedOut(now)) return Http.SlimResults.Locked(http, user.LockoutEndUtc!.Value, now);

        if (await VerifyPasswordAsync(user, password, ct) != SlimPasswordCheck.Failed) return null;

        var locked = await RegisterFailureAsync(user, ct);
        return locked
            ? Http.SlimResults.Locked(http, user.LockoutEndUtc!.Value, now)
            : Http.SlimResults.BadRequest("invalid_password", "The password is incorrect.");
    }

    /// <summary>
    /// Counts a failed attempt. Every <c>MaxFailedAttempts</c> consecutive failures lock the account; the duration
    /// doubles with each lockout (<c>Duration</c>, 2×, 4×, … up to <c>MaxDuration</c>). The counter is only reset by
    /// a successful sign-in. Returns true if the account is now locked.
    /// </summary>
    public async Task<bool> RegisterFailureAsync(SlimUser user, CancellationToken ct)
    {
        var lockout = options.Value.Lockout;
        if (lockout.MaxFailedAttempts == 0) return false;   // lockout disabled

        // atomic in the store: parallel failures are all counted, and exactly one of them reaches the next multiple
        user.FailedLoginAttempts = await store.IncrementFailedLoginAttemptsAsync(user, ct);
        if (user.FailedLoginAttempts <= 0 || user.FailedLoginAttempts % lockout.MaxFailedAttempts != 0) return false;

        var lockoutNumber = user.FailedLoginAttempts / lockout.MaxFailedAttempts; // 1, 2, 3, …
        var duration = LockoutDuration(lockout, lockoutNumber);
        user.LockoutEndUtc = time.GetUtcNow() + duration;
        await store.SetLockoutEndAsync(user, user.LockoutEndUtc, ct);
        Log.LockedOut(logger, user.Id, user.LockoutEndUtc, lockoutNumber);
        metrics.Lockout();

        // inform the owner once per attack (first lockout since the last successful sign-in)
        if (lockoutNumber == 1)
        {
            var email = user.Email;
            var end = user.LockoutEndUtc.Value;
            await mail.SendAsync("lockout-notification", (s, c) => s.SendLockoutNotificationEmailAsync(email, end, c), ct);
        }
        return true;
    }

    internal static TimeSpan LockoutDuration(SlimLockoutOptions lockout, int lockoutNumber)
    {
        // Duration * 2^(n-1), computed in ticks with an overflow-safe cap
        var ticks = lockout.Duration.Ticks;
        for (var i = 1; i < lockoutNumber && ticks < lockout.MaxDuration.Ticks; i++) ticks *= 2;
        return TimeSpan.FromTicks(Math.Min(ticks, lockout.MaxDuration.Ticks));
    }

    /// <summary>
    /// Resets lockout counters (unless <paramref name="resetLockout"/> is false) and rehashes outdated hashes.
    /// Uses the narrow store methods only – <paramref name="user"/> may be outdated by the time the (slow) password
    /// verification finished, and writing it back as a whole could undo a concurrent password change.
    /// </summary>
    public async Task RegisterSuccessAsync(SlimUser user, string? password, bool rehash, bool resetLockout, CancellationToken ct)
    {
        if (resetLockout && (user.FailedLoginAttempts != 0 || user.LockoutEndUtc is not null))
        {
            user.FailedLoginAttempts = 0;
            user.LockoutEndUtc = null;
            await store.ResetFailedLoginAttemptsAsync(user, ct);
        }
        if (rehash && !string.IsNullOrEmpty(password) && !string.IsNullOrEmpty(user.PasswordHash))
        {
            var newHash = hasher.HashPassword(user, password);
            await store.UpdatePasswordHashAsync(user, user.PasswordHash, newHash, ct);
            user.PasswordHash = newHash;
            Log.PasswordRehashed(logger, user.Id);
        }
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
