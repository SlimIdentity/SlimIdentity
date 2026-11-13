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
    SlimHookRunner hooks,
    IOptions<SlimIdentityOptions> options,
    TimeProvider time,
    IServiceProvider services,
    ILogger<SlimCredentialService> logger)
{
    /// <summary>How recent a sign-in must be to stand in for the password of an account that has none.</summary>
    internal static readonly TimeSpan RecentSignInWindow = TimeSpan.FromMinutes(5);

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
    /// A password to confirm: a local hash, or – with an <see cref="ISlimCustomPasswordValidator"/> – what it says.
    /// </summary>
    public async ValueTask<bool> HasPasswordAsync(SlimUser user, CancellationToken ct) =>
        !string.IsNullOrEmpty(user.PasswordHash)
        || (services.GetService<ISlimCustomPasswordValidator>() is { } custom && await custom.HasPasswordAsync(user, ct).ConfigureAwait(false));

    /// <summary>
    /// The owner confirms a sensitive change (a sign-in method, 2FA, the e-mail address) – a stolen session alone must
    /// not do it. With a password: the password, with lockout bookkeeping (400 <c>invalid_password</c> or 423). Without
    /// one: a sign-in of at most <see cref="RecentSignInWindow"/> ago – otherwise 403 <c>reauthentication_required</c>
    /// (sign in again with the provider or a passkey, then repeat); nothing is counted as a failed attempt.
    /// Returns <c>null</c> when confirmed.
    /// </summary>
    public async Task<IResult?> ConfirmPasswordAsync(SlimUser user, string? password, HttpContext http, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        if (!await HasPasswordAsync(user, ct))
        {
            // the fresh sign-in of an impersonation is the administrator's, not the owner's
            return !http.User.IsImpersonating()
                && long.TryParse(http.User.FindFirst(SlimClaimTypes.AuthTime)?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var signedIn)
                && now - DateTimeOffset.FromUnixTimeSeconds(signedIn) <= RecentSignInWindow
                ? null
                : Http.SlimResults.Status(SlimErrorCodes.ReauthenticationRequired,
                    "Sign in again to confirm this change – your account has no password.", StatusCodes.Status403Forbidden);
        }


        // the attempt is reserved before the check: parallel guesses cannot all pass the lockout check first
        var attempt = await BeginAttemptAsync(user, SlimAttemptFactor.Password, ct);
        if (attempt.Status == SlimAttemptStatus.LockedOut) return Http.SlimResults.Locked(http, attempt.LockoutEndUtc!.Value, now);
        if (attempt.Status == SlimAttemptStatus.NotReserved) return Http.SlimResults.BadRequest(SlimErrorCodes.InvalidPassword, "The password is incorrect.");

        var check = await VerifyPasswordAsync(user, password, ct);
        if (check != SlimPasswordCheck.Failed)
        {
            // like a successful sign-in: the counter starts over and an outdated hash is upgraded
            await SucceedAttemptAsync(user, attempt, ct);
            await RehashAsync(user, password, check, ct);
            return null;
        }

        return await FailAttemptAsync(user, attempt, ct) is { } lockedUntil
            ? Http.SlimResults.Locked(http, lockedUntil, now)
            : Http.SlimResults.BadRequest(SlimErrorCodes.InvalidPassword, "The password is incorrect.");
    }


    /// <summary>
    /// Reserves one attempt of <paramref name="factor"/> in the store before it is checked (see
    /// <see cref="ISlimUserStore.TryBeginAttemptAsync"/>). Every <c>MaxFailedAttempts</c> consecutive failures lock the
    /// factor; the duration doubles with each lockout (<c>Duration</c>, 2×, 4×, … up to <c>MaxDuration</c>). With the
    /// lockout disabled nothing is counted, an existing lockout end still holds.
    /// </summary>
    public async Task<SlimAttempt> BeginAttemptAsync(SlimUser user, SlimAttemptFactor factor, CancellationToken ct)
    {
        var lockout = options.Value.Lockout;
        var now = time.GetUtcNow();
        if (lockout.MaxFailedAttempts == 0)
        {
            return user.LockoutEndOf(factor) is { } end && end > now
                ? new SlimAttempt(SlimAttemptStatus.LockedOut, factor, 0, end, 0)
                : new SlimAttempt(SlimAttemptStatus.Reserved, factor, 0, null, 0);
        }

        var request = new SlimAttemptRequest(factor, now, lockout);
        var reservation = await store.TryBeginAttemptAsync(user, request, ct);
        if (reservation is null) return new SlimAttempt(SlimAttemptStatus.NotReserved, factor, 0, null, 0);
        if (reservation.IsLockedOut) return new SlimAttempt(SlimAttemptStatus.LockedOut, factor, 0, reservation.LockoutEndUtc, 0);

        var lockoutNumber = request.LockoutNumber(reservation.FailedAttempts);
        var setEnd = lockoutNumber > 0 ? request.NextLockoutEnd(reservation.FailedAttempts, null) : null;
        user.SetAttempts(factor, reservation.FailedAttempts, setEnd ?? user.LockoutEndOf(factor));
        return new SlimAttempt(SlimAttemptStatus.Reserved, factor, reservation.FailedAttempts, setEnd, lockoutNumber);
    }

    /// <summary>
    /// The reserved attempt failed. If it was the one that locked the factor, the lockout is reported (log, metric, event
    /// and – once per series – a mail to the owner) and its end returned; otherwise <c>null</c>.
    /// </summary>
    public async Task<DateTimeOffset?> FailAttemptAsync(SlimUser user, SlimAttempt attempt, CancellationToken ct)
    {
        if (attempt.LockoutNumber == 0 || attempt.LockoutEndUtc is not { } end) return null;

        Log.LockedOut(logger, user.Id, end, attempt.LockoutNumber);
        metrics.Lockout();
        await hooks.RaiseAsync(SlimEventTypes.LockedOut, user.Id,
            reason: attempt.Factor == SlimAttemptFactor.Password ? "password" : "second_factor", ct: ct);

        // inform the owner once per attack (first lockout since the counter was last reset)
        if (attempt.LockoutNumber == 1)
        {
            var email = user.Email;
            await mail.SendAsync(SlimEmailKinds.LockoutNotification, email, user.Id, (s, x, c) => s.SendLockoutNotificationEmailAsync(x, email, end, c), ct);
        }
        return end;
    }

    /// <summary>The reserved attempt succeeded: the counter of its factor starts over, a lockout it set ends.</summary>
    public Task SucceedAttemptAsync(SlimUser user, SlimAttempt attempt, CancellationToken ct) =>
        attempt.FailedAttempts == 0 ? Task.CompletedTask : ResetAttemptsAsync(user, attempt.Factor, ct);   // 0: nothing counted

    /// <summary>Sets the counter of <paramref name="factor"/> to 0 and ends its lockout (store and this copy).</summary>
    public async Task ResetAttemptsAsync(SlimUser user, SlimAttemptFactor factor, CancellationToken ct)
    {
        await store.ResetFailedAttemptsAsync(user, factor, ct);
        user.SetAttempts(factor, 0, null);
    }

    internal static TimeSpan LockoutDuration(SlimLockoutOptions lockout, int lockoutNumber)
    {
        // Duration * 2^(n-1), computed in ticks with an overflow-safe cap
        var ticks = lockout.Duration.Ticks;
        for (var i = 1; i < lockoutNumber && ticks < lockout.MaxDuration.Ticks; i++) ticks *= 2;
        return TimeSpan.FromTicks(Math.Min(ticks, lockout.MaxDuration.Ticks));
    }

    /// <summary>
    /// Rehashes an outdated hash after a successful check. Uses the narrow store method only – <paramref name="user"/>
    /// may be outdated by the time the (slow) password verification finished, and writing it back as a whole could undo
    /// a concurrent password change.
    /// </summary>
    public async Task RehashAsync(SlimUser user, string? password, SlimPasswordCheck check, CancellationToken ct)
    {
        if (check != SlimPasswordCheck.SuccessRehashNeeded || string.IsNullOrEmpty(password) || string.IsNullOrEmpty(user.PasswordHash)) return;
        var newHash = hasher.HashPassword(user, password);
        await store.UpdatePasswordHashAsync(user, user.PasswordHash, newHash, ct);
        user.PasswordHash = newHash;
        Log.PasswordRehashed(logger, user.Id);
    }

    /// <summary>
    /// Sets a new password, rotates the stamp and clears a pending forced change (does not persist). The failed-attempt
    /// counters are not part of the security state – reset them explicitly where a new password lifts the lockout.
    /// </summary>
    public void ApplyNewPassword(SlimUser user, string newPassword)
    {
        user.PasswordHash = hasher.HashPassword(user, newPassword);
        user.SecurityStamp = SlimUser.NewSecurityStamp();
        user.PasswordChangeRequired = false;
    }
}

internal enum SlimAttemptStatus { Reserved, LockedOut, NotReserved }

/// <summary>
/// A reserved or refused attempt. <c>LockoutEndUtc</c>: the end of the lockout that refused it, or of the lockout this
/// attempt set (<c>LockoutNumber</c> &gt; 0) – reported only if the check then fails.
/// </summary>
internal sealed record SlimAttempt(SlimAttemptStatus Status, SlimAttemptFactor Factor, int FailedAttempts, DateTimeOffset? LockoutEndUtc, int LockoutNumber);