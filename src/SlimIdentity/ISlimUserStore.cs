namespace SlimIdentity;

/// <summary>
/// Mandatory database bridge for basic authentication. Implemented by the host project
/// (EF Core, Dapper, REST, …). SlimIdentity never touches a database itself.
/// </summary>
public interface ISlimUserStore
{
    /// <summary>Looks a user up by login identifier. Should compare case-insensitively.</summary>
    Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct);

    /// <summary>Looks a user up by id (security-stamp validation, refresh, 2FA, …).</summary>
    Task<SlimUser?> FindByIdAsync(string userId, CancellationToken ct);

    /// <summary>
    /// Creates a user – together with <see cref="SlimNewUser.Profile"/>, your business data, in one transaction. Must
    /// return the persisted user including its generated <see cref="SlimUser.Id"/>, or <c>null</c> if the address is
    /// already taken (e.g. unique-index violation by a concurrent registration) – nothing must be created then, neither
    /// the account nor its profile.
    /// </summary>
    Task<SlimUser?> CreateAsync(SlimNewUser newUser, CancellationToken ct);

    /// <summary>
    /// Persists the security fields of <paramref name="user"/> – PasswordHash, SecurityStamp, EmailConfirmed,
    /// TwoFactorEnabled, PasswordChangeRequired – <b>only if</b> the stored security stamp still equals
    /// <paramref name="expectedStamp"/> (the whole string, ordinal); returns whether they were written, e.g.
    /// <c>UPDATE users SET … WHERE id = @id AND COALESCE(security_stamp, '') = @expectedStamp</c> (affected rows = 1).
    /// A missing stamp (<c>NULL</c>) equals an empty <paramref name="expectedStamp"/>.
    /// Writes <b>no other field</b>: not the failed-attempt counters or lockout ends (those change only through
    /// <see cref="TryBeginAttemptAsync"/> and <see cref="ResetFailedAttemptsAsync"/>), not <c>IsActive</c> and not the
    /// address (<see cref="UpdateEmailAsync"/>) – an outdated copy must never unblock an account.
    /// </summary>
    /// <remarks>
    /// SlimIdentity changes the stamp with every write, so a request that read the user before a concurrent change
    /// cannot write back an outdated state: it reads the user again and either applies its change once more or gives
    /// up (a link or a password confirmed against the old state). The high-frequency sign-in bookkeeping uses the narrow
    /// methods below instead. Code of your own that changes these fields must set a new stamp as well, e.g.
    /// <c>var expected = user.SecurityStamp; user.EmailConfirmed = true; user.SecurityStamp =
    /// SlimUser.NewSecurityStamp(); await store.UpdateSecurityStateAsync(user, expected, ct);</c>
    /// </remarks>
    Task<bool> UpdateSecurityStateAsync(SlimUser user, string expectedStamp, CancellationToken ct);

    /// <summary>
    /// Replaces <b>only</b> the security stamp, and <b>only if</b> it still equals <paramref name="expectedStamp"/>;
    /// returns whether it was replaced, e.g.
    /// <c>UPDATE users SET security_stamp = @newStamp WHERE id = @id AND security_stamp = @expectedStamp</c>
    /// (affected rows = 1).
    /// </summary>
    /// <remarks>
    /// Used where SlimIdentity only ends sessions or refreshes claims – sign-out everywhere, <c>RefreshClaimsAsync</c>,
    /// forgetting all remembered devices. A password or 2FA change that happened in the meantime is never written back
    /// over; SlimIdentity reads the user again and retries.
    /// </remarks>
    Task<bool> UpdateSecurityStampAsync(SlimUser user, string expectedStamp, string newStamp, CancellationToken ct);

    /// <summary>
    /// Reserves one attempt of <see cref="SlimAttemptRequest.Factor"/> <b>before</b> it is checked, as one atomic step
    /// on the stored counter and lockout end of that factor (password: <see cref="SlimUser.FailedLoginAttempts"/> and
    /// <see cref="SlimUser.LockoutEndUtc"/>; second factor: <see cref="SlimUser.FailedSecondFactorAttempts"/> and
    /// <see cref="SlimUser.SecondFactorLockoutEndUtc"/>). Touches no other field.
    /// <list type="number">
    /// <item>If <see cref="SlimAttemptRequest.IsLockedOut"/> holds for the stored end: change nothing, return
    /// <see cref="SlimAttemptReservation.LockedOut"/> with that end.</item>
    /// <item>Otherwise store counter + 1 and <see cref="SlimAttemptRequest.NextLockoutEnd"/> as the new end, and return
    /// <see cref="SlimAttemptReservation.Reserved"/> with the new counter.</item>
    /// </list>
    /// Return <c>null</c> if the user no longer exists, or if the attempt could not be reserved (e.g. under heavy
    /// contention) – it is then not checked.
    /// </summary>
    /// <remarks>
    /// Must be atomic across all instances: of parallel attempts at the threshold exactly one may reach it, every later
    /// one must see the lockout. Typical implementations: a row lock (<c>SELECT … FOR UPDATE</c>) in a transaction, or a
    /// compare-and-set loop (<c>UPDATE … SET counter = @new, end = @newEnd WHERE id = @id AND counter = @old AND
    /// end IS NOT DISTINCT FROM @oldEnd</c>, retried on 0 affected rows).
    /// </remarks>
    Task<SlimAttemptReservation?> TryBeginAttemptAsync(SlimUser user, SlimAttemptRequest attempt, CancellationToken ct);

    /// <summary>
    /// Sets <b>only</b> the counter of <paramref name="factor"/> to 0 and its lockout end to <c>null</c> (after a
    /// successful check, an unlock, a new password, …). The other factor is left alone.
    /// </summary>
    Task ResetFailedAttemptsAsync(SlimUser user, SlimAttemptFactor factor, CancellationToken ct);

    /// <summary>
    /// Transparent rehash after a successful sign-in (outdated hash parameters): replaces the password hash with
    /// <paramref name="newHash"/> <b>only if</b> it still equals <paramref name="currentHash"/>, e.g.
    /// <c>UPDATE users SET password_hash = @newHash WHERE id = @id AND password_hash = @currentHash</c>.
    /// A password change in the meantime therefore always wins. Writes no other field.
    /// </summary>
    Task UpdatePasswordHashAsync(SlimUser user, string currentHash, string newHash, CancellationToken ct);

    /// <summary>
    /// Changes the login e-mail address after the new address was confirmed, in one write: the address (including any
    /// normalized lookup column), <c>EmailConfirmed = true</c> and the security stamp <paramref name="newStamp"/> –
    /// <b>only if</b> the stored stamp still equals <paramref name="expectedStamp"/> (as in
    /// <see cref="UpdateSecurityStateAsync"/>). Writes no other field, and nothing unless the result is
    /// <see cref="SlimEmailUpdateResult.Updated"/>. A new spelling of the user's own address is not taken.
    /// </summary>
    /// <returns>
    /// <see cref="SlimEmailUpdateResult.EmailTaken"/> if another account uses the address (e.g. unique-index
    /// violation), <see cref="SlimEmailUpdateResult.StampChanged"/> if the stamp did not match or the user no longer
    /// exists.
    /// </returns>
    Task<SlimEmailUpdateResult> UpdateEmailAsync(SlimUser user, string newEmail, string expectedStamp, string newStamp, CancellationToken ct);

    /// <summary>
    /// Host-specific claims (roles, permissions, tenant_id, …) that are added before the cookie / JWT is signed.
    /// <c>ClaimTypes.Role</c> is normalized to <c>role</c>; reserved SlimIdentity claims are ignored.
    /// </summary>
    Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct);
}

/// <summary>What <see cref="ISlimUserStore.CreateAsync"/> creates.</summary>
public sealed class SlimNewUser
{
    /// <summary>
    /// The address – trimmed and Unicode-normalized (NFC) by SlimIdentity, case as entered. Unique case-insensitively:
    /// store a normalized column (e.g. upper case) with a unique index.
    /// </summary>
    public required string Email { get; init; }

    /// <summary>
    /// The password hash – empty for accounts without a password (external login, passkey, invitation, created by an
    /// administrator).
    /// </summary>
    public string PasswordHash { get; init; } = string.Empty;

    /// <summary>
    /// <c>true</c> if the address is already proven (a registration that started with a mailed code or link) – store it
    /// as given. <c>false</c> for every other account.
    /// </summary>
    public bool EmailConfirmed { get; init; }

    /// <summary>
    /// Your business data for the new account: what <see cref="ISlimRegistrationProfile"/> returned for the
    /// <c>profile</c> of a registration, what your code passed to <see cref="ISlimAuthManager.CreateUserAsync"/>, or
    /// what you set yourself. <c>null</c> without a profile (always for an external login). Write it in the same
    /// transaction as the account.
    /// </summary>
    public object? Profile { get; init; }

    /// <summary>The external provider an account is created for (automatic registration), else <c>null</c>.</summary>
    public string? Provider { get; init; }
}

/// <summary>The answer of <see cref="ISlimUserStore.UpdateEmailAsync"/>.</summary>
public enum SlimEmailUpdateResult
{
    /// <summary>Address, confirmation and stamp were written.</summary>
    Updated,

    /// <summary>Another account uses the address; nothing was written.</summary>
    EmailTaken,

    /// <summary>The stored stamp no longer equals the expected one (or the user is gone); nothing was written.</summary>
    StampChanged,
}

/// <summary>The factor a failed-attempt counter belongs to. Each factor has its own counter and lockout.</summary>
public enum SlimAttemptFactor
{
    /// <summary>The password (<see cref="SlimUser.FailedLoginAttempts"/>, <see cref="SlimUser.LockoutEndUtc"/>).</summary>
    Password,

    /// <summary>
    /// The second factor – authenticator, e-mail or recovery code (<see cref="SlimUser.FailedSecondFactorAttempts"/>,
    /// <see cref="SlimUser.SecondFactorLockoutEndUtc"/>).
    /// </summary>
    SecondFactor,
}

/// <summary>
/// One attempt to reserve with <see cref="ISlimUserStore.TryBeginAttemptAsync"/>. Carries the lockout policy, so a
/// store only reads, compares and writes.
/// </summary>
public sealed class SlimAttemptRequest
{
    private readonly SlimLockoutOptions _lockout;

    /// <summary>Creates a request; <paramref name="lockout"/> must have <c>MaxFailedAttempts</c> &gt; 0.</summary>
    public SlimAttemptRequest(SlimAttemptFactor factor, DateTimeOffset utcNow, SlimLockoutOptions lockout)
    {
        ArgumentNullException.ThrowIfNull(lockout);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(lockout.MaxFailedAttempts);
        Factor = factor;
        UtcNow = utcNow;
        _lockout = lockout;
    }

    /// <summary>The counter to reserve on.</summary>
    public SlimAttemptFactor Factor { get; }

    /// <summary>The point in time of the attempt.</summary>
    public DateTimeOffset UtcNow { get; }

    /// <summary>Whether the stored lockout end of the factor still blocks the attempt.</summary>
    public bool IsLockedOut(DateTimeOffset? lockoutEndUtc) => lockoutEndUtc is { } end && end > UtcNow;

    /// <summary>
    /// The lockout end to store together with the new counter: a new end if <paramref name="newFailedAttempts"/>
    /// reaches the next multiple of <c>MaxFailedAttempts</c>, else <paramref name="currentLockoutEndUtc"/> unchanged.
    /// </summary>
    public DateTimeOffset? NextLockoutEnd(int newFailedAttempts, DateTimeOffset? currentLockoutEndUtc) =>
        LockoutNumber(newFailedAttempts) is var n and > 0
            ? UtcNow + Services.SlimCredentialService.LockoutDuration(_lockout, n)
            : currentLockoutEndUtc;

    /// <summary>1, 2, 3, … if this counter value locks the factor (the n-th lockout of the series), else 0.</summary>
    internal int LockoutNumber(int failedAttempts) =>
        failedAttempts > 0 && failedAttempts % _lockout.MaxFailedAttempts == 0 ? failedAttempts / _lockout.MaxFailedAttempts : 0;
}

/// <summary>The answer of <see cref="ISlimUserStore.TryBeginAttemptAsync"/>.</summary>
public sealed class SlimAttemptReservation
{
    private SlimAttemptReservation(int failedAttempts, DateTimeOffset? lockoutEndUtc)
    {
        FailedAttempts = failedAttempts;
        LockoutEndUtc = lockoutEndUtc;
    }

    /// <summary>The attempt was counted; <paramref name="failedAttempts"/> is the new counter value.</summary>
    public static SlimAttemptReservation Reserved(int failedAttempts) => new(failedAttempts, null);

    /// <summary>The factor is locked until <paramref name="lockoutEndUtc"/>; nothing was counted.</summary>
    public static SlimAttemptReservation LockedOut(DateTimeOffset lockoutEndUtc) => new(0, lockoutEndUtc);

    /// <summary>Whether the factor was locked and the attempt was not counted.</summary>
    public bool IsLockedOut => LockoutEndUtc is not null;

    /// <summary>The new counter value of a reserved attempt.</summary>
    public int FailedAttempts { get; }

    /// <summary>The end of the lockout that refused the attempt.</summary>
    public DateTimeOffset? LockoutEndUtc { get; }
}
