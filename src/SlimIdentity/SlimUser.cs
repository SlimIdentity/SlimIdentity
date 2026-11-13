namespace SlimIdentity;

/// <summary>
/// The only data structure exchanged between the host database and SlimIdentity.
/// Contains nothing but authentication / hardening state – no profile or business data.
/// </summary>
public sealed class SlimUser
{
    /// <summary>Unique user id (Guid, int or string in the host DB – always transported as string).</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>Primary login identifier (or user name / UPN for LDAP).</summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>Hash produced by <c>PasswordHasher&lt;SlimUser&gt;</c>. Empty for pure OAuth / LDAP users.</summary>
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>
    /// Random value, rotated on password change and other security events – that invalidates all sessions, tokens and
    /// links. May carry a claims part after a dot (<c>"&lt;security&gt;.&lt;claims&gt;"</c>), changed by
    /// <c>ISlimAuthManager.RefreshClaimsAsync</c>: sessions then reload their claims, nothing else is invalidated.
    /// Store it as an opaque string (at most 64 characters); compare stamps only with <see cref="IsSameSecurityState"/>.
    /// </summary>
    public string SecurityStamp { get; set; } = NewSecurityStamp();

    /// <summary>Immediate login blocker (admin ban, soft delete, pending approval).</summary>
    public bool IsActive { get; set; } = true;

    /// <summary>Whether the e-mail address has been verified.</summary>
    public bool EmailConfirmed { get; set; }

    /// <summary>Consecutive failed password attempts (account lockout of the password).</summary>
    public int FailedLoginAttempts { get; set; }

    /// <summary>
    /// Point in time until which the password is locked because of brute force. Passkeys, external providers and host
    /// sign-ins are not affected; to block an account, use <see cref="IsActive"/>.
    /// </summary>
    public DateTimeOffset? LockoutEndUtc { get; set; }

    /// <summary>Consecutive failed second-factor attempts (authenticator, e-mail or recovery code).</summary>
    public int FailedSecondFactorAttempts { get; set; }

    /// <summary>Point in time until which the second factor is locked because of brute force.</summary>
    public DateTimeOffset? SecondFactorLockoutEndUtc { get; set; }

    /// <summary>Whether the 2FA state machine kicks in after a successful password check.</summary>
    public bool TwoFactorEnabled { get; set; }

    /// <summary>
    /// The password was set by an administrator and must be changed at the next sign-in, before any session exists
    /// (<c>password_change_required</c>). Cleared by every new password.
    /// </summary>
    public bool PasswordChangeRequired { get; set; }

    /// <summary>True while <see cref="LockoutEndUtc"/> (the password lockout) lies in the future.</summary>
    public bool IsLockedOut(DateTimeOffset utcNow) => LockoutEndUtc is { } end && end > utcNow;

    /// <summary>True while <see cref="SecondFactorLockoutEndUtc"/> lies in the future.</summary>
    public bool IsSecondFactorLockedOut(DateTimeOffset utcNow) => SecondFactorLockoutEndUtc is { } end && end > utcNow;

    /// <summary>The lockout end of <paramref name="factor"/>.</summary>
    internal DateTimeOffset? LockoutEndOf(SlimAttemptFactor factor) =>
        factor == SlimAttemptFactor.Password ? LockoutEndUtc : SecondFactorLockoutEndUtc;

    /// <summary>Sets counter and lockout end of <paramref name="factor"/> on this copy.</summary>
    internal void SetAttempts(SlimAttemptFactor factor, int failedAttempts, DateTimeOffset? lockoutEndUtc)
    {
        if (factor == SlimAttemptFactor.Password) (FailedLoginAttempts, LockoutEndUtc) = (failedAttempts, lockoutEndUtc);
        else (FailedSecondFactorAttempts, SecondFactorLockoutEndUtc) = (failedAttempts, lockoutEndUtc);
    }

    /// <summary>Creates a new cryptographically random security stamp (no claims part).</summary>
    public static string NewSecurityStamp() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    /// <summary>
    /// True if two security stamps stand for the same security state – they may differ in their claims part only.
    /// Constant time. Use this instead of comparing stamps directly.
    /// </summary>
    public static bool IsSameSecurityState(string? stamp, string? other) =>
        stamp is not null && other is not null
        && Security.SlimHashing.FixedTimeEquals(SecurityPartOf(stamp), SecurityPartOf(other));

    /// <summary>The stamp with a new claims part – same security state, new claims version.</summary>
    internal static string WithNewClaimsPart(string stamp) =>
        $"{SecurityPartOf(stamp)}.{Convert.ToHexString(RandomNumberGenerator.GetBytes(4))}";

    private static string SecurityPartOf(string stamp) => stamp.IndexOf('.', StringComparison.Ordinal) is var dot and >= 0 ? stamp[..dot] : stamp;
}
