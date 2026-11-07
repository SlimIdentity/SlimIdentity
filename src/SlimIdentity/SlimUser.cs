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

    /// <summary>Random value, rotated on password change / security events. Invalidates all cookies and tokens.</summary>
    public string SecurityStamp { get; set; } = NewSecurityStamp();

    /// <summary>Immediate login blocker (admin ban, soft delete, pending approval).</summary>
    public bool IsActive { get; set; } = true;

    /// <summary>Whether the e-mail address has been verified.</summary>
    public bool EmailConfirmed { get; set; }

    /// <summary>Consecutive failed login attempts (account lockout).</summary>
    public int FailedLoginAttempts { get; set; }

    /// <summary>Point in time until which the account is locked because of brute force.</summary>
    public DateTimeOffset? LockoutEndUtc { get; set; }

    /// <summary>Whether the 2FA state machine kicks in after a successful password check.</summary>
    public bool TwoFactorEnabled { get; set; }

    /// <summary>True while <see cref="LockoutEndUtc"/> lies in the future.</summary>
    public bool IsLockedOut(DateTimeOffset utcNow) => LockoutEndUtc is { } end && end > utcNow;

    /// <summary>Creates a new cryptographically random security stamp.</summary>
    public static string NewSecurityStamp() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
}
