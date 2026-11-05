namespace SlimIdentity;

/// <summary>
/// Optional capability: replaces the internal <c>PasswordHasher</c> check of existing passwords (LDAP / Active Directory,
/// legacy hashes). Brute-force protection, lockout and 2FA stay fully active. For rules on <b>new</b> passwords see
/// <see cref="ISlimPasswordRule"/>.
/// </summary>
public interface ISlimCustomPasswordValidator
{
    /// <summary>Returns true if <paramref name="providedPassword"/> is correct for <paramref name="user"/>. Infrastructure errors should return false and be logged.</summary>
    Task<bool> ValidateAsync(SlimUser user, string providedPassword, CancellationToken ct);
}
