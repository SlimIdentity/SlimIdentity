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

    /// <summary>
    /// Whether <paramref name="user"/> has a password this validator checks – default <c>true</c> (every directory
    /// account). Return <c>false</c> for accounts that sign in only externally or with passkeys (e.g. no legacy hash):
    /// they confirm sensitive changes with a fresh sign-in instead of a password they do not have.
    /// </summary>
    ValueTask<bool> HasPasswordAsync(SlimUser user, CancellationToken ct) => ValueTask.FromResult(true);
}
