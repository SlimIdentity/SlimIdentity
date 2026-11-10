namespace SlimIdentity;

/// <summary>
/// Optional, additional rule for <b>new</b> passwords (registration, reset, change, invitation) on top of
/// <see cref="SlimPasswordOptions"/> – e.g. a check against breached passwords (NIST SP 800-63B) or a blocklist of
/// product names. Any number of rules can be registered with <c>AddPasswordRule&lt;T&gt;()</c>.
/// </summary>
public interface ISlimPasswordRule
{
    /// <summary>Returns error messages (shown to the user), or an empty list if the password is acceptable.</summary>
    /// <param name="password">The new password.</param>
    /// <param name="email">E-mail address of the account (e.g. to reject passwords that contain it).</param>
    /// <param name="ct">Cancellation token.</param>
    Task<IReadOnlyList<string>> ValidateAsync(string password, string email, CancellationToken ct);
}
