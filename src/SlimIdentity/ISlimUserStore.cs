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
    /// Creates a user. <paramref name="passwordHash"/> is empty for users created through an external login or an
    /// invitation. Must return the persisted user including its generated <see cref="SlimUser.Id"/>, or <c>null</c> if
    /// the address is already taken (e.g. unique-index violation by a concurrent registration) – nothing must be created then.
    /// </summary>
    Task<SlimUser?> CreateAsync(string email, string passwordHash, CancellationToken ct);

    /// <summary>
    /// Persists all security fields of <paramref name="user"/>:
    /// PasswordHash, SecurityStamp, EmailConfirmed, FailedLoginAttempts, LockoutEndUtc, TwoFactorEnabled.
    /// </summary>
    /// <remarks>
    /// Used for deliberate state changes (password change, 2FA, e-mail confirmation, …). The high-frequency sign-in
    /// bookkeeping uses the narrow methods below instead, so that a failed login can never write back an outdated
    /// password hash or security stamp.
    /// </remarks>
    Task UpdateSecurityStateAsync(SlimUser user, CancellationToken ct);

    /// <summary>
    /// Adds one failed sign-in attempt <b>atomically</b> and returns the new count; touches no other field, e.g.
    /// <c>UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = @id RETURNING failed_login_attempts</c>.
    /// </summary>
    Task<int> IncrementFailedLoginAttemptsAsync(SlimUser user, CancellationToken ct);

    /// <summary>Sets <b>only</b> the lockout end (<see cref="SlimUser.LockoutEndUtc"/>).</summary>
    Task SetLockoutEndAsync(SlimUser user, DateTimeOffset? lockoutEndUtc, CancellationToken ct);

    /// <summary>
    /// After a successful sign-in: sets <b>only</b> <see cref="SlimUser.FailedLoginAttempts"/> to 0 and
    /// <see cref="SlimUser.LockoutEndUtc"/> to <c>null</c>.
    /// </summary>
    Task ResetFailedLoginAttemptsAsync(SlimUser user, CancellationToken ct);

    /// <summary>
    /// Transparent rehash after a successful sign-in (outdated hash parameters): replaces the password hash with
    /// <paramref name="newHash"/> <b>only if</b> it still equals <paramref name="currentHash"/>, e.g.
    /// <c>UPDATE users SET password_hash = @newHash WHERE id = @id AND password_hash = @currentHash</c>.
    /// A password change in the meantime therefore always wins.
    /// </summary>
    Task UpdatePasswordHashAsync(SlimUser user, string currentHash, string newHash, CancellationToken ct);

    /// <summary>
    /// Changes the login e-mail address (after the new address was confirmed via <c>/confirm-email-change</c>), including
    /// any normalized lookup column. Return <c>false</c> if the address is already taken by another account
    /// (e.g. unique-index violation) – nothing must be changed then.
    /// </summary>
    Task<bool> UpdateEmailAsync(SlimUser user, string newEmail, CancellationToken ct);

    /// <summary>
    /// Host-specific claims (roles, permissions, tenant_id, …) that are added before the cookie / JWT is signed.
    /// <c>ClaimTypes.Role</c> is normalized to <c>role</c>; reserved SlimIdentity claims are ignored.
    /// </summary>
    Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct);
}
