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
    /// Creates a user. <paramref name="passwordHash"/> is empty for users created through an external login.
    /// Must return the persisted user including its generated <see cref="SlimUser.Id"/>.
    /// </summary>
    Task<SlimUser> CreateAsync(string email, string passwordHash, CancellationToken ct);

    /// <summary>
    /// Persists all security fields of <paramref name="user"/>:
    /// PasswordHash, SecurityStamp, EmailConfirmed, FailedLoginAttempts, LockoutEndUtc, TwoFactorEnabled.
    /// </summary>
    Task UpdateSecurityStateAsync(SlimUser user, CancellationToken ct);

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
