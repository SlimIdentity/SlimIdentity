using SlimIdentity.Security;

namespace SlimIdentity.Abstractions;

/// <summary>
/// Optional capability: activates <c>/auth/refresh</c> (JWT rotation).
/// SlimIdentity only ever hands out the SHA-256 hash of a refresh token – store nothing else.
/// </summary>
public interface ISlimRefreshTokenStore
{
    Task StoreRefreshTokenAsync(string userId, string tokenHash, DateTimeOffset expiresAt, CancellationToken ct);

    /// <summary>
    /// Returns the owning user id if the hash exists and is not expired, and deletes it atomically
    /// (single use / rotation). Returns <c>null</c> otherwise.
    /// </summary>
    Task<string?> ValidateAndConsumeRefreshTokenAsync(string tokenHash, CancellationToken ct);
}

/// <summary>
/// Optional capability: activates <c>/auth/login/2fa</c> and the <c>/auth/2fa/*</c> setup routes (TOTP, e-mail codes, recovery codes).
/// </summary>
public interface ISlimTwoFactorStore
{
    /// <summary>Base32 TOTP secret, or <c>null</c>/empty if the user uses e-mail codes.</summary>
    Task<string?> GetTotpSecretAsync(SlimUser user, CancellationToken ct);

    /// <summary>Stores the Base32 secret. An empty string removes the authenticator.</summary>
    Task SetTotpSecretAsync(SlimUser user, string secret, CancellationToken ct);

    /// <summary>Replaces <b>all</b> existing recovery codes of the user (SHA-256 hashes). An empty list removes them.</summary>
    Task StoreRecoveryCodesAsync(SlimUser user, IEnumerable<string> hashedCodes, CancellationToken ct);

    /// <summary>Returns true and deletes the code if the hash belongs to the user.</summary>
    Task<bool> ValidateAndConsumeRecoveryCodeAsync(SlimUser user, string hashedCode, CancellationToken ct);
}

/// <summary>
/// Optional capability: activates OAuth social logins and enterprise OIDC (Entra ID, Keycloak, …).
/// The provider handlers themselves are registered by the host (e.g. <c>AddGoogle</c>, <c>AddOpenIdConnect</c>).
/// </summary>
public interface ISlimExternalLoginStore
{
    Task<SlimUser?> FindByExternalLoginAsync(string provider, string providerKey, CancellationToken ct);
    Task LinkExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct);
}

/// <summary>
/// Optional capability: activates the <c>X-API-Key</c> authentication handler for M2M access.
/// The key is never passed in clear text – only its SHA-256 hex hash (see <see cref="SlimApiKeys"/>).
/// </summary>
public interface ISlimApiKeyStore
{
    /// <summary>Claims of the key owner, or <c>null</c> if the key is unknown / revoked / expired.</summary>
    Task<IReadOnlyCollection<Claim>?> ValidateApiKeyAsync(string keyHash, CancellationToken ct);
}

/// <summary>
/// Optional capability: replaces the internal <c>PasswordHasher</c> check (LDAP / Active Directory, legacy hashes).
/// Brute-force protection, lockout and 2FA stay fully active.
/// </summary>
public interface ISlimCustomPasswordValidator
{
    Task<bool> ValidateAsync(SlimUser user, string providedPassword, CancellationToken ct);
}
