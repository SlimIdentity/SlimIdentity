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
/// Optional capability: server-side sessions. Every sign-in (cookie or JWT) gets a session id (<c>sid</c> claim) that is
/// checked against this store, which enables a real per-device <c>/auth/logout</c>, <c>GET /auth/sessions</c> and
/// <c>DELETE /auth/sessions/{id}</c>. Without it, sessions are stateless and only <c>/auth/logout-all</c>
/// (security-stamp rotation) ends them server-side.
/// </summary>
public interface ISlimSessionStore
{
    Task CreateAsync(SlimSession session, CancellationToken ct);

    /// <summary>Returns the session, or <c>null</c> if it does not exist or was revoked. (SlimIdentity checks the expiry itself.)</summary>
    Task<SlimSession?> FindAsync(string sessionId, CancellationToken ct);

    /// <summary>Active sessions of the user (for the "your devices" list). Expired rows may be omitted or cleaned up by the host.</summary>
    Task<IReadOnlyCollection<SlimSession>> ListAsync(string userId, CancellationToken ct);

    /// <summary>Updates <see cref="SlimSession.LastSeenUtc"/> and <see cref="SlimSession.ExpiresUtc"/> (refresh, sliding cookies).</summary>
    Task TouchAsync(string sessionId, DateTimeOffset lastSeenUtc, DateTimeOffset expiresUtc, CancellationToken ct);

    Task RevokeAsync(string sessionId, CancellationToken ct);

    /// <summary>Revokes all sessions of the user except <paramref name="exceptSessionId"/> (null = all).</summary>
    Task RevokeAllAsync(string userId, string? exceptSessionId, CancellationToken ct);
}

/// <summary>A server-side session (one device / browser).</summary>
public sealed class SlimSession
{
    public string Id { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    /// <summary><c>cookie</c> or <c>bearer</c>.</summary>
    public string Mode { get; set; } = "cookie";
    /// <summary><c>pwd</c>, <c>mfa</c>, <c>ext</c>, <c>impersonation</c>, …</summary>
    public string AuthenticationMethod { get; set; } = string.Empty;
    /// <summary>Set for impersonation sessions (id of the admin).</summary>
    public string? ImpersonatorId { get; set; }
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset LastSeenUtc { get; set; }
    public DateTimeOffset ExpiresUtc { get; set; }
    /// <summary>Truncated to 256 characters. Personal data – the host decides whether to persist it.</summary>
    public string? UserAgent { get; set; }
    /// <summary>Client IP at sign-in. Personal data – the host decides whether to persist it.</summary>
    public string? IpAddress { get; set; }
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
