namespace SlimIdentity;

/// <summary>
/// Optional capability: server-side sessions. Every sign-in (cookie or JWT) gets a session id (<c>sid</c> claim) that is
/// checked against this store, which enables a real per-device <c>/auth/logout</c>, <c>GET /auth/sessions</c> and
/// <c>DELETE /auth/sessions/{id}</c>. Without it, sessions are stateless and only <c>/auth/logout-all</c>
/// (security-stamp rotation) ends them server-side.
/// </summary>
public interface ISlimSessionStore
{
    /// <summary>Persists a new session at sign-in.</summary>
    Task CreateAsync(SlimSession session, CancellationToken ct);

    /// <summary>Returns the session, or <c>null</c> if it does not exist or was revoked. (SlimIdentity checks the expiry itself.)</summary>
    Task<SlimSession?> FindAsync(string sessionId, CancellationToken ct);

    /// <summary>Active sessions of the user (for the "your devices" list). Expired rows may be omitted or cleaned up by the host.</summary>
    Task<IReadOnlyCollection<SlimSession>> ListAsync(string userId, CancellationToken ct);

    /// <summary>Updates <see cref="SlimSession.LastSeenUtc"/> and <see cref="SlimSession.ExpiresUtc"/> (refresh, sliding cookies).</summary>
    Task TouchAsync(string sessionId, DateTimeOffset lastSeenUtc, DateTimeOffset expiresUtc, CancellationToken ct);

    /// <summary>Revokes (deletes) one session; afterwards <see cref="FindAsync"/> must return <c>null</c> for it.</summary>
    Task RevokeAsync(string sessionId, CancellationToken ct);

    /// <summary>Revokes all sessions of the user except <paramref name="exceptSessionId"/> (null = all).</summary>
    Task RevokeAllAsync(string userId, string? exceptSessionId, CancellationToken ct);
}

/// <summary>A server-side session (one device / browser).</summary>
public sealed class SlimSession
{
    /// <summary>Random session id (32 hex characters), also the <c>sid</c> claim.</summary>
    public string Id { get; set; } = string.Empty;
    /// <summary>Owner of the session.</summary>
    public string UserId { get; set; } = string.Empty;
    /// <summary><c>cookie</c> or <c>bearer</c>.</summary>
    public string Mode { get; set; } = "cookie";
    /// <summary><c>pwd</c>, <c>mfa</c>, <c>ext</c>, <c>impersonation</c>, …</summary>
    public string AuthenticationMethod { get; set; } = string.Empty;
    /// <summary>Set for impersonation sessions (id of the admin).</summary>
    public string? ImpersonatorId { get; set; }
    /// <summary>Sign-in time.</summary>
    public DateTimeOffset CreatedUtc { get; set; }
    /// <summary>Last validation or refresh.</summary>
    public DateTimeOffset LastSeenUtc { get; set; }
    /// <summary>End of the session; SlimIdentity rejects it afterwards even if the row still exists.</summary>
    public DateTimeOffset ExpiresUtc { get; set; }
    /// <summary>Truncated to 256 characters. Personal data – the host decides whether to persist it.</summary>
    public string? UserAgent { get; set; }
    /// <summary>Client IP at sign-in. Personal data – the host decides whether to persist it.</summary>
    public string? IpAddress { get; set; }
}
