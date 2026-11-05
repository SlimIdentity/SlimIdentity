namespace SlimIdentity;

/// <summary>
/// Optional capability: activates <c>/auth/login/2fa</c> and the <c>/auth/2fa/*</c> management routes
/// (authenticator apps, e-mail codes, recovery codes).
/// </summary>
/// <remarks>
/// The store never sees secrets in clear text: TOTP secrets arrive encrypted with Data Protection
/// (purpose <see cref="SlimIdentityDefaults.TotpSecretProtectionPurpose"/>), recovery codes as salted SHA-256 hashes.
/// </remarks>
public interface ISlimTwoFactorStore
{
    /// <summary>The encrypted TOTP secret as stored by <see cref="SetTotpSecretAsync"/>, or <c>null</c>/empty if the user uses e-mail codes.</summary>
    Task<string?> GetTotpSecretAsync(SlimUser user, CancellationToken ct);

    /// <summary>Stores the encrypted TOTP secret. An empty string removes the authenticator.</summary>
    Task SetTotpSecretAsync(SlimUser user, string protectedSecret, CancellationToken ct);

    /// <summary>Replaces <b>all</b> existing recovery codes of the user (hashes). An empty list removes them.</summary>
    Task StoreRecoveryCodesAsync(SlimUser user, IEnumerable<string> hashedCodes, CancellationToken ct);

    /// <summary>Returns true and deletes the code <b>atomically</b> if the hash belongs to the user (single use).</summary>
    Task<bool> ValidateAndConsumeRecoveryCodeAsync(SlimUser user, string hashedCode, CancellationToken ct);

    /// <summary>
    /// Replay protection (RFC 6238 §5.2): stores <paramref name="usedAt"/> (unix milliseconds of the code's time step or
    /// issue time, a 64-bit value) and returns <c>true</c> only if it is <b>greater</b> than the value stored before. Must be atomic, e.g.
    /// <c>UPDATE users SET last_2fa_code_at = @usedAt WHERE id = @id AND (last_2fa_code_at IS NULL OR last_2fa_code_at &lt; @usedAt)</c>
    /// and return whether a row was updated. A code is thereby accepted at most once.
    /// </summary>
    Task<bool> TryMarkCodeUsedAsync(SlimUser user, long usedAt, CancellationToken ct);

    /// <summary>
    /// Makes a sign-in challenge (<c>preAuthToken</c>) single use: stores <paramref name="issuedAt"/> (unix milliseconds
    /// at which the challenge was issued) and returns <c>true</c> only if it is <b>greater</b> than the value stored
    /// before. Same atomic compare-and-set as <see cref="TryMarkCodeUsedAsync"/>, but on a <b>separate</b> value, e.g.
    /// <c>UPDATE users SET last_2fa_challenge_at = @issuedAt WHERE id = @id AND (last_2fa_challenge_at IS NULL OR last_2fa_challenge_at &lt; @issuedAt)</c>.
    /// </summary>
    Task<bool> TryMarkChallengeUsedAsync(SlimUser user, long issuedAt, CancellationToken ct);
}
