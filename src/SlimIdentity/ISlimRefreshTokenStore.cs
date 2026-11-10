namespace SlimIdentity;

/// <summary>
/// Optional capability: activates <c>/auth/refresh</c> (JWT rotation).
/// SlimIdentity only ever hands out the SHA-256 hash of a refresh token – store nothing else.
/// </summary>
public interface ISlimRefreshTokenStore
{
    /// <summary>Persists a newly issued refresh token (hash only) with its owner and expiry.</summary>
    Task StoreRefreshTokenAsync(string userId, string tokenHash, DateTimeOffset expiresAt, CancellationToken ct);

    /// <summary>
    /// Returns the owning user id if the hash exists and is not expired, and deletes it atomically
    /// (single use / rotation). Returns <c>null</c> otherwise.
    /// </summary>
    Task<string?> ValidateAndConsumeRefreshTokenAsync(string tokenHash, CancellationToken ct);
}
