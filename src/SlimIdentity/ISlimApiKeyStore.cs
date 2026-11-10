namespace SlimIdentity;

/// <summary>
/// Optional capability: activates the <c>X-API-Key</c> authentication handler for M2M access.
/// The key is never passed in clear text – only its SHA-256 hex hash (see <see cref="SlimApiKeys"/>).
/// </summary>
public interface ISlimApiKeyStore
{
    /// <summary>Claims of the key owner, or <c>null</c> if the key is unknown / revoked / expired.</summary>
    Task<IReadOnlyCollection<Claim>?> ValidateApiKeyAsync(string keyHash, CancellationToken ct);
}
