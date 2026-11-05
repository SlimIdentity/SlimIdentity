using System.Collections.Concurrent;

namespace SlimIdentity.Services;

/// <summary>
/// In-memory registry of consumed one-time nonces – the fallback that makes stateless one-time codes single use when no
/// <see cref="ISlimRefreshTokenStore"/> is registered. Per instance only: with several instances register a refresh-token
/// store, which then provides the atomic, shared consumption.
/// </summary>
internal sealed class SlimLocalNonceRegistry(TimeProvider time)
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _used = new(StringComparer.Ordinal);

    /// <summary>Returns true exactly once per nonce (until it expires).</summary>
    public bool TryConsume(string nonce, DateTimeOffset expiresAt)
    {
        var now = time.GetUtcNow();
        if (_used.Count > 1024)
            foreach (var (key, expiry) in _used)
                if (expiry <= now) _used.TryRemove(key, out _);

        return _used.TryAdd(nonce, expiresAt);
    }
}
