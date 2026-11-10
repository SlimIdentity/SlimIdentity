using System.Collections.Concurrent;

namespace SlimIdentity.Services;

/// <summary>
/// In-memory registry of consumed one-time nonces – the fallback that makes stateless one-time codes single use when no
/// <see cref="ISlimRefreshTokenStore"/> is registered. Per instance only: with several instances register a refresh-token
/// store, which then provides the atomic, shared consumption.
/// </summary>
/// <remarks>
/// Bounded: at most <see cref="MaxEntries"/> nonces are tracked; expired ones are purged at most once per second (one
/// pass over the table, never per request). A full table refuses new nonces – fail closed: a code is rather rejected
/// than accepted a second time.
/// </remarks>
internal sealed class SlimLocalNonceRegistry(TimeProvider time)
{
    internal const int MaxEntries = 100_000;
    private static readonly TimeSpan PurgeInterval = TimeSpan.FromSeconds(1);

    private readonly ConcurrentDictionary<string, DateTimeOffset> _used = new(StringComparer.Ordinal);
    private long _nextPurgeTicks;   // 0: purge at the first opportunity

    /// <summary>Returns true exactly once per nonce (until it expires); false for a reuse or when the table is full.</summary>
    public bool TryConsume(string nonce, DateTimeOffset expiresAt)
    {
        var now = time.GetUtcNow();
        if (_used.Count >= MaxEntries / 2) Purge(now);
        if (_used.Count >= MaxEntries) return false;
        return _used.TryAdd(nonce, expiresAt);
    }

    private void Purge(DateTimeOffset now)
    {
        var due = Interlocked.Read(ref _nextPurgeTicks);
        if (now.UtcTicks < due || Interlocked.CompareExchange(ref _nextPurgeTicks, (now + PurgeInterval).UtcTicks, due) != due) return;
        foreach (var (key, expiry) in _used)
            if (expiry <= now) _used.TryRemove(key, out _);
    }
}
