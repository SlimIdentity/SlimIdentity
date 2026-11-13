using System.Collections.Concurrent;

namespace SlimIdentity.Services;

/// <summary>
/// The default <see cref="ISlimSharedState"/>: in memory, per instance. Also the fallback for counters while a shared
/// implementation fails.
/// </summary>
/// <remarks>
/// Bounded: at most <see cref="MaxEntries"/> entries; expired ones are purged at most once per second once the table is
/// half full (one pass, never per request). A full table refuses new keys – fail closed: a code is rather rejected than
/// accepted twice, a new recipient rather gets no mail than an unlimited number (warning 8005). Existing keys keep
/// working.
/// </remarks>
internal sealed class SlimMemorySharedState(TimeProvider time, ILogger<SlimMemorySharedState>? logger = null) : ISlimSharedState
{
    internal const int MaxEntries = 200_000;
    private static readonly TimeSpan PurgeInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan FullWarningInterval = TimeSpan.FromMinutes(1);

    // a class, not a record: TryUpdate must compare references, not values
    private sealed class Entry(long count, DateTimeOffset expiresAt)
    {
        public long Count { get; } = count;
        public DateTimeOffset ExpiresAt { get; } = expiresAt;
    }

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private int _count;               // ConcurrentDictionary.Count takes every lock – too expensive per request
    private long _nextPurgeTicks;     // 0: purge at the first opportunity
    private long _nextWarningTicks;

    public Task<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken ct) => Task.FromResult(TryAdd(key, expiresAt));

    public Task<long> IncrementAsync(string key, TimeSpan window, CancellationToken ct) => Task.FromResult(Increment(key, window));

    internal bool TryAdd(string key, DateTimeOffset expiresAt)
    {
        ArgumentNullException.ThrowIfNull(key);
        var now = time.GetUtcNow();
        var added = new Entry(0, expiresAt);
        while (true)
        {
            if (_entries.TryGetValue(key, out var current))
            {
                if (current.ExpiresAt > now) return false;
                if (_entries.TryUpdate(key, added, current)) return true;
            }
            else
            {
                if (!HasRoom(now)) return false;
                if (_entries.TryAdd(key, added)) { Interlocked.Increment(ref _count); return true; }
            }
        }
    }

    /// <summary>The new count; <see cref="long.MaxValue"/> (over every limit) when the table is full.</summary>
    internal long Increment(string key, TimeSpan window)
    {
        ArgumentNullException.ThrowIfNull(key);
        var now = time.GetUtcNow();
        while (true)
        {
            if (_entries.TryGetValue(key, out var current))
            {
                var next = current.ExpiresAt > now ? new Entry(current.Count + 1, current.ExpiresAt) : new Entry(1, now + window);
                if (_entries.TryUpdate(key, next, current)) return next.Count;
            }
            else
            {
                if (!HasRoom(now)) return long.MaxValue;
                if (_entries.TryAdd(key, new Entry(1, now + window))) { Interlocked.Increment(ref _count); return 1; }
            }
        }
    }

    private bool HasRoom(DateTimeOffset now)
    {
        if (Volatile.Read(ref _count) >= MaxEntries / 2) Purge(now);
        if (Volatile.Read(ref _count) < MaxEntries) return true;

        var due = Interlocked.Read(ref _nextWarningTicks);
        if (logger is not null && now.UtcTicks >= due
            && Interlocked.CompareExchange(ref _nextWarningTicks, (now + FullWarningInterval).UtcTicks, due) == due)
            Log.SharedStateFull(logger, MaxEntries);
        return false;
    }

    private void Purge(DateTimeOffset now)
    {
        var due = Interlocked.Read(ref _nextPurgeTicks);
        if (now.UtcTicks < due || Interlocked.CompareExchange(ref _nextPurgeTicks, (now + PurgeInterval).UtcTicks, due) != due) return;
        foreach (var entry in _entries)
            if (entry.Value.ExpiresAt <= now && _entries.TryRemove(entry)) Interlocked.Decrement(ref _count);   // only if not renewed meanwhile
    }
}
