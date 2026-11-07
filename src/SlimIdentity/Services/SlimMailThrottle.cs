using System.Collections.Concurrent;

namespace SlimIdentity.Services;

/// <summary>
/// Limits mails per recipient and kind (attack scenario "mail bombing": the per-IP rate limit does not stop a
/// distributed attacker from flooding one inbox with reset or verification mails). Requests over the limit get the
/// same answer as always – the mail is just not sent. In memory, per instance: with several instances the effective
/// limit is a multiple, which still bounds the flood.
/// </summary>
/// <remarks>
/// The table is bounded. When it is full of recipients from the last 15 minutes (a distributed flood of fresh
/// addresses), new recipients get no mail until entries expire – it fails closed: failing open would switch the
/// protection off for every inbox exactly while it is attacked. Recipients already tracked keep their normal limit.
/// </remarks>
internal sealed class SlimMailThrottle(TimeProvider time, ILogger<SlimMailThrottle>? logger = null)
{
    internal static readonly TimeSpan Window = TimeSpan.FromMinutes(15);
    internal const int PerKindAndRecipient = 3;
    internal const int TwoFactorCodesPerRecipient = 5;   // users legitimately retry a sign-in more often
    internal const int MaxTrackedRecipients = 100_000;    // memory bound; when full, new recipients get no mail
    private static readonly TimeSpan FullPurgeInterval = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _sent = new(StringComparer.Ordinal);
    private long _calls;
    private long _lastFullPurgeTicks;   // 0: no purge yet

    /// <summary>True if a mail of <paramref name="kind"/> may be sent to <paramref name="recipient"/> now (and counts it).</summary>
    public bool TryAcquire(string kind, string recipient)
    {
        var now = time.GetUtcNow();
        if (Interlocked.Increment(ref _calls) % 1024 == 0) Purge(now);

        var key = $"{kind}\n{recipient.Trim().ToUpperInvariant()}";
        if (!_sent.TryGetValue(key, out var sent))
        {
            if (_sent.Count >= MaxTrackedRecipients && !MakeRoom(now)) return false;   // fail closed, see remarks
            sent = _sent.GetOrAdd(key, _ => new Queue<DateTimeOffset>());
        }

        var limit = kind == SlimEmailKinds.TwoFactorCode ? TwoFactorCodesPerRecipient : PerKindAndRecipient;
        lock (sent)
        {
            while (sent.Count > 0 && now - sent.Peek() >= Window) sent.Dequeue();
            if (sent.Count >= limit) return false;
            sent.Enqueue(now);
            return true;
        }
    }

    /// <summary>
    /// The table is full: drop expired entries – at most once per minute, so a flood cannot make every request scan
    /// the whole table. True if there is room again.
    /// </summary>
    private bool MakeRoom(DateTimeOffset now)
    {
        var last = Interlocked.Read(ref _lastFullPurgeTicks);
        if (now.UtcTicks - last >= FullPurgeInterval.Ticks
            && Interlocked.CompareExchange(ref _lastFullPurgeTicks, now.UtcTicks, last) == last)
        {
            Purge(now);
            if (_sent.Count >= MaxTrackedRecipients && logger is not null) Log.MailThrottleFull(logger, MaxTrackedRecipients);
        }
        return _sent.Count < MaxTrackedRecipients;
    }

    private void Purge(DateTimeOffset now)
    {
        foreach (var (key, sent) in _sent)
        {
            lock (sent)
            {
                if (sent.Count == 0 || now - sent.Last() >= Window) _sent.TryRemove(key, out _);
            }
        }
    }
}

