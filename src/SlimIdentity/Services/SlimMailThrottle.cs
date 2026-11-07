using System.Collections.Concurrent;

namespace SlimIdentity.Services;

/// <summary>
/// Limits mails per recipient and kind (attack scenario "mail bombing": the per-IP rate limit does not stop a
/// distributed attacker from flooding one inbox with reset or verification mails). Requests over the limit get the
/// same answer as always – the mail is just not sent. In memory, per instance: with several instances the effective
/// limit is a multiple, which still bounds the flood.
/// </summary>
internal sealed class SlimMailThrottle(TimeProvider time)
{
    internal static readonly TimeSpan Window = TimeSpan.FromMinutes(15);
    internal const int PerKindAndRecipient = 3;
    internal const int TwoFactorCodesPerRecipient = 5;   // users legitimately retry a sign-in more often
    private const int MaxTrackedRecipients = 100_000;     // memory bound; beyond it mails are allowed (fail open)

    private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _sent = new(StringComparer.Ordinal);
    private long _calls;

    /// <summary>True if a mail of <paramref name="kind"/> may be sent to <paramref name="recipient"/> now (and counts it).</summary>
    public bool TryAcquire(string kind, string recipient)
    {
        var now = time.GetUtcNow();
        if (Interlocked.Increment(ref _calls) % 1024 == 0) Purge(now);

        var key = $"{kind}\n{recipient.Trim().ToUpperInvariant()}";
        if (!_sent.TryGetValue(key, out var sent))
        {
            if (_sent.Count >= MaxTrackedRecipients) return true;
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

