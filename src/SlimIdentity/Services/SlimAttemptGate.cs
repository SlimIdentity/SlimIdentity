namespace SlimIdentity.Services;

/// <summary>
/// Serializes the credential attempts (password, second factor, password confirmation) of one account within this
/// instance: lockout check, evaluation and counting run as one step, so parallel guesses cannot all pass the lockout
/// check before the first failure is recorded. The key is the user id – never the address as typed, whose spelling
/// the store may treat as equal. Legitimate users never send parallel sign-ins; at most
/// <see cref="MaxWaitingPerAccount"/> attempts wait per account, further ones are refused at once without being
/// evaluated. Across several instances, at most one attempt per instance can overlap at a lockout boundary
/// (documented in docs/security.md).
/// </summary>
internal sealed class SlimAttemptGate
{
    /// <summary>Attempts that may wait behind the running one of the same account.</summary>
    public const int MaxWaitingPerAccount = 8;

    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    /// <summary>
    /// Waits until no other attempt for <paramref name="userId"/> runs in this instance. Returns <c>null</c> without
    /// waiting when <see cref="MaxWaitingPerAccount"/> attempts are already queued – answer as for a failed attempt.
    /// </summary>
    public async Task<Lease?> TryEnterAsync(string userId, CancellationToken ct)
    {
        Entry entry;
        lock (_entries)
        {
            if (!_entries.TryGetValue(userId, out entry!)) _entries[userId] = entry = new Entry();
            if (entry.Holders > MaxWaitingPerAccount) return null;   // one running + MaxWaitingPerAccount waiting
            entry.Holders++;
        }

        try
        {
            await entry.Semaphore.WaitAsync(ct);
        }
        catch
        {
            Leave(userId, entry, entered: false);
            throw;
        }
        return new Lease(this, userId, entry);
    }

    private void Leave(string key, Entry entry, bool entered)
    {
        if (entered) entry.Semaphore.Release();
        lock (_entries)
        {
            if (--entry.Holders != 0) return;
            _entries.Remove(key);
        }
        entry.Dispose();   // nobody waits on it any more – a later attempt creates a new entry
    }

    internal sealed class Entry : IDisposable
    {
        public readonly SemaphoreSlim Semaphore = new(1, 1);
        public int Holders;   // waiting + running – the entry is removed when the last one leaves
        public void Dispose() => Semaphore.Dispose();
    }

    internal sealed class Lease(SlimAttemptGate gate, string key, Entry entry) : IDisposable
    {
        private int _disposed;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0) gate.Leave(key, entry, entered: true);
        }
    }
}
