namespace SlimIdentity.Services;

/// <summary>
/// Serializes the credential attempts (password, second factor, password confirmation) of one account within this
/// instance: lockout check, evaluation and counting run as one step, so parallel guesses cannot all pass the lockout
/// check before the first failure is recorded. Legitimate users never send parallel sign-ins; the queue only slows
/// down whoever races guesses. Across several instances, at most one attempt per instance can overlap at a lockout
/// boundary (documented in docs/security.md).
/// </summary>
internal sealed class SlimAttemptGate
{
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    /// <summary>The gate key of an account: its normalized e-mail (known before the account is loaded at sign-in).</summary>
    public static string KeyFor(string email) => Security.SlimEmailAddress.Normalize(email) ?? email;

    /// <summary>Waits until no other attempt for <paramref name="key"/> (the normalized e-mail) runs in this instance.</summary>
    public async Task<Lease> EnterAsync(string key, CancellationToken ct)
    {
        Entry entry;
        lock (_entries)
        {
            if (!_entries.TryGetValue(key, out entry!)) _entries[key] = entry = new Entry();
            entry.Holders++;
        }

        try
        {
            await entry.Semaphore.WaitAsync(ct);
        }
        catch
        {
            Leave(key, entry, entered: false);
            throw;
        }
        return new Lease(this, key, entry);
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
