namespace SlimIdentity;

/// <summary>
/// Short-lived state that every instance must see: single-use markers (external-login exchange and link codes,
/// back-channel logout tokens) and counters (mails per recipient). The default keeps it in memory – correct for one
/// instance. With several instances register a shared implementation (<c>AddSharedState&lt;T&gt;()</c>; the EF Core
/// package registers one on the <c>SlimSharedState</c> table).
/// </summary>
/// <remarks>
/// <para>
/// Keys are at most 128 ASCII characters; SlimIdentity hands over SHA-256 hashes, never codes, tokens or addresses in
/// clear text. An entry whose expiry has passed counts as absent – remove such entries now and then (the operations
/// may do it on the way). Both operations must be atomic across all instances: a check followed by a separate write
/// lets two parallel requests both succeed.
/// </para>
/// <para>
/// When an operation throws, a single-use marker counts as already used (the request is rejected) and a counter falls
/// back to the instance's memory – both are logged (event 8006).
/// </para>
/// </remarks>
public interface ISlimSharedState
{
    /// <summary>
    /// Adds <paramref name="key"/> unless it exists and has not expired. True for exactly one of any number of
    /// parallel calls with the same key; false for every later call until <paramref name="expiresAt"/> has passed.
    /// </summary>
    /// <param name="key">The marker (at most 128 ASCII characters).</param>
    /// <param name="expiresAt">When the marker may be forgotten.</param>
    /// <param name="ct">Cancellation.</param>
    Task<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken ct);

    /// <summary>
    /// Increments the counter <paramref name="key"/> and returns its new value. The first increment – and the first
    /// after the window has passed – starts a new window of <paramref name="window"/> at 1 (fixed window). Parallel
    /// calls never return the same value within one window.
    /// </summary>
    /// <param name="key">The counter (at most 128 ASCII characters).</param>
    /// <param name="window">Length of the window, counted from its first increment.</param>
    /// <param name="ct">Cancellation.</param>
    Task<long> IncrementAsync(string key, TimeSpan window, CancellationToken ct);
}
