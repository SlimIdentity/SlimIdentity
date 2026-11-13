using SlimIdentity.Security;

namespace SlimIdentity.Services;

/// <summary>
/// SlimIdentity's way to <see cref="ISlimSharedState"/>: hashes every key (no code, token or address reaches the
/// store in clear text) and decides what a failing store means – a single-use marker counts as used, a counter
/// continues in this instance's memory.
/// </summary>
internal sealed class SlimSharedStateAccess(ISlimSharedState state, SlimMemorySharedState local, ILogger<SlimSharedStateAccess> logger)
{
    internal const string ExchangeCode = "exchange-code";
    internal const string LinkCode = "link-code";
    internal const string BackChannelToken = "backchannel-jti";
    internal const string Mail = "mail";
    internal const string SignInFlow = "sign-in-flow";
    internal const string VerificationCodeFlow = "verification-code-flow";
    internal const string VerificationCodeAddress = "verification-code-address";

    /// <summary>True exactly once per <paramref name="purpose"/> and <paramref name="value"/> until <paramref name="expiresAt"/>.</summary>
    public async Task<bool> TryConsumeAsync(string purpose, string value, DateTimeOffset expiresAt, CancellationToken ct)
    {
        try
        {
            return await state.TryAddAsync(Key(purpose, value), expiresAt, ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            Log.SharedStateFailed(logger, ex, purpose);
            return false;   // fail closed: rather reject a code than accept it twice
        }
    }

    /// <summary>Counts one more event of <paramref name="purpose"/> and <paramref name="value"/> in a fixed window; returns the count.</summary>
    public async Task<long> CountAsync(string purpose, string value, TimeSpan window, CancellationToken ct)
    {
        var key = Key(purpose, value);
        try
        {
            return await state.IncrementAsync(key, window, ct);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            Log.SharedStateFailed(logger, ex, purpose);
            return local.Increment(key, window);   // still a limit, per instance
        }
    }

    internal static string Key(string purpose, string value) => SlimHashing.Sha256Hex($"slimidentity.{purpose}.v1:{value}");
}
