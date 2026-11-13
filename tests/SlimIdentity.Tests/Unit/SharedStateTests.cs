using System.Globalization;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using SlimIdentity.Services;

namespace SlimIdentity.Tests.Unit;

public sealed class SharedStateTests
{
    private static FakeTimeProvider Clock() => new(DateTimeOffset.Parse("2026-01-01T00:00:00Z", CultureInfo.InvariantCulture));

    [Fact(Timeout = 30_000)]
    public async Task The_in_memory_shared_state_is_bounded_and_stays_fast()
    {
        await Task.Yield();
        var time = Clock();
        var state = new SlimMemorySharedState(time);
        var expiry = time.GetUtcNow().AddMinutes(5);

        for (var i = 0; i < SlimMemorySharedState.MaxEntries; i++)
            Assert.True(state.TryAdd($"nonce-{i}", expiry));
        Assert.False(state.TryAdd("nonce-0", expiry));                        // single use
        Assert.False(state.TryAdd("one-too-many", expiry));                   // full: refused (fail closed), no growth
        Assert.Equal(long.MaxValue, state.Increment("counter", TimeSpan.FromMinutes(5)));   // over every limit

        time.Advance(TimeSpan.FromMinutes(6));                                  // all expired
        Assert.True(state.TryAdd("after-expiry", time.GetUtcNow().AddMinutes(5)));
    }

    [Fact]
    public async Task A_full_mail_throttle_fails_closed_until_its_window_ends()
    {
        var time = Clock();
        var memory = new SlimMemorySharedState(time);
        var throttle = new SlimMailThrottle(new SlimSharedStateAccess(memory, memory, NullLogger<SlimSharedStateAccess>.Instance));

        // a distributed attacker fills the table with fresh recipients
        for (var i = 0; i < SlimMemorySharedState.MaxEntries; i++)
            Assert.True(await throttle.TryAcquireAsync(SlimEmailKinds.Verification, $"bot-{i}@example.invalid", default));

        var allowedForVictim = 0;
        for (var i = 0; i < 20; i++)
            if (await throttle.TryAcquireAsync(SlimEmailKinds.PasswordReset, "victim@example.com", default)) allowedForVictim++;
        Assert.True(allowedForVictim <= SlimMailThrottle.PerKindAndRecipient, $"{allowedForVictim} mails to victim@example.com were allowed.");
        Assert.False(await throttle.TryAcquireAsync(SlimEmailKinds.Verification, "late@example.com", default));

        time.Advance(SlimMailThrottle.Window + TimeSpan.FromMinutes(1));

        Assert.True(await throttle.TryAcquireAsync(SlimEmailKinds.Verification, "late@example.com", default));
    }
}
