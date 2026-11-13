using SlimIdentity.Services;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Unit;

public sealed class SecurityWritesTests
{
    private const string Email = "cas@test.local";

    [Fact]
    public async Task A_bound_write_is_applied_again_after_a_concurrent_change_of_the_claims_part_only()
    {
        var (store, stale, stamp) = await SeededAsync();
        await store.UpdateSecurityStampAsync(stale, stamp, SlimUser.WithNewClaimsPart(stamp), default);   // roles changed

        Assert.True(await store.TryWriteSecurityStateAsync(stale, u => u.EmailConfirmed = true, default));
        var saved = store.Get(Email);
        Assert.True(saved.EmailConfirmed);
        Assert.Equal(saved.SecurityStamp, stale.SecurityStamp);
        Assert.True(SlimUser.IsSameSecurityState(saved.SecurityStamp, stamp));
    }

    [Fact]
    public async Task A_bound_write_fails_after_a_concurrent_change_of_the_security_part()
    {
        var (store, stale, stamp) = await SeededAsync();
        var rotated = SlimUser.NewSecurityStamp();
        await store.UpdateSecurityStampAsync(stale, stamp, rotated, default);   // e.g. a password change elsewhere

        Assert.False(await store.TryWriteSecurityStateAsync(stale, u => u.EmailConfirmed = true, default));
        Assert.False(store.Get(Email).EmailConfirmed);
        Assert.Equal(rotated, stale.SecurityStamp);   // the caller holds the current state
    }

    [Fact]
    public async Task An_unconditional_write_is_applied_on_top_of_a_concurrent_change()
    {
        var (store, stale, stamp) = await SeededAsync();
        var fresh = store.Get(Email);
        fresh.PasswordChangeRequired = true;
        fresh.SecurityStamp = SlimUser.NewSecurityStamp();
        await store.UpdateSecurityStateAsync(fresh, stamp, default);

        Assert.True(await store.WriteSecurityStateAsync(stale, u => u.EmailConfirmed = true, default));
        var saved = store.Get(Email);
        Assert.True(saved.EmailConfirmed);
        Assert.True(saved.PasswordChangeRequired);   // the concurrent change is kept, not written back over
    }

    [Fact]
    public async Task Every_write_changes_the_stamp()
    {
        var (store, user, stamp) = await SeededAsync();

        Assert.True(await store.WriteSecurityStateAsync(user, u => u.EmailConfirmed = true, default));
        Assert.NotEqual(stamp, store.Get(Email).SecurityStamp);
        Assert.True(SlimUser.IsSameSecurityState(store.Get(Email).SecurityStamp, stamp));   // the security state is the same
    }

    private static async Task<(TestUserStore Store, SlimUser User, string Stamp)> SeededAsync()
    {
        var store = new TestUserStore();
        var user = store.Seed(Email, password: null);
        var stamp = SlimUser.NewSecurityStamp();
        user.EmailConfirmed = false;
        user.SecurityStamp = stamp;
        await store.UpdateSecurityStateAsync(user, default);
        return (store, user, stamp);
    }
}
