using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace SlimIdentity.EntityFrameworkCore.Tests;

/// <summary>
/// Review finding R4: a host endpoint and SlimIdentity run in the same request scope – the stores must neither detach
/// the host's tracked entities nor save its pending changes along with their own.
/// </summary>
public sealed class SharedContextTests
{
    private static async Task<ServiceProvider> CreateAsync()
    {
        var file = new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(Path.GetTempPath(), $"slimidentity-shared-{Guid.NewGuid():N}.db"), Pooling = false,
        }.ToString();
        var services = new ServiceCollection();
        services.AddDbContext<GuidContext>(o => o.UseSqlite(file));
        services.AddSingleton(TimeProvider.System);
        services.AddSlimIdentity(o => o.Tokens.JwtSecret = new string('x', 32)).AddEntityFrameworkStores<GuidContext, GuidUser, Guid>();
        var sp = services.BuildServiceProvider();

        await using var setup = sp.CreateAsyncScope();
        var db = setup.ServiceProvider.GetRequiredService<GuidContext>();
        await db.Database.EnsureCreatedAsync();
        db.Users.Add(new GuidUser { Email = "a@test.local", NormalizedEmail = "A@TEST.LOCAL", SecurityStamp = "s" });
        await db.SaveChangesAsync();
        return sp;
    }

    private static async Task<GuidUser> StoredUserAsync(ServiceProvider sp)
    {
        await using var check = sp.CreateAsyncScope();
        return await check.ServiceProvider.GetRequiredService<GuidContext>().Users.AsNoTracking().SingleAsync();
    }

    [Fact]
    public async Task Storing_a_refresh_token_does_not_detach_the_hosts_tracked_entities()
    {
        await using var sp = await CreateAsync();
        await using var scope = sp.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<GuidContext>();
        var refresh = scope.ServiceProvider.GetRequiredService<ISlimRefreshTokenStore>();

        var user = await db.Users.SingleAsync();          // host loads its entity …
        await refresh.StoreRefreshTokenAsync(user.Id.ToString(), new string('a', 64), DateTimeOffset.UtcNow.AddHours(1), default);   // … sign-in issues a token …
        user.DisplayName = "changed after sign-in";       // … the host continues its own work
        await db.SaveChangesAsync();

        Assert.Equal("changed after sign-in", (await StoredUserAsync(sp)).DisplayName);
    }

    [Fact]
    public async Task A_store_operation_does_not_save_the_hosts_pending_changes()
    {
        await using var sp = await CreateAsync();
        await using var scope = sp.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<GuidContext>();
        var sessions = scope.ServiceProvider.GetRequiredService<ISlimSessionStore>();

        var user = await db.Users.SingleAsync();
        user.DisplayName = "half-done host work";        // the host has not decided to save yet …
        await sessions.CreateAsync(new SlimSession                                    // … and a session is created
        {
            Id = new string('b', 32), UserId = user.Id.ToString(), AuthenticationMethod = "pwd",
            CreatedUtc = DateTimeOffset.UtcNow, LastSeenUtc = DateTimeOffset.UtcNow, ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1),
        }, default);

        Assert.Null((await StoredUserAsync(sp)).DisplayName);
    }
}
