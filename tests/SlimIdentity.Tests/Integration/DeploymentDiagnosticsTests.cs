using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Deployment mistakes behind load balancers and with several instances are reported, not silently tolerated.</summary>
public sealed class DeploymentDiagnosticsTests
{
    [Fact]
    public async Task Unapplied_forwarded_headers_are_reported_once_per_proxy()
    {
        var logs = new CapturingLoggerProvider();
        await using var app = await TestApp.StartAsync(new TestAppOptions { LoggerProvider = logs });
        var client = app.CreateClient();
        var forwarded = new Dictionary<string, string> { ["X-Forwarded-For"] = "203.0.113.7" };

        for (var i = 0; i < 3; i++)
            await client.SendAsync(HttpMethod.Post, "/auth/login", new { email = TestApp.UserEmail, password = "wrong" }, forwarded);

        Assert.Equal(1, logs.EventIds.Count(id => id == 8001));
    }

    [Fact]
    public async Task Applied_forwarded_headers_are_not_reported()
    {
        var logs = new CapturingLoggerProvider();
        await using var app = await TestApp.StartAsync(new TestAppOptions { LoggerProvider = logs });
        // what UseForwardedHeaders leaves behind when it applied the header
        var applied = new Dictionary<string, string> { ["X-Forwarded-For"] = "198.51.100.1", ["X-Original-For"] = "10.0.0.5:4711" };

        await app.CreateClient().SendAsync(HttpMethod.Post, "/auth/login", new { email = TestApp.UserEmail, password = "wrong" }, applied);

        Assert.DoesNotContain(8001, logs.EventIds);
    }

    private static async Task<CapturingLoggerProvider> StartInProductionAsync(Action<IServiceCollection> configure, Action<SlimIdentityBuilder>? slim = null)
    {
        var logs = new CapturingLoggerProvider();
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = Environments.Production });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Logging.AddProvider(logs);
        configure(builder.Services);
        var identity = builder.Services.AddSlimIdentity(o => o.Tokens.JwtSecret = new string('x', 32))
            .AddUserStore<TestUserStore>(ServiceLifetime.Singleton)
            .AddEmailSender<CapturingEmailSender>(ServiceLifetime.Singleton);
        slim?.Invoke(identity);
        await using var app = builder.Build();
        app.MapSlimIdentityApi();
        return logs;
    }

    [Fact]
    public async Task Local_key_ring_and_missing_application_name_are_reported_in_production()
    {
        var logs = await StartInProductionAsync(_ => { });
        Assert.True(logs.EventIds.Contains(8002) && logs.EventIds.Contains(8003),
            "events: " + string.Join(", ", logs.EventIds.Distinct()) + "\n" + string.Join("\n", logs.Entries.Where(e => e.Contains("DataProtection", StringComparison.Ordinal))));
    }

    [Fact]
    public async Task A_shared_key_ring_with_an_application_name_is_not_reported()
    {
        var keys = Directory.CreateTempSubdirectory("slim-keys");
        var logs = await StartInProductionAsync(s => s.AddDataProtection().PersistKeysToFileSystem(keys).SetApplicationName("my-app"));
        Assert.DoesNotContain(8002, logs.EventIds);
        Assert.DoesNotContain(8003, logs.EventIds);
    }

    [Fact]
    public async Task In_memory_shared_state_is_reported_in_production()
    {
        var without = await StartInProductionAsync(_ => { });
        Assert.Contains(8004, without.EventIds);

        var with = await StartInProductionAsync(_ => { }, b => b.AddSharedState<TestSharedState>(ServiceLifetime.Singleton));
        Assert.DoesNotContain(8004, with.EventIds);
    }

    [Fact]
    public async Task Without_UseRateLimiter_the_brute_force_limit_is_not_silently_off()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.WebHost.UseTestServer();
        builder.Services.AddSlimIdentity(o => o.RateLimit.PermitLimit = 2)
            .AddUserStore<TestUserStore>(ServiceLifetime.Singleton)
            .AddNullEmailSender();
        await using var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapSlimIdentityApi();   // no app.UseRateLimiter()
        await app.StartAsync();
        var client = new ApiClient(app.GetTestClient());

        var error = await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
            client.PostAsync("/auth/login", new { email = "nobody@test.local", password = "Whatever-123" }));
        Assert.Contains("UseRateLimiter", error.Message);
        await app.StopAsync();
    }
}
