using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace SlimIdentity.Tests.Integration;

/// <summary>The development mail sender must not leak live links and codes into production logs.</summary>
public sealed class NullEmailSenderGuardTests
{
    private static WebApplication Build(string environment, Action<SlimIdentityBuilder> configure)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = environment });
        builder.WebHost.UseTestServer();
        configure(builder.Services.AddSlimIdentity(o => o.Tokens.JwtSecret = new string('x', 32))
            .AddUserStore<Infrastructure.TestUserStore>(ServiceLifetime.Singleton));
        return builder.Build();
    }

    [Fact]
    public async Task Null_sender_stops_the_start_in_production()
    {
        await using var app = Build(Environments.Production, b => b.AddNullEmailSender());
        var ex = Assert.Throws<InvalidOperationException>(() => app.MapSlimIdentityApi());
        Assert.Contains("AddNullEmailSender", ex.Message);
    }

    [Theory]
    [InlineData("Development")]
    [InlineData("Staging")]
    public async Task Null_sender_is_fine_outside_production(string environment)
    {
        await using var app = Build(environment, b => b.AddNullEmailSender());
        app.MapSlimIdentityApi();
    }

    [Fact]
    public async Task Null_sender_can_be_allowed_in_production_explicitly()
    {
        await using var app = Build(Environments.Production, b => b.AddNullEmailSender(allowInProduction: true));
        app.MapSlimIdentityApi();
    }

    [Fact]
    public async Task A_real_sender_registered_later_replaces_the_guard()
    {
        await using var app = Build(Environments.Production, b => b.AddNullEmailSender().AddEmailSender<Infrastructure.CapturingEmailSender>());
        app.MapSlimIdentityApi();
    }
}
