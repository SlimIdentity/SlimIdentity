using System.Net;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// The first administrator, created by code at start-up – outside any request – exactly as docs/guides/seeding.md shows.
/// </summary>
public sealed class SeedingTests
{
    private const string AdminEmail = "first-admin@test.local";

    // ---- the snippet of the guide (only the names of the configuration values differ)
    private static async Task SeedAdministratorAsync(IServiceProvider services, string email, string startPassword, CancellationToken ct)
    {
        await using var scope = services.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<ISlimUserStore>();
        var auth = scope.ServiceProvider.GetRequiredService<ISlimAuthManager>();

        if (await store.FindByEmailAsync(email, ct) is not null) return;                  // already there: nothing to do
        var admin = await store.CreateAsync(new SlimNewUser { Email = email }, ct);        // Profile = your data (role, name)
        if (admin is null) return;                                                         // created in parallel by another instance

        admin.EmailConfirmed = true;                                                       // you vouch for the address
        await store.UpdateSecurityStateAsync(admin, admin.SecurityStamp, ct);
        if (await auth.SetPasswordAsync(admin, startPassword, mustChange: true, ct) is not null)   // 400 with the violated rules
            throw new InvalidOperationException("The start password does not meet the password rules.");
    }
    // ----

    [Fact]
    public async Task The_seeded_administrator_signs_in_once_with_the_start_password_and_chooses_an_own_one()
    {
        await using var app = await TestApp.StartAsync();
        await SeedAdministratorAsync(app.App.Services, AdminEmail, "Start-Password-123", default);
        await SeedAdministratorAsync(app.App.Services, AdminEmail, "Another-Start-456", default);   // idempotent

        var client = app.CreateClient();
        var first = await client.PostJsonAsync("/auth/login", new { email = AdminEmail, password = "Start-Password-123" });
        Assert.Equal("change_password", first.GetProperty("actions")[0].GetString());

        var session = await client.PostJsonAsync("/auth/login/password-change",
            new { flowToken = first.Str("flowToken"), newPassword = "Own-Admin-Password-789" });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
        Assert.True(app.Users.Get(AdminEmail).EmailConfirmed);
    }

    [Fact]
    public async Task Without_a_start_password_a_reset_link_hands_the_account_over()
    {
        await using var app = await TestApp.StartAsync();
        string token;
        await using (var scope = app.App.Services.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ISlimUserStore>();
            var auth = scope.ServiceProvider.GetRequiredService<ISlimAuthManager>();
            var admin = (await store.CreateAsync(new SlimNewUser { Email = AdminEmail }, default))!;
            token = (await auth.CreatePasswordResetAsync(admin, TimeSpan.FromDays(1))).Token;   // log or print the link once
        }

        // an administrator's link proves no mailbox: the address is confirmed with a mailed code first
        var client = app.CreateClient();
        var started = await client.PostJsonAsync("/auth/flow", new { token });
        Assert.Equal("verify_email", started.GetProperty("actions")[0].GetString());
        var code = (await app.Mail.WaitForAsync("verification-code", AdminEmail)).Payload;
        var verified = await client.PostJsonAsync("/auth/login/verify-email", new { flowToken = started.Str("flowToken"), code });
        Assert.Equal("set_credential", verified.GetProperty("actions")[0].GetString());
        await client.PostJsonAsync("/auth/register/password", new { flowToken = verified.Str("flowToken"), password = "Own-Admin-Password-789" });

        await app.CreateClient().PostJsonAsync("/auth/login", new { email = AdminEmail, password = "Own-Admin-Password-789" });
    }
}
