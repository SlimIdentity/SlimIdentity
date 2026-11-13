using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// Claims are a snapshot of their issuance. RefreshClaimsAsync changes only the claims part of the security stamp:
/// running sessions pick up the new claims at their next validation – without a sign-out, and without reloading
/// claims as long as nothing changed.
/// </summary>
public sealed class ClaimsRefreshTests
{
    private static TestAppOptions WithAdminOnlyEndpoint() => new()
    {
        Map = app => app.MapGet("/api/admin-only", () => "secret").RequireAuthorization(p => p.RequireRole("Admin")),
    };

    private static async Task RevokeAdminRoleAsync(TestApp app)
    {
        var admin = app.Users.Get(TestApp.AdminEmail);
        app.Users.SetRoles(admin.Id);   // the host removes the role in its own data …
        await using var scope = app.App.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<ISlimAuthManager>().RefreshClaimsAsync(admin);   // … and says so
    }

    private static async Task<ApiClient> CookieAdminAsync(TestApp app)
    {
        var browser = app.CreateClient();
        browser.SendCsrfHeader = true;
        await browser.PostJsonAsync("/auth/login?useCookies=true", new { email = TestApp.AdminEmail, password = TestApp.AdminPassword });
        return browser;
    }

    [Fact]
    public async Task A_cookie_session_loses_a_revoked_role_without_being_signed_out()
    {
        await using var app = await TestApp.StartAsync(WithAdminOnlyEndpoint());   // cookies re-validated on every request in tests
        var browser = await CookieAdminAsync(app);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/admin-only")).StatusCode);

        await RevokeAdminRoleAsync(app);

        Assert.Equal(HttpStatusCode.Forbidden, (await browser.GetAsync("/api/admin-only")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/auth/me")).StatusCode);   // still signed in
    }

    [Fact]
    public async Task A_bearer_session_loses_a_revoked_role_at_once_and_its_refresh_issues_the_new_claims()
    {
        await using var app = await TestApp.StartAsync(WithAdminOnlyEndpoint());
        var tokens = await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword);
        var api = app.CreateClient();
        api.BearerToken = tokens.AccessToken;
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync("/api/admin-only")).StatusCode);

        await RevokeAdminRoleAsync(app);

        Assert.Equal(HttpStatusCode.Forbidden, (await api.GetAsync("/api/admin-only")).StatusCode);   // same token, new claims
        Assert.Equal(HttpStatusCode.OK, (await api.GetAsync("/auth/me")).StatusCode);

        var refreshed = await app.CreateClient().PostJsonAsync("/auth/refresh", new { refreshToken = tokens.RefreshToken });
        api.BearerToken = refreshed.Str("accessToken");
        Assert.Equal(HttpStatusCode.Forbidden, (await api.GetAsync("/api/admin-only")).StatusCode);
    }

    [Fact]
    public async Task Without_a_change_no_claims_are_reloaded()
    {
        await using var app = await TestApp.StartAsync(WithAdminOnlyEndpoint());
        var browser = await CookieAdminAsync(app);
        var api = app.CreateClient();
        api.BearerToken = (await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword)).AccessToken;
        var loadsAfterSignIn = app.Users.ClaimsLoads;

        for (var i = 0; i < 10; i++)
        {
            await browser.GetAsync("/api/admin-only");
            await api.GetAsync("/api/admin-only");
        }

        Assert.Equal(loadsAfterSignIn, app.Users.ClaimsLoads);
    }

    [Fact]
    public async Task Without_RefreshClaimsAsync_a_session_keeps_its_snapshot()
    {
        // documented behaviour: changing the host's data alone does not reach running sessions
        await using var app = await TestApp.StartAsync(WithAdminOnlyEndpoint());
        var browser = await CookieAdminAsync(app);
        app.Users.SetRoles(app.Users.Get(TestApp.AdminEmail).Id);

        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/admin-only")).StatusCode);
    }

    [Fact]
    public async Task Links_refresh_tokens_and_remembered_state_survive_a_claims_change()
    {
        await using var app = await TestApp.StartAsync(WithAdminOnlyEndpoint());
        var tokens = await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword);
        await app.CreateClient().PostAsync("/auth/forgot-password", new { email = TestApp.AdminEmail });
        var resetLink = (await app.Mail.WaitForAsync("password-reset", TestApp.AdminEmail)).Payload;

        await RevokeAdminRoleAsync(app);

        await app.CreateClient().PostJsonAsync("/auth/refresh", new { refreshToken = tokens.RefreshToken });
        await app.CreateClient().ResetPasswordJsonAsync(resetLink, "New-Admin-Pass-2026");
    }

    [Fact]
    public async Task A_security_change_still_ends_every_session()
    {
        await using var app = await TestApp.StartAsync(WithAdminOnlyEndpoint());
        var browser = await CookieAdminAsync(app);
        await RevokeAdminRoleAsync(app);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/auth/me")).StatusCode);

        await using var scope = app.App.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<ISlimAuthManager>().SignOutEverywhereAsync(app.Users.Get(TestApp.AdminEmail));

        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task An_impersonation_stays_an_impersonation_after_a_claims_change()
    {
        await using var app = await TestApp.StartAsync(WithAdminOnlyEndpoint());
        var admin = app.CreateClient();
        admin.BearerToken = (await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword)).AccessToken;
        var impersonation = await admin.PostJsonAsync($"/api/impersonate/{app.Users.Get(TestApp.UserEmail).Id}");
        var asUser = app.CreateClient();
        asUser.BearerToken = impersonation.Str("accessToken");

        var user = app.Users.Get(TestApp.UserEmail);
        app.Users.SetRoles(user.Id, "Reader");
        await using (var scope = app.App.Services.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<ISlimAuthManager>().RefreshClaimsAsync(user);

        var me = await (await asUser.GetAsync("/auth/me")).Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.True(me.GetProperty("isImpersonating").GetBoolean());
        Assert.Contains(me.GetProperty("claims").EnumerateArray(), c => c.Str("type") == "role" && c.Str("value") == "Reader");
    }

    [Fact]
    public void Stamps_compare_by_their_security_part()
    {
        var stamp = SlimUser.NewSecurityStamp();
        Assert.True(SlimUser.IsSameSecurityState(stamp, stamp + ".ab12cd34"));
        Assert.True(SlimUser.IsSameSecurityState(stamp + ".00000000", stamp + ".ab12cd34"));
        Assert.False(SlimUser.IsSameSecurityState(stamp, SlimUser.NewSecurityStamp()));
        Assert.False(SlimUser.IsSameSecurityState(stamp, null));
    }
}
