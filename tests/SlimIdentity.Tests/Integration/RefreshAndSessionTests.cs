using System.Net;
using System.Net.Http.Json;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

public sealed class RefreshAndSessionTests
{
    private static async Task<HttpStatusCode> Hello(TestApp app, string? accessToken)
    {
        var client = app.CreateClient();
        client.BearerToken = accessToken;
        return (await client.GetAsync("/api/hello")).StatusCode;
    }

    private static async Task<HttpResponseMessage> Refresh(TestApp app, string? refreshToken) =>
        await app.CreateClient().PostAsync("/auth/refresh", new { refreshToken });

    [Fact]
    public async Task Refresh_rotates_and_old_token_is_single_use()
    {
        await using var app = await TestApp.StartAsync();
        var first = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);

        var rotated = await Refresh(app, first.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, rotated.StatusCode);
        var second = (await rotated.Content.ReadFromJsonAsync<AuthTokens>(ApiClient.Json))!;
        Assert.NotEqual(first.RefreshToken, second.RefreshToken);
        Assert.Equal(HttpStatusCode.OK, await Hello(app, second.AccessToken));

        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(app, first.RefreshToken)).StatusCode);
    }

    [Fact]
    public async Task Refresh_token_reuse_revokes_only_the_affected_session()
    {
        await using var app = await TestApp.StartAsync();
        var stolen = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var otherDevice = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);

        var attacker = (await (await Refresh(app, stolen.RefreshToken)).Content.ReadFromJsonAsync<AuthTokens>(ApiClient.Json))!;
        Assert.Equal(HttpStatusCode.OK, await Hello(app, attacker.AccessToken));

        // the legitimate client presents the already used token → family revoked
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(app, stolen.RefreshToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, await Hello(app, attacker.AccessToken));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(app, attacker.RefreshToken)).StatusCode);

        Assert.Equal(HttpStatusCode.OK, await Hello(app, otherDevice.AccessToken));
    }

    [Fact]
    public async Task Refresh_token_reuse_without_session_store_signs_out_everywhere()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Sessions = false });
        var stolen = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var otherDevice = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var stampBefore = app.Users.Get(TestApp.UserEmail).SecurityStamp;

        Assert.Equal(HttpStatusCode.OK, (await Refresh(app, stolen.RefreshToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(app, stolen.RefreshToken)).StatusCode);

        Assert.NotEqual(stampBefore, app.Users.Get(TestApp.UserEmail).SecurityStamp);
        Assert.Equal(HttpStatusCode.Unauthorized, await Hello(app, otherDevice.AccessToken));
    }

    [Fact]
    public async Task Refresh_chain_is_capped_by_the_absolute_lifetime()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Sessions = false });
        var loginTime = app.Time.GetUtcNow();
        var refreshToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).RefreshToken;
        DateTimeOffset expiresAt = default;

        // a client that refreshes every 6 days (sliding lifetime 7 days)
        for (var day = 6; day <= 24; day += 6)
        {
            app.Time.Advance(TimeSpan.FromDays(6));
            var response = await Refresh(app, refreshToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var body = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
            refreshToken = body.Str("refreshToken");
            expiresAt = body.GetProperty("refreshTokenExpiresAt").GetDateTimeOffset();
        }

        // on day 24 the new token no longer gets 7 days but ends with the chain on day 30
        // (auth_time has second precision)
        Assert.InRange(expiresAt, loginTime + TimeSpan.FromDays(30) - TimeSpan.FromSeconds(1), loginTime + TimeSpan.FromDays(30));

        app.Time.Advance(TimeSpan.FromDays(6));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(app, refreshToken)).StatusCode);
        // an expired token is not mistaken for a stolen one
        Assert.Equal(HttpStatusCode.OK, (await app.CreateClient().PostAsync("/auth/login",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword })).StatusCode);
    }

    [Fact]
    public async Task Sessions_can_be_listed_and_revoked_per_device()
    {
        await using var app = await TestApp.StartAsync();
        var laptop = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var phone = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);

        var client = app.CreateClient();
        client.BearerToken = laptop.AccessToken;
        var sessions = (await (await client.GetAsync("/auth/sessions")).Content.ReadFromJsonAsync<List<SessionDto>>(ApiClient.Json))!;
        Assert.Equal(2, sessions.Count);
        var phoneSession = Assert.Single(sessions, s => !s.IsCurrent);

        Assert.Equal(HttpStatusCode.OK, (await client.DeleteAsync($"/auth/sessions/{phoneSession.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, await Hello(app, phone.AccessToken));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(app, phone.RefreshToken)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, await Hello(app, laptop.AccessToken));
    }

    [Fact]
    public async Task Sessions_of_other_users_cannot_be_revoked()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword);
        var user = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var adminSessionId = (await app.Sessions!.ListAsync(app.Users.Get(TestApp.AdminEmail).Id, default)).Single().Id;

        var client = app.CreateClient();
        client.BearerToken = user.AccessToken;
        Assert.Equal(HttpStatusCode.NotFound, (await client.DeleteAsync($"/auth/sessions/{adminSessionId}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, await Hello(app, admin.AccessToken));
    }

    [Fact]
    public async Task Logout_revokes_the_current_session_server_side()
    {
        await using var app = await TestApp.StartAsync();
        var tokens = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var client = app.CreateClient();
        client.BearerToken = tokens.AccessToken;

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/auth/logout", new { refreshToken = tokens.RefreshToken })).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, await Hello(app, tokens.AccessToken));
        Assert.Equal(HttpStatusCode.Unauthorized, (await Refresh(app, tokens.RefreshToken)).StatusCode);
    }

    [Fact]
    public async Task Logout_all_ends_every_session()
    {
        await using var app = await TestApp.StartAsync();
        var a = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var b = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var client = app.CreateClient();
        client.BearerToken = a.AccessToken;

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/auth/logout-all")).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, await Hello(app, a.AccessToken));
        Assert.Equal(HttpStatusCode.Unauthorized, await Hello(app, b.AccessToken));
        Assert.Equal(0, app.Sessions!.Count);
    }

    [Fact]
    public async Task Change_password_keeps_the_current_device_and_signs_out_the_others()
    {
        await using var app = await TestApp.StartAsync();
        var current = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var other = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var client = app.CreateClient();
        client.BearerToken = current.AccessToken;

        var result = await client.PostJsonAsync("/auth/change-password", new { currentPassword = TestApp.UserPassword, newPassword = "Changed123!" });

        Assert.Equal(HttpStatusCode.OK, await Hello(app, result.Str("accessToken")));
        Assert.Equal(HttpStatusCode.Unauthorized, await Hello(app, other.AccessToken));
        Assert.Equal(1, app.Sessions!.Count);
    }

    [Fact]
    public async Task Ban_via_SignOutEverywhere_ends_all_sessions()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword);
        var user = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var client = app.CreateClient();
        client.BearerToken = admin.AccessToken;

        await client.PostJsonAsync($"/api/ban/{app.Users.Get(TestApp.UserEmail).Id}");

        Assert.Equal(HttpStatusCode.Unauthorized, await Hello(app, user.AccessToken));
        Assert.Equal(HttpStatusCode.Unauthorized, (await app.CreateClient().PostAsync("/auth/login",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword })).StatusCode);
    }

    private sealed record SessionDto(string Id, bool IsCurrent);
}
