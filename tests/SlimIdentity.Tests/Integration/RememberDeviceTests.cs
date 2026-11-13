using System.Net;
using System.Text.Json;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

public sealed class RememberDeviceTests
{
    private static TestAppOptions Enabled(int days = 30) => new() { Configure = o => o.TwoFactor.RememberDeviceLifetime = TimeSpan.FromDays(days) };

    private static async Task EnableEmailTwoFactorAsync(TestApp app, string email, string password)
    {
        var tokens = await app.LoginBearerAsync(email, password);
        var client = app.CreateClient();
        client.BearerToken = tokens.AccessToken;
        await client.PostJsonAsync("/auth/2fa/enable-email", new { password });
    }

    /// <summary>Password + e-mail code; returns the final session.</summary>
    private static async Task<JsonElement> SignInWithSecondFactorAsync(TestApp app, ApiClient client, string email, string password,
        bool rememberDevice, string query = "")
    {
        app.Time.Advance(TimeSpan.FromSeconds(1));   // distinct issue time per e-mail code (fake clock)
        var challenge = await client.PostJsonAsync($"/auth/login{query}", new { email, password }, HttpStatusCode.Unauthorized);
        Assert.Equal("requires_two_factor", challenge.Str("status"));
        var code = (await app.Mail.WaitForAsync("two-factor", email)).Payload;
        return await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = challenge.Str("preAuthToken"), code, rememberDevice });
    }

    [Fact]
    public async Task Bearer_clients_skip_the_second_factor_with_the_remember_token()
    {
        await using var app = await TestApp.StartAsync(Enabled());
        await EnableEmailTwoFactorAsync(app, TestApp.UserEmail, TestApp.UserPassword);

        var session = await SignInWithSecondFactorAsync(app, app.CreateClient(), TestApp.UserEmail, TestApp.UserPassword, rememberDevice: true);
        var rememberToken = session.Str("twoFactorRememberToken");

        var remembered = await app.CreateClient().PostJsonAsync("/auth/login",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword, twoFactorRememberToken = rememberToken });
        Assert.False(string.IsNullOrEmpty(remembered.Str("accessToken")));

        // another device without the token still needs the second factor, and the password is always required
        await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);
        await app.CreateClient().PostJsonAsync("/auth/login",
            new { email = TestApp.UserEmail, password = "wrong", twoFactorRememberToken = rememberToken }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_remembered_device_skips_a_locked_second_factor_but_not_a_locked_password()
    {
        await using var app = await TestApp.StartAsync(Enabled());
        await EnableEmailTwoFactorAsync(app, TestApp.UserEmail, TestApp.UserPassword);
        var rememberToken = (await SignInWithSecondFactorAsync(app, app.CreateClient(), TestApp.UserEmail, TestApp.UserPassword, rememberDevice: true))
            .Str("twoFactorRememberToken");
        var id = app.Users.Get(TestApp.UserEmail).Id;
        app.Users.SetAttempts(id, SlimAttemptFactor.SecondFactor, 5, app.Time.GetUtcNow().AddMinutes(5));

        var remembered = await app.CreateClient().PostJsonAsync("/auth/login",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword, twoFactorRememberToken = rememberToken });
        Assert.False(string.IsNullOrEmpty(remembered.Str("accessToken")));
        Assert.True(app.Users.Get(TestApp.UserEmail).IsSecondFactorLockedOut(app.Time.GetUtcNow()));   // not reset by the password

        app.Users.SetAttempts(id, SlimAttemptFactor.Password, 5, app.Time.GetUtcNow().AddMinutes(5));
        await app.CreateClient().PostJsonAsync("/auth/login",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword, twoFactorRememberToken = rememberToken }, HttpStatusCode.Unauthorized);   // no hint by default
    }
    [Fact]
    public async Task Browsers_remember_the_device_with_a_cookie()
    {
        await using var app = await TestApp.StartAsync(Enabled());
        await EnableEmailTwoFactorAsync(app, TestApp.UserEmail, TestApp.UserPassword);
        var browser = app.CreateClient();
        browser.SendCsrfHeader = true;

        await SignInWithSecondFactorAsync(app, browser, TestApp.UserEmail, TestApp.UserPassword, rememberDevice: true, "?useCookies=true");
        Assert.True(browser.Cookies.ContainsKey("SlimAuth.2fa"));
        await browser.PostAsync("/auth/logout");

        var again = await browser.PostAsync("/auth/login?useCookies=true", new { email = TestApp.UserEmail, password = TestApp.UserPassword });
        Assert.Equal(HttpStatusCode.OK, again.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/hello")).StatusCode);

        // forget this device → second factor again
        await browser.PostAsync("/auth/2fa/forget-device");
        Assert.False(browser.Cookies.ContainsKey("SlimAuth.2fa"));
        await browser.PostAsync("/auth/logout");
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await browser.PostAsync("/auth/login?useCookies=true", new { email = TestApp.UserEmail, password = TestApp.UserPassword })).StatusCode);
    }

    [Fact]
    public async Task Feature_is_off_by_default()
    {
        await using var app = await TestApp.StartAsync();
        await EnableEmailTwoFactorAsync(app, TestApp.UserEmail, TestApp.UserPassword);

        var session = await SignInWithSecondFactorAsync(app, app.CreateClient(), TestApp.UserEmail, TestApp.UserPassword, rememberDevice: true);

        Assert.False(session.TryGetProperty("twoFactorRememberToken", out var token) && token.ValueKind == JsonValueKind.String);
    }

    [Fact]
    public async Task Remember_token_belongs_to_one_user()
    {
        await using var app = await TestApp.StartAsync(Enabled());
        await EnableEmailTwoFactorAsync(app, TestApp.UserEmail, TestApp.UserPassword);
        await EnableEmailTwoFactorAsync(app, TestApp.AdminEmail, TestApp.AdminPassword);
        var userToken = (await SignInWithSecondFactorAsync(app, app.CreateClient(), TestApp.UserEmail, TestApp.UserPassword, true)).Str("twoFactorRememberToken");

        var result = await app.CreateClient().PostJsonAsync("/auth/login",
            new { email = TestApp.AdminEmail, password = TestApp.AdminPassword, twoFactorRememberToken = userToken }, HttpStatusCode.Unauthorized);

        Assert.Equal("requires_two_factor", result.Str("status"));
    }

    [Fact]
    public async Task Remembered_devices_expire()
    {
        await using var app = await TestApp.StartAsync(Enabled(days: 30));
        await EnableEmailTwoFactorAsync(app, TestApp.UserEmail, TestApp.UserPassword);
        var token = (await SignInWithSecondFactorAsync(app, app.CreateClient(), TestApp.UserEmail, TestApp.UserPassword, true)).Str("twoFactorRememberToken");

        app.Time.Advance(TimeSpan.FromDays(31));

        await app.CreateClient().PostJsonAsync("/auth/login",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword, twoFactorRememberToken = token }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Forget_all_devices_invalidates_every_token_and_keeps_the_current_session()
    {
        await using var app = await TestApp.StartAsync(Enabled());
        await EnableEmailTwoFactorAsync(app, TestApp.UserEmail, TestApp.UserPassword);
        var session = await SignInWithSecondFactorAsync(app, app.CreateClient(), TestApp.UserEmail, TestApp.UserPassword, true);
        var token = session.Str("twoFactorRememberToken");

        var client = app.CreateClient();
        client.BearerToken = session.Str("accessToken");
        var renewed = await client.PostJsonAsync("/auth/2fa/forget-all-devices");

        client.BearerToken = renewed.Str("accessToken");
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/hello")).StatusCode);
        await app.CreateClient().PostJsonAsync("/auth/login",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword, twoFactorRememberToken = token }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Password_change_invalidates_remembered_devices()
    {
        await using var app = await TestApp.StartAsync(Enabled());
        await EnableEmailTwoFactorAsync(app, TestApp.UserEmail, TestApp.UserPassword);
        var session = await SignInWithSecondFactorAsync(app, app.CreateClient(), TestApp.UserEmail, TestApp.UserPassword, true);
        var token = session.Str("twoFactorRememberToken");

        var client = app.CreateClient();
        client.BearerToken = session.Str("accessToken");
        await client.PostJsonAsync("/auth/change-password", new { currentPassword = TestApp.UserPassword, newPassword = "Changed123!" });

        await app.CreateClient().PostJsonAsync("/auth/login",
            new { email = TestApp.UserEmail, password = "Changed123!", twoFactorRememberToken = token }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Recovery_codes_never_remember_the_device()
    {
        await using var app = await TestApp.StartAsync(Enabled());
        var tokens = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var me = app.CreateClient();
        me.BearerToken = tokens.AccessToken;
        var codes = (await me.PostJsonAsync("/auth/2fa/enable-email", new { password = TestApp.UserPassword })).GetProperty("recoveryCodes");

        app.Time.Advance(TimeSpan.FromSeconds(1));
        var client = app.CreateClient();
        var preAuth = (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized)).Str("preAuthToken");
        var session = await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = preAuth, recoveryCode = codes[0].GetString(), rememberDevice = true });

        Assert.False(session.TryGetProperty("twoFactorRememberToken", out var token) && token.ValueKind == JsonValueKind.String);
    }
}
