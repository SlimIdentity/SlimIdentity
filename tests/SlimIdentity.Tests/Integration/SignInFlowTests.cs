using System.Net;
using System.Text.Json;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Sign-ins with open steps: <c>action_required</c>, the flow token and <c>POST /auth/flow</c>.</summary>
public sealed class SignInFlowTests
{
    private static IEnumerable<string?> Actions(JsonElement answer) => answer.GetProperty("actions").EnumerateArray().Select(a => a.GetString());

    private static async Task EnableEmailTwoFactorAsync(TestApp app, string email, string password)
    {
        var client = app.CreateClient();
        client.BearerToken = (await app.LoginBearerAsync(email, password)).AccessToken;
        await client.PostJsonAsync("/auth/2fa/enable-email", new { password });
    }

    [Fact]
    public async Task The_flow_endpoint_repeats_the_open_steps_and_changes_nothing()
    {
        await using var app = await TestApp.StartAsync();
        await EnableEmailTwoFactorAsync(app, TestApp.UserEmail, TestApp.UserPassword);
        app.Time.Advance(TimeSpan.FromSeconds(1));
        var start = await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword });
        Assert.Equal("action_required", start.Str("status"));
        Assert.True(start.GetProperty("expiresIn").GetInt32() > 0);
        var code = (await app.Mail.WaitForAsync("two-factor", TestApp.UserEmail)).Payload;

        var read = await app.CreateClient().PostJsonAsync("/auth/flow", new { flowToken = start.Str("flowToken") });
        Assert.Equal(["second_factor"], Actions(read));
        Assert.Equal("email", read.GetProperty("details").GetProperty("secondFactor").GetProperty("methods")[0].GetString());
        await Task.Delay(100);
        Assert.Single(app.Mail.Mails, m => m.Kind == "two-factor");   // reading sends no further code

        var session = await app.CreateClient().PostJsonAsync("/auth/login/2fa", new { flowToken = start.Str("flowToken"), code });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
    }

    [Theory]
    [InlineData("not-a-token")]
    [InlineData("")]
    public async Task The_flow_endpoint_answers_every_unusable_token_alike(string token)
    {
        await using var app = await TestApp.StartAsync();
        var answer = await app.CreateClient().PostJsonAsync("/auth/flow", new { flowToken = token }, HttpStatusCode.Unauthorized);
        Assert.Equal("invalid_token", answer.Str("code"));
    }

    [Fact]
    public async Task A_completed_or_outdated_flow_cannot_be_read()
    {
        await using var app = await TestApp.StartAsync();
        var user = app.Users.Get(TestApp.UserEmail);
        user.PasswordChangeRequired = true;
        await app.Users.UpdateSecurityStateAsync(user, default);
        var token = (await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword })).Str("flowToken");

        await app.CreateClient().PostJsonAsync("/auth/login/password-change", new { flowToken = token, newPassword = "My-Own-Pass-2026" });

        var answer = await app.CreateClient().PostJsonAsync("/auth/flow", new { flowToken = token }, HttpStatusCode.Unauthorized);
        Assert.Equal("invalid_token", answer.Str("code"));
    }

    [Fact]
    public async Task The_flow_token_expires()
    {
        await using var app = await TestApp.StartAsync();
        var user = app.Users.Get(TestApp.UserEmail);
        user.PasswordChangeRequired = true;
        await app.Users.UpdateSecurityStateAsync(user, default);
        var token = (await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword })).Str("flowToken");

        app.Time.Advance(SlimIdentityDefaults.SignInFlowLifetime + TimeSpan.FromSeconds(1));

        await app.CreateClient().PostJsonAsync("/auth/flow", new { flowToken = token }, HttpStatusCode.Unauthorized);
        await app.CreateClient().PostJsonAsync("/auth/login/password-change", new { flowToken = token, newPassword = "My-Own-Pass-2026" }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task The_remembered_device_is_issued_when_the_last_step_is_done()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Configure = o => o.TwoFactor.RememberDeviceLifetime = TimeSpan.FromDays(30) });
        await EnableEmailTwoFactorAsync(app, TestApp.UserEmail, TestApp.UserPassword);
        var user = app.Users.Get(TestApp.UserEmail);
        user.PasswordChangeRequired = true;
        await app.Users.UpdateSecurityStateAsync(user, default);
        app.Time.Advance(TimeSpan.FromSeconds(1));

        var start = await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword });
        Assert.Equal(["second_factor", "change_password"], Actions(start));
        var code = (await app.Mail.WaitForAsync("two-factor", TestApp.UserEmail)).Payload;
        var next = await app.CreateClient().PostJsonAsync("/auth/login/2fa", new { flowToken = start.Str("flowToken"), code, rememberDevice = true });
        Assert.False(next.TryGetProperty("twoFactorRememberToken", out _));

        var session = await app.CreateClient().PostJsonAsync("/auth/login/password-change",
            new { flowToken = next.Str("flowToken"), newPassword = "My-Own-Pass-2026" });
        var rememberToken = session.Str("twoFactorRememberToken");
        Assert.False(string.IsNullOrEmpty(rememberToken));

        // bound to the stamp after the change: it works with the new password
        var remembered = await app.CreateClient().PostJsonAsync("/auth/login",
            new { email = TestApp.UserEmail, password = "My-Own-Pass-2026", twoFactorRememberToken = rememberToken });
        Assert.False(string.IsNullOrEmpty(remembered.Str("accessToken")));
    }

    [Fact]
    public async Task An_invitation_asks_the_second_factor_before_the_password_with_a_mailed_code()
    {
        await using var app = await TestApp.StartAsync();
        var admin = app.CreateClient();
        admin.BearerToken = (await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword)).AccessToken;
        var token = (await admin.PostJsonAsync("/api/invite", new { email = "invited@test.local" })).Str("token");
        var invited = app.Users.Get("invited@test.local");
        invited.TwoFactorEnabled = true;   // required by the organization before the first sign-in
        await app.Users.UpdateSecurityStateAsync(invited, default);
        app.Time.Advance(TimeSpan.FromSeconds(1));

        var answer = await app.CreateClient().PostJsonAsync("/auth/flow", new { token });

        Assert.Equal(["second_factor", "set_credential"], Actions(answer));
        var code = (await app.Mail.WaitForAsync("two-factor", "invited@test.local")).Payload;
        var verified = await app.CreateClient().PostJsonAsync("/auth/login/2fa", new { flowToken = answer.Str("flowToken"), code });
        Assert.Equal(["set_credential"], Actions(verified));
        var session = await app.CreateClient().PostJsonAsync("/auth/register/password", new { flowToken = verified.Str("flowToken"), password = "Invited123!" });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
    }
}
