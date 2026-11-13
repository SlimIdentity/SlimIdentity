using System.Net;
using System.Net.Http.Json;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Internal services without a mail server: <c>WithoutEmail()</c> and <c>TwoFactor.AllowEmailCodes</c>.</summary>
public sealed class WithoutEmailTests
{
    private static TestAppOptions Mailless(bool allowSelfRegistration = false, Action<SlimIdentityOptions>? configure = null) => new()
    {
        EmailSender = false,
        Builder = b => b.WithoutEmail(allowSelfRegistration),
        Configure = configure,
    };

    [Theory]
    [InlineData("/auth/forgot-password")]
    [InlineData("/auth/register")]
    [InlineData("/auth/verify-email")]
    [InlineData("/auth/resend-verification")]
    [InlineData("/auth/login/verify-email")]
    [InlineData("/auth/change-email")]
    [InlineData("/auth/confirm-email-change")]
    public async Task Mail_based_endpoints_are_not_mapped(string path)
    {
        await using var app = await TestApp.StartAsync(Mailless());
        Assert.Equal(HttpStatusCode.NotFound, (await app.CreateClient().PostAsync(path, new { email = "x@test.local" })).StatusCode);
    }

    [Fact]
    public async Task Sign_in_password_change_and_reset_links_keep_working()
    {
        await using var app = await TestApp.StartAsync(Mailless());
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;

        await me.PostJsonAsync("/auth/change-password", new { currentPassword = TestApp.UserPassword, newPassword = "Changed-Pass-123" });
        await app.LoginBearerAsync(TestApp.UserEmail, "Changed-Pass-123");

        // /reset-password stays for links the administrator hands over
        await app.CreateClient().PostJsonAsync("/auth/reset-password", new { token = "invalid", newPassword = "Another-Pass-123" }, HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task A_lockout_needs_no_mail_sender()
    {
        await using var app = await TestApp.StartAsync(Mailless());
        for (var i = 0; i < 5; i++)
            await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = "wrong-password" }, HttpStatusCode.Unauthorized);
        Assert.True(app.Users.Get(TestApp.UserEmail).IsLockedOut(app.Time.GetUtcNow()));
    }

    [Fact]
    public async Task Self_registration_can_be_allowed_explicitly()
    {
        await using var app = await TestApp.StartAsync(Mailless(allowSelfRegistration: true));
        await app.CreateClient().PostJsonAsync("/auth/register", new { email = "new@test.local", password = "New-Member-Pass-1" });
        await app.LoginBearerAsync("new@test.local", "New-Member-Pass-1");
    }

    [Fact]
    public async Task A_mail_sender_next_to_WithoutEmail_cannot_start()
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(() => TestApp.StartAsync(new TestAppOptions { Builder = b => b.WithoutEmail() }));
        Assert.Contains("WithoutEmail", error.ToString());
    }

    [Fact]
    public async Task Without_WithoutEmail_a_mail_sender_is_still_required()
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(() => TestApp.StartAsync(new TestAppOptions { EmailSender = false }));
        Assert.Contains("ISlimEmailSender", error.ToString());
    }

    // ------------------------------------------------------------------ e-mail codes as second factor

    [Fact]
    public async Task Email_codes_can_be_switched_off_while_mail_is_available()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Configure = o => o.TwoFactor.AllowEmailCodes = false });
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await me.PostJsonAsync("/auth/2fa/enable-email", new { password = TestApp.UserPassword }, HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task An_account_with_email_codes_falls_back_to_recovery_codes_when_codes_cannot_be_sent()
    {
        await using var app = await TestApp.StartAsync(Mailless());
        var user = app.Users.Get(TestApp.UserEmail);   // e-mail 2FA from the time the host still sent mail
        user.TwoFactorEnabled = true;
        await app.Users.UpdateSecurityStateAsync(user, default);

        var challenge = await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword });

        Assert.Equal("second_factor", challenge.GetProperty("actions")[0].GetString());
        Assert.Equal("recovery", challenge.GetProperty("details").GetProperty("secondFactor").GetProperty("methods")[0].GetString());
    }

    [Theory]
    [InlineData(true)]    // WithoutEmail()
    [InlineData(false)]   // mail available, TwoFactor.AllowEmailCodes = false
    public async Task The_2fa_status_reports_recovery_when_codes_cannot_be_sent(bool withoutEmail)
    {
        // review finding F-07: GET /2fa said "email" while the sign-in already asked for a recovery code
        await using var app = await TestApp.StartAsync(withoutEmail
            ? Mailless()
            : new TestAppOptions { Configure = o => o.TwoFactor.AllowEmailCodes = false });
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        var user = app.Users.Get(TestApp.UserEmail);
        user.TwoFactorEnabled = true;   // e-mail codes from earlier – no authenticator
        await app.Users.UpdateSecurityStateAsync(user, default);

        var status = await (await me.GetAsync("/auth/2fa")).Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.Equal("recovery", status.Str("method"));
    }
}
