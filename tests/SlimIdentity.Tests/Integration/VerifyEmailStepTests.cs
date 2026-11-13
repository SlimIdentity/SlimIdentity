using System.Net;
using System.Text.Json;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>The sign-in step <c>verify_email</c>: a mailed code proves the mailbox of an unconfirmed account.</summary>
public sealed class VerifyEmailStepTests
{
    private const string Email = "fresh@test.local";
    private const string Password = "Fresh-Pass-123!";

    private static IEnumerable<string?> Actions(JsonElement answer) => answer.GetProperty("actions").EnumerateArray().Select(a => a.GetString());

    private static async Task<TestApp> StartWithUnconfirmedAsync(TestAppOptions? options = null)
    {
        var app = await TestApp.StartAsync(options);
        await app.CreateClient().PostJsonAsync("/auth/register", new { email = Email, password = Password });
        return app;
    }

    private static async Task<JsonElement> StartLoginAsync(TestApp app, ApiClient? client = null, string query = "")
    {
        app.Time.Advance(TimeSpan.FromSeconds(1));
        var answer = await (client ?? app.CreateClient()).PostJsonAsync("/auth/login" + query, new { email = Email, password = Password });
        Assert.Equal(["verify_email"], Actions(answer));
        return answer;
    }

    private static Task<JsonElement> VerifyAsync(TestApp app, JsonElement start, string code, HttpStatusCode expected = HttpStatusCode.OK, ApiClient? client = null) =>
        (client ?? app.CreateClient()).PostJsonAsync("/auth/login/verify-email", new { flowToken = start.Str("flowToken"), code }, expected);

    private static async Task<string> LatestCodeAsync(TestApp app, string kind = "verification-code", string email = Email)
    {
        await app.Mail.WaitForAsync(kind, email);
        return app.Mail.Mails.Last(m => m.Kind == kind && m.To == email).Payload;
    }

    [Fact]
    public async Task The_mailed_code_confirms_the_address_and_completes_the_sign_in()
    {
        await using var app = await StartWithUnconfirmedAsync();
        var start = await StartLoginAsync(app);
        Assert.False(start.TryGetProperty("accessToken", out _));

        var session = await VerifyAsync(app, start, await LatestCodeAsync(app));

        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
        Assert.True(app.Users.Get(Email).EmailConfirmed);
        await app.LoginBearerAsync(Email, Password);   // no further step
    }

    [Fact]
    public async Task A_wrong_code_is_refused_and_the_flow_token_cannot_be_used_twice()
    {
        await using var app = await StartWithUnconfirmedAsync();
        var start = await StartLoginAsync(app);
        var code = await LatestCodeAsync(app);

        Assert.Equal("invalid_verification_code", (await VerifyAsync(app, start, code == "000000" ? "111111" : "000000", HttpStatusCode.Unauthorized)).Str("code"));
        Assert.False(app.Users.Get(Email).EmailConfirmed);

        await VerifyAsync(app, start, code);
        Assert.Equal("invalid_token", (await VerifyAsync(app, start, code, HttpStatusCode.Unauthorized)).Str("code"));
    }

    [Fact]
    public async Task A_flow_allows_five_attempts()
    {
        await using var app = await StartWithUnconfirmedAsync();
        var start = await StartLoginAsync(app);
        var code = await LatestCodeAsync(app);
        var wrong = code == "000000" ? "111111" : "000000";

        for (var i = 0; i < 5; i++) await VerifyAsync(app, start, wrong, HttpStatusCode.Unauthorized);

        Assert.Equal("too_many_attempts", (await VerifyAsync(app, start, code, (HttpStatusCode)429)).Str("code"));
        Assert.False(app.Users.Get(Email).EmailConfirmed);
    }

    [Fact]
    public async Task An_address_allows_ten_attempts_across_flows()
    {
        await using var app = await StartWithUnconfirmedAsync();
        for (var i = 0; i < 2; i++)
        {
            var start = await StartLoginAsync(app);
            for (var j = 0; j < 5; j++) await VerifyAsync(app, start, "000000", HttpStatusCode.Unauthorized);
        }

        var last = await StartLoginAsync(app);
        Assert.Equal("too_many_attempts", (await VerifyAsync(app, last, await LatestCodeAsync(app), (HttpStatusCode)429)).Str("code"));

        app.Time.Advance(TimeSpan.FromHours(25));
        var later = await StartLoginAsync(app);
        await VerifyAsync(app, later, await LatestCodeAsync(app));
    }

    [Fact]
    public async Task A_flow_without_a_delivered_code_accepts_no_code()
    {
        await using var app = await StartWithUnconfirmedAsync();
        for (var i = 0; i < 5; i++) await StartLoginAsync(app);
        await app.Mail.WaitForAsync("verification-code", Email);
        var lastDelivered = await LatestCodeAsync(app);

        var throttled = await StartLoginAsync(app);
        await Task.Delay(100);

        Assert.Equal(5, app.Mail.Mails.Count(m => m.Kind == "verification-code"));
        await VerifyAsync(app, throttled, lastDelivered, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_second_factor_challenge_without_a_delivered_code_accepts_no_code()
    {
        await using var app = await TestApp.StartAsync();
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await me.PostJsonAsync("/auth/2fa/enable-email", new { password = TestApp.UserPassword });

        JsonElement start = default;
        for (var i = 0; i < 6; i++)
        {
            app.Time.Advance(TimeSpan.FromSeconds(1));
            start = await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword });
        }
        await Task.Delay(100);

        Assert.Equal(5, app.Mail.Mails.Count(m => m.Kind == "two-factor"));
        var lastDelivered = app.Mail.Mails.Last(m => m.Kind == "two-factor").Payload;
        await app.CreateClient().PostJsonAsync("/auth/login/2fa", new { flowToken = start.Str("flowToken"), code = lastDelivered }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task The_second_factor_follows_the_verified_address()
    {
        await using var app = await TestApp.StartAsync();
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await me.PostJsonAsync("/auth/2fa/enable-email", new { password = TestApp.UserPassword });
        await app.SetEmailConfirmedAsync(TestApp.UserEmail, false);

        app.Time.Advance(TimeSpan.FromSeconds(1));
        var start = await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword });
        Assert.Equal(["verify_email", "second_factor"], Actions(start));
        var code = await LatestCodeAsync(app, email: TestApp.UserEmail);
        Assert.DoesNotContain(app.Mail.Mails, m => m.Kind == "two-factor");

        var next = await VerifyAsync(app, start, code);
        Assert.Equal(["second_factor"], Actions(next));
        await app.CreateClient().PostJsonAsync("/auth/login/2fa", new { flowToken = start.Str("flowToken"), code = "000000" }, HttpStatusCode.Unauthorized);

        var twoFactor = await LatestCodeAsync(app, "two-factor", TestApp.UserEmail);
        var session = await app.CreateClient().PostJsonAsync("/auth/login/2fa", new { flowToken = next.Str("flowToken"), code = twoFactor });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
    }

    [Fact]
    public async Task The_cookie_flow_requires_csrf()
    {
        await using var app = await StartWithUnconfirmedAsync(new TestAppOptions { Configure = o => o.Endpoints.DefaultUseCookies = false });
        var browser = app.CreateClient();
        browser.SendCsrfHeader = true;
        var start = await StartLoginAsync(app, browser, "?useCookies=true");
        var code = await LatestCodeAsync(app);

        browser.SendCsrfHeader = false;
        Assert.Equal("csrf_validation_failed", (await VerifyAsync(app, start, code, HttpStatusCode.Forbidden, browser)).Str("code"));

        browser.SendCsrfHeader = true;
        await VerifyAsync(app, start, code, client: browser);
        Assert.True(browser.Cookies.ContainsKey("SlimAuth"));
    }
}
