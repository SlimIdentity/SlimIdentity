using System.Net;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

public sealed class AccountTests
{
    [Fact]
    public async Task Register_answers_identically_for_new_and_existing_addresses()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();

        var existing = await client.PostJsonAsync("/auth/register", new { email = TestApp.UserEmail });
        var fresh = await client.PostJsonAsync("/auth/register", new { email = "new@test.local" });

        Assert.Equal(Shape(existing), Shape(fresh));
        Assert.Equal("""["verify_email","set_credential"]""", fresh.GetProperty("actions").GetRawText());

        await app.Mail.WaitForAsync("account-exists", TestApp.UserEmail);
        await app.Mail.WaitForAsync("verification", "new@test.local");

        static string Shape(System.Text.Json.JsonElement e) =>
            string.Join(",", e.EnumerateObject().Select(p => p.Name + "=" + (p.Name == "flowToken" ? "" : p.Value.GetRawText())));
    }

    [Fact]
    public async Task Register_validates_the_password_policy()
    {
        await using var app = await TestApp.StartAsync();
        var response = await app.RegisterAsync("new@test.local", "short");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.DoesNotContain(app.Users.All, u => u.Email == "new@test.local");
    }

    [Fact]
    public async Task Verification_link_confirms_the_email()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();
        await client.PostJsonAsync("/auth/register", new { email = "new@test.local" });
        var token = TestApp.LinkToken((await app.Mail.WaitForAsync("verification", "new@test.local")).Link!);

        var other = app.CreateClient();
        var steps = await other.PostJsonAsync("/auth/flow", new { token });
        Assert.Equal("""["set_credential"]""", steps.GetProperty("actions").GetRawText());
        await other.PostJsonAsync("/auth/register/password", new { flowToken = steps.Str("flowToken"), password = "Another123!" });

        Assert.True(app.Users.Get("new@test.local").EmailConfirmed);
    }

    [Fact]
    public async Task Forgot_password_answers_identically_and_mails_only_existing_accounts()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();

        var existing = await client.PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        var unknown = await client.PostAsync("/auth/forgot-password", new { email = "nobody@test.local" });

        Assert.Equal(await existing.Content.ReadAsStringAsync(), await unknown.Content.ReadAsStringAsync());
        await app.Mail.WaitForAsync("password-reset", TestApp.UserEmail);
        Assert.DoesNotContain(app.Mail.Mails, m => m.To == "nobody@test.local");
    }

    [Fact]
    public async Task Reset_password_is_single_use_and_ends_all_sessions()
    {
        await using var app = await TestApp.StartAsync();
        var session = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var client = app.CreateClient();
        await client.PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        var token = (await app.Mail.WaitForAsync("password-reset", TestApp.UserEmail)).Payload;

        await client.PostJsonAsync("/auth/reset-password", new { token, newPassword = "Reset1234!" });
        await client.PostJsonAsync("/auth/reset-password", new { token, newPassword = "Again1234!" }, HttpStatusCode.BadRequest);

        var old = app.CreateClient();
        old.BearerToken = session.AccessToken;
        Assert.Equal(HttpStatusCode.Unauthorized, (await old.GetAsync("/api/hello")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = "Reset1234!" })).StatusCode);
    }

    [Fact]
    public async Task Reset_password_ends_only_the_password_lockout()
    {
        await using var app = await TestApp.StartAsync();
        var id = app.Users.Get(TestApp.UserEmail).Id;
        app.Users.SetAttempts(id, SlimAttemptFactor.Password, 5, app.Time.GetUtcNow().AddMinutes(5));
        app.Users.SetAttempts(id, SlimAttemptFactor.SecondFactor, 5, app.Time.GetUtcNow().AddMinutes(5));
        var client = app.CreateClient();
        await client.PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        var token = (await app.Mail.WaitForAsync("password-reset", TestApp.UserEmail)).Payload;

        await client.PostJsonAsync("/auth/reset-password", new { token, newPassword = "Reset1234!" });

        var user = app.Users.Get(TestApp.UserEmail);
        Assert.Equal((0, null), (user.FailedLoginAttempts, user.LockoutEndUtc));
        Assert.True(user.IsSecondFactorLockedOut(app.Time.GetUtcNow()));   // the mailbox proves no second factor
    }
    [Fact]
    public async Task Me_returns_the_user_without_internal_claims()
    {
        await using var app = await TestApp.StartAsync();
        var tokens = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var client = app.CreateClient();
        client.BearerToken = tokens.AccessToken;

        var body = await (await client.GetAsync("/auth/me")).Content.ReadAsStringAsync();

        Assert.Contains(TestApp.UserEmail, body);
        Assert.DoesNotContain("slim_stamp", body);
    }
}
