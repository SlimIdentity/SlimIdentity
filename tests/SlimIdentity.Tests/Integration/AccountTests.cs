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
        var body = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("validation_failed", body.Str("code"));
        Assert.True(body.GetProperty("errors").TryGetProperty("password", out _));
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

        await client.ResetPasswordJsonAsync(token, "Reset1234!");
        await client.ResetPasswordJsonAsync(token, "Again1234!", HttpStatusCode.Unauthorized);

        var old = app.CreateClient();
        old.BearerToken = session.AccessToken;
        Assert.Equal(HttpStatusCode.Unauthorized, (await old.GetAsync("/api/hello")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = "Reset1234!" })).StatusCode);
    }

    [Fact]
    public async Task A_reset_link_dies_when_the_password_is_changed_elsewhere()
    {
        await using var app = await TestApp.StartAsync();
        await app.CreateClient().PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        var link = (await app.Mail.WaitForAsync("password-reset", TestApp.UserEmail)).Payload;

        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await me.PostJsonAsync("/auth/change-password", new { currentPassword = TestApp.UserPassword, newPassword = "Changed-Pass-123" });

        await app.CreateClient().ResetPasswordJsonAsync(link, "Attacker-Pass-123", HttpStatusCode.Unauthorized);
        await app.LoginBearerAsync(TestApp.UserEmail, "Changed-Pass-123");
    }

    [Fact]
    public async Task One_inbox_cannot_be_flooded_with_mails()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();

        var answers = new List<string>();
        for (var i = 0; i < 6; i++)
            answers.Add(await (await client.PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail })).Content.ReadAsStringAsync());
        await client.PostAsync("/auth/forgot-password", new { email = TestApp.AdminEmail });   // another inbox is not affected

        await app.Mail.WaitForAsync("password-reset", TestApp.AdminEmail);
        await app.WaitForQueuedMailAsync();
        Assert.Equal(3, app.Mail.Mails.Count(m => m.Kind == "password-reset" && m.To == TestApp.UserEmail));
        Assert.Single(answers.Distinct());   // throttled requests get the same answer – nothing to learn

        app.Time.Advance(TimeSpan.FromMinutes(16));
        await client.PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        await app.WaitForQueuedMailAsync();
        Assert.Equal(4, app.Mail.Mails.Count(m => m.Kind == "password-reset" && m.To == TestApp.UserEmail));
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

        await client.ResetPasswordJsonAsync(token, "Reset1234!");

        var user = app.Users.Get(TestApp.UserEmail);
        Assert.Equal((0, null), (user.FailedLoginAttempts, user.LockoutEndUtc));
        Assert.True(user.IsSecondFactorLockedOut(app.Time.GetUtcNow()));   // the mailbox proves no second factor
    }

    [Fact]
    public async Task A_reset_link_opens_step_set_credential_and_ends_in_a_session()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Configure = o => o.Endpoints.DefaultUseCookies = false });
        var client = app.CreateClient();
        await client.PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        var token = (await app.Mail.WaitForAsync("password-reset", TestApp.UserEmail)).Payload;

        var started = await client.PostJsonAsync("/auth/flow", new { token });
        Assert.Equal("""["set_credential"]""", started.GetProperty("actions").GetRawText());
        var details = started.GetProperty("details").GetProperty("setCredential");
        Assert.Equal(TestApp.UserEmail, details.Str("email"));
        Assert.Equal("""["password"]""", details.GetProperty("kinds").GetRawText());

        var flowToken = started.Str("flowToken");
        await client.PostJsonAsync("/auth/register/password", new { flowToken, password = "x" }, HttpStatusCode.BadRequest);
        await client.PostJsonAsync("/auth/register/password", new { flowToken, password = "Reset1234!", profile = new { name = "x" } }, HttpStatusCode.BadRequest);
        var session = await client.PostJsonAsync("/auth/register/password", new { flowToken, password = "Reset1234!" });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
        await client.PostJsonAsync("/auth/register/password", new { flowToken, password = "Again1234!" }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task With_an_external_password_validator_and_no_passkeys_a_reset_link_sets_nothing()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Builder = b => b.AddCustomPasswordValidator<DirectoryValidator>() });
        await app.CreateClient().PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        var token = (await app.Mail.WaitForAsync("password-reset", TestApp.UserEmail)).Payload;

        var refused = await app.CreateClient().PostJsonAsync("/auth/flow", new { token }, HttpStatusCode.BadRequest);
        Assert.Equal("password_managed_externally", refused.Str("code"));
    }

    private sealed class DirectoryValidator : ISlimCustomPasswordValidator
    {
        public Task<bool> ValidateAsync(SlimUser user, string providedPassword, CancellationToken ct) => Task.FromResult(false);
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
