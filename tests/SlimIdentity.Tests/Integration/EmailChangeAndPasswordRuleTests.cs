using System.Net;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

public sealed class EmailChangeTests
{
    private static async Task<ApiClient> SignedInAsync(TestApp app)
    {
        var tokens = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var client = app.CreateClient();
        client.BearerToken = tokens.AccessToken;
        return client;
    }

    private static async Task<string> RequestAsync(ApiClient client, string newEmail = "new@test.local")
    {
        var requested = await client.PostJsonAsync("/auth/change-email", new { newEmail, password = TestApp.UserPassword });
        Assert.Equal("email_change_requested", requested.Str("status"));
        return requested.Str("token")!;
    }

    [Fact]
    public async Task Email_changes_only_after_the_code_sent_to_the_new_address_is_entered()
    {
        await using var app = await TestApp.StartAsync();
        var client = await SignedInAsync(app);
        var otherDevice = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);

        var token = await RequestAsync(client);
        Assert.Equal(TestApp.UserEmail, app.Users.Get(TestApp.UserEmail).Email);   // not changed yet
        var code = (await app.Mail.WaitForAsync("email-change", "new@test.local")).Payload;

        var confirmed = await client.PostJsonAsync("/auth/change-email/confirm", new { token, code });
        client.BearerToken = confirmed.Str("accessToken");

        var user = app.Users.Get("new@test.local");
        Assert.True(user.EmailConfirmed);
        await app.Mail.WaitForAsync("email-changed", TestApp.UserEmail);   // old address is informed
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/hello")).StatusCode);   // calling session continues

        // single use (the stamp rotated) and all other sessions ended
        var replay = await client.PostJsonAsync("/auth/change-email/confirm", new { token, code }, HttpStatusCode.BadRequest);
        Assert.Equal("invalid_token", replay.Str("code"));
        var old = app.CreateClient();
        old.BearerToken = otherDevice.AccessToken;
        Assert.Equal(HttpStatusCode.Unauthorized, (await old.GetAsync("/api/hello")).StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await app.CreateClient().PostAsync("/auth/login",
            new { email = "new@test.local", password = TestApp.UserPassword })).StatusCode);
    }

    [Fact]
    public async Task Confirmation_needs_a_session_of_the_same_account_but_not_the_requesting_one()
    {
        await using var app = await TestApp.StartAsync();
        var client = await SignedInAsync(app);
        var token = await RequestAsync(client);
        var code = (await app.Mail.WaitForAsync("email-change", "new@test.local")).Payload;

        await app.CreateClient().PostJsonAsync("/auth/change-email/confirm", new { token, code }, HttpStatusCode.Unauthorized);

        var admin = app.CreateClient();
        admin.BearerToken = (await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword)).AccessToken;
        var foreign = await admin.PostJsonAsync("/auth/change-email/confirm", new { token, code }, HttpStatusCode.BadRequest);
        Assert.Equal("invalid_token", foreign.Str("code"));

        var otherDevice = await SignedInAsync(app);
        await otherDevice.PostJsonAsync("/auth/change-email/confirm", new { token, code });
        Assert.Equal("new@test.local", app.Users.Get("new@test.local").Email);
    }

    [Fact]
    public async Task Wrong_codes_are_rejected_and_limited()
    {
        await using var app = await TestApp.StartAsync();
        var client = await SignedInAsync(app);
        var token = await RequestAsync(client);
        var code = (await app.Mail.WaitForAsync("email-change", "new@test.local")).Payload;
        var wrong = code == "000000" ? "111111" : "000000";

        for (var i = 0; i < 5; i++)
        {
            var rejected = await client.PostJsonAsync("/auth/change-email/confirm", new { token, code = wrong }, HttpStatusCode.BadRequest);
            Assert.Equal("invalid_verification_code", rejected.Str("code"));
        }
        await client.PostJsonAsync("/auth/change-email/confirm", new { token, code }, HttpStatusCode.TooManyRequests);
        Assert.Equal(TestApp.UserEmail, app.Users.Get(TestApp.UserEmail).Email);
    }

    [Fact]
    public async Task Taken_address_answers_identically_informs_its_owner_and_cannot_be_confirmed()
    {
        await using var app = await TestApp.StartAsync();
        var client = await SignedInAsync(app);

        var token = await RequestAsync(client, TestApp.AdminEmail);

        await app.Mail.WaitForAsync("account-exists", TestApp.AdminEmail);
        Assert.DoesNotContain(app.Mail.Mails, m => m.Kind == "email-change");
        var result = await client.PostJsonAsync("/auth/change-email/confirm", new { token, code = "123456" }, HttpStatusCode.BadRequest);
        Assert.Equal("invalid_verification_code", result.Str("code"));
    }

    [Fact]
    public async Task Wrong_passwords_are_counted_and_a_correct_one_resets_the_count()
    {
        await using var app = await TestApp.StartAsync();
        var client = await SignedInAsync(app);

        for (var i = 0; i < 4; i++)   // threshold is 5
            await client.PostJsonAsync("/auth/change-email", new { newEmail = "new@test.local", password = "wrong" }, HttpStatusCode.BadRequest);
        Assert.Equal(4, app.Users.Get(TestApp.UserEmail).FailedLoginAttempts);

        await client.PostJsonAsync("/auth/change-email", new { newEmail = "new@test.local", password = TestApp.UserPassword });

        Assert.Equal(0, app.Users.Get(TestApp.UserEmail).FailedLoginAttempts);
    }

    [Fact]
    public async Task Address_taken_between_request_and_confirmation_is_reported()
    {
        await using var app = await TestApp.StartAsync();
        var client = await SignedInAsync(app);
        var token = await RequestAsync(client);
        var code = (await app.Mail.WaitForAsync("email-change", "new@test.local")).Payload;

        app.Users.Seed("new@test.local", "Other1234!");

        var result = await client.PostJsonAsync("/auth/change-email/confirm", new { token, code }, HttpStatusCode.BadRequest);
        Assert.Equal("email_taken", result.Str("code"));
    }
}
public sealed class PasswordRuleTests
{
    private sealed class NoProductNameRule : ISlimPasswordRule
    {
        public Task<IReadOnlyList<string>> ValidateAsync(string password, string email, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<string>>(password.Contains("Slim", StringComparison.OrdinalIgnoreCase)
                ? ["Password must not contain the product name."]
                : []);
    }

    [Fact]
    public async Task Custom_rules_apply_to_all_new_passwords()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Builder = b => b.AddPasswordRule<NoProductNameRule>() });

        var rejected = await app.RegisterAsync("new@test.local", "SlimSecret123");
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        Assert.Contains("product name", await rejected.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, (await app.RegisterAsync("new@test.local", "Secret123!")).StatusCode);
    }
}
