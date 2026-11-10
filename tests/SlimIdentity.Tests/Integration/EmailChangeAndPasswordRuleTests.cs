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

    [Fact]
    public async Task Email_changes_only_after_confirmation_by_the_new_address()
    {
        await using var app = await TestApp.StartAsync();
        var client = await SignedInAsync(app);
        var otherDevice = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);

        var requested = await client.PostJsonAsync("/auth/change-email", new { newEmail = "new@test.local", password = TestApp.UserPassword });
        Assert.Equal("email_change_requested", requested.Str("status"));
        Assert.Equal(TestApp.UserEmail, app.Users.Get(TestApp.UserEmail).Email);   // not changed yet

        var token = (await app.Mail.WaitForAsync("email-change", "new@test.local")).Payload;
        var confirmed = await app.CreateClient().PostJsonAsync("/auth/confirm-email-change", new { token });
        Assert.Equal("email_changed", confirmed.Str("status"));

        var user = app.Users.Get("new@test.local");
        Assert.True(user.EmailConfirmed);
        await app.Mail.WaitForAsync("email-changed", TestApp.UserEmail);   // old address is informed

        // the link is single use and all sessions ended (they carry the old address)
        await app.CreateClient().PostJsonAsync("/auth/confirm-email-change", new { token }, HttpStatusCode.BadRequest);
        var old = app.CreateClient();
        old.BearerToken = otherDevice.AccessToken;
        Assert.Equal(HttpStatusCode.Unauthorized, (await old.GetAsync("/api/hello")).StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await app.CreateClient().PostAsync("/auth/login",
            new { email = "new@test.local", password = TestApp.UserPassword })).StatusCode);
    }

    [Fact]
    public async Task Taken_address_answers_identically_and_informs_its_owner()
    {
        await using var app = await TestApp.StartAsync();
        var client = await SignedInAsync(app);

        var response = await client.PostJsonAsync("/auth/change-email", new { newEmail = TestApp.AdminEmail, password = TestApp.UserPassword });

        Assert.Equal("email_change_requested", response.Str("status"));
        await app.Mail.WaitForAsync("account-exists", TestApp.AdminEmail);
        Assert.DoesNotContain(app.Mail.Mails, m => m.Kind == "email-change");
    }

    [Fact]
    public async Task Wrong_password_is_rejected_and_counted()
    {
        await using var app = await TestApp.StartAsync();
        var client = await SignedInAsync(app);

        await client.PostJsonAsync("/auth/change-email", new { newEmail = "new@test.local", password = "wrong" }, HttpStatusCode.BadRequest);

        Assert.Equal(1, app.Users.Get(TestApp.UserEmail).FailedLoginAttempts);
    }

    [Fact]
    public async Task Address_taken_between_request_and_confirmation_is_reported()
    {
        await using var app = await TestApp.StartAsync();
        var client = await SignedInAsync(app);
        await client.PostJsonAsync("/auth/change-email", new { newEmail = "new@test.local", password = TestApp.UserPassword });
        var token = (await app.Mail.WaitForAsync("email-change", "new@test.local")).Payload;

        app.Users.Seed("new@test.local", "Other1234!");

        var result = await app.CreateClient().PostJsonAsync("/auth/confirm-email-change", new { token }, HttpStatusCode.BadRequest);
        Assert.Equal("email_taken", result.Str("status"));
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
        var client = app.CreateClient();

        var rejected = await client.PostAsync("/auth/register", new { email = "new@test.local", password = "SlimSecret123" });
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        Assert.Contains("product name", await rejected.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/auth/register", new { email = "new@test.local", password = "Secret123!" })).StatusCode);
    }
}
