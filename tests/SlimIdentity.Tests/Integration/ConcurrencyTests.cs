using System.Net;
using SlimIdentity.Security;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Single-use challenges, CSRF on the 2FA step and races between parallel requests.</summary>
public sealed class ConcurrencyTests
{
    private static string Code(TestApp app, string sharedKey) =>
        SlimTotp.Compute(SlimBase32.Decode(sharedKey), app.Time.GetUtcNow().ToUnixTimeSeconds() / 30);

    private static async Task<(string SharedKey, string[] RecoveryCodes)> EnableTotpAsync(TestApp app)
    {
        var tokens = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var client = app.CreateClient();
        client.BearerToken = tokens.AccessToken;

        var setup = await client.PostJsonAsync("/auth/2fa/setup");
        var sharedKey = setup.Str("sharedKey");
        var enabled = await client.PostJsonAsync("/auth/2fa/enable", new { setupToken = setup.Str("setupToken"), code = Code(app, sharedKey), password = TestApp.UserPassword });
        app.Time.Advance(TimeSpan.FromSeconds(30));   // next time step – the enable code is used
        return (sharedKey, enabled.GetProperty("recoveryCodes").EnumerateArray().Select(c => c.GetString()!).ToArray());
    }

    [Fact]
    public async Task A_sign_in_challenge_completes_only_one_sign_in()
    {
        await using var app = await TestApp.StartAsync();
        var (sharedKey, recoveryCodes) = await EnableTotpAsync(app);
        var client = app.CreateClient();

        var preAuth = (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized)).Str("preAuthToken");
        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = preAuth, code = Code(app, sharedKey) });

        // the same challenge with another, valid factor: a fresh TOTP step …
        app.Time.Advance(TimeSpan.FromSeconds(30));
        var reused = await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = preAuth, code = Code(app, sharedKey) }, HttpStatusCode.Unauthorized);
        Assert.Equal("invalid_token", reused.Str("status"));
        // … or a recovery code
        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = preAuth, recoveryCode = recoveryCodes[0] }, HttpStatusCode.Unauthorized);

        // a new challenge (password again) works
        app.Time.Advance(TimeSpan.FromSeconds(30));
        var fresh = (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized)).Str("preAuthToken");
        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = fresh, code = Code(app, sharedKey) });
    }

    [Fact]
    public async Task A_wrong_code_does_not_burn_the_challenge()
    {
        await using var app = await TestApp.StartAsync();
        var (sharedKey, _) = await EnableTotpAsync(app);
        var client = app.CreateClient();

        var preAuth = (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized)).Str("preAuthToken");
        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = preAuth, code = "000000" }, HttpStatusCode.Unauthorized);
        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = preAuth, code = Code(app, sharedKey) });
    }

    [Fact]
    public async Task Cookie_mode_2fa_step_requires_csrf_even_if_bearer_is_the_default()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Configure = o => o.Endpoints.DefaultUseCookies = false });
        var (sharedKey, _) = await EnableTotpAsync(app);
        var client = app.CreateClient();
        client.SendCsrfHeader = true;

        var preAuth = (await client.PostJsonAsync("/auth/login?useCookies=true", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized)).Str("preAuthToken");

        // no session cookie, no useCookies flag – only the signed challenge says "cookie mode"
        client.SendCsrfHeader = false;
        var missingHeader = await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = preAuth, code = Code(app, sharedKey) }, HttpStatusCode.Forbidden);
        Assert.Equal("csrf_validation_failed", missingHeader.Str("status"));

        client.SendCsrfHeader = true;
        client.Origin = "https://evil.example";
        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = preAuth, code = Code(app, sharedKey) }, HttpStatusCode.Forbidden);

        client.Origin = null;
        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = preAuth, code = Code(app, sharedKey) });
        Assert.True(client.Cookies.ContainsKey("SlimAuth"));
    }

    [Fact]
    public async Task Bearer_mode_2fa_step_needs_no_csrf_header()
    {
        await using var app = await TestApp.StartAsync();
        var (sharedKey, _) = await EnableTotpAsync(app);
        var client = app.CreateClient();

        var preAuth = (await client.PostJsonAsync("/auth/login?useCookies=false", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized)).Str("preAuthToken");
        var session = await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = preAuth, code = Code(app, sharedKey) });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
    }

    [Fact]
    public async Task Parallel_failed_logins_are_all_counted()
    {
        await using var app = await TestApp.StartAsync();

        await Task.WhenAll(Enumerable.Range(0, 5).Select(_ =>
            app.CreateClient().PostAsync("/auth/login", new { email = TestApp.UserEmail, password = "wrong-password" })));

        var user = app.Users.Get(TestApp.UserEmail);
        Assert.Equal(5, user.FailedLoginAttempts);
        Assert.True(user.IsLockedOut(app.Time.GetUtcNow()));
        await app.Mail.WaitForAsync("lockout", TestApp.UserEmail);
        Assert.Single(app.Mail.Mails, m => m.Kind == "lockout");
    }

    [Fact]
    public async Task A_failed_login_never_undoes_a_concurrent_password_change()
    {
        await using var app = await TestApp.StartAsync();
        var before = app.Users.Get(TestApp.UserEmail);

        // the password is changed while the failed attempt is being verified / recorded
        app.Users.BeforeFailedAttempt = id => { app.Users.BeforeFailedAttempt = null; app.Users.ChangePassword(id, "Changed123!"); };
        await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = "wrong-password" }, HttpStatusCode.Unauthorized);

        var after = app.Users.Get(TestApp.UserEmail);
        Assert.NotEqual(before.PasswordHash, after.PasswordHash);
        Assert.NotEqual(before.SecurityStamp, after.SecurityStamp);
        Assert.Equal(1, after.FailedLoginAttempts);

        await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);
        await app.LoginBearerAsync(TestApp.UserEmail, "Changed123!");
    }

    [Fact]
    public async Task A_registration_race_gets_the_uniform_answer()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();
        var normal = await (await client.PostAsync("/auth/register", new { email = "first@test.local", password = "Another123!" })).Content.ReadAsStringAsync();

        // another request registers the same address between the lookup and the insert
        app.Users.BeforeCreate = email => { app.Users.BeforeCreate = null; app.Users.Seed(email, "Other123!"); };
        var raced = await client.PostAsync("/auth/register", new { email = "race@test.local", password = "Another123!" });

        Assert.Equal(HttpStatusCode.OK, raced.StatusCode);
        Assert.Equal(normal, await raced.Content.ReadAsStringAsync());
        await app.Mail.WaitForAsync("account-exists", "race@test.local");
    }
}
