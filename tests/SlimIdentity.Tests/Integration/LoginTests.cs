using System.Net;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

public sealed class LoginTests
{
    [Fact]
    public async Task Bearer_login_returns_token_pair_usable_for_authorized_endpoints()
    {
        await using var app = await TestApp.StartAsync();
        var tokens = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);

        Assert.Equal("bearer", tokens.Mode);
        Assert.False(string.IsNullOrEmpty(tokens.AccessToken));
        Assert.False(string.IsNullOrEmpty(tokens.RefreshToken));

        var client = app.CreateClient();
        client.BearerToken = tokens.AccessToken;
        var me = await client.GetAsync("/auth/me");
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
    }

    [Fact]
    public async Task Wrong_password_unknown_user_and_inactive_user_get_identical_answers()
    {
        await using var app = await TestApp.StartAsync();
        var inactive = app.Users.Seed("inactive@test.local", "Inactive123!");
        app.Users.SetActive(inactive.Id, false);
        var client = app.CreateClient();

        var wrong = await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = "nope" });
        var unknown = await client.PostAsync("/auth/login", new { email = "nobody@test.local", password = "nope" });
        var disabled = await client.PostAsync("/auth/login", new { email = "inactive@test.local", password = "Inactive123!" });

        Assert.All(new[] { wrong, unknown, disabled }, r => Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode));
        var bodies = await Task.WhenAll(wrong.Content.ReadAsStringAsync(), unknown.Content.ReadAsStringAsync(), disabled.Content.ReadAsStringAsync());
        Assert.Single(bodies.Distinct());
        Assert.Contains("invalid_credentials", bodies[0]);
    }

    [Fact]
    public async Task Oversized_password_is_rejected_without_distinguishing_accounts()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();
        var huge = new string('a', 10_000);

        var known = await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = huge });
        var unknown = await client.PostAsync("/auth/login", new { email = "nobody@test.local", password = huge });

        Assert.Equal(HttpStatusCode.Unauthorized, known.StatusCode);
        Assert.Equal(await known.Content.ReadAsStringAsync(), await unknown.Content.ReadAsStringAsync());
        Assert.Equal(0, app.Users.Get(TestApp.UserEmail).FailedLoginAttempts);
    }

    [Fact]
    public async Task Lockout_is_progressive_and_hidden_by_default()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();

        for (var i = 1; i <= 5; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = $"wrong{i}" })).StatusCode);

        var user = app.Users.Get(TestApp.UserEmail);
        Assert.Equal(TimeSpan.FromMinutes(1), user.LockoutEndUtc - app.Time.GetUtcNow());

        // correct password during the lockout: same 401, not verified, not counted
        var locked = await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, locked.StatusCode);
        Assert.Equal(5, app.Users.Get(TestApp.UserEmail).FailedLoginAttempts);

        // second series → doubled duration
        app.Time.Advance(TimeSpan.FromMinutes(1.5));
        for (var i = 1; i <= 5; i++)
            await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = $"again{i}" });
        Assert.Equal(TimeSpan.FromMinutes(2), app.Users.Get(TestApp.UserEmail).LockoutEndUtc - app.Time.GetUtcNow());

        // success after expiry resets the counter
        app.Time.Advance(TimeSpan.FromMinutes(3));
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword })).StatusCode);
        Assert.Equal(0, app.Users.Get(TestApp.UserEmail).FailedLoginAttempts);
        Assert.Null(app.Users.Get(TestApp.UserEmail).LockoutEndUtc);
    }

    [Fact]
    public async Task Lockout_notification_is_sent_once_per_series()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();

        for (var i = 1; i <= 5; i++)
            await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = $"wrong{i}" });
        await app.Mail.WaitForAsync("lockout", TestApp.UserEmail);

        app.Time.Advance(TimeSpan.FromMinutes(2));
        for (var i = 1; i <= 5; i++)
            await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = $"again{i}" });
        await app.WaitForQueuedMailAsync();

        Assert.Single(app.Mail.Mails, m => m.Kind == "lockout");
    }

    [Fact]
    public async Task RevealAccountState_returns_403_for_inactive_and_423_for_locked_accounts()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Configure = o => o.SignIn.RevealAccountState = true });
        var inactive = app.Users.Seed("inactive@test.local", "Inactive123!");
        app.Users.SetActive(inactive.Id, false);
        var client = app.CreateClient();

        var disabled = await client.PostJsonAsync("/auth/login", new { email = "inactive@test.local", password = "Inactive123!" }, HttpStatusCode.Forbidden);
        Assert.Equal("account_disabled", disabled.Str("code"));

        for (var i = 1; i <= 4; i++)
            await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = $"wrong{i}" });
        var locked = await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = "wrong5" });
        Assert.Equal((HttpStatusCode)423, locked.StatusCode);
        Assert.True(locked.Headers.RetryAfter is not null);
        var problem = await ProblemAsync(locked);
        Assert.Equal("locked_out", problem.Str("code"));
        Assert.Equal(app.Users.Get(TestApp.UserEmail).LockoutEndUtc, problem.GetProperty("lockoutEndUtc").GetDateTimeOffset());
    }

    [Fact]
    public async Task Every_error_is_a_problem_with_a_code()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Configure = o => o.RateLimit.PermitLimit = 3 });
        var client = app.CreateClient();

        var wrong = await ProblemAsync(await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = "wrong" }));
        Assert.Equal((401, "invalid_credentials"), (wrong.GetProperty("status").GetInt32(), wrong.Str("code")));
        Assert.False(wrong.TryGetProperty("type", out _));

        var invalid = await ProblemAsync(await client.PostAsync("/auth/register", new { email = "not-an-address" }));
        Assert.Equal("validation_failed", invalid.Str("code"));
        Assert.True(invalid.GetProperty("errors").TryGetProperty("email", out _));

        Assert.Equal("unauthenticated", (await ProblemAsync(await client.GetAsync("/auth/me"))).Str("code"));

        HttpResponseMessage limited;
        do limited = await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = "wrong" });
        while (limited.StatusCode != HttpStatusCode.TooManyRequests);
        Assert.Equal("rate_limited", (await ProblemAsync(limited)).Str("code"));
    }

    private static async Task<System.Text.Json.JsonElement> ProblemAsync(HttpResponseMessage response)
    {
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var problem = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal((int)response.StatusCode, problem.GetProperty("status").GetInt32());
        return problem;
    }

    [Fact]
    public async Task Request_without_credentials_is_a_bad_request()
    {
        await using var app = await TestApp.StartAsync();
        var response = await app.CreateClient().PostAsync("/auth/login", new { email = "", password = "" });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task A_user_without_security_stamp_gets_one_at_the_first_sign_in()
    {
        // a user seeded by the host without a security stamp must not be signed out right after signing in
        await using var app = await TestApp.StartAsync();
        var user = app.Users.Get(TestApp.UserEmail);
        user.SecurityStamp = "";
        await app.Users.UpdateSecurityStateAsync(user, default);

        var client = app.CreateClient();
        client.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/me")).StatusCode);
        Assert.False(string.IsNullOrEmpty(app.Users.Get(TestApp.UserEmail).SecurityStamp));
    }

    [Theory]
    [InlineData("/auth/login?useCookies=false")]
    [InlineData("/auth/2fa/setup")]
    public async Task Responses_with_secrets_are_never_cached(string path)
    {
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();
        client.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;

        var response = await client.SendAsync(HttpMethod.Post, path, new { email = TestApp.UserEmail, password = TestApp.UserPassword });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore, $"{path}: Cache-Control is '{response.Headers.CacheControl}'");
    }

    [Fact]
    public async Task Spoofed_forwarded_headers_do_not_reset_the_rate_limit()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Configure = o => o.RateLimit.PermitLimit = 3 });
        var client = app.CreateClient();
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 5; i++)
        {
            var spoofed = new Dictionary<string, string> { ["X-Forwarded-For"] = $"203.0.113.{i}", ["X-Real-IP"] = $"198.51.100.{i}" };
            statuses.Add((await client.SendAsync(HttpMethod.Post, "/auth/login", new { email = TestApp.UserEmail, password = "wrong" }, spoofed)).StatusCode);
        }
        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[^1]);
        Assert.Equal(2, statuses.Count(s => s == HttpStatusCode.TooManyRequests));
    }

    // Unhandled exceptions (e.g. a failing store) are the host's exception handler's business – in Production ASP.NET Core
    // answers 500 without details. This test covers every error answer SlimIdentity produces itself.
    [Fact]
    public async Task Error_answers_reveal_no_internals()
    {
        await using var app = await TestApp.StartAsync();
        var responses = new[]
        {
            await app.CreateClient().SendRawAsync("/auth/login", "{ \"email\": ", "application/json"),                       // malformed JSON
            await app.CreateClient().SendRawAsync("/auth/login", "email=a&password=b", "application/x-www-form-urlencoded"),  // wrong type
            await app.CreateClient().SendRawAsync("/auth/login", """{"email":"x@test.local","password":["a"]}""", "application/json"), // wrong shape
            await app.CreateClient().PostAsync("/auth/flow", new { token = "AAAA" + new string('x', 300) }),
            await app.CreateClient().PostAsync("/auth/login/2fa", new { flowToken = "not-a-token", code = "123456" }),
            await app.CreateClient().PostAsync("/auth/refresh", new { refreshToken = "CfDJ8" + new string('A', 200) }),
            await app.CreateClient().PostAsync("/auth/register", new { email = "not-an-address" }),
        };

        foreach (var response in responses)
        {
            Assert.True((int)response.StatusCode is >= 400 and < 500, $"{response.RequestMessage!.RequestUri}: {(int)response.StatusCode}");
            var body = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain("   at ", body);                 // stack trace
            Assert.DoesNotContain("Exception", body);
            Assert.DoesNotContain("SlimIdentity.", body);          // type or namespace names
            Assert.DoesNotContain("CfDJ8", body);                  // echoed tokens
            Assert.False(response.Headers.Contains("X-Powered-By"));
        }
    }
}
