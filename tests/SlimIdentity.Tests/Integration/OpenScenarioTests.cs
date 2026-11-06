using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Security.Claims;
using Microsoft.AspNetCore.WebUtilities;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Attack scenarios of docs/attack-scenarios.md that were "open": each test performs the attack and fails if it succeeds.</summary>
public sealed class OpenScenarioTests
{
    private const string JwtSecret = "test-secret-0123456789-abcdefghijklmnopqrstuvwxyz";   // TestApp's key

    // ------------------------------------------------------------------ C1: JWT manipulation

    private static (JsonObject Header, JsonObject Payload) Decode(string jwt)
    {
        var parts = jwt.Split('.');
        return (JsonNode.Parse(Base64Url.DecodeFromChars(parts[0]))!.AsObject(), JsonNode.Parse(Base64Url.DecodeFromChars(parts[1]))!.AsObject());
    }

    private static string Encode(JsonObject header, JsonObject payload, string? key, Func<byte[], byte[], byte[]>? mac = null)
    {
        var unsigned = $"{Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString()))}.{Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payload.ToJsonString()))}";
        if (key is null) return unsigned + ".";
        var signature = (mac ?? HMACSHA256.HashData)(Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(unsigned));
        return $"{unsigned}.{Base64Url.EncodeToString(signature)}";
    }

    private static async Task<HttpStatusCode> CallWith(TestApp app, string token)
    {
        var client = app.CreateClient();
        client.BearerToken = token;
        return (await client.GetAsync("/api/hello")).StatusCode;
    }

    public static TheoryData<string> Manipulations => ["control", "alg-none", "wrong-key", "hs512-same-key", "expired", "no-exp", "wrong-issuer", "wrong-audience", "future-nbf", "stamp-swapped"];

    [Theory]
    [MemberData(nameof(Manipulations))]
    public async Task C1_manipulated_jwts_are_rejected(string manipulation)
    {
        await using var app = await TestApp.StartAsync();
        var real = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken!;
        var (header, payload) = Decode(real);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();   // JWT validation uses the system clock

        var token = manipulation switch
        {
            "control" => Encode(header, payload, JwtSecret),   // re-signed unchanged: proves the forging helper is correct
            "alg-none" => Encode(Set(header, "alg", "none"), payload, key: null),
            "wrong-key" => Encode(header, payload, "another-secret-0123456789-abcdefghijklmnop"),
            "hs512-same-key" => Encode(Set(header, "alg", "HS512"), payload, JwtSecret, HMACSHA512.HashData),
            "expired" => Encode(header, Set(Set(payload, "exp", now - 3600), "nbf", now - 7200), JwtSecret),
            "no-exp" => Encode(header, Remove(payload, "exp"), JwtSecret),
            "wrong-issuer" => Encode(header, Set(payload, "iss", "evil"), JwtSecret),
            "wrong-audience" => Encode(header, Set(payload, "aud", "evil"), JwtSecret),
            "future-nbf" => Encode(header, Set(payload, "nbf", now + 3600), JwtSecret),
            "stamp-swapped" => Encode(header, Set(payload, SlimClaimTypes.SecurityStamp, SlimUser.NewSecurityStamp()), JwtSecret),
            _ => throw new ArgumentOutOfRangeException(nameof(manipulation)),
        };

        var expected = manipulation == "control" ? HttpStatusCode.OK : HttpStatusCode.Unauthorized;
        Assert.Equal(expected, await CallWith(app, token));
    }

    private static JsonObject Set(JsonObject o, string name, JsonNode? value) { var copy = o.DeepClone().AsObject(); copy[name] = value; return copy; }
    private static JsonObject Remove(JsonObject o, string name) { var copy = o.DeepClone().AsObject(); copy.Remove(name); return copy; }

    // ------------------------------------------------------------------ C7: token of one user against the session of another

    [Fact]
    public async Task C7_a_token_bound_to_another_users_session_is_rejected()
    {
        // Even with the signing key (defence in depth): the session id must belong to the token's user.
        await using var app = await TestApp.StartAsync();
        var user = Decode((await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken!).Payload;
        var (header, admin) = Decode((await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword)).AccessToken!);

        var forged = Encode(header, Set(admin, SlimClaimTypes.SessionId, user[SlimClaimTypes.SessionId]!.GetValue<string>()), JwtSecret);
        Assert.Equal(HttpStatusCode.Unauthorized, await CallWith(app, forged));
    }

    // ------------------------------------------------------------------ C9: /logout with someone else's or a garbage token

    [Fact]
    public async Task C9_logout_cannot_end_other_users_sessions()
    {
        await using var app = await TestApp.StartAsync();
        var victim = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var attacker = app.CreateClient();
        attacker.BearerToken = (await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword)).AccessToken;

        await attacker.PostJsonAsync("/auth/logout", new { refreshToken = "garbage" });
        await attacker.PostJsonAsync("/auth/logout", new { refreshToken = victim.RefreshToken + "x" });
        await app.CreateClient().PostJsonAsync("/auth/logout", new { refreshToken = victim.RefreshToken![..20] });

        Assert.Equal(HttpStatusCode.OK, await CallWith(app, victim.AccessToken!));
        await app.CreateClient().PostJsonAsync("/auth/refresh", new { refreshToken = victim.RefreshToken });
    }

    // ------------------------------------------------------------------ E4: reset link after a password change elsewhere

    [Fact]
    public async Task E4_a_reset_link_dies_when_the_password_is_changed_elsewhere()
    {
        await using var app = await TestApp.StartAsync();
        await app.CreateClient().PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        var link = (await app.Mail.WaitForAsync("password-reset", TestApp.UserEmail)).Payload;

        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await me.PostJsonAsync("/auth/change-password", new { currentPassword = TestApp.UserPassword, newPassword = "Changed-Pass-123" });

        await app.CreateClient().PostJsonAsync("/auth/reset-password", new { token = link, newPassword = "Attacker-Pass-123" }, HttpStatusCode.BadRequest);
        await app.LoginBearerAsync(TestApp.UserEmail, "Changed-Pass-123");
    }

    // ------------------------------------------------------------------ B6: session fixation

    [Fact]
    public async Task B6_a_planted_cookie_never_becomes_the_victims_session()
    {
        await using var app = await TestApp.StartAsync();
        var attacker = app.CreateClient();
        attacker.SendCsrfHeader = true;
        await attacker.PostJsonAsync("/auth/login?useCookies=true", new { email = TestApp.AdminEmail, password = TestApp.AdminPassword });
        var planted = attacker.Cookies["SlimAuth"];

        var victim = app.CreateClient();
        victim.SendCsrfHeader = true;
        victim.SetCookies(new Dictionary<string, string> { ["SlimAuth"] = planted });
        await victim.PostJsonAsync("/auth/login?useCookies=true", new { email = TestApp.UserEmail, password = TestApp.UserPassword });

        Assert.NotEqual(planted, victim.Cookies["SlimAuth"]);   // a new ticket was issued
        var withPlanted = app.CreateClient();
        withPlanted.SetCookies(new Dictionary<string, string> { ["SlimAuth"] = planted });
        var response = await withPlanted.GetAsync("/api/hello");
        Assert.DoesNotContain(TestApp.UserEmail, await response.Content.ReadAsStringAsync());   // never the victim
    }

    // ------------------------------------------------------------------ A7: X-Forwarded-For spoofing

    [Fact]
    public async Task A7_spoofed_forwarded_headers_do_not_reset_the_rate_limit()
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

    // ------------------------------------------------------------------ H7: error answers reveal no internals

    // Unhandled exceptions (e.g. a failing store) are the host's exception handler's business – in Production ASP.NET Core
    // answers 500 without details. This test covers every error answer SlimIdentity produces itself.
    [Fact]
    public async Task H7_error_answers_reveal_no_internals()
    {
        await using var app = await TestApp.StartAsync();
        var responses = new[]
        {
            await app.CreateClient().SendRawAsync("/auth/login", "{ \"email\": ", "application/json"),                       // malformed JSON
            await app.CreateClient().SendRawAsync("/auth/login", "email=a&password=b", "application/x-www-form-urlencoded"),  // wrong type
            await app.CreateClient().SendRawAsync("/auth/login", """{"email":"x@test.local","password":["a"]}""", "application/json"), // wrong shape
            await app.CreateClient().PostAsync("/auth/reset-password", new { token = "AAAA" + new string('x', 300), newPassword = "Whatever-123" }),
            await app.CreateClient().PostAsync("/auth/login/2fa", new { preAuthToken = "not-a-token", code = "123456" }),
            await app.CreateClient().PostAsync("/auth/refresh", new { refreshToken = "CfDJ8" + new string('A', 200) }),
            await app.CreateClient().PostAsync("/auth/register", new { email = "not-an-address", password = "x" }),
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

    // ------------------------------------------------------------------ G2 / G4 / D9: impersonation and 2FA changes

    private static async Task<(ApiClient Impersonation, JsonElement Response)> ImpersonateUserAsync(TestApp app)
    {
        var admin = app.CreateClient();
        admin.BearerToken = (await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword)).AccessToken;
        var response = await admin.PostJsonAsync($"/api/impersonate/{app.Users.Get(TestApp.UserEmail).Id}");
        var impersonation = app.CreateClient();
        impersonation.BearerToken = response.Str("accessToken");
        return (impersonation, response);
    }

    public static TheoryData<string, string> SensitiveActions => new()
    {
        { "/auth/change-password", """{"currentPassword":"User1234!","newPassword":"Hijacked-123"}""" },
        { "/auth/change-email", """{"newEmail":"hijack@test.local","password":"User1234!"}""" },
        { "/auth/logout-all", "{}" },
        { "/auth/2fa/setup", "{}" },
        { "/auth/2fa/enable-email", """{"password":"User1234!"}""" },
        { "/auth/2fa/disable", """{"password":"User1234!"}""" },
        { "/auth/2fa/recovery-codes", """{"password":"User1234!"}""" },
        { "/auth/2fa/forget-all-devices", "{}" },
    };

    [Theory]
    [MemberData(nameof(SensitiveActions))]
    public async Task G2_an_impersonation_session_cannot_perform_sensitive_actions(string path, string body)
    {
        await using var app = await TestApp.StartAsync();
        var (impersonation, _) = await ImpersonateUserAsync(app);
        var response = await impersonation.SendRawAsync(path, body, "application/json");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("not_allowed_while_impersonating", await response.Content.ReadAsStringAsync());
        await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);   // the user's account is untouched
    }

    [Fact]
    public async Task G4_impersonation_issues_no_refresh_token()
    {
        await using var app = await TestApp.StartAsync();
        var (_, response) = await ImpersonateUserAsync(app);
        Assert.True(!response.TryGetProperty("refreshToken", out var r) || r.ValueKind == JsonValueKind.Null);
    }

    [Theory]
    [InlineData("/auth/2fa/disable")]
    [InlineData("/auth/2fa/recovery-codes")]
    [InlineData("/auth/2fa/enable-email")]
    public async Task D9_two_factor_changes_need_the_password(string path)
    {
        await using var app = await TestApp.StartAsync();
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await me.PostJsonAsync(path, new { }, HttpStatusCode.BadRequest);
        await me.PostJsonAsync(path, new { password = "wrong-password" }, HttpStatusCode.BadRequest);
    }

    // ------------------------------------------------------------------ F4: exchange code in parallel and after expiry

    private static TestAppOptions WithProvider() => new()
    {
        Builder = b =>
        {
            b.AddExternalLoginStore<TestExternalLoginStore>(Microsoft.Extensions.DependencyInjection.ServiceLifetime.Singleton);
            b.Authentication.AddScheme<FakeOAuthOptions, FakeOAuthHandler>("Fake", o => o.Claims =
                [new Claim(ClaimTypes.NameIdentifier, "ext-1"), new Claim(ClaimTypes.Email, "social@test.local"), new Claim("email_verified", "true")]);
        },
    };

    private static async Task<string> ExchangeCodeAsync(TestApp app)
    {
        var browser = app.CreateClient();
        var challenge = await browser.GetAsync("/auth/login/Fake?useCookies=false&returnUrl=/done");
        var callback = await browser.GetAsync(challenge.Headers.Location!.OriginalString);
        var target = new Uri(new Uri("https://localhost"), callback.Headers.Location!);
        return QueryHelpers.ParseQuery(target.Query)["code"].ToString();
    }

    [Fact]
    public async Task F4_an_exchange_code_is_redeemed_once_even_in_parallel()
    {
        await using var app = await TestApp.StartAsync(WithProvider());
        var code = await ExchangeCodeAsync(app);
        var statuses = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
            (await app.CreateClient().PostAsync("/auth/login/external/exchange", new { code })).StatusCode)));
        Assert.Equal(1, statuses.Count(s => s == HttpStatusCode.OK));
    }

    [Fact]
    public async Task F4_an_exchange_code_expires()
    {
        await using var app = await TestApp.StartAsync(WithProvider());
        var code = await ExchangeCodeAsync(app);
        app.Time.Advance(TimeSpan.FromMinutes(2));
        await app.CreateClient().PostJsonAsync("/auth/login/external/exchange", new { code }, HttpStatusCode.Unauthorized);
    }
}
