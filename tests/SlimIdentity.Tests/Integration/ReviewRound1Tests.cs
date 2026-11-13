using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Findings of the first external review round (docs/review-prompt.md), each proven by a failing test first.</summary>
public sealed class ReviewRound1Tests
{
    private const string Victim = "victim@test.local";

    private static TestAppOptions WithProvider(params Claim[] claims) => new()
    {
        Builder = b =>
        {
            b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
            b.Authentication.AddScheme<FakeOAuthOptions, FakeOAuthHandler>("Fake", o => o.Claims = [.. claims]);
        },
    };

    private static async Task<Uri> SignInExternallyAsync(ApiClient browser, string query = "useCookies=true&returnUrl=/done")
    {
        var challenge = await browser.GetAsync($"/auth/login/Fake?{query}");
        var callback = await browser.GetAsync(challenge.Headers.Location!.OriginalString);
        return new Uri(new Uri("https://localhost"), callback.Headers.Location!);
    }

    // ------------------------------------------------------------------ C1 / R6: secrets after external login

    private static readonly Claim[] VerifiedUser =
        [new Claim(ClaimTypes.NameIdentifier, "ext-1"), new Claim(ClaimTypes.Email, "social@test.local"), new Claim("email_verified", "true")];

    internal static (string Verifier, string Challenge) Pkce()
    {
        var verifier = System.Buffers.Text.Base64Url.EncodeToString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var challenge = System.Buffers.Text.Base64Url.EncodeToString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }

    private static Dictionary<string, string> Fragment(Uri target) =>
        QueryHelpers.ParseQuery(target.Fragment.TrimStart('#')).ToDictionary(p => p.Key, p => p.Value.ToString());

    [Fact]
    public async Task C1_bearer_external_login_requires_a_pkce_challenge()
    {
        await using var app = await TestApp.StartAsync(WithProvider(VerifiedUser));
        var response = await app.CreateClient().GetAsync("/auth/login/Fake?useCookies=false&returnUrl=/done");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("code_challenge_required", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task C1_the_exchange_code_travels_in_the_fragment_and_is_worthless_without_the_verifier()
    {
        await using var app = await TestApp.StartAsync(WithProvider(VerifiedUser));
        var (verifier, challenge) = Pkce();

        var target = await SignInExternallyAsync(app.CreateClient(), $"useCookies=false&returnUrl=/done&code_challenge={challenge}&code_challenge_method=S256");
        Assert.DoesNotContain("code=", target.Query);                  // never sent to servers, logs or referrers
        var code = Fragment(target)["code"];

        // whoever intercepted the URL (deep link, history) has the code – but not the verifier
        await app.CreateClient().PostJsonAsync("/auth/login/external/exchange", new { code }, HttpStatusCode.Unauthorized);
        await app.CreateClient().PostJsonAsync("/auth/login/external/exchange", new { code, codeVerifier = Pkce().Verifier }, HttpStatusCode.Unauthorized);
        var tokens = await app.CreateClient().PostJsonAsync("/auth/login/external/exchange", new { code, codeVerifier = verifier });
        Assert.False(string.IsNullOrEmpty(tokens.Str("accessToken")));
    }

    [Fact]
    public async Task R6_no_pre_auth_token_in_the_query_after_external_login_with_2fa()
    {
        await using var app = await TestApp.StartAsync(WithProvider(VerifiedUser));
        // the external user exists and has e-mail 2FA
        await SignInExternallyAsync(app.CreateClient());
        var user = app.Users.Get("social@test.local");
        user.TwoFactorEnabled = true;
        await app.Users.UpdateSecurityStateAsync(user, default);

        // cookie mode: the challenge comes back in the fragment
        var cookieTarget = await SignInExternallyAsync(app.CreateClient());
        Assert.DoesNotContain("flowToken", cookieTarget.Query);
        Assert.Equal("action_required", Fragment(cookieTarget)["slim_status"]);
        Assert.False(string.IsNullOrEmpty(Fragment(cookieTarget)["flowToken"]));

        // bearer mode: the (PKCE-bound) exchange answers with the challenge instead of tokens
        var (verifier, challenge) = Pkce();
        var bearerTarget = await SignInExternallyAsync(app.CreateClient(), $"useCookies=false&returnUrl=/done&code_challenge={challenge}&code_challenge_method=S256");
        Assert.DoesNotContain("flowToken", bearerTarget.Query + bearerTarget.Fragment);
        var exchanged = await app.CreateClient().PostJsonAsync("/auth/login/external/exchange",
            new { code = Fragment(bearerTarget)["code"], codeVerifier = verifier });
        Assert.Equal("second_factor", exchanged.GetProperty("actions")[0].GetString());
        Assert.False(string.IsNullOrEmpty(exchanged.Str("flowToken")));
    }

    // ------------------------------------------------------------------ R3

    /// <summary>Counts the real password verifications of non-dummy users (per test instance via the user's e-mail).</summary>
    private sealed class CountingHasher : Microsoft.AspNetCore.Identity.IPasswordHasher<SlimUser>
    {
        public static readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> Verified = new();
        private readonly Microsoft.AspNetCore.Identity.PasswordHasher<SlimUser> _inner = new();
        public string HashPassword(SlimUser user, string password) => _inner.HashPassword(user, password);
        public Microsoft.AspNetCore.Identity.PasswordVerificationResult VerifyHashedPassword(SlimUser user, string hashedPassword, string providedPassword)
        {
            if (user.Id != "slim-dummy") Verified.AddOrUpdate(user.Email, 1, (_, n) => n + 1);
            return _inner.VerifyHashedPassword(user, hashedPassword, providedPassword);
        }
    }

    [Fact]
    public async Task R3_parallel_password_guesses_beyond_the_threshold_are_not_evaluated()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions   // MaxFailedAttempts = 5 (default)
        {
            Builder = b => b.Services.AddScoped<Microsoft.AspNetCore.Identity.IPasswordHasher<SlimUser>, CountingHasher>(),
        });
        CountingHasher.Verified.TryRemove(TestApp.UserEmail, out _);

        await Task.WhenAll(Enumerable.Range(0, 40).Select(i => Task.Run(() =>
            app.CreateClient().PostAsync("/auth/login", new { email = TestApp.UserEmail, password = $"guess-{i:D3}-wrong" }))));

        Assert.Equal(5, CountingHasher.Verified.GetValueOrDefault(TestApp.UserEmail));
        Assert.Equal(5, app.Users.Get(TestApp.UserEmail).FailedLoginAttempts);
    }

    [Fact]
    public async Task R3_parallel_second_factor_guesses_beyond_the_threshold_are_not_evaluated()
    {
        await using var app = await TestApp.StartAsync();
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        var setup = await me.PostJsonAsync("/auth/2fa/setup");
        await me.PostJsonAsync("/auth/2fa/enable",
            new { setupToken = setup.Str("setupToken"), code = Code(app, setup.Str("sharedKey")), password = TestApp.UserPassword });
        app.Time.Advance(TimeSpan.FromSeconds(30));

        // the attacker knows the password and races 40 guesses of the 6-digit code
        var preAuth = (await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword })).Str("flowToken");
        var valid = Code(app, setup.Str("sharedKey"));
        var guesses = Enumerable.Range(0, 1_000_000).Select(n => n.ToString("D6", System.Globalization.CultureInfo.InvariantCulture))
            .Where(g => g != valid).Take(40).ToArray();
        await Task.WhenAll(guesses.Select(g => Task.Run(() =>
            app.CreateClient().PostAsync("/auth/login/2fa", new { flowToken = preAuth, code = g }))));

        // every evaluated wrong guess is counted – more than five means guesses slipped past the lockout
        Assert.Equal(5, app.Users.Get(TestApp.UserEmail).FailedSecondFactorAttempts);
    }

    // ------------------------------------------------------------------ R5

    /// <summary>A host that binds API keys to users ("personal access tokens" with a narrow scope).</summary>
    private sealed class PersonalApiKeys(ISlimUserStore users) : ISlimApiKeyStore
    {
        public static readonly (string Key, string Hash) Key = SlimApiKeys.Generate("pat");

        public async Task<IReadOnlyCollection<Claim>?> ValidateApiKeyAsync(string keyHash, CancellationToken ct) =>
            keyHash == Key.Hash
                ? [new Claim(SlimClaimTypes.UserId, (await users.FindByEmailAsync(TestApp.UserEmail, ct))!.Id), new Claim("scope", "reports:read")]
                : null;
    }

    [Theory]
    [InlineData("/auth/2fa/forget-all-devices")]
    [InlineData("/auth/logout-all")]
    [InlineData("/auth/2fa/setup")]
    public async Task R5_an_api_key_cannot_act_as_the_user_on_the_account_endpoints(string path)
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions
        {
            Builder = b => b.AddApiKeyStore<PersonalApiKeys>(ServiceLifetime.Singleton),
        });

        var response = await app.CreateClient().SendAsync(HttpMethod.Post, path, new { },
            new Dictionary<string, string> { [SlimIdentityDefaults.ApiKeyHeaderName] = PersonalApiKeys.Key.Key });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);   // API keys are machine-to-machine, never a user session
    }

    // ------------------------------------------------------------------ R2

    [Fact]
    public async Task R2_replacing_the_authenticator_needs_the_password()
    {
        await using var app = await TestApp.StartAsync();
        var owner = app.CreateClient();
        owner.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        var ownerSetup = await owner.PostJsonAsync("/auth/2fa/setup");
        var enabled = await owner.PostJsonAsync("/auth/2fa/enable",
            new { setupToken = ownerSetup.Str("setupToken"), code = Code(app, ownerSetup.Str("sharedKey")), password = TestApp.UserPassword });

        // someone holds the session (stolen access token, XSS) but not the password
        var thief = app.CreateClient();
        thief.BearerToken = enabled.GetProperty("session").Str("accessToken");
        app.Time.Advance(TimeSpan.FromSeconds(30));
        var thiefSetup = await thief.PostJsonAsync("/auth/2fa/setup");
        await thief.PostJsonAsync("/auth/2fa/enable",
            new { setupToken = thiefSetup.Str("setupToken"), code = Code(app, thiefSetup.Str("sharedKey")) }, HttpStatusCode.BadRequest);
        await thief.PostJsonAsync("/auth/2fa/enable",
            new { setupToken = thiefSetup.Str("setupToken"), code = Code(app, thiefSetup.Str("sharedKey")), password = "guess" }, HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task R2_a_setup_token_dies_with_the_security_stamp()
    {
        await using var app = await TestApp.StartAsync();
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        var setup = await me.PostJsonAsync("/auth/2fa/setup");

        await me.PostJsonAsync("/auth/logout-all");   // rotates the stamp (e.g. after a suspected compromise)
        var fresh = app.CreateClient();
        fresh.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await fresh.PostJsonAsync("/auth/2fa/enable",
            new { setupToken = setup.Str("setupToken"), code = Code(app, setup.Str("sharedKey")), password = TestApp.UserPassword }, HttpStatusCode.BadRequest);
    }

    private static string Code(TestApp app, string sharedKey) =>
        SlimIdentity.Security.SlimTotp.Compute(SlimIdentity.Security.SlimBase32.Decode(sharedKey), app.Time.GetUtcNow().ToUnixTimeSeconds() / 30);

    // ------------------------------------------------------------------ R1

    [Fact]
    public async Task R1_no_account_is_created_for_an_unverified_provider_address()
    {
        // the attacker's own IdP account claims the victim's address without verifying it
        await using var app = await TestApp.StartAsync(WithProvider(
            new Claim(ClaimTypes.NameIdentifier, "attacker-idp-account"), new Claim(ClaimTypes.Email, Victim)));
        var browser = app.CreateClient();

        var target = await SignInExternallyAsync(browser);

        Assert.Equal("email_not_verified", QueryHelpers.ParseQuery(target.Query)["slim_error"].ToString());
        Assert.Null(await app.Users.FindByEmailAsync(Victim, default));
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/hello")).StatusCode);
    }

    [Fact]
    public async Task R1_the_owners_mailbox_proof_removes_external_logins_linked_before()
    {
        // defence in depth: an unconfirmed account that already carries a foreign external login (older data, a host
        // that linked it, a provider wrongly listed as trusted) – the owner's first mailbox proof must cut it off
        await using var app = await TestApp.StartAsync(WithProvider(
            new Claim(ClaimTypes.NameIdentifier, "attacker-idp-account"), new Claim(ClaimTypes.Email, Victim)));
        await app.PreRegisterUnconfirmedAsync(Victim, "Attacker-Pass-123");
        var victimId = app.Users.Get(Victim).Id;
        var links = (TestExternalLoginStore)app.App.Services.GetRequiredService<ISlimExternalLoginStore>();
        await links.LinkExternalLoginAsync(victimId, "Fake", "attacker-idp-account", default);

        await app.CreateClient().PostAsync("/auth/forgot-password", new { email = Victim });
        var token = (await app.Mail.WaitForAsync("password-reset", Victim)).Payload;
        await app.CreateClient().PostJsonAsync("/auth/reset-password", new { token, newPassword = "Owner-Pass-456" });

        Assert.Null(await links.FindByExternalLoginAsync("Fake", "attacker-idp-account", default));
        var again = app.CreateClient();
        await SignInExternallyAsync(again);
        Assert.Equal(HttpStatusCode.Unauthorized, (await again.GetAsync("/api/hello")).StatusCode);
    }
}
