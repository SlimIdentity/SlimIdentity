using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Sign-in with an external provider: account creation, joining existing accounts, the bearer exchange code.</summary>
public sealed class ExternalLoginTests
{
    private const string SocialEmail = "social@test.local";
    private const string Victim = "victim@test.local";

    private static readonly Claim[] VerifiedSocial =
        [new Claim(ClaimTypes.NameIdentifier, "ext-123"), new Claim(ClaimTypes.Email, SocialEmail), new Claim("email_verified", "true")];

    private static TestAppOptions WithProvider(params Claim[] claims) => WithProvider(refreshTokens: true, claims);

    private static TestAppOptions WithProvider(bool refreshTokens, params Claim[] claims) => new()
    {
        RefreshTokens = refreshTokens,
        Builder = b =>
        {
            b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
            b.Authentication.AddScheme<FakeOAuthOptions, FakeOAuthHandler>("Fake", o => o.Claims = [.. claims]);
        },
    };

    /// <summary>Browser navigation: /auth/login/Fake → provider → callback → returnUrl.</summary>
    private static async Task<Uri> NavigateAsync(ApiClient browser, string query = "useCookies=true&returnUrl=/done")
    {
        var challenge = await browser.GetAsync($"/auth/login/Fake?{query}");
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        var callback = await browser.GetAsync(challenge.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        return new Uri(new Uri("https://localhost"), callback.Headers.Location!);
    }

    private static Dictionary<string, string> Fragment(Uri target) =>
        QueryHelpers.ParseQuery(target.Fragment.TrimStart('#')).ToDictionary(p => p.Key, p => p.Value.ToString());

    private static string Error(Uri target) => QueryHelpers.ParseQuery(target.Query)["slim_error"].ToString();

    /// <summary>Bearer mode with PKCE: returns the exchange code from the fragment and its verifier.</summary>
    private static async Task<(string Code, string Verifier)> ExchangeCodeAsync(TestApp app)
    {
        var (verifier, challenge) = Pkce.Create();
        var target = await NavigateAsync(app.CreateClient(), $"useCookies=false&returnUrl=/done&code_challenge={challenge}&code_challenge_method=S256");
        Assert.DoesNotContain("code=", target.Query);   // never sent to servers, logs or referrers
        return (Fragment(target)["code"], verifier);
    }

    // ------------------------------------------------------------------ bearer exchange code

    [Fact]
    public async Task New_external_user_is_created_and_bearer_clients_exchange_a_one_time_code()
    {
        await using var app = await TestApp.StartAsync(WithProvider(VerifiedSocial));
        var browser = app.CreateClient();

        var (verifier, challenge) = Pkce.Create();
        var target = await NavigateAsync(browser, $"useCookies=false&returnUrl=/done&code_challenge={challenge}");
        Assert.Equal("/done", target.AbsolutePath);
        var code = Fragment(target)["code"];
        Assert.DoesNotContain("accessToken", target.ToString());   // tokens never travel in URLs

        var tokens = await app.CreateClient().PostJsonAsync("/auth/login/external/exchange", new { code, codeVerifier = verifier });
        Assert.False(string.IsNullOrEmpty(tokens.Str("accessToken")));
        Assert.True(app.Users.Get(SocialEmail).EmailConfirmed);
    }

    [Fact]
    public async Task Bearer_external_login_requires_a_pkce_challenge()
    {
        await using var app = await TestApp.StartAsync(WithProvider(VerifiedSocial));
        var response = await app.CreateClient().GetAsync("/auth/login/Fake?useCookies=false&returnUrl=/done");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("code_challenge_required", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task The_exchange_code_is_worthless_without_the_verifier()
    {
        await using var app = await TestApp.StartAsync(WithProvider(VerifiedSocial));
        var (code, verifier) = await ExchangeCodeAsync(app);

        // whoever intercepted the URL (deep link, history) has the code – but not the verifier
        await app.CreateClient().PostJsonAsync("/auth/login/external/exchange", new { code }, HttpStatusCode.Unauthorized);
        await app.CreateClient().PostJsonAsync("/auth/login/external/exchange", new { code, codeVerifier = Pkce.Create().Verifier }, HttpStatusCode.Unauthorized);
        var tokens = await app.CreateClient().PostJsonAsync("/auth/login/external/exchange", new { code, codeVerifier = verifier });
        Assert.False(string.IsNullOrEmpty(tokens.Str("accessToken")));
    }

    [Theory]
    [InlineData(true)]    // consumed atomically via ISlimRefreshTokenStore
    [InlineData(false)]   // in-memory fallback
    public async Task The_exchange_code_is_redeemed_once_even_in_parallel(bool refreshTokens)
    {
        await using var app = await TestApp.StartAsync(WithProvider(refreshTokens, VerifiedSocial));
        var (code, verifier) = await ExchangeCodeAsync(app);

        var statuses = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
            (await app.CreateClient().PostAsync("/auth/login/external/exchange", new { code, codeVerifier = verifier })).StatusCode)));

        Assert.Equal(1, statuses.Count(s => s == HttpStatusCode.OK));
    }

    [Theory]
    [InlineData(true)]    // store path
    [InlineData(false)]   // in-memory path: the expiry follows the registered clock, too
    public async Task The_exchange_code_expires(bool refreshTokens)
    {
        await using var app = await TestApp.StartAsync(WithProvider(refreshTokens, VerifiedSocial));
        var (code, verifier) = await ExchangeCodeAsync(app);
        app.Time.Advance(TimeSpan.FromMinutes(2));
        await app.CreateClient().PostJsonAsync("/auth/login/external/exchange", new { code, codeVerifier = verifier }, HttpStatusCode.Unauthorized);
    }

    // ------------------------------------------------------------------ open steps after the provider round trip

    [Fact]
    public async Task A_linked_account_with_an_unconfirmed_address_proves_the_mailbox_in_the_flow()
    {
        await using var app = await TestApp.StartAsync(WithProvider(VerifiedSocial));
        await NavigateAsync(app.CreateClient());
        await app.SetEmailConfirmedAsync(SocialEmail, false);

        var browser = app.CreateClient();
        browser.SendCsrfHeader = true;
        var target = await NavigateAsync(browser);
        var fragment = Fragment(target);
        Assert.Equal("action_required", fragment["slim_status"]);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/hello")).StatusCode);

        var flowToken = fragment["flowToken"];
        Assert.Equal("verify_email", (await browser.PostJsonAsync("/auth/flow", new { flowToken })).GetProperty("actions")[0].GetString());
        var code = (await app.Mail.WaitForAsync("verification-code", SocialEmail)).Payload;
        await browser.PostJsonAsync("/auth/login/verify-email", new { flowToken, code });
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/hello")).StatusCode);
    }

    [Fact]
    public async Task No_flow_token_travels_in_the_query_when_a_second_factor_follows()
    {
        await using var app = await TestApp.StartAsync(WithProvider(VerifiedSocial));
        await NavigateAsync(app.CreateClient());
        var user = app.Users.Get(SocialEmail);
        user.TwoFactorEnabled = true;
        await app.Users.UpdateSecurityStateAsync(user, default);

        // cookie mode: the challenge comes back in the fragment
        var cookieTarget = await NavigateAsync(app.CreateClient());
        Assert.DoesNotContain("flowToken", cookieTarget.Query);
        Assert.Equal("action_required", Fragment(cookieTarget)["slim_status"]);
        Assert.False(string.IsNullOrEmpty(Fragment(cookieTarget)["flowToken"]));

        // bearer mode: the (PKCE-bound) exchange answers with the challenge instead of tokens
        var (verifier, challenge) = Pkce.Create();
        var bearerTarget = await NavigateAsync(app.CreateClient(), $"useCookies=false&returnUrl=/done&code_challenge={challenge}&code_challenge_method=S256");
        Assert.DoesNotContain("flowToken", bearerTarget.Query + bearerTarget.Fragment);
        var exchanged = await app.CreateClient().PostJsonAsync("/auth/login/external/exchange",
            new { code = Fragment(bearerTarget)["code"], codeVerifier = verifier });
        Assert.Equal("second_factor", exchanged.GetProperty("actions")[0].GetString());
        Assert.False(string.IsNullOrEmpty(exchanged.Str("flowToken")));
    }

    [Fact]
    public async Task A_forced_password_change_is_not_skipped_with_an_external_login()
    {
        await using var app = await TestApp.StartAsync(WithProvider(VerifiedSocial));
        await NavigateAsync(app.CreateClient());   // creates the account with its linked provider
        await using (var scope = app.App.Services.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<ISlimAuthManager>()
                .SetPasswordAsync(app.Users.Get(SocialEmail), "Start-Password-123", mustChange: true);

        var browser = app.CreateClient();
        var target = await NavigateAsync(browser);

        Assert.Equal("action_required", Fragment(target)["slim_status"]);
        Assert.False(string.IsNullOrEmpty(Fragment(target)["flowToken"]));
        Assert.DoesNotContain("flowToken", target.Query);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/auth/me")).StatusCode);
    }

    // ------------------------------------------------------------------ which addresses are trusted

    [Fact]
    public async Task Unverified_email_of_an_existing_account_is_not_linked()
    {
        await using var app = await TestApp.StartAsync(WithProvider(
            new Claim(ClaimTypes.NameIdentifier, "ext-attacker"), new Claim(ClaimTypes.Email, TestApp.UserEmail)));

        var target = await NavigateAsync(app.CreateClient());

        Assert.Equal("account_conflict", Error(target));
    }

    [Fact]
    public async Task No_account_is_created_for_an_address_the_provider_did_not_verify()
    {
        // the attacker's own IdP account claims the victim's address without verifying it
        await using var app = await TestApp.StartAsync(WithProvider(
            new Claim(ClaimTypes.NameIdentifier, "attacker-idp-account"), new Claim(ClaimTypes.Email, Victim)));
        var browser = app.CreateClient();

        var target = await NavigateAsync(browser);

        Assert.Equal("email_not_verified", Error(target));
        Assert.Null(await app.Users.FindByEmailAsync(Victim, default));
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/hello")).StatusCode);
    }

    [Fact]
    public async Task A_verified_flag_does_not_vouch_for_a_user_name_that_looks_like_an_address()
    {
        await using var app = await TestApp.StartAsync(WithProvider(
            new Claim(ClaimTypes.NameIdentifier, "entra-1"), new Claim("preferred_username", SocialEmail), new Claim("email_verified", "true")));

        var target = await NavigateAsync(app.CreateClient());

        Assert.Equal("email_not_verified", Error(target));
        Assert.Null(await app.Users.FindByEmailAsync(SocialEmail, default));
    }

    // ------------------------------------------------------------------ joining existing accounts

    [Fact]
    public async Task Verified_email_is_linked_to_an_account_without_password_and_cookie_mode_sets_the_session_cookie()
    {
        // only accounts without an own password are joined automatically (see ExternalLinkTests for the others)
        await using var app = await TestApp.StartAsync(WithProvider(
            new Claim(ClaimTypes.NameIdentifier, "ext-user"), new Claim(ClaimTypes.Email, "no-password@test.local"), new Claim("email_verified", "true")));
        app.Users.Seed("no-password@test.local", password: null);
        var browser = app.CreateClient();

        var target = await NavigateAsync(browser);

        Assert.Equal("/done", target.AbsolutePath);
        Assert.True(browser.Cookies.ContainsKey("SlimAuth"));
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/hello")).StatusCode);
    }

    [Fact]
    public async Task Pre_registered_unverified_account_is_not_joined_by_the_verified_owner()
    {
        // Pre-account hijacking: the attacker registers the victim's address with an own password before the victim
        // ever signs up (without mail, or imported). The victim later signs in with a provider that has verified the
        // address – the account is not shared; the victim takes it over with a password reset.
        await using var app = await TestApp.StartAsync(WithProvider(
            new Claim(ClaimTypes.NameIdentifier, "google-victim"), new Claim(ClaimTypes.Email, Victim), new Claim("email_verified", "true")));

        await app.PreRegisterUnconfirmedAsync(Victim, "Attacker-Pass-123");
        var pending = await app.CreateClient().PostJsonAsync("/auth/login", new { email = Victim, password = "Attacker-Pass-123" });
        Assert.Equal("verify_email", pending.GetProperty("actions")[0].GetString());   // no session without the mailbox

        var browser = app.CreateClient();
        var target = await NavigateAsync(browser);

        Assert.Equal("account_conflict", Error(target));
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/hello")).StatusCode);
        var account = app.Users.Get(Victim);
        Assert.False(account.EmailConfirmed);
        Assert.Null(await app.App.Services.GetRequiredService<ISlimExternalLoginStore>().FindByExternalLoginAsync("Fake", "google-victim", default));
    }

    [Fact]
    public async Task An_unconfirmed_account_with_a_start_password_is_not_joined_by_an_external_login()
    {
        await using var app = await TestApp.StartAsync(WithProvider(VerifiedSocial));
        await using (var scope = app.App.Services.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ISlimUserStore>();
            var created = await store.CreateAsync(new SlimNewUser { Email = SocialEmail }, default);
            Assert.False(created!.EmailConfirmed);
            await scope.ServiceProvider.GetRequiredService<ISlimAuthManager>().SetPasswordAsync(created, "Start-Password-123", mustChange: true);
        }

        var target = await NavigateAsync(app.CreateClient());

        Assert.Equal("account_conflict", Error(target));
        var user = app.Users.Get(SocialEmail);
        Assert.False(string.IsNullOrEmpty(user.PasswordHash));   // the start password and its change requirement stay
        Assert.True(user.PasswordChangeRequired);
    }

    [Fact]
    public async Task The_owners_mailbox_proof_removes_external_logins_linked_before()
    {
        // an unconfirmed account that already carries a foreign external login (older data, a host that linked it, a
        // provider wrongly listed as trusted) – the owner's first mailbox proof cuts it off
        await using var app = await TestApp.StartAsync(WithProvider(
            new Claim(ClaimTypes.NameIdentifier, "attacker-idp-account"), new Claim(ClaimTypes.Email, Victim)));
        await app.PreRegisterUnconfirmedAsync(Victim, "Attacker-Pass-123");
        var links = app.App.Services.GetRequiredService<ISlimExternalLoginStore>();
        await links.LinkExternalLoginAsync(app.Users.Get(Victim).Id, "Fake", "attacker-idp-account", default);

        await app.CreateClient().PostAsync("/auth/forgot-password", new { email = Victim });
        var token = (await app.Mail.WaitForAsync("password-reset", Victim)).Payload;
        await app.CreateClient().ResetPasswordJsonAsync(token, "Owner-Pass-456");

        Assert.Null(await links.FindByExternalLoginAsync("Fake", "attacker-idp-account", default));
        var again = app.CreateClient();
        await NavigateAsync(again);
        Assert.Equal(HttpStatusCode.Unauthorized, (await again.GetAsync("/api/hello")).StatusCode);
    }

    [Fact]
    public async Task An_unconfirmed_account_without_a_way_in_is_confirmed_and_linked_by_a_verified_external_login()
    {
        // created by a host or an import without a password: the provider's verified address is the first proof
        const string member = "member@test.local";
        await using var app = await TestApp.StartAsync(WithProvider(
            new Claim(ClaimTypes.NameIdentifier, "google-member"), new Claim(ClaimTypes.Email, member), new Claim("email_verified", "true")));
        await using (var scope = app.App.Services.CreateAsyncScope())
            Assert.False((await scope.ServiceProvider.GetRequiredService<ISlimUserStore>().CreateAsync(new SlimNewUser { Email = member }, default))!.EmailConfirmed);

        var browser = app.CreateClient();
        await NavigateAsync(browser);

        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/hello")).StatusCode);
        Assert.True(app.Users.Get(member).EmailConfirmed);
    }

    [Fact]
    public async Task Linking_a_confirmed_account_keeps_its_password()
    {
        await using var app = await TestApp.StartAsync(WithProvider(
            new Claim(ClaimTypes.NameIdentifier, "ext-user"), new Claim(ClaimTypes.Email, TestApp.UserEmail), new Claim("email_verified", "true")));
        await NavigateAsync(app.CreateClient());
        await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
    }

    // ------------------------------------------------------------------ lockout and accounts without a password

    [Fact]
    public async Task Wrong_passwords_of_a_stranger_do_not_count_against_an_account_without_a_password()
    {
        await using var app = await TestApp.StartAsync(WithProvider(VerifiedSocial));
        await NavigateAsync(app.CreateClient());   // the account exists, external login only

        var stranger = app.CreateClient();
        for (var i = 0; i < 6; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await stranger.PostAsync("/auth/login", new { email = SocialEmail, password = "guess-" + i })).StatusCode);

        Assert.Equal(0, app.Users.Get(SocialEmail).FailedLoginAttempts);
    }

    [Fact]
    public async Task A_lockout_does_not_block_the_external_sign_in()
    {
        await using var app = await TestApp.StartAsync(WithProvider(VerifiedSocial));
        await NavigateAsync(app.CreateClient());
        var id = app.Users.Get(SocialEmail).Id;
        app.Users.SetAttempts(id, SlimAttemptFactor.Password, 5, app.Time.GetUtcNow().AddMinutes(5));
        app.Users.SetAttempts(id, SlimAttemptFactor.SecondFactor, 5, app.Time.GetUtcNow().AddMinutes(5));

        var browser = app.CreateClient();
        var target = await NavigateAsync(browser);

        Assert.DoesNotContain("locked_out", target.ToString());
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/hello")).StatusCode);
    }

    [Fact]
    public async Task Foreign_return_urls_are_rejected()
    {
        await using var app = await TestApp.StartAsync(WithProvider(new Claim(ClaimTypes.NameIdentifier, "x")));
        var response = await app.CreateClient().GetAsync("/auth/login/Fake?returnUrl=https://evil.example/");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
