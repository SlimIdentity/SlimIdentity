using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Independent review (round 4, fresh-context agent): each test performs the attack / situation and failed before the fix.</summary>
public sealed class ReviewRound4Tests
{
    private const string Origin = "https://app.test.local";
    private const string SocialEmail = "social-only@test.local";

    private static TestAppOptions WithProviderAndPasskeys(Action<SlimIdentityBuilder>? more = null) => new()
    {
        Builder = b =>
        {
            b.AddPasskeyStore<TestPasskeyStore>(ServiceLifetime.Singleton).AddPasskeys(o => o.RelyingPartyId = "test.local");
            b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
            b.Authentication.AddScheme<FakeOAuthOptions, FakeOAuthHandler>("Fake", o => o.Claims =
                [new Claim(ClaimTypes.NameIdentifier, "google-1"), new Claim(ClaimTypes.Email, SocialEmail), new Claim("email_verified", "true")]);
            more?.Invoke(b);
        },
    };

    /// <summary>The owner signs in with the provider; the account has no password. Returns the cookie session.</summary>
    private static async Task<ApiClient> SocialOnlySessionAsync(TestApp app)
    {
        var browser = app.CreateClient();
        browser.SendCsrfHeader = true;
        var start = await browser.GetAsync("/auth/login/Fake?useCookies=true&returnUrl=/done");
        await browser.GetAsync(start.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/auth/me")).StatusCode);
        return browser;
    }

    // ------------------------------------------------------------------ S-1

    /// <summary>
    /// security.md: "Adding a passkey needs the password" / "a stolen session alone must not add a permanent way in" /
    /// "a stolen session alone must not cut the owner's ways in". For an account without a password none of this holds:
    /// a stolen cookie (XSS, malware, shared computer) adds the attacker's passkey without any proof and then removes the
    /// owner's external login – the owner is locked out for good, the attacker keeps a permanent way in.
    /// </summary>
    [Fact]
    public async Task S1_a_stolen_session_of_a_passwordless_account_cannot_swap_its_sign_in_methods()
    {
        await using var app = await TestApp.StartAsync(WithProviderAndPasskeys());
        var stolen = await SocialOnlySessionAsync(app);   // the attacker holds the owner's session cookie
        app.Time.Advance(TimeSpan.FromMinutes(10));        // … not the moment the owner signed in

        // 1. a passkey of the attacker – no password, no re-authentication asked
        using var attackersKey = new SoftwarePasskey();
        var options = await stolen.PostAsync("/auth/passkeys/register/options", new { });
        if (options.StatusCode == HttpStatusCode.OK)
        {
            var start = await options.Content.ReadFromJsonAsync<JsonElement>();
            var credential = attackersKey.Create(start.GetProperty("options"), Origin);
            await stolen.PostAsync("/auth/passkeys/register", new { state = start.Str("state"), credential, name = "attacker" });

            // 2. the owner's way in goes – the attacker's passkey counts as "another method"
            await stolen.PostAsync("/auth/sign-in-methods/external/remove", new { provider = "Fake", providerKey = "google-1" });
        }

        // the owner can still sign in with the provider
        var owner = app.Users.Get(SocialEmail);
        var links = await app.App.Services.GetRequiredService<ISlimExternalLoginStore>().GetExternalLoginsAsync(owner.Id, default);
        Assert.Contains(new SlimExternalLogin("Fake", "google-1"), links);
        Assert.Empty(await app.App.Services.GetRequiredService<ISlimPasskeyStore>().GetPasskeysAsync(owner.Id, default));
    }

    /// <summary>The owner, right after signing in, still manages the sign-in methods without a password.</summary>
    [Fact]
    public async Task S1_after_a_fresh_sign_in_a_passwordless_owner_adds_and_removes_methods()
    {
        await using var app = await TestApp.StartAsync(WithProviderAndPasskeys());
        var owner = await SocialOnlySessionAsync(app);
        app.Time.Advance(TimeSpan.FromMinutes(10));
        var stale = await owner.PostAsync("/auth/passkeys/register/options", new { });
        Assert.Equal(HttpStatusCode.Forbidden, stale.StatusCode);
        Assert.Equal("reauthentication_required", (await stale.Content.ReadFromJsonAsync<JsonElement>()).Str("status"));

        owner = await SocialOnlySessionAsync(app);          // signs in again with the provider
        using var key = new SoftwarePasskey();
        var start = await owner.PostJsonAsync("/auth/passkeys/register/options", new { });
        await owner.PostJsonAsync("/auth/passkeys/register", new { state = start.Str("state"), credential = key.Create(start.GetProperty("options"), Origin), name = "phone" });
        await owner.PostJsonAsync("/auth/sign-in-methods/external/remove", new { provider = "Fake", providerKey = "google-1" });

        var user = app.Users.Get(SocialEmail);
        Assert.Single(await app.App.Services.GetRequiredService<ISlimPasskeyStore>().GetPasskeysAsync(user.Id, default));
    }

    // ------------------------------------------------------------------ forced password change (finding after round 4)

    /// <summary>An external sign-in does not get around a start password the administrator set (mustChange).</summary>
    [Fact]
    public async Task A_forced_password_change_is_not_skipped_with_an_external_login()
    {
        await using var app = await TestApp.StartAsync(WithProviderAndPasskeys());
        await SocialOnlySessionAsync(app);   // creates the account with its linked provider
        await using (var scope = app.App.Services.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<ISlimAuthManager>()
                .SetPasswordAsync(app.Users.Get(SocialEmail), "Start-Password-123", mustChange: true);

        var browser = app.CreateClient();
        var start = await browser.GetAsync("/auth/login/Fake?useCookies=true&returnUrl=/done");
        var callback = await browser.GetAsync(start.Headers.Location!.OriginalString);

        Assert.Contains("slim_error=password_change_required", callback.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/auth/me")).StatusCode);
    }

    // ------------------------------------------------------------------ Q: renewals reported as new sign-ins

    private sealed class Recorder : ISlimEventObserver
    {
        public readonly ConcurrentQueue<SlimEvent> Events = new();
        public ValueTask HandleAsync(SlimEvent e, CancellationToken ct)
        {
            Events.Enqueue(e);
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>
    /// Without ISlimSessionStore every refresh (and every password change, 2FA change, sudo elevation) is treated as a
    /// new sign-in: guards see SlimSignInStage.SignIn instead of Renewal and observers get "signed_in" every 15 minutes.
    /// </summary>
    [Fact]
    public async Task Q_without_a_session_store_a_refresh_is_not_reported_as_a_new_sign_in()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions
        {
            Sessions = false,
            Builder = b => b.AddEventObserver<Recorder>(ServiceLifetime.Singleton),
        });
        var tokens = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var refreshToken = tokens.RefreshToken!;
        for (var i = 0; i < 3; i++)
        {
            var renewed = await app.CreateClient().PostJsonAsync("/auth/refresh", new { refreshToken });
            refreshToken = renewed.Str("refreshToken");
        }

        var recorder = app.App.Services.GetServices<ISlimEventObserver>().OfType<Recorder>().Single();
        Assert.Single(recorder.Events, e => e.Type == SlimEventTypes.SignedIn);
    }

    // ------------------------------------------------------------------ S-4: the way back from an impersonation

    private static long AuthTimeOf(string accessToken) =>
        new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(accessToken).GetPayloadValue<long>("auth_time");

    /// <summary>Ending an impersonation returns to the administrator's own sign-in – not a fresh session chain.</summary>
    [Fact]
    public async Task S4_ending_an_impersonation_keeps_the_administrators_sign_in_time()
    {
        await using var app = await TestApp.StartAsync();
        var admin = app.CreateClient();
        admin.BearerToken = (await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword)).AccessToken;
        var signedIn = AuthTimeOf(admin.BearerToken!);
        app.Time.Advance(TimeSpan.FromMinutes(10));

        admin.BearerToken = (await admin.PostJsonAsync($"/api/impersonate/{app.Users.Get(TestApp.UserEmail).Id}")).Str("accessToken");
        app.Time.Advance(TimeSpan.FromMinutes(2));
        var back = await admin.PostJsonAsync("/api/impersonate/stop");

        Assert.Equal(signedIn, AuthTimeOf(back.Str("accessToken")!));
    }

    // ------------------------------------------------------------------ Q-3: one "last code" marker for TOTP and e-mail codes

    [Fact]
    public async Task Q3_an_authenticator_can_be_switched_on_right_after_a_sign_in_with_an_e_mail_code()
    {
        await using var app = await TestApp.StartAsync();
        var setup = app.CreateClient();
        setup.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await setup.PostJsonAsync("/auth/2fa/enable-email", new { password = TestApp.UserPassword });
        app.Time.Advance(TimeSpan.FromSeconds(31 - app.Time.GetUtcNow().ToUnixTimeSeconds() % 30));   // early in a TOTP step

        var client = app.CreateClient();
        var challenge = await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);
        var code = (await app.Mail.WaitForAsync("two-factor", TestApp.UserEmail)).Payload;
        client.BearerToken = (await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = challenge.Str("preAuthToken"), code })).Str("accessToken");

        app.Time.Advance(TimeSpan.FromSeconds(5));                                   // same TOTP step as the e-mail code
        var authenticator = await client.PostJsonAsync("/auth/2fa/setup");
        var totp = SlimIdentity.Security.SlimTotp.Compute(SlimIdentity.Security.SlimBase32.Decode(authenticator.Str("sharedKey")!),
            app.Time.GetUtcNow().ToUnixTimeSeconds() / 30);
        await client.PostJsonAsync("/auth/2fa/enable", new { setupToken = authenticator.Str("setupToken"), code = totp, password = TestApp.UserPassword });
    }

    // ------------------------------------------------------------------ U: 2FA management of passwordless accounts

    /// <summary>
    /// A passwordless account is asked for "the password" by every 2FA endpoint; each attempt counts as a failed
    /// password, and five of them lock the account – which then also blocks the external sign-in (account_locked).
    /// </summary>
    [Fact]
    public async Task U_a_passwordless_account_is_not_locked_out_by_the_2fa_settings_page()
    {
        await using var app = await TestApp.StartAsync(WithProviderAndPasskeys());
        var me = await SocialOnlySessionAsync(app);

        for (var i = 0; i < 5; i++)
            await me.PostAsync("/auth/2fa/enable-email", new { password = "" });

        var fresh = app.CreateClient();
        var start = await fresh.GetAsync("/auth/login/Fake?useCookies=true&returnUrl=/done");
        var callback = await fresh.GetAsync(start.Headers.Location!.OriginalString);
        Assert.DoesNotContain("account_locked", callback.Headers.Location!.OriginalString);
    }
}

public sealed class ReviewRound4AddressTests
{
    [Theory]
    [InlineData("victim@test.local <attacker@evil.example>")]
    [InlineData("\"victim@test.local\" <attacker@evil.example>")]
    [InlineData("attacker@evil.example (victim@test.local)")]
    public async Task Q_a_display_name_form_is_not_accepted_as_an_address(string address)
    {
        await using var app = await TestApp.StartAsync();
        var response = await app.CreateClient().PostAsync("/auth/register", new { email = address, password = "Long-Enough-Pass-1" });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// D6 ("3 mails per recipient and kind"): the throttle keys on the raw string, the mail transport (MailKit's
    /// MailboxAddress.Parse in the template, System.Net.Mail) delivers to the address inside the angle brackets. Every
    /// display name is a fresh account and a fresh throttle key – but the same inbox.
    /// </summary>
    [Fact]
    public async Task S_display_names_do_not_bypass_the_per_recipient_mail_limit()
    {
        await using var app = await TestApp.StartAsync();
        for (var i = 0; i < 10; i++)
            await app.CreateClient().PostAsync("/auth/register", new { email = $"n{i} <victim@test.local>", password = "Long-Enough-Pass-1" });
        await Task.Delay(300);   // background queue

        var toVictim = app.Mail.Mails.Count(m => m.Kind == "verification"
            && System.Net.Mail.MailAddress.TryCreate(m.To, out var a) && a.Address == "victim@test.local");
        Assert.True(toVictim <= 3, $"{toVictim} verification mails reached victim@test.local");
    }
}
