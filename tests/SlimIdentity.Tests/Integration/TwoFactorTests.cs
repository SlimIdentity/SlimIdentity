using System.Net;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Security;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

public sealed class TwoFactorTests
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
        var codes = enabled.GetProperty("recoveryCodes").EnumerateArray().Select(c => c.GetString()!).ToArray();
        return (sharedKey, codes);
    }

    [Fact]
    public async Task Totp_login_requires_the_second_factor()
    {
        await using var app = await TestApp.StartAsync();
        var (sharedKey, _) = await EnableTotpAsync(app);
        app.Time.Advance(TimeSpan.FromSeconds(30));   // next time step – the enable code is already used
        var client = app.CreateClient();

        var challenge = await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword });
        Assert.Equal("second_factor", challenge.GetProperty("actions")[0].GetString());
        Assert.Equal("totp", challenge.GetProperty("details").GetProperty("secondFactor").GetProperty("methods")[0].GetString());

        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = challenge.Str("flowToken"), code = "000000" }, HttpStatusCode.Unauthorized);
        var session = await client.PostJsonAsync("/auth/login/2fa", new { flowToken = challenge.Str("flowToken"), code = Code(app, sharedKey) });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
    }

    [Fact]
    public async Task A_totp_code_is_accepted_only_once()
    {
        await using var app = await TestApp.StartAsync();
        var (sharedKey, _) = await EnableTotpAsync(app);
        app.Time.Advance(TimeSpan.FromSeconds(30));
        var code = Code(app, sharedKey);
        var client = app.CreateClient();

        async Task<string> PreAuth() =>
            (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword })).Str("flowToken");

        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = await PreAuth(), code });
        // an attacker who observed the code (phishing proxy, shoulder surfing) cannot reuse it
        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = await PreAuth(), code }, HttpStatusCode.Unauthorized);
        // the enable code itself was consumed as well: a code from the previous step is rejected
        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = await PreAuth(),
            code = SlimTotp.Compute(SlimBase32.Decode(sharedKey), app.Time.GetUtcNow().ToUnixTimeSeconds() / 30 - 1) }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Email_codes_are_single_use()
    {
        await using var app = await TestApp.StartAsync();
        var tokens = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var me = app.CreateClient();
        me.BearerToken = tokens.AccessToken;
        await me.PostJsonAsync("/auth/2fa/enable-email", new { password = TestApp.UserPassword });

        var client = app.CreateClient();
        var preAuth = (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword })).Str("flowToken");
        var code = (await app.Mail.WaitForAsync("two-factor", TestApp.UserEmail)).Payload;

        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = preAuth, code });
        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = preAuth, code }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Totp_secret_and_recovery_codes_are_never_stored_in_clear_text()
    {
        await using var app = await TestApp.StartAsync();
        var (sharedKey, recoveryCodes) = await EnableTotpAsync(app);
        var store = (TestTwoFactorStore)app.App.Services.GetRequiredService<ISlimTwoFactorStore>();
        var userId = app.Users.Get(TestApp.UserEmail).Id;

        var raw = store.RawSecret(userId)!;
        Assert.DoesNotContain(sharedKey.Replace(" ", "").ToUpperInvariant(), raw.ToUpperInvariant());
        Assert.True(raw.Length > 40);   // a Data Protection payload, not a 32-character Base32 secret

        var hashes = store.RecoveryHashes(userId);
        Assert.Equal(10, hashes.Count);
        Assert.All(recoveryCodes, c => Assert.DoesNotContain(c.Replace("-", ""), string.Concat(hashes)));
    }

    [Fact]
    public async Task Recovery_code_works_exactly_once()
    {
        await using var app = await TestApp.StartAsync();
        var (_, recoveryCodes) = await EnableTotpAsync(app);
        var client = app.CreateClient();

        async Task<string> PreAuth() =>
            (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword })).Str("flowToken");

        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = await PreAuth(), recoveryCode = recoveryCodes[0] });
        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = await PreAuth(), recoveryCode = recoveryCodes[0] }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Enabling_2fa_signs_out_other_devices()
    {
        await using var app = await TestApp.StartAsync();
        var other = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);

        await EnableTotpAsync(app);

        var client = app.CreateClient();
        client.BearerToken = other.AccessToken;
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/hello")).StatusCode);
    }

    [Fact]
    public async Task Failed_second_factors_lock_only_the_second_factor()
    {
        await using var app = await TestApp.StartAsync();
        await EnableTotpAsync(app);
        var client = app.CreateClient();
        var preAuth = (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword })).Str("flowToken");

        for (var i = 0; i < 5; i++)
            await client.PostAsync("/auth/login/2fa", new { flowToken = preAuth, code = "000000" });

        var user = app.Users.Get(TestApp.UserEmail);
        Assert.True(user.IsSecondFactorLockedOut(app.Time.GetUtcNow()));
        Assert.False(user.IsLockedOut(app.Time.GetUtcNow()));

        // the password step still works, but no new challenge is issued while the second factor is locked
        await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Locked);
    }

    [Theory]
    [InlineData("/auth/2fa/disable")]
    [InlineData("/auth/2fa/recovery-codes")]
    [InlineData("/auth/2fa/enable-email")]
    public async Task Two_factor_changes_need_the_password(string path)
    {
        await using var app = await TestApp.StartAsync();
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await me.PostJsonAsync(path, new { }, HttpStatusCode.BadRequest);
        await me.PostJsonAsync(path, new { password = "wrong-password" }, HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Replacing_the_authenticator_needs_the_password()
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
    public async Task A_setup_token_dies_with_the_security_stamp()
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

    [Fact]
    public async Task An_authenticator_can_be_switched_on_right_after_a_sign_in_with_an_email_code()
    {
        await using var app = await TestApp.StartAsync();
        var setup = app.CreateClient();
        setup.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await setup.PostJsonAsync("/auth/2fa/enable-email", new { password = TestApp.UserPassword });
        app.Time.Advance(TimeSpan.FromSeconds(31 - app.Time.GetUtcNow().ToUnixTimeSeconds() % 30));   // early in a TOTP step

        var client = app.CreateClient();
        var challenge = await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword });
        var code = (await app.Mail.WaitForAsync("two-factor", TestApp.UserEmail)).Payload;
        client.BearerToken = (await client.PostJsonAsync("/auth/login/2fa", new { flowToken = challenge.Str("flowToken"), code })).Str("accessToken");

        app.Time.Advance(TimeSpan.FromSeconds(5));   // same TOTP step as the e-mail code
        var authenticator = await client.PostJsonAsync("/auth/2fa/setup");
        await client.PostJsonAsync("/auth/2fa/enable",
            new { setupToken = authenticator.Str("setupToken"), code = Code(app, authenticator.Str("sharedKey")), password = TestApp.UserPassword });
    }

    [Fact]
    public async Task A_correct_password_resets_the_failed_attempts_even_when_the_endpoint_writes_the_security_state()
    {
        // /2fa/disable writes the whole security state after the confirmation – it must not write the old counter back
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();
        client.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await client.PostJsonAsync("/auth/2fa/enable-email", new { password = TestApp.UserPassword });

        var challenge = await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword });
        var code = (await app.Mail.WaitForAsync("two-factor", TestApp.UserEmail)).Payload;
        var me = app.CreateClient();
        me.BearerToken = (await app.CreateClient().PostJsonAsync("/auth/login/2fa", new { flowToken = challenge.Str("flowToken"), code })).Str("accessToken");

        for (var i = 0; i < 4; i++)
            await me.PostJsonAsync("/auth/2fa/disable", new { password = "wrong" }, HttpStatusCode.BadRequest);
        var disabled = await me.PostJsonAsync("/auth/2fa/disable", new { password = TestApp.UserPassword });

        Assert.False(app.Users.Get(TestApp.UserEmail).TwoFactorEnabled);
        Assert.Equal(0, app.Users.Get(TestApp.UserEmail).FailedLoginAttempts);
        Assert.False(string.IsNullOrEmpty(disabled.Str("accessToken")));
    }

    // ------------------------------------------------------------------ second factor and the mailbox

    [Fact]
    public async Task The_second_factor_needs_a_confirmed_address()
    {
        await using var app = await TestApp.StartAsync();
        const string email = "legit-unconfirmed@test.local";
        const string pass = "Legit-Pass-123!";
        await app.PreRegisterUnconfirmedAsync(email, pass);
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginConfirmingAsync(email, pass)).AccessToken;
        await app.SetEmailConfirmedAsync(email, false);

        // unconfirmed: no second factor – nobody has proven the mailbox yet, a later proof would have to remove it
        Assert.Equal("email_not_confirmed", (await me.PostJsonAsync("/auth/2fa/setup", null, HttpStatusCode.Forbidden)).Str("code"));
        await me.PostJsonAsync("/auth/2fa/enable-email", new { password = pass }, HttpStatusCode.Forbidden);

        await app.SetEmailConfirmedAsync(email, true);
        var setup = await me.PostJsonAsync("/auth/2fa/setup");
        await me.PostJsonAsync("/auth/2fa/enable", new { setupToken = setup.Str("setupToken"), code = Code(app, setup.Str("sharedKey")), password = pass });
    }

    [Fact]
    public async Task A_confirmed_accounts_second_factor_survives_a_password_reset()
    {
        await using var app = await TestApp.StartAsync();
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        var setup = await me.PostJsonAsync("/auth/2fa/setup");
        await me.PostJsonAsync("/auth/2fa/enable", new { setupToken = setup.Str("setupToken"), code = Code(app, setup.Str("sharedKey")), password = TestApp.UserPassword });

        await app.CreateClient().PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        var link = (await app.Mail.WaitForAsync("password-reset", TestApp.UserEmail)).Payload;
        // a reset alone must never bypass an owner's 2FA – and the mailbox the link proved is no second factor
        var client = app.CreateClient();
        var started = await client.ResetPasswordJsonAsync(link, "New-Pass-789");
        Assert.Equal("second_factor", started.GetProperty("actions")[0].GetString());
        Assert.DoesNotContain("email", started.GetProperty("details").GetProperty("secondFactor").GetProperty("methods").EnumerateArray().Select(m => m.GetString()));
        await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword });   // nothing changed yet

        app.Time.Advance(TimeSpan.FromSeconds(30));
        var proven = await client.PostJsonAsync("/auth/login/2fa", new { flowToken = started.Str("flowToken"), code = Code(app, setup.Str("sharedKey")) });
        Assert.Equal("set_credential", proven.GetProperty("actions")[0].GetString());
        var session = await client.PostJsonAsync("/auth/register/password", new { flowToken = proven.Str("flowToken"), password = "New-Pass-789" });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));

        var login = await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = "New-Pass-789" });
        Assert.Equal("second_factor", login.GetProperty("actions")[0].GetString());
    }

    [Fact]
    public async Task A_second_factor_set_up_by_the_registrant_does_not_survive_the_owners_password_reset()
    {
        // pre-account hijacking, reset variant: the attacker registers the victim's address and enables an authenticator
        // the victim does not have; the victim later proves the mailbox via password reset
        const string victim = "victim@test.local";
        await using var app = await TestApp.StartAsync();
        await app.PreRegisterUnconfirmedAsync(victim, "Attacker-Pass-123");

        // without the mailbox the registrant gets no session, so no second factor can be set up through the API
        var pending = await app.CreateClient().PostJsonAsync("/auth/login", new { email = victim, password = "Attacker-Pass-123" });
        Assert.Equal("verify_email", pending.GetProperty("actions")[0].GetString());
        Assert.False(pending.TryGetProperty("accessToken", out _));

        // a second factor that got there anyway (imported data, a host that set it) is removed by the owner's mailbox proof
        var registered = app.Users.Get(victim);
        registered.TwoFactorEnabled = true;
        await app.Users.UpdateSecurityStateAsync(registered, default);

        await app.CreateClient().PostAsync("/auth/forgot-password", new { email = victim });
        var link = (await app.Mail.WaitForAsync("password-reset", victim)).Payload;
        await app.CreateClient().ResetPasswordJsonAsync(link, "Owner-Pass-456");

        await app.LoginBearerAsync(victim, "Owner-Pass-456");   // no second factor of the attacker in the way
        await app.CreateClient().PostJsonAsync("/auth/login", new { email = victim, password = "Attacker-Pass-123" }, HttpStatusCode.Unauthorized);
    }
}
