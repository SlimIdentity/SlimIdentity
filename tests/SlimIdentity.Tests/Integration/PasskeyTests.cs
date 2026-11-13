using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Passkeys;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Passkeys: registration, sign-in without user name, every WebAuthn check, management.</summary>
public sealed class PasskeyTests
{
    private const string Origin = "https://app.test.local";   // a trusted origin of TestApp, inside the RP id

    private static TestAppOptions WithPasskeys(Action<SlimIdentityBuilder>? more = null) => new()
    {
        Builder = b =>
        {
            b.AddPasskeyStore<TestPasskeyStore>(ServiceLifetime.Singleton).AddPasskeys(o => o.RelyingPartyId = "test.local");
            more?.Invoke(b);
        },
    };

    private static async Task<ApiClient> SignedInAsync(TestApp app, string email = TestApp.UserEmail, string password = TestApp.UserPassword)
    {
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(email, password)).AccessToken;
        return me;
    }

    private static async Task<JsonElement> RegisterAsync(TestApp app, ApiClient me, SoftwarePasskey key,
        SoftwarePasskey.Tamper? tamper = null, HttpStatusCode expected = HttpStatusCode.OK, string? password = TestApp.UserPassword)
    {
        var start = await me.PostJsonAsync("/auth/passkeys/register/options", new { password });
        var credential = key.Create(start.GetProperty("options"), Origin, tamper);
        return await me.PostJsonAsync("/auth/passkeys/register", new { state = start.Str("state"), credential, name = "Test key" }, expected);
    }

    private static async Task<(HttpStatusCode Status, JsonElement Body)> LoginAsync(TestApp app, SoftwarePasskey key, SoftwarePasskey.Tamper? tamper = null, string? reuseState = null, object? reuseCredential = null)
    {
        app.Time.Advance(TimeSpan.FromSeconds(1));   // real sign-ins are at least milliseconds apart (each challenge counts once)
        var start = await app.CreateClient().PostJsonAsync("/auth/passkeys/login/options");
        var state = reuseState ?? start.Str("state");
        var credential = reuseCredential ?? key.Get(start.GetProperty("options"), Origin, tamper);
        var response = await app.CreateClient().PostAsync("/auth/passkeys/login?useCookies=false", new { state, credential });
        var text = await response.Content.ReadAsStringAsync();
        return (response.StatusCode, text.Length == 0 ? default : JsonDocument.Parse(text).RootElement.Clone());
    }

    // ------------------------------------------------------------------ the happy path

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_registered_passkey_signs_in_without_a_user_name(bool rsa)
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var key = new SoftwarePasskey(rsa);
        var info = await RegisterAsync(app, await SignedInAsync(app), key);
        Assert.Equal(key.IdBase64Url, info.Str("id"));

        var (status, body) = await LoginAsync(app, key);

        Assert.Equal(HttpStatusCode.OK, status);
        var api = app.CreateClient();
        api.BearerToken = body.Str("accessToken");
        var me = await (await api.GetAsync("/auth/me")).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(TestApp.UserEmail, me.Str("email"));
        Assert.Equal("passkey", me.Str("authenticationMethod"));
    }

    [Fact]
    public async Task The_user_handle_is_random_and_shared_by_the_passkeys_of_one_account()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        var me = await SignedInAsync(app);
        using var first = new SoftwarePasskey();
        using var second = new SoftwarePasskey();
        await RegisterAsync(app, me, first);
        await RegisterAsync(app, me, second);

        var userId = app.Users.Get(TestApp.UserEmail).Id;
        Assert.Equal(32, System.Buffers.Text.Base64Url.DecodeFromChars(first.UserHandle).Length);
        Assert.NotEqual(System.Buffers.Text.Base64Url.EncodeToString(System.Text.Encoding.UTF8.GetBytes(userId)), first.UserHandle);
        Assert.Equal(first.UserHandle, second.UserHandle);
        Assert.Equal(HttpStatusCode.OK, (await LoginAsync(app, first)).Status);
        Assert.Equal(HttpStatusCode.OK, (await LoginAsync(app, second)).Status);
    }

    [Fact]
    public async Task A_passkey_stored_without_a_user_handle_keeps_the_user_id_as_its_handle()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        var me = await SignedInAsync(app);
        using var legacy = new SoftwarePasskey();
        await RegisterAsync(app, me, legacy);
        var userId = app.Users.Get(TestApp.UserEmail).Id;
        var store = app.App.Services.GetRequiredService<ISlimPasskeyStore>();
        var stored = (await store.FindPasskeyAsync(legacy.CredentialId, default))!;
        await store.RemovePasskeyAsync(userId, legacy.CredentialId, default);
        stored.UserHandle = null;
        await store.AddPasskeyAsync(stored, default);
        legacy.UserHandle = System.Buffers.Text.Base64Url.EncodeToString(System.Text.Encoding.UTF8.GetBytes(userId));

        Assert.Equal(HttpStatusCode.OK, (await LoginAsync(app, legacy)).Status);
        using var added = new SoftwarePasskey();
        await RegisterAsync(app, me, added);
        Assert.Equal(legacy.UserHandle, added.UserHandle);   // the authenticator keeps one entry per account
    }

    [Fact]
    public async Task A_passkey_is_multi_factor_no_second_factor_follows()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var key = new SoftwarePasskey();
        await RegisterAsync(app, await SignedInAsync(app), key);
        var user = app.Users.Get(TestApp.UserEmail);
        user.TwoFactorEnabled = true;
        await app.Users.UpdateSecurityStateAsync(user, default);

        var (status, body) = await LoginAsync(app, key);
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.False(string.IsNullOrEmpty(body.Str("accessToken")));
    }

    [Fact]
    public async Task Counting_authenticators_work_repeatedly()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var key = new SoftwarePasskey { CountUp = true };
        await RegisterAsync(app, await SignedInAsync(app), key);
        for (var i = 0; i < 3; i++) Assert.Equal(HttpStatusCode.OK, (await LoginAsync(app, key)).Status);
    }

    // ------------------------------------------------------------------ registration checks

    public static TheoryData<string> RegistrationForgeries => new()
    {
        "foreign origin", "origin outside the rp id", "cross origin", "wrong rp id", "wrong type", "wrong challenge", "no user verification",
    };

    [Theory]
    [MemberData(nameof(RegistrationForgeries))]
    public async Task Forged_registrations_are_rejected(string forgery)
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var key = new SoftwarePasskey();
        var tamper = forgery switch
        {
            "foreign origin" => new SoftwarePasskey.Tamper(Origin: "https://evil.test.local"),     // within the RP id, not trusted
            "origin outside the rp id" => new SoftwarePasskey.Tamper(Origin: "https://evil.example"),
            "cross origin" => new SoftwarePasskey.Tamper(CrossOrigin: true),
            "wrong rp id" => new SoftwarePasskey.Tamper(RpId: "evil.example"),
            "wrong type" => new SoftwarePasskey.Tamper(Type: "webauthn.get"),
            "wrong challenge" => new SoftwarePasskey.Tamper(Challenge: SlimWebAuthn.NewChallenge()),
            _ => new SoftwarePasskey.Tamper(UserVerified: false),
        };

        await RegisterAsync(app, await SignedInAsync(app), key, tamper, HttpStatusCode.BadRequest);

        Assert.Empty(await app.App.Services.GetRequiredService<ISlimPasskeyStore>().GetPasskeysAsync(app.Users.Get(TestApp.UserEmail).Id, default));
    }

    [Fact]
    public async Task Adding_a_passkey_needs_the_password_a_confirmed_address_and_no_impersonation()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        var me = await SignedInAsync(app);
        await me.PostJsonAsync("/auth/passkeys/register/options", new { password = "wrong" }, HttpStatusCode.BadRequest);
        await me.PostJsonAsync("/auth/passkeys/register/options", new { }, HttpStatusCode.BadRequest);

        await app.CreateClient().PostJsonAsync("/auth/register", new { email = "fresh@test.local", password = "Fresh-Pass-123!" });
        var fresh = await SignedInAsync(app, "fresh@test.local", "Fresh-Pass-123!");
        Assert.Equal("email_not_confirmed",
            (await fresh.PostJsonAsync("/auth/passkeys/register/options", new { password = "Fresh-Pass-123!" }, HttpStatusCode.Forbidden)).Str("code"));

        var admin = await SignedInAsync(app, TestApp.AdminEmail, TestApp.AdminPassword);
        var impersonation = app.CreateClient();
        impersonation.BearerToken = (await admin.PostJsonAsync($"/api/impersonate/{app.Users.Get(TestApp.UserEmail).Id}")).Str("accessToken");
        await impersonation.PostJsonAsync("/auth/passkeys/register/options", new { password = TestApp.UserPassword }, HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_registration_state_belongs_to_its_account_and_stamp()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var key = new SoftwarePasskey();
        var me = await SignedInAsync(app);
        var start = await me.PostJsonAsync("/auth/passkeys/register/options", new { password = TestApp.UserPassword });
        var credential = key.Create(start.GetProperty("options"), Origin);

        var admin = await SignedInAsync(app, TestApp.AdminEmail, TestApp.AdminPassword);   // someone else's session
        await admin.PostJsonAsync("/auth/passkeys/register", new { state = start.Str("state"), credential }, HttpStatusCode.BadRequest);

        var changed = await me.PostJsonAsync("/auth/change-password", new { currentPassword = TestApp.UserPassword, newPassword = "Changed-Pass-123!" });
        me.BearerToken = changed.Str("accessToken");   // the session continues with a new token – the old state died with the stamp
        await me.PostJsonAsync("/auth/passkeys/register", new { state = start.Str("state"), credential }, HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task A_credential_is_registered_once_and_excluded_from_new_registrations()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var key = new SoftwarePasskey();
        var me = await SignedInAsync(app);
        await RegisterAsync(app, me, key);

        var again = await me.PostJsonAsync("/auth/passkeys/register/options", new { password = TestApp.UserPassword });
        Assert.Contains(again.GetProperty("options").GetProperty("excludeCredentials").EnumerateArray(), c => c.Str("id") == key.IdBase64Url);
        await RegisterAsync(app, me, key, expected: HttpStatusCode.Conflict);
    }

    // ------------------------------------------------------------------ sign-in checks

    public static TheoryData<string> LoginForgeries => new()
    {
        "foreign origin", "wrong rp id", "wrong type", "wrong challenge", "no user verification", "foreign signature", "foreign user handle",
    };

    [Theory]
    [MemberData(nameof(LoginForgeries))]
    public async Task Forged_sign_ins_are_rejected(string forgery)
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var key = new SoftwarePasskey();
        using var other = new SoftwarePasskey();
        await RegisterAsync(app, await SignedInAsync(app), key);
        var tamper = forgery switch
        {
            "foreign origin" => new SoftwarePasskey.Tamper(Origin: "https://evil.example"),
            "wrong rp id" => new SoftwarePasskey.Tamper(RpId: "evil.example"),
            "wrong type" => new SoftwarePasskey.Tamper(Type: "webauthn.create"),
            "wrong challenge" => new SoftwarePasskey.Tamper(Challenge: SlimWebAuthn.NewChallenge()),
            "no user verification" => new SoftwarePasskey.Tamper(UserVerified: false),
            "foreign signature" => new SoftwarePasskey.Tamper(SignWith: other),
            _ => new SoftwarePasskey.Tamper(UserHandle: System.Buffers.Text.Base64Url.EncodeToString("someone-else"u8)),
        };

        var (status, body) = await LoginAsync(app, key, tamper);
        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Equal("invalid_passkey", body.Str("code"));
    }

    [Fact]
    public async Task An_unknown_passkey_is_rejected()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var stranger = new SoftwarePasskey();
        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(app, stranger)).Status);
    }

    [Fact]
    public async Task A_replayed_sign_in_is_rejected()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var key = new SoftwarePasskey();   // counter 0 – the counter cannot catch the replay
        await RegisterAsync(app, await SignedInAsync(app), key);

        var start = await app.CreateClient().PostJsonAsync("/auth/passkeys/login/options");
        var credential = key.Get(start.GetProperty("options"), Origin);
        Assert.Equal(HttpStatusCode.OK, (await LoginAsync(app, key, reuseState: start.Str("state"), reuseCredential: credential)).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(app, key, reuseState: start.Str("state"), reuseCredential: credential)).Status);
    }

    [Fact]
    public async Task A_counter_that_goes_back_is_rejected()
    {
        // a cloned authenticator: the original has signed 5 times, the clone still says 3
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var key = new SoftwarePasskey { CountUp = true };
        await RegisterAsync(app, await SignedInAsync(app), key);
        for (var i = 0; i < 5; i++) Assert.Equal(HttpStatusCode.OK, (await LoginAsync(app, key)).Status);

        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(app, key, new SoftwarePasskey.Tamper(Counter: 3))).Status);
    }

    [Fact]
    public async Task An_inactive_account_and_a_vetoing_guard_get_no_session()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var key = new SoftwarePasskey { CountUp = true };
        await RegisterAsync(app, await SignedInAsync(app), key);
        var store = (TestPasskeyStore)app.App.Services.GetRequiredService<ISlimPasskeyStore>();
        app.Users.SetActive(app.Users.Get(TestApp.UserEmail).Id, false);

        var (status, body) = await LoginAsync(app, key);
        Assert.Equal(HttpStatusCode.Forbidden, status);
        Assert.Equal("account_disabled", body.Str("code"));
        // the refused sign-in leaves no trace on the passkey (counter, last use)
        var stored = await store.FindPasskeyAsync(key.CredentialId, default);
        Assert.Null(stored!.LastUsedUtc);
        Assert.Equal(0u, stored.SignCount);
    }

    [Fact]
    public async Task A_weak_rsa_key_is_refused_even_when_padded_to_2048_bit()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var weak = new SoftwarePasskey(rsa: true, rsaBits: 1024);
        var refused = await RegisterAsync(app, await SignedInAsync(app), weak, expected: HttpStatusCode.BadRequest);
        Assert.Equal("invalid_passkey", refused.Str("code"));
    }

    // ------------------------------------------------------------------ synced or device-bound (flags BE / BS)

    [Fact]
    public async Task Synced_and_device_bound_passkeys_are_told_apart_and_the_backup_state_follows()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        var me = await SignedInAsync(app);
        using var synced = new SoftwarePasskey { BackupEligible = true, BackedUp = false };
        using var securityKey = new SoftwarePasskey();
        await RegisterAsync(app, me, synced);
        await RegisterAsync(app, me, securityKey);

        synced.BackedUp = true;                                   // the user switched sync on in the meantime
        Assert.Equal(HttpStatusCode.OK, (await LoginAsync(app, synced)).Status);

        var methods = (await (await me.GetAsync("/auth/sign-in-methods")).Content.ReadFromJsonAsync<JsonElement>()).GetProperty("passkeys");
        var byId = methods.EnumerateArray().ToDictionary(p => p.Str("id")!);
        Assert.True(byId[synced.IdBase64Url].GetProperty("backupEligible").GetBoolean());
        Assert.True(byId[synced.IdBase64Url].GetProperty("backedUp").GetBoolean());
        Assert.False(byId[securityKey.IdBase64Url].GetProperty("backupEligible").GetBoolean());
    }

    [Fact]
    public async Task Inconsistent_backup_flags_are_rejected()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        var me = await SignedInAsync(app);
        using var impossible = new SoftwarePasskey { BackupEligible = false, BackedUp = true };   // backed up but not eligible
        Assert.Equal("invalid_passkey", (await RegisterAsync(app, me, impossible, expected: HttpStatusCode.BadRequest)).Str("code"));

        using var deviceBound = new SoftwarePasskey();
        await RegisterAsync(app, me, deviceBound);
        deviceBound.BackupEligible = true;                        // eligibility is fixed: another authenticator answers
        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(app, deviceBound)).Status);
    }

    /// <summary>
    /// A start password set by an administrator must be replaced before any session – a passkey is no way around it
    /// (the start password stays known to whoever set or read it).
    /// </summary>
    [Fact]
    public async Task A_forced_password_change_is_not_skipped_with_a_passkey()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var key = new SoftwarePasskey();
        await RegisterAsync(app, await SignedInAsync(app), key);
        await using (var scope = app.App.Services.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<ISlimAuthManager>()
                .SetPasswordAsync(app.Users.Get(TestApp.UserEmail), "Start-Password-123", mustChange: true);

        var (status, body) = await LoginAsync(app, key);

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(["change_password"], body.GetProperty("actions").EnumerateArray().Select(a => a.GetString()));
        Assert.False(body.TryGetProperty("accessToken", out _));

        // the passkey proves the account: an own password follows directly, afterwards the passkey works alone
        var session = await app.CreateClient().PostJsonAsync("/auth/login/password-change",
            new { flowToken = body.Str("flowToken"), newPassword = "Own-Password-456" });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
        Assert.Equal(HttpStatusCode.OK, (await LoginAsync(app, key)).Status);
    }

    // ------------------------------------------------------------------ pre-account hijacking

    /// <summary>
    /// A passkey can only be added to a confirmed account – but a host may have run without mail, imported accounts
    /// or reset the confirmation. Whoever registered before the owner proves the mailbox keeps no passkey.
    /// </summary>
    [Fact]
    public async Task The_registrants_passkeys_do_not_survive_the_owners_mailbox_proof()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var key = new SoftwarePasskey();
        await RegisterAsync(app, await SignedInAsync(app), key);
        var user = app.Users.Get(TestApp.UserEmail);
        user.EmailConfirmed = false;                       // e.g. imported, or mail switched on later
        await app.Users.UpdateSecurityStateAsync(user, default);

        await app.CreateClient().PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        var token = (await app.Mail.WaitForAsync("password-reset", TestApp.UserEmail)).Payload;
        await app.CreateClient().PostJsonAsync("/auth/reset-password", new { token, newPassword = "Owner-Pass-456" });

        Assert.Empty(await app.App.Services.GetRequiredService<ISlimPasskeyStore>().GetPasskeysAsync(user.Id, default));
        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(app, key)).Status);
    }

    [Fact]
    public async Task The_registrants_passkeys_do_not_survive_a_verified_external_sign_in_of_the_owner()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys(b =>
        {
            b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
            b.Authentication.AddScheme<FakeOAuthOptions, FakeOAuthHandler>("Fake", o => o.Claims =
            [
                new Claim(ClaimTypes.NameIdentifier, "owner-1"),
                new Claim(ClaimTypes.Email, TestApp.UserEmail),
                new Claim("email_verified", "true"),
            ]);
        }));
        using var key = new SoftwarePasskey();
        await RegisterAsync(app, await SignedInAsync(app), key);
        var user = app.Users.Get(TestApp.UserEmail);
        user.EmailConfirmed = false;
        await app.Users.UpdateSecurityStateAsync(user, default);

        var browser = app.CreateClient();
        var challenge = await browser.GetAsync("/auth/login/Fake?useCookies=true&returnUrl=/done");
        await browser.GetAsync(challenge.Headers.Location!.OriginalString);

        Assert.True(app.Users.Get(TestApp.UserEmail).EmailConfirmed);   // the owner took the account over
        Assert.Empty(await app.App.Services.GetRequiredService<ISlimPasskeyStore>().GetPasskeysAsync(user.Id, default));
    }

    // ------------------------------------------------------------------ management

    [Fact]
    public async Task Passkeys_are_listed_renamed_and_removed_with_the_password()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var key = new SoftwarePasskey();
        var me = await SignedInAsync(app);
        await RegisterAsync(app, me, key);

        await me.PostJsonAsync("/auth/sign-in-methods/passkeys/rename", new { id = key.IdBase64Url, name = "Laptop" });
        var methods = await (await me.GetAsync("/auth/sign-in-methods")).Content.ReadFromJsonAsync<JsonElement>();
        var listed = Assert.Single(methods.GetProperty("passkeys").EnumerateArray());
        Assert.Equal("Laptop", listed.Str("name"));

        await me.PostJsonAsync("/auth/sign-in-methods/passkeys/remove", new { id = key.IdBase64Url, password = "wrong" }, HttpStatusCode.BadRequest);
        await me.PostJsonAsync("/auth/sign-in-methods/passkeys/remove", new { id = key.IdBase64Url, password = TestApp.UserPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(app, key)).Status);
    }

    [Fact]
    public async Task Someone_elses_passkey_cannot_be_renamed_or_removed()
    {
        await using var app = await TestApp.StartAsync(WithPasskeys());
        using var key = new SoftwarePasskey();
        await RegisterAsync(app, await SignedInAsync(app), key);
        var admin = await SignedInAsync(app, TestApp.AdminEmail, TestApp.AdminPassword);

        await admin.PostJsonAsync("/auth/sign-in-methods/passkeys/rename", new { id = key.IdBase64Url, name = "Mine now" }, HttpStatusCode.NotFound);
        await admin.PostJsonAsync("/auth/sign-in-methods/passkeys/remove", new { id = key.IdBase64Url, password = TestApp.AdminPassword }, HttpStatusCode.NotFound);
        Assert.Equal(HttpStatusCode.OK, (await LoginAsync(app, key)).Status);
    }

    [Fact]
    public async Task The_last_way_in_stays_across_passkeys_and_external_logins()
    {
        // an account without password: one external login + one passkey – one of them may go, never both
        await using var app = await TestApp.StartAsync(WithPasskeys(b =>
        {
            b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
            b.Authentication.AddScheme<FakeOAuthOptions, FakeOAuthHandler>("Fake", o => o.Claims =
                [new Claim(ClaimTypes.NameIdentifier, "google-1"), new Claim(ClaimTypes.Email, "social@test.local"), new Claim("email_verified", "true")]);
        }));
        var browser = app.CreateClient();
        browser.SendCsrfHeader = true;
        var start = await browser.GetAsync("/auth/login/Fake?useCookies=true&returnUrl=/done");
        await browser.GetAsync(start.Headers.Location!.OriginalString);
        // such an account only comes from before passkeys needed a password: register with a temporary password, drop it
        var userId = app.Users.Get("social@test.local").Id;
        await using (var scope = app.App.Services.CreateAsyncScope())
            await scope.ServiceProvider.GetRequiredService<ISlimAuthManager>().SetPasswordAsync(app.Users.Get("social@test.local"), "Temporary-Pass-123", mustChange: false);
        var me = await SignedInAsync(app, "social@test.local", "Temporary-Pass-123");
        using var key = new SoftwarePasskey();
        await RegisterAsync(app, me, key, password: "Temporary-Pass-123");
        await using (var scope = app.App.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<ISlimUserStore>();
            var user = (await users.FindByIdAsync(userId, default))!;
            user.PasswordHash = string.Empty;
            await users.UpdateSecurityStateAsync(user, user.SecurityStamp, default);
        }

        me.BearerToken = (await me.PostJsonAsync("/auth/sign-in-methods/external/remove", new { provider = "Fake", providerKey = "google-1" })).Str("accessToken");
        var refused = await me.PostJsonAsync("/auth/sign-in-methods/passkeys/remove", new { id = key.IdBase64Url }, HttpStatusCode.Conflict);
        Assert.Equal("last_sign_in_method", refused.Str("code"));
        Assert.Equal(HttpStatusCode.OK, (await LoginAsync(app, key)).Status);
    }

    [Fact]
    public async Task Without_a_relying_party_the_start_fails()
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(() => TestApp.StartAsync(new TestAppOptions
        {
            Builder = b => b.AddPasskeyStore<TestPasskeyStore>(ServiceLifetime.Singleton),
        }));
        Assert.Contains("RelyingPartyId", error.ToString());
    }

    [Fact]
    public async Task AddPasskeys_without_a_store_fails_at_the_start()
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(() => TestApp.StartAsync(new TestAppOptions
        {
            Builder = b => b.AddPasskeys(o => o.RelyingPartyId = "test.local"),
        }));
        Assert.Contains("AddPasskeyStore", error.ToString());
    }
}
