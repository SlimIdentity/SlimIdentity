using System.Net;
using SlimIdentity.Security;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Regression tests for scenarios of docs/attack-scenarios.md that are not covered elsewhere.</summary>
public sealed class AttackScenarioTests
{
    [Fact]
    public async Task D6_one_inbox_cannot_be_flooded_with_mails()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();

        var answers = new List<string>();
        for (var i = 0; i < 6; i++)
            answers.Add(await (await client.PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail })).Content.ReadAsStringAsync());
        await client.PostAsync("/auth/forgot-password", new { email = TestApp.AdminEmail });   // another inbox is not affected

        await app.Mail.WaitForAsync("password-reset", TestApp.AdminEmail);
        await Task.Delay(200);   // background queue
        Assert.Equal(3, app.Mail.Mails.Count(m => m.Kind == "password-reset" && m.To == TestApp.UserEmail));
        Assert.Single(answers.Distinct());   // throttled requests get the same answer – nothing to learn

        app.Time.Advance(TimeSpan.FromMinutes(16));
        await client.PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        await Task.Delay(200);
        Assert.Equal(4, app.Mail.Mails.Count(m => m.Kind == "password-reset" && m.To == TestApp.UserEmail));
    }

    [Fact]
    public async Task E8_a_second_factor_set_up_by_the_registrant_does_not_survive_the_owners_password_reset()
    {
        // Pre-account hijacking, reset variant: the attacker registers the victim's address and enables an authenticator
        // the victim does not have. The victim later proves the mailbox via password reset.
        const string victim = "victim@test.local";
        await using var app = await TestApp.StartAsync();
        await app.CreateClient().PostJsonAsync("/auth/register", new { email = victim, password = "Attacker-Pass-123" });
        var attacker = app.CreateClient();
        attacker.BearerToken = (await app.LoginBearerAsync(victim, "Attacker-Pass-123")).AccessToken;
        var setup = await attacker.PostJsonAsync("/auth/2fa/setup");
        var code = SlimTotp.Compute(SlimBase32.Decode(setup.Str("sharedKey")), app.Time.GetUtcNow().ToUnixTimeSeconds() / 30);
        await attacker.PostJsonAsync("/auth/2fa/enable", new { setupToken = setup.Str("setupToken"), code, password = "Attacker-Pass-123" });

        await app.CreateClient().PostAsync("/auth/forgot-password", new { email = victim });
        var link = (await app.Mail.WaitForAsync("password-reset", victim)).Payload;
        await app.CreateClient().PostJsonAsync("/auth/reset-password", new { token = link, newPassword = "Owner-Pass-456" });

        var owner = await app.CreateClient().PostJsonAsync("/auth/login", new { email = victim, password = "Owner-Pass-456" });
        Assert.False(string.IsNullOrEmpty(owner.Str("accessToken")));   // no second factor of the attacker in the way
        Assert.Equal(HttpStatusCode.Unauthorized, (await attacker.GetAsync("/api/hello")).StatusCode);
    }

    [Fact]
    public async Task A4_unicode_normalization_forms_of_one_address_are_one_account()
    {
        // "josé@…" can arrive precomposed (NFC, U+00E9) or decomposed (NFD, e + U+0301) – both look identical
        var nfc = "josé@test.local";
        var nfd = "josé@test.local";
        await using var app = await TestApp.StartAsync();

        await app.CreateClient().PostJsonAsync("/auth/register", new { email = nfd, password = "Owner-Pass-123" });
        await app.CreateClient().PostJsonAsync("/auth/register", new { email = nfc, password = "Other-Pass-456" });

        Assert.Single(app.Users.All, u => u.Email.Normalize() == nfc);           // no second account
        await app.LoginBearerAsync(nfc, "Owner-Pass-123");                          // one identity, either form
        await app.LoginBearerAsync(nfd, "Owner-Pass-123");
        await app.Mail.WaitForAsync("account-exists", nfc);
    }

    [Theory]
    [InlineData("user+tag@test.local")]   // sub-addressing: a different mailbox for SlimIdentity, by design
    [InlineData("usеr@test.local")]       // Cyrillic "е" (U+0435): a homoglyph is a different address
    public async Task A4_look_alike_addresses_are_different_accounts(string lookAlike)
    {
        await using var app = await TestApp.StartAsync();
        await app.CreateClient().PostJsonAsync("/auth/register", new { email = lookAlike, password = "Other-Pass-456" });
        await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);   // the original is untouched
        await app.CreateClient().PostJsonAsync("/auth/login", new { email = lookAlike, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task E8_a_confirmed_accounts_second_factor_survives_a_password_reset()
    {
        await using var app = await TestApp.StartAsync();
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        var setup = await me.PostJsonAsync("/auth/2fa/setup");
        var code = SlimTotp.Compute(SlimBase32.Decode(setup.Str("sharedKey")), app.Time.GetUtcNow().ToUnixTimeSeconds() / 30);
        await me.PostJsonAsync("/auth/2fa/enable", new { setupToken = setup.Str("setupToken"), code, password = TestApp.UserPassword });

        await app.CreateClient().PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        var link = (await app.Mail.WaitForAsync("password-reset", TestApp.UserEmail)).Payload;
        await app.CreateClient().PostJsonAsync("/auth/reset-password", new { token = link, newPassword = "New-Pass-789" });

        var login = await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = "New-Pass-789" }, HttpStatusCode.Unauthorized);
        Assert.Equal("requires_two_factor", login.Str("status"));   // a reset alone must never bypass an owner's 2FA
    }
}
