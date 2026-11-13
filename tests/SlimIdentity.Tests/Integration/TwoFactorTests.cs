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

        var challenge = await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);
        Assert.Equal("requires_two_factor", challenge.Str("status"));
        Assert.Equal("totp", challenge.Str("twoFactorMethod"));

        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = challenge.Str("preAuthToken"), code = "000000" }, HttpStatusCode.Unauthorized);
        var session = await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = challenge.Str("preAuthToken"), code = Code(app, sharedKey) });
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
            (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized)).Str("preAuthToken");

        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = await PreAuth(), code });
        // an attacker who observed the code (phishing proxy, shoulder surfing) cannot reuse it
        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = await PreAuth(), code }, HttpStatusCode.Unauthorized);
        // the enable code itself was consumed as well: a code from the previous step is rejected
        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = await PreAuth(),
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
        var preAuth = (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized)).Str("preAuthToken");
        var code = (await app.Mail.WaitForAsync("two-factor", TestApp.UserEmail)).Payload;

        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = preAuth, code });
        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = preAuth, code }, HttpStatusCode.Unauthorized);
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
            (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized)).Str("preAuthToken");

        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = await PreAuth(), recoveryCode = recoveryCodes[0] });
        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = await PreAuth(), recoveryCode = recoveryCodes[0] }, HttpStatusCode.Unauthorized);
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
        var preAuth = (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized)).Str("preAuthToken");

        for (var i = 0; i < 5; i++)
            await client.PostAsync("/auth/login/2fa", new { preAuthToken = preAuth, code = "000000" });

        var user = app.Users.Get(TestApp.UserEmail);
        Assert.True(user.IsSecondFactorLockedOut(app.Time.GetUtcNow()));
        Assert.False(user.IsLockedOut(app.Time.GetUtcNow()));

        // the password step still works, but no new challenge is issued while the second factor is locked
        await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Locked);
    }
}
