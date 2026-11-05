using System.Net;
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
        var enabled = await client.PostJsonAsync("/auth/2fa/enable", new { setupToken = setup.Str("setupToken"), code = Code(app, sharedKey) });
        var codes = enabled.GetProperty("recoveryCodes").EnumerateArray().Select(c => c.GetString()!).ToArray();
        return (sharedKey, codes);
    }

    [Fact]
    public async Task Totp_login_requires_the_second_factor()
    {
        await using var app = await TestApp.StartAsync();
        var (sharedKey, _) = await EnableTotpAsync(app);
        var client = app.CreateClient();

        var challenge = await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);
        Assert.Equal("requires_two_factor", challenge.Str("status"));
        Assert.Equal("totp", challenge.Str("twoFactorMethod"));

        await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = challenge.Str("preAuthToken"), code = "000000" }, HttpStatusCode.Unauthorized);
        var session = await client.PostJsonAsync("/auth/login/2fa", new { preAuthToken = challenge.Str("preAuthToken"), code = Code(app, sharedKey) });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
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
    public async Task Failed_second_factors_count_towards_the_lockout()
    {
        await using var app = await TestApp.StartAsync();
        await EnableTotpAsync(app);
        var client = app.CreateClient();
        var preAuth = (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized)).Str("preAuthToken");

        for (var i = 0; i < 5; i++)
            await client.PostAsync("/auth/login/2fa", new { preAuthToken = preAuth, code = "000000" });

        Assert.True(app.Users.Get(TestApp.UserEmail).IsLockedOut(app.Time.GetUtcNow()));
    }
}
