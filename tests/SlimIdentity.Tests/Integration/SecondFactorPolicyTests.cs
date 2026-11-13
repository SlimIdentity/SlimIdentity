using System.Collections.Concurrent;
using System.Net;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Security;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// <see cref="ISlimSecondFactorPolicy"/>: a sign-in that has to prove more than a mail code sets up an authenticator app
/// in the flow, confirms its recovery codes, and only then gets its session.
/// </summary>
public sealed class SecondFactorPolicyTests
{
    private sealed class Policy : ISlimSecondFactorPolicy
    {
        public volatile bool Required = true;
        public readonly ConcurrentQueue<string> Methods = new();

        public ValueTask<bool> IsRequiredAsync(SlimSecondFactorPolicyContext context, CancellationToken ct)
        {
            Methods.Enqueue(context.AuthenticationMethod);
            return ValueTask.FromResult(Required);
        }
    }

    private static TestAppOptions WithPolicy(bool twoFactor = true) =>
        new() { TwoFactor = twoFactor, Builder = b => b.AddSecondFactorPolicy<Policy>(ServiceLifetime.Singleton) };

    private static Policy PolicyOf(TestApp app) =>
        app.App.Services.GetServices<ISlimSecondFactorPolicy>().OfType<Policy>().Single();

    private static string Code(TestApp app, string sharedKey) =>
        SlimTotp.Compute(SlimBase32.Decode(sharedKey), app.Time.GetUtcNow().ToUnixTimeSeconds() / 30);

    private static Task<System.Text.Json.JsonElement> LoginAsync(ApiClient client) =>
        client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword });

    [Fact]
    public async Task A_required_second_factor_is_set_up_in_the_sign_in()
    {
        await using var app = await TestApp.StartAsync(WithPolicy());
        var client = app.CreateClient();

        var step = await LoginAsync(client);
        Assert.Equal(["setup_second_factor"], step.GetProperty("actions").EnumerateArray().Select(a => a.GetString()));
        Assert.Equal("totp", step.GetProperty("details").GetProperty("setupSecondFactor").GetProperty("methods")[0].GetString());
        Assert.Equal("pwd", PolicyOf(app).Methods.Single());

        var setup = await client.PostJsonAsync("/auth/login/2fa/setup", new { flowToken = step.Str("flowToken") });
        var sharedKey = setup.Str("sharedKey");
        var enable = new { flowToken = step.Str("flowToken"), setupToken = setup.Str("setupToken"), code = Code(app, sharedKey) };
        await client.PostJsonAsync("/auth/login/2fa/enable", enable with { code = "000000" }, HttpStatusCode.BadRequest);
        var codes = await client.PostJsonAsync("/auth/login/2fa/enable", enable);
        Assert.Equal("confirm_recovery_codes", codes.GetProperty("actions")[0].GetString());
        Assert.Equal(10, codes.GetProperty("details").GetProperty("recoveryCodes").GetArrayLength());
        Assert.True(app.Users.Get(TestApp.UserEmail).TwoFactorEnabled);

        // the stamp rotated with the new factor: the token of the setup step works once
        app.Time.Advance(TimeSpan.FromSeconds(30));
        await client.PostJsonAsync("/auth/login/2fa/enable", enable with { code = Code(app, sharedKey) }, HttpStatusCode.Unauthorized);
        // the codes are not read back
        Assert.False((await client.PostJsonAsync("/auth/flow", new { flowToken = codes.Str("flowToken") }))
            .TryGetProperty("details", out _));

        var session = await client.PostJsonAsync("/auth/login/2fa/recovery-codes-saved", new { flowToken = codes.Str("flowToken") });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
        await client.PostJsonAsync("/auth/login/2fa/recovery-codes-saved", new { flowToken = codes.Str("flowToken") }, HttpStatusCode.Unauthorized);

        // from now on the authenticator app is the second factor – and fulfils the policy
        app.Time.Advance(TimeSpan.FromSeconds(30));
        var next = await LoginAsync(client);
        Assert.Equal(["second_factor"], next.GetProperty("actions").EnumerateArray().Select(a => a.GetString()));
        var again = await client.PostJsonAsync("/auth/login/2fa", new { flowToken = next.Str("flowToken"), code = Code(app, sharedKey) });
        Assert.False(string.IsNullOrEmpty(again.Str("accessToken")));
    }

    [Fact]
    public async Task Mail_codes_are_passed_first_then_an_authenticator_is_set_up()
    {
        await using var app = await TestApp.StartAsync(WithPolicy());
        var policy = PolicyOf(app);
        policy.Required = false;
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await me.PostJsonAsync("/auth/2fa/enable-email", new { password = TestApp.UserPassword });
        policy.Required = true;

        var client = app.CreateClient();
        var step = await LoginAsync(client);
        Assert.Equal(["second_factor"], step.GetProperty("actions").EnumerateArray().Select(a => a.GetString()));
        var code = (await app.Mail.WaitForAsync("two-factor", TestApp.UserEmail)).Payload;

        var setup = await client.PostJsonAsync("/auth/login/2fa", new { flowToken = step.Str("flowToken"), code });
        Assert.Equal(["setup_second_factor"], setup.GetProperty("actions").EnumerateArray().Select(a => a.GetString()));
        // the mail code does not open the session
        await client.PostJsonAsync("/auth/login/2fa/recovery-codes-saved", new { flowToken = setup.Str("flowToken") }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_recovery_code_fulfils_the_policy()
    {
        await using var app = await TestApp.StartAsync(WithPolicy());
        var client = app.CreateClient();
        var step = await LoginAsync(client);
        var setup = await client.PostJsonAsync("/auth/login/2fa/setup", new { flowToken = step.Str("flowToken") });
        var codes = await client.PostJsonAsync("/auth/login/2fa/enable",
            new { flowToken = step.Str("flowToken"), setupToken = setup.Str("setupToken"), code = Code(app, setup.Str("sharedKey")) });
        var recoveryCode = codes.GetProperty("details").GetProperty("recoveryCodes")[0].GetString();

        var next = await LoginAsync(client);
        var session = await client.PostJsonAsync("/auth/login/2fa", new { flowToken = next.Str("flowToken"), recoveryCode });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
    }

    [Fact]
    public async Task The_policy_needs_a_two_factor_store()
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => TestApp.StartAsync(WithPolicy(twoFactor: false)));
        Assert.Contains("ISlimTwoFactorStore", error.Message);
    }
}
