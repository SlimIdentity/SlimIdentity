using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Time.Testing;
using SlimIdentity.Services;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Findings of the third external review (Gemini) that hold – each reproduced before it was fixed.</summary>
public sealed class ReviewRound3Tests
{
    // ------------------------------------------------------------------ S-2: ISlimAuthManager.SignInAsync

    /// <summary>A host endpoint after its own first factor (here: a pretend certificate check).</summary>
    private static TestAppOptions WithHostSignIn(Action<SlimIdentityOptions>? configure = null) => new()
    {
        Configure = configure,
        Map = app => app.MapPost("/api/cert-login/{email}", async (string email, bool? secondFactor, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
        {
            if (await store.FindByEmailAsync(email, ct) is not { } user) return Results.NotFound();
            var result = await auth.SignInAsync(user, useCookies: false, authenticationMethod: "cert", secondFactorVerified: secondFactor == true, ct: ct);
            if (result.Succeeded) return Results.Ok(result.ToResponse());
            return result.ActionRequired is { } steps
                ? Results.Ok(steps)
                : Results.Json(new { status = result.Error }, statusCode: StatusCodes.Status403Forbidden);
        }),
    };

    private static async Task EnableEmailTwoFactorAsync(TestApp app)
    {
        var client = app.CreateClient();
        client.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await client.PostJsonAsync("/auth/2fa/enable-email", new { password = TestApp.UserPassword });
    }

    private static async Task SaveAsync(TestApp app, Action<SlimUser> change)
    {
        var user = app.Users.Get(TestApp.UserEmail);
        change(user);
        await app.Users.UpdateSecurityStateAsync(user, default);
    }

    [Fact]
    public async Task S2_SignInAsync_issues_a_session_with_the_hosts_method()
    {
        await using var app = await TestApp.StartAsync(WithHostSignIn());

        var session = await app.CreateClient().PostJsonAsync($"/api/cert-login/{TestApp.UserEmail}");

        var me = app.CreateClient();
        me.BearerToken = session.Str("accessToken");
        Assert.Equal("cert", (await (await me.GetAsync("/auth/me")).Content.ReadFromJsonAsync<JsonElement>()).Str("authenticationMethod"));
    }

    [Fact]
    public async Task S2_SignInAsync_refuses_unconfirmed_accounts()
    {
        await using var app = await TestApp.StartAsync(WithHostSignIn(o => o.SignIn.RequireConfirmedEmail = true));
        await SaveAsync(app, u => u.EmailConfirmed = false);

        var refused = await app.CreateClient().PostJsonAsync($"/api/cert-login/{TestApp.UserEmail}", expected: HttpStatusCode.Forbidden);
        Assert.Equal("email_not_confirmed", refused.Str("status"));
    }

    [Fact]
    public async Task S2_SignInAsync_asks_for_an_own_password_instead_of_a_session()
    {
        await using var app = await TestApp.StartAsync(WithHostSignIn());
        await SaveAsync(app, u => u.PasswordChangeRequired = true);

        var steps = await app.CreateClient().PostJsonAsync($"/api/cert-login/{TestApp.UserEmail}");
        Assert.Equal(["change_password"], steps.GetProperty("actions").EnumerateArray().Select(a => a.GetString()));
        Assert.False(steps.TryGetProperty("accessToken", out _));

        var session = await app.CreateClient().PostJsonAsync("/auth/login/password-change",
            new { flowToken = steps.Str("flowToken"), newPassword = "My-Own-Pass-2026" });
        var me = app.CreateClient();
        me.BearerToken = session.Str("accessToken");
        Assert.Equal("cert", (await (await me.GetAsync("/auth/me")).Content.ReadFromJsonAsync<JsonElement>()).Str("authenticationMethod"));
    }

    [Fact]
    public async Task SignInAsync_ignores_a_lockout_of_the_password()
    {
        await using var app = await TestApp.StartAsync(WithHostSignIn());
        var user = app.Users.Get(TestApp.UserEmail);
        app.Users.SetAttempts(user.Id, SlimAttemptFactor.Password, 5, app.Time.GetUtcNow().AddMinutes(5));
        app.Users.SetAttempts(user.Id, SlimAttemptFactor.SecondFactor, 5, app.Time.GetUtcNow().AddMinutes(5));

        // the lockout guards guessable factors; the host vouches for its own proof (block an account with IsActive)
        var session = await app.CreateClient().PostJsonAsync($"/api/cert-login/{TestApp.UserEmail}");

        Assert.Equal("success", session.Str("status"));
    }

    [Fact]
    public async Task S2_SignInAsync_asks_for_the_second_factor_and_the_built_in_flow_completes_it()
    {
        await using var app = await TestApp.StartAsync(WithHostSignIn());
        await EnableEmailTwoFactorAsync(app);
        app.Time.Advance(TimeSpan.FromSeconds(1));

        var challenge = await app.CreateClient().PostJsonAsync($"/api/cert-login/{TestApp.UserEmail}");
        Assert.Equal("second_factor", challenge.GetProperty("actions")[0].GetString());

        var code = (await app.Mail.WaitForAsync("two-factor", TestApp.UserEmail)).Payload;
        var session = await app.CreateClient().PostJsonAsync("/auth/login/2fa", new { flowToken = challenge.Str("flowToken"), code });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));

        // a host that checked a second factor itself (e.g. a smart card with PIN) says so explicitly
        await app.CreateClient().PostJsonAsync($"/api/cert-login/{TestApp.UserEmail}?secondFactor=true");
    }

    // ------------------------------------------------------------------ S-3: remember token only in its own mode

    [Fact]
    public async Task S3_a_bearer_sign_in_never_uses_the_browsers_remember_cookie()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Configure = o => o.TwoFactor.RememberDeviceLifetime = TimeSpan.FromDays(30) });
        await EnableEmailTwoFactorAsync(app);
        var browser = app.CreateClient();
        browser.SendCsrfHeader = true;
        app.Time.Advance(TimeSpan.FromSeconds(1));
        var challenge = await browser.PostJsonAsync("/auth/login?useCookies=true",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword });
        var code = (await app.Mail.WaitForAsync("two-factor", TestApp.UserEmail)).Payload;
        await browser.PostJsonAsync("/auth/login/2fa", new { flowToken = challenge.Str("flowToken"), code, rememberDevice = true });
        await browser.PostAsync("/auth/logout");
        Assert.True(browser.Cookies.ContainsKey("SlimAuth.2fa"));

        // the same browser asks for tokens: the cookie remembers the browser's cookie sessions, not token clients
        browser.SendCsrfHeader = false;
        var bearer = await browser.PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword });
        Assert.Equal("second_factor", bearer.GetProperty("actions")[0].GetString());
    }

    // ------------------------------------------------------------------ S-4: bounded in-memory shared state

    [Fact(Timeout = 30_000)]
    public async Task S4_the_in_memory_shared_state_is_bounded_and_stays_fast()
    {
        await Task.Yield();
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        var state = new SlimMemorySharedState(time);
        var expiry = time.GetUtcNow().AddMinutes(5);

        for (var i = 0; i < SlimMemorySharedState.MaxEntries; i++)
            Assert.True(state.TryAdd($"nonce-{i}", expiry));
        Assert.False(state.TryAdd("nonce-0", expiry));                        // single use
        Assert.False(state.TryAdd("one-too-many", expiry));                   // full: refused (fail closed), no growth
        Assert.Equal(long.MaxValue, state.Increment("counter", TimeSpan.FromMinutes(5)));   // over every limit

        time.Advance(TimeSpan.FromMinutes(6));                                  // all expired
        Assert.True(state.TryAdd("after-expiry", time.GetUtcNow().AddMinutes(5)));
    }
}
