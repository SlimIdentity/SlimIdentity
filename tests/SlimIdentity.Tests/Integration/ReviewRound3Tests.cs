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
            return result.TwoFactorChallenge is { } challenge
                ? Results.Json(challenge, statusCode: StatusCodes.Status401Unauthorized)
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

    [Theory]
    [InlineData("locked", "locked_out")]
    [InlineData("unconfirmed", "email_not_confirmed")]
    [InlineData("password_change", "password_change_required")]
    public async Task S2_SignInAsync_refuses_accounts_that_may_not_sign_in(string state, string expected)
    {
        await using var app = await TestApp.StartAsync(WithHostSignIn(o => o.SignIn.RequireConfirmedEmail = true));
        await SaveAsync(app, u =>
        {
            if (state == "locked") u.LockoutEndUtc = app.Time.GetUtcNow().AddMinutes(5);
            if (state == "unconfirmed") u.EmailConfirmed = false;
            if (state == "password_change") u.PasswordChangeRequired = true;
        });

        var refused = await app.CreateClient().PostJsonAsync($"/api/cert-login/{TestApp.UserEmail}", expected: HttpStatusCode.Forbidden);

        Assert.Equal(expected, refused.Str("status"));
    }

    [Fact]
    public async Task S2_SignInAsync_asks_for_the_second_factor_and_the_built_in_flow_completes_it()
    {
        await using var app = await TestApp.StartAsync(WithHostSignIn());
        await EnableEmailTwoFactorAsync(app);
        app.Time.Advance(TimeSpan.FromSeconds(1));

        var challenge = await app.CreateClient().PostJsonAsync($"/api/cert-login/{TestApp.UserEmail}", expected: HttpStatusCode.Unauthorized);
        Assert.Equal("requires_two_factor", challenge.Str("status"));

        var code = (await app.Mail.WaitForAsync("two-factor", TestApp.UserEmail)).Payload;
        var session = await app.CreateClient().PostJsonAsync("/auth/login/2fa", new { preAuthToken = challenge.Str("preAuthToken"), code });
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
            new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);
        var code = (await app.Mail.WaitForAsync("two-factor", TestApp.UserEmail)).Payload;
        await browser.PostJsonAsync("/auth/login/2fa", new { preAuthToken = challenge.Str("preAuthToken"), code, rememberDevice = true });
        await browser.PostAsync("/auth/logout");
        Assert.True(browser.Cookies.ContainsKey("SlimAuth.2fa"));

        // the same browser asks for tokens: the cookie remembers the browser's cookie sessions, not token clients
        browser.SendCsrfHeader = false;
        var bearer = await browser.PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);
        Assert.Equal("requires_two_factor", bearer.Str("status"));
    }

    // ------------------------------------------------------------------ S-4: bounded nonce registry

    [Fact(Timeout = 30_000)]
    public async Task S4_the_nonce_registry_is_bounded_and_stays_fast()
    {
        await Task.Yield();
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));
        var registry = new SlimLocalNonceRegistry(time);
        var expiry = time.GetUtcNow().AddMinutes(5);

        for (var i = 0; i < SlimLocalNonceRegistry.MaxEntries; i++)
            Assert.True(registry.TryConsume($"nonce-{i}", expiry));
        Assert.False(registry.TryConsume("nonce-0", expiry));                 // single use
        Assert.False(registry.TryConsume("one-too-many", expiry));            // full: refused (fail closed), no growth

        time.Advance(TimeSpan.FromMinutes(6));                                  // all expired
        Assert.True(registry.TryConsume("after-expiry", time.GetUtcNow().AddMinutes(5)));
    }
}
