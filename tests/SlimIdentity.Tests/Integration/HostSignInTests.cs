using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>ISlimAuthManager.SignInAsync: a host endpoint signs a user in after its own first factor.</summary>
public sealed class HostSignInTests
{
    /// <summary>A host endpoint after its own first factor (here: a pretend certificate check).</summary>
    private static TestAppOptions WithHostSignIn() => new()
    {
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

    private static async Task SaveAsync(TestApp app, Action<SlimUser> change)
    {
        var user = app.Users.Get(TestApp.UserEmail);
        change(user);
        await app.Users.UpdateSecurityStateAsync(user, default);
    }

    private static async Task<string?> AuthenticationMethodAsync(TestApp app, string? accessToken)
    {
        var me = app.CreateClient();
        me.BearerToken = accessToken;
        return (await (await me.GetAsync("/auth/me")).Content.ReadFromJsonAsync<JsonElement>()).Str("authenticationMethod");
    }

    [Fact]
    public async Task SignInAsync_issues_a_session_with_the_hosts_method()
    {
        await using var app = await TestApp.StartAsync(WithHostSignIn());

        var session = await app.CreateClient().PostJsonAsync($"/api/cert-login/{TestApp.UserEmail}");

        Assert.Equal("cert", await AuthenticationMethodAsync(app, session.Str("accessToken")));
    }

    [Fact]
    public async Task The_token_lifetime_of_a_host_sign_in_follows_the_registered_clock()
    {
        await using var app = await TestApp.StartAsync(WithHostSignIn());
        app.Time.Advance(TimeSpan.FromDays(30));   // the registered clock is far from the system clock

        var session = await app.CreateClient().PostJsonAsync($"/api/cert-login/{TestApp.UserEmail}");

        Assert.Equal((int)TimeSpan.FromMinutes(15).TotalSeconds, session.GetProperty("expiresIn").GetInt32());
        var client = app.CreateClient();
        client.BearerToken = session.Str("accessToken");
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/me")).StatusCode);
        app.Time.Advance(TimeSpan.FromMinutes(16));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task SignInAsync_asks_unconfirmed_accounts_for_the_mailbox()
    {
        await using var app = await TestApp.StartAsync(WithHostSignIn());
        await SaveAsync(app, u => u.EmailConfirmed = false);

        var steps = await app.CreateClient().PostJsonAsync($"/api/cert-login/{TestApp.UserEmail}");
        Assert.Equal(["verify_email"], steps.GetProperty("actions").EnumerateArray().Select(a => a.GetString()));
        Assert.False(steps.TryGetProperty("accessToken", out _));
    }

    [Fact]
    public async Task SignInAsync_asks_for_an_own_password_instead_of_a_session()
    {
        await using var app = await TestApp.StartAsync(WithHostSignIn());
        await SaveAsync(app, u => u.PasswordChangeRequired = true);

        var steps = await app.CreateClient().PostJsonAsync($"/api/cert-login/{TestApp.UserEmail}");
        Assert.Equal(["change_password"], steps.GetProperty("actions").EnumerateArray().Select(a => a.GetString()));
        Assert.False(steps.TryGetProperty("accessToken", out _));

        var session = await app.CreateClient().PostJsonAsync("/auth/login/password-change",
            new { flowToken = steps.Str("flowToken"), newPassword = "My-Own-Pass-2026" });
        Assert.Equal("cert", await AuthenticationMethodAsync(app, session.Str("accessToken")));
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
    public async Task SignInAsync_asks_for_the_second_factor_and_the_built_in_flow_completes_it()
    {
        await using var app = await TestApp.StartAsync(WithHostSignIn());
        var client = app.CreateClient();
        client.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await client.PostJsonAsync("/auth/2fa/enable-email", new { password = TestApp.UserPassword });
        app.Time.Advance(TimeSpan.FromSeconds(1));

        var challenge = await app.CreateClient().PostJsonAsync($"/api/cert-login/{TestApp.UserEmail}");
        Assert.Equal("second_factor", challenge.GetProperty("actions")[0].GetString());

        var code = (await app.Mail.WaitForAsync("two-factor", TestApp.UserEmail)).Payload;
        var session = await app.CreateClient().PostJsonAsync("/auth/login/2fa", new { flowToken = challenge.Str("flowToken"), code });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));

        // a host that checked a second factor itself (e.g. a smart card with PIN) says so explicitly
        await app.CreateClient().PostJsonAsync($"/api/cert-login/{TestApp.UserEmail}?secondFactor=true");
    }
}
