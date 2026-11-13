using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using SlimIdentity.Security;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// Account administration without mail: start passwords that must be changed, reset links handed over by an
/// administrator, resetting the second factor, unlocking.
/// </summary>
public sealed class AdministratorTests
{
    private sealed record SetPasswordRequest(string Email, string Password, bool MustChange);

    /// <summary>The host's admin endpoints (authorization is the host's job – here: role Admin).</summary>
    private static TestAppOptions WithAdminEndpoints(bool withoutEmail = true) => new()
    {
        EmailSender = !withoutEmail,
        Builder = b => { if (withoutEmail) b.WithoutEmail(); },
        Map = app =>
        {
            var admin = app.MapGroup("/api/admin").RequireAuthorization(p => p.RequireRole("Admin"));
            admin.MapPost("/set-password", async (SetPasswordRequest r, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
                await auth.SetPasswordAsync((await store.FindByEmailAsync(r.Email, ct))!, r.Password, r.MustChange, ct) ?? Results.Ok());
            admin.MapPost("/reset-link/{email}", async (string email, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
                Results.Ok(await auth.CreatePasswordResetAsync((await store.FindByEmailAsync(email, ct))!, ct: ct)));
            admin.MapPost("/reset-2fa/{email}", async (string email, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
            {
                await auth.ResetTwoFactorAsync((await store.FindByEmailAsync(email, ct))!, ct);
                return Results.Ok();
            });
            admin.MapPost("/unlock/{email}", async (string email, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
            {
                await auth.UnlockAsync((await store.FindByEmailAsync(email, ct))!, ct);
                return Results.Ok();
            });
        },
    };

    private static async Task<ApiClient> AdminAsync(TestApp app)
    {
        var admin = app.CreateClient();
        admin.BearerToken = (await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword)).AccessToken;
        return admin;
    }

    private static string Code(TestApp app, string sharedKey) =>
        SlimTotp.Compute(SlimBase32.Decode(sharedKey), app.Time.GetUtcNow().ToUnixTimeSeconds() / 30);

    // ------------------------------------------------------------------ start password + forced change

    [Fact]
    public async Task A_start_password_must_be_changed_before_any_session_exists()
    {
        await using var app = await TestApp.StartAsync(WithAdminEndpoints());
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;

        await (await AdminAsync(app)).PostJsonAsync("/api/admin/set-password", new { email = TestApp.UserEmail, password = "Start-Pass-2026", mustChange = true });
        Assert.Equal(HttpStatusCode.Unauthorized, (await me.GetAsync("/auth/me")).StatusCode);   // old sessions ended

        var challenge = await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = "Start-Pass-2026" });
        Assert.Equal("action_required", challenge.Str("status"));
        Assert.Equal("change_password", challenge.GetProperty("actions")[0].GetString());
        Assert.False(challenge.TryGetProperty("accessToken", out var accessToken) && accessToken.ValueKind == System.Text.Json.JsonValueKind.String);

        var token = challenge.Str("flowToken");
        await app.CreateClient().PostJsonAsync("/auth/login/password-change", new { flowToken = token, newPassword = "Start-Pass-2026" }, HttpStatusCode.BadRequest);   // must differ
        var session = await app.CreateClient().PostJsonAsync("/auth/login/password-change", new { flowToken = token, newPassword = "My-Own-Pass-2026" });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));

        await app.CreateClient().PostJsonAsync("/auth/login/password-change", new { flowToken = token, newPassword = "Another-Pass-2026" }, HttpStatusCode.Unauthorized);   // single use
        await app.LoginBearerAsync(TestApp.UserEmail, "My-Own-Pass-2026");   // a normal sign-in from now on
        Assert.False(app.Users.Get(TestApp.UserEmail).PasswordChangeRequired);
    }

    [Fact]
    public async Task The_second_factor_comes_before_the_forced_change()
    {
        await using var app = await TestApp.StartAsync(WithAdminEndpoints());
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        var setup = await me.PostJsonAsync("/auth/2fa/setup");
        await me.PostJsonAsync("/auth/2fa/enable", new { setupToken = setup.Str("setupToken"), code = Code(app, setup.Str("sharedKey")), password = TestApp.UserPassword });
        app.Time.Advance(TimeSpan.FromSeconds(30));

        await (await AdminAsync(app)).PostJsonAsync("/api/admin/set-password", new { email = TestApp.UserEmail, password = "Start-Pass-2026", mustChange = true });
        var start = await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = "Start-Pass-2026" });
        Assert.Equal(["second_factor", "change_password"], start.GetProperty("actions").EnumerateArray().Select(a => a.GetString()));

        // the steps in their order: no own password before the account is proven completely
        await app.CreateClient().PostJsonAsync("/auth/login/password-change",
            new { flowToken = start.Str("flowToken"), newPassword = "My-Own-Pass-2026" }, HttpStatusCode.Unauthorized);
        var next = await app.CreateClient().PostJsonAsync("/auth/login/2fa", new { flowToken = start.Str("flowToken"), code = Code(app, setup.Str("sharedKey")) });
        Assert.Equal(["change_password"], next.GetProperty("actions").EnumerateArray().Select(a => a.GetString()));
        var session = await app.CreateClient().PostJsonAsync("/auth/login/password-change", new { flowToken = next.Str("flowToken"), newPassword = "My-Own-Pass-2026" });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));

        var signedIn = app.CreateClient();
        signedIn.BearerToken = session.Str("accessToken");
        Assert.Equal("mfa", (await (await signedIn.GetAsync("/auth/me")).Content.ReadFromJsonAsync<JsonElement>()).Str("authenticationMethod"));
    }

    [Fact]
    public async Task A_password_set_without_forced_change_works_at_once()
    {
        await using var app = await TestApp.StartAsync(WithAdminEndpoints());
        await (await AdminAsync(app)).PostJsonAsync("/api/admin/set-password", new { email = TestApp.UserEmail, password = "Set-By-Admin-2026", mustChange = false });
        await app.LoginBearerAsync(TestApp.UserEmail, "Set-By-Admin-2026");
    }

    [Fact]
    public async Task A_start_password_follows_the_password_rules()
    {
        await using var app = await TestApp.StartAsync(WithAdminEndpoints());
        await (await AdminAsync(app)).PostJsonAsync("/api/admin/set-password", new { email = TestApp.UserEmail, password = "short", mustChange = true }, HttpStatusCode.BadRequest);
        await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);   // unchanged
    }

    [Fact]
    public async Task The_change_token_is_no_session_and_dies_with_the_stamp()
    {
        await using var app = await TestApp.StartAsync(WithAdminEndpoints());
        var admin = await AdminAsync(app);
        await admin.PostJsonAsync("/api/admin/set-password", new { email = TestApp.UserEmail, password = "Start-Pass-2026", mustChange = true });
        var token = (await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = "Start-Pass-2026" })).Str("flowToken");

        var bearer = app.CreateClient();
        bearer.BearerToken = token;
        Assert.Equal(HttpStatusCode.Unauthorized, (await bearer.GetAsync("/auth/me")).StatusCode);

        await admin.PostJsonAsync("/api/admin/set-password", new { email = TestApp.UserEmail, password = "Second-Start-2026", mustChange = true });
        await app.CreateClient().PostJsonAsync("/auth/login/password-change", new { flowToken = token, newPassword = "My-Own-Pass-2026" }, HttpStatusCode.Unauthorized);
    }

    // ------------------------------------------------------------------ reset link handed over by the administrator

    [Fact]
    public async Task A_reset_link_from_the_administrator_sets_a_password_the_administrator_never_sees()
    {
        await using var app = await TestApp.StartAsync(WithAdminEndpoints());
        var link = await (await AdminAsync(app)).PostJsonAsync($"/api/admin/reset-link/{TestApp.UserEmail}");
        Assert.True(link.GetProperty("expiresAt").GetDateTimeOffset() > app.Time.GetUtcNow());

        await app.CreateClient().ResetPasswordJsonAsync(link.Str("token"), "Chosen-By-Me-2026");
        await app.LoginBearerAsync(TestApp.UserEmail, "Chosen-By-Me-2026");
        await app.CreateClient().ResetPasswordJsonAsync(link.Str("token"), "Again-2026-Pass", HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task An_administrators_reset_link_is_no_proof_of_the_mailbox()
    {
        // an unconfirmed account (e.g. self-registered): a mailbox proof would confirm it and drop its second factor –
        // a link the administrator hands over proves nothing about the mailbox
        await using var app = await TestApp.StartAsync(WithAdminEndpoints(withoutEmail: false));
        var user = app.Users.Get(TestApp.UserEmail);
        user.EmailConfirmed = false;
        user.TwoFactorEnabled = true;
        await app.Users.UpdateSecurityStateAsync(user, default);

        var link = await (await AdminAsync(app)).PostJsonAsync($"/api/admin/reset-link/{TestApp.UserEmail}");
        await app.CreateClient().ResetPasswordJsonAsync(link.Str("token"), "Chosen-By-Me-2026");

        var after = app.Users.Get(TestApp.UserEmail);
        Assert.False(after.EmailConfirmed);
        Assert.True(after.TwoFactorEnabled);
    }

    // ------------------------------------------------------------------ second factor and lockout

    [Fact]
    public async Task Resetting_the_second_factor_lets_the_user_sign_in_with_the_password_again()
    {
        await using var app = await TestApp.StartAsync(WithAdminEndpoints());
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        var setup = await me.PostJsonAsync("/auth/2fa/setup");
        await me.PostJsonAsync("/auth/2fa/enable", new { setupToken = setup.Str("setupToken"), code = Code(app, setup.Str("sharedKey")), password = TestApp.UserPassword });

        await (await AdminAsync(app)).PostJsonAsync($"/api/admin/reset-2fa/{TestApp.UserEmail}");

        Assert.False(app.Users.Get(TestApp.UserEmail).TwoFactorEnabled);
        Assert.Equal(HttpStatusCode.Unauthorized, (await me.GetAsync("/auth/me")).StatusCode);   // sessions ended
        await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
    }

    [Fact]
    public async Task Unlocking_ends_a_lockout()
    {
        await using var app = await TestApp.StartAsync(WithAdminEndpoints());
        for (var i = 0; i < 5; i++)
            await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = "wrong-password" }, HttpStatusCode.Unauthorized);
        await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);

        await (await AdminAsync(app)).PostJsonAsync($"/api/admin/unlock/{TestApp.UserEmail}");

        await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
    }

    // ------------------------------------------------------------------ attempt counters per factor

    private static void LockBothFactors(TestApp app)
    {
        var id = app.Users.Get(TestApp.UserEmail).Id;
        app.Users.SetAttempts(id, SlimAttemptFactor.Password, 5, app.Time.GetUtcNow().AddMinutes(5));
        app.Users.SetAttempts(id, SlimAttemptFactor.SecondFactor, 5, app.Time.GetUtcNow().AddMinutes(5));
    }

    [Fact]
    public async Task Unlocking_resets_both_factors()
    {
        await using var app = await TestApp.StartAsync(WithAdminEndpoints());
        var admin = await AdminAsync(app);
        LockBothFactors(app);

        await admin.PostJsonAsync($"/api/admin/unlock/{TestApp.UserEmail}");

        var user = app.Users.Get(TestApp.UserEmail);
        Assert.Equal((0, null, 0, null), (user.FailedLoginAttempts, user.LockoutEndUtc, user.FailedSecondFactorAttempts, user.SecondFactorLockoutEndUtc));
    }

    [Fact]
    public async Task Setting_a_password_resets_only_the_password_counter()
    {
        await using var app = await TestApp.StartAsync(WithAdminEndpoints());
        var admin = await AdminAsync(app);
        LockBothFactors(app);

        await admin.PostJsonAsync("/api/admin/set-password", new { email = TestApp.UserEmail, password = "Set-By-Admin-2026", mustChange = false });

        var user = app.Users.Get(TestApp.UserEmail);
        Assert.Equal((0, null), (user.FailedLoginAttempts, user.LockoutEndUtc));
        Assert.Equal(5, user.FailedSecondFactorAttempts);
        Assert.True(user.IsSecondFactorLockedOut(app.Time.GetUtcNow()));
    }

    [Fact]
    public async Task Resetting_the_second_factor_resets_only_its_counter()
    {
        await using var app = await TestApp.StartAsync(WithAdminEndpoints());
        var admin = await AdminAsync(app);
        LockBothFactors(app);

        await admin.PostJsonAsync($"/api/admin/reset-2fa/{TestApp.UserEmail}");

        var user = app.Users.Get(TestApp.UserEmail);
        Assert.Equal((0, null), (user.FailedSecondFactorAttempts, user.SecondFactorLockoutEndUtc));
        Assert.Equal(5, user.FailedLoginAttempts);
        Assert.True(user.IsLockedOut(app.Time.GetUtcNow()));
    }

    private static async Task<string> PasswordChangeTokenAsync(TestApp app)
    {
        var user = app.Users.Get(TestApp.UserEmail);
        user.PasswordChangeRequired = true;
        await app.Users.UpdateSecurityStateAsync(user, default);
        return (await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword })).Str("flowToken");
    }

    [Fact]
    public async Task A_locked_account_cannot_complete_the_forced_password_change_until_the_lockout_ends()
    {
        await using var app = await TestApp.StartAsync();
        var token = await PasswordChangeTokenAsync(app);

        for (var i = 0; i < 5; i++)   // locked before the token is redeemed
            await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = "wrong" }, HttpStatusCode.Unauthorized);
        Assert.True(app.Users.Get(TestApp.UserEmail).IsLockedOut(app.Time.GetUtcNow()));

        var answer = await app.CreateClient().PostAsync("/auth/login/password-change", new { flowToken = token, newPassword = "New-Valid-Pass-123!" });

        Assert.Equal((HttpStatusCode)423, answer.StatusCode);
        Assert.True(app.Users.Get(TestApp.UserEmail).IsLockedOut(app.Time.GetUtcNow()));   // the lockout was not cleared
        Assert.True(app.Users.Get(TestApp.UserEmail).PasswordChangeRequired);

        app.Time.Advance(TimeSpan.FromMinutes(1) + TimeSpan.FromSeconds(1));   // first lockout: 1 minute, token: 5 minutes

        var session = await app.CreateClient().PostJsonAsync("/auth/login/password-change", new { flowToken = token, newPassword = "New-Valid-Pass-123!" });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
    }
}
