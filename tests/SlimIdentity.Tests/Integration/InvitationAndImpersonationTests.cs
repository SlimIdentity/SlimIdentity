using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

public sealed class InvitationAndImpersonationTests
{
    private static async Task<ApiClient> AdminAsync(TestApp app)
    {
        var tokens = await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword);
        var client = app.CreateClient();
        client.BearerToken = tokens.AccessToken;
        return client;
    }

    [Fact]
    public async Task Invitation_sets_the_password_confirms_the_email_and_is_single_use()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await AdminAsync(app);
        var token = (await admin.PostJsonAsync("/api/invite", new { email = "invited@test.local" })).Str("token");
        var anonymous = app.CreateClient();

        var started = await anonymous.PostJsonAsync("/auth/flow", new { token });
        Assert.Equal("""["set_credential"]""", started.GetProperty("actions").GetRawText());
        Assert.Equal("invited@test.local", started.GetProperty("details").GetProperty("setCredential").Str("email"));
        var flowToken = started.Str("flowToken");

        await anonymous.PostJsonAsync("/auth/register/password", new { flowToken, password = "weak" }, HttpStatusCode.BadRequest);
        var session = await anonymous.PostJsonAsync("/auth/register/password", new { flowToken, password = "Invited123!" });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
        Assert.True(app.Users.Get("invited@test.local").EmailConfirmed);

        await anonymous.PostJsonAsync("/auth/register/password", new { flowToken, password = "Other1234!" }, HttpStatusCode.Unauthorized);
        await anonymous.PostJsonAsync("/auth/flow", new { token }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Invitation_cannot_be_created_for_users_with_a_password()
    {
        await using var app = await TestApp.StartAsync();
        var auth = app.App.Services.CreateScope().ServiceProvider.GetRequiredService<ISlimAuthManager>();

        await Assert.ThrowsAsync<InvalidOperationException>(() => auth.CreateInvitationAsync(app.Users.Get(TestApp.UserEmail)));
    }

    [Fact]
    public async Task Impersonation_carries_the_admin_and_ends_with_a_checked_return()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await AdminAsync(app);
        var userId = app.Users.Get(TestApp.UserEmail).Id;

        var impersonation = app.CreateClient();
        impersonation.BearerToken = (await admin.PostJsonAsync($"/api/impersonate/{userId}")).Str("accessToken");
        var hello = await (await impersonation.GetAsync("/api/hello")).Content.ReadAsStringAsync();
        Assert.Contains(TestApp.UserEmail, hello);
        Assert.Contains(app.Users.Get(TestApp.AdminEmail).Id, hello);

        var back = await impersonation.PostJsonAsync("/api/impersonate/stop");
        var adminAgain = app.CreateClient();
        adminAgain.BearerToken = back.Str("accessToken");
        Assert.Contains(TestApp.AdminEmail, await (await adminAgain.GetAsync("/api/hello")).Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Impersonation_dies_when_the_admin_signs_out_everywhere()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await AdminAsync(app);
        var impersonation = app.CreateClient();
        impersonation.BearerToken = (await admin.PostJsonAsync($"/api/impersonate/{app.Users.Get(TestApp.UserEmail).Id}")).Str("accessToken");
        Assert.Equal(HttpStatusCode.OK, (await impersonation.GetAsync("/api/hello")).StatusCode);

        await admin.PostJsonAsync("/auth/logout-all");

        Assert.Equal(HttpStatusCode.Unauthorized, (await impersonation.GetAsync("/api/hello")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await impersonation.PostAsync("/api/impersonate/stop")).StatusCode);
    }

    [Fact]
    public async Task Admin_cannot_impersonate_themselves()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await AdminAsync(app);
        var result = await admin.PostJsonAsync($"/api/impersonate/{app.Users.Get(TestApp.AdminEmail).Id}", expected: HttpStatusCode.BadRequest);
        Assert.Equal("cannot_impersonate_self", result.Str("status"));
    }

    private static async Task<(ApiClient Impersonation, JsonElement Response)> ImpersonateUserAsync(TestApp app)
    {
        var admin = await AdminAsync(app);
        var response = await admin.PostJsonAsync($"/api/impersonate/{app.Users.Get(TestApp.UserEmail).Id}");
        var impersonation = app.CreateClient();
        impersonation.BearerToken = response.Str("accessToken");
        return (impersonation, response);
    }

    public static TheoryData<string, string> SensitiveActions => new()
    {
        { "/auth/change-password", """{"currentPassword":"User1234!","newPassword":"Hijacked-123"}""" },
        { "/auth/change-email", """{"newEmail":"hijack@test.local","password":"User1234!"}""" },
        { "/auth/logout-all", "{}" },
        { "/auth/2fa/setup", "{}" },
        { "/auth/2fa/enable-email", """{"password":"User1234!"}""" },
        { "/auth/2fa/disable", """{"password":"User1234!"}""" },
        { "/auth/2fa/recovery-codes", """{"password":"User1234!"}""" },
        { "/auth/2fa/forget-all-devices", "{}" },
    };

    [Theory]
    [MemberData(nameof(SensitiveActions))]
    public async Task An_impersonation_session_cannot_perform_sensitive_actions(string path, string body)
    {
        await using var app = await TestApp.StartAsync();
        var (impersonation, _) = await ImpersonateUserAsync(app);
        var response = await impersonation.SendRawAsync(path, body, "application/json");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("not_allowed_while_impersonating", await response.Content.ReadAsStringAsync());
        await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);   // the user's account is untouched
    }

    [Fact]
    public async Task Impersonation_issues_no_refresh_token()
    {
        await using var app = await TestApp.StartAsync();
        var (_, response) = await ImpersonateUserAsync(app);
        Assert.True(!response.TryGetProperty("refreshToken", out var r) || r.ValueKind == JsonValueKind.Null);
    }

    private static long AuthTimeOf(string accessToken) =>
        new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(accessToken).GetPayloadValue<long>("auth_time");

    [Fact]
    public async Task Ending_an_impersonation_keeps_the_administrators_sign_in_time()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await AdminAsync(app);
        var signedIn = AuthTimeOf(admin.BearerToken!);
        app.Time.Advance(TimeSpan.FromMinutes(10));

        admin.BearerToken = (await admin.PostJsonAsync($"/api/impersonate/{app.Users.Get(TestApp.UserEmail).Id}")).Str("accessToken");
        app.Time.Advance(TimeSpan.FromMinutes(2));
        var back = await admin.PostJsonAsync("/api/impersonate/stop");

        Assert.Equal(signedIn, AuthTimeOf(back.Str("accessToken")!));
    }

    [Fact]
    public async Task Revoking_the_administrators_session_ends_the_impersonation_started_from_it()
    {
        await using var app = await TestApp.StartAsync();
        var userId = app.Users.Get(TestApp.UserEmail).Id;

        // session A: the administrator's session in the attacker's hands; session B: the administrator
        var stolen = await AdminAsync(app);
        var owner = await AdminAsync(app);

        var impersonation = app.CreateClient();
        impersonation.BearerToken = (await stolen.PostJsonAsync($"/api/impersonate/{userId}")).Str("accessToken");
        Assert.Equal(HttpStatusCode.OK, (await impersonation.GetAsync("/api/hello")).StatusCode);

        // the administrator spots the foreign session and signs that device out
        var sessions = JsonDocument.Parse(await (await owner.GetAsync("/auth/sessions")).Content.ReadAsStringAsync()).RootElement;
        foreach (var s in sessions.EnumerateArray().Where(s => !s.GetProperty("isCurrent").GetBoolean()))
            Assert.Equal(HttpStatusCode.OK, (await owner.DeleteAsync($"/auth/sessions/{s.Str("id")}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await stolen.GetAsync("/api/hello")).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await impersonation.GetAsync("/api/hello")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await impersonation.PostAsync("/api/impersonate/stop")).StatusCode);
    }

    [Fact]
    public async Task A_cookie_impersonation_returns_to_the_administrators_original_session()
    {
        await using var app = await TestApp.StartAsync();
        var userId = app.Users.Get(TestApp.UserEmail).Id;
        var admin = app.CreateClient();
        admin.SendCsrfHeader = true;
        await admin.PostJsonAsync("/auth/login?useCookies=true", new { email = TestApp.AdminEmail, password = TestApp.AdminPassword });

        await admin.PostJsonAsync($"/api/impersonate/{userId}");   // the cookie mode follows the administrator's session
        var during = JsonDocument.Parse(await (await admin.GetAsync("/api/hello")).Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(TestApp.UserEmail, during.Str("email"));

        await admin.PostJsonAsync("/api/impersonate/stop");
        var after = JsonDocument.Parse(await (await admin.GetAsync("/api/hello")).Content.ReadAsStringAsync()).RootElement;
        Assert.Equal(TestApp.AdminEmail, after.Str("email"));

        // still exactly the administrator's session – nothing dangling, nothing revoked
        var sessions = JsonDocument.Parse(await (await admin.GetAsync("/auth/sessions")).Content.ReadAsStringAsync()).RootElement;
        Assert.Single(sessions.EnumerateArray());
    }

    [Fact]
    public async Task An_impersonation_session_does_not_stand_in_for_the_owners_fresh_sign_in()
    {
        const string socialEmail = "social-only@test.local";
        await using var app = await TestApp.StartAsync(new TestAppOptions
        {
            Builder = b =>
            {
                b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
                b.Authentication.AddScheme<FakeOAuthOptions, FakeOAuthHandler>("Fake", o => o.Claims =
                    [new Claim(ClaimTypes.NameIdentifier, "google-1"), new Claim(ClaimTypes.Email, socialEmail), new Claim("email_verified", "true")]);
            },
            Map = a => a.MapPost("/api/confirm", async (ClaimsPrincipal me, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
                await auth.ConfirmPasswordAsync((await store.FindByIdAsync(me.GetSlimUserId()!, ct))!, null, ct) ?? Results.Ok(new { status = "confirmed" }))
                .RequireAuthorization(),
        });

        // the owner's account exists without a password (external login only) – the sign-in is long ago
        var owner = app.CreateClient();
        owner.SendCsrfHeader = true;
        var start = await owner.GetAsync("/auth/login/Fake?useCookies=true&returnUrl=/done");
        await owner.GetAsync(start.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await owner.PostAsync("/api/confirm")).StatusCode);   // the owner's own fresh sign-in counts
        app.Time.Advance(TimeSpan.FromHours(1));

        var admin = await AdminAsync(app);
        var impersonation = app.CreateClient();
        impersonation.BearerToken = (await admin.PostJsonAsync($"/api/impersonate/{app.Users.Get(socialEmail).Id}")).Str("accessToken");

        Assert.Equal(HttpStatusCode.Forbidden, (await impersonation.PostAsync("/api/confirm")).StatusCode);
    }
}
