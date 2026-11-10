using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Findings of review round 5 – each test performs the attack and failed before the fix.</summary>
public sealed class ReviewRound5Tests
{
    private const string SocialEmail = "social-only@test.local";

    private static TestAppOptions WithProvider(Action<WebApplication>? map = null, params Claim[] claims) => new()
    {
        Builder = b =>
        {
            b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
            b.Authentication.AddScheme<FakeOAuthOptions, FakeOAuthHandler>("Fake", o => o.Claims = claims.Length > 0 ? [.. claims] :
                [new Claim(ClaimTypes.NameIdentifier, "google-1"), new Claim(ClaimTypes.Email, SocialEmail), new Claim("email_verified", "true")]);
        },
        Map = map,
    };

    private static async Task<string> ExternalSignInAsync(ApiClient browser)
    {
        var start = await browser.GetAsync("/auth/login/Fake?useCookies=true&returnUrl=/done");
        var callback = await browser.GetAsync(start.Headers.Location!.OriginalString);
        return callback.Headers.Location!.OriginalString;
    }

    // ---------------------------------------------------------------- S-1: tenant binding

    private sealed class TenantStores
    {
        public readonly TestUserStore A = new(), B = new();
    }

    private sealed class TenantUserStore(IHttpContextAccessor http, TenantStores stores) : ISlimUserStore
    {
        private TestUserStore Current => http.HttpContext?.Request.Host.Host == "a.api.test" ? stores.A : stores.B;
        public Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct) => Current.FindByEmailAsync(email, ct);
        public Task<SlimUser?> FindByIdAsync(string userId, CancellationToken ct) => Current.FindByIdAsync(userId, ct);
        public Task<SlimUser?> CreateAsync(SlimNewUser newUser, CancellationToken ct) => Current.CreateAsync(newUser, ct);
        public Task UpdateSecurityStateAsync(SlimUser user, CancellationToken ct) => Current.UpdateSecurityStateAsync(user, ct);
        public Task<int> IncrementFailedLoginAttemptsAsync(SlimUser user, CancellationToken ct) => Current.IncrementFailedLoginAttemptsAsync(user, ct);
        public Task SetLockoutEndAsync(SlimUser user, DateTimeOffset? lockoutEndUtc, CancellationToken ct) => Current.SetLockoutEndAsync(user, lockoutEndUtc, ct);
        public Task ResetFailedLoginAttemptsAsync(SlimUser user, CancellationToken ct) => Current.ResetFailedLoginAttemptsAsync(user, ct);
        public Task UpdatePasswordHashAsync(SlimUser user, string currentHash, string newHash, CancellationToken ct) => Current.UpdatePasswordHashAsync(user, currentHash, newHash, ct);
        public Task<bool> UpdateEmailAsync(SlimUser user, string newEmail, CancellationToken ct) => Current.UpdateEmailAsync(user, newEmail, ct);
        public Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct) => Current.GetClaimsAsync(user, ct);
    }

    private static async Task<TestApp> StartTenantsAsync(string attackerId, bool sessions, Action<SlimIdentityOptions>? configure = null)
    {
        var stores = new TenantStores();
        stores.A.SeedWithId(attackerId, "mallory@a.test", "Tenant-A-Pass-1", "Admin");   // admin of the attacker's own tenant
        stores.B.SeedWithId("1", "bert@b.test", "Tenant-B-Pass-1");
        return await TestApp.StartAsync(new TestAppOptions
        {
            Sessions = sessions,
            Configure = o =>
            {
                o.Cookies.SecurityStampValidationInterval = new SlimCookieOptions().SecurityStampValidationInterval;   // the default (1 min)
                configure?.Invoke(o);
            },
            Builder = b =>
            {
                b.Services.AddSingleton(stores);
                b.AddUserStore<TenantUserStore>(ServiceLifetime.Scoped);
                b.UseTenantKey(h => h.Request.Host.Host);
            },
            Map = a => a.MapGet("/api/admin", (ClaimsPrincipal user) => new { sub = user.GetSlimUserId() }).RequireAuthorization(p => p.RequireRole("Admin")),
        });
    }

    [Theory]
    [InlineData("1", false)]                                      // colliding ids, no session store
    [InlineData("1", true)]                                       // colliding ids, session store
    [InlineData("11111111-1111-1111-1111-111111111111", false)]   // ids unique across tenants
    public async Task A_cookie_of_one_tenant_is_not_accepted_by_another(string attackerId, bool sessions)
    {
        await using var app = await StartTenantsAsync(attackerId, sessions);

        var home = new ApiClient(app.App.GetTestClient()) { Host = "a.api.test", SendCsrfHeader = true };
        await home.PostJsonAsync("/auth/login?useCookies=true", new { email = "mallory@a.test", password = "Tenant-A-Pass-1" });
        Assert.Equal(HttpStatusCode.OK, (await home.GetAsync("/api/admin")).StatusCode);

        var foreign = new ApiClient(app.App.GetTestClient()) { Host = "b.api.test", SendCsrfHeader = true };
        foreign.SetCookies(home.Cookies);

        Assert.Equal(HttpStatusCode.Unauthorized, (await foreign.GetAsync("/auth/me")).StatusCode);
        foreign.SetCookies(home.Cookies);
        Assert.Equal(HttpStatusCode.Unauthorized, (await foreign.GetAsync("/api/admin")).StatusCode);
        foreign.SetCookies(home.Cookies);
        app.Time.Advance(TimeSpan.FromMinutes(5));
        Assert.Equal(HttpStatusCode.Unauthorized, (await foreign.GetAsync("/auth/me")).StatusCode);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]   // no per-request validation: the tenant is checked anyway
    public async Task A_bearer_token_of_one_tenant_is_not_accepted_by_another(bool validateEachRequest)
    {
        await using var app = await StartTenantsAsync("1", sessions: false, o => o.Tokens.ValidateSecurityStampOnEachRequest = validateEachRequest);

        var home = new ApiClient(app.App.GetTestClient()) { Host = "a.api.test" };
        var token = (await home.PostJsonAsync("/auth/login", new { email = "mallory@a.test", password = "Tenant-A-Pass-1" })).Str("accessToken");
        home.BearerToken = token;
        Assert.Equal(HttpStatusCode.OK, (await home.GetAsync("/api/admin")).StatusCode);

        var foreign = new ApiClient(app.App.GetTestClient()) { Host = "b.api.test", BearerToken = token };
        Assert.Equal(HttpStatusCode.Unauthorized, (await foreign.GetAsync("/api/admin")).StatusCode);
    }

    // ---------------------------------------------------------------- S-2: impersonation is bound to the administrator's session

    [Fact]
    public async Task Revoking_the_administrators_session_ends_the_impersonation_started_from_it()
    {
        await using var app = await TestApp.StartAsync();
        var userId = app.Users.Get(TestApp.UserEmail).Id;

        // session A: the administrator's session in the attacker's hands; session B: the administrator
        var stolen = app.CreateClient();
        stolen.BearerToken = (await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword)).AccessToken;
        var owner = app.CreateClient();
        owner.BearerToken = (await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword)).AccessToken;

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

    // ---------------------------------------------------------------- S-3: lockout of passwordless accounts

    [Fact]
    public async Task Wrong_passwords_of_a_stranger_do_not_block_the_external_sign_in_of_a_passwordless_account()
    {
        await using var app = await TestApp.StartAsync(WithProvider());
        await ExternalSignInAsync(app.CreateClient());   // the account exists, external login only

        var stranger = app.CreateClient();
        for (var i = 0; i < 6; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await stranger.PostAsync("/auth/login", new { email = SocialEmail, password = "guess-" + i })).StatusCode);

        Assert.DoesNotContain("locked_out", await ExternalSignInAsync(app.CreateClient()));
        Assert.Equal(0, app.Users.Get(SocialEmail).FailedLoginAttempts);
    }

    // ---------------------------------------------------------------- S-4: start password + unconfirmed + external login

    [Fact]
    public async Task An_unconfirmed_account_with_a_start_password_is_not_dead_ended_by_the_owners_external_login()
    {
        await using var app = await TestApp.StartAsync(WithProvider());
        await using (var scope = app.App.Services.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<ISlimUserStore>();
            var created = await store.CreateAsync(new SlimNewUser { Email = SocialEmail }, default);
            Assert.False(created!.EmailConfirmed);
            await scope.ServiceProvider.GetRequiredService<ISlimAuthManager>().SetPasswordAsync(created, "Start-Password-123", mustChange: true);
        }

        var location = await ExternalSignInAsync(app.CreateClient());

        Assert.DoesNotContain("slim_error", location);
        var user = app.Users.Get(SocialEmail);
        Assert.True(string.IsNullOrEmpty(user.PasswordHash));
        Assert.False(user.PasswordChangeRequired);
    }

    // ---------------------------------------------------------------- S-5: impersonation is not the owner's fresh sign-in

    [Fact]
    public async Task An_impersonation_session_does_not_stand_in_for_the_owners_fresh_sign_in()
    {
        await using var app = await TestApp.StartAsync(WithProvider(app => app.MapPost("/api/confirm", async (ClaimsPrincipal me, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
            await auth.ConfirmPasswordAsync((await store.FindByIdAsync(me.GetSlimUserId()!, ct))!, null, ct) ?? Results.Ok(new { status = "confirmed" }))
            .RequireAuthorization()));

        // the owner's account exists without a password (external login only) – the sign-in is long ago
        var owner = app.CreateClient();
        owner.SendCsrfHeader = true;
        await ExternalSignInAsync(owner);
        Assert.Equal(HttpStatusCode.OK, (await owner.PostAsync("/api/confirm")).StatusCode);   // the owner's own fresh sign-in counts
        app.Time.Advance(TimeSpan.FromHours(1));

        var admin = app.CreateClient();
        admin.BearerToken = (await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword)).AccessToken;
        var impersonation = app.CreateClient();
        impersonation.BearerToken = (await admin.PostJsonAsync($"/api/impersonate/{app.Users.Get(SocialEmail).Id}")).Str("accessToken");

        Assert.Equal(HttpStatusCode.Forbidden, (await impersonation.PostAsync("/api/confirm")).StatusCode);
    }

    // ---------------------------------------------------------------- S-6: forgotten UseRateLimiter()

    [Fact]
    public async Task Without_UseRateLimiter_the_brute_force_limit_is_not_silently_off()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.WebHost.UseTestServer();
        builder.Services.AddSlimIdentity(o => o.RateLimit.PermitLimit = 2)
            .AddUserStore<TestUserStore>(ServiceLifetime.Singleton)
            .AddNullEmailSender();
        await using var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapSlimIdentityApi();   // no app.UseRateLimiter()
        await app.StartAsync();
        var client = new ApiClient(app.GetTestClient());

        var error = await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
            client.PostAsync("/auth/login", new { email = "nobody@test.local", password = "Whatever-123" }));
        Assert.Contains("UseRateLimiter", error.Message);
        await app.StopAsync();
    }

    // ---------------------------------------------------------------- S-7: email_verified only covers the email claim

    [Fact]
    public async Task A_verified_flag_does_not_vouch_for_a_user_name_that_looks_like_an_address()
    {
        await using var app = await TestApp.StartAsync(WithProvider(null,
            new Claim(ClaimTypes.NameIdentifier, "entra-1"), new Claim("preferred_username", SocialEmail), new Claim("email_verified", "true")));

        var location = await ExternalSignInAsync(app.CreateClient());

        Assert.Contains("email_not_verified", location);
        Assert.Null(await app.Users.FindByEmailAsync(SocialEmail, default));
    }
}
