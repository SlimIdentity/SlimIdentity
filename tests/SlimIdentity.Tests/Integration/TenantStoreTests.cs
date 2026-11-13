using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// One user store per tenant (a database per customer) with colliding ids: user "1" exists in both tenants. Links,
/// codes and tokens of one tenant must not act on the other's user "1" – they are bound to the security stamp, which
/// differs. Docs: guides/multi-tenancy.md.
/// </summary>
public sealed class TenantStoreTests
{
    private const string UserA = "anna@a.test";
    private const string UserB = "bert@b.test";
    private const string PasswordA = "Tenant-A-Pass-1";
    private const string PasswordB = "Tenant-B-Pass-1";

    /// <summary>The store of the tenant the request is for (by host) – both hand out the id "1".</summary>
    private sealed class TenantUserStore(IHttpContextAccessor http) : ISlimUserStore
    {
        public static readonly TestUserStore A = new(), B = new();

        private TestUserStore Current => http.HttpContext?.Request.Host.Host switch
        {
            "a.api.test" => A,
            "b.api.test" => B,
            var other => throw new InvalidOperationException($"No tenant for host '{other}'."),
        };

        public Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct) => Current.FindByEmailAsync(email, ct);
        public Task<SlimUser?> FindByIdAsync(string userId, CancellationToken ct) => Current.FindByIdAsync(userId, ct);
        public Task<SlimUser?> CreateAsync(SlimNewUser newUser, CancellationToken ct) => Current.CreateAsync(newUser, ct);
        public Task<bool> UpdateSecurityStateAsync(SlimUser user, string expectedStamp, CancellationToken ct) => Current.UpdateSecurityStateAsync(user, expectedStamp, ct);
        public Task<bool> UpdateSecurityStampAsync(SlimUser user, string expectedStamp, string newStamp, CancellationToken ct) => Current.UpdateSecurityStampAsync(user, expectedStamp, newStamp, ct);
        public Task<SlimAttemptReservation?> TryBeginAttemptAsync(SlimUser user, SlimAttemptRequest attempt, CancellationToken ct) => Current.TryBeginAttemptAsync(user, attempt, ct);
        public Task ResetFailedAttemptsAsync(SlimUser user, SlimAttemptFactor factor, CancellationToken ct) => Current.ResetFailedAttemptsAsync(user, factor, ct);
        public Task UpdatePasswordHashAsync(SlimUser user, string currentHash, string newHash, CancellationToken ct) => Current.UpdatePasswordHashAsync(user, currentHash, newHash, ct);
        public Task<SlimEmailUpdateResult> UpdateEmailAsync(SlimUser user, string newEmail, string expectedStamp, string newStamp, CancellationToken ct) => Current.UpdateEmailAsync(user, newEmail, expectedStamp, newStamp, ct);
        public Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct) => Current.GetClaimsAsync(user, ct);
    }

    private static async Task<TestApp> StartAsync(bool stampOnEachRequest = true)
    {
        // the stores are static (resolved per request, the data must outlive it); seeding id "1" again resets the user
        TenantUserStore.A.SeedWithId("1", UserA, PasswordA);
        TenantUserStore.B.SeedWithId("1", UserB, PasswordB);

        return await TestApp.StartAsync(new TestAppOptions
        {
            Configure = o => o.Tokens.ValidateSecurityStampOnEachRequest = stampOnEachRequest,
            Builder = b => b.AddUserStore<TenantUserStore>(ServiceLifetime.Scoped),
            Map = app => app.MapPost("/api/reset-link/{email}", async (string email, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
                (await auth.CreatePasswordResetAsync((await store.FindByEmailAsync(email, ct))!, ct: ct)).Token),
        });
    }

    private static ApiClient Tenant(TestApp app, string host) => new(app.App.GetTestClient()) { Host = host };

    [Fact]
    public async Task A_reset_link_of_one_tenant_does_not_reset_the_same_id_in_another()
    {
        await using var app = await StartAsync();
        var token = await (await Tenant(app, "a.api.test").PostAsync($"/api/reset-link/{UserA}")).Content.ReadAsStringAsync();   // plain text

        var foreign = await Tenant(app, "b.api.test").ResetPasswordAsync(token, "Hijacked-Pass-9");

        Assert.Equal(HttpStatusCode.Unauthorized, foreign.StatusCode);
        await Tenant(app, "b.api.test").PostJsonAsync("/auth/login", new { email = UserB, password = PasswordB });    // unchanged
        await Tenant(app, "a.api.test").ResetPasswordJsonAsync(token, "Anna-New-Pass-2");   // works at home
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task An_access_token_of_one_tenant_is_not_accepted_by_another(bool stampOnEachRequest)
    {
        await using var app = await StartAsync(stampOnEachRequest);
        var tokens = await Tenant(app, "a.api.test").PostJsonAsync("/auth/login", new { email = UserA, password = PasswordA });
        var accessToken = tokens.Str("accessToken");

        var home = Tenant(app, "a.api.test");
        home.BearerToken = accessToken;
        var foreign = Tenant(app, "b.api.test");
        foreign.BearerToken = accessToken;

        Assert.Equal(HttpStatusCode.OK, (await home.GetAsync("/auth/me")).StatusCode);
        if (stampOnEachRequest)
            Assert.Equal(HttpStatusCode.Unauthorized, (await foreign.GetAsync("/auth/me")).StatusCode);
        else
            // documented: without the check per request the signature alone decides – one signing key, one audience for
            // all tenants means the token works at the other tenant until it expires (guides/multi-tenancy.md)
            Assert.Equal(HttpStatusCode.OK, (await foreign.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task A_refresh_token_of_one_tenant_is_refused_by_another()
    {
        await using var app = await StartAsync();
        var tokens = await Tenant(app, "a.api.test").PostJsonAsync("/auth/login", new { email = UserA, password = PasswordA });

        var foreign = await Tenant(app, "b.api.test").PostAsync("/auth/refresh", new { refreshToken = tokens.Str("refreshToken") });

        Assert.Equal(HttpStatusCode.Unauthorized, foreign.StatusCode);
    }

    // With UseTenantKey every cookie and token is bound to its tenant, whatever the ids and the per-request validation.

    private sealed class KeyedTenantStores
    {
        public readonly TestUserStore A = new(), B = new();
    }

    private sealed class KeyedTenantUserStore(IHttpContextAccessor http, KeyedTenantStores stores) : ISlimUserStore
    {
        private TestUserStore Current => http.HttpContext?.Request.Host.Host == "a.api.test" ? stores.A : stores.B;
        public Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct) => Current.FindByEmailAsync(email, ct);
        public Task<SlimUser?> FindByIdAsync(string userId, CancellationToken ct) => Current.FindByIdAsync(userId, ct);
        public Task<SlimUser?> CreateAsync(SlimNewUser newUser, CancellationToken ct) => Current.CreateAsync(newUser, ct);
        public Task<bool> UpdateSecurityStateAsync(SlimUser user, string expectedStamp, CancellationToken ct) => Current.UpdateSecurityStateAsync(user, expectedStamp, ct);
        public Task<bool> UpdateSecurityStampAsync(SlimUser user, string expectedStamp, string newStamp, CancellationToken ct) => Current.UpdateSecurityStampAsync(user, expectedStamp, newStamp, ct);
        public Task<SlimAttemptReservation?> TryBeginAttemptAsync(SlimUser user, SlimAttemptRequest attempt, CancellationToken ct) => Current.TryBeginAttemptAsync(user, attempt, ct);
        public Task ResetFailedAttemptsAsync(SlimUser user, SlimAttemptFactor factor, CancellationToken ct) => Current.ResetFailedAttemptsAsync(user, factor, ct);
        public Task UpdatePasswordHashAsync(SlimUser user, string currentHash, string newHash, CancellationToken ct) => Current.UpdatePasswordHashAsync(user, currentHash, newHash, ct);
        public Task<SlimEmailUpdateResult> UpdateEmailAsync(SlimUser user, string newEmail, string expectedStamp, string newStamp, CancellationToken ct) => Current.UpdateEmailAsync(user, newEmail, expectedStamp, newStamp, ct);
        public Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct) => Current.GetClaimsAsync(user, ct);
    }

    private static async Task<TestApp> StartWithTenantKeyAsync(string attackerId, bool sessions, bool stampOnEachRequest = true)
    {
        var stores = new KeyedTenantStores();
        stores.A.SeedWithId(attackerId, "mallory@a.test", PasswordA, "Admin");   // administrator of the own tenant
        stores.B.SeedWithId("1", UserB, PasswordB);
        return await TestApp.StartAsync(new TestAppOptions
        {
            Sessions = sessions,
            Configure = o =>
            {
                o.Cookies.SecurityStampValidationInterval = new SlimCookieOptions().SecurityStampValidationInterval;   // the default (1 min)
                o.Tokens.ValidateSecurityStampOnEachRequest = stampOnEachRequest;
            },
            Builder = b =>
            {
                b.Services.AddSingleton(stores);
                b.AddUserStore<KeyedTenantUserStore>(ServiceLifetime.Scoped);
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
        await using var app = await StartWithTenantKeyAsync(attackerId, sessions);

        var home = Tenant(app, "a.api.test");
        home.SendCsrfHeader = true;
        await home.PostJsonAsync("/auth/login?useCookies=true", new { email = "mallory@a.test", password = PasswordA });
        Assert.Equal(HttpStatusCode.OK, (await home.GetAsync("/api/admin")).StatusCode);

        var foreign = Tenant(app, "b.api.test");
        foreign.SendCsrfHeader = true;
        foreign.SetCookies(home.Cookies);
        Assert.Equal(HttpStatusCode.Unauthorized, (await foreign.GetAsync("/auth/me")).StatusCode);
        foreign.SetCookies(home.Cookies);
        Assert.Equal(HttpStatusCode.Unauthorized, (await foreign.GetAsync("/api/admin")).StatusCode);
        foreign.SetCookies(home.Cookies);
        app.Time.Advance(TimeSpan.FromMinutes(5));
        Assert.Equal(HttpStatusCode.Unauthorized, (await foreign.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task With_a_tenant_key_a_bearer_token_of_one_tenant_is_refused_by_another_even_without_per_request_validation()
    {
        await using var app = await StartWithTenantKeyAsync("1", sessions: false, stampOnEachRequest: false);

        var home = Tenant(app, "a.api.test");
        home.BearerToken = (await home.PostJsonAsync("/auth/login", new { email = "mallory@a.test", password = PasswordA })).Str("accessToken");
        Assert.Equal(HttpStatusCode.OK, (await home.GetAsync("/api/admin")).StatusCode);

        var foreign = Tenant(app, "b.api.test");
        foreign.BearerToken = home.BearerToken;
        Assert.Equal(HttpStatusCode.Unauthorized, (await foreign.GetAsync("/api/admin")).StatusCode);
    }
}
