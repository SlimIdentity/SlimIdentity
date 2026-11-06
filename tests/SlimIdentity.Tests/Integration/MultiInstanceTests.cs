using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using SlimIdentity.Security;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// Two instances behind a (simulated) load balancer: separate hosts, one database (shared store instances) and one
/// Data Protection key ring. Proves that no sticky sessions are needed – and what breaks without a shared key ring.
/// </summary>
public sealed class MultiInstanceTests
{
    private sealed class Cluster : IAsyncDisposable
    {
        public readonly FakeTimeProvider Time = new(DateTimeOffset.UtcNow);
        public readonly TestUserStore Users = new();
        public readonly TestSessionStore Sessions = new();
        public readonly TestTwoFactorStore TwoFactor = new();
        public readonly CapturingEmailSender Mail = new();
        public readonly TestRefreshTokenStore RefreshTokens;
        private readonly DirectoryInfo _keys = Directory.CreateTempSubdirectory("slim-cluster-keys");
        public WebApplication A = null!, B = null!;

        private Cluster() => RefreshTokens = new TestRefreshTokenStore(Time);

        public static async Task<Cluster> StartAsync(bool sharedKeyRing = true, int permitLimit = 10_000)
        {
            var cluster = new Cluster();
            cluster.Users.Seed(TestApp.UserEmail, TestApp.UserPassword);
            cluster.A = await cluster.StartNodeAsync(sharedKeyRing, permitLimit);
            cluster.B = await cluster.StartNodeAsync(sharedKeyRing, permitLimit);
            return cluster;
        }

        private async Task<WebApplication> StartNodeAsync(bool sharedKeyRing, int permitLimit)
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
            builder.WebHost.UseTestServer();
            builder.Logging.ClearProviders();
            builder.Services.AddSingleton<TimeProvider>(Time);
            if (sharedKeyRing) builder.Services.AddDataProtection().PersistKeysToFileSystem(_keys).SetApplicationName("slim-cluster");
            else builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();

            builder.Services.AddSlimIdentity(o =>
                {
                    o.Tokens.JwtSecret = "cluster-secret-0123456789-abcdefghijklmnopqrstuvwxyz";   // identical on every node
                    o.RateLimit.PermitLimit = permitLimit;
                    o.Cookies.SecurityStampValidationInterval = TimeSpan.Zero;
                })
                .AddUserStore<TestUserStore>(ServiceLifetime.Singleton)
                .AddEmailSender<CapturingEmailSender>(ServiceLifetime.Singleton)
                .AddRefreshTokenStore<TestRefreshTokenStore>(ServiceLifetime.Singleton)
                .AddSessionStore<TestSessionStore>(ServiceLifetime.Singleton)
                .AddTwoFactorStore<TestTwoFactorStore>(ServiceLifetime.Singleton);
            // one database: every node gets the same store instances
            builder.Services.Replace(ServiceDescriptor.Singleton<ISlimUserStore>(Users));
            builder.Services.Replace(ServiceDescriptor.Singleton<ISlimEmailSender>(Mail));
            builder.Services.Replace(ServiceDescriptor.Singleton<ISlimRefreshTokenStore>(RefreshTokens));
            builder.Services.Replace(ServiceDescriptor.Singleton<ISlimSessionStore>(Sessions));
            builder.Services.Replace(ServiceDescriptor.Singleton<ISlimTwoFactorStore>(TwoFactor));

            var app = builder.Build();
            app.UseRateLimiter();
            app.UseAuthentication();
            app.UseAuthorization();
            app.MapSlimIdentityApi();
            app.MapGet("/api/hello", (ClaimsPrincipal user) => user.GetSlimEmail()).RequireAuthorization();
            await app.StartAsync();
            return app;
        }

        public ApiClient On(WebApplication node, ApiClient? takeOver = null)
        {
            var client = new ApiClient(node.GetTestClient());
            if (takeOver is not null)
            {
                client.SetCookies(takeOver.Cookies);
                client.BearerToken = takeOver.BearerToken;
                client.SendCsrfHeader = takeOver.SendCsrfHeader;
            }
            return client;
        }

        public async ValueTask DisposeAsync()
        {
            await A.DisposeAsync();
            await B.DisposeAsync();
            _keys.Delete(recursive: true);
        }
    }

    private static object UserLogin => new { email = TestApp.UserEmail, password = TestApp.UserPassword };

    [Fact]
    public async Task A_cookie_issued_by_one_instance_works_on_the_other()
    {
        await using var cluster = await Cluster.StartAsync();
        var onA = cluster.On(cluster.A);
        onA.SendCsrfHeader = true;
        await onA.PostJsonAsync("/auth/login?useCookies=true", UserLogin);

        var onB = cluster.On(cluster.B, takeOver: onA);
        Assert.Equal(HttpStatusCode.OK, (await onB.GetAsync("/api/hello")).StatusCode);
    }

    [Fact]
    public async Task Refresh_rotation_and_reuse_detection_span_instances()
    {
        await using var cluster = await Cluster.StartAsync();
        var tokens = await cluster.On(cluster.A).PostJsonAsync("/auth/login", UserLogin);

        var rotated = await cluster.On(cluster.B).PostJsonAsync("/auth/refresh", new { refreshToken = tokens.Str("refreshToken") });
        // the stolen old token is replayed on the other instance: detected, the session (token family) is revoked
        await cluster.On(cluster.A).PostJsonAsync("/auth/refresh", new { refreshToken = tokens.Str("refreshToken") }, HttpStatusCode.Unauthorized);

        var afterReuse = cluster.On(cluster.B);
        afterReuse.BearerToken = rotated.Str("accessToken");
        Assert.Equal(HttpStatusCode.Unauthorized, (await afterReuse.GetAsync("/api/hello")).StatusCode);
    }

    [Fact]
    public async Task A_2fa_challenge_issued_on_one_instance_is_completed_once_on_another()
    {
        await using var cluster = await Cluster.StartAsync();
        var me = cluster.On(cluster.A);
        me.BearerToken = (await me.PostJsonAsync("/auth/login", UserLogin)).Str("accessToken");
        var setup = await me.PostJsonAsync("/auth/2fa/setup");
        var key = SlimBase32.Decode(setup.Str("sharedKey"));
        string Code() => SlimTotp.Compute(key, cluster.Time.GetUtcNow().ToUnixTimeSeconds() / 30);
        await cluster.On(cluster.B, takeOver: me).PostJsonAsync("/auth/2fa/enable", new { setupToken = setup.Str("setupToken"), code = Code(), password = TestApp.UserPassword });
        cluster.Time.Advance(TimeSpan.FromSeconds(30));

        var challenge = await cluster.On(cluster.A).PostJsonAsync("/auth/login", UserLogin, HttpStatusCode.Unauthorized);
        await cluster.On(cluster.B).PostJsonAsync("/auth/login/2fa", new { preAuthToken = challenge.Str("preAuthToken"), code = Code() });

        cluster.Time.Advance(TimeSpan.FromSeconds(30));   // a fresh, valid code – but the challenge is used up everywhere
        await cluster.On(cluster.A).PostJsonAsync("/auth/login/2fa", new { preAuthToken = challenge.Str("preAuthToken"), code = Code() }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_reset_link_from_one_instance_works_once_on_another()
    {
        await using var cluster = await Cluster.StartAsync();
        await cluster.On(cluster.A).PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        var link = (await cluster.Mail.WaitForAsync("password-reset", TestApp.UserEmail)).Payload;

        await cluster.On(cluster.B).PostJsonAsync("/auth/reset-password", new { token = link, newPassword = "Cluster-Pass-123" });
        await cluster.On(cluster.A).PostJsonAsync("/auth/reset-password", new { token = link, newPassword = "Again-Pass-456" }, HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Sign_out_everywhere_on_one_instance_ends_sessions_on_the_other_immediately()
    {
        await using var cluster = await Cluster.StartAsync();
        var browser = cluster.On(cluster.B);
        browser.SendCsrfHeader = true;
        await browser.PostJsonAsync("/auth/login?useCookies=true", UserLogin);
        var phone = cluster.On(cluster.B);
        phone.BearerToken = (await phone.PostJsonAsync("/auth/login", UserLogin)).Str("accessToken");

        var other = cluster.On(cluster.A);
        other.BearerToken = (await other.PostJsonAsync("/auth/login", UserLogin)).Str("accessToken");
        await other.PostJsonAsync("/auth/logout-all");

        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/hello")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await phone.GetAsync("/api/hello")).StatusCode);
    }

    [Fact]
    public async Task The_account_lockout_is_global_while_the_rate_limit_is_per_instance()
    {
        await using var cluster = await Cluster.StartAsync(permitLimit: 3);
        var statuses = new List<HttpStatusCode>();
        foreach (var node in new[] { cluster.A, cluster.A, cluster.A, cluster.A, cluster.B, cluster.B })
            statuses.Add((await cluster.On(node).PostAsync("/auth/login", new { email = TestApp.UserEmail, password = "wrong" })).StatusCode);

        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[3]);   // A's own bucket is exhausted …
        Assert.NotEqual(HttpStatusCode.TooManyRequests, statuses[4]); // … B has its own (documented: limit × instances)
        // but the per-account lockout counts every failure on every instance: 5 failures → locked everywhere
        Assert.Equal(5, cluster.Users.Get(TestApp.UserEmail).FailedLoginAttempts);
        Assert.True(cluster.Users.Get(TestApp.UserEmail).IsLockedOut(cluster.Time.GetUtcNow()));
    }

    [Fact]
    public async Task Without_a_shared_key_ring_instances_reject_each_others_cookies_and_links()
    {
        // the failure mode the start-up diagnostics warn about (event 8002)
        await using var cluster = await Cluster.StartAsync(sharedKeyRing: false);
        var onA = cluster.On(cluster.A);
        onA.SendCsrfHeader = true;
        await onA.PostJsonAsync("/auth/login?useCookies=true", UserLogin);
        await cluster.On(cluster.A).PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        var link = (await cluster.Mail.WaitForAsync("password-reset", TestApp.UserEmail)).Payload;

        Assert.Equal(HttpStatusCode.Unauthorized, (await cluster.On(cluster.B, takeOver: onA).GetAsync("/api/hello")).StatusCode);
        await cluster.On(cluster.B).PostJsonAsync("/auth/reset-password", new { token = link, newPassword = "Cluster-Pass-123" }, HttpStatusCode.BadRequest);
    }
}
