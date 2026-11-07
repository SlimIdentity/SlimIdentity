using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// Tenants with their own domains: trusted origins (CSRF, returnUrl, CORS) and mail links per request.
/// Tenant a: API https://a.api.test, front end https://a.app.test – tenant b likewise.
/// </summary>
public sealed class TenantTests
{
    private static string? TenantOf(HttpContext http) => http.Request.Host.Host switch
    {
        "a.api.test" => "a",
        "b.api.test" => "b",
        _ => null,
    };

    /// <summary>Each tenant trusts its own front end only.</summary>
    private sealed class TenantOriginPolicy : ISlimOriginPolicy
    {
        public bool IsTrusted(HttpContext httpContext, string origin) =>
            TenantOf(httpContext) is { } tenant && origin == $"https://{tenant}.app.test";
    }

    /// <summary>Mail links point to the tenant's front end.</summary>
    private sealed class TenantLinkBuilder : ISlimLinkBuilder
    {
        public string? BuildLink(SlimLinkKind kind, string token, HttpContext? httpContext) =>
            httpContext is not null && TenantOf(httpContext) is { } tenant
                ? $"https://{tenant}.app.test/{kind.ToString().ToLowerInvariant()}#token={Uri.EscapeDataString(token)}"
                : null;   // no tenant: the configured Links.* apply
    }

    private static TestAppOptions Tenants(bool cors = false) => new()
    {
        Builder = b =>
        {
            b.AddOriginPolicy<TenantOriginPolicy>();
            b.AddLinkBuilder<TenantLinkBuilder>();
            b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
            b.Authentication.AddScheme<FakeOAuthOptions, FakeOAuthHandler>("Fake", o => o.Claims =
                [new Claim(ClaimTypes.NameIdentifier, "ext-1"), new Claim(ClaimTypes.Email, "social@test.local"), new Claim("email_verified", "true")]);
            if (cors) b.AddCorsPolicy();
        },
        Configure = o => o.Links.BaseUrl = "https://default.app.test",
        Map = app => { if (cors) app.UseCors(SlimIdentityDefaults.CorsPolicy); },
    };

    private static ApiClient Browser(TestApp app, string apiHost, string origin) =>
        new ApiClient(app.App.GetTestClient()) { Host = apiHost, Origin = origin, SendCsrfHeader = true };

    [Fact]
    public async Task Cookie_requests_are_accepted_only_from_the_tenants_own_front_end()
    {
        await using var app = await TestApp.StartAsync(Tenants());
        var login = new { email = TestApp.UserEmail, password = TestApp.UserPassword };

        Assert.Equal(HttpStatusCode.OK, (await Browser(app, "a.api.test", "https://a.app.test").PostAsync("/auth/login?useCookies=true", login)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Browser(app, "b.api.test", "https://a.app.test").PostAsync("/auth/login?useCookies=true", login)).StatusCode);
        // TrustedOrigins of the default policy no longer apply once a policy is registered
        Assert.Equal(HttpStatusCode.Forbidden, (await Browser(app, "a.api.test", "https://app.test.local").PostAsync("/auth/login?useCookies=true", login)).StatusCode);
    }

    [Fact]
    public async Task A_return_url_must_belong_to_the_tenant()
    {
        await using var app = await TestApp.StartAsync(Tenants());

        var own = await Browser(app, "a.api.test", "https://a.app.test").GetAsync("/auth/login/Fake?useCookies=true&returnUrl=https://a.app.test/done");
        Assert.Equal(HttpStatusCode.Redirect, own.StatusCode);

        var foreign = await Browser(app, "b.api.test", "https://b.app.test").GetAsync("/auth/login/Fake?useCookies=true&returnUrl=https://a.app.test/done");
        Assert.Equal(HttpStatusCode.BadRequest, foreign.StatusCode);
    }

    [Fact]
    public async Task Mail_links_point_to_the_tenants_front_end()
    {
        await using var app = await TestApp.StartAsync(Tenants());

        await Browser(app, "b.api.test", "https://b.app.test").PostAsync("/auth/forgot-password", new { email = TestApp.UserEmail });
        var tenantMail = await app.Mail.WaitForAsync("password-reset", TestApp.UserEmail);
        Assert.StartsWith("https://b.app.test/passwordreset#token=", tenantMail.Payload);

        await app.CreateClient().PostAsync("/auth/forgot-password", new { email = TestApp.AdminEmail });   // no tenant
        var defaultMail = await app.Mail.WaitForAsync("password-reset", TestApp.AdminEmail);
        Assert.StartsWith("https://default.app.test/reset-password?token=", defaultMail.Payload);
    }

    [Fact]
    public async Task Cors_allows_credentials_for_the_tenants_front_end_only()
    {
        await using var app = await TestApp.StartAsync(Tenants(cors: true));

        var allowed = await PreflightAsync(app, "a.api.test", "https://a.app.test");
        Assert.Equal("https://a.app.test", Header(allowed, "Access-Control-Allow-Origin"));
        Assert.Equal("true", Header(allowed, "Access-Control-Allow-Credentials"));
        Assert.Contains("x-csrf", Header(allowed, "Access-Control-Allow-Headers")!, StringComparison.OrdinalIgnoreCase);

        var refused = await PreflightAsync(app, "b.api.test", "https://a.app.test");
        Assert.Null(Header(refused, "Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task Without_tenants_cors_follows_the_trusted_origins()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions   // TrustedOrigins = https://app.test.local
        {
            Builder = b => b.AddCorsPolicy(),
            Map = a => a.UseCors(SlimIdentityDefaults.CorsPolicy),
        });

        Assert.Equal("https://app.test.local", Header(await PreflightAsync(app, "localhost", "https://app.test.local"), "Access-Control-Allow-Origin"));
        Assert.Null(Header(await PreflightAsync(app, "localhost", "https://evil.test"), "Access-Control-Allow-Origin"));
    }

    private static async Task<HttpResponseMessage> PreflightAsync(TestApp app, string apiHost, string origin)
    {
        using var request = new HttpRequestMessage(HttpMethod.Options, $"https://{apiHost}/auth/login");
        request.Headers.Add("Origin", origin);
        request.Headers.Add("Access-Control-Request-Method", "POST");
        request.Headers.Add("Access-Control-Request-Headers", "content-type,x-csrf");
        return await app.App.GetTestClient().SendAsync(request);
    }

    private static string? Header(HttpResponseMessage response, string name) =>
        response.Headers.TryGetValues(name, out var values) ? string.Join(",", values) : null;
}
