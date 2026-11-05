using System.Net;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

public sealed class CookieAndCsrfTests
{
    private static readonly object UserLogin = new { email = TestApp.UserEmail, password = TestApp.UserPassword };

    [Fact]
    public async Task Cookie_login_requires_the_csrf_header()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();

        var withoutHeader = await client.PostAsync("/auth/login?useCookies=true", UserLogin);
        Assert.Equal(HttpStatusCode.Forbidden, withoutHeader.StatusCode);
        Assert.Contains("csrf_validation_failed", await withoutHeader.Content.ReadAsStringAsync());

        client.SendCsrfHeader = true;
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/auth/login?useCookies=true", UserLogin)).StatusCode);
        Assert.True(client.Cookies.ContainsKey("SlimAuth"));
    }

    [Fact]
    public async Task Cookie_is_HttpOnly_Secure_and_SameSite_strict()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();
        client.SendCsrfHeader = true;

        var response = await client.PostAsync("/auth/login?useCookies=true", UserLogin);
        var setCookie = Assert.Single(response.Headers.GetValues("Set-Cookie"), h => h.StartsWith("SlimAuth=", StringComparison.Ordinal));

        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("secure", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", setCookie, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("https://evil.example", HttpStatusCode.Forbidden)]
    [InlineData("https://app.test.local", HttpStatusCode.OK)]   // Csrf.AllowedOrigins
    [InlineData("https://localhost", HttpStatusCode.OK)]        // the API itself
    public async Task Origin_is_checked_in_cookie_mode(string origin, HttpStatusCode expected)
    {
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();
        client.SendCsrfHeader = true;
        client.Origin = origin;

        Assert.Equal(expected, (await client.PostAsync("/auth/login?useCookies=true", UserLogin)).StatusCode);
    }

    [Fact]
    public async Task Bearer_requests_need_no_csrf_header()
    {
        await using var app = await TestApp.StartAsync();
        var tokens = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var client = app.CreateClient();
        client.BearerToken = tokens.AccessToken;

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/auth/logout-all")).StatusCode);
    }

    [Fact]
    public async Task Copied_cookie_is_rejected_after_logout()
    {
        await using var app = await TestApp.StartAsync();
        var browser = app.CreateClient();
        browser.SendCsrfHeader = true;
        await browser.PostAsync("/auth/login?useCookies=true", UserLogin);

        var thief = app.CreateClient();
        thief.SetCookies(browser.Cookies);
        Assert.Equal(HttpStatusCode.OK, (await thief.GetAsync("/api/hello")).StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await browser.PostAsync("/auth/logout")).StatusCode);
        Assert.False(browser.Cookies.ContainsKey("SlimAuth"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await thief.GetAsync("/api/hello")).StatusCode);
    }

    [Fact]
    public async Task Without_session_store_logout_all_still_invalidates_copied_cookies()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Sessions = false });
        var browser = app.CreateClient();
        browser.SendCsrfHeader = true;
        await browser.PostAsync("/auth/login?useCookies=true", UserLogin);
        var thief = app.CreateClient();
        thief.SetCookies(browser.Cookies);

        Assert.Equal(HttpStatusCode.OK, (await browser.PostAsync("/auth/logout-all")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await thief.GetAsync("/api/hello")).StatusCode);
    }
}
