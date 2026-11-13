using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Listing and removing sign-in methods – never the last one.</summary>
public sealed class SignInMethodTests
{
    private const string SocialEmail = "social-only@test.local";

    private static TestAppOptions WithProvider() => new()
    {
        Builder = b =>
        {
            b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
            b.Authentication.AddScheme<FakeOAuthOptions, FakeOAuthHandler>("Fake", o => o.Claims =
                [new Claim(ClaimTypes.NameIdentifier, "google-1"), new Claim(ClaimTypes.Email, SocialEmail), new Claim("email_verified", "true")]);
        },
    };

    private static ISlimExternalLoginStore Links(TestApp app) => app.App.Services.GetRequiredService<ISlimExternalLoginStore>();

    private static async Task<ApiClient> PasswordUserAsync(TestApp app)
    {
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        return me;
    }

    /// <summary>An account created by the external sign-in – it has no password.</summary>
    private static async Task<ApiClient> SocialOnlyUserAsync(TestApp app)
    {
        var browser = app.CreateClient();
        browser.SendCsrfHeader = true;
        var start = await browser.GetAsync("/auth/login/Fake?useCookies=true&returnUrl=/done");
        await browser.GetAsync(start.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/auth/me")).StatusCode);
        return browser;
    }

    [Fact]
    public async Task The_methods_of_an_account_are_listed()
    {
        await using var app = await TestApp.StartAsync(WithProvider());
        await Links(app).LinkExternalLoginAsync(app.Users.Get(TestApp.UserEmail).Id, "Fake", "google-9", default);
        var me = await PasswordUserAsync(app);

        var methods = await (await me.GetAsync("/auth/sign-in-methods")).Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();

        Assert.True(methods.GetProperty("hasPassword").GetBoolean());
        var external = Assert.Single(methods.GetProperty("externalLogins").EnumerateArray());
        Assert.Equal("Fake", external.Str("provider"));
        Assert.Equal("google-9", external.Str("providerKey"));
    }

    [Fact]
    public async Task An_external_login_is_removed_with_the_password()
    {
        await using var app = await TestApp.StartAsync(WithProvider());
        await Links(app).LinkExternalLoginAsync(app.Users.Get(TestApp.UserEmail).Id, "Fake", "google-9", default);
        var me = await PasswordUserAsync(app);

        await me.PostJsonAsync("/auth/sign-in-methods/external/remove", new { provider = "Fake", providerKey = "google-9" }, HttpStatusCode.BadRequest);   // no password
        await me.PostJsonAsync("/auth/sign-in-methods/external/remove", new { provider = "Fake", providerKey = "google-9", password = "wrong" }, HttpStatusCode.BadRequest);
        var removed = await me.PostJsonAsync("/auth/sign-in-methods/external/remove", new { provider = "Fake", providerKey = "google-9", password = TestApp.UserPassword });

        Assert.Null(await Links(app).FindByExternalLoginAsync("Fake", "google-9", default));
        // the removal ends the old session state; the reissued tokens carry on
        Assert.Equal(HttpStatusCode.Unauthorized, (await me.GetAsync("/api/hello")).StatusCode);
        me.BearerToken = removed.Str("accessToken");
        Assert.Equal(HttpStatusCode.OK, (await me.GetAsync("/api/hello")).StatusCode);
    }

    [Fact]
    public async Task The_last_sign_in_method_cannot_be_removed()
    {
        await using var app = await TestApp.StartAsync(WithProvider());
        var browser = await SocialOnlyUserAsync(app);   // Google is the only way in

        var refused = await browser.PostJsonAsync("/auth/sign-in-methods/external/remove", new { provider = "Fake", providerKey = "google-1" }, HttpStatusCode.Conflict);

        Assert.Equal("last_sign_in_method", refused.Str("status"));
        Assert.NotNull(await Links(app).FindByExternalLoginAsync("Fake", "google-1", default));
    }

    [Fact]
    public async Task One_of_two_external_logins_can_be_removed_without_a_password()
    {
        await using var app = await TestApp.StartAsync(WithProvider());
        var browser = await SocialOnlyUserAsync(app);
        await Links(app).LinkExternalLoginAsync(app.Users.Get(SocialEmail).Id, "Other", "microsoft-1", default);

        await browser.PostJsonAsync("/auth/sign-in-methods/external/remove", new { provider = "Other", providerKey = "microsoft-1" });

        Assert.Null(await Links(app).FindByExternalLoginAsync("Other", "microsoft-1", default));
        await browser.PostJsonAsync("/auth/sign-in-methods/external/remove", new { provider = "Fake", providerKey = "google-1" }, HttpStatusCode.Conflict);
    }

    [Fact]
    public async Task Parallel_removals_never_remove_both_last_methods()
    {
        await using var app = await TestApp.StartAsync(WithProvider());
        var browser = await SocialOnlyUserAsync(app);
        await Links(app).LinkExternalLoginAsync(app.Users.Get(SocialEmail).Id, "Other", "microsoft-1", default);

        await Task.WhenAll(
            browser.PostAsync("/auth/sign-in-methods/external/remove", new { provider = "Fake", providerKey = "google-1" }),
            browser.PostAsync("/auth/sign-in-methods/external/remove", new { provider = "Other", providerKey = "microsoft-1" }));

        var remaining = await Links(app).GetExternalLoginsAsync(app.Users.Get(SocialEmail).Id, default);
        Assert.Single(remaining);
    }

    [Fact]
    public async Task Someone_elses_link_is_not_found()
    {
        await using var app = await TestApp.StartAsync(WithProvider());
        await Links(app).LinkExternalLoginAsync(app.Users.Get(TestApp.AdminEmail).Id, "Fake", "admins-google", default);
        var me = await PasswordUserAsync(app);

        await me.PostJsonAsync("/auth/sign-in-methods/external/remove",
            new { provider = "Fake", providerKey = "admins-google", password = TestApp.UserPassword }, HttpStatusCode.NotFound);
        Assert.NotNull(await Links(app).FindByExternalLoginAsync("Fake", "admins-google", default));
    }

    [Fact]
    public async Task Sign_in_methods_need_a_session_and_no_impersonation()
    {
        await using var app = await TestApp.StartAsync(WithProvider());
        Assert.Equal(HttpStatusCode.Unauthorized, (await app.CreateClient().GetAsync("/auth/sign-in-methods")).StatusCode);

        var admin = app.CreateClient();
        admin.BearerToken = (await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword)).AccessToken;
        var impersonation = await admin.PostJsonAsync($"/api/impersonate/{app.Users.Get(TestApp.UserEmail).Id}");
        var asUser = app.CreateClient();
        asUser.BearerToken = impersonation.Str("accessToken");
        await asUser.PostJsonAsync("/auth/sign-in-methods/external/remove", new { provider = "Fake", providerKey = "x", password = TestApp.UserPassword }, HttpStatusCode.Forbidden);
    }
}
