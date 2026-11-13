using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// Linking an external login to the signed-in account (accounts with a password are never joined automatically):
/// start with PKCE, the provider round trip returns a one-time link code in the fragment, the signed-in client redeems
/// it with the verifier – and its password.
/// </summary>
public sealed class ExternalLinkTests
{
    private static TestAppOptions WithProviders() => new()
    {
        Builder = b =>
        {
            b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
            b.Authentication.AddScheme<FakeOAuthOptions, FakeOAuthHandler>("Fake", o => o.Claims =
                [new Claim(ClaimTypes.NameIdentifier, "google-user"), new Claim(ClaimTypes.Email, TestApp.UserEmail), new Claim("email_verified", "true")]);
            b.Authentication.AddScheme<FakeOAuthOptions, FakeOAuthHandler>("Other", o => o.Claims =
                [new Claim(ClaimTypes.NameIdentifier, "other-user"), new Claim(ClaimTypes.Email, "elsewhere@test.local"), new Claim("email_verified", "true")]);
        },
    };

    /// <summary>Starts the link flow like the TypeScript client and returns the link code from the fragment.</summary>
    private static async Task<(string Code, string Verifier)> LinkCodeAsync(TestApp app, string provider = "Fake")
    {
        var (verifier, challenge) = ReviewRound1Tests.Pkce();
        var browser = app.CreateClient();
        var start = await browser.GetAsync($"/auth/login/{provider}?link=true&returnUrl=/settings&code_challenge={challenge}&code_challenge_method=S256");
        var callback = await browser.GetAsync(start.Headers.Location!.OriginalString);
        var target = new Uri(new Uri("https://localhost"), callback.Headers.Location!);
        Assert.DoesNotContain("slim_link_code", target.Query);   // fragment only
        return (QueryHelpers.ParseQuery(target.Fragment.TrimStart('#'))["slim_link_code"].ToString(), verifier);
    }

    private static async Task<ApiClient> SignedInAsync(TestApp app)
    {
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        return me;
    }

    private static async Task<HttpStatusCode> SocialSignInAsync(TestApp app)
    {
        var browser = app.CreateClient();
        var start = await browser.GetAsync("/auth/login/Fake?useCookies=true&returnUrl=/done");
        await browser.GetAsync(start.Headers.Location!.OriginalString);
        return (await browser.GetAsync("/api/hello")).StatusCode;
    }

    [Fact]
    public async Task An_account_with_a_password_is_not_joined_automatically_but_can_link_while_signed_in()
    {
        await using var app = await TestApp.StartAsync(WithProviders());
        Assert.Equal(HttpStatusCode.Unauthorized, await SocialSignInAsync(app));   // account_conflict, no session

        var me = await SignedInAsync(app);
        var (code, verifier) = await LinkCodeAsync(app);
        var linked = await me.PostJsonAsync("/auth/link/external", new { code, codeVerifier = verifier, password = TestApp.UserPassword });

        Assert.Equal("external_login_linked", linked.Str("status"));
        Assert.Equal(HttpStatusCode.OK, await SocialSignInAsync(app));              // from now on Google signs in
    }

    [Fact]
    public async Task The_link_code_needs_the_verifier_the_session_and_the_password()
    {
        await using var app = await TestApp.StartAsync(WithProviders());
        var me = await SignedInAsync(app);

        var (code, verifier) = await LinkCodeAsync(app);
        await app.CreateClient().PostJsonAsync("/auth/link/external", new { code, codeVerifier = verifier, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);
        await me.PostJsonAsync("/auth/link/external", new { code, codeVerifier = ReviewRound1Tests.Pkce().Verifier, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);
        await me.PostJsonAsync("/auth/link/external", new { code, codeVerifier = verifier, password = "wrong" }, HttpStatusCode.BadRequest);
        await me.PostJsonAsync("/auth/link/external", new { code, codeVerifier = verifier, password = TestApp.UserPassword });
        await me.PostJsonAsync("/auth/link/external", new { code, codeVerifier = verifier, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);   // single use
    }

    [Fact]
    public async Task An_attackers_link_code_cannot_be_planted_in_the_victims_session()
    {
        // link CSRF: the attacker runs the flow with an own provider account and lures the victim's app to the
        // redirect – the victim's app redeems it with its own verifier, which does not match
        await using var app = await TestApp.StartAsync(WithProviders());
        var (attackersCode, _) = await LinkCodeAsync(app, "Other");
        var victim = await SignedInAsync(app);
        var victimsVerifier = ReviewRound1Tests.Pkce().Verifier;

        await victim.PostJsonAsync("/auth/link/external", new { code = attackersCode, codeVerifier = victimsVerifier, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);
        var links = app.App.Services.GetRequiredService<ISlimExternalLoginStore>();
        Assert.Null(await links.FindByExternalLoginAsync("Other", "other-user", default));
    }

    [Fact]
    public async Task An_identity_linked_to_another_account_is_not_moved()
    {
        await using var app = await TestApp.StartAsync(WithProviders());
        var links = app.App.Services.GetRequiredService<ISlimExternalLoginStore>();
        await links.LinkExternalLoginAsync(app.Users.Get(TestApp.AdminEmail).Id, "Fake", "google-user", default);

        var me = await SignedInAsync(app);
        var (code, verifier) = await LinkCodeAsync(app);
        var taken = await me.PostJsonAsync("/auth/link/external", new { code, codeVerifier = verifier, password = TestApp.UserPassword }, HttpStatusCode.Conflict);

        Assert.Equal("external_login_taken", taken.Str("code"));
        Assert.Equal(app.Users.Get(TestApp.AdminEmail).Id, (await links.FindByExternalLoginAsync("Fake", "google-user", default))!.Id);
    }

    [Fact]
    public async Task The_link_flow_requires_pkce()
    {
        await using var app = await TestApp.StartAsync(WithProviders());
        var start = await app.CreateClient().GetAsync("/auth/login/Fake?link=true&returnUrl=/settings");
        Assert.Equal(HttpStatusCode.BadRequest, start.StatusCode);
    }

    [Fact]
    public async Task An_account_without_a_password_links_without_one()
    {
        await using var app = await TestApp.StartAsync(WithProviders());
        // created by the "Other" provider: no password
        var browser = app.CreateClient();
        var (exchangeVerifier, exchangeChallenge) = ReviewRound1Tests.Pkce();
        var login = await browser.GetAsync($"/auth/login/Other?useCookies=false&returnUrl=/done&code_challenge={exchangeChallenge}&code_challenge_method=S256");
        var callback = await browser.GetAsync(login.Headers.Location!.OriginalString);
        var exchangeCode = QueryHelpers.ParseQuery(new Uri(new Uri("https://localhost"), callback.Headers.Location!).Fragment.TrimStart('#'))["code"].ToString();
        var tokens = await app.CreateClient().PostJsonAsync("/auth/login/external/exchange", new { code = exchangeCode, codeVerifier = exchangeVerifier });
        var me = app.CreateClient();
        me.BearerToken = tokens.Str("accessToken");

        var (code, verifier) = await LinkCodeAsync(app);
        await me.PostJsonAsync("/auth/link/external", new { code, codeVerifier = verifier });

        var links = app.App.Services.GetRequiredService<ISlimExternalLoginStore>();
        Assert.Equal(app.Users.Get("elsewhere@test.local").Id, (await links.FindByExternalLoginAsync("Fake", "google-user", default))!.Id);
    }
}
