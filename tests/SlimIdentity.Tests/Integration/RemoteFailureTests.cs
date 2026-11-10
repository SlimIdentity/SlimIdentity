using System.Net;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// The user cancels at the provider ("Cancel" on Google's consent screen) or the provider's answer cannot be matched
/// (state lost, correlation cookie gone): the front end gets <c>?slim_error=…</c> at its returnUrl instead of an error
/// page. A real OAuth handler (ASP.NET Core's generic one) runs the protocol; the provider's answer is simulated.
/// </summary>
public sealed class RemoteFailureTests
{
    private const string ReturnUrl = "https://app.test.local/after-login";

    private static Task<TestApp> StartAsync(bool errorRedirects = true) => TestApp.StartAsync(new TestAppOptions
    {
        Builder = b =>
        {
            b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
            b.Authentication.AddOAuth("Corp", o =>
            {
                o.ClientId = "client";
                o.ClientSecret = "secret";
                o.AuthorizationEndpoint = "https://idp.test/authorize";
                o.TokenEndpoint = "https://idp.test/token";
                o.CallbackPath = "/signin-corp";
                if (errorRedirects) o.UseSlimErrorRedirects();
            });
        },
    });

    /// <summary>Starts the sign-in and returns the <c>state</c> the provider would send back.</summary>
    private static async Task<string> ChallengeAsync(ApiClient browser)
    {
        var challenge = await browser.GetAsync($"/auth/login/Corp?useCookies=true&returnUrl={Uri.EscapeDataString(ReturnUrl)}");
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        Assert.StartsWith("https://idp.test/authorize", challenge.Headers.Location!.OriginalString);
        return QueryHelpers.ParseQuery(challenge.Headers.Location.Query)["state"]!;
    }

    [Fact]
    public async Task Cancelling_at_the_provider_returns_to_the_front_end_with_access_denied()
    {
        await using var app = await StartAsync();
        var browser = app.CreateClient();
        var state = await ChallengeAsync(browser);

        var back = await browser.GetAsync($"/signin-corp?error=access_denied&state={Uri.EscapeDataString(state)}");

        Assert.Equal(HttpStatusCode.Redirect, back.StatusCode);
        Assert.Equal($"{ReturnUrl}?slim_error=access_denied", back.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task An_answer_without_a_valid_state_returns_to_the_default_page_with_external_login_failed()
    {
        await using var app = await StartAsync();

        var back = await app.CreateClient().GetAsync("/signin-corp?code=abc&state=forged");

        Assert.Equal(HttpStatusCode.Redirect, back.StatusCode);
        Assert.Equal("/?slim_error=external_login_failed", back.Headers.Location!.OriginalString);   // ExternalLogin.DefaultReturnUrl
    }

    [Fact]
    public async Task Without_the_redirects_a_cancellation_ends_on_an_error_page()
    {
        // what UseSlimErrorRedirects() prevents: the framework throws, the host's exception handler answers
        await using var app = await StartAsync(errorRedirects: false);
        var browser = app.CreateClient();
        var state = await ChallengeAsync(browser);

        await Assert.ThrowsAnyAsync<Exception>(() => browser.GetAsync($"/signin-corp?error=access_denied&state={Uri.EscapeDataString(state)}"));
    }
}
