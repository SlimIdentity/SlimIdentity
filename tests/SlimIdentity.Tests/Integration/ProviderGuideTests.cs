using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// The provider guide (docs/guides/google-and-entra-id.md) in code: Google answers whether it verified the address,
/// but the ASP.NET Core handler drops that field unless it is mapped – then SlimIdentity can rely on it instead of
/// trusting the provider blindly.
/// </summary>
public sealed class ProviderGuideTests
{
    /// <summary>What Google's userinfo endpoint (v3) answers, through the handler's claim actions as the guide configures them.</summary>
    private static ClaimsIdentity GoogleIdentity(bool verified, bool mapped)
    {
        var options = new GoogleOptions();
        if (mapped) options.ClaimActions.MapJsonKey("email_verified", "email_verified");   // the line of the guide
        var userinfo = JsonDocument.Parse($$"""
            { "sub": "1098", "name": "Ada", "email": "ada@gmail.test", "email_verified": {{(verified ? "true" : "false")}} }
            """).RootElement;
        var identity = new ClaimsIdentity("Google");
        foreach (var action in options.ClaimActions) action.Run(userinfo, identity, "https://accounts.google.com");
        return identity;
    }

    [Fact]
    public void The_google_handler_passes_the_verification_on_only_when_it_is_mapped()
    {
        Assert.Null(GoogleIdentity(verified: true, mapped: false).FindFirst("email_verified"));
        Assert.Equal("True", GoogleIdentity(verified: true, mapped: true).FindFirst("email_verified")?.Value);
        Assert.Equal("False", GoogleIdentity(verified: false, mapped: true).FindFirst("email_verified")?.Value);
    }

    [Theory]
    [InlineData(true, null)]
    [InlineData(false, "email_not_verified")]
    public async Task A_new_account_is_created_only_for_an_address_google_verified(bool verified, string? error)
    {
        var claims = GoogleIdentity(verified, mapped: true).Claims.ToArray();
        await using var app = await TestApp.StartAsync(new TestAppOptions
        {
            // no TrustedEmailProviders: the decision comes from Google's own answer
            Builder = b =>
            {
                b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
                b.Authentication.AddScheme<FakeOAuthOptions, FakeOAuthHandler>("Google", o => o.Claims = [.. claims]);
            },
        });
        var browser = app.CreateClient();

        var challenge = await browser.GetAsync("/auth/login/Google?useCookies=true&returnUrl=/done");
        var callback = await browser.GetAsync(challenge.Headers.Location!.OriginalString);

        var location = callback.Headers.Location!.OriginalString;
        if (error is null)
        {
            Assert.Equal("/done", location);
            Assert.True(app.Users.Get("ada@gmail.test").EmailConfirmed);
        }
        else
        {
            Assert.Equal($"/done?slim_error={error}", location);
        }
    }
}
