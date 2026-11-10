using System.Net;
using System.Security.Cryptography;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// OpenID Connect Back-Channel Logout 1.0: the identity provider posts a signed logout token when it signs a user out
/// (or blocks them) – the user's sessions here end.
/// </summary>
public sealed class BackChannelLogoutTests
{
    private const string Issuer = "https://idp.test/realms/corp";
    private const string ClientId = "slim-app";
    private const string Event = "http://schemas.openid.net/event/backchannel-logout";

    private static readonly RsaSecurityKey IdpKey = new(RSA.Create(2048)) { KeyId = "idp-key-1" };
    private static readonly RsaSecurityKey ForeignKey = new(RSA.Create(2048)) { KeyId = "idp-key-1" };

    private static TestAppOptions WithIdp(bool cookieDefault = false) => new()
    {
        Builder = b =>
        {
            b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
            b.AddBackChannelLogout("Corp", o =>
            {
                o.ClientId = ClientId;
                o.Configuration = new OpenIdConnectConfiguration { Issuer = Issuer };
                o.Configuration.SigningKeys.Add(IdpKey);
            });
        },
        Configure = o => { if (cookieDefault) o.Endpoints.DefaultUseCookies = true; },
    };

    private static string LogoutToken(TestApp app, Action<Dictionary<string, object>>? change = null, SecurityKey? key = null,
        string sub = "corp-sub-1", string issuer = Issuer, string audience = ClientId)
    {
        var claims = new Dictionary<string, object>
        {
            ["sub"] = sub,
            ["sid"] = "idp-session-42",
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["iat"] = app.Time.GetUtcNow().ToUnixTimeSeconds(),
            ["exp"] = app.Time.GetUtcNow().AddMinutes(2).ToUnixTimeSeconds(),
            ["events"] = new Dictionary<string, object> { [Event] = new Dictionary<string, object>() },
        };
        change?.Invoke(claims);
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Claims = claims,
            TokenType = "logout+jwt",
            SigningCredentials = new SigningCredentials(key ?? IdpKey, SecurityAlgorithms.RsaSha256),
        });
    }

    private static Task<HttpResponseMessage> PostAsync(TestApp app, string token, string provider = "Corp") =>
        app.CreateClient().SendRawAsync($"/auth/backchannel-logout/{provider}", $"logout_token={Uri.EscapeDataString(token)}", "application/x-www-form-urlencoded");

    private static async Task<(ApiClient User, ApiClient Admin)> SignedInAsync(TestApp app)
    {
        var links = app.App.Services.GetRequiredService<ISlimExternalLoginStore>();
        await links.LinkExternalLoginAsync(app.Users.Get(TestApp.UserEmail).Id, "Corp", "corp-sub-1", default);
        var user = app.CreateClient();
        user.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        var admin = app.CreateClient();
        admin.BearerToken = (await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword)).AccessToken;
        return (user, admin);
    }

    [Fact]
    public async Task A_valid_logout_token_ends_the_users_sessions()
    {
        await using var app = await TestApp.StartAsync(WithIdp());
        var (user, admin) = await SignedInAsync(app);

        var response = await PostAsync(app, LogoutToken(app));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.Equal(HttpStatusCode.Unauthorized, (await user.GetAsync("/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync("/auth/me")).StatusCode);   // nobody else
    }

    [Fact]
    public async Task No_anti_forgery_header_is_needed_even_with_cookie_default()
    {
        // the provider posts a plain form – in cookie mode it must not trip the anti-forgery check
        await using var app = await TestApp.StartAsync(WithIdp(cookieDefault: true));
        var links = app.App.Services.GetRequiredService<ISlimExternalLoginStore>();
        await links.LinkExternalLoginAsync(app.Users.Get(TestApp.UserEmail).Id, "Corp", "corp-sub-1", default);
        var stampBefore = app.Users.Get(TestApp.UserEmail).SecurityStamp;

        Assert.Equal(HttpStatusCode.OK, (await PostAsync(app, LogoutToken(app))).StatusCode);
        Assert.NotEqual(stampBefore, app.Users.Get(TestApp.UserEmail).SecurityStamp);
    }

    /// <summary>Review round 4: jti is required – without it the single-use check could not apply.</summary>
    [Fact]
    public async Task A_logout_token_without_jti_is_rejected()
    {
        await using var app = await TestApp.StartAsync(WithIdp());
        var (user, _) = await SignedInAsync(app);

        var response = await PostAsync(app, LogoutToken(app, c => c.Remove("jti")));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task An_unknown_subject_is_acknowledged_without_effect()
    {
        await using var app = await TestApp.StartAsync(WithIdp());
        var (user, _) = await SignedInAsync(app);
        Assert.Equal(HttpStatusCode.OK, (await PostAsync(app, LogoutToken(app, sub: "someone-else"))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/auth/me")).StatusCode);
    }

    public static TheoryData<string> Forgeries => new()
    {
        "foreign key", "wrong audience", "wrong issuer", "no event", "nonce", "no sub", "issued long ago", "expired",
    };

    [Theory]
    [MemberData(nameof(Forgeries))]
    public async Task Forged_or_unfit_tokens_are_rejected(string forgery)
    {
        await using var app = await TestApp.StartAsync(WithIdp());
        var (user, _) = await SignedInAsync(app);
        var now = app.Time.GetUtcNow();

        var token = forgery switch
        {
            "foreign key" => LogoutToken(app, key: ForeignKey),
            "wrong audience" => LogoutToken(app, audience: "another-app"),
            "wrong issuer" => LogoutToken(app, issuer: "https://evil.test"),
            "no event" => LogoutToken(app, c => c.Remove("events")),
            "nonce" => LogoutToken(app, c => c["nonce"] = "abc"),          // an ID token, not a logout token
            "no sub" => LogoutToken(app, c => c.Remove("sub")),            // sid-only tokens are not supported
            "issued long ago" => LogoutToken(app, c => { c["iat"] = now.AddMinutes(-30).ToUnixTimeSeconds(); c.Remove("exp"); }),
            _ => LogoutToken(app, c => c["exp"] = now.AddMinutes(-5).ToUnixTimeSeconds()),
        };

        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync(app, token)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await user.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task A_replayed_token_is_rejected()
    {
        // a replay would sign the user out again – including sessions started after the logout
        await using var app = await TestApp.StartAsync(WithIdp());
        await SignedInAsync(app);
        var token = LogoutToken(app);
        Assert.Equal(HttpStatusCode.OK, (await PostAsync(app, token)).StatusCode);

        var again = app.CreateClient();
        again.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync(app, token)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await again.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task Only_configured_providers_and_form_posts_are_accepted()
    {
        await using var app = await TestApp.StartAsync(WithIdp());
        Assert.Equal(HttpStatusCode.NotFound, (await PostAsync(app, LogoutToken(app), "Other")).StatusCode);
        var json = await app.CreateClient().SendRawAsync("/auth/backchannel-logout/Corp", "{\"logout_token\":\"x\"}", "application/json");
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, json.StatusCode);
    }

    [Fact]
    public async Task Without_configuration_the_endpoint_does_not_exist()
    {
        await using var app = await TestApp.StartAsync();
        var response = await app.CreateClient().SendRawAsync("/auth/backchannel-logout/Corp", "logout_token=x", "application/x-www-form-urlencoded");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
