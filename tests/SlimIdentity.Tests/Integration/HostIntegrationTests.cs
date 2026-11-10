using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

public sealed class ExternalLoginTests
{
    private static TestAppOptions WithProvider(params Claim[] claims) => WithProvider(refreshTokens: true, claims);

    private static TestAppOptions WithProvider(bool refreshTokens, params Claim[] claims) => new()
    {
        RefreshTokens = refreshTokens,
        Builder = b =>
        {
            b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
            b.Authentication.AddScheme<FakeOAuthOptions, FakeOAuthHandler>("Fake", o => o.Claims = [.. claims]);
        },
    };

    /// <summary>Browser navigation: /auth/login/Fake → provider → callback → returnUrl.</summary>
    private static async Task<Uri> NavigateAsync(ApiClient browser, string query)
    {
        var challenge = await browser.GetAsync($"/auth/login/Fake?{query}");
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        var callback = await browser.GetAsync(challenge.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        return new Uri(new Uri("https://localhost"), callback.Headers.Location!);
    }

    [Fact]
    public async Task New_external_user_is_created_and_bearer_clients_exchange_a_one_time_code()
    {
        await using var app = await TestApp.StartAsync(WithProvider(
            new Claim(ClaimTypes.NameIdentifier, "ext-123"), new Claim(ClaimTypes.Email, "social@test.local"), new Claim("email_verified", "true")));
        var browser = app.CreateClient();

        var (verifier, challenge) = ReviewRound1Tests.Pkce();
        var target = await NavigateAsync(browser, $"useCookies=false&returnUrl=/done&code_challenge={challenge}");
        Assert.Equal("/done", target.AbsolutePath);
        var code = QueryHelpers.ParseQuery(target.Fragment.TrimStart('#'))["code"].ToString();
        Assert.DoesNotContain("accessToken", target.ToString());   // tokens never travel in URLs

        var tokens = await app.CreateClient().PostJsonAsync("/auth/login/external/exchange", new { code, codeVerifier = verifier });
        Assert.False(string.IsNullOrEmpty(tokens.Str("accessToken")));
        Assert.True(app.Users.Get("social@test.local").EmailConfirmed);
    }

    [Theory]
    [InlineData(true)]    // consumed atomically via ISlimRefreshTokenStore
    [InlineData(false)]   // in-memory fallback
    public async Task The_exchange_code_works_only_once(bool refreshTokens)
    {
        await using var app = await TestApp.StartAsync(WithProvider(refreshTokens,
            new Claim(ClaimTypes.NameIdentifier, "ext-123"), new Claim(ClaimTypes.Email, "social@test.local"), new Claim("email_verified", "true")));

        var (verifier, challenge) = ReviewRound1Tests.Pkce();
        var target = await NavigateAsync(app.CreateClient(), $"useCookies=false&returnUrl=/done&code_challenge={challenge}");
        var code = QueryHelpers.ParseQuery(target.Fragment.TrimStart('#'))["code"].ToString();

        await app.CreateClient().PostJsonAsync("/auth/login/external/exchange", new { code, codeVerifier = verifier });
        await app.CreateClient().PostJsonAsync("/auth/login/external/exchange", new { code, codeVerifier = verifier }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Unverified_email_of_an_existing_account_is_not_linked()
    {
        await using var app = await TestApp.StartAsync(WithProvider(
            new Claim(ClaimTypes.NameIdentifier, "ext-attacker"), new Claim(ClaimTypes.Email, TestApp.UserEmail)));

        var target = await NavigateAsync(app.CreateClient(), "useCookies=true&returnUrl=/done");

        Assert.Equal("account_conflict", QueryHelpers.ParseQuery(target.Query)["slim_error"].ToString());
    }

    [Fact]
    public async Task Verified_email_is_linked_to_an_account_without_password_and_cookie_mode_sets_the_session_cookie()
    {
        // only accounts without an own password are joined automatically (see ExternalLinkTests for the others)
        await using var app = await TestApp.StartAsync(WithProvider(
            new Claim(ClaimTypes.NameIdentifier, "ext-user"), new Claim(ClaimTypes.Email, "no-password@test.local"), new Claim("email_verified", "true")));
        app.Users.Seed("no-password@test.local", password: null);
        var browser = app.CreateClient();

        var target = await NavigateAsync(browser, "useCookies=true&returnUrl=/done");

        Assert.Equal("/done", target.AbsolutePath);
        Assert.True(browser.Cookies.ContainsKey("SlimAuth"));
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/hello")).StatusCode);
    }

    [Fact]
    public async Task Pre_registered_unverified_account_is_taken_over_by_the_verified_owner_not_shared()
    {
        // Attack scenario E8 (pre-account hijacking): the attacker registers the victim's address with an own password
        // before the victim ever signs up. The victim later signs in with a provider that has verified the address.
        const string victim = "victim@test.local";
        await using var app = await TestApp.StartAsync(WithProvider(
            new Claim(ClaimTypes.NameIdentifier, "google-victim"), new Claim(ClaimTypes.Email, victim), new Claim("email_verified", "true")));

        await app.CreateClient().PostJsonAsync("/auth/register", new { email = victim, password = "Attacker-Pass-123" });
        var attacker = await app.LoginBearerAsync(victim, "Attacker-Pass-123");   // unconfirmed accounts can sign in by default

        var browser = app.CreateClient();
        await NavigateAsync(browser, "useCookies=true&returnUrl=/done");
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/hello")).StatusCode);   // the victim is in

        var attackerClient = app.CreateClient();
        attackerClient.BearerToken = attacker.AccessToken;
        Assert.Equal(HttpStatusCode.Unauthorized, (await attackerClient.GetAsync("/api/hello")).StatusCode);   // running session ended
        await app.CreateClient().PostJsonAsync("/auth/login", new { email = victim, password = "Attacker-Pass-123" }, HttpStatusCode.Unauthorized);
        await app.CreateClient().PostJsonAsync("/auth/refresh", new { refreshToken = attacker.RefreshToken }, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Linking_a_confirmed_account_keeps_its_password()
    {
        await using var app = await TestApp.StartAsync(WithProvider(
            new Claim(ClaimTypes.NameIdentifier, "ext-user"), new Claim(ClaimTypes.Email, TestApp.UserEmail), new Claim("email_verified", "true")));
        await NavigateAsync(app.CreateClient(), "useCookies=true&returnUrl=/done");
        await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
    }

    [Fact]
    public async Task Foreign_return_urls_are_rejected()
    {
        await using var app = await TestApp.StartAsync(WithProvider(new Claim(ClaimTypes.NameIdentifier, "x")));
        var response = await app.CreateClient().GetAsync("/auth/login/Fake?returnUrl=https://evil.example/");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}

public sealed class HostEndpointTests
{
    private sealed class TestApiKeyStore : ISlimApiKeyStore
    {
        public static readonly (string Key, string Hash) Key = SlimApiKeys.Generate("test");

        public Task<IReadOnlyCollection<Claim>?> ValidateApiKeyAsync(string keyHash, CancellationToken ct) =>
            Task.FromResult<IReadOnlyCollection<Claim>?>(keyHash == Key.Hash ? [new Claim(SlimClaimTypes.UserId, "client:reports")] : null);
    }

    private sealed record SudoRequest(string Password);

    private static TestAppOptions HostSetup() => new()
    {
        Builder = b => b.AddApiKeyStore<TestApiKeyStore>(ServiceLifetime.Singleton),
        Map = app =>
        {
            app.MapGet("/api/m2m", (ClaimsPrincipal client) => client.GetSlimUserId())
                .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = SlimIdentityDefaults.ApiKeyScheme });

            app.MapPost("/api/action", () => "done").RequireAuthorization().RequireSlimCsrf();

            app.MapPost("/api/sudo", async (SudoRequest req, ClaimsPrincipal me, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
                {
                    var user = await store.FindByIdAsync(me.GetSlimUserId()!, ct);
                    if (user is null) return Results.Unauthorized();
                    if (await auth.ConfirmPasswordAsync(user, req.Password, ct) is { } failure) return failure;   // lockout like the built-in endpoints
                    var result = await auth.ElevateToSudoAsync(user, TimeSpan.FromMinutes(5), ct);
                    return Results.Ok(result.ToResponse());
                })
                .RequireAuthorization();

            // a host bug: elevating someone else than the signed-in user
            app.MapPost("/api/sudo-wrong-user", async (ClaimsPrincipal me, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
                {
                    var other = (await store.FindByEmailAsync(TestApp.AdminEmail, ct))!;
                    try
                    {
                        await auth.ElevateToSudoAsync(other, TimeSpan.FromMinutes(5), ct);
                        return Results.Ok("elevated");
                    }
                    catch (InvalidOperationException) { return Results.Ok("refused"); }
                })
                .RequireAuthorization();

            app.MapDelete("/api/danger", () => "deleted").RequireAuthorization(SlimIdentityDefaults.SudoPolicy);
        },
    };

    [Fact]
    public async Task Api_key_authenticates_machine_clients()
    {
        await using var app = await TestApp.StartAsync(HostSetup());

        var valid = await app.CreateClient().SendWithHeaderAsync("/api/m2m", SlimIdentityDefaults.ApiKeyHeaderName, TestApiKeyStore.Key.Key);
        Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
        Assert.Equal("client:reports", await valid.Content.ReadAsStringAsync());

        var invalid = await app.CreateClient().SendWithHeaderAsync("/api/m2m", SlimIdentityDefaults.ApiKeyHeaderName, "test_wrong");
        Assert.Equal(HttpStatusCode.Unauthorized, invalid.StatusCode);
    }

    [Fact]
    public async Task RequireSlimCsrf_protects_host_endpoints_in_cookie_mode()
    {
        await using var app = await TestApp.StartAsync(HostSetup());
        var browser = app.CreateClient();
        browser.SendCsrfHeader = true;
        await browser.PostAsync("/auth/login?useCookies=true", new { email = TestApp.UserEmail, password = TestApp.UserPassword });

        browser.SendCsrfHeader = false;
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.PostAsync("/api/action")).StatusCode);
        browser.SendCsrfHeader = true;
        Assert.Equal(HttpStatusCode.OK, (await browser.PostAsync("/api/action")).StatusCode);
    }

    [Fact]
    public async Task Sudo_policy_requires_an_elevated_session_that_expires()
    {
        await using var app = await TestApp.StartAsync(HostSetup());
        var tokens = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var client = app.CreateClient();
        client.BearerToken = tokens.AccessToken;

        Assert.Equal(HttpStatusCode.Forbidden, (await client.DeleteAsync("/api/danger")).StatusCode);

        var elevated = await client.PostJsonAsync("/api/sudo", new { password = TestApp.UserPassword });
        client.BearerToken = elevated.Str("accessToken");
        Assert.Equal(HttpStatusCode.OK, (await client.DeleteAsync("/api/danger")).StatusCode);

        app.Time.Advance(TimeSpan.FromMinutes(6));
        Assert.Equal(HttpStatusCode.Forbidden, (await client.DeleteAsync("/api/danger")).StatusCode);
    }

    [Fact]
    public async Task R7_password_confirmation_on_host_endpoints_counts_towards_the_lockout()
    {
        await using var app = await TestApp.StartAsync(HostSetup());
        var client = app.CreateClient();
        client.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;

        // a stolen session guesses the password on the host's sudo endpoint
        for (var i = 0; i < 4; i++)
            await client.PostJsonAsync("/api/sudo", new { password = $"guess-{i}" }, HttpStatusCode.BadRequest);
        await client.PostJsonAsync("/api/sudo", new { password = "guess-4" }, (HttpStatusCode)423);

        await app.Mail.WaitForAsync("lockout", TestApp.UserEmail);
        await client.PostJsonAsync("/api/sudo", new { password = TestApp.UserPassword }, (HttpStatusCode)423);   // even the right one
    }

    [Fact]
    public async Task Q3_a_session_is_never_elevated_to_another_account()
    {
        await using var app = await TestApp.StartAsync(HostSetup());
        var client = app.CreateClient();
        client.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;

        Assert.Equal("\"refused\"", await (await client.PostAsync("/api/sudo-wrong-user")).Content.ReadAsStringAsync());
    }
}

public sealed class MetricsTests
{
    [Fact]
    public async Task Sign_in_attempts_are_counted_without_personal_data()
    {
        await using var app = await TestApp.StartAsync();
        var factory = app.App.Services.GetRequiredService<IMeterFactory>();
        var measurements = new List<(string Instrument, long Value, Dictionary<string, object?> Tags)>();

        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (instrument.Meter.Name == SlimIdentityDefaults.MeterName && ReferenceEquals(instrument.Meter.Scope, factory))
                l.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
        {
            lock (measurements) measurements.Add((instrument.Name, value, tags.ToArray().ToDictionary(t => t.Key, t => t.Value)));
        });
        listener.Start();

        var client = app.CreateClient();
        await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = "wrong" });
        await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword });

        var logins = measurements.Where(m => m.Instrument == "slimidentity.logins").ToList();
        Assert.Contains(logins, m => (string?)m.Tags["result"] == "invalid_password" && (string?)m.Tags["mode"] == "bearer");
        Assert.Contains(logins, m => (string?)m.Tags["result"] == "success");
        Assert.DoesNotContain(measurements.SelectMany(m => m.Tags.Values), v => v is string s && s.Contains('@'));
    }
}

/// <summary>External-login store for the tests.</summary>
public sealed class TestExternalLoginStore(ISlimUserStore users) : ISlimExternalLoginStore
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<(string, string), string> _links = new();

    public async Task<SlimUser?> FindByExternalLoginAsync(string provider, string providerKey, CancellationToken ct) =>
        _links.TryGetValue((provider, providerKey), out var id) ? await users.FindByIdAsync(id, ct) : null;

    public Task LinkExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct)
    {
        _links[(provider, providerKey)] = userId;
        return Task.CompletedTask;
    }

    public Task RemoveExternalLoginsAsync(string userId, CancellationToken ct)
    {
        foreach (var link in _links.Where(l => l.Value == userId).ToList()) _links.TryRemove(link.Key, out _);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<SlimExternalLogin>> GetExternalLoginsAsync(string userId, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<SlimExternalLogin>>(_links.Where(l => l.Value == userId)
            .Select(l => new SlimExternalLogin(l.Key.Item1, l.Key.Item2))
            .OrderBy(l => l.Provider, StringComparer.Ordinal).ThenBy(l => l.ProviderKey, StringComparer.Ordinal).ToList());

    public Task<bool> RemoveExternalLoginAsync(string userId, string provider, string providerKey, CancellationToken ct) =>
        Task.FromResult(((ICollection<KeyValuePair<(string, string), string>>)_links)
            .Remove(new KeyValuePair<(string, string), string>((provider, providerKey), userId)));
}

internal static class ApiClientExtensions
{
    public static Task<HttpResponseMessage> SendWithHeaderAsync(this ApiClient client, string path, string header, string value) =>
        client.SendAsync(HttpMethod.Get, path, null, new Dictionary<string, string> { [header] = value });
}
