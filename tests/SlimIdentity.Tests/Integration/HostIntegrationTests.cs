using System.Diagnostics.Metrics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

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
        app.Time.Advance(TimeSpan.FromDays(30));   // the window follows the registered clock, not the system clock
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
    public async Task Password_confirmation_on_host_endpoints_counts_towards_the_lockout()
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
    public async Task A_session_is_never_elevated_to_another_account()
    {
        await using var app = await TestApp.StartAsync(HostSetup());
        var client = app.CreateClient();
        client.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;

        Assert.Equal("\"refused\"", await (await client.PostAsync("/api/sudo-wrong-user")).Content.ReadAsStringAsync());
    }

    /// <summary>A host that binds API keys to users ("personal access tokens" with a narrow scope).</summary>
    private sealed class PersonalApiKeys(ISlimUserStore users) : ISlimApiKeyStore
    {
        public static readonly (string Key, string Hash) Key = SlimApiKeys.Generate("pat");

        public async Task<IReadOnlyCollection<Claim>?> ValidateApiKeyAsync(string keyHash, CancellationToken ct) =>
            keyHash == Key.Hash
                ? [new Claim(SlimClaimTypes.UserId, (await users.FindByEmailAsync(TestApp.UserEmail, ct))!.Id), new Claim("scope", "reports:read")]
                : null;
    }

    [Theory]
    [InlineData("/auth/2fa/forget-all-devices")]
    [InlineData("/auth/logout-all")]
    [InlineData("/auth/2fa/setup")]
    public async Task An_api_key_cannot_act_as_the_user_on_the_account_endpoints(string path)
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions
        {
            Builder = b => b.AddApiKeyStore<PersonalApiKeys>(ServiceLifetime.Singleton),
        });

        var response = await app.CreateClient().SendAsync(HttpMethod.Post, path, new { },
            new Dictionary<string, string> { [SlimIdentityDefaults.ApiKeyHeaderName] = PersonalApiKeys.Key.Key });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);   // API keys are machine-to-machine, never a user session
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
        // unique per provider + key, like a unique index: a taken identity is never moved to another account
        if (!_links.TryAdd((provider, providerKey), userId) && _links[(provider, providerKey)] != userId)
            throw new InvalidOperationException("This external identity is already linked to another account.");
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
