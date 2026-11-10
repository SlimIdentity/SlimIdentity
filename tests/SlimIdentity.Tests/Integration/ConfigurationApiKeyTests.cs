using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>API keys from configuration (hashes, scopes, expiry) – a fixed set of machine clients without a database.</summary>
public sealed class ConfigurationApiKeyTests
{
    private static readonly (string Key, string Hash) Reports = SlimApiKeys.Generate("rpt");
    private static readonly (string Key, string Hash) Billing = SlimApiKeys.Generate("bil");

    private static IConfigurationRoot Config(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value))).Build();

    private static IConfigurationRoot TwoClients() => Config(
        ("ApiKeys:0:ClientId", "reports"), ("ApiKeys:0:Hash", Reports.Hash), ("ApiKeys:0:Scopes:0", "reports:read"),
        ("ApiKeys:1:ClientId", "billing"), ("ApiKeys:1:Hash", Billing.Hash.ToUpperInvariant()), ("ApiKeys:1:Roles:0", "Billing"),
        ("ApiKeys:1:ExpiresUtc", "2026-12-01T00:00:00Z"));

    private static TestAppOptions WithKeys(IConfiguration config) => new()
    {
        Builder = b => b.AddConfigurationApiKeys(config.GetSection("ApiKeys")),
        Map = app => app.MapGet("/api/m2m", (ClaimsPrincipal client) =>
                $"{client.GetSlimUserId()}|{string.Join(',', client.FindAll("scope").Select(c => c.Value))}|{client.IsInRole("Billing")}")
            .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = SlimIdentityDefaults.ApiKeyScheme }),
    };

    private static async Task<(HttpStatusCode Status, string Body)> CallAsync(TestApp app, string key)
    {
        var response = await app.CreateClient().SendWithHeaderAsync("/api/m2m", SlimIdentityDefaults.ApiKeyHeaderName, key);
        return (response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Configured_keys_authenticate_their_client_with_scopes_and_roles()
    {
        await using var app = await TestApp.StartAsync(WithKeys(TwoClients()));

        Assert.Equal((HttpStatusCode.OK, "client:reports|reports:read|False"), await CallAsync(app, Reports.Key));
        Assert.Equal((HttpStatusCode.OK, "client:billing||True"), await CallAsync(app, Billing.Key));   // hash case does not matter
        Assert.Equal(HttpStatusCode.Unauthorized, (await CallAsync(app, SlimApiKeys.Generate("rpt").Key)).Status);
    }

    [Fact]
    public async Task An_expired_key_is_rejected()
    {
        await using var app = await TestApp.StartAsync(WithKeys(TwoClients()));
        app.Time.SetUtcNow(new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero));
        Assert.Equal(HttpStatusCode.Unauthorized, (await CallAsync(app, Billing.Key)).Status);
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(app, Reports.Key)).Status);
    }

    [Fact]
    public async Task A_key_is_revoked_by_a_configuration_reload()
    {
        var config = TwoClients();
        await using var app = await TestApp.StartAsync(WithKeys(config));
        Assert.Equal(HttpStatusCode.OK, (await CallAsync(app, Reports.Key)).Status);

        config["ApiKeys:0:Hash"] = SlimApiKeys.Generate("rpt").Hash;   // rotated in the configuration
        config.Reload();

        Assert.Equal(HttpStatusCode.Unauthorized, (await CallAsync(app, Reports.Key)).Status);
    }

    [Fact]
    public async Task A_machine_to_machine_api_runs_without_users_mail_or_account_endpoints()
    {
        // production host that only protects its API with keys: no user store, no mail sender, no MapSlimIdentityApi
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Production" });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Services.AddSlimIdentity().AddConfigurationApiKeys(TwoClients().GetSection("ApiKeys"));

        await using var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/api/m2m", (ClaimsPrincipal client) => client.GetSlimUserId())
            .RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = SlimIdentityDefaults.ApiKeyScheme });
        await app.StartAsync();

        using var client = app.GetTestClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/m2m");
        request.Headers.Add(SlimIdentityDefaults.ApiKeyHeaderName, Reports.Key);
        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("client:reports", await response.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/m2m")).StatusCode);
    }

    [Theory]
    [InlineData("reports", "rpt_plain-key-pasted-instead-of-its-hash", "Hash")]   // the key itself must never be configured
    [InlineData("", "0000000000000000000000000000000000000000000000000000000000000000", "ClientId")]
    public async Task Invalid_entries_stop_the_start(string clientId, string hash, string expected)
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(() => TestApp.StartAsync(WithKeys(Config(("ApiKeys:0:ClientId", clientId), ("ApiKeys:0:Hash", hash)))));
        Assert.Contains(expected, error.ToString());
    }
}
