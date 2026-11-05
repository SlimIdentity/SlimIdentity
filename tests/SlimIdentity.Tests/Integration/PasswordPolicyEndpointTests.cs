using System.Net;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

public sealed class PasswordPolicyEndpointTests
{
    private sealed class AnyRule : ISlimPasswordRule
    {
        public Task<IReadOnlyList<string>> ValidateAsync(string password, string email, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<string>>([]);
    }

    [Fact]
    public async Task Policy_reflects_the_configured_options_anonymously()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions
        {
            Configure = o => { o.Password.MinimumLength = 16; o.Password.RequireUppercase = false; o.Password.RequireNonAlphanumeric = true; },
        });

        var response = await app.CreateClient().GetAsync("/auth/password-policy");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var policy = System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

        Assert.Equal(16, policy.GetProperty("minimumLength").GetInt32());
        Assert.Equal(256, policy.GetProperty("maximumLength").GetInt32());
        Assert.True(policy.GetProperty("requireDigit").GetBoolean());
        Assert.False(policy.GetProperty("requireUppercase").GetBoolean());
        Assert.True(policy.GetProperty("requireNonAlphanumeric").GetBoolean());
        Assert.False(policy.GetProperty("hasAdditionalRules").GetBoolean());
    }

    [Fact]
    public async Task Policy_reports_additional_server_side_rules()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Builder = b => b.AddPasswordRule<AnyRule>() });

        var policy = System.Text.Json.JsonDocument.Parse(await (await app.CreateClient().GetAsync("/auth/password-policy")).Content.ReadAsStringAsync()).RootElement;

        Assert.True(policy.GetProperty("hasAdditionalRules").GetBoolean());
    }

    [Fact]
    public async Task Policy_endpoint_can_be_disabled()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Configure = o => o.Endpoints.EnablePasswordPolicy = false });
        Assert.Equal(HttpStatusCode.NotFound, (await app.CreateClient().GetAsync("/auth/password-policy")).StatusCode);
    }
}
