using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// API details that are hard to get right in host code and would be breaking to change after 1.0 (review round 3:
/// clocks, error shapes, users created outside SlimIdentity).
/// </summary>
public sealed class PreReleaseApiTests
{
    private static TestAppOptions WithHostEndpoints() => new()
    {
        Map = app =>
        {
            app.MapPost("/api/session", async (ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
                Results.Ok((await auth.SignInAsync((await store.FindByEmailAsync(TestApp.UserEmail, ct))!, useCookies: false, ct: ct)).ToResponse()));

            app.MapPost("/api/sudo", async (ClaimsPrincipal me, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
                {
                    var user = (await store.FindByIdAsync(me.GetSlimUserId()!, ct))!;
                    return Results.Ok((await auth.ElevateToSudoAsync(user, TimeSpan.FromMinutes(5), ct)).ToResponse());
                })
                .RequireAuthorization();

            app.MapDelete("/api/danger", () => "deleted").RequireAuthorization(SlimIdentityDefaults.SudoPolicy);
        },
    };

    [Fact]
    public async Task The_token_lifetime_of_a_host_sign_in_follows_the_registered_clock()
    {
        await using var app = await TestApp.StartAsync(WithHostEndpoints());
        app.Time.Advance(TimeSpan.FromDays(30));   // the registered clock is far from the system clock

        var session = await app.CreateClient().PostJsonAsync("/api/session");

        Assert.Equal((int)TimeSpan.FromMinutes(15).TotalSeconds, session.GetProperty("expiresIn").GetInt32());

        // and the token expires on that clock, too – not on the system clock
        var client = app.CreateClient();
        client.BearerToken = session.Str("accessToken");
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/me")).StatusCode);
        app.Time.Advance(TimeSpan.FromMinutes(16));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public async Task A_sudo_window_follows_the_registered_clock()
    {
        await using var app = await TestApp.StartAsync(WithHostEndpoints());
        app.Time.Advance(TimeSpan.FromDays(30));
        var client = app.CreateClient();
        client.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;

        client.BearerToken = (await client.PostJsonAsync("/api/sudo")).Str("accessToken");

        Assert.Equal(HttpStatusCode.OK, (await client.DeleteAsync("/api/danger")).StatusCode);
        app.Time.Advance(TimeSpan.FromMinutes(6));
        client.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        Assert.Equal(HttpStatusCode.Forbidden, (await client.DeleteAsync("/api/danger")).StatusCode);
    }

    [Fact]
    public async Task Validation_errors_carry_a_machine_readable_code_like_every_other_error()
    {
        await using var app = await TestApp.StartAsync();

        var response = await app.CreateClient().PostAsync("/auth/register", new { email = "new@test.local", password = "short" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("validation_failed", body.Str("code"));
        Assert.True(body.GetProperty("errors").TryGetProperty("password", out _));
    }

    /// <summary>A user seeded by the host without a security stamp must not be signed out right after signing in.</summary>
    [Fact]
    public async Task A_user_without_security_stamp_gets_one_at_the_first_sign_in()
    {
        await using var app = await TestApp.StartAsync();
        var user = app.Users.Get(TestApp.UserEmail);
        user.SecurityStamp = "";
        await app.Users.UpdateSecurityStateAsync(user, default);

        var client = app.CreateClient();
        client.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/me")).StatusCode);
        Assert.False(string.IsNullOrEmpty(app.Users.Get(TestApp.UserEmail).SecurityStamp));
    }
}
