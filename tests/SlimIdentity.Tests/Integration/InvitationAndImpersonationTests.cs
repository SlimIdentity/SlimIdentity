using System.Net;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

public sealed class InvitationAndImpersonationTests
{
    private static async Task<ApiClient> AdminAsync(TestApp app)
    {
        var tokens = await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword);
        var client = app.CreateClient();
        client.BearerToken = tokens.AccessToken;
        return client;
    }

    [Fact]
    public async Task Invitation_sets_the_password_confirms_the_email_and_is_single_use()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await AdminAsync(app);
        var token = (await admin.PostJsonAsync("/api/invite", new { email = "invited@test.local" })).Str("token");
        var anonymous = app.CreateClient();

        var info = await anonymous.PostJsonAsync("/auth/invitation/info", new { token });
        Assert.Equal("invited@test.local", info.Str("email"));

        await anonymous.PostJsonAsync("/auth/invitation/accept", new { token, password = "weak" }, HttpStatusCode.BadRequest);
        var session = await anonymous.PostJsonAsync("/auth/invitation/accept", new { token, password = "Invited123!" });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
        Assert.True(app.Users.Get("invited@test.local").EmailConfirmed);

        await anonymous.PostJsonAsync("/auth/invitation/accept", new { token, password = "Other1234!" }, HttpStatusCode.BadRequest);
        await anonymous.PostJsonAsync("/auth/invitation/info", new { token }, HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task Invitation_cannot_be_created_for_users_with_a_password()
    {
        await using var app = await TestApp.StartAsync();
        var auth = app.App.Services.CreateScope().ServiceProvider.GetRequiredService<ISlimAuthManager>();

        await Assert.ThrowsAsync<InvalidOperationException>(() => auth.CreateInvitationAsync(app.Users.Get(TestApp.UserEmail)));
    }

    [Fact]
    public async Task Impersonation_carries_the_admin_and_ends_with_a_checked_return()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await AdminAsync(app);
        var userId = app.Users.Get(TestApp.UserEmail).Id;

        var impersonation = app.CreateClient();
        impersonation.BearerToken = (await admin.PostJsonAsync($"/api/impersonate/{userId}")).Str("accessToken");
        var hello = await (await impersonation.GetAsync("/api/hello")).Content.ReadAsStringAsync();
        Assert.Contains(TestApp.UserEmail, hello);
        Assert.Contains(app.Users.Get(TestApp.AdminEmail).Id, hello);

        var back = await impersonation.PostJsonAsync("/api/impersonate/stop");
        var adminAgain = app.CreateClient();
        adminAgain.BearerToken = back.Str("accessToken");
        Assert.Contains(TestApp.AdminEmail, await (await adminAgain.GetAsync("/api/hello")).Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Impersonation_dies_when_the_admin_signs_out_everywhere()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await AdminAsync(app);
        var impersonation = app.CreateClient();
        impersonation.BearerToken = (await admin.PostJsonAsync($"/api/impersonate/{app.Users.Get(TestApp.UserEmail).Id}")).Str("accessToken");
        Assert.Equal(HttpStatusCode.OK, (await impersonation.GetAsync("/api/hello")).StatusCode);

        await admin.PostJsonAsync("/auth/logout-all");

        Assert.Equal(HttpStatusCode.Unauthorized, (await impersonation.GetAsync("/api/hello")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await impersonation.PostAsync("/api/impersonate/stop")).StatusCode);
    }

    [Fact]
    public async Task Admin_cannot_impersonate_themselves()
    {
        await using var app = await TestApp.StartAsync();
        var admin = await AdminAsync(app);
        var result = await admin.PostJsonAsync($"/api/impersonate/{app.Users.Get(TestApp.AdminEmail).Id}", expected: HttpStatusCode.BadRequest);
        Assert.Equal("cannot_impersonate_self", result.Str("status"));
    }
}
