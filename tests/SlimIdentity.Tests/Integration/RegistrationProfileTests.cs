using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// Registration with business data: the <c>profile</c> comes with the credential after the mailbox is proven, the host
/// validates it, and the store receives it with the account – both are created together or not at all. Hosts with their own endpoint use
/// <see cref="ISlimAuthManager.RegisterAsync"/> and keep every rule of <c>/register</c>.
/// </summary>
public sealed class RegistrationProfileTests
{
    private sealed record SignUpProfile(string Company);

    /// <summary>A company is required; the hook sees every registration, also one without a profile.</summary>
    private sealed class CompanyProfile : ISlimRegistrationProfile
    {
        public ValueTask<SlimProfileValidation> ValidateAsync(SlimRegistrationProfileContext context, CancellationToken ct)
        {
            var company = context.Profile is { ValueKind: JsonValueKind.Object } p && p.TryGetProperty("company", out var c)
                && c.ValueKind == JsonValueKind.String ? c.GetString()!.Trim() : null;
            return ValueTask.FromResult(string.IsNullOrEmpty(company) || company.Length > 100
                ? SlimProfileValidation.Invalid("company", "The company is required.")
                : SlimProfileValidation.Valid(new SignUpProfile(company)));
        }
    }

    private sealed class CompanyDomainGuard : ISlimRegistrationGuard
    {
        public ValueTask<SlimVeto?> CheckAsync(SlimRegistrationContext context, CancellationToken ct) =>
            ValueTask.FromResult(context.Email.EndsWith("@firma.test", StringComparison.OrdinalIgnoreCase)
                ? null
                : new SlimVeto("registration_not_allowed"));
    }

    /// <summary>Decides from the validated profile: no accounts for a competitor.</summary>
    private sealed class CompetitorGuard : ISlimRegistrationGuard
    {
        public ValueTask<SlimVeto?> CheckAsync(SlimRegistrationContext context, CancellationToken ct) =>
            ValueTask.FromResult(context is { Stage: SlimRegistrationStage.Complete, Profile: SignUpProfile { Company: "Competitor" } }
                ? new SlimVeto("company_not_allowed")
                : null);
    }

    private static Task<TestApp> WithProfileAsync() =>
        TestApp.StartAsync(new TestAppOptions { Builder = b => b.AddRegistrationProfile<CompanyProfile>() });

    private static async Task<JsonElement> ErrorsOf(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetProperty("errors");

    [Fact]
    public async Task A_valid_profile_reaches_the_store_with_the_account()
    {
        await using var app = await WithProfileAsync();

        var response = await app.RegisterAsync("new@test.local", "Another123!", new { company = "  ACME  " });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var user = app.Users.Get("new@test.local");
        Assert.Equal(new SignUpProfile("ACME"), app.Users.Profiles[user.Id]);   // what the hook returned, not the raw JSON
        Assert.True(user.EmailConfirmed);
    }

    [Fact]
    public async Task A_veto_on_the_validated_profile_keeps_the_flow_open()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions
        {
            Builder = b => b.AddRegistrationProfile<CompanyProfile>().AddRegistrationGuard<CompetitorGuard>(),
        });
        var client = app.CreateClient();
        var flowToken = await app.VerifyRegistrationAsync("new@test.local", client);

        var refused = await client.PostJsonAsync("/auth/register/password",
            new { flowToken, password = "Another123!", profile = new { company = " Competitor " } }, HttpStatusCode.Forbidden);
        Assert.Equal("company_not_allowed", refused.Str("code"));
        Assert.Null(await app.Users.FindByEmailAsync("new@test.local", default));

        await client.PostJsonAsync("/auth/register/password", new { flowToken, password = "Another123!", profile = new { company = "ACME" } });
        Assert.Equal(new SignUpProfile("ACME"), app.Users.Profiles[app.Users.Get("new@test.local").Id]);
    }

    [Fact]
    public async Task An_invalid_profile_answers_400_and_creates_nothing()
    {
        await using var app = await WithProfileAsync();

        var invalid = await app.RegisterAsync("new@test.local", "Another123!", new { company = "" });
        var missing = await app.RegisterAsync("other@test.local", "Another123!");

        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);                       // the hook decides about "no profile" too
        Assert.True((await ErrorsOf(invalid)).TryGetProperty("profile.company", out _));
        Assert.DoesNotContain(app.Users.All, u => u.Email is "new@test.local" or "other@test.local");
    }

    [Fact]
    public async Task The_first_step_takes_neither_a_password_nor_a_profile()
    {
        await using var app = await WithProfileAsync();
        var client = app.CreateClient();

        var withProfile = await client.PostAsync("/auth/register", new { email = "new@test.local", profile = new { company = "ACME" } });
        var withPassword = await client.PostAsync("/auth/register", new { email = TestApp.UserEmail, password = "Another123!" });

        Assert.Equal(HttpStatusCode.BadRequest, withProfile.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, withPassword.StatusCode);
        await Task.Delay(100);
        Assert.Empty(app.Mail.Mails);                                                       // no mail – not even "account exists"
        Assert.False(app.Users.Profiles.ContainsKey(app.Users.Get(TestApp.UserEmail).Id));
    }

    [Fact]
    public async Task Without_a_profile_hook_a_profile_is_refused()
    {
        await using var app = await TestApp.StartAsync();

        var refused = await app.RegisterAsync("new@test.local", "Another123!", new { isAdmin = true });
        var none = await app.RegisterAsync("none@test.local", "Another123!");

        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.True((await ErrorsOf(refused)).TryGetProperty("profile", out _));
        Assert.Equal(HttpStatusCode.OK, none.StatusCode);
        Assert.Null(app.Users.Profiles[app.Users.Get("none@test.local").Id]);
    }

    [Fact]
    public async Task The_password_rules_come_before_the_profile()
    {
        await using var app = await WithProfileAsync();

        var response = await app.RegisterAsync("new@test.local", "short", new { company = "" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.True((await ErrorsOf(response)).TryGetProperty("password", out _));
    }

    // ------------------------------------------------------------------ ISlimAuthManager.RegisterAsync

    private sealed record SignUpForm(string Email, string Password, string Company);

    private static Task<TestApp> WithOwnEndpointAsync(Action<SlimIdentityBuilder>? builder = null) => TestApp.StartAsync(new TestAppOptions
    {
        Configure = o => o.Endpoints.EnableRegistration = false,   // the host's own endpoint replaces /register
        Builder = builder,
        Map = app => app.MapPost("/api/sign-up", async (SignUpForm form, ISlimAuthManager auth, CancellationToken ct) =>
            (await auth.RegisterAsync(form.Email, form.Password, new SignUpProfile(form.Company), ct)).Response),
    });

    [Fact]
    public async Task RegisterAsync_creates_the_account_with_its_profile_by_the_rules_of_register()
    {
        await using var app = await WithOwnEndpointAsync();
        var client = app.CreateClient();

        var fresh = await client.PostAsync("/api/sign-up", new { email = " New@Test.local ", password = "Another123!", company = "ACME" });
        var existing = await client.PostAsync("/api/sign-up", new { email = TestApp.UserEmail, password = "Another123!", company = "Evil" });

        Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);
        Assert.Equal(await fresh.Content.ReadAsStringAsync(), await existing.Content.ReadAsStringAsync());   // no enumeration
        var user = app.Users.Get("new@test.local");
        Assert.Equal(new SignUpProfile("ACME"), app.Users.Profiles[user.Id]);
        await app.Mail.WaitForAsync("account-exists", TestApp.UserEmail);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsync("/auth/register", new { email = "x@test.local" })).StatusCode);
    }

    [Fact]
    public async Task RegisterAsync_applies_address_password_rules_and_guards()
    {
        await using var app = await WithOwnEndpointAsync(b => b.AddRegistrationGuard<CompanyDomainGuard>());
        var client = app.CreateClient();

        var badAddress = await client.PostAsync("/api/sign-up", new { email = "not-an-address", password = "Another123!", company = "ACME" });
        var badPassword = await client.PostAsync("/api/sign-up", new { email = "new@firma.test", password = "short", company = "ACME" });
        var vetoed = await client.PostAsync("/api/sign-up", new { email = "new@test.local", password = "Another123!", company = "ACME" });
        var allowed = await client.PostAsync("/api/sign-up", new { email = "new@firma.test", password = "Another123!", company = "ACME" });

        Assert.Equal(HttpStatusCode.BadRequest, badAddress.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, badPassword.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, vetoed.StatusCode);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        Assert.Equal(new SignUpProfile("ACME"), app.Users.Profiles[app.Users.Get("new@firma.test").Id]);
    }

    [Fact]
    public async Task RegisterAsync_returns_the_new_account_but_not_an_existing_one()
    {
        SlimRegistrationResult? created = null, taken = null;
        await using var app = await TestApp.StartAsync(new TestAppOptions
        {
            Map = app => app.MapPost("/api/probe", async (ISlimAuthManager auth, CancellationToken ct) =>
            {
                created = await auth.RegisterAsync("probe@test.local", "Another123!", ct: ct);
                taken = await auth.RegisterAsync(TestApp.UserEmail, "Another123!", ct: ct);
                return Results.Ok();
            }),
        });

        await app.CreateClient().PostAsync("/api/probe", new { });

        Assert.Equal(app.Users.Get("probe@test.local").Id, created!.User!.Id);
        Assert.Null(created.Failure);
        Assert.Null(taken!.User);
        Assert.Null(taken.Failure);
    }
}
