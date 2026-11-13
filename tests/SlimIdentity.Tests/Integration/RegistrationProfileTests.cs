using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// Registration with business data: the <c>profile</c> comes with the credential after the mailbox is proven, the host
/// validates it, and the store receives it with the account – both are created together or not at all. Hosts with their own first
/// step use <see cref="ISlimAuthManager.BeginRegistrationAsync"/> and keep every rule of <c>/register</c>; administrators create
/// accounts with <see cref="ISlimAuthManager.CreateUserAsync"/>.
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
        await app.WaitForQueuedMailAsync();
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

    // ------------------------------------------------------------------ ISlimAuthManager.BeginRegistrationAsync

    private sealed record SignUpForm(string Email, string Captcha);

    /// <summary>The host's own first step (a captcha); the steps after it are the built-in ones.</summary>
    private static Task<TestApp> WithOwnEndpointAsync(Action<SlimIdentityBuilder>? builder = null) => TestApp.StartAsync(new TestAppOptions
    {
        Configure = o => { o.Endpoints.EnableRegistration = false; o.Endpoints.DefaultUseCookies = false; },
        Builder = b => { b.AddRegistrationProfile<CompanyProfile>(); builder?.Invoke(b); },
        Map = app => app.MapPost("/api/sign-up", async (SignUpForm form, ISlimAuthManager auth, CancellationToken ct) =>
            form.Captcha == "solved" ? await auth.BeginRegistrationAsync(form.Email, ct: ct) : Results.BadRequest()),
    });

    [Fact]
    public async Task An_own_first_step_continues_with_the_built_in_steps()
    {
        await using var app = await WithOwnEndpointAsync();
        var client = app.CreateClient();

        var started = await client.PostJsonAsync("/api/sign-up", new { email = " New@Test.local ", captcha = "solved" });
        var existing = await client.PostJsonAsync("/api/sign-up", new { email = TestApp.UserEmail, captcha = "solved" });
        Assert.Equal("verify_email", started.GetProperty("actions")[0].GetString());
        Assert.Equal(started.GetProperty("actions").ToString(), existing.GetProperty("actions").ToString());   // no enumeration
        await app.Mail.WaitForAsync("account-exists", TestApp.UserEmail);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsync("/auth/register", new { email = "x@test.local" })).StatusCode);

        var code = (await app.Mail.WaitForAsync("verification", "New@Test.local")).Payload;
        var verified = await client.PostJsonAsync("/auth/register/verify", new { flowToken = started.Str("flowToken"), code });
        var session = await client.PostJsonAsync("/auth/register/password",
            new { flowToken = verified.Str("flowToken"), password = "Another123!", profile = new { company = "ACME" } });

        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
        var user = app.Users.Get("new@test.local");
        Assert.True(user.EmailConfirmed);
        Assert.Equal(new SignUpProfile("ACME"), app.Users.Profiles[user.Id]);
    }

    [Fact]
    public async Task An_own_first_step_keeps_the_address_rules_and_the_guards()
    {
        await using var app = await WithOwnEndpointAsync(b => b.AddRegistrationGuard<CompanyDomainGuard>());
        var client = app.CreateClient();

        var badAddress = await client.PostAsync("/api/sign-up", new { email = "Name <new@firma.test>", captcha = "solved" });
        var vetoed = await client.PostAsync("/api/sign-up", new { email = "new@test.local", captcha = "solved" });
        await client.PostJsonAsync("/api/sign-up", new { email = "new@firma.test", captcha = "solved" });

        Assert.Equal(HttpStatusCode.BadRequest, badAddress.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, vetoed.StatusCode);
        await app.Mail.WaitForAsync("verification", "new@firma.test");
        Assert.DoesNotContain(app.Mail.Mails, m => m.To is "new@test.local" or "Name <new@firma.test>");
    }

    [Fact]
    public async Task BeginRegistrationAsync_needs_mail()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { EmailSender = false, Builder = b => b.WithoutEmail() });
        await using var scope = app.App.Services.CreateAsyncScope();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            scope.ServiceProvider.GetRequiredService<ISlimAuthManager>().BeginRegistrationAsync("new@test.local"));
    }

    // ------------------------------------------------------------------ ISlimAuthManager.CreateUserAsync

    [Fact]
    public async Task CreateUserAsync_creates_a_confirmed_account_without_a_sign_in_method()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Builder = b => b.AddRegistrationGuard<CompanyDomainGuard>() });
        await using var scope = app.App.Services.CreateAsyncScope();
        var auth = scope.ServiceProvider.GetRequiredService<ISlimAuthManager>();

        var created = await auth.CreateUserAsync(" Member@Gmail.test ", profile: new SignUpProfile("ACME"));

        Assert.True(created.Succeeded);                                                     // no guard is asked
        var user = app.Users.Get("member@gmail.test");
        Assert.Equal(user.Id, created.User.Id);
        Assert.True(user.EmailConfirmed);
        Assert.Equal(new SignUpProfile("ACME"), app.Users.Profiles[user.Id]);
        Assert.False(await auth.HasSignInMethodAsync(user));
        Assert.True(await auth.HasSignInMethodAsync(app.Users.Get(TestApp.UserEmail)));
        await app.WaitForQueuedMailAsync();
        Assert.Empty(app.Mail.Mails);
    }

    [Fact]
    public async Task CreateUserAsync_sets_a_start_password_that_must_be_changed()
    {
        await using var app = await TestApp.StartAsync();
        await using var scope = app.App.Services.CreateAsyncScope();
        var auth = scope.ServiceProvider.GetRequiredService<ISlimAuthManager>();

        var weak = await auth.CreateUserAsync("member@test.local", "short");
        var created = await auth.CreateUserAsync("member@test.local", "Start-Pass-123");

        Assert.Equal(StatusCodes.Status400BadRequest, ((IStatusCodeHttpResult)weak.Failure!).StatusCode);
        Assert.True(created.Succeeded);
        Assert.True(await auth.HasSignInMethodAsync(created.User));
        var steps = await app.CreateClient().PostJsonAsync("/auth/login", new { email = "member@test.local", password = "Start-Pass-123" });
        Assert.Equal("change_password", steps.GetProperty("actions")[0].GetString());
    }

    [Fact]
    public async Task CreateUserAsync_refuses_a_taken_address_and_an_invalid_one()
    {
        await using var app = await TestApp.StartAsync();
        await using var scope = app.App.Services.CreateAsyncScope();
        var auth = scope.ServiceProvider.GetRequiredService<ISlimAuthManager>();
        var before = app.Users.All.Count();

        var taken = await auth.CreateUserAsync(TestApp.UserEmail.ToUpperInvariant());
        var invalid = await auth.CreateUserAsync("not-an-address");

        Assert.Equal(StatusCodes.Status409Conflict, ((IStatusCodeHttpResult)taken.Failure!).StatusCode);
        Assert.Equal(StatusCodes.Status400BadRequest, ((IStatusCodeHttpResult)invalid.Failure!).StatusCode);
        Assert.Equal(before, app.Users.All.Count());
    }
}