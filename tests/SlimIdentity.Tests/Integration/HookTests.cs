using System.Collections.Concurrent;
using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// Hooks only tighten: a sign-in guard and a registration guard can say "no", event handlers can only watch.
/// </summary>
public sealed class HookTests
{
    // ------------------------------------------------------------------ host hooks used by the tests

    /// <summary>Suspended tenants: their users get no session, running sessions end.</summary>
    private sealed class TenantGuard : ISlimSignInGuard
    {
        public readonly ConcurrentDictionary<string, bool> Suspended = new();
        public readonly ConcurrentQueue<(string UserId, string Method, SlimSignInStage Stage)> Seen = new();

        public ValueTask<SlimVeto?> CheckAsync(SlimSignInContext context, CancellationToken ct)
        {
            Seen.Enqueue((context.User.Id, context.AuthenticationMethod, context.Stage));
            return ValueTask.FromResult(Suspended.ContainsKey(context.User.Id)
                ? new SlimVeto("tenant_suspended", "Your organization's access is suspended.")
                : null);
        }
    }

    /// <summary>Only company addresses may register.</summary>
    private sealed class CompanyDomainGuard : ISlimRegistrationGuard
    {
        public ValueTask<SlimVeto?> CheckAsync(SlimRegistrationContext context, CancellationToken ct) =>
            ValueTask.FromResult(context.Email.EndsWith("@firma.test", StringComparison.OrdinalIgnoreCase)
                ? null
                : new SlimVeto("registration_not_allowed", "Only company addresses can register."));
    }

    private sealed class Recorder : ISlimEventObserver
    {
        public readonly ConcurrentQueue<SlimEvent> Events = new();
        public ValueTask HandleAsync(SlimEvent e, CancellationToken ct)
        {
            Events.Enqueue(e);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class Failing : ISlimEventObserver
    {
        public ValueTask HandleAsync(SlimEvent e, CancellationToken ct) => throw new InvalidOperationException("audit database down");
    }

    private static TestAppOptions With(Action<SlimIdentityBuilder> hooks, params Claim[] providerClaims) => new()
    {
        Builder = b =>
        {
            hooks(b);
            if (providerClaims.Length > 0)
            {
                b.AddExternalLoginStore<TestExternalLoginStore>(ServiceLifetime.Singleton);
                b.Authentication.AddScheme<FakeOAuthOptions, FakeOAuthHandler>("Fake", o => o.Claims = [.. providerClaims]);
            }
        },
    };

    private static T Hook<T>(TestApp app) where T : class =>
        app.App.Services.GetServices<ISlimSignInGuard>().OfType<T>().FirstOrDefault()
        ?? app.App.Services.GetServices<ISlimEventObserver>().OfType<T>().First();

    private static async Task<Uri> SignInExternallyAsync(ApiClient browser)
    {
        var challenge = await browser.GetAsync("/auth/login/Fake?useCookies=true&returnUrl=/done");
        var callback = await browser.GetAsync(challenge.Headers.Location!.OriginalString);
        return new Uri(new Uri("https://localhost"), callback.Headers.Location!);
    }

    // ------------------------------------------------------------------ sign-in guard

    [Fact]
    public async Task A_vetoed_user_gets_no_session_and_learns_why()
    {
        await using var app = await TestApp.StartAsync(With(b => b.AddSignInGuard<TenantGuard>(ServiceLifetime.Singleton)));
        Hook<TenantGuard>(app).Suspended[app.Users.Get(TestApp.UserEmail).Id] = true;

        var answer = await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Forbidden);

        Assert.Equal("tenant_suspended", answer.Str("code"));
        Assert.Equal("Your organization's access is suspended.", answer.Str("detail"));
        Assert.False(answer.TryGetProperty("accessToken", out _));
        await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword);   // others are not affected
    }

    [Fact]
    public async Task A_veto_ends_running_sessions_and_refreshes()
    {
        await using var app = await TestApp.StartAsync(With(b => b.AddSignInGuard<TenantGuard>(ServiceLifetime.Singleton)));
        var tokens = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var bearer = app.CreateClient();
        bearer.BearerToken = tokens.AccessToken;
        var browser = app.CreateClient();
        browser.SendCsrfHeader = true;
        await browser.PostAsync("/auth/login?useCookies=true", new { email = TestApp.UserEmail, password = TestApp.UserPassword });
        Assert.Equal(HttpStatusCode.OK, (await bearer.GetAsync("/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/auth/me")).StatusCode);

        Hook<TenantGuard>(app).Suspended[app.Users.Get(TestApp.UserEmail).Id] = true;

        Assert.Equal(HttpStatusCode.Unauthorized, (await bearer.GetAsync("/auth/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/auth/me")).StatusCode);
        var refresh = await app.CreateClient().PostJsonAsync("/auth/refresh", new { refreshToken = tokens.RefreshToken }, HttpStatusCode.Forbidden);
        Assert.Equal("tenant_suspended", refresh.Str("code"));
    }

    [Fact]
    public async Task The_guard_sees_method_and_stage()
    {
        await using var app = await TestApp.StartAsync(With(b => b.AddSignInGuard<TenantGuard>(ServiceLifetime.Singleton)));
        var tokens = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        await app.CreateClient().PostJsonAsync("/auth/refresh", new { refreshToken = tokens.RefreshToken });

        var seen = Hook<TenantGuard>(app).Seen.ToArray();
        Assert.Contains(seen, s => s is { Method: "pwd", Stage: SlimSignInStage.SignIn });
        Assert.Contains(seen, s => s is { Method: "pwd", Stage: SlimSignInStage.Renewal });
    }

    [Fact]
    public async Task An_external_sign_in_is_vetoed_as_well()
    {
        await using var app = await TestApp.StartAsync(With(b => b.AddSignInGuard<TenantGuard>(ServiceLifetime.Singleton),
            new Claim(ClaimTypes.NameIdentifier, "ext-1"), new Claim(ClaimTypes.Email, "social@test.local"), new Claim("email_verified", "true")));
        await SignInExternallyAsync(app.CreateClient());   // creates the account
        Hook<TenantGuard>(app).Suspended[app.Users.Get("social@test.local").Id] = true;

        var browser = app.CreateClient();
        var target = await SignInExternallyAsync(browser);

        Assert.Equal("tenant_suspended", QueryHelpers.ParseQuery(target.Query)["slim_error"].ToString());
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/api/hello")).StatusCode);
    }

    // ------------------------------------------------------------------ registration guard

    [Fact]
    public async Task Only_allowed_addresses_can_register()
    {
        await using var app = await TestApp.StartAsync(With(b => b.AddRegistrationGuard<CompanyDomainGuard>()));

        var refused = await app.CreateClient().PostJsonAsync("/auth/register",
            new { email = "someone@gmail.test" }, HttpStatusCode.Forbidden);
        Assert.Equal("registration_not_allowed", refused.Str("code"));
        Assert.Null(await app.Users.FindByEmailAsync("someone@gmail.test", default));

        Assert.Equal(HttpStatusCode.OK, (await app.RegisterAsync("colleague@firma.test", "Some-Long-Pass-1")).StatusCode);
        Assert.NotNull(await app.Users.FindByEmailAsync("colleague@firma.test", default));
    }

    [Fact]
    public async Task External_auto_registration_asks_the_registration_guard()
    {
        await using var app = await TestApp.StartAsync(With(b => b.AddRegistrationGuard<CompanyDomainGuard>(),
            new Claim(ClaimTypes.NameIdentifier, "ext-2"), new Claim(ClaimTypes.Email, "private@gmail.test"), new Claim("email_verified", "true")));

        var target = await SignInExternallyAsync(app.CreateClient());

        Assert.Equal("registration_not_allowed", QueryHelpers.ParseQuery(target.Query)["slim_error"].ToString());
        Assert.Null(await app.Users.FindByEmailAsync("private@gmail.test", default));
    }

    [Fact]
    public async Task Registration_guards_also_run_without_a_request()
    {
        await using var app = await TestApp.StartAsync(With(b => b.AddRegistrationGuard<CompanyDomainGuard>()));
        await using var job = app.App.Services.CreateAsyncScope();   // a background job: no HttpContext
        var auth = job.ServiceProvider.GetRequiredService<ISlimAuthManager>();

        var refused = await auth.RegisterAsync("imported@gmail.test", "Some-Long-Pass-1");
        var allowed = await auth.RegisterAsync("imported@firma.test", "Some-Long-Pass-1");

        Assert.Null(refused.User);
        Assert.Null(await app.Users.FindByEmailAsync("imported@gmail.test", default));
        Assert.NotNull(allowed.User);
    }

    [Fact]
    public async Task A_guard_can_trust_calls_without_a_request()
    {
        await using var app = await TestApp.StartAsync(With(b => b.AddRegistrationGuard<RequestsOnlyGuard>()));
        await using var job = app.App.Services.CreateAsyncScope();

        var imported = await job.ServiceProvider.GetRequiredService<ISlimAuthManager>().RegisterAsync("imported@gmail.test", "Some-Long-Pass-1");
        var refused = await app.CreateClient().PostJsonAsync("/auth/register",
            new { email = "someone@gmail.test" }, HttpStatusCode.Forbidden);

        Assert.NotNull(imported.User);
        Assert.Equal("registration_not_allowed", refused.Str("code"));
    }

    [Fact]
    public async Task Registration_guards_are_asked_at_each_stage()
    {
        await using var app = await TestApp.StartAsync(With(b => b.AddRegistrationGuard<StageRecorder>(ServiceLifetime.Singleton),
            new Claim(ClaimTypes.NameIdentifier, "ext-3"), new Claim(ClaimTypes.Email, "social@test.local"), new Claim("email_verified", "true")));
        var seen = app.App.Services.GetServices<ISlimRegistrationGuard>().OfType<StageRecorder>().Single().Seen;

        Assert.Equal(HttpStatusCode.OK, (await app.RegisterAsync("new@test.local", "Some-Long-Pass-1")).StatusCode);
        await SignInExternallyAsync(app.CreateClient());

        Assert.Equal(
        [
            ("new@test.local", SlimRegistrationStage.Begin, null, null),
            ("new@test.local", SlimRegistrationStage.Complete, SlimCredentialKinds.Password, null),
            ("social@test.local", SlimRegistrationStage.External, SlimCredentialKinds.External, "Fake"),
        ], seen.ToArray());
    }

    [Fact]
    public async Task Without_mail_both_stages_are_asked_before_the_account_exists()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions
        {
            EmailSender = false,
            Builder = b => b.WithoutEmail(allowSelfRegistration: true).AddRegistrationGuard<StageRecorder>(ServiceLifetime.Singleton),
        });
        var recorder = app.App.Services.GetServices<ISlimRegistrationGuard>().OfType<StageRecorder>().Single();
        recorder.Refuse = SlimRegistrationStage.Complete;

        var refused = await app.CreateClient().PostJsonAsync("/auth/register",
            new { email = "new-member", password = "Some-Long-Pass-1" }, HttpStatusCode.Forbidden);

        Assert.Equal("registration_not_allowed", refused.Str("code"));
        Assert.Equal([SlimRegistrationStage.Begin, SlimRegistrationStage.Complete], recorder.Seen.Select(s => s.Stage));
        Assert.Null(await app.Users.FindByEmailAsync("new-member", default));
    }

    private sealed class StageRecorder : ISlimRegistrationGuard
    {
        public readonly ConcurrentQueue<(string Email, SlimRegistrationStage Stage, string? Kind, string? Provider)> Seen = new();
        public SlimRegistrationStage? Refuse { get; set; }

        public ValueTask<SlimVeto?> CheckAsync(SlimRegistrationContext context, CancellationToken ct)
        {
            Seen.Enqueue((context.Email, context.Stage, context.CredentialKind, context.Provider));
            return ValueTask.FromResult(context.Stage == Refuse ? new SlimVeto("registration_not_allowed") : null);
        }
    }

    /// <summary>Self-service registration is closed; the host's own import (no request) is trusted.</summary>
    private sealed class RequestsOnlyGuard : ISlimRegistrationGuard
    {
        public ValueTask<SlimVeto?> CheckAsync(SlimRegistrationContext context, CancellationToken ct) =>
            ValueTask.FromResult(context.HttpContext is null ? null : new SlimVeto("registration_not_allowed"));
    }

    // ------------------------------------------------------------------ events

    [Fact]
    public async Task Security_events_are_reported_with_user_and_method()
    {
        await using var app = await TestApp.StartAsync(With(b => b.AddEventObserver<Recorder>(ServiceLifetime.Singleton)));
        var userId = app.Users.Get(TestApp.UserEmail).Id;

        await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = "wrong-password" }, HttpStatusCode.Unauthorized);
        var me = app.CreateClient();
        me.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await me.PostJsonAsync("/auth/change-password", new { currentPassword = TestApp.UserPassword, newPassword = "Changed-Pass-123" });
        Assert.Equal(HttpStatusCode.OK, (await app.RegisterAsync("new@test.local", "New-Member-Pass-1")).StatusCode);
        for (var i = 0; i < 5; i++)
            await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.AdminEmail, password = "wrong-password" }, HttpStatusCode.Unauthorized);

        var events = Hook<Recorder>(app).Events.ToArray();
        Assert.Contains(events, e => e is { Type: SlimEventTypes.SignInFailed, Reason: "invalid_password" } && e.UserId == userId);
        Assert.Contains(events, e => e is { Type: SlimEventTypes.SignedIn, Method: "pwd" } && e.UserId == userId);
        Assert.Contains(events, e => e is { Type: SlimEventTypes.PasswordChanged, Reason: "changed" } && e.UserId == userId);
        Assert.Contains(events, e => e is { Type: SlimEventTypes.UserCreated, Reason: "registration" });
        Assert.Contains(events, e => e.Type == SlimEventTypes.LockedOut && e.UserId == app.Users.Get(TestApp.AdminEmail).Id);
        Assert.All(events, e => Assert.Equal(app.Time.GetUtcNow(), e.Timestamp));

        // never a password, token or address in an event
        var serialized = JsonSerializer.Serialize(events.Select(e => new { e.Type, e.UserId, e.ActorId, e.Method, e.Reason }));
        Assert.DoesNotContain("Pass", serialized);
        Assert.DoesNotContain("@", serialized);
    }

    [Fact]
    public async Task A_failing_event_handler_changes_nothing()
    {
        await using var app = await TestApp.StartAsync(With(b => b
            .AddEventObserver<Failing>(ServiceLifetime.Singleton)
            .AddEventObserver<Recorder>(ServiceLifetime.Singleton)));

        await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);

        Assert.Contains(Hook<Recorder>(app).Events, e => e.Type == SlimEventTypes.SignedIn);
    }
}
