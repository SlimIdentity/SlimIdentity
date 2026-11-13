using System.Net;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Security;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Single-use challenges, CSRF on the 2FA step and races between parallel requests.</summary>
public sealed class ConcurrencyTests
{
    private static string Code(TestApp app, string sharedKey) =>
        SlimTotp.Compute(SlimBase32.Decode(sharedKey), app.Time.GetUtcNow().ToUnixTimeSeconds() / 30);

    private static async Task<(string SharedKey, string[] RecoveryCodes)> EnableTotpAsync(TestApp app)
    {
        var tokens = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var client = app.CreateClient();
        client.BearerToken = tokens.AccessToken;

        var setup = await client.PostJsonAsync("/auth/2fa/setup");
        var sharedKey = setup.Str("sharedKey");
        var enabled = await client.PostJsonAsync("/auth/2fa/enable", new { setupToken = setup.Str("setupToken"), code = Code(app, sharedKey), password = TestApp.UserPassword });
        app.Time.Advance(TimeSpan.FromSeconds(30));   // next time step – the enable code is used
        return (sharedKey, enabled.GetProperty("recoveryCodes").EnumerateArray().Select(c => c.GetString()!).ToArray());
    }

    [Fact]
    public async Task A_sign_in_challenge_completes_only_one_sign_in()
    {
        await using var app = await TestApp.StartAsync();
        var (sharedKey, recoveryCodes) = await EnableTotpAsync(app);
        var client = app.CreateClient();

        var preAuth = (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword })).Str("flowToken");
        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = preAuth, code = Code(app, sharedKey) });

        // the same challenge with another, valid factor: a fresh TOTP step …
        app.Time.Advance(TimeSpan.FromSeconds(30));
        var reused = await client.PostJsonAsync("/auth/login/2fa", new { flowToken = preAuth, code = Code(app, sharedKey) }, HttpStatusCode.Unauthorized);
        Assert.Equal("invalid_token", reused.Str("code"));
        // … or a recovery code
        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = preAuth, recoveryCode = recoveryCodes[0] }, HttpStatusCode.Unauthorized);

        // a new challenge (password again) works
        app.Time.Advance(TimeSpan.FromSeconds(30));
        var fresh = (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword })).Str("flowToken");
        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = fresh, code = Code(app, sharedKey) });
    }

    [Fact]
    public async Task A_wrong_code_does_not_burn_the_challenge()
    {
        await using var app = await TestApp.StartAsync();
        var (sharedKey, _) = await EnableTotpAsync(app);
        var client = app.CreateClient();

        var preAuth = (await client.PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword })).Str("flowToken");
        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = preAuth, code = "000000" }, HttpStatusCode.Unauthorized);
        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = preAuth, code = Code(app, sharedKey) });
    }

    [Fact]
    public async Task Cookie_mode_2fa_step_requires_csrf_even_if_bearer_is_the_default()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Configure = o => o.Endpoints.DefaultUseCookies = false });
        var (sharedKey, _) = await EnableTotpAsync(app);
        var client = app.CreateClient();
        client.SendCsrfHeader = true;

        var preAuth = (await client.PostJsonAsync("/auth/login?useCookies=true", new { email = TestApp.UserEmail, password = TestApp.UserPassword })).Str("flowToken");

        // no session cookie, no useCookies flag – only the signed challenge says "cookie mode"
        client.SendCsrfHeader = false;
        var missingHeader = await client.PostJsonAsync("/auth/login/2fa", new { flowToken = preAuth, code = Code(app, sharedKey) }, HttpStatusCode.Forbidden);
        Assert.Equal("csrf_validation_failed", missingHeader.Str("code"));

        client.SendCsrfHeader = true;
        client.Origin = "https://evil.example";
        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = preAuth, code = Code(app, sharedKey) }, HttpStatusCode.Forbidden);

        client.Origin = null;
        await client.PostJsonAsync("/auth/login/2fa", new { flowToken = preAuth, code = Code(app, sharedKey) });
        Assert.True(client.Cookies.ContainsKey("SlimAuth"));
    }

    [Fact]
    public async Task Bearer_mode_2fa_step_needs_no_csrf_header()
    {
        await using var app = await TestApp.StartAsync();
        var (sharedKey, _) = await EnableTotpAsync(app);
        var client = app.CreateClient();

        var preAuth = (await client.PostJsonAsync("/auth/login?useCookies=false", new { email = TestApp.UserEmail, password = TestApp.UserPassword })).Str("flowToken");
        var session = await client.PostJsonAsync("/auth/login/2fa", new { flowToken = preAuth, code = Code(app, sharedKey) });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
    }

    /// <summary>Counts the real password verifications of non-dummy users (per test via the user's e-mail).</summary>
    private sealed class CountingHasher : Microsoft.AspNetCore.Identity.IPasswordHasher<SlimUser>
    {
        public static readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> Verified = new();
        private readonly Microsoft.AspNetCore.Identity.PasswordHasher<SlimUser> _inner = new();
        public string HashPassword(SlimUser user, string password) => _inner.HashPassword(user, password);
        public Microsoft.AspNetCore.Identity.PasswordVerificationResult VerifyHashedPassword(SlimUser user, string hashedPassword, string providedPassword)
        {
            if (user.Id != "slim-dummy") Verified.AddOrUpdate(user.Email, 1, (_, n) => n + 1);
            return _inner.VerifyHashedPassword(user, hashedPassword, providedPassword);
        }
    }

    private static string CaseVariant(string email, int i) =>
        new([.. email.Select((c, n) => n < 10 && ((i >> n) & 1) == 1 ? char.ToUpperInvariant(c) : c)]);

    [Fact]
    public async Task Parallel_password_guesses_beyond_the_threshold_are_counted_but_not_evaluated()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions   // MaxFailedAttempts = 5 (default)
        {
            Builder = b => b.Services.AddScoped<Microsoft.AspNetCore.Identity.IPasswordHasher<SlimUser>, CountingHasher>(),
        });
        CountingHasher.Verified.TryRemove(TestApp.UserEmail, out _);

        // the store looks addresses up case-insensitively – every spelling hits the same account and the same gate
        await Task.WhenAll(Enumerable.Range(0, 40).Select(i => Task.Run(() =>
            app.CreateClient().PostAsync("/auth/login", new { email = CaseVariant(TestApp.UserEmail, i), password = $"guess-{i:D3}-wrong" }))));

        Assert.Equal(5, CountingHasher.Verified.GetValueOrDefault(TestApp.UserEmail));
        var user = app.Users.Get(TestApp.UserEmail);
        Assert.Equal(5, user.FailedLoginAttempts);
        Assert.True(user.IsLockedOut(app.Time.GetUtcNow()));
        await app.Mail.WaitForAsync("lockout", TestApp.UserEmail);
        Assert.Single(app.Mail.Mails, m => m.Kind == "lockout");
    }

    [Fact]
    public async Task Parallel_second_factor_guesses_beyond_the_threshold_are_not_evaluated()
    {
        await using var app = await TestApp.StartAsync();
        var (sharedKey, _) = await EnableTotpAsync(app);

        // the attacker knows the password and races 40 guesses of the 6-digit code
        var preAuth = (await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword })).Str("flowToken");
        var valid = Code(app, sharedKey);
        var guesses = Enumerable.Range(0, 1_000_000).Select(n => n.ToString("D6", System.Globalization.CultureInfo.InvariantCulture))
            .Where(g => g != valid).Take(40).ToArray();
        await Task.WhenAll(guesses.Select(g => Task.Run(() =>
            app.CreateClient().PostAsync("/auth/login/2fa", new { flowToken = preAuth, code = g }))));

        // every evaluated wrong guess is counted – more than five means guesses slipped past the lockout
        Assert.Equal(5, app.Users.Get(TestApp.UserEmail).FailedSecondFactorAttempts);
    }

    [Fact]
    public async Task Refreshing_claims_or_signing_out_everywhere_with_a_stale_user_keeps_a_concurrent_password_change()
    {
        await using var app = await TestApp.StartAsync();
        using var scope = app.App.Services.CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<ISlimUserStore>();
        var auth = scope.ServiceProvider.GetRequiredService<ISlimAuthManager>();
        var stale = (await store.FindByEmailAsync(TestApp.UserEmail, default))!;

        // another request changes the password after "stale" was read (e.g. a loop over group members)
        var fresh = (await store.FindByIdAsync(stale.Id, default))!;
        await auth.SetPasswordAsync(fresh, "Concurrent-Password-456");
        var changedHash = (await store.FindByIdAsync(stale.Id, default))!.PasswordHash;

        await auth.RefreshClaimsAsync(stale);
        Assert.Equal(changedHash, (await store.FindByIdAsync(stale.Id, default))!.PasswordHash);

        await auth.SignOutEverywhereAsync(stale);
        var saved = (await store.FindByIdAsync(stale.Id, default))!;
        Assert.Equal(changedHash, saved.PasswordHash);
        Assert.Equal(saved.SecurityStamp, stale.SecurityStamp);   // the caller's instance carries the rotated stamp
    }

    [Fact]
    public async Task A_failed_login_never_undoes_a_concurrent_password_change()
    {
        await using var app = await TestApp.StartAsync();
        var before = app.Users.Get(TestApp.UserEmail);

        // the password is changed while the failed attempt is being verified / recorded
        app.Users.BeforeAttempt = id => { app.Users.BeforeAttempt = null; app.Users.ChangePassword(id, "Changed123!"); };
        await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = "wrong-password" }, HttpStatusCode.Unauthorized);

        var after = app.Users.Get(TestApp.UserEmail);
        Assert.NotEqual(before.PasswordHash, after.PasswordHash);
        Assert.NotEqual(before.SecurityStamp, after.SecurityStamp);
        Assert.Equal(1, after.FailedLoginAttempts);

        await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);
        await app.LoginBearerAsync(TestApp.UserEmail, "Changed123!");
    }

    [Fact]
    public async Task A_registration_race_creates_one_account()
    {
        await using var app = await TestApp.StartAsync();
        var flowToken = await app.VerifyRegistrationAsync("race@test.local");

        // another registration of the address completes between the lookup and the insert
        app.Users.BeforeCreate = email => { app.Users.BeforeCreate = null; app.Users.Seed(email, "Other123!"); };
        var raced = await app.CreateClient().PostJsonAsync("/auth/register/password",
            new { flowToken, password = "Another123!" }, HttpStatusCode.Conflict);

        Assert.Equal("email_taken", raced.Str("code"));
        Assert.Single(app.Users.All, u => u.Email == "race@test.local");
        await app.LoginBearerAsync("race@test.local", "Other123!");
    }
}
