using System.Net;
using Microsoft.Extensions.DependencyInjection;
using SlimIdentity.Services;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Findings of the second review round (re-check of the round-1 fixes), each proven by a failing test first.</summary>
public sealed class ReviewRound2Tests
{
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
    public async Task Different_spellings_of_one_address_share_the_attempt_gate()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions
        {
            Builder = b => b.Services.AddScoped<Microsoft.AspNetCore.Identity.IPasswordHasher<SlimUser>, CountingHasher>(),
        });
        CountingHasher.Verified.TryRemove(TestApp.UserEmail, out _);

        // the store looks addresses up case-insensitively – every spelling hits the same account
        await Task.WhenAll(Enumerable.Range(0, 40).Select(i => Task.Run(() =>
            app.CreateClient().PostAsync("/auth/login", new { email = CaseVariant(TestApp.UserEmail, i), password = $"guess-{i:D3}-wrong" }))));

        Assert.Equal(5, CountingHasher.Verified.GetValueOrDefault(TestApp.UserEmail));
        Assert.Equal(5, app.Users.Get(TestApp.UserEmail).FailedLoginAttempts);
    }

    [Fact]
    public async Task The_queue_of_one_account_is_limited()
    {
        var gate = new SlimAttemptGate();
        using var running = await gate.TryEnterAsync("user-1", default);
        Assert.NotNull(running);

        var waiting = Enumerable.Range(0, SlimAttemptGate.MaxWaitingPerAccount).Select(_ => gate.TryEnterAsync("user-1", default)).ToArray();
        Assert.All(waiting, w => Assert.False(w.IsCompleted));                       // queued behind the running attempt

        var overflow = gate.TryEnterAsync("user-1", default);                          // full: answered at once, never evaluated
        Assert.True(overflow.IsCompleted, "The attempt beyond the queue limit waits instead of being refused.");
        Assert.Null(await overflow);
        using (var other = await gate.TryEnterAsync("user-2", default)) Assert.NotNull(other);   // other accounts are unaffected

        running!.Dispose();
        foreach (var w in waiting) (await w)!.Dispose();
        using var later = await gate.TryEnterAsync("user-1", default);
        Assert.NotNull(later);
    }

    // ------------------------------------------------------------------ F-03: forced password change during a lockout

    private static async Task<string> PasswordChangeTokenAsync(TestApp app)
    {
        var user = app.Users.Get(TestApp.UserEmail);
        user.PasswordChangeRequired = true;
        await app.Users.UpdateSecurityStateAsync(user, default);
        return (await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized)).Str("passwordChangeToken");
    }

    [Fact]
    public async Task F03_a_locked_account_cannot_complete_the_forced_password_change()
    {
        await using var app = await TestApp.StartAsync();
        var token = await PasswordChangeTokenAsync(app);

        for (var i = 0; i < 5; i++)   // locked before the token is redeemed
            await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = "wrong" }, HttpStatusCode.Unauthorized);
        Assert.True(app.Users.Get(TestApp.UserEmail).IsLockedOut(app.Time.GetUtcNow()));

        var answer = await app.CreateClient().PostAsync("/auth/login/password-change", new { token, newPassword = "New-Valid-Pass-123!" });

        Assert.Equal((HttpStatusCode)423, answer.StatusCode);
        Assert.True(app.Users.Get(TestApp.UserEmail).IsLockedOut(app.Time.GetUtcNow()));   // the lockout was not cleared
        Assert.True(app.Users.Get(TestApp.UserEmail).PasswordChangeRequired);
    }

    [Fact]
    public async Task F03_after_the_lockout_the_change_token_works_again()
    {
        await using var app = await TestApp.StartAsync();
        var token = await PasswordChangeTokenAsync(app);
        for (var i = 0; i < 5; i++)
            await app.CreateClient().PostJsonAsync("/auth/login", new { email = TestApp.UserEmail, password = "wrong" }, HttpStatusCode.Unauthorized);

        app.Time.Advance(TimeSpan.FromMinutes(1) + TimeSpan.FromSeconds(1));   // first lockout: 1 minute, token: 5 minutes

        var session = await app.CreateClient().PostJsonAsync("/auth/login/password-change", new { token, newPassword = "New-Valid-Pass-123!" });
        Assert.False(string.IsNullOrEmpty(session.Str("accessToken")));
    }

    // ------------------------------------------------------------------ F-04: a confirmed password resets the counter

    [Fact]
    public async Task F04_a_correct_password_confirmation_resets_the_failed_attempts()
    {
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();
        client.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;

        for (var i = 0; i < 4; i++)   // threshold is 5
            await client.PostJsonAsync("/auth/change-email", new { newEmail = "new@test.local", password = "wrong" }, HttpStatusCode.BadRequest);
        Assert.Equal(4, app.Users.Get(TestApp.UserEmail).FailedLoginAttempts);

        await client.PostJsonAsync("/auth/change-email", new { newEmail = "new@test.local", password = TestApp.UserPassword });

        Assert.Equal(0, app.Users.Get(TestApp.UserEmail).FailedLoginAttempts);
    }

    [Fact]
    public async Task F04_the_reset_survives_endpoints_that_write_the_security_state_afterwards()
    {
        // /2fa/disable writes the whole security state after the confirmation – it must not write the old counter back
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();
        client.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;
        await client.PostJsonAsync("/auth/2fa/enable-email", new { password = TestApp.UserPassword });
        var me = app.CreateClient();
        me.BearerToken = await SignInWithEmailCodeAsync(app);

        for (var i = 0; i < 4; i++)
            await me.PostJsonAsync("/auth/2fa/disable", new { password = "wrong" }, HttpStatusCode.BadRequest);
        var disabled = await me.PostJsonAsync("/auth/2fa/disable", new { password = TestApp.UserPassword });

        Assert.False(app.Users.Get(TestApp.UserEmail).TwoFactorEnabled);
        Assert.Equal(0, app.Users.Get(TestApp.UserEmail).FailedLoginAttempts);
        Assert.False(string.IsNullOrEmpty(disabled.Str("accessToken")));
    }

    private static async Task<string> SignInWithEmailCodeAsync(TestApp app)
    {
        var challenge = await app.CreateClient().PostJsonAsync("/auth/login?useCookies=false",
            new { email = TestApp.UserEmail, password = TestApp.UserPassword }, HttpStatusCode.Unauthorized);
        var code = (await app.Mail.WaitForAsync("two-factor", TestApp.UserEmail)).Payload;
        return (await app.CreateClient().PostJsonAsync("/auth/login/2fa", new { preAuthToken = challenge.Str("preAuthToken"), code })).Str("accessToken");
    }

    // ------------------------------------------------------------------ F-05: mail throttle at capacity

    [Fact]
    public void F05_a_full_mail_throttle_does_not_let_a_victim_be_flooded()
    {
        var time = new Microsoft.Extensions.Time.Testing.FakeTimeProvider(DateTimeOffset.UtcNow);
        var throttle = new SlimMailThrottle(time);

        // a distributed attacker fills the table with 100,000 fresh recipients
        for (var i = 0; i < 100_000; i++)
            Assert.True(throttle.TryAcquire(SlimEmailKinds.Verification, $"bot-{i}@example.invalid"));

        var allowedForVictim = Enumerable.Range(0, 20).Count(_ => throttle.TryAcquire(SlimEmailKinds.PasswordReset, "victim@example.com"));

        Assert.True(allowedForVictim <= SlimMailThrottle.PerKindAndRecipient,
            $"{allowedForVictim} mails to victim@example.com were allowed (fail open).");
    }

    [Fact]
    public void F05_after_the_flood_new_recipients_get_mail_again()
    {
        var time = new Microsoft.Extensions.Time.Testing.FakeTimeProvider(DateTimeOffset.UtcNow);
        var throttle = new SlimMailThrottle(time);
        for (var i = 0; i < 100_000; i++) throttle.TryAcquire(SlimEmailKinds.Verification, $"bot-{i}@example.invalid");
        Assert.False(throttle.TryAcquire(SlimEmailKinds.Verification, "late@example.com"));   // full: refused, not unlimited

        time.Advance(SlimMailThrottle.Window + TimeSpan.FromMinutes(1));

        Assert.True(throttle.TryAcquire(SlimEmailKinds.Verification, "late@example.com"));
    }

    // ------------------------------------------------------------------ F-06: logout with a dead refresh token

    [Fact]
    public async Task F06_a_refresh_token_from_before_a_password_change_cannot_end_the_renewed_session()
    {
        await using var app = await TestApp.StartAsync();
        var initial = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);

        // the password is changed on this device: the stamp rotates, the session (sid) continues with new tokens
        var me = app.CreateClient();
        me.BearerToken = initial.AccessToken;
        var changed = await me.PostJsonAsync("/auth/change-password", new { currentPassword = TestApp.UserPassword, newPassword = "New-Secure-Pass-123!" });

        // whoever kept the old refresh token sends it to the anonymous logout
        await app.CreateClient().PostJsonAsync("/auth/logout", new { refreshToken = initial.RefreshToken });

        me.BearerToken = changed.Str("accessToken");
        Assert.Equal(HttpStatusCode.OK, (await me.GetAsync("/api/hello")).StatusCode);
        await app.CreateClient().PostJsonAsync("/auth/refresh", new { refreshToken = changed.Str("refreshToken") });
    }

    [Fact]
    public async Task F06_an_already_rotated_refresh_token_cannot_end_the_session_through_logout()
    {
        await using var app = await TestApp.StartAsync();
        var initial = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);
        var rotated = await app.CreateClient().PostJsonAsync("/auth/refresh", new { refreshToken = initial.RefreshToken });

        await app.CreateClient().PostJsonAsync("/auth/logout", new { refreshToken = initial.RefreshToken });

        var me = app.CreateClient();
        me.BearerToken = rotated.Str("accessToken");
        Assert.Equal(HttpStatusCode.OK, (await me.GetAsync("/api/hello")).StatusCode);
    }

    [Fact]
    public async Task F06_the_current_refresh_token_still_ends_its_session()
    {
        await using var app = await TestApp.StartAsync();
        var tokens = await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);

        await app.CreateClient().PostJsonAsync("/auth/logout", new { refreshToken = tokens.RefreshToken });   // e.g. app closed, access token gone

        var me = app.CreateClient();
        me.BearerToken = tokens.AccessToken;
        Assert.Equal(HttpStatusCode.Unauthorized, (await me.GetAsync("/api/hello")).StatusCode);
        await app.CreateClient().PostJsonAsync("/auth/refresh", new { refreshToken = tokens.RefreshToken }, HttpStatusCode.Unauthorized);
    }

    [Theory]
    [InlineData("/auth/login?useCookies=false")]
    [InlineData("/auth/2fa/setup")]
    public async Task Responses_with_secrets_are_never_cached(string path)
    {
        await using var app = await TestApp.StartAsync();
        var client = app.CreateClient();
        client.BearerToken = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;

        var response = await client.SendAsync(HttpMethod.Post, path, new { email = TestApp.UserEmail, password = TestApp.UserPassword });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore, $"{path}: Cache-Control is '{response.Headers.CacheControl}'");
    }
}
