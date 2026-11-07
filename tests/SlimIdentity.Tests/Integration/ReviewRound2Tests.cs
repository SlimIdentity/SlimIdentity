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
