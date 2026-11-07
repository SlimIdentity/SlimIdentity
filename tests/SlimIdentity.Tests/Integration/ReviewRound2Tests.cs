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
