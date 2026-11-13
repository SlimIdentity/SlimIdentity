using System.Diagnostics;
using SlimIdentity.Tests.Infrastructure;
using Xunit.Abstractions;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// Attack scenario A3: unknown, known, inactive and locked accounts must not be distinguishable by response time.
/// A statistical measurement (Mann-Whitney U, interleaved requests), too slow and noisy for every CI run – run it before
/// a release: <c>SLIMIDENTITY_TIMING=1 dotnet test --filter TimingTests</c>.
/// </summary>
public sealed class TimingTests(ITestOutputHelper output)
{
    private const int SamplesPerGroup = 150;

    [SkippableFact]
    public async Task A3_login_timing_does_not_reveal_whether_an_account_exists_or_its_state()
    {
        Skip.IfNot(Environment.GetEnvironmentVariable("SLIMIDENTITY_TIMING") == "1", "Set SLIMIDENTITY_TIMING=1 to run timing measurements.");

        await using var app = await TestApp.StartAsync(new TestAppOptions { FastHashing = false, Configure = o => o.Lockout.MaxFailedAttempts = 0 });
        var inactive = app.Users.Seed("inactive@test.local", "Inactive-123");
        app.Users.SetActive(inactive.Id, false);
        var locked = app.Users.Seed("locked@test.local", "Locked-123");
        app.Users.SetAttempts(locked.Id, SlimAttemptFactor.Password, 0, DateTimeOffset.UtcNow.AddYears(1));

        var groups = new Dictionary<string, (string Email, string Password)>
        {
            ["wrong password"] = (TestApp.UserEmail, "Wrong-Pass-123"),
            ["unknown user"] = ("nobody@test.local", "Wrong-Pass-123"),
            ["inactive user"] = ("inactive@test.local", "Inactive-123"),
            ["locked user"] = ("locked@test.local", "Locked-123"),
        };
        var samples = groups.Keys.ToDictionary(k => k, _ => new List<double>());
        var client = app.CreateClient();

        for (var i = 0; i < 20; i++)   // warm-up
            await client.PostAsync("/auth/login", new { email = TestApp.UserEmail, password = "warm-up" });

        var order = Enumerable.Range(0, SamplesPerGroup).SelectMany(_ => groups.Keys).OrderBy(_ => Random.Shared.Next()).ToList();
        foreach (var group in order)
        {
            var (email, password) = groups[group];
            var sw = Stopwatch.StartNew();
            var response = await client.PostAsync("/auth/login", new { email, password });
            sw.Stop();
            Assert.Equal(System.Net.HttpStatusCode.Unauthorized, response.StatusCode);
            samples[group].Add(sw.Elapsed.TotalMilliseconds);
        }

        var baseline = samples["wrong password"];
        foreach (var (group, values) in samples)
        {
            var z = MannWhitneyZ(baseline, values);
            output.WriteLine($"{group,-15} median {Median(values),7:F2} ms   z vs. wrong password {z,6:F2}");
            // |z| > 3.29 ⇔ p < 0.001 (two-sided): a difference that large would be measurable for an attacker
            Assert.True(Math.Abs(z) < 3.29, $"{group}: response time differs measurably from a wrong password (z = {z:F2}).");
        }
    }

    private static double Median(List<double> values)
    {
        var sorted = values.Order().ToArray();
        return (sorted[(sorted.Length - 1) / 2] + sorted[sorted.Length / 2]) / 2;
    }

    /// <summary>Normal approximation of the Mann-Whitney U statistic (ties get average ranks).</summary>
    private static double MannWhitneyZ(List<double> a, List<double> b)
    {
        var all = a.Select(v => (v, g: 0)).Concat(b.Select(v => (v, g: 1))).OrderBy(x => x.v).ToArray();
        var ranks = new double[all.Length];
        for (var i = 0; i < all.Length;)
        {
            var j = i;
            while (j + 1 < all.Length && all[j + 1].v == all[i].v) j++;
            for (var k = i; k <= j; k++) ranks[k] = (i + j) / 2.0 + 1;
            i = j + 1;
        }
        double n1 = a.Count, n2 = b.Count;
        var r1 = all.Select((x, i) => x.g == 0 ? ranks[i] : 0).Sum();
        var u = r1 - n1 * (n1 + 1) / 2;
        return (u - n1 * n2 / 2) / Math.Sqrt(n1 * n2 * (n1 + n2 + 1) / 12);
    }
}
