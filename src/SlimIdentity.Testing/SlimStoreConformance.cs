using Microsoft.Extensions.DependencyInjection;

namespace SlimIdentity.Testing;

/// <summary>
/// Checks your store implementations against the contracts SlimIdentity relies on – including the ones that only
/// show under parallel requests (atomic counters, single-use tokens, unique addresses). Works with any test framework:
/// <code>
/// var services = new ServiceCollection()
///     .AddDbContext&lt;AppDbContext&gt;(o =&gt; o.UseNpgsql(testDatabase))
///     .AddScoped&lt;ISlimUserStore, MyUserStore&gt;()
///     .AddScoped&lt;ISlimTwoFactorStore, MyTwoFactorStore&gt;()
///     .BuildServiceProvider();
///
/// await SlimStoreConformance.VerifyAsync(services);   // throws with one line per violated rule
/// </code>
/// </summary>
/// <remarks>
/// <para>
/// Every registered store interface is checked: <see cref="ISlimUserStore"/> (required), <see cref="ISlimTwoFactorStore"/>,
/// <see cref="ISlimRefreshTokenStore"/>, <see cref="ISlimSessionStore"/>, <see cref="ISlimExternalLoginStore"/>, <see cref="ISlimPasskeyStore"/>
/// <see cref="ISlimApiKeyStore"/> and <see cref="ISlimSharedState"/>.
/// Each operation resolves the store from a <b>new DI scope</b>, so scoped stores with their own <c>DbContext</c> or
/// connection run truly in parallel – exactly like concurrent HTTP requests.
/// </para>
/// <para>
/// Run it against a <b>real database of the same kind as production</b> (a test instance or a container): in-memory
/// providers do not enforce unique indexes or row locks, so they prove nothing about atomicity. The checks create users
/// with addresses under <see cref="SlimConformanceOptions.EmailDomain"/> and do not delete them – never point it at
/// production data.
/// </para>
/// </remarks>
public static class SlimStoreConformance
{
    /// <summary>
    /// Runs all checks and throws <see cref="SlimStoreConformanceException"/> if at least one fails. The exception
    /// message lists every violated rule with a hint how to fix it.
    /// </summary>
    /// <param name="services">Service provider with the store implementations registered (any lifetime).</param>
    /// <param name="options">Parallelism and test e-mail domain.</param>
    /// <param name="ct">Cancellation.</param>
    /// <returns>The report (all checks passed).</returns>
    public static async Task<SlimConformanceReport> VerifyAsync(IServiceProvider services, SlimConformanceOptions? options = null, CancellationToken ct = default)
    {
        var report = await RunAsync(services, options, ct).ConfigureAwait(false);
        return report.Succeeded ? report : throw new SlimStoreConformanceException(report);
    }

    /// <summary>Runs all checks and returns the report without throwing (e.g. to print or inspect single results).</summary>
    /// <param name="services">Service provider with the store implementations registered (any lifetime).</param>
    /// <param name="options">Parallelism and test e-mail domain.</param>
    /// <param name="ct">Cancellation.</param>
    public static async Task<SlimConformanceReport> RunAsync(IServiceProvider services, SlimConformanceOptions? options = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(services);
        options ??= new SlimConformanceOptions();
        if (options.Parallelism < 2) throw new ArgumentOutOfRangeException(nameof(options), "Parallelism must be at least 2.");
        if (options.RaceRounds < 1) throw new ArgumentOutOfRangeException(nameof(options), "RaceRounds must be at least 1.");

        var access = new StoreAccess(services);
        if (!access.Has<ISlimUserStore>())
            throw new InvalidOperationException("SlimStoreConformance: no ISlimUserStore is registered in the service provider.");

        var run = new ConformanceRun(access, options, ct);
        await run.WarmUpAsync().ConfigureAwait(false);
        await UserStoreChecks.RunAsync(run).ConfigureAwait(false);
        if (access.Has<ISlimTwoFactorStore>()) await TwoFactorStoreChecks.RunAsync(run).ConfigureAwait(false);
        if (access.Has<ISlimRefreshTokenStore>()) await RefreshTokenStoreChecks.RunAsync(run).ConfigureAwait(false);
        if (access.Has<ISlimSessionStore>()) await SessionStoreChecks.RunAsync(run).ConfigureAwait(false);
        if (access.Has<ISlimExternalLoginStore>()) await ExternalLoginStoreChecks.RunAsync(run).ConfigureAwait(false);
        if (access.Has<ISlimPasskeyStore>()) await PasskeyStoreChecks.RunAsync(run).ConfigureAwait(false);
        if (access.Has<ISlimApiKeyStore>()) await ApiKeyStoreChecks.RunAsync(run).ConfigureAwait(false);
        if (access.Has<ISlimSharedState>()) await SharedStateChecks.RunAsync(run).ConfigureAwait(false);
        return run.ToReport();
    }
}

/// <summary>Options for <see cref="SlimStoreConformance"/>.</summary>
public sealed class SlimConformanceOptions
{
    /// <summary>Number of parallel calls in the concurrency checks (at least 2). Default 8.</summary>
    public int Parallelism { get; set; } = 8;

    /// <summary>
    /// How often each concurrency check runs, each time on fresh data (at least 1). Default 5: a store that checks
    /// first and writes afterwards can win a single race by chance.
    /// </summary>
    public int RaceRounds { get; set; } = 5;

    /// <summary>
    /// Domain of the generated test addresses (<c>slim-&lt;guid&gt;@domain</c>). Default <c>conformance.invalid</c>
    /// (the reserved <c>.invalid</c> TLD can never receive mail).
    /// </summary>
    public string EmailDomain { get; set; } = "conformance.invalid";

    /// <summary>
    /// A valid key (clear text) of your <see cref="ISlimApiKeyStore"/>, e.g. one created by the test setup. The kit cannot
    /// create keys itself: without it, only unknown and malformed hashes are checked.
    /// </summary>
    public string? ApiKey { get; set; }
}

/// <summary>Result of one conformance rule.</summary>
/// <param name="Store">The interface, e.g. <c>ISlimUserStore</c>.</param>
/// <param name="Rule">What was checked.</param>
/// <param name="Passed">Whether the store honours the rule.</param>
/// <param name="Failure">What went wrong (null if passed).</param>
/// <param name="Hint">How a correct implementation looks.</param>
public sealed record SlimConformanceResult(string Store, string Rule, bool Passed, string? Failure, string Hint);

/// <summary>All results of a conformance run.</summary>
public sealed class SlimConformanceReport
{
    internal SlimConformanceReport(IReadOnlyList<SlimConformanceResult> results) => Results = results;

    /// <summary>Every executed check in order.</summary>
    public IReadOnlyList<SlimConformanceResult> Results { get; }

    /// <summary>The failed checks.</summary>
    public IEnumerable<SlimConformanceResult> Failures => Results.Where(r => !r.Passed);

    /// <summary>True if every check passed.</summary>
    public bool Succeeded => Results.All(r => r.Passed);

    /// <summary>A readable summary: one line per check, failures with their hint.</summary>
    public override string ToString()
    {
        var sb = new StringBuilder();
        var failed = Results.Count(r => !r.Passed);
        sb.Append(CultureInfo.InvariantCulture, $"SlimIdentity store conformance: {Results.Count - failed} of {Results.Count} checks passed.");
        foreach (var r in Results)
        {
            sb.AppendLine();
            sb.Append(r.Passed ? "  ok    " : "  FAIL  ").Append(r.Store).Append(": ").Append(r.Rule);
            if (r.Passed) continue;
            sb.AppendLine().Append("          ").Append(r.Failure);
            sb.AppendLine().Append("          fix: ").Append(r.Hint);
        }
        return sb.ToString();
    }
}

/// <summary>Thrown by <see cref="SlimStoreConformance.VerifyAsync"/> if a store violates its contract.</summary>
public sealed class SlimStoreConformanceException : Exception
{
    /// <summary>Creates the exception for a failed report.</summary>
    public SlimStoreConformanceException(SlimConformanceReport report) : base(report?.ToString()) =>
        Report = report ?? throw new ArgumentNullException(nameof(report));

    /// <summary>Creates the exception without a report.</summary>
    public SlimStoreConformanceException() : this("SlimIdentity store conformance failed.") { }

    /// <summary>Creates the exception with a message and without a report.</summary>
    public SlimStoreConformanceException(string message) : base(message) => Report = new SlimConformanceReport([]);

    /// <summary>Creates the exception with a message and an inner exception, without a report.</summary>
    public SlimStoreConformanceException(string message, Exception innerException) : base(message, innerException) =>
        Report = new SlimConformanceReport([]);

    /// <summary>The complete report, including the passed checks.</summary>
    public SlimConformanceReport Report { get; }
}
