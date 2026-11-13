global using System.Globalization;
global using System.Security.Cryptography;
global using System.Text;

using Microsoft.Extensions.DependencyInjection;

namespace SlimIdentity.Testing;

/// <summary>Resolves stores from a fresh DI scope per operation – like one HTTP request each.</summary>
internal sealed class StoreAccess(IServiceProvider root)
{
    public bool Has<T>() =>
        root.GetService<IServiceProviderIsService>() is { } isService ? isService.IsService(typeof(T)) : root.GetService(typeof(T)) is not null;

    public async Task<TResult> UseAsync<TStore, TResult>(Func<TStore, Task<TResult>> action) where TStore : notnull
    {
        var scope = root.CreateAsyncScope();
        await using (scope.ConfigureAwait(false))
            return await action(scope.ServiceProvider.GetRequiredService<TStore>()).ConfigureAwait(false);
    }

    public Task UseAsync<TStore>(Func<TStore, Task> action) where TStore : notnull =>
        UseAsync<TStore, bool>(async s => { await action(s).ConfigureAwait(false); return true; });
}

/// <summary>Collects the results of the individual checks.</summary>
internal sealed class ConformanceRun(StoreAccess access, SlimConformanceOptions options, CancellationToken ct)
{
    private readonly List<SlimConformanceResult> _results = [];

    public StoreAccess Stores => access;
    public SlimConformanceOptions Options => options;
    public CancellationToken Ct => ct;

    public async Task CheckAsync(string store, string rule, string hint, Func<Task> body)
    {
        ct.ThrowIfCancellationRequested();
        try
        {
            await body().ConfigureAwait(false);
            _results.Add(new SlimConformanceResult(store, rule, true, null, hint));
        }
        catch (ConformanceFailure f)
        {
            _results.Add(new SlimConformanceResult(store, rule, false, f.Message, hint));
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            var inner = ex is AggregateException { InnerException: { } i } ? i : ex;
            _results.Add(new SlimConformanceResult(store, rule, false, $"threw {inner.GetType().Name}: {inner.Message}", hint));
        }
    }

    /// <summary>
    /// A check whose outcome depends on timing: run <see cref="SlimConformanceOptions.RaceRounds"/> times, each on fresh
    /// data – a check-then-write store may win a single race by chance.
    /// </summary>
    public Task CheckRaceAsync(string store, string rule, string hint, Func<Task> body) =>
        CheckAsync(store, rule, hint, async () =>
        {
            for (var round = 1; round <= options.RaceRounds; round++)
            {
                try
                {
                    await body().ConfigureAwait(false);
                }
                catch (ConformanceFailure f) when (options.RaceRounds > 1)
                {
                    throw new ConformanceFailure($"Round {round} of {options.RaceRounds}: {f.Message}");
                }
            }
        });

    /// <summary>
    /// Opens <see cref="SlimConformanceOptions.Parallelism"/> connections at once before the first race, so the races
    /// are not serialized by connections being opened one after another.
    /// </summary>
    public Task WarmUpAsync() =>
        InParallelAsync(_ => access.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByIdAsync(Guid.NewGuid().ToString(), ct)));

    public SlimConformanceReport ToReport() => new(_results.ToArray());

    // ---------------------------------------------------------------- test data

    public string NewEmail() => $"slim-{Guid.NewGuid():N}@{options.EmailDomain}";

    /// <summary>Creates a fresh user through the user store (other stores may reference it by foreign key).</summary>
    public async Task<SlimUser> NewUserAsync(string? email = null)
    {
        var address = email ?? NewEmail();
        var user = await access.UseAsync<ISlimUserStore, SlimUser?>(s => s.CreateAsync(new SlimNewUser { Email = address, PasswordHash = NewHash() }, ct)).ConfigureAwait(false);
        return user ?? throw new ConformanceFailure($"CreateAsync returned null for the new address {address}.");
    }

    public Task<SlimUser?> FindUserAsync(string id) => access.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByIdAsync(id, ct));

    public async Task<SlimUser> ReloadAsync(SlimUser user) =>
        await FindUserAsync(user.Id).ConfigureAwait(false) ?? throw new ConformanceFailure($"FindByIdAsync returned null for the existing user {user.Id}.");

    /// <summary>A realistic password-hash-like value (Identity v3 hashes are ~84 characters).</summary>
    public static string NewHash() => "AQAAAAIAAYagAAAAE" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));

    /// <summary>A SHA-256 hex value like the token / code hashes SlimIdentity hands to the stores.</summary>
    public static string NewSha256Hex() => Convert.ToHexStringLower(SHA256.HashData(RandomNumberGenerator.GetBytes(32)));

    /// <summary>A time with whole seconds – databases differ in sub-second precision.</summary>
    public static DateTimeOffset WholeSeconds(DateTimeOffset t) => DateTimeOffset.FromUnixTimeSeconds(t.ToUnixTimeSeconds());

    /// <summary>Starts <see cref="SlimConformanceOptions.Parallelism"/> operations at once and waits for all of them.</summary>
    public async Task<T[]> InParallelAsync<T>(Func<int, Task<T>> operation)
    {
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var tasks = Enumerable.Range(0, options.Parallelism)
            .Select(i => Task.Run(async () => { await start.Task.ConfigureAwait(false); return await operation(i).ConfigureAwait(false); }, ct))
            .ToArray();
        start.SetResult();   // release all at once
        return await Task.WhenAll(tasks).ConfigureAwait(false);
    }
}

/// <summary>A violated rule (expected outcome, not a crash). Internal control flow – never leaves the package.</summary>
#pragma warning disable CA1032, CA1064 // internal by design: caught inside ConformanceRun.CheckAsync, never thrown to callers
internal sealed class ConformanceFailure(string message) : Exception(message);
#pragma warning restore CA1032, CA1064

internal static class Expect
{
    public static void True(bool condition, string message)
    {
        if (!condition) throw new ConformanceFailure(message);
    }

    public static void Equal<T>(T expected, T actual, string what)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new ConformanceFailure($"{what}: expected {Show(expected)}, got {Show(actual)}.");
    }

    public static void SameInstant(DateTimeOffset? expected, DateTimeOffset? actual, string what)
    {
        var same = expected is null ? actual is null : actual is not null && Math.Abs((expected.Value - actual.Value).TotalSeconds) < 1;
        if (!same) throw new ConformanceFailure($"{what}: expected {Show(expected)}, got {Show(actual)} (compared as UTC instants).");
    }

    private static string Show<T>(T value) => value switch
    {
        null => "null",
        string s => $"\"{s}\"",
        DateTimeOffset d => d.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
        _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? "?",
    };
}
