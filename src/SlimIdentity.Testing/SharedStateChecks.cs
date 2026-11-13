namespace SlimIdentity.Testing;

internal static class SharedStateChecks
{
    private const string Store = nameof(ISlimSharedState);

    public static async Task RunAsync(ConformanceRun run)
    {
        var ct = run.Ct;
        var stores = run.Stores;

        await run.CheckAsync(Store, "a marker is added once",
            "TryAddAsync inserts the key and returns true; while it has not expired every further call returns false (primary key on the key).",
            async () =>
            {
                var key = ConformanceRun.NewSha256Hex();
                Expect.True(await TryAdd(key, DateTimeOffset.UtcNow.AddMinutes(5)), "first TryAddAsync returned false");
                Expect.True(!await TryAdd(key, DateTimeOffset.UtcNow.AddMinutes(5)), "second TryAddAsync returned true");
            });

        await run.CheckAsync(Store, "an expired marker counts as absent",
            "Treat a row whose expiry has passed like a missing one: take it over (UPDATE … WHERE key = @key AND expires_at <= now) instead of failing on the primary key.",
            async () =>
            {
                var key = ConformanceRun.NewSha256Hex();
                Expect.True(await TryAdd(key, DateTimeOffset.UtcNow.AddMinutes(-1)), "TryAddAsync with a past expiry returned false");
                Expect.True(await TryAdd(key, DateTimeOffset.UtcNow.AddMinutes(5)), "TryAddAsync over an expired marker returned false");
                Expect.True(!await TryAdd(key, DateTimeOffset.UtcNow.AddMinutes(5)), "TryAddAsync over a live marker returned true");
            });

        await run.CheckAsync(Store, "keys of 128 characters are accepted",
            "Store keys of up to 128 ASCII characters (e.g. varchar(128)).",
            async () =>
            {
                var key = ConformanceRun.NewSha256Hex() + ConformanceRun.NewSha256Hex();
                Expect.True(await TryAdd(key, DateTimeOffset.UtcNow.AddMinutes(5)), "TryAddAsync with a 128-character key returned false");
                var counter = ConformanceRun.NewSha256Hex() + ConformanceRun.NewSha256Hex();
                Expect.Equal(1L, await Increment(counter, TimeSpan.FromMinutes(5)), "IncrementAsync with a 128-character key");
            });

        await run.CheckRaceAsync(Store, "a marker is added once even under parallel requests",
            "Rely on the primary key (INSERT … ON CONFLICT DO NOTHING, or catch the duplicate-key error) – never check first and insert afterwards.",
            async () =>
            {
                var key = ConformanceRun.NewSha256Hex();
                var results = await run.InParallelAsync(_ => TryAdd(key, DateTimeOffset.UtcNow.AddMinutes(5)));
                Expect.Equal(1, results.Count(r => r), "parallel TryAddAsync calls that returned true");
            });

        await run.CheckAsync(Store, "a counter counts up per key",
            "IncrementAsync adds one and returns the new value: 1, 2, 3 … – separately for every key.",
            async () =>
            {
                var key = ConformanceRun.NewSha256Hex();
                var other = ConformanceRun.NewSha256Hex();
                Expect.Equal(1L, await Increment(key, TimeSpan.FromMinutes(5)), "first increment");
                Expect.Equal(2L, await Increment(key, TimeSpan.FromMinutes(5)), "second increment");
                Expect.Equal(1L, await Increment(other, TimeSpan.FromMinutes(5)), "first increment of another key");
                Expect.Equal(3L, await Increment(key, TimeSpan.FromMinutes(5)), "third increment");
            });

        await run.CheckAsync(Store, "a counter restarts at 1 after its window",
            "Fixed window: the first increment sets expires_at = now + window; an increment after it starts again at 1.",
            async () =>
            {
                var key = ConformanceRun.NewSha256Hex();
                var window = TimeSpan.FromMilliseconds(300);
                await Increment(key, window);
                await Increment(key, window);
                await Task.Delay(window * 2, ct).ConfigureAwait(false);
                Expect.Equal(1L, await Increment(key, window), "increment after the window");
            });

        await run.CheckRaceAsync(Store, "a counter loses no increment under parallel requests",
            "Increment atomically (UPDATE … SET count = count + 1 … RETURNING count, or compare-and-set) – never read, add and write back.",
            async () =>
            {
                var key = ConformanceRun.NewSha256Hex();
                var results = await run.InParallelAsync(_ => Increment(key, TimeSpan.FromMinutes(5)));
                var expected = Enumerable.Range(1, results.Length).Select(i => (long)i);
                Expect.True(results.Order().SequenceEqual(expected),
                    $"parallel increments returned {string.Join(", ", results.Order())} instead of 1 … {results.Length}");
            });

        Task<bool> TryAdd(string key, DateTimeOffset expiresAt) => stores.UseAsync<ISlimSharedState, bool>(s => s.TryAddAsync(key, expiresAt, ct));
        Task<long> Increment(string key, TimeSpan window) => stores.UseAsync<ISlimSharedState, long>(s => s.IncrementAsync(key, window, ct));
    }
}
