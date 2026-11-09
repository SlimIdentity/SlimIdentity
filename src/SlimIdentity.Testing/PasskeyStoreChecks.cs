namespace SlimIdentity.Testing;

internal static class PasskeyStoreChecks
{
    private const string Store = nameof(ISlimPasskeyStore);

    private static SlimPasskey NewPasskey(string userId, uint signCount = 0) => new()
    {
        UserId = userId,
        CredentialId = RandomNumberGenerator.GetBytes(32),
        PublicKey = RandomNumberGenerator.GetBytes(77),
        SignCount = signCount,
        Name = "Conformance key",
        CreatedUtc = ConformanceRun.WholeSeconds(DateTimeOffset.UtcNow),
    };

    public static async Task RunAsync(ConformanceRun run)
    {
        var ct = run.Ct;
        var stores = run.Stores;

        await run.CheckAsync(Store, "stores, finds and lists passkeys of one user only",
            "AddPasskeyAsync stores every field; FindPasskeyAsync by credential id (exact bytes); GetPasskeysAsync WHERE user_id = @userId.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var other = await run.NewUserAsync();
                var mine = NewPasskey(user.Id, signCount: 7);
                var theirs = NewPasskey(other.Id);
                Expect.True(await stores.UseAsync<ISlimPasskeyStore, bool>(s => s.AddPasskeyAsync(mine, ct)), "AddPasskeyAsync returned false for a new credential.");
                await stores.UseAsync<ISlimPasskeyStore, bool>(s => s.AddPasskeyAsync(theirs, ct));

                var found = await stores.UseAsync<ISlimPasskeyStore, SlimPasskey?>(s => s.FindPasskeyAsync(mine.CredentialId, ct));
                Expect.Equal(user.Id, found?.UserId, "FindPasskeyAsync → UserId");
                Expect.True(found is not null && found.PublicKey.AsSpan().SequenceEqual(mine.PublicKey), "The public key came back changed.");
                Expect.Equal(7u, found?.SignCount, "SignCount");
                Expect.Equal("Conformance key", found?.Name, "Name");
                Expect.SameInstant(mine.CreatedUtc, found?.CreatedUtc, "CreatedUtc");

                var shorter = mine.CredentialId[..^1];
                Expect.True(await stores.UseAsync<ISlimPasskeyStore, SlimPasskey?>(s => s.FindPasskeyAsync(shorter, ct)) is null,
                    "FindPasskeyAsync matched a different (prefix) credential id.");

                var listed = await stores.UseAsync<ISlimPasskeyStore, IReadOnlyList<SlimPasskey>>(s => s.GetPasskeysAsync(user.Id, ct));
                Expect.Equal(1, listed.Count, "passkeys of the user");
            });

        await run.CheckAsync(Store, "a credential id is registered once",
            "Unique index on the credential id; AddPasskeyAsync returns false instead of throwing – also in parallel.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var passkey = NewPasskey(user.Id);
                var results = await run.InParallelAsync(_ => stores.UseAsync<ISlimPasskeyStore, bool>(s => s.AddPasskeyAsync(new SlimPasskey
                {
                    UserId = user.Id, CredentialId = passkey.CredentialId, PublicKey = passkey.PublicKey, Name = passkey.Name, CreatedUtc = passkey.CreatedUtc,
                }, ct)));
                Expect.Equal(1, results.Count(r => r), "successful AddPasskeyAsync calls with one credential id");
            });

        await run.CheckAsync(Store, "TryRecordUseAsync is single use and compare-and-set",
            "One statement: UPDATE … WHERE credential_id = @id AND sign_count = @expected AND (last_challenge_at IS NULL OR last_challenge_at < @issuedAt).",
            async () =>
            {
                var user = await run.NewUserAsync();
                var passkey = NewPasskey(user.Id);
                await stores.UseAsync<ISlimPasskeyStore, bool>(s => s.AddPasskeyAsync(passkey, ct));
                var used = ConformanceRun.WholeSeconds(DateTimeOffset.UtcNow);

                Expect.True(await stores.UseAsync<ISlimPasskeyStore, bool>(s => s.TryRecordUseAsync(passkey.CredentialId, 0, 1, 1_000, used, ct)), "first use refused");
                Expect.True(!await stores.UseAsync<ISlimPasskeyStore, bool>(s => s.TryRecordUseAsync(passkey.CredentialId, 1, 2, 1_000, used, ct)), "the same challenge was accepted twice");
                Expect.True(!await stores.UseAsync<ISlimPasskeyStore, bool>(s => s.TryRecordUseAsync(passkey.CredentialId, 1, 2, 999, used, ct)), "an older challenge was accepted");
                Expect.True(!await stores.UseAsync<ISlimPasskeyStore, bool>(s => s.TryRecordUseAsync(passkey.CredentialId, 0, 2, 2_000, used, ct)), "an outdated expected counter was accepted");
                Expect.True(await stores.UseAsync<ISlimPasskeyStore, bool>(s => s.TryRecordUseAsync(passkey.CredentialId, 1, 2, 2_000, used, ct)), "a newer challenge was refused");

                var stored = await stores.UseAsync<ISlimPasskeyStore, SlimPasskey?>(s => s.FindPasskeyAsync(passkey.CredentialId, ct));
                Expect.Equal(2u, stored?.SignCount, "SignCount after use");
                Expect.Equal(2_000L, stored?.LastChallengeAt, "LastChallengeAt after use");
                Expect.SameInstant(used, stored?.LastUsedUtc, "LastUsedUtc after use");

                var parallel = await run.InParallelAsync(i =>
                    stores.UseAsync<ISlimPasskeyStore, bool>(s => s.TryRecordUseAsync(passkey.CredentialId, 2, 3, 3_000 + i, used, ct)));
                Expect.Equal(1, parallel.Count(r => r), "parallel uses with the same expected counter that succeeded");
            });

        await run.CheckAsync(Store, "renames and removes passkeys of their own user only",
            "UPDATE / DELETE … WHERE credential_id = @id AND user_id = @userId.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var other = await run.NewUserAsync();
                var passkey = NewPasskey(user.Id);
                await stores.UseAsync<ISlimPasskeyStore, bool>(s => s.AddPasskeyAsync(passkey, ct));

                Expect.True(!await stores.UseAsync<ISlimPasskeyStore, bool>(s => s.RenamePasskeyAsync(other.Id, passkey.CredentialId, "Stolen", ct)), "renamed another user's passkey");
                Expect.True(!await stores.UseAsync<ISlimPasskeyStore, bool>(s => s.RemovePasskeyAsync(other.Id, passkey.CredentialId, ct)), "removed another user's passkey");
                Expect.True(await stores.UseAsync<ISlimPasskeyStore, bool>(s => s.RenamePasskeyAsync(user.Id, passkey.CredentialId, "Laptop", ct)), "rename refused");
                Expect.Equal("Laptop", (await stores.UseAsync<ISlimPasskeyStore, SlimPasskey?>(s => s.FindPasskeyAsync(passkey.CredentialId, ct)))?.Name, "Name after rename");
                Expect.True(await stores.UseAsync<ISlimPasskeyStore, bool>(s => s.RemovePasskeyAsync(user.Id, passkey.CredentialId, ct)), "remove refused");
                Expect.True(await stores.UseAsync<ISlimPasskeyStore, SlimPasskey?>(s => s.FindPasskeyAsync(passkey.CredentialId, ct)) is null, "The removed passkey is still found.");
            });
    }
}
