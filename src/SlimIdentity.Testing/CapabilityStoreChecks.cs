using Microsoft.AspNetCore.DataProtection;

namespace SlimIdentity.Testing;

internal static class TwoFactorStoreChecks
{
    private const string Store = nameof(ISlimTwoFactorStore);

    public static async Task RunAsync(ConformanceRun run)
    {
        var ct = run.Ct;
        var stores = run.Stores;

        await run.CheckAsync(Store, "stores the encrypted TOTP secret unchanged and removes it on empty string",
            "Store the string exactly as received in a text column without length limit (it is a Data Protection payload of ~200 characters); an empty string removes it.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var other = await run.NewUserAsync();
                var secret = RealisticProtectedSecret();
                var otherSecret = RealisticProtectedSecret();
                await stores.UseAsync<ISlimTwoFactorStore>(s => s.SetTotpSecretAsync(user, secret, ct));
                await stores.UseAsync<ISlimTwoFactorStore>(s => s.SetTotpSecretAsync(other, otherSecret, ct));
                Expect.Equal(secret, await stores.UseAsync<ISlimTwoFactorStore, string?>(s => s.GetTotpSecretAsync(user, ct)), "GetTotpSecretAsync");

                await stores.UseAsync<ISlimTwoFactorStore>(s => s.SetTotpSecretAsync(user, string.Empty, ct));
                Expect.True(string.IsNullOrEmpty(await stores.UseAsync<ISlimTwoFactorStore, string?>(s => s.GetTotpSecretAsync(user, ct))),
                    "GetTotpSecretAsync still returns a secret after SetTotpSecretAsync(\"\").");
                Expect.Equal(otherSecret, await stores.UseAsync<ISlimTwoFactorStore, string?>(s => s.GetTotpSecretAsync(other, ct)),
                    "the secret of another user (must stay untouched)");
            });

        await run.CheckAsync(Store, "recovery codes are single use, per user and replaced as a whole",
            "ValidateAndConsumeRecoveryCodeAsync deletes the matching row of THIS user and returns whether it existed; StoreRecoveryCodesAsync replaces all codes of the user.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var other = await run.NewUserAsync();
                string[] codes = [ConformanceRun.NewSha256Hex(), ConformanceRun.NewSha256Hex(), ConformanceRun.NewSha256Hex()];
                var otherCode = ConformanceRun.NewSha256Hex();
                await stores.UseAsync<ISlimTwoFactorStore>(s => s.StoreRecoveryCodesAsync(user, codes, ct));
                await stores.UseAsync<ISlimTwoFactorStore>(s => s.StoreRecoveryCodesAsync(other, [otherCode], ct));

                Expect.True(await Consume(user, codes[0]), "A stored recovery code was not accepted.");
                Expect.True(!await Consume(user, codes[0]), "A recovery code was accepted twice.");
                Expect.True(!await Consume(user, ConformanceRun.NewSha256Hex()), "An unknown recovery code was accepted.");
                Expect.True(!await Consume(user, otherCode), "The recovery code of another user was accepted.");

                var replacement = ConformanceRun.NewSha256Hex();
                await stores.UseAsync<ISlimTwoFactorStore>(s => s.StoreRecoveryCodesAsync(user, [replacement], ct));
                Expect.True(!await Consume(user, codes[1]), "An old recovery code still works after StoreRecoveryCodesAsync replaced them.");
                Expect.True(await Consume(user, replacement), "The new recovery code was not accepted.");

                await stores.UseAsync<ISlimTwoFactorStore>(s => s.StoreRecoveryCodesAsync(user, [], ct));
                Expect.True(!await Consume(user, codes[2]), "A recovery code still works after StoreRecoveryCodesAsync([]).");
                Expect.True(await Consume(other, otherCode), "Replacing the codes of one user removed the codes of another user.");
            });

        await run.CheckAsync(Store, "a recovery code is accepted once even under parallel requests",
            "Consume with one atomic statement (DELETE … WHERE user_id = @id AND code_hash = @hash, then check that exactly one row was deleted).",
            async () =>
            {
                var user = await run.NewUserAsync();
                var code = ConformanceRun.NewSha256Hex();
                await stores.UseAsync<ISlimTwoFactorStore>(s => s.StoreRecoveryCodesAsync(user, [code], ct));
                var results = await run.InParallelAsync(_ => Consume(user, code));
                Expect.Equal(1, results.Count(r => r), "parallel consumptions of one recovery code that succeeded");
            });

        await MonotonicChecksAsync(run, "TryMarkCodeUsedAsync", (s, u, v) => s.TryMarkCodeUsedAsync(u, v, ct),
            "UPDATE users SET last_2fa_code_at = @v WHERE id = @id AND (last_2fa_code_at IS NULL OR last_2fa_code_at < @v), then return whether a row changed (64-bit column).");
        await MonotonicChecksAsync(run, "TryMarkChallengeUsedAsync", (s, u, v) => s.TryMarkChallengeUsedAsync(u, v, ct),
            "Same compare-and-set as TryMarkCodeUsedAsync, but on its own column (last_2fa_challenge_at).");

        await run.CheckAsync(Store, "codes and challenges are tracked independently",
            "TryMarkCodeUsedAsync and TryMarkChallengeUsedAsync must use two separate columns.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                Expect.True(await stores.UseAsync<ISlimTwoFactorStore, bool>(s => s.TryMarkCodeUsedAsync(user, now + 60_000, ct)), "TryMarkCodeUsedAsync failed for a fresh user.");
                Expect.True(await stores.UseAsync<ISlimTwoFactorStore, bool>(s => s.TryMarkChallengeUsedAsync(user, now, ct)),
                    "TryMarkChallengeUsedAsync was rejected because of a later code time – both share one column.");
            });

        Task<bool> Consume(SlimUser user, string hash) =>
            stores.UseAsync<ISlimTwoFactorStore, bool>(s => s.ValidateAndConsumeRecoveryCodeAsync(user, hash, ct));
    }

    private static async Task MonotonicChecksAsync(ConformanceRun run, string method, Func<ISlimTwoFactorStore, SlimUser, long, Task<bool>> mark, string hint)
    {
        var stores = run.Stores;

        await run.CheckAsync(Store, $"{method} accepts only increasing values, per user", hint, async () =>
        {
            var user = await run.NewUserAsync();
            var other = await run.NewUserAsync();
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();   // realistic, needs a 64-bit column
            Expect.True(await Mark(user, now), $"{method}: the first value was rejected.");
            Expect.True(!await Mark(user, now), $"{method}: the same value was accepted twice (replay).");
            Expect.True(!await Mark(user, now - 30_000), $"{method}: an older value was accepted.");
            Expect.True(await Mark(user, now + 1), $"{method}: a newer value was rejected.");
            Expect.True(await Mark(other, now), $"{method}: the value of one user blocked another user.");
        });

        await run.CheckAsync(Store, $"{method} accepts a value once even under parallel requests", hint, async () =>
        {
            var user = await run.NewUserAsync();
            var value = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var results = await run.InParallelAsync(_ => Mark(user, value));
            Expect.Equal(1, results.Count(r => r), $"parallel {method} calls with the same value that succeeded");
        });

        Task<bool> Mark(SlimUser user, long value) => stores.UseAsync<ISlimTwoFactorStore, bool>(s => mark(s, user, value));
    }

    private static string RealisticProtectedSecret() =>
        new EphemeralDataProtectionProvider().CreateProtector(SlimIdentityDefaults.TotpSecretProtectionPurpose)
            .Protect(Convert.ToBase64String(RandomNumberGenerator.GetBytes(20)));
}

internal static class RefreshTokenStoreChecks
{
    private const string Store = nameof(ISlimRefreshTokenStore);

    public static async Task RunAsync(ConformanceRun run)
    {
        var ct = run.Ct;
        var stores = run.Stores;

        await run.CheckAsync(Store, "a refresh token is returned once and then gone",
            "ValidateAndConsumeRefreshTokenAsync deletes the row and returns its user id; afterwards and for unknown hashes it returns null.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var hash = ConformanceRun.NewSha256Hex();
                await stores.UseAsync<ISlimRefreshTokenStore>(s => s.StoreRefreshTokenAsync(user.Id, hash, DateTimeOffset.UtcNow.AddHours(1), ct));
                Expect.Equal(user.Id, await Consume(hash), "first consumption → user id");
                Expect.Equal<string?>(null, await Consume(hash), "second consumption");
                Expect.Equal<string?>(null, await Consume(ConformanceRun.NewSha256Hex()), "unknown hash");
            });

        await run.CheckAsync(Store, "expired refresh tokens are not returned",
            "Return null if expires_at has passed (e.g. … AND expires_at > now() in the DELETE).",
            async () =>
            {
                var user = await run.NewUserAsync();
                var hash = ConformanceRun.NewSha256Hex();
                await stores.UseAsync<ISlimRefreshTokenStore>(s => s.StoreRefreshTokenAsync(user.Id, hash, DateTimeOffset.UtcNow.AddMinutes(-5), ct));
                Expect.Equal<string?>(null, await Consume(hash), "consumption of an expired token");
            });

        await run.CheckAsync(Store, "a refresh token is consumed once even under parallel requests",
            "Consume atomically: DELETE … RETURNING user_id, or check that the DELETE affected exactly one row.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var hash = ConformanceRun.NewSha256Hex();
                await stores.UseAsync<ISlimRefreshTokenStore>(s => s.StoreRefreshTokenAsync(user.Id, hash, DateTimeOffset.UtcNow.AddHours(1), ct));
                var results = await run.InParallelAsync(_ => Consume(hash));
                Expect.Equal(1, results.Count(r => r is not null), "parallel consumptions of one refresh token that succeeded");
            });

        Task<string?> Consume(string hash) => stores.UseAsync<ISlimRefreshTokenStore, string?>(s => s.ValidateAndConsumeRefreshTokenAsync(hash, ct));
    }
}

internal static class SessionStoreChecks
{
    private const string Store = nameof(ISlimSessionStore);

    public static async Task RunAsync(ConformanceRun run)
    {
        var ct = run.Ct;
        var stores = run.Stores;

        await run.CheckAsync(Store, "stores and finds sessions",
            "Persist Id, UserId, Mode, AuthenticationMethod, ImpersonatorId and the three timestamps; FindAsync returns null for unknown ids.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var admin = await run.NewUserAsync();
                var session = NewSession(user.Id);
                session.Mode = "bearer";
                session.AuthenticationMethod = "impersonation";
                session.ImpersonatorId = admin.Id;
                await stores.UseAsync<ISlimSessionStore>(s => s.CreateAsync(session, ct));

                var found = await Find(session.Id) ?? throw new ConformanceFailure("FindAsync returned null for a stored session.");
                Expect.Equal(session.UserId, found.UserId, "UserId");
                Expect.Equal(session.Mode, found.Mode, "Mode");
                Expect.Equal(session.AuthenticationMethod, found.AuthenticationMethod, "AuthenticationMethod");
                Expect.Equal(session.ImpersonatorId, found.ImpersonatorId, "ImpersonatorId");
                Expect.SameInstant(session.CreatedUtc, found.CreatedUtc, "CreatedUtc");
                Expect.SameInstant(session.ExpiresUtc, found.ExpiresUtc, "ExpiresUtc");
                Expect.True(await Find(NewSessionId()) is null, "FindAsync returned a session for an unknown id.");
            });

        await run.CheckAsync(Store, "TouchAsync updates last-seen and expiry",
            "UPDATE … SET last_seen_utc = @lastSeen, expires_utc = @expires WHERE id = @id.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var session = NewSession(user.Id);
                await stores.UseAsync<ISlimSessionStore>(s => s.CreateAsync(session, ct));
                var lastSeen = ConformanceRun.WholeSeconds(DateTimeOffset.UtcNow.AddMinutes(5));
                var expires = ConformanceRun.WholeSeconds(DateTimeOffset.UtcNow.AddDays(2));
                await stores.UseAsync<ISlimSessionStore>(s => s.TouchAsync(session.Id, lastSeen, expires, ct));
                var found = await Find(session.Id) ?? throw new ConformanceFailure("FindAsync returned null after TouchAsync.");
                Expect.SameInstant(lastSeen, found.LastSeenUtc, "LastSeenUtc");
                Expect.SameInstant(expires, found.ExpiresUtc, "ExpiresUtc");

                await stores.UseAsync<ISlimSessionStore>(s => s.RevokeAsync(session.Id, ct));
                await stores.UseAsync<ISlimSessionStore>(s => s.TouchAsync(session.Id, lastSeen, expires, ct));
                Expect.True(await Find(session.Id) is null,
                    "TouchAsync brought a revoked session back – update existing rows only, never upsert (a refresh racing a logout would revive the session).");
            });

        await run.CheckAsync(Store, "revoked sessions are gone – one, all, or all but the current",
            "RevokeAsync deletes one session; RevokeAllAsync deletes all sessions of the user except exceptSessionId (null = all) and no others.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var other = await run.NewUserAsync();
                var a = NewSession(user.Id); var b = NewSession(user.Id); var c = NewSession(user.Id); var foreign = NewSession(other.Id);
                foreach (var s in new[] { a, b, c, foreign }) await stores.UseAsync<ISlimSessionStore>(st => st.CreateAsync(s, ct));

                await stores.UseAsync<ISlimSessionStore>(s => s.RevokeAsync(a.Id, ct));
                Expect.True(await Find(a.Id) is null, "FindAsync still returns a revoked session.");
                Expect.True(await Find(b.Id) is not null, "RevokeAsync removed another session, too.");

                await stores.UseAsync<ISlimSessionStore>(s => s.RevokeAllAsync(user.Id, b.Id, ct));
                Expect.True(await Find(b.Id) is not null, "RevokeAllAsync removed the excepted (current) session.");
                Expect.True(await Find(c.Id) is null, "RevokeAllAsync left another session of the user.");
                Expect.True(await Find(foreign.Id) is not null, "RevokeAllAsync removed a session of another user.");

                var listed = await stores.UseAsync<ISlimSessionStore, IReadOnlyCollection<SlimSession>>(s => s.ListAsync(user.Id, ct));
                Expect.True(listed.Select(s => s.Id).SequenceEqual([b.Id]), $"ListAsync should return exactly the remaining session, got {listed.Count}.");

                await stores.UseAsync<ISlimSessionStore>(s => s.RevokeAllAsync(user.Id, null, ct));
                Expect.True(await Find(b.Id) is null, "RevokeAllAsync(userId, null) left a session.");
            });

        Task<SlimSession?> Find(string id) => stores.UseAsync<ISlimSessionStore, SlimSession?>(s => s.FindAsync(id, ct));
    }

    private static string NewSessionId() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));

    private static SlimSession NewSession(string userId)
    {
        var now = ConformanceRun.WholeSeconds(DateTimeOffset.UtcNow);
        return new SlimSession
        {
            Id = NewSessionId(), UserId = userId, Mode = "cookie", AuthenticationMethod = "pwd",
            CreatedUtc = now, LastSeenUtc = now, ExpiresUtc = now.AddHours(8),
            UserAgent = "SlimIdentity.Testing", IpAddress = "192.0.2.1",
        };
    }
}

internal static class ExternalLoginStoreChecks
{
    private const string Store = nameof(ISlimExternalLoginStore);

    public static async Task RunAsync(ConformanceRun run)
    {
        var ct = run.Ct;
        var stores = run.Stores;

        await run.CheckAsync(Store, "finds users by provider and key",
            "FindByExternalLoginAsync matches provider AND provider key exactly and returns null otherwise.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var key = Guid.NewGuid().ToString("N");
                await stores.UseAsync<ISlimExternalLoginStore>(s => s.LinkExternalLoginAsync(user.Id, "SlimConformance", key, ct));

                var found = await stores.UseAsync<ISlimExternalLoginStore, SlimUser?>(s => s.FindByExternalLoginAsync("SlimConformance", key, ct));
                Expect.Equal(user.Id, found?.Id, "FindByExternalLoginAsync → Id");
                Expect.True(await stores.UseAsync<ISlimExternalLoginStore, SlimUser?>(s => s.FindByExternalLoginAsync("SlimConformanceOther", key, ct)) is null,
                    "The same key of another provider found the user.");
                Expect.True(await stores.UseAsync<ISlimExternalLoginStore, SlimUser?>(s => s.FindByExternalLoginAsync("SlimConformance", Guid.NewGuid().ToString("N"), ct)) is null,
                    "An unknown key found a user.");
            });

        await run.CheckAsync(Store, "provider keys are compared case-sensitively",
            "Subjects are opaque, case-sensitive strings. Compare them exactly – a case-insensitive database collation (SQL Server's default) would let \"Alice\" sign in as \"alice\"; re-check the key in memory or use a binary collation.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var key = $"Subject-{Guid.NewGuid():N}";
                await stores.UseAsync<ISlimExternalLoginStore>(s => s.LinkExternalLoginAsync(user.Id, "SlimConformance", key, ct));
                Expect.True(await stores.UseAsync<ISlimExternalLoginStore, SlimUser?>(s => s.FindByExternalLoginAsync("SlimConformance", key.ToLowerInvariant(), ct)) is null,
                    "A provider key differing only in case found the user.");
            });

        await run.CheckAsync(Store, "an external identity stays linked to its first user",
            "Unique index on (provider, provider_key): linking a taken identity to another user must fail (throw) or do nothing – never move it to the other account.",
            async () =>
            {
                var owner = await run.NewUserAsync();
                var intruder = await run.NewUserAsync();
                var key = Guid.NewGuid().ToString("N");
                await stores.UseAsync<ISlimExternalLoginStore>(s => s.LinkExternalLoginAsync(owner.Id, "SlimConformance", key, ct));
                try
                {
                    await stores.UseAsync<ISlimExternalLoginStore>(s => s.LinkExternalLoginAsync(intruder.Id, "SlimConformance", key, ct));
                }
#pragma warning disable CA1031 // a unique violation is the expected outcome
                catch (Exception ex) when (ex is not ConformanceFailure && !ct.IsCancellationRequested) { }
#pragma warning restore CA1031

                Expect.Equal(owner.Id, (await stores.UseAsync<ISlimExternalLoginStore, SlimUser?>(s => s.FindByExternalLoginAsync("SlimConformance", key, ct)))?.Id,
                    "FindByExternalLoginAsync after linking the same identity to a second user");
                var intruderLinks = await stores.UseAsync<ISlimExternalLoginStore, IReadOnlyList<SlimExternalLogin>>(s => s.GetExternalLoginsAsync(intruder.Id, ct));
                Expect.Equal(0, intruderLinks.Count, "links of the second user");
            });

        await run.CheckAsync(Store, "RemoveExternalLoginsAsync removes all links of one user only",
            "DELETE … WHERE user_id = @userId.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var other = await run.NewUserAsync();
                string a = Guid.NewGuid().ToString("N"), b = Guid.NewGuid().ToString("N"), c = Guid.NewGuid().ToString("N");
                await stores.UseAsync<ISlimExternalLoginStore>(s => s.LinkExternalLoginAsync(user.Id, "SlimConformanceA", a, ct));
                await stores.UseAsync<ISlimExternalLoginStore>(s => s.LinkExternalLoginAsync(user.Id, "SlimConformanceB", b, ct));
                await stores.UseAsync<ISlimExternalLoginStore>(s => s.LinkExternalLoginAsync(other.Id, "SlimConformanceA", c, ct));

                await stores.UseAsync<ISlimExternalLoginStore>(s => s.RemoveExternalLoginsAsync(user.Id, ct));

                Expect.True(await stores.UseAsync<ISlimExternalLoginStore, SlimUser?>(s => s.FindByExternalLoginAsync("SlimConformanceA", a, ct)) is null
                    && await stores.UseAsync<ISlimExternalLoginStore, SlimUser?>(s => s.FindByExternalLoginAsync("SlimConformanceB", b, ct)) is null,
                    "A link of the user survived RemoveExternalLoginsAsync.");
                Expect.Equal(other.Id, (await stores.UseAsync<ISlimExternalLoginStore, SlimUser?>(s => s.FindByExternalLoginAsync("SlimConformanceA", c, ct)))?.Id,
                    "the link of another user (must stay)");
            });

        await run.CheckAsync(Store, "GetExternalLoginsAsync lists the links of one user only",
            "SELECT provider, provider_key … WHERE user_id = @userId.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var other = await run.NewUserAsync();
                string a = Guid.NewGuid().ToString("N"), b = Guid.NewGuid().ToString("N"), c = Guid.NewGuid().ToString("N");
                await stores.UseAsync<ISlimExternalLoginStore>(s => s.LinkExternalLoginAsync(user.Id, "SlimConformanceA", a, ct));
                await stores.UseAsync<ISlimExternalLoginStore>(s => s.LinkExternalLoginAsync(user.Id, "SlimConformanceB", b, ct));
                await stores.UseAsync<ISlimExternalLoginStore>(s => s.LinkExternalLoginAsync(other.Id, "SlimConformanceA", c, ct));

                var links = await stores.UseAsync<ISlimExternalLoginStore, IReadOnlyList<SlimExternalLogin>>(s => s.GetExternalLoginsAsync(user.Id, ct));
                Expect.Equal(2, links.Count, "links of the user");
                Expect.True(links.Contains(new SlimExternalLogin("SlimConformanceA", a)) && links.Contains(new SlimExternalLogin("SlimConformanceB", b)),
                    "GetExternalLoginsAsync did not return the user's links (provider and key unchanged).");
            });

        await run.CheckAsync(Store, "RemoveExternalLoginAsync removes exactly one link of its user",
            "DELETE … WHERE user_id = @userId AND provider = @provider AND provider_key = @providerKey (key compared case-sensitively).",
            async () =>
            {
                var user = await run.NewUserAsync();
                var other = await run.NewUserAsync();
                string a = "Key" + Guid.NewGuid().ToString("N"), b = Guid.NewGuid().ToString("N"), c = Guid.NewGuid().ToString("N");
                await stores.UseAsync<ISlimExternalLoginStore>(s => s.LinkExternalLoginAsync(user.Id, "SlimConformanceA", a, ct));
                await stores.UseAsync<ISlimExternalLoginStore>(s => s.LinkExternalLoginAsync(user.Id, "SlimConformanceB", b, ct));
                await stores.UseAsync<ISlimExternalLoginStore>(s => s.LinkExternalLoginAsync(other.Id, "SlimConformanceA", c, ct));

                Expect.True(!await stores.UseAsync<ISlimExternalLoginStore, bool>(s => s.RemoveExternalLoginAsync(user.Id, "SlimConformanceA", c, ct)),
                    "RemoveExternalLoginAsync removed the link of another user.");
                Expect.True(!await stores.UseAsync<ISlimExternalLoginStore, bool>(s => s.RemoveExternalLoginAsync(user.Id, "SlimConformanceA", a.ToUpperInvariant(), ct)),
                    "RemoveExternalLoginAsync matched a key that differs in case only.");
                Expect.True(await stores.UseAsync<ISlimExternalLoginStore, bool>(s => s.RemoveExternalLoginAsync(user.Id, "SlimConformanceA", a, ct)),
                    "RemoveExternalLoginAsync did not report the removed link.");

                Expect.True(await stores.UseAsync<ISlimExternalLoginStore, SlimUser?>(s => s.FindByExternalLoginAsync("SlimConformanceA", a, ct)) is null,
                    "The removed link is still found.");
                Expect.Equal(user.Id, (await stores.UseAsync<ISlimExternalLoginStore, SlimUser?>(s => s.FindByExternalLoginAsync("SlimConformanceB", b, ct)))?.Id,
                    "the user's other link (must stay)");
                Expect.Equal(other.Id, (await stores.UseAsync<ISlimExternalLoginStore, SlimUser?>(s => s.FindByExternalLoginAsync("SlimConformanceA", c, ct)))?.Id,
                    "the link of another user (must stay)");
            });
    }
}

internal static class ApiKeyStoreChecks
{
    private const string Store = nameof(ISlimApiKeyStore);

    public static async Task RunAsync(ConformanceRun run)
    {
        var ct = run.Ct;
        var stores = run.Stores;

        await run.CheckAsync(Store, "unknown and malformed key hashes are rejected",
            "ValidateApiKeyAsync looks the hash up with '=' in a parameterized statement and returns null – never throws, never matches a prefix or pattern.",
            async () =>
            {
                foreach (var hash in new[] { ConformanceRun.NewSha256Hex(), "", "%", "_", "' OR 1=1 --", new string('f', 200) })
                {
                    var claims = await stores.UseAsync<ISlimApiKeyStore, IReadOnlyCollection<System.Security.Claims.Claim>?>(s => s.ValidateApiKeyAsync(hash, ct));
                    Expect.True(claims is null, $"ValidateApiKeyAsync returned claims for the unknown hash '{hash}'.");
                }
            });

        if (run.Options.ApiKey is not { Length: > 0 } key) return;

        await run.CheckAsync(Store, "a valid key returns its owner – and only for its exact hash",
            "Store only SlimApiKeys.Hash(key) and compare it exactly; return at least the user id claim (e.g. client:<id>) of the owner.",
            async () =>
            {
                var hash = SlimApiKeys.Hash(key);
                var claims = await stores.UseAsync<ISlimApiKeyStore, IReadOnlyCollection<System.Security.Claims.Claim>?>(s => s.ValidateApiKeyAsync(hash, ct));
                Expect.True(claims is not null, "ValidateApiKeyAsync returned null for SlimConformanceOptions.ApiKey.");
                Expect.True(claims!.Any(c => c.Type == SlimClaimTypes.UserId && !string.IsNullOrEmpty(c.Value)),
                    $"The claims of a valid key contain no {SlimClaimTypes.UserId} claim – the handler cannot tell who called.");

                foreach (var near in new[] { hash[..^1], hash + "0", hash[..^1] + (hash[^1] == '0' ? '1' : '0') })
                {
                    var other = await stores.UseAsync<ISlimApiKeyStore, IReadOnlyCollection<System.Security.Claims.Claim>?>(s => s.ValidateApiKeyAsync(near, ct));
                    Expect.True(other is null, $"ValidateApiKeyAsync accepted the hash '{near}', which differs from the key's hash.");
                }
            });
    }
}
