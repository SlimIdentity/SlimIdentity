namespace SlimIdentity.Testing;

internal static class UserStoreChecks
{
    private const string Store = nameof(ISlimUserStore);

    public static async Task RunAsync(ConformanceRun run)
    {
        var ct = run.Ct;
        var stores = run.Stores;

        await run.CheckAsync(Store, "creates users and finds them by id and e-mail",
            "CreateAsync returns the persisted user with its generated Id and a security stamp; FindByIdAsync / FindByEmailAsync return null for unknown users and malformed ids.",
            async () =>
            {
                var email = run.NewEmail();
                var created = await run.NewUserAsync(email);
                Expect.True(!string.IsNullOrEmpty(created.Id), "CreateAsync returned a user without Id.");
                Expect.Equal(email, created.Email, "Email of the created user");

                var byId = await run.ReloadAsync(created);
                Expect.Equal(email, byId.Email, "FindByIdAsync → Email");
                Expect.True(!string.IsNullOrEmpty(byId.SecurityStamp), "The persisted user has no SecurityStamp – store the value of SlimUser.NewSecurityStamp() on create.");
                Expect.True(byId.IsActive, "A new user must be active (IsActive = true).");

                var byEmail = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByEmailAsync(email, ct));
                Expect.Equal(created.Id, byEmail?.Id, "FindByEmailAsync → Id");

                var unknownId = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByIdAsync(Guid.NewGuid().ToString(), ct));
                Expect.True(unknownId is null, "FindByIdAsync returned a user for an unknown id.");
                // ids from tokens are input: another key format (an old token after a migration, a forged one) is "not found"
                foreach (var malformed in new[] { "not-a-valid-id", "", "0x' OR 1=1 --", new string('9', 40) })
                {
                    var found = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByIdAsync(malformed, ct));
                    Expect.True(found is null, $"FindByIdAsync returned a user for the malformed id '{malformed}'.");
                }
                var unknownEmail = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByEmailAsync(run.NewEmail(), ct));
                Expect.True(unknownEmail is null, "FindByEmailAsync returned a user for an unknown address.");
            });

        await run.CheckAsync(Store, "looks up e-mail addresses case-insensitively",
            "Store a normalized (upper-cased) address in its own column with a unique index and search that column.",
            async () =>
            {
                var email = $"Slim.Mixed-{Guid.NewGuid():N}@{run.Options.EmailDomain}";
                var user = await run.NewUserAsync(email);
                foreach (var variant in new[] { email.ToUpperInvariant(), email.ToLowerInvariant() })
                {
                    var found = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByEmailAsync(variant, ct));
                    Expect.Equal(user.Id, found?.Id, $"FindByEmailAsync(\"{variant}\") → Id");
                }
            });

        await run.CheckAsync(Store, "compares e-mail addresses case-insensitively beyond ASCII",
            "Normalize in .NET with ToUpperInvariant() and compare the normalized column with '='. Database functions and collations may fold ASCII only (SQLite NOCASE, UPPER() without ICU) and treat É and é as different addresses.",
            async () =>
            {
                var email = $"Élodie.Ærø-{Guid.NewGuid():N}@{run.Options.EmailDomain}";
                var user = await run.NewUserAsync(email);
                foreach (var variant in new[] { email.ToUpperInvariant(), email.ToLowerInvariant() })
                {
                    var found = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByEmailAsync(variant, ct));
                    Expect.Equal(user.Id, found?.Id, $"FindByEmailAsync(\"{variant}\") → Id");
                }
                var duplicate = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.CreateAsync(new SlimNewUser { Email = email.ToLowerInvariant(), PasswordHash = ConformanceRun.NewHash() }, ct));
                Expect.True(duplicate is null, "CreateAsync created a second account for the same address with lower-case non-ASCII letters.");
            });

        await run.CheckAsync(Store, "treats quotes, SQL metacharacters and LIKE wildcards in addresses as plain text",
            "Use parameterized statements only (never build SQL from the address) and compare with '=' – not LIKE, whose '%' and '_' would match other addresses.",
            async () =>
            {
                var id = Guid.NewGuid().ToString("N");
                var tricky = $"o'brien'--/*{id}*/@{run.Options.EmailDomain}";   // a valid address, also for a CHECK constraint
                var user = await run.NewUserAsync(tricky);
                var found = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByEmailAsync(tricky, ct));
                Expect.Equal(user.Id, found?.Id, "FindByEmailAsync with quotes and comment characters");

                var underscore = await run.NewUserAsync($"wild_card-{id}@{run.Options.EmailDomain}");
                var wildcard = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByEmailAsync($"wild%card-{id}@{run.Options.EmailDomain}", ct));
                Expect.True(wildcard is null, "FindByEmailAsync(\"wild%card…\") found \"wild_card…\" – the lookup interprets LIKE wildcards.");
                var single = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByEmailAsync($"wildXcard-{id}@{run.Options.EmailDomain}", ct));
                Expect.True(single is null, "FindByEmailAsync(\"wildXcard…\") found \"wild_card…\" – '_' is treated as a wildcard.");
                Expect.Equal(underscore.Id, (await run.ReloadAsync(underscore)).Id, "the user with '_' in the address");
            });

        await run.CheckAsync(Store, "CreateAsync returns null for a taken address (any casing)",
            "Let the unique index on the normalized address decide; catch the unique violation (or use ON CONFLICT DO NOTHING) and return null.",
            async () =>
            {
                var email = run.NewEmail();
                var first = await run.NewUserAsync(email);
                var duplicate = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.CreateAsync(new SlimNewUser { Email = email.ToUpperInvariant(), PasswordHash = ConformanceRun.NewHash() }, ct));
                Expect.True(duplicate is null, "CreateAsync created a second account for the same address (different casing).");
                var found = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByEmailAsync(email, ct));
                Expect.Equal(first.Id, found?.Id, "the original account after the duplicate attempt");
            });

        await run.CheckRaceAsync(Store, "parallel registrations of one address create exactly one account",
            "Do not check for existence first – insert and let the unique index on the normalized address reject the losers (also for other casings); return null for them instead of throwing.",
            async () =>
            {
                var email = $"Slim.Race-{Guid.NewGuid():N}@{run.Options.EmailDomain}";
                var results = await run.InParallelAsync(i =>
                    stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.CreateAsync(new SlimNewUser { Email = i % 2 == 0 ? email : email.ToLowerInvariant(), PasswordHash = ConformanceRun.NewHash() }, ct)));
                Expect.Equal(1, results.Count(u => u is not null), "accounts created by parallel CreateAsync calls (two casings of one address)");
            });

        await run.CheckAsync(Store, "a new user starts unconfirmed, unlocked and without 2FA",
            "Insert the given PasswordHash and a fresh SecurityStamp; EmailConfirmed = false, both attempt counters 0, both lockout ends null, TwoFactorEnabled = false, PasswordChangeRequired = false – no column defaults that grant more.",
            async () =>
            {
                var hash = ConformanceRun.NewHash();
                var created = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.CreateAsync(new SlimNewUser { Email = run.NewEmail(), PasswordHash = hash }, ct))
                    ?? throw new ConformanceFailure("CreateAsync returned null for a new address.");
                var saved = await run.ReloadAsync(created);
                Expect.Equal(hash, saved.PasswordHash, "PasswordHash");
                Expect.Equal(false, saved.EmailConfirmed, "EmailConfirmed");
                Expect.Equal(0, saved.FailedLoginAttempts, "FailedLoginAttempts");
                Expect.SameInstant(null, saved.LockoutEndUtc, "LockoutEndUtc");
                Expect.Equal(0, saved.FailedSecondFactorAttempts, "FailedSecondFactorAttempts");
                Expect.SameInstant(null, saved.SecondFactorLockoutEndUtc, "SecondFactorLockoutEndUtc");
                Expect.Equal(false, saved.TwoFactorEnabled, "TwoFactorEnabled");
                Expect.Equal(false, saved.PasswordChangeRequired, "PasswordChangeRequired");

                var other = await run.NewUserAsync();
                Expect.True(other.SecurityStamp != created.SecurityStamp && (await run.ReloadAsync(other)).SecurityStamp != saved.SecurityStamp,
                    "Two new users got the same SecurityStamp – store the value of the SlimUser, not a constant default.");
            });

        await run.CheckAsync(Store, "UpdateSecurityStateAsync persists all security fields",
            "Write PasswordHash, SecurityStamp, EmailConfirmed, TwoFactorEnabled and PasswordChangeRequired and return true when the stored stamp equals the expected one.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var expected = user.SecurityStamp;
                user.PasswordHash = ConformanceRun.NewHash();
                user.SecurityStamp = SlimUser.NewSecurityStamp();
                user.EmailConfirmed = true;
                user.TwoFactorEnabled = true;
                user.PasswordChangeRequired = true;
                Expect.True(await WriteStateAsync(user, expected), "UpdateSecurityStateAsync returned false although the stamp was unchanged.");

                var saved = await run.ReloadAsync(user);
                Expect.Equal(user.PasswordHash, saved.PasswordHash, "PasswordHash");
                Expect.Equal(user.SecurityStamp, saved.SecurityStamp, "SecurityStamp");
                Expect.Equal(true, saved.EmailConfirmed, "EmailConfirmed");
                Expect.Equal(true, saved.TwoFactorEnabled, "TwoFactorEnabled");
                Expect.Equal(true, saved.PasswordChangeRequired, "PasswordChangeRequired");

                // and back: cleared values must be written, too (no "only if not null" updates)
                user.EmailConfirmed = false;
                user.TwoFactorEnabled = false;
                user.PasswordChangeRequired = false;
                user.PasswordHash = string.Empty;
                expected = user.SecurityStamp;
                user.SecurityStamp = SlimUser.NewSecurityStamp();
                Expect.True(await WriteStateAsync(user, expected), "UpdateSecurityStateAsync returned false although the stamp was unchanged.");

                var cleared = await run.ReloadAsync(user);
                Expect.Equal(false, cleared.EmailConfirmed, "EmailConfirmed after clearing");
                Expect.Equal(false, cleared.TwoFactorEnabled, "TwoFactorEnabled after clearing");
                Expect.Equal(false, cleared.PasswordChangeRequired, "PasswordChangeRequired after clearing");
                Expect.True(string.IsNullOrEmpty(cleared.PasswordHash), "PasswordHash after removing the password (empty) – the old hash is still stored.");
            });

        await run.CheckAsync(Store, "UpdateSecurityStateAsync leaves IsActive and the address alone",
            "Write only the five security fields and the stamp – never the whole user. A copy read before an administrator blocked the account must not unblock it, and the address changes only through UpdateEmailAsync.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var stale = await run.ReloadAsync(user);
                var expected = stale.SecurityStamp;
                stale.IsActive = false;
                stale.Email = run.NewEmail();
                stale.SecurityStamp = SlimUser.NewSecurityStamp();
                Expect.True(await WriteStateAsync(stale, expected), "UpdateSecurityStateAsync returned false although the stamp was unchanged.");

                var saved = await run.ReloadAsync(user);
                Expect.Equal(true, saved.IsActive, "IsActive after UpdateSecurityStateAsync with IsActive = false (must stay)");
                Expect.Equal(user.Email, saved.Email, "Email after UpdateSecurityStateAsync with another address (must stay)");
                Expect.Equal(user.Id, (await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByEmailAsync(user.Email, ct)))?.Id,
                    "FindByEmailAsync(original address) after UpdateSecurityStateAsync");
                Expect.True(await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByEmailAsync(stale.Email, ct)) is null,
                    "UpdateSecurityStateAsync wrote the address of the user object – it changes only through UpdateEmailAsync.");
            });

        await run.CheckAsync(Store, "UpdateSecurityStateAsync writes only while the whole stamp is unchanged",
            "UPDATE … WHERE id = @id AND COALESCE(security_stamp, '') = @expectedStamp; return affected rows = 1. Compare the whole stamp, claims part included – a copy read before any other change must never be written back over it.",
            async () =>
            {
                var stale = await run.NewUserAsync();
                var original = stale.SecurityStamp;

                // another request changes only the claims part (roles) – the outdated copy must still lose
                var fresh = await run.ReloadAsync(stale);
                var claimsOnly = $"{original.Split('.')[0]}.C1A1";   // same security part, new claims part
                Expect.True(await stores.UseAsync<ISlimUserStore, bool>(s => s.UpdateSecurityStampAsync(fresh, original, claimsOnly, ct)),
                    "UpdateSecurityStampAsync returned false although the stamp was unchanged.");

                stale.PasswordHash = ConformanceRun.NewHash();
                stale.SecurityStamp = SlimUser.NewSecurityStamp();
                Expect.True(!await WriteStateAsync(stale, original), "UpdateSecurityStateAsync returned true although the claims part of the stamp changed in between.");
                var kept = await run.ReloadAsync(stale);
                Expect.Equal(claimsOnly, kept.SecurityStamp, "SecurityStamp after a refused write");
                Expect.Equal(fresh.PasswordHash, kept.PasswordHash, "PasswordHash after a refused write (must stay unchanged)");

                // and a change of the security part
                var rotated = SlimUser.NewSecurityStamp();
                Expect.True(await stores.UseAsync<ISlimUserStore, bool>(s => s.UpdateSecurityStampAsync(fresh, claimsOnly, rotated, ct)),
                    "UpdateSecurityStampAsync returned false although the stamp was unchanged.");
                Expect.True(!await WriteStateAsync(stale, claimsOnly), "UpdateSecurityStateAsync returned true for an outdated security part.");
                Expect.Equal(rotated, (await run.ReloadAsync(stale)).SecurityStamp, "SecurityStamp after a refused write");
            });

        await run.CheckRaceAsync(Store, "of parallel UpdateSecurityStateAsync calls from one stamp exactly one wins",
            "The stamp comparison and the write must be one atomic UPDATE – never read the stamp, compare in code and write afterwards.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var expected = user.SecurityStamp;
                var hashes = Enumerable.Range(0, run.Options.Parallelism).Select(_ => ConformanceRun.NewHash()).ToArray();
                var results = await run.InParallelAsync(i => WriteStateAsync(new SlimUser
                {
                    Id = user.Id, Email = user.Email, PasswordHash = hashes[i], SecurityStamp = SlimUser.NewSecurityStamp(),
                }, expected));
                Expect.Equal(1, results.Count(r => r), "parallel writes from the same stamp that succeeded");
                Expect.Equal(hashes[Array.IndexOf(results, true)], (await run.ReloadAsync(user)).PasswordHash, "PasswordHash (must be the one of the winning write)");
            });

        await run.CheckRaceAsync(Store, "UpdateSecurityStampAsync replaces only the stamp and only if it is unchanged",
            "UPDATE users SET security_stamp = @newStamp WHERE id = @id AND security_stamp = @expectedStamp; return affected rows = 1. Never write other columns.",
            async () =>
            {
                var stale = await run.NewUserAsync();
                var original = (await run.ReloadAsync(stale)).SecurityStamp;

                // another request changes the password in the meantime – the stamp rotation must not undo it
                var fresh = await run.ReloadAsync(stale);
                fresh.PasswordHash = ConformanceRun.NewHash();
                Expect.True(await WriteStateAsync(fresh, original), "UpdateSecurityStateAsync returned false although the stamp was unchanged.");

                var rotated = SlimUser.NewSecurityStamp();
                Expect.True(await stores.UseAsync<ISlimUserStore, bool>(s => s.UpdateSecurityStampAsync(stale, original, rotated, ct)),
                    "UpdateSecurityStampAsync returned false although the stamp was unchanged.");
                var saved = await run.ReloadAsync(stale);
                Expect.Equal(rotated, saved.SecurityStamp, "SecurityStamp after the rotation");
                Expect.Equal(fresh.PasswordHash, saved.PasswordHash, "PasswordHash after the rotation (must stay – only the stamp is written)");

                Expect.True(!await stores.UseAsync<ISlimUserStore, bool>(s => s.UpdateSecurityStampAsync(stale, original, SlimUser.NewSecurityStamp(), ct)),
                    "UpdateSecurityStampAsync returned true for an outdated expected stamp.");
                Expect.Equal(rotated, (await run.ReloadAsync(stale)).SecurityStamp, "SecurityStamp after a rotation with an outdated stamp (must stay unchanged)");

                var parallel = await run.InParallelAsync(_ =>
                    stores.UseAsync<ISlimUserStore, bool>(s => s.UpdateSecurityStampAsync(stale, rotated, SlimUser.NewSecurityStamp(), ct)));
                Expect.Equal(1, parallel.Count(r => r), "parallel rotations from the same stamp that succeeded");
            });

        await run.CheckAsync(Store, "UpdateSecurityStateAsync never writes the attempt counters",
            "Leave FailedLoginAttempts, LockoutEndUtc, FailedSecondFactorAttempts and SecondFactorLockoutEndUtc out of the UPDATE – an outdated copy of the user must not undo counted attempts or lift a lockout.",
            async () =>
            {
                var stale = await run.NewUserAsync();
                var now = ConformanceRun.WholeSeconds(DateTimeOffset.UtcNow);
                await ReserveAsync(stale, SlimAttemptFactor.Password, now, 1);              // locks the password
                await ReserveAsync(stale, SlimAttemptFactor.SecondFactor, now, 100);        // counts one second-factor attempt

                stale.EmailConfirmed = true;   // a deliberate change from a copy read before the attempts
                Expect.True(await WriteStateAsync(stale, stale.SecurityStamp), "UpdateSecurityStateAsync returned false although the stamp was unchanged.");

                var saved = await run.ReloadAsync(stale);
                Expect.Equal(true, saved.EmailConfirmed, "EmailConfirmed");
                Expect.Equal(1, saved.FailedLoginAttempts, "FailedLoginAttempts after UpdateSecurityStateAsync with an outdated copy (must stay)");
                Expect.True(saved.LockoutEndUtc is not null, "UpdateSecurityStateAsync with an outdated copy lifted the password lockout.");
                Expect.Equal(1, saved.FailedSecondFactorAttempts, "FailedSecondFactorAttempts after UpdateSecurityStateAsync with an outdated copy (must stay)");
            });

        await run.CheckRaceAsync(Store, "TryBeginAttemptAsync reserves parallel attempts atomically",
            "Read and write counter and lockout end in one atomic step: a row lock (SELECT … FOR UPDATE) in a transaction, or a compare-and-set UPDATE … WHERE counter = @old AND lockout_end IS NOT DISTINCT FROM @oldEnd, retried on 0 rows. Never read, add and write back.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var n = run.Options.Parallelism;
                var now = ConformanceRun.WholeSeconds(DateTimeOffset.UtcNow);
                var results = await run.InParallelAsync(_ => ReserveAsync(user, SlimAttemptFactor.Password, now, 1000));
                var counts = results.Where(r => r is { IsLockedOut: false }).Select(r => r!.FailedAttempts).Order().ToList();
                var saved = await run.ReloadAsync(user);
                Expect.Equal(counts.Count, saved.FailedLoginAttempts, $"FailedLoginAttempts after {counts.Count} reserved parallel attempts");
                Expect.True(counts.SequenceEqual(Enumerable.Range(1, counts.Count)),
                    $"The returned counts must be 1…{counts.Count}, each exactly once (got {string.Join(", ", counts)}) – otherwise no single request sees the lockout threshold.");
                Expect.True(counts.Count >= n / 2, $"Only {counts.Count} of {n} parallel attempts were reserved – retry a failed compare-and-set instead of giving up.");
            });

        await run.CheckRaceAsync(Store, "of parallel attempts at the threshold exactly one locks the factor",
            "Store the new lockout end (SlimAttemptRequest.NextLockoutEnd) in the same atomic step as the counter, and refuse every attempt while the stored end lies in the future (SlimAttemptReservation.LockedOut) without counting it.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var threshold = run.Options.Parallelism - 1;
                var now = ConformanceRun.WholeSeconds(DateTimeOffset.UtcNow);
                var results = await run.InParallelAsync(_ => ReserveAsync(user, SlimAttemptFactor.Password, now, threshold));
                Expect.Equal(threshold, results.Count(r => r is { IsLockedOut: false }), $"reserved attempts of {run.Options.Parallelism} parallel ones with the threshold {threshold}");
                Expect.Equal(1, results.Count(r => r is { IsLockedOut: false } && r.FailedAttempts == threshold), "attempts that reached the threshold");
                var saved = await run.ReloadAsync(user);
                Expect.Equal(threshold, saved.FailedLoginAttempts, "FailedLoginAttempts (a refused attempt must not be counted)");
                Expect.True(saved.LockoutEndUtc > now, "The attempt that reached the threshold did not store a lockout end.");
                Expect.True(results.Where(r => r is { IsLockedOut: true }).All(r => r!.LockoutEndUtc == saved.LockoutEndUtc),
                    "A refused attempt must report the stored lockout end.");

                // after the lockout: counted on, the old end stays until the next multiple of the threshold
                var later = await ReserveAsync(user, SlimAttemptFactor.Password, saved.LockoutEndUtc!.Value.AddSeconds(1), threshold);
                Expect.Equal(threshold + 1, later?.FailedAttempts, "FailedAttempts of the first attempt after the lockout");
                Expect.SameInstant(saved.LockoutEndUtc, (await run.ReloadAsync(user)).LockoutEndUtc, "LockoutEndUtc after an attempt below the next threshold (must stay)");
            });

        await run.CheckAsync(Store, "password and second factor have separate attempt counters",
            "TryBeginAttemptAsync and ResetFailedAttemptsAsync touch only the counter and lockout end of the requested factor.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var now = ConformanceRun.WholeSeconds(DateTimeOffset.UtcNow);
                await ReserveAsync(user, SlimAttemptFactor.Password, now, 100);
                await ReserveAsync(user, SlimAttemptFactor.Password, now, 100);
                await ReserveAsync(user, SlimAttemptFactor.SecondFactor, now, 1);   // locks the second factor only

                var counted = await run.ReloadAsync(user);
                Expect.Equal(2, counted.FailedLoginAttempts, "FailedLoginAttempts");
                Expect.SameInstant(null, counted.LockoutEndUtc, "LockoutEndUtc (the second factor was locked, not the password)");
                Expect.Equal(1, counted.FailedSecondFactorAttempts, "FailedSecondFactorAttempts");
                Expect.True(counted.SecondFactorLockoutEndUtc > now, "SecondFactorLockoutEndUtc was not stored.");

                await stores.UseAsync<ISlimUserStore>(s => s.ResetFailedAttemptsAsync(user, SlimAttemptFactor.Password, ct));
                var reset = await run.ReloadAsync(user);
                Expect.Equal(0, reset.FailedLoginAttempts, "FailedLoginAttempts after resetting the password");
                Expect.Equal(1, reset.FailedSecondFactorAttempts, "FailedSecondFactorAttempts after resetting the password (must stay)");
                Expect.SameInstant(counted.SecondFactorLockoutEndUtc, reset.SecondFactorLockoutEndUtc, "SecondFactorLockoutEndUtc after resetting the password (must stay)");

                await stores.UseAsync<ISlimUserStore>(s => s.ResetFailedAttemptsAsync(user, SlimAttemptFactor.SecondFactor, ct));
                var cleared = await run.ReloadAsync(user);
                Expect.Equal(0, cleared.FailedSecondFactorAttempts, "FailedSecondFactorAttempts after resetting the second factor");
                Expect.SameInstant(null, cleared.SecondFactorLockoutEndUtc, "SecondFactorLockoutEndUtc after resetting the second factor");
            });

        await run.CheckAsync(Store, "sign-in bookkeeping never overwrites the password hash or security stamp",
            "TryBeginAttemptAsync and ResetFailedAttemptsAsync update only the attempt columns – never write back the (possibly outdated) SlimUser.",
            async () =>
            {
                var stale = await run.NewUserAsync();
                // another request changes the password in the meantime
                var fresh = await run.ReloadAsync(stale);
                fresh.PasswordHash = ConformanceRun.NewHash();
                fresh.SecurityStamp = SlimUser.NewSecurityStamp();
                Expect.True(await WriteStateAsync(fresh, stale.SecurityStamp), "UpdateSecurityStateAsync returned false although the stamp was unchanged.");

                await ReserveAsync(stale, SlimAttemptFactor.Password, DateTimeOffset.UtcNow, 100);
                await AssertCredentialsAsync("TryBeginAttemptAsync");
                await stores.UseAsync<ISlimUserStore>(s => s.ResetFailedAttemptsAsync(stale, SlimAttemptFactor.Password, ct));
                await AssertCredentialsAsync("ResetFailedAttemptsAsync");

                async Task AssertCredentialsAsync(string method)
                {
                    var saved = await run.ReloadAsync(stale);
                    Expect.True(saved.PasswordHash == fresh.PasswordHash && saved.SecurityStamp == fresh.SecurityStamp,
                        $"{method} restored the old password hash / security stamp of an outdated SlimUser – a failed login could undo a password change.");
                }
            });

        await run.CheckAsync(Store, "UpdatePasswordHashAsync writes only if the hash is unchanged",
            "UPDATE users SET password_hash = @newHash WHERE id = @id AND password_hash = @currentHash – a password change in the meantime must win over a rehash.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var original = (await run.ReloadAsync(user)).PasswordHash;
                var rehashed = ConformanceRun.NewHash();
                await stores.UseAsync<ISlimUserStore>(s => s.UpdatePasswordHashAsync(user, original, rehashed, ct));
                Expect.Equal(rehashed, (await run.ReloadAsync(user)).PasswordHash, "PasswordHash after a rehash with the current hash");

                await stores.UseAsync<ISlimUserStore>(s => s.UpdatePasswordHashAsync(user, original, ConformanceRun.NewHash(), ct));
                Expect.Equal(rehashed, (await run.ReloadAsync(user)).PasswordHash, "PasswordHash after a rehash with an outdated hash (must stay unchanged)");
            });

        await run.CheckAsync(Store, "UpdatePasswordHashAsync and UpdateEmailAsync write nothing else",
            "Each is one narrow UPDATE of its own columns – never write back the passed SlimUser, which may have been read before other changes (stamp, attempt counters, block by an administrator).",
            async () =>
            {
                var user = await run.NewUserAsync();
                await ReserveAsync(user, SlimAttemptFactor.Password, DateTimeOffset.UtcNow, 100);
                var stored = await run.ReloadAsync(user);

                var stale = await run.ReloadAsync(user);
                stale.SecurityStamp = SlimUser.NewSecurityStamp();
                stale.FailedLoginAttempts = 0;
                stale.EmailConfirmed = true;
                stale.TwoFactorEnabled = true;
                stale.IsActive = false;
                var rehashed = ConformanceRun.NewHash();
                await stores.UseAsync<ISlimUserStore>(s => s.UpdatePasswordHashAsync(stale, stored.PasswordHash, rehashed, ct));
                var rehashedUser = await run.ReloadAsync(user);
                AssertUnchanged(rehashedUser, stored.SecurityStamp, "UpdatePasswordHashAsync");
                Expect.Equal(false, rehashedUser.EmailConfirmed, "EmailConfirmed after UpdatePasswordHashAsync (must stay)");

                stale.PasswordHash = ConformanceRun.NewHash();
                var newStamp = SlimUser.NewSecurityStamp();
                Expect.Equal(SlimEmailUpdateResult.Updated, await ChangeEmailAsync(stale, run.NewEmail(), stored.SecurityStamp, newStamp), "UpdateEmailAsync with the current stamp");
                var changed = await run.ReloadAsync(user);
                AssertUnchanged(changed, newStamp, "UpdateEmailAsync");
                Expect.Equal(rehashed, changed.PasswordHash, "PasswordHash after UpdateEmailAsync (must stay)");

                void AssertUnchanged(SlimUser saved, string stamp, string method)
                {
                    Expect.Equal(stamp, saved.SecurityStamp, $"SecurityStamp after {method}");
                    Expect.Equal(1, saved.FailedLoginAttempts, $"FailedLoginAttempts after {method} (must stay)");
                    Expect.Equal(false, saved.TwoFactorEnabled, $"TwoFactorEnabled after {method} (must stay)");
                    Expect.Equal(true, saved.IsActive, $"IsActive after {method} (must stay)");
                }
            });

        await run.CheckAsync(Store, "UpdateEmailAsync changes the address, confirmation and stamp in one step and refuses taken ones",
            "One UPDATE of address, normalized column, EmailConfirmed = true and the new stamp, WHERE the stamp equals the expected one; Updated for 1 row, StampChanged for 0 rows, EmailTaken on a unique violation (and nothing changed).",
            async () =>
            {
                var a = await run.NewUserAsync();
                var b = await run.NewUserAsync();
                var newAddress = run.NewEmail();
                var newStamp = SlimUser.NewSecurityStamp();

                Expect.Equal(SlimEmailUpdateResult.Updated, await ChangeEmailAsync(a, newAddress, a.SecurityStamp, newStamp), "UpdateEmailAsync for a free address");
                var changed = await run.ReloadAsync(a);
                Expect.Equal(newAddress, changed.Email, "Email after the change");
                Expect.Equal(true, changed.EmailConfirmed, "EmailConfirmed after the change");
                Expect.Equal(newStamp, changed.SecurityStamp, "SecurityStamp after the change");
                var byNew = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByEmailAsync(newAddress.ToUpperInvariant(), ct));
                Expect.Equal(a.Id, byNew?.Id, "FindByEmailAsync(new address, other casing) → Id");
                var byOld = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByEmailAsync(a.Email, ct));
                Expect.True(byOld is null, "The old address still finds the user after the change (normalized column not updated?).");

                var taken = await ChangeEmailAsync(a, b.Email.ToUpperInvariant(), newStamp, SlimUser.NewSecurityStamp());
                Expect.Equal(SlimEmailUpdateResult.EmailTaken, taken, "UpdateEmailAsync for an address that belongs to another account");
                var refused = await run.ReloadAsync(a);
                Expect.Equal(newAddress, refused.Email, "Email after the refused change");
                Expect.Equal(newStamp, refused.SecurityStamp, "SecurityStamp after the refused change");

                // a link issued before the last change: nothing may be written
                var stale = await ChangeEmailAsync(a, run.NewEmail(), a.SecurityStamp, SlimUser.NewSecurityStamp());
                Expect.Equal(SlimEmailUpdateResult.StampChanged, stale, "UpdateEmailAsync with an outdated stamp");
                var unchanged = await run.ReloadAsync(a);
                Expect.Equal(newAddress, unchanged.Email, "Email after a change with an outdated stamp");
                Expect.Equal(newStamp, unchanged.SecurityStamp, "SecurityStamp after a change with an outdated stamp");
            });

        await run.CheckAsync(Store, "UpdateEmailAsync accepts a new spelling of the own address",
            "The address is taken only if ANOTHER account uses it: a unique index on the normalized column does that by itself; an explicit check must exclude the user's own row.",
            async () =>
            {
                var user = await run.NewUserAsync($"Slim.Spelling-{Guid.NewGuid():N}@{run.Options.EmailDomain}");
                var respelled = user.Email.ToLowerInvariant();
                var newStamp = SlimUser.NewSecurityStamp();
                Expect.Equal(SlimEmailUpdateResult.Updated, await ChangeEmailAsync(user, respelled, user.SecurityStamp, newStamp), "UpdateEmailAsync with a new spelling of the own address");
                var saved = await run.ReloadAsync(user);
                Expect.Equal(respelled, saved.Email, "Email after the new spelling");
                Expect.Equal(newStamp, saved.SecurityStamp, "SecurityStamp after the new spelling");
            });

        await run.CheckRaceAsync(Store, "of parallel e-mail changes to one address exactly one wins",
            "Let the unique index on the normalized address decide inside the UPDATE and map the violation to EmailTaken – a check for the address before the write lets several accounts through.",
            async () =>
            {
                var target = $"Slim.Target-{Guid.NewGuid():N}@{run.Options.EmailDomain}";
                var users = new SlimUser[run.Options.Parallelism];
                for (var i = 0; i < users.Length; i++) users[i] = await run.NewUserAsync();
                var results = await run.InParallelAsync(i =>
                    ChangeEmailAsync(users[i], i % 2 == 0 ? target : target.ToLowerInvariant(), users[i].SecurityStamp, SlimUser.NewSecurityStamp()));

                Expect.Equal(1, results.Count(r => r == SlimEmailUpdateResult.Updated), "parallel changes to one address (two casings) that succeeded");
                Expect.True(results.All(r => r is SlimEmailUpdateResult.Updated or SlimEmailUpdateResult.EmailTaken), "The losers of the race must get EmailTaken.");
                var winner = users[Array.IndexOf(results, SlimEmailUpdateResult.Updated)];
                Expect.Equal(winner.Id, (await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByEmailAsync(target, ct)))?.Id, "FindByEmailAsync(target) → the winner");
            });

        await run.CheckAsync(Store, "GetClaimsAsync works for a new user",
            "Return an empty collection when the user has no roles or claims yet.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var claims = await stores.UseAsync<ISlimUserStore, IReadOnlyCollection<System.Security.Claims.Claim>>(s => s.GetClaimsAsync(user, ct));
                Expect.True(claims is not null, "GetClaimsAsync returned null.");
            });

        Task<bool> WriteStateAsync(SlimUser user, string expectedStamp) =>
            stores.UseAsync<ISlimUserStore, bool>(s => s.UpdateSecurityStateAsync(user, expectedStamp, ct));

        Task<SlimEmailUpdateResult> ChangeEmailAsync(SlimUser user, string newEmail, string expectedStamp, string newStamp) =>
            stores.UseAsync<ISlimUserStore, SlimEmailUpdateResult>(s => s.UpdateEmailAsync(user, newEmail, expectedStamp, newStamp, ct));

        Task<SlimAttemptReservation?> ReserveAsync(SlimUser user, SlimAttemptFactor factor, DateTimeOffset now, int maxFailedAttempts) =>
            stores.UseAsync<ISlimUserStore, SlimAttemptReservation?>(s => s.TryBeginAttemptAsync(user,
                new SlimAttemptRequest(factor, now, new SlimLockoutOptions { MaxFailedAttempts = maxFailedAttempts }), ct));
    }
}
