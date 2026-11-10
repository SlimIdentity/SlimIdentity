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

        await run.CheckAsync(Store, "treats quotes, SQL metacharacters and LIKE wildcards in addresses as plain text",
            "Use parameterized statements only (never build SQL from the address) and compare with '=' – not LIKE, whose '%' and '_' would match other addresses.",
            async () =>
            {
                var id = Guid.NewGuid().ToString("N");
                var tricky = $"o'brien\"--;{id}@{run.Options.EmailDomain}";
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

        await run.CheckAsync(Store, "parallel registrations of one address create exactly one account",
            "Do not check for existence first – insert and let the unique index on the normalized address reject the losers (also for other casings); return null for them instead of throwing.",
            async () =>
            {
                var email = $"Slim.Race-{Guid.NewGuid():N}@{run.Options.EmailDomain}";
                var results = await run.InParallelAsync(i =>
                    stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.CreateAsync(new SlimNewUser { Email = i % 2 == 0 ? email : email.ToLowerInvariant(), PasswordHash = ConformanceRun.NewHash() }, ct)));
                Expect.Equal(1, results.Count(u => u is not null), "accounts created by parallel CreateAsync calls (two casings of one address)");
            });

        await run.CheckAsync(Store, "a new user starts unconfirmed, unlocked and without 2FA",
            "Insert the given PasswordHash and a fresh SecurityStamp; EmailConfirmed = false, FailedLoginAttempts = 0, LockoutEndUtc = null, TwoFactorEnabled = false, PasswordChangeRequired = false – no column defaults that grant more.",
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
                Expect.Equal(false, saved.TwoFactorEnabled, "TwoFactorEnabled");
                Expect.Equal(false, saved.PasswordChangeRequired, "PasswordChangeRequired");

                var other = await run.NewUserAsync();
                Expect.True(other.SecurityStamp != created.SecurityStamp && (await run.ReloadAsync(other)).SecurityStamp != saved.SecurityStamp,
                    "Two new users got the same SecurityStamp – store the value of the SlimUser, not a constant default.");
            });

        await run.CheckAsync(Store, "UpdateSecurityStateAsync persists all security fields",
            "Write PasswordHash, SecurityStamp, EmailConfirmed, FailedLoginAttempts, LockoutEndUtc, TwoFactorEnabled and PasswordChangeRequired.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var lockoutEnd = ConformanceRun.WholeSeconds(DateTimeOffset.UtcNow.AddHours(1));
                user.PasswordHash = ConformanceRun.NewHash();
                user.SecurityStamp = SlimUser.NewSecurityStamp();
                user.EmailConfirmed = true;
                user.FailedLoginAttempts = 3;
                user.LockoutEndUtc = lockoutEnd;
                user.TwoFactorEnabled = true;
                user.PasswordChangeRequired = true;
                await stores.UseAsync<ISlimUserStore>(s => s.UpdateSecurityStateAsync(user, ct));

                var saved = await run.ReloadAsync(user);
                Expect.Equal(user.PasswordHash, saved.PasswordHash, "PasswordHash");
                Expect.Equal(user.SecurityStamp, saved.SecurityStamp, "SecurityStamp");
                Expect.Equal(true, saved.EmailConfirmed, "EmailConfirmed");
                Expect.Equal(3, saved.FailedLoginAttempts, "FailedLoginAttempts");
                Expect.SameInstant(lockoutEnd, saved.LockoutEndUtc, "LockoutEndUtc");
                Expect.Equal(true, saved.TwoFactorEnabled, "TwoFactorEnabled");
                Expect.Equal(true, saved.PasswordChangeRequired, "PasswordChangeRequired");

                // and back: cleared values must be written, too (no "only if not null" updates)
                user.EmailConfirmed = false;
                user.FailedLoginAttempts = 0;
                user.LockoutEndUtc = null;
                user.TwoFactorEnabled = false;
                user.PasswordChangeRequired = false;
                user.PasswordHash = string.Empty;
                await stores.UseAsync<ISlimUserStore>(s => s.UpdateSecurityStateAsync(user, ct));

                var cleared = await run.ReloadAsync(user);
                Expect.Equal(false, cleared.EmailConfirmed, "EmailConfirmed after clearing");
                Expect.Equal(0, cleared.FailedLoginAttempts, "FailedLoginAttempts after clearing");
                Expect.SameInstant(null, cleared.LockoutEndUtc, "LockoutEndUtc after clearing");
                Expect.Equal(false, cleared.TwoFactorEnabled, "TwoFactorEnabled after clearing");
                Expect.Equal(false, cleared.PasswordChangeRequired, "PasswordChangeRequired after clearing");
                Expect.True(string.IsNullOrEmpty(cleared.PasswordHash), "PasswordHash after removing the password (empty) – the old hash is still stored.");
            });

        await run.CheckAsync(Store, "UpdateSecurityStampAsync replaces only the stamp and only if it is unchanged",
            "UPDATE users SET security_stamp = @newStamp WHERE id = @id AND security_stamp = @expectedStamp; return affected rows = 1. Never write other columns.",
            async () =>
            {
                var stale = await run.NewUserAsync();
                var original = (await run.ReloadAsync(stale)).SecurityStamp;

                // another request changes the password in the meantime – the stamp rotation must not undo it
                var fresh = await run.ReloadAsync(stale);
                fresh.PasswordHash = ConformanceRun.NewHash();
                await stores.UseAsync<ISlimUserStore>(s => s.UpdateSecurityStateAsync(fresh, ct));

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

        await run.CheckAsync(Store, "IncrementFailedLoginAttemptsAsync counts parallel failures atomically",
            "One statement: UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = @id RETURNING failed_login_attempts (or a compare-and-set loop). Never read, add and write back.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var n = run.Options.Parallelism;
                var counts = await run.InParallelAsync(_ =>
                    stores.UseAsync<ISlimUserStore, int>(s => s.IncrementFailedLoginAttemptsAsync(user, ct)));
                Expect.Equal(n, (await run.ReloadAsync(user)).FailedLoginAttempts, $"FailedLoginAttempts after {n} parallel increments");
                Expect.True(counts.Order().SequenceEqual(Enumerable.Range(1, n)),
                    $"The returned counts must be 1…{n}, each exactly once (got {string.Join(", ", counts.Order())}) – otherwise no single request sees the lockout threshold.");
            });

        await run.CheckAsync(Store, "sign-in bookkeeping never overwrites the password hash or security stamp",
            "IncrementFailedLoginAttemptsAsync, SetLockoutEndAsync and ResetFailedLoginAttemptsAsync update only their own columns – never write back the (possibly outdated) SlimUser.",
            async () =>
            {
                var stale = await run.NewUserAsync();
                // another request changes the password in the meantime
                var fresh = await run.ReloadAsync(stale);
                fresh.PasswordHash = ConformanceRun.NewHash();
                fresh.SecurityStamp = SlimUser.NewSecurityStamp();
                await stores.UseAsync<ISlimUserStore>(s => s.UpdateSecurityStateAsync(fresh, ct));

                await stores.UseAsync<ISlimUserStore, int>(s => s.IncrementFailedLoginAttemptsAsync(stale, ct));
                await AssertCredentialsAsync("IncrementFailedLoginAttemptsAsync");
                await stores.UseAsync<ISlimUserStore>(s => s.SetLockoutEndAsync(stale, DateTimeOffset.UtcNow.AddMinutes(1), ct));
                await AssertCredentialsAsync("SetLockoutEndAsync");
                await stores.UseAsync<ISlimUserStore>(s => s.ResetFailedLoginAttemptsAsync(stale, ct));
                await AssertCredentialsAsync("ResetFailedLoginAttemptsAsync");

                async Task AssertCredentialsAsync(string method)
                {
                    var saved = await run.ReloadAsync(stale);
                    Expect.True(saved.PasswordHash == fresh.PasswordHash && saved.SecurityStamp == fresh.SecurityStamp,
                        $"{method} restored the old password hash / security stamp of an outdated SlimUser – a failed login could undo a password change.");
                }
            });

        await run.CheckAsync(Store, "SetLockoutEndAsync and ResetFailedLoginAttemptsAsync change only the lockout state",
            "SetLockoutEndAsync writes LockoutEndUtc only; ResetFailedLoginAttemptsAsync sets FailedLoginAttempts = 0 and LockoutEndUtc = null.",
            async () =>
            {
                var user = await run.NewUserAsync();
                await stores.UseAsync<ISlimUserStore, int>(s => s.IncrementFailedLoginAttemptsAsync(user, ct));
                await stores.UseAsync<ISlimUserStore, int>(s => s.IncrementFailedLoginAttemptsAsync(user, ct));

                var end = ConformanceRun.WholeSeconds(DateTimeOffset.UtcNow.AddMinutes(5));
                await stores.UseAsync<ISlimUserStore>(s => s.SetLockoutEndAsync(user, end, ct));
                var locked = await run.ReloadAsync(user);
                Expect.SameInstant(end, locked.LockoutEndUtc, "LockoutEndUtc after SetLockoutEndAsync");
                Expect.Equal(2, locked.FailedLoginAttempts, "FailedLoginAttempts after SetLockoutEndAsync (must stay unchanged)");

                await stores.UseAsync<ISlimUserStore>(s => s.ResetFailedLoginAttemptsAsync(user, ct));
                var reset = await run.ReloadAsync(user);
                Expect.Equal(0, reset.FailedLoginAttempts, "FailedLoginAttempts after ResetFailedLoginAttemptsAsync");
                Expect.SameInstant(null, reset.LockoutEndUtc, "LockoutEndUtc after ResetFailedLoginAttemptsAsync");
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

        await run.CheckAsync(Store, "UpdateEmailAsync changes the address and refuses taken ones",
            "Update the address and its normalized column; return false on a unique violation and change nothing.",
            async () =>
            {
                var a = await run.NewUserAsync();
                var b = await run.NewUserAsync();
                var newAddress = run.NewEmail();

                Expect.True(await stores.UseAsync<ISlimUserStore, bool>(s => s.UpdateEmailAsync(a, newAddress, ct)), "UpdateEmailAsync returned false for a free address.");
                var byNew = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByEmailAsync(newAddress.ToUpperInvariant(), ct));
                Expect.Equal(a.Id, byNew?.Id, "FindByEmailAsync(new address, other casing) → Id");
                var byOld = await stores.UseAsync<ISlimUserStore, SlimUser?>(s => s.FindByEmailAsync(a.Email, ct));
                Expect.True(byOld is null, "The old address still finds the user after the change (normalized column not updated?).");

                var taken = await stores.UseAsync<ISlimUserStore, bool>(s => s.UpdateEmailAsync(a, b.Email.ToUpperInvariant(), ct));
                Expect.True(!taken, "UpdateEmailAsync returned true for an address that belongs to another account.");
                Expect.Equal(newAddress, (await run.ReloadAsync(a)).Email, "Email after the refused change");
            });

        await run.CheckAsync(Store, "GetClaimsAsync works for a new user",
            "Return an empty collection when the user has no roles or claims yet.",
            async () =>
            {
                var user = await run.NewUserAsync();
                var claims = await stores.UseAsync<ISlimUserStore, IReadOnlyCollection<System.Security.Claims.Claim>>(s => s.GetClaimsAsync(user, ct));
                Expect.True(claims is not null, "GetClaimsAsync returned null.");
            });
    }
}
