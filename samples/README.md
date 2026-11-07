# SlimIdentity – samples

| Folder | Purpose |
| :--- | :--- |
| [`SlimIdentity.Demo/`](SlimIdentity.Demo) | Runnable demo with in-memory stores (Native AOT capable) and the **playground** (`wwwroot/`: every flow clickable, fake mailbox, virtual authenticator, request log). `dotnet run --project samples/SlimIdentity.Demo` → <http://localhost:5209>, or `docker compose up --build` in the repository root → <http://localhost:8080> ([Breakme mode](../BREAKME.md)). Requests for editors: `SlimIdentity.Demo.http`. |
| [`templates/`](templates) | Copy-paste templates for your own project (below). |

The templates are **not** NuGet dependencies and are not shipped. Copy them into your project and adapt them – this
keeps the core package free of EF Core, Dapper, SMTP & co. CI compiles them against the current library and runs the
[`SlimIdentity.Testing`](../src/SlimIdentity.Testing/README.md) conformance checks against the EF Core stores
(`tests/SlimIdentity.Samples.Tests`: EF Core on SQLite, PostgreSQL and SQL Server, Dapper on PostgreSQL – the servers
as CI service containers), so they never drift from the API or the store contracts. Locally the server runs are
skipped unless `SLIMIDENTITY_TEST_POSTGRES` / `SLIMIDENTITY_TEST_SQLSERVER` hold connection strings to disposable
servers (see CONTRIBUTING).

| Template | Content | Packages in your host |
| :--- | :--- | :--- |
| `EfCore/` | `AppDbContext` + all stores (user, refresh, 2FA, external login, API key, sessions) – only if you need full control over the mapping; otherwise use the **`SlimIdentity.EntityFrameworkCore` package** | `Microsoft.EntityFrameworkCore` + provider |
| `Dapper/` | `schema.sql` (PostgreSQL) + all stores | `Dapper`, `Npgsql` |
| `Email/` | `MailKitEmailSender`, `SendGridEmailSender`, `LoggingEmailSender`, `OutboxEmailSender` + `OutboxMailWorker` (guaranteed delivery) | `MailKit` or `SendGrid`, EF Core |
| `Enterprise/` | `LdapPasswordValidator`, legacy hash migration, client certificates (mTLS), admin endpoints (impersonation, sudo, API keys, invitations, ban) | `System.DirectoryServices.Protocols`, `Microsoft.AspNetCore.Authentication.Certificate` |
| `Security/` | `PwnedPasswordRule` – rejects breached passwords via Have I Been Pwned (k-anonymity) | – |
| `DataProtection/` | Persisting the key ring: EF Core, Redis, file system + certificate | `Microsoft.AspNetCore.DataProtection.*` |
| `Frontend/` | `slimIdentityClient.ts` – cookie flow (`X-CSRF`, device list, invitations, TOTP setup with QR code, e-mail change) and bearer flow with refresh rotation | – |

## Rules for your own stores

Verify them automatically with [`SlimIdentity.Testing`](../src/SlimIdentity.Testing/README.md) – one call in a test
against your real database checks all of the following, including the parallel cases.

- `FindByEmailAsync` must search **case-insensitively** (e.g. a normalized column with a unique index). Addresses
  arrive trimmed and Unicode-normalized (NFC); if you import users, normalize existing addresses the same way
  (`email.Normalize(NormalizationForm.FormC)`).
- `CreateAsync` returns `null` if the address is already taken (unique index on the normalized address,
  `ON CONFLICT DO NOTHING` / catch the unique violation) – concurrent registrations then get the uniform answer.
- `UpdateSecurityStateAsync` persists only the security fields of `SlimUser`
  (PasswordHash, SecurityStamp, EmailConfirmed, FailedLoginAttempts, LockoutEndUtc, TwoFactorEnabled, PasswordChangeRequired).
- The sign-in bookkeeping methods touch **only their own columns**, in a single statement:
  `IncrementFailedLoginAttemptsAsync` (`SET failed = failed + 1 … RETURNING failed`), `SetLockoutEndAsync`,
  `ResetFailedLoginAttemptsAsync` and `UpdatePasswordHashAsync` (`… WHERE password_hash = @currentHash`). Never
  implement them by writing back the whole user – a concurrent password change could be undone.
- `UpdateEmailAsync` changes the address and its normalized column and returns `false` if it is already taken – let
  the unique constraint decide instead of checking first.
- `ValidateAndConsumeRefreshTokenAsync` / `ValidateAndConsumeRecoveryCodeAsync` must delete **atomically**
  (`DELETE … RETURNING` or `ExecuteDeleteAsync() == 1`), otherwise parallel replays are possible.
- `TryMarkCodeUsedAsync` and `TryMarkChallengeUsedAsync` must be **atomic compare-and-sets** on two **separate**
  columns (`UPDATE … SET last = @v WHERE id = @id AND (last IS NULL OR last < @v)` and return whether a row changed).
- TOTP secrets arrive encrypted – store the string as is; do not decrypt or re-encode it.
- `IsActive = false` **plus** `ISlimAuthManager.SignOutEverywhereAsync(user)` ends all sessions of a user immediately.
- `ISlimSessionStore`: `FindAsync` must not return revoked sessions (deleting the row is enough); clean up expired rows
  regularly (`DELETE … WHERE expires_utc < now()`). `UserAgent` / `IpAddress` are personal data – only store them if
  your device list needs them.
- Invited users are created with an empty `passwordHash` (`CreateAsync(email, "")`) before calling
  `CreateInvitationAsync`; a `null` result means the address is already registered.
- Custom claims from `GetClaimsAsync`: `ClaimTypes.Role` is normalized to `role`; reserved claims
  (`sub`, `email`, `slim_stamp`, `amr`, `act`, `sid`, `auth_time`) are ignored.
