# SlimIdentity – copy-paste samples

These files are **not** NuGet dependencies and are not part of the solution. Copy them into your project and adapt
them – this keeps the core package free of EF Core, Dapper, SMTP & co.
CI compiles them against the current library (`dotnet build samples/SamplesCheck`) so they never drift from the API.

| Folder | Content | Packages in your host |
| :--- | :--- | :--- |
| `EfCore/` | `AppDbContext` + all stores (user, refresh, 2FA, external login, API key, sessions) | `Microsoft.EntityFrameworkCore` + provider |
| `Dapper/` | `schema.sql` (PostgreSQL), `DapperUserStore`, `DapperRefreshTokenStore` | `Dapper`, `Npgsql` |
| `Email/` | `MailKitEmailSender`, `SendGridEmailSender`, `LoggingEmailSender`, `OutboxEmailSender` + `OutboxMailWorker` (guaranteed delivery) | `MailKit` or `SendGrid`, EF Core |
| `Enterprise/` | `LdapPasswordValidator`, legacy hash migration, admin endpoints (impersonation, sudo, API keys, invitations, ban) | `System.DirectoryServices.Protocols` |
| `Frontend/` | `slimIdentityClient.ts` – cookie flow (incl. `X-CSRF`, device list, invitations) and bearer flow with refresh rotation | – |

## Rules for your own stores

- `FindByEmailAsync` must search **case-insensitively** (e.g. a normalized column with a unique index).
- `UpdateSecurityStateAsync` persists only the security fields of `SlimUser`
  (PasswordHash, SecurityStamp, EmailConfirmed, FailedLoginAttempts, LockoutEndUtc, TwoFactorEnabled).
- `ValidateAndConsumeRefreshTokenAsync` / `ValidateAndConsumeRecoveryCodeAsync` must delete **atomically**
  (`DELETE … RETURNING` or `ExecuteDeleteAsync() == 1`), otherwise parallel replays are possible.
- `IsActive = false` **plus** `ISlimAuthManager.SignOutEverywhereAsync(user)` ends all sessions of a user immediately.
- `ISlimSessionStore`: `FindAsync` must not return revoked sessions (deleting the row is enough); clean up expired rows
  regularly (`DELETE … WHERE expires_utc < now()`). `UserAgent` / `IpAddress` are personal data – only store them if
  your device list needs them.
- Invited users are created with an empty `passwordHash` (`CreateAsync(email, "")`) before calling `CreateInvitationAsync`.
- Custom claims from `GetClaimsAsync`: `ClaimTypes.Role` is normalized to `role`; reserved claims
  (`sub`, `email`, `slim_stamp`, `amr`, `act`, `sid`, `auth_time`) are ignored.
