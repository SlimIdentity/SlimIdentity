# SlimIdentity – Copy-Paste-Vorlagen

Diese Dateien sind **keine** NuGet-Abhängigkeiten und werden nicht mitgebaut. Sie werden in das eigene
Projekt kopiert und angepasst – so bleibt das Kernpaket frei von EF Core, Dapper, SMTP & Co.

| Ordner | Inhalt | Pakete im Host |
| :--- | :--- | :--- |
| `EfCore/` | `AppDbContext` + alle Stores (User, Refresh, 2FA, External Login, API-Key) | `Microsoft.EntityFrameworkCore` + Provider |
| `Dapper/` | `schema.sql` (PostgreSQL), `DapperUserStore`, `DapperRefreshTokenStore` | `Dapper`, `Npgsql` |
| `Email/` | `MailKitEmailSender`, `SendGridEmailSender`, `LoggingEmailSender` | `MailKit` bzw. `SendGrid` |
| `Enterprise/` | `LdapPasswordValidator`, Legacy-Hash-Migration, Admin-Endpoints (Impersonation, Sudo, API-Keys, Invite-Registrierung) | `System.DirectoryServices.Protocols` |
| `Frontend/` | `slimIdentityClient.ts` – Cookie-Flow (inkl. `X-CSRF`) und Bearer-Flow mit Refresh-Rotation | – |

## Wichtige Regeln für eigene Stores

- `FindByEmailAsync` muss **case-insensitiv** suchen (z. B. über eine normalisierte Spalte mit Unique-Index).
- `UpdateSecurityStateAsync` persistiert ausschließlich die Security-Felder des `SlimUser`
  (PasswordHash, SecurityStamp, EmailConfirmed, FailedLoginAttempts, LockoutEndUtc, TwoFactorEnabled).
- `ValidateAndConsumeRefreshTokenAsync` / `ValidateAndConsumeRecoveryCodeAsync` müssen **atomar** löschen
  (`DELETE … RETURNING` bzw. `ExecuteDeleteAsync() == 1`), sonst sind parallele Replays möglich.
- `IsActive = false` **plus** neuer `SecurityStamp` beendet alle Sessions eines Users sofort.
- Eigene Claims aus `GetClaimsAsync`: `ClaimTypes.Role` wird automatisch zu `role` normalisiert,
  reservierte Claims (`sub`, `email`, `slim_stamp`, `amr`, `act`) werden ignoriert.
