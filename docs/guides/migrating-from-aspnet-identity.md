# Migrating from ASP.NET Core Identity

SlimIdentity uses the same `PasswordHasher<T>` format, so existing hashes keep working. The migration is mostly
column mapping in your `ISlimUserStore` – against the existing tables (EF Core: map an entity to the same table) or a
new schema.

| ASP.NET Core Identity | SlimIdentity | Notes |
| :--- | :--- | :--- |
| `Id` | `Id` | string |
| `Email` / `NormalizedEmail` | `Email` | look up by `NormalizedEmail` (upper-case) |
| `PasswordHash` | `PasswordHash` | same format; `null` → empty string |
| `SecurityStamp` | `SecurityStamp` | keep it; rotating signs users out |
| `EmailConfirmed` | `EmailConfirmed` | see [unconfirmed addresses](#unconfirmed-addresses) |
| `AccessFailedCount` / `LockoutEnd` | `FailedLoginAttempts` / `LockoutEndUtc` | ignore `LockoutEnd` where `LockoutEnabled` is false |
| – | `FailedSecondFactorAttempts`, `SecondFactorLockoutEndUtc` | new, start with `0` / `null` |
| `TwoFactorEnabled` | `TwoFactorEnabled` | |
| – | `PasswordChangeRequired`, `IsActive` | new; `false` / `true` (or your own flag) |
| `AspNetUserRoles`, `AspNetUserClaims` | `GetClaimsAsync` | roles as `ClaimTypes.Role` |
| `AspNetUserLogins` | `ISlimExternalLoginStore` | provider names must match your scheme names |
| `AspNetUserTokens` (`AuthenticatorKey`) | `ISlimTwoFactorStore.GetTotpSecretAsync` | clear-text Base32; encrypt once with `CreateProtector(SlimIdentityDefaults.TotpSecretProtectionPurpose).Protect(key)` |
| `AspNetUserTokens` (`RecoveryCodes`) | – | clear text, low entropy: users regenerate (`POST /auth/2fa/recovery-codes`) |
| – | `TryMarkCodeUsedAsync`, `TryMarkChallengeUsedAsync` | two new nullable `bigint` columns |

## Unconfirmed addresses

With mail, an account with an unconfirmed address is not yet proven to belong to the mailbox owner:

- every sign-in continues with the `verify_email` step until the address is confirmed;
- a password reset confirms it and removes 2FA, external logins and passkeys;
- a verified external login of the same address answers `account_conflict`;
- no second factor or passkey can be added.

Carry `EmailConfirmed` over unchanged to keep this; setting it to `true` for everyone trusts every imported address.

## Differences

- **Endpoints and payloads** differ from `MapIdentityApi` (`/auth/login`, `/auth/refresh`, `/auth/me`, …).
- **Sessions end once:** SlimIdentity issues JWTs plus rotating refresh tokens and its own cookie (`SlimAuth`).
- **Lockout** is progressive (1 min doubling up to 1 h); `Duration` = `MaxDuration` gives a fixed one.
- **Password options:** compare with your previous `PasswordOptions`.
- **No `UserManager` / `SignInManager`:** use `ISlimAuthManager`, `IPasswordHasher<SlimUser>` and your store.
