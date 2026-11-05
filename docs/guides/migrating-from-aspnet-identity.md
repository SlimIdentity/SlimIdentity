# Migrating from ASP.NET Core Identity

SlimIdentity uses the same `PasswordHasher<T>` format as ASP.NET Core Identity, so existing password hashes keep
working – users do not have to reset their passwords. The migration is mostly a matter of mapping columns in your
`ISlimUserStore`.

## Column mapping (`AspNetUsers` → `SlimUser`)

| ASP.NET Core Identity | SlimUser | Notes |
| :--- | :--- | :--- |
| `Id` | `Id` | string |
| `Email` / `NormalizedEmail` | `Email` | look up by `NormalizedEmail` (upper-case) |
| `PasswordHash` | `PasswordHash` | identical format (Identity V3 / PBKDF2); `null` → empty string |
| `SecurityStamp` | `SecurityStamp` | keep it; rotating it signs users out |
| `EmailConfirmed` | `EmailConfirmed` | |
| `AccessFailedCount` | `FailedLoginAttempts` | |
| `LockoutEnd` | `LockoutEndUtc` | ignore it if `LockoutEnabled` is false for a user |
| `TwoFactorEnabled` | `TwoFactorEnabled` | |
| – | `IsActive` | new; map from your own flag (e.g. not deleted) or always `true` |
| `AspNetUserRoles` + `AspNetRoles` | `GetClaimsAsync` | return `ClaimTypes.Role` claims |
| `AspNetUserClaims` | `GetClaimsAsync` | return them as additional claims |
| `AspNetUserLogins` | `ISlimExternalLoginStore` | `LoginProvider` / `ProviderKey`; provider names must match your scheme names |
| `AspNetUserTokens` (`AuthenticatorKey`) | `ISlimTwoFactorStore.GetTotpSecretAsync` | Identity stores the Base32 key in clear text; encrypt it once during migration: `provider.CreateProtector(SlimIdentityDefaults.TotpSecretProtectionPurpose).Protect(key)` |
| `AspNetUserTokens` (`RecoveryCodes`) | – | Identity stores them in clear text and with less entropy; users should regenerate codes (`POST /auth/2fa/recovery-codes`) |
| – | `ISlimTwoFactorStore.TryMarkCodeUsedAsync` | new column for replay protection (nullable `bigint`) |
| – | `ISlimTwoFactorStore.TryMarkChallengeUsedAsync` | new column for single-use sign-in challenges (nullable `bigint`) |

You can keep the existing tables and implement the stores directly against them (EF Core: map your existing
`IdentityUser` entity or a plain class to the same table), or migrate into your own schema.

## Behavioural differences

- **Endpoints:** `MapIdentityApi` routes (`/login`, `/refresh`, `/manage/info`, …) differ from SlimIdentity's
  (`/auth/login`, `/auth/refresh`, `/auth/me`, …) and so do the payloads; front ends need to be adapted.
- **Tokens:** Identity's bearer tokens are opaque Data Protection tokens; SlimIdentity issues JWTs (plus refresh
  tokens with rotation). Existing sessions end at the switch – users sign in once.
- **Cookies:** the cookie name and scheme change (`SlimAuth`, `SlimIdentity.Cookie`); users sign in once.
- **Lockout:** progressive (1 min, doubling up to 1 h) instead of a fixed 5 minutes; configure `Lockout` if you need
  the old behaviour (`Duration` = `MaxDuration`).
- **Password policy:** check `Password` options against your previous `PasswordOptions`.
- **UserManager / SignInManager:** not used. For your own flows use `ISlimAuthManager`, `IPasswordHasher<SlimUser>`
  and your store.
