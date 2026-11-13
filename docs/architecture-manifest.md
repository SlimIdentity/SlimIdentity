# SlimIdentity – Architecture and design principles

## 1. Purpose

SlimIdentity is a database-agnostic authentication facade for ASP.NET Core: hardened JSON endpoints for web front ends
and mobile apps, between hand-written login code and the fixed schema of `Microsoft.AspNetCore.Identity`. Databases,
ORMs and domain models stay with the host.

## 2. Core principles

1. **Zero persistence in the core:** the `SlimIdentity` package references no ORM or database driver. Persistence lives
   in optional packages (`SlimIdentity.EntityFrameworkCore`) or in the host, behind small interfaces. Internal helpers
   (e.g. the mail queue) stay in memory; durability is the host's (outbox).
2. **No generics, no base classes** in the core API. A single transfer object (`SlimUser`) carries the security state.
3. **Framework native:** no custom cryptography; `PasswordHasher`, Data Protection, `ClaimsPrincipal`, rate limiting
   and the standard cookie, JWT and OAuth/OIDC handlers. `[Authorize]` and policies work unchanged.
4. **Explicit, validated configuration** via `IOptions<T>`, validated at startup. The middleware order stays in the
   host's `Program.cs`.
5. **Opt-in capabilities:** refresh tokens, server-side sessions, 2FA, external logins, passkeys, API keys and custom
   password validation are inactive until their interface is registered.
6. **OpenAPI first:** every endpoint carries complete OpenAPI metadata.
7. **Secure by default, few knobs:** convenience is an explicit opt-in (e.g. `SignIn.RevealAccountState`); CSRF,
   refresh-token reuse detection and protocol lifetimes are not configurable.
8. **Native AOT compatible:** source-generated JSON, request delegates and configuration binding.
9. **Observable without dependencies:** `System.Diagnostics.Metrics` and stable log event ids, no personal data in tags.
10. **The host's database never holds usable secrets:** only hashes of tokens, keys and recovery codes, and TOTP secrets
    encrypted with Data Protection.

## 3. Core data model (`SlimUser`)

| Property | Type | Purpose |
| :--- | :--- | :--- |
| `Id` | `string` | User id (`Guid`, `int`, `long` or `string` in the host database). |
| `Email` | `string` | Login identifier (or user name / UPN for LDAP). |
| `PasswordHash` | `string` | `PasswordHasher<SlimUser>` hash. Empty for external-login, passkey-only, LDAP and invited users. |
| `SecurityStamp` | `string` | Opaque, ≤ 64 characters; rotating it invalidates all sessions, tokens and outstanding links. A claims part after a dot (`RefreshClaimsAsync`) only makes sessions reload their claims. |
| `IsActive` | `bool` | Login blocker (ban, soft delete, pending approval). |
| `EmailConfirmed` | `bool` | Address proven. |
| `FailedLoginAttempts` / `LockoutEndUtc` | `int` / `DateTimeOffset?` | Progressive password lockout. |
| `FailedSecondFactorAttempts` / `SecondFactorLockoutEndUtc` | `int` / `DateTimeOffset?` | Separate second-factor lockout. |
| `TwoFactorEnabled` | `bool` | A second factor follows the first. |
| `PasswordChangeRequired` | `bool` | Set by an administrator: the next sign-in must choose an own password. |

No profile or business data – that stays in the host's user model.

## 4. Contracts

| Interface | Required | Enables |
| :--- | :--- | :--- |
| `ISlimUserStore` | yes | find, create, security state, atomic sign-in bookkeeping, e-mail change, host claims |
| `ISlimEmailSender` | yes, unless `WithoutEmail()` | codes, links and notices, each with a `SlimEmailContext` (account, culture, host data) |
| `ISlimRefreshTokenStore` | – | `/refresh` (hashes only, atomic consumption) |
| `ISlimSessionStore` | – | server-side sessions, `/sessions` |
| `ISlimTwoFactorStore` | – | `/login/2fa`, `/2fa/*` (encrypted TOTP secrets, recovery-code hashes, replay protection) |
| `ISlimSecondFactorPolicy` | – | requires a second factor per account |
| `ISlimExternalLoginStore` | – | OAuth/OIDC login and linking (also client certificates) |
| `ISlimPasskeyStore` (package `SlimIdentity.Passkeys`) | – | passkeys (public keys only) |
| `ISlimApiKeyStore` | – | `X-API-Key` authentication (hashes only) |
| `ISlimSharedState` | – | single-use codes and mail limits across instances |
| `ISlimCustomPasswordValidator` | – | LDAP / legacy password verification |
| `ISlimPasswordRule` (any number) | – | additional rules for new passwords |
| `ISlimSignInGuard`, `ISlimRegistrationGuard` (any number) | – | vetoes against sessions and new accounts ([hooks](guides/hooks.md)) |
| `ISlimEventObserver` (any number) | – | security events (observe only) |
| `ISlimRegistrationProfile` | – | business data of a registration ([guide](guides/registration-profile.md)) |
| `ISlimOriginPolicy`, `ISlimLinkBuilder`, `ISlimEmailContextEnricher` | – | per-request origins, links and mail data ([multi-tenancy](guides/multi-tenancy.md)) |

`ISlimAuthManager` is the service for host endpoints: `SignInAsync`, `BeginRegistrationAsync`, `ImpersonateAsync` /
`EndImpersonationAsync`, `ElevateToSudoAsync` / `ElevateSessionAsync` with `ConfirmPasswordAsync`, `SignOutAsync`,
`SignOutEverywhereAsync`, `CreateInvitationAsync`, `RefreshClaimsAsync`, and for administrators `CreateUserAsync`,
`HasSignInMethodAsync`, `SetPasswordAsync`, `CreatePasswordResetAsync`, `ResetTwoFactorAsync` and `UnlockAsync`.

Namespaces: `SlimIdentity` for everything a host uses, `SlimIdentity.Contracts` for the wire DTOs. Endpoints:
[reference](endpoints.md); options: [configuration](configuration.md); threat model: [security](security.md).

## 5. Repository layout

```
src/SlimIdentity/                          the main package
src/SlimIdentity.Testing/                  package: conformance checks for store implementations
src/SlimIdentity.EntityFrameworkCore/      package: EF Core stores on the host's DbContext and user entity
src/SlimIdentity.Passkeys/                 package: passkeys (WebAuthn)
tests/                                     unit, integration and store conformance tests
samples/SlimIdentity.Demo/                 runnable demo with in-memory stores (Native AOT) + .http file
samples/templates/                         copy-paste templates: EfCore, Dapper, Email, Enterprise, Security,
                                           DataProtection, Frontend
docs/                                      references and guides
```

## 6. Design decisions

| Decision | Rationale |
| :--- | :--- |
| `/logout` ends the current session; `/logout-all` ends all | Signing out on the laptop should not sign out the phone. |
| Progressive lockout | NIST SP 800-63B: throttle rather than lock hard; fewer deliberate lockouts of victims. |
| External-login errors are redirects (`?slim_error=`) | The flow is a browser navigation, not a JSON request. |
| Background mail queue | Mail server latency would reveal whether an account exists. |
| Links are stateless and stamp-bound | Single use without a token table; survive restarts. |
| Impersonation carries the admin's stamp | A banned admin cannot keep or return through a running impersonation. |
| mTLS is a template ([guide](guides/client-certificates.md)) | Extra dependency, strongly deployment specific. |
| TOTP secrets are encrypted by the library, not the store | Hardening must not depend on every store author. |
| Recovery codes: 80 bits + per-user salted SHA-256 | Offline search is infeasible; an HMAC key would be one more secret to manage. |
| Replay protection via one "last used" value per user | RFC 6238 §5.2; one atomic compare-and-set covers TOTP steps and e-mail codes. |
| Single-use sign-in challenges via a second "last used" value | Code and challenge times cannot share one counter; no token table. Of two open challenges only the newer completes. |
| Narrow store methods for sign-in bookkeeping | Sign-ins are slow and parallel; writing back the whole user could undo a concurrent password change. |
| EF Core stores: an interface on the host's entity | The host keeps entity, table and key type; generics stay inside the optional package. |
| Passkeys as a package of their own | Most hosts never offer passkeys and should not ship CBOR/WebAuthn code. The package uses core internals (no public "issue a session" API) and requires the core's exact version. No third-party dependency, Native AOT. |
| Store contracts are checked by a test kit | Atomicity, uniqueness and single use are invisible in normal operation; `SlimIdentity.Testing` verifies them against the real database. |
| `CreateAsync` returns `null` for a taken address | The unique index decides; concurrent registrations get the uniform answer. |
| "Remember this device" is stateless and off by default | Signed token bound to the stamp: no table, revoked by every security event. |
| QR codes are rendered by the front end | No image dependency. |
