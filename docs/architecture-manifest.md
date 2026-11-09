# SlimIdentity – Architecture and design principles (1.0)

## 1. Vision and purpose
**SlimIdentity** is a pragmatic, database-agnostic authentication and security facade for ASP.NET Core. It closes the
gap between error-prone hand-written login endpoints and the fixed table schema of `Microsoft.AspNetCore.Identity`
(`MapIdentityApi`).

Within minutes it provides hardened, best-practice JSON endpoints for modern web front ends (Blazor, Vue, React) and
mobile apps, while leaving databases, ORMs (EF Core, Dapper) and domain models entirely to the host project.

## 2. Core principles
1. **Zero persistence in the core:** the `SlimIdentity` package references no EF Core, Dapper or database driver.
   Persistence lives in separate, optional packages (`SlimIdentity.EntityFrameworkCore`) or in the host. It talks to the host
   exclusively through small interfaces. Internal helpers (e.g. the mail queue) stay in memory; durability is
   implemented by the host behind an interface (outbox pattern).
2. **No generics, no base classes:** no generic type parameters on the application, no inheritance. Internally a
   single transfer object (`SlimUser`) carries the security state.
3. **Framework native:** no custom cryptography. SlimIdentity orchestrates `PasswordHasher`, Data Protection, the
   `ClaimsPrincipal` system, `Microsoft.AspNetCore.RateLimiting` and the standard cookie, JWT bearer and OAuth/OIDC
   handlers. `[Authorize]` and policies work unchanged.
4. **Explicit, validated configuration:** code and/or `IConfiguration` via `IOptions<T>`; every security-relevant
   setting is validated at startup (fail fast). The middleware order stays in the host's `Program.cs`.
5. **Opt-in complexity (capability pattern):** refresh tokens, server-side sessions, 2FA, external logins, API keys and
   custom password validation are inactive until the corresponding interface is registered.
6. **OpenAPI first:** every endpoint carries complete OpenAPI metadata, so clients can be generated.
7. **Secure by default, few knobs:** where security and convenience conflict, the secure value is the default and the
   convenient one an explicit opt-in (e.g. `SignIn.RevealAccountState`). Protections that should never be off (CSRF,
   refresh-token reuse detection, protocol lifetimes) are not configurable at all.
8. **Native AOT compatible:** source-generated JSON, request delegates and configuration binding; CI publishes an AOT app.
9. **Observable without dependencies:** metrics via `System.Diagnostics.Metrics`, logs with stable event ids – never
   personal data in tags.
10. **The host's database never holds usable secrets:** only hashes of tokens, keys and recovery codes, and TOTP
    secrets encrypted with Data Protection.

## 3. Core data model (`SlimUser`)

| Property | Type | Purpose |
| :--- | :--- | :--- |
| `Id` | `string` | Unique user id (`Guid`, `int` or `string` in the host database). |
| `Email` | `string` | Login identifier (or user name / UPN for LDAP). |
| `PasswordHash` | `string` | `PasswordHasher<SlimUser>` hash. Empty for external-login, LDAP and not yet accepted invited users. |
| `SecurityStamp` | `string` | Random value (≤ 64 characters, opaque); rotating it invalidates all sessions, tokens and outstanding links. A claims part after a dot (`RefreshClaimsAsync`) only makes sessions reload their claims. |
| `IsActive` | `bool` | Login blocker (ban, soft delete, pending approval). |
| `EmailConfirmed` | `bool` | E-mail verified. |
| `FailedLoginAttempts` | `int` | Consecutive failures since the last successful sign-in (progressive lockout). |
| `LockoutEndUtc` | `DateTimeOffset?` | End of the current lockout. |
| `TwoFactorEnabled` | `bool` | The 2FA state machine applies after a correct password. |
| `PasswordChangeRequired` | `bool` | Set by an administrator: the next sign-in must choose an own password first. |

No profile or business data – that stays in the host's own user model.

## 4. Contracts

| Interface | Required | Enables |
| :--- | :--- | :--- |
| `ISlimUserStore` | yes | everything (find, create, persist security state, atomic sign-in bookkeeping, change e-mail, host claims) |
| `ISlimEmailSender` | yes, unless `WithoutEmail()` | verification, reset, 2FA codes, e-mail change; optional "account exists", lockout and "address changed" notices – each with a `SlimEmailContext` (account, culture, host data) |
| `ISlimRefreshTokenStore` | – | `/refresh`, refresh tokens (hashes only, atomic consumption) |
| `ISlimSessionStore` | – | server-side sessions, per-device logout, `/sessions` |
| `ISlimTwoFactorStore` | – | `/login/2fa`, `/2fa/*` (encrypted TOTP secrets, recovery-code hashes, replay protection, single-use challenges) |
| `ISlimExternalLoginStore` | – | OAuth/OIDC login and account linking (also used for client certificates) |
| `ISlimPasskeyStore` | – | passkeys (WebAuthn): `/passkeys/*`, public keys only, atomic single use per challenge |
| `ISlimApiKeyStore` | – | `X-API-Key` authentication (key hashes only) |
| `ISlimCustomPasswordValidator` | – | LDAP / legacy password verification |
| `ISlimPasswordRule` (any number) | – | additional rules for new passwords (e.g. breached-password check) |
| `ISlimSignInGuard` (any number) | – | veto before and during every session (tenants, IP allow-lists) – [hooks](guides/hooks.md) |
| `ISlimRegistrationGuard` (any number) | – | veto against new accounts (company domains, captcha) |
| `ISlimEventObserver` (any number) | – | security events for audit trails and alerts (observe only) |

`ISlimAuthManager` is the service for host endpoints: `SignInAsync`, `RegisterAsync`, `ImpersonateAsync` /
`EndImpersonationAsync`, `ElevateSessionAsync` (sudo) with `ConfirmPasswordAsync`, `SignOutAsync`,
`SignOutEverywhereAsync`, `CreateInvitationAsync`, `RefreshClaimsAsync`, and for administrators `SetPasswordAsync`,
`CreatePasswordResetAsync`, `ResetTwoFactorAsync` and `UnlockAsync`.

## 5. Security mechanisms
Summarized here; details and the threat model are in [security.md](security.md).

1. Brute-force protection in two layers: per-client rate limiting (IPv6 grouped by prefix; separate, generous policy
   for `/refresh`) and a progressive account lockout.
2. Timing and enumeration resistance: dummy hashing, uniform answers, background mail queue, hidden account state.
3. Stateless workflow tokens via Data Protection, bound to the security stamp (single use, no token table).
4. Cookie hardening (`HttpOnly`, `Secure`, `SameSite=Strict`) and CSRF protection (custom header + `Origin` check).
5. Refresh-token rotation with reuse detection (RFC 9700) and an absolute session lifetime.
6. Security-stamp and server-side-session validation of every bearer request and periodically of cookies.
7. Impersonation bound to the impersonator's security state.
8. Transparent password rehashing when the hash algorithm parameters change.
9. 2FA hardening: TOTP secrets encrypted at rest, 80-bit recovery codes hashed per user, every code accepted once.
10. E-mail change with password confirmation, confirmation by the new address and notification of the old one.

## 6. Public API surface
Endpoints: see the [endpoint reference](endpoints.md). Options: see the [configuration reference](configuration.md).
Namespaces: `SlimIdentity` for everything a host uses, `SlimIdentity.Contracts` for the wire DTOs of the endpoints.

## 7. Integration
```csharp
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))
    .AddUserStore<MyUserStore>()
    .AddEmailSender<MyEmailSender>()
    .AddRefreshTokenStore<MyTokenStore>();     // further capabilities as needed

var app = builder.Build();
app.UseForwardedHeaders();   // only behind a reverse proxy
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapSlimIdentityApi();
```

## 8. Repository layout
```
src/SlimIdentity/                          the main package
src/SlimIdentity.Testing/                  package: conformance checks for store implementations (test projects only)
src/SlimIdentity.EntityFrameworkCore/      package: EF Core stores on the host's DbContext and user entity
tests/SlimIdentity.EntityFrameworkCore.Tests/  conformance of the EF Core package on SQLite, PostgreSQL, SQL Server
tests/SlimIdentity.Tests/                  unit and integration tests (in-memory host, fake clock, fake OAuth provider)
tests/SlimIdentity.Samples.Tests/          compiles the copy-paste templates; conformance of the EF Core stores (SQLite)
samples/SlimIdentity.Demo/                 runnable demo with in-memory stores (Native AOT) + .http file
samples/templates/                         copy-paste templates (not shipped): EfCore, Dapper, Email, Enterprise,
                                           Security, DataProtection, Frontend
docs/                                      this document, references and guides
assets/                                    package icon
```

## 9. mTLS / client certificates (documented, not built in)
Deliberately not part of the package (extra dependency, highly deployment specific). A complete template is in
`samples/templates/Enterprise/CertificateAuthentication.cs` ([guide](guides/client-certificates.md)). The building blocks:

1. **Package:** `Microsoft.AspNetCore.Authentication.Certificate` in the host.
2. **Transport:** Kestrel with `ClientCertificateMode.RequireCertificate` (or `AllowCertificate` for selected routes),
   or a TLS proxy that validates the certificate and forwards it in a header (nginx
   `proxy_set_header X-Client-Cert $ssl_client_escaped_cert;`) together with `AddCertificateForwarding` +
   `UseCertificateForwarding()` – accept the header only from trusted proxies.
3. **Validation:** `AddCertificate(o => { o.AllowedCertificateTypes = CertificateTypes.Chained; o.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust; o.CustomTrustStore = …; o.RevocationMode = X509RevocationMode.Online; })`.
4. **Mapping to users:** `ISlimExternalLoginStore` with provider `"certificate"` and the SHA-256 thumbprint (or SAN/UPN)
   as provider key, resolved in `OnCertificateValidated`.
5. **Usage:** machine-to-machine – certificate scheme per request (like API keys); user login – a host endpoint that
   calls `ISlimAuthManager.SignInAsync` after the certificate check (lockout, 2FA and sessions apply as usual).
6. Certificate-bound tokens (RFC 8705) are not planned.

## 10. Design decisions

| Decision | Rationale |
| :--- | :--- |
| `/logout` ends the current session; `/logout-all` ends all | Signing out on the laptop should not sign out the phone; stateless cookies cannot be revoked individually without a session store. |
| Server-side sessions are optional | Stateless works for many apps; real per-device revocation needs state, so it is an opt-in capability. |
| Refresh-token reuse revokes the token family | RFC 9700 / OAuth 2.1 recommendation against stolen refresh tokens. |
| Progressive lockout instead of a fixed one | NIST SP 800-63B: throttle rather than lock hard; reduces deliberate lockouts of victims. |
| Uniform `/login` answer for inactive and locked accounts | OWASP: no account enumeration through the login; opt-in for explicit states. |
| External-login errors are redirects (`?slim_error=`), not `409` | The flow is a browser navigation, not a JSON request. |
| Background mail queue | Mail server latency would otherwise reveal whether an account exists. |
| Invitation links are stateless and stamp-bound | Single use without a token table; survive restarts. |
| Impersonation carries the admin's stamp | A banned admin must not keep or return through a running impersonation. |
| mTLS is a template, not built in | Extra dependency, strongly deployment specific; the template covers the common cases. |
| One root namespace for host-facing types | Fewer `using` directives; wire DTOs separated in `SlimIdentity.Contracts`. |
| TOTP secrets are encrypted by the library, not by the store | "Hardened" must not depend on every store author remembering it; the key ring has to be protected anyway. |
| Recovery codes: 80 bits + per-user salted SHA-256 instead of a keyed HMAC | At 80 bits an offline search is infeasible; a separate HMAC key would add a secret to manage (and lose) without real gain. |
| Replay protection via one "last used" value per user | RFC 6238 §5.2; a single atomic compare-and-set covers TOTP steps and e-mail codes. |
| Single-use challenges via a second "last used" value | Code times and challenge times cannot share one counter (a code from the current step may predate a new challenge); a second compare-and-set needs no token table. Of two open challenges only the newer one can still complete. |
| Narrow store methods for sign-in bookkeeping | Sign-ins are slow (hashing) and parallel; writing back the whole user could undo a concurrent password change, and read-modify-write would lose failed attempts. One small statement each is easy to implement atomically in any database. |
| Few options, secure behaviour fixed | Every switch is something to understand and a way to weaken the protection. JWT is enabled by its secret, all links derive from one `BaseUrl`, one `TrustedOrigins` list serves CSRF and redirects; CSRF, reuse detection and protocol lifetimes are not configurable. |
| EF Core stores as a package: an interface on the host's entity, not a base class or a fixed table | The host keeps its user entity, table and key type (`Guid`, `int`, `long`, `string`); SlimIdentity only needs thirteen properties besides the key. Generics are fine here – they stay inside the optional package, the core API remains generic-free. |
| Store contracts are checked by a test kit, not just documented | The guarantees that matter (atomicity, uniqueness, single use) are invisible in normal operation; `SlimIdentity.Testing` makes them verifiable against the real database. Separate package, so test code never ships to production. |
| No password composition rules | NIST SP 800-63B: length and a breached-password check beat character classes; classic rules remain possible as an `ISlimPasswordRule`. |
| `CreateAsync` returns `null` for a taken address | The unique index decides, not a prior lookup – concurrent registrations get the uniform answer instead of an error. |
| Metrics via `System.Diagnostics.Metrics` | Zero dependency, OpenTelemetry-ready, no cost when nobody listens. |
| "Remember this device" is stateless and off by default | Signed token bound to the security stamp: no table, revoked by every security event; "forget all" rotates the stamp (other sessions end, too). |
| QR codes are rendered by the front end | No image dependency; the front end controls size and styling. |
