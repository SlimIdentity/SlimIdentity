# SlimIdentity – Architecture Manifest & Design Specification (v1.2)

> v1.2 describes the current implementation. Deviations from and additions to the v1.1 draft are listed in
> [Appendix A](#appendix-a--changes-since-v11).

## 1. Vision & purpose
**SlimIdentity** is a pragmatic, database-agnostic authentication and security facade for ASP.NET Core. It closes the gap between error-prone hand-written login endpoints and the fixed table schema of `Microsoft.AspNetCore.Identity` (`MapIdentityApi`).

Within minutes SlimIdentity provides hardened, best-practice JSON endpoints for modern web front ends (Blazor, Vue, React) and mobile apps, while leaving databases, ORMs (EF Core, Dapper) and domain models 100 % to the host project.

---

## 2. Core principles (the manifest)
1. **Zero persistence (no database):** The core NuGet package references no EF Core, Dapper or database driver. It talks to the host exclusively through flat C# interfaces. Internal helpers (e.g. the mail queue) stay in memory; whoever needs durability implements it behind an interface (outbox pattern).
2. **No generics, no base classes:** SlimIdentity forces no generic type parameters on the application and requires no inheritance. Internally it works with a single, slim transfer object (`SlimUser`).
3. **Framework native:** SlimIdentity invents no cryptography. It orchestrates `Microsoft.Extensions.Identity.Core` (`PasswordHasher`, `IDataProtector`), the native `ClaimsPrincipal` system, `Microsoft.AspNetCore.RateLimiting` and the standard authentication handlers (cookies, JwtBearer, OAuth/OIDC). All `[Authorize]` attributes and policies work out of the box.
4. **Explicit & validated configuration:** code configuration (fluent API) and/or an `IConfigurationSection` via `IOptions<T>`. `ValidateOnStart()` checks every security-relevant setting at startup (fail fast).
5. **Opt-in complexity (capability pattern):** advanced features (2FA, social login/OIDC, refresh tokens, server-side sessions, API keys, LDAP/custom auth) stay inactive until the developer registers the corresponding interface.
6. **OpenAPI first:** every endpoint carries complete OpenAPI metadata (`.Produces<T>()`, `.WithTags()`, precise DTOs) – including the 403 answer of the CSRF check – so clients can be generated.
7. **Secure by default (new):** where security and convenience conflict, the secure value is the default and the convenient one an explicit opt-in (e.g. `SignIn.RevealAccountState`).

---

## 3. Core data model (`SlimUser` DTO)

| Property | Type | Purpose |
| :--- | :--- | :--- |
| **`Id`** | `string` | Unique user id (`Guid`, `int` or `string` in the host database). |
| **`Email`** | `string` | Primary login identifier (or user name / UPN for LDAP). |
| **`PasswordHash`** | `string` | Hash from `PasswordHasher<SlimUser>`. Empty for OAuth/LDAP users and for **invited** users who have not accepted their invitation yet. |
| **`SecurityStamp`** | `string` | Random value. Rotated on password change, "sign out everywhere", 2FA changes and refresh-token theft; immediately invalidates all cookies, JWTs, refresh tokens and workflow links. |
| **`IsActive`** | `bool` | Login blocker (ban, soft delete, pending approval). |
| **`EmailConfirmed`** | `bool` | Whether the e-mail address has been verified. |
| **`FailedLoginAttempts`** | `int` | Consecutive failed attempts since the last successful sign-in (basis of the progressive lockout). |
| **`LockoutEndUtc`** | `DateTimeOffset?` | End of the current lockout. |
| **`TwoFactorEnabled`** | `bool` | After a successful password check the 2FA state machine applies. |

---

## 4. Contracts (interfaces & services)

### 4.1 Mandatory interfaces

**`ISlimUserStore`** – unchanged since v1.1:
```csharp
public interface ISlimUserStore
{
    Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct);
    Task<SlimUser?> FindByIdAsync(string userId, CancellationToken ct);
    Task<SlimUser> CreateAsync(string email, string passwordHash, CancellationToken ct);
    Task UpdateSecurityStateAsync(SlimUser user, CancellationToken ct);
    Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct);
}
```
`GetClaimsAsync` is where the host adds roles, permissions or tenant ids before the cookie or JWT is issued.

**`ISlimEmailSender`** – three required methods, two optional ones (default interface methods; without an implementation no mail is sent):
```csharp
public interface ISlimEmailSender
{
    Task SendVerificationEmailAsync(string email, string verificationTokenOrLink, CancellationToken ct);
    Task SendPasswordResetEmailAsync(string email, string resetTokenOrLink, CancellationToken ct);
    Task SendTwoFactorCodeAsync(string email, string code, CancellationToken ct);

    // optional
    Task SendAccountExistsEmailAsync(string email, CancellationToken ct) => Task.CompletedTask;
    Task SendLockoutNotificationEmailAsync(string email, DateTimeOffset lockoutEndUtc, CancellationToken ct) => Task.CompletedTask;
}
```
Verification, reset, "account exists" and lockout mails go through a bounded in-memory queue with a background service (`Email.SendInBackground`, default `true`). On a regular shutdown the queue is drained within `HostOptions.ShutdownTimeout`; only a crash loses mails. For guaranteed delivery: outbox sender + `SendInBackground = false` (sample).

### 4.2 Optional capability interfaces
* **`ISlimRefreshTokenStore`** – enables `/auth/refresh`:
  * `StoreRefreshTokenAsync(userId, tokenHash, expiresAt, ct)`
  * `ValidateAndConsumeRefreshTokenAsync(tokenHash, ct)` – returns the `userId` and deletes the token **atomically**.
* **`ISlimSessionStore`** *(new)* – enables server-side sessions (see 5.7):
  * `CreateAsync(SlimSession)`, `FindAsync(sessionId)`, `ListAsync(userId)`, `TouchAsync(sessionId, lastSeen, expires)`, `RevokeAsync(sessionId)`, `RevokeAllAsync(userId, exceptSessionId)`
* **`ISlimTwoFactorStore`** – enables `/auth/login/2fa` and `/auth/2fa/*` (TOTP, e-mail codes, recovery codes). Unchanged.
* **`ISlimExternalLoginStore`** – enables OAuth/OIDC (Google, Apple, Entra ID, Keycloak). Unchanged. For mTLS see section 9.
* **`ISlimApiKeyStore`** – enables the `X-API-Key` handler. Unchanged.
* **`ISlimCustomPasswordValidator`** – LDAP/AD/legacy hashes; brute-force protection, lockout and 2FA stay active. Unchanged.

### 4.3 Library services
```csharp
public interface ISlimAuthManager
{
    Task<SlimAuthResult> SignInAsync(SlimUser user, bool useCookies, bool isPersistent = false, CancellationToken ct = default);

    // Impersonation: the 'act' claim carries the admin's id AND security stamp; if the admin is banned
    // or their stamp rotates, the impersonation ends immediately.
    Task<SlimAuthResult> ImpersonateAsync(SlimUser targetUser, string impersonatorUserId, bool useCookies, CancellationToken ct = default);
    Task<SlimAuthResult> EndImpersonationAsync(CancellationToken ct = default);                       // new

    // Step-up ("sudo" mode): re-issues the current session with extra temporary claims (e.g. sudo_until).
    Task<SlimAuthResult> ElevateSessionAsync(SlimUser user, IEnumerable<Claim> additionalClaims, bool useCookies, CancellationToken ct = default);

    Task SignOutAsync(string? refreshToken = null, CancellationToken ct = default);                    // current session
    Task SignOutEverywhereAsync(SlimUser user, CancellationToken ct = default);                        // new: all sessions (e.g. ban)

    Task<SlimInvitation> CreateInvitationAsync(SlimUser user, TimeSpan? lifetime = null, CancellationToken ct = default); // new
}
```

---

## 5. Security & hardening ("the shield")

1. **Multi-layer brute-force protection**
   * *Layer 1 – IP rate limiting:* policy `SlimIdentity_BruteForce` (default 10/min) for login, 2FA, register, reset and invitations; a separate, generous policy `SlimIdentity_Refresh` (default 60/min) for `/refresh`, because refresh tokens cannot be guessed.
   * *Layer 2 – progressive account lockout (NIST SP 800-63B: throttle rather than lock hard):* every `MaxFailedAttempts` failures lock the account, starting with `Lockout.Duration` (default 1 min) and doubling each time up to `Lockout.MaxDuration` (default 1 h). Only a successful sign-in resets the counter. Attempts during a lockout are neither verified nor counted. The first lockout of a series optionally triggers a notification mail.
2. **Timing-attack mitigation:** unknown e-mail, inactive and locked accounts perform a dummy hash. Oversized passwords (> `Password.MaximumLength`) are never hashed – identically for known and unknown accounts. Token, stamp and code comparisons use `CryptographicOperations.FixedTimeEquals`.
3. **Enumeration prevention:**
   * `/register`, `/forgot-password` and `/resend-verification` always answer identically; mails are sent in the background, so the response time does not depend on the mail server. For `/register` with an existing address the real owner optionally receives "you already have an account".
   * By default `/login` does **not** distinguish a wrong password from an inactive or locked account (uniform `401 invalid_credentials`). `SignIn.RevealAccountState = true` returns `403 account_disabled` / `423`.
4. **Transparent password rehashing** on `SuccessRehashNeeded`.
5. **Stateless workflow tokens:** verification, password reset, invitation, 2FA pre-auth and refresh tokens all use `IDataProtector`, carry an expiry and are bound to the `SecurityStamp` (single use through stamp rotation).
6. **Cookie, CORS & CSRF security:**
   * The cookie is always `HttpOnly` + `Secure` (also correct behind TLS-terminating proxies).
   * `SameSite = Strict` by default, `Lax` for cross-subdomain SPAs.
   * State-changing cookie requests need the `X-CSRF` header; a present `Origin` must be the API itself or listed in `Csrf.AllowedOrigins`.
7. **Sessions & logout (new):**
   * `/logout` ends the **current** session: deletes the cookie, consumes the refresh token and – with `ISlimSessionStore` – revokes the server-side session, so copied cookies/tokens stop working too.
   * `/logout-all` ends **all** sessions on all devices (stamp rotation + `RevokeAllAsync`) and works without a session store.
   * Without a session store sessions stay stateless: a single copied cookie can then only be invalidated via `/logout-all`.
8. **Refresh-token hardening (RFC 9700 / OAuth 2.1, new):**
   * Rotation: every token can be used exactly once.
   * Reuse detection: a genuine but already consumed token is treated as stolen → with a session store the affected session (token family) is revoked, otherwise the stamp rotates (all sessions end). Tokens at the very end of their lifetime are excluded (clock drift). Can be disabled via `Tokens.RevokeSessionsOnRefreshTokenReuse`.
   * Sliding lifetime (`RefreshTokenLifetime`, 7 days) with an absolute cap counted from the original sign-in (`RefreshTokenAbsoluteLifetime`, 30 days, `auth_time` claim).
9. **Impersonation binding (new):** the `act` claim contains the admin's id and stamp; every request also validates the admin. Returning is only possible via `EndImpersonationAsync` (checked again).

---

## 6. REST API (public facade)
Mapped by `app.MapSlimIdentityApi()`. Dual mode via `?useCookies=true` or `Endpoints.DefaultUseCookies`.

| Route (prefix `/auth`) | Method | Available when | Description |
| :--- | :--- | :--- | :--- |
| `/login` | POST | always | 200 (cookie/JWT), 401 `invalid_credentials` or `requires_two_factor` (+ `preAuthToken`); 403/423 only with `RevealAccountState`. |
| `/login/2fa` | POST | `ISlimTwoFactorStore` | `preAuthToken` + TOTP/e-mail code or recovery code → session. |
| `/login/{provider}` (+ `/callback`) | GET | `ISlimExternalLoginStore` | OAuth/OIDC flow. Errors (including the split-account conflict) are redirects with `?slim_error=<code>` – it is a browser navigation, not a `fetch`, hence no `409`. |
| `/login/external/exchange` | POST | `ISlimExternalLoginStore` + JWT | Exchanges the one-time code from the redirect for a JWT pair (tokens never travel in URLs). |
| `/logout` | POST | `EnableLogout` | Ends the current session. |
| `/logout-all` | POST | `EnableLogout` (authenticated) | Ends all sessions. |
| `/refresh` | POST | `ISlimRefreshTokenStore` + JWT | Rotation with reuse detection. |
| `/sessions` | GET | `ISlimSessionStore` (authenticated) | Active devices/sessions incl. "current". |
| `/sessions/{id}` | DELETE | `ISlimSessionStore` (authenticated) | Signs out one device. |
| `/register` | POST | `EnableRegistration` | Only `email` + `password`; always 200. |
| `/verify-email`, `/resend-verification` | POST | `EnableEmailVerification` | |
| `/forgot-password`, `/reset-password` | POST | `EnablePasswordReset` | Reset rotates the stamp and revokes all sessions. |
| `/invitation/info` | POST | `EnableInvitations` | Validates the invitation link, returns the invited address and the expiry. |
| `/invitation/accept` | POST | `EnableInvitations` | Sets the password, confirms the e-mail, signs in (cookie/JWT). |
| `/change-password` | POST | `EnableChangePassword` (authenticated) | Other devices are signed out, the current one stays. |
| `/me` | GET | `EnableMe` (authenticated) | Id, e-mail, impersonation info, claims. |
| `/2fa`, `/2fa/setup`, `/2fa/enable`, `/2fa/enable-email`, `/2fa/disable`, `/2fa/recovery-codes` | GET/POST | `ISlimTwoFactorStore` (authenticated) | |

### 6.1 Invitations / "complete your registration"
1. The host creates the user with its business data but **without a password** (`CreateAsync(email, "")`).
2. `ISlimAuthManager.CreateInvitationAsync(user, lifetime)` returns token, link (`Links.InvitationUrl`) and expiry. Sending it is up to the host (own text, sender, branding).
3. The SPA calls `/invitation/info` (the form shows the address) and `/invitation/accept` (password according to the policy).
4. The link is stateless, bound to the stamp and therefore single use; it survives restarts. Default validity 7 days (max. 30).
5. With `ISlimCustomPasswordValidator` (LDAP) there is no local password – invitations are rejected (`password_managed_externally`).

---

## 7. Integration & developer experience
The middleware order stays in the developer's hands:

```csharp
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"), options =>
    {
        options.Endpoints.EnableRegistration = false;              // e.g. invite-only B2B
        options.Links.InvitationUrl = "https://app.example.com/accept-invitation?token={token}";
        options.Tokens.JwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET")!;
    })
    .AddUserStore<MyUserStore>()                // required
    .AddEmailSender<MyEmailSender>()            // required (or .AddNullEmailSender())
    .AddRefreshTokenStore<MyTokenStore>()       // optional → /refresh
    .AddSessionStore<MySessionStore>()          // optional → real per-device /logout, /sessions
    .AddTwoFactorStore<MyTotpStore>()           // optional → 2FA
    .AddExternalLoginStore<MyOAuthStore>()      // optional → social login / OIDC
    .AddApiKeyStore<MyApiKeyStore>()            // optional → X-API-Key
    .AddCustomPasswordValidator<MyLdap>();      // optional → LDAP / legacy

var app = builder.Build();
app.UseForwardedHeaders();   // only behind a reverse proxy – before everything else (see README)
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapSlimIdentityApi();
```

---

## 8. Repository layout & ecosystem
```
docs/architecture-manifest.md   this document
src/SlimIdentity/               core package (no database, SMTP or ORM dependencies)
tests/SlimIdentity.Tests/       unit and integration tests (in-memory host, fake clock)
tests/SlimIdentityDemo/         runnable demo with in-memory stores + .http file
samples/                        copy-paste templates (compiled by CI via samples/SamplesCheck, not shipped)
  EfCore/       all stores incl. sessions, AppDbContext
  Dapper/       user and refresh store, schema.sql
  Email/        MailKit, SendGrid, logging, outbox (guaranteed delivery)
  Enterprise/   LDAP, legacy hash migration, admin endpoints (impersonation, sudo, invitations, ban, API keys)
  Frontend/     TypeScript client (cookie and bearer flow, device list, invitations)
```

---

## 9. mTLS / client certificates (documented, not built in)
Deliberately not part of the core; this is how to build it with the existing building blocks:

1. **Package:** `Microsoft.AspNetCore.Authentication.Certificate` in the host (it is not part of the shared framework).
2. **Transport:**
   * Kestrel directly: `ClientCertificateMode.RequireCertificate` (or `AllowCertificate` for selected routes only).
   * Behind a TLS proxy: the proxy validates the certificate and forwards it in a header (nginx `proxy_set_header X-Client-Cert $ssl_client_escaped_cert;`). In the app use `AddCertificateForwarding(o => o.CertificateHeader = "X-Client-Cert")` + `UseCertificateForwarding()` – only accept the header from trusted proxies (as with `UseForwardedHeaders`).
3. **Validation:** `AddCertificate(o => { o.AllowedCertificateTypes = CertificateTypes.Chained; o.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust; o.CustomTrustStore = …; o.RevocationMode = X509RevocationMode.Online; })`.
4. **Certificate → user mapping:** via `ISlimExternalLoginStore` with provider `"certificate"` and the SHA-256 thumbprint (or SAN/UPN) as `providerKey` – in the `OnCertificateValidated` event.
5. **Variants:**
   * *Machine-to-machine:* certificate on every request as its own scheme (like API keys), used via `[Authorize(AuthenticationSchemes = …)]`.
   * *User login:* a host endpoint `POST /api/login/certificate` that calls `ISlimAuthManager.SignInAsync(user, useCookies)` after a successful certificate check. Lockout, 2FA requirements and sessions behave like any other sign-in.
6. Certificate-bound tokens (RFC 8705, `cnf`/`x5t#S256`) are not planned.

---

## Appendix A – changes since v1.1

| Area | v1.1 | v1.2 | Reason |
| :--- | :--- | :--- | :--- |
| `/logout` | "deletes the cookie server-side" | Current session; server-side only with `ISlimSessionStore`. New `/logout-all`. | Stateless cookies cannot be revoked individually; signing out on the laptop should not sign out the phone. |
| Server-side sessions | – | `ISlimSessionStore`, `/sessions`, `DELETE /sessions/{id}` | Real per-device logout, device list. |
| `/refresh` | rotation | + reuse detection, absolute lifetime, own rate-limit policy | RFC 9700 / OAuth 2.1. |
| Lockout | fixed duration, counter reset on lockout | progressive (doubling, capped), reset only on success, optional mail | NIST SP 800-63B, less risk of locking users out. |
| `/login` for inactive/locked accounts | `423 Locked`, inactive without hashing | uniform 401 + dummy hash by default; 403/423 via `RevealAccountState` | OWASP: no account enumeration through the login. |
| `/login/{provider}` split account | `409 Conflict` | redirect `?slim_error=account_conflict` | Browser navigation, not a JSON client. |
| Mails | synchronous | background queue, drained on shutdown, outbox sample | Response times would otherwise reveal existing accounts. |
| `ISlimEmailSender` | 3 methods | + `SendAccountExistsEmailAsync`, `SendLockoutNotificationEmailAsync` (optional) | See above. |
| Impersonation | `act` = admin id | `act` = admin id + stamp + amr; `EndImpersonationAsync` | A banned admin must not return through a running impersonation. |
| `ISlimAuthManager` | 3 methods | + `SignOutAsync`, `SignOutEverywhereAsync`, `EndImpersonationAsync`, `CreateInvitationAsync` | Invitations, bans, return from impersonation. |
| Invitations | sample with invite code only | `CreateInvitationAsync` + `/invitation/info` + `/invitation/accept` | Common B2B case that nobody should have to build themselves. |
| mTLS | listed under `ISlimExternalLoginStore` | documented (section 9), not in the core | Extra dependency and highly deployment specific. |
| Reverse proxy | – | docs + demo (`UseForwardedHeaders`), CSRF diagnostic log | Origin check, OAuth redirects and rate limits need the real scheme/IP. |
| Principle 7 | – | "secure by default" | |
| Language | German | English | International open-source project. |
