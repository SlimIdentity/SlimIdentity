# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

First public release (0.9.0) in preparation: feature-complete, but the API may still change before 1.0. Version 1.0
follows an independent security audit and feedback from first production use; from then on, breaking changes only
with a new major version.

### Added

- Hardened JSON endpoints under `/auth`: login (cookie or JWT), 2FA, external login (OAuth/OIDC), refresh, logout,
  logout-all, sessions, register, e-mail verification, password reset/change, invitations, `/me`.
- Database-agnostic stores: `ISlimUserStore` (required) and optional capabilities for refresh tokens, server-side
  sessions, 2FA, external logins, API keys and custom password validation (LDAP / legacy hashes).
- `ISlimAuthManager` for host endpoints: sign-in, impersonation (RFC 8693 `act` claim), step-up "sudo" mode,
  sign out everywhere, invitations.
- Security: per-client rate limiting (IPv6 grouped by prefix), progressive account lockout, uniform answers and timing
  against account enumeration, CSRF protection for cookies, refresh-token rotation with reuse detection and absolute
  lifetime, security-stamp based session invalidation, background mail queue.
- 2FA hardening: TOTP secrets encrypted with Data Protection before they reach the store, 80-bit recovery codes hashed
  per user, replay protection for TOTP and e-mail codes (`ISlimTwoFactorStore.TryMarkCodeUsedAsync`).
- Optional "remember this device" for 2FA (`TwoFactor.RememberDeviceLifetime`, off by default): cookie or bearer token
  bound to user and security stamp, `/2fa/forget-device` and `/2fa/forget-all-devices`.
- E-mail change: `/change-email` (password confirmation) and `/confirm-email-change` (link to the new address,
  notification of the old one, all sessions end).
- Pluggable password rules (`ISlimPasswordRule`, `AddPasswordRule<T>()`), e.g. a breached-password check, and
  `GET /password-policy` so front ends can show and live-check the active rules.
- Metrics on the meter `SlimIdentity` (System.Diagnostics.Metrics, OpenTelemetry-ready) and source-generated logs with
  stable event ids.
- Race and replay hardening: sign-in challenges (`preAuthToken`) complete at most one sign-in
  (`ISlimTwoFactorStore.TryMarkChallengeUsedAsync`); atomic, narrow sign-in bookkeeping in `ISlimUserStore`
  (`TryBeginAttemptAsync`, `ResetFailedAttemptsAsync`, `UpdatePasswordHashAsync`) so parallel failures are all counted and never undo a password change; `CreateAsync`
  returns `null` for a taken address (uniform answer for concurrent registrations); CSRF check for the 2FA step of a
  cookie sign-in.
- Lean configuration: most apps set only `Tokens.JwtSecret` (enables bearer tokens), `Links.BaseUrl` (all mail links)
  and `TrustedOrigins` (CSRF origin check and external-login return URLs in one list). Security-relevant protocol
  details (CSRF, refresh-token reuse detection, challenge and code lifetimes, TOTP tolerance, recovery codes) are fixed
  by design; passwords follow NIST SP 800-63B (length, no composition rules).
- `SlimIdentity.EntityFrameworkCore` package: `ISlimUserEntity<TKey>` on your own user entity,
  `modelBuilder.ApplySlimIdentity<AppUser, Guid>()` and `.AddEntityFrameworkStores<AppDbContext, AppUser, Guid>()` –
  all stores on your `DbContext` (Guid, int, long or string keys), optional claims provider and user factory. Verified
  on SQLite, PostgreSQL and SQL Server.
- `SlimIdentity.Testing` package: `SlimStoreConformance.VerifyAsync(services)` checks store implementations against
  their contracts – lookup, uniqueness, atomic counters and single-use consumption under parallel requests – with any
  test framework and against the real database. CI runs it against the test stores and the EF Core templates (SQLite).
- Quality gates: .NET analyzers (`latest-recommended` plus selected rules, warnings fail CI), CodeQL
  `security-extended` (once the repository is public), property-based tests (FsCheck) for every parser of outside
  input – return URLs, origins, workflow tokens, claims, Base32/TOTP, rate-limit keys.
- Abuse protection: pre-account hijacking defused (the first proof of the mailbox removes the registrant's password,
  2FA and sessions), addresses Unicode-normalized (NFC), mail limit per recipient against mail bombing,
  `AddNullEmailSender()` refuses to start in `Production`, no secrets or addresses in logs (tested).
- [Attack scenarios](docs/attack-scenarios.md): review checklist with the covering test per scenario.
- Playground in the demo (every flow clickable, fake mailbox, virtual authenticator, request log),
  `docker compose up` and a local [Breakme mode](BREAKME.md) with secret passwords for the seeded accounts.
- The TypeScript client template is type-checked (`tsc --strict`) in CI.
- Several instances: deployment diagnostics (unapplied forwarded headers, local key ring, missing Data Protection
  application name, exchange codes without a shared store – log events 8001–8004), a two-instance test suite proving
  that no sticky sessions are needed, and the guide [Running several instances](docs/guides/multiple-instances.md).
- Native AOT and trimming compatibility.
- Samples for EF Core, Dapper, MailKit, SendGrid, outbox delivery, LDAP, client certificates (mTLS), Data Protection
  key ring persistence, Have I Been Pwned, admin endpoints and a TypeScript client (incl. QR code for TOTP setup).
- `ISlimAuthManager.ConfirmPasswordAsync` – password confirmation for host endpoints (sudo mode) with the lockout
  rules of the built-in endpoints.
- Password hashes use 210,000 PBKDF2-HMAC-SHA512 iterations by default (OWASP); older hashes are upgraded at the next
  sign-in, a host value always wins.
- `Tokens.PreviousJwtSecrets` – rotate the JWT secret without rejecting tokens during a rolling deployment.
- `AddConfigurationApiKeys(section)` – API keys from configuration (hashes, scopes, roles, expiry, revocation by
  reload) and `tools/new-api-key.cs` to create key and hash; machine-to-machine-only hosts need neither user store nor
  mail sender.
- `SlimUser` is sealed.
- `SlimEmailContext` on every `ISlimEmailSender` method: kind of mail, account id, the request's culture (captured for
  the background queue) and host data from `AddEmailContextEnricher<T>()` – localized and branded mails, tenants.
  `SlimEmailKinds` lists the kinds. **Breaking** for mail senders.
- `WithoutEmail()` – hosts without a mail server: no sender, no mail-based endpoints, contradictions stop the start.
- `TwoFactor.AllowEmailCodes` – switch off e-mail as second factor; affected accounts sign in with a recovery code.
- Administration in `ISlimAuthManager`: `SetPasswordAsync` (start password, forced change by default),
  `CreatePasswordResetAsync` (reset link to hand over – no proof of the mailbox), `ResetTwoFactorAsync`, `UnlockAsync`.
- Hooks that only tighten: `ISlimSignInGuard` (veto before every session, at renewals and for running sessions),
  `ISlimRegistrationGuard` (veto against new accounts, also external auto-registration), `ISlimEventObserver`
  (security events: sign-ins, failures, lockouts, password and 2FA changes, impersonation, …). `SlimAuthResult`
  carries `Vetoed` / `ErrorMessage`.
- Tenants with own domains: `ISlimOriginPolicy` (`AddOriginPolicy<T>()`) decides trusted origins per request for the
  CSRF check, `returnUrl` and CORS; `ISlimLinkBuilder` (`AddLinkBuilder<T>()`) builds mail, reset and invitation links
  per request. `AddCorsPolicy()` derives CORS from the same origins (`SlimIdentityDefaults.CorsPolicy`).
- Releases attest their build provenance (`gh attestation verify <package>.nupkg --owner SlimIdentity`, SECURITY.md);
  OpenSSF Scorecard workflow and badge. The repository moved to the organization `SlimIdentity`
  (`https://github.com/SlimIdentity/SlimIdentity`).
- Playground: passkeys – add, sign in, autofill, sign-in methods with sync status, rename, remove – with a virtual
  passkey (ES256 in WebCrypto) that answers like a real authenticator, so no phone or security key is needed. The demo
  references `SlimIdentity.Passkeys`, so the Native AOT publish in CI checks the passkey package as well.
- Tests with one user store per tenant and colliding ids: links, refresh tokens and access tokens of one tenant are
  refused by the other (bound to the security stamp); the multi-tenancy guide documents the one exception
  (`ValidateSecurityStampOnEachRequest = false`).
- Guide "The first administrator": seeding by code at start-up (start password with forced change, or a reset link),
  roles through the registration profile, database seeds. The minimal setup covers a front-end dev server on another
  port (proxy or `AddCorsPolicy()`) and initializes `SecurityStamp` in the user entity; the README separates what is in
  the box from what can be switched on.
- Registration with business data: `/register` takes an optional `profile`, validated by the host's
  `ISlimRegistrationProfile` (`AddRegistrationProfile<T>()`) before anything is looked up (`400 profile.<field>`;
  refused without a hook) and passed to the store as `SlimNewUser.Profile` – account and profile are created together.
  `ISlimAuthManager.RegisterAsync` gives host endpoints every rule of `/register` (validation, guards, uniform answer
  and mails, event). **Breaking:** `ISlimUserStore.CreateAsync(SlimNewUser, ct)` replaces `(email, passwordHash, ct)`;
  EF Core package `ISlimUserFactory<TUser>.Create(SlimNewUser)` (refuses a profile without a factory).
- Passkeys (WebAuthn), opt-in, in the separate package `SlimIdentity.Passkeys` (the core contains no WebAuthn code;
  `AddPasskeyStore<T>()`, `AddPasskeys(o => …)`; checks at start-up that it has the core's version):
  `ISlimPasskeyStore` (EF Core package table `SlimPasskeys`, `o.Passkeys = true`; EF Core and Dapper
  templates; conformance checks), registration for signed-in users (password, confirmed address), sign-in without user
  name (`amr: passkey`, multi-factor on its own), rename / remove in the sign-in methods with last-method protection.
  ES256 and RS256, every check of WebAuthn Level 2 §7.1/§7.2 without attestation, atomic single use per challenge,
  clone detection by counter. Options `RelyingPartyId` / `RelyingPartyName` (`AddPasskeys`); TypeScript `addPasskey`,
  `loginWithPasskey`, `loginWithPasskeyAutofill` (browser autofill, conditional mediation), `renamePasskey`,
  `removePasskey`. Backup flags: synced or device-bound (`backupEligible` / `backedUp` in `/sign-in-methods`, updated at
  every sign-in; inconsistent flags or a changed eligibility are refused). No third-party dependency
  (`System.Formats.Cbor` is part of ASP.NET Core).
- Sign-in methods: `GET /auth/sign-in-methods` (password, linked external logins) and
  `POST /auth/sign-in-methods/external/remove` – password required, never the last way in. `ISlimExternalLoginStore`
  gains `GetExternalLoginsAsync` and `RemoveExternalLoginAsync` (checked by the conformance kit). **Breaking** for
  external-login stores.
- OpenID Connect Back-Channel Logout: `AddBackChannelLogout(provider, …)` maps `POST /auth/backchannel-logout/{provider}`;
  a validated logout token from an enterprise identity provider ends every session of the user linked to its `sub`.
- `ISlimAuthManager.RefreshClaimsAsync(user)`: after a change of roles or permissions, running sessions reload their
  claims at their next validation – bearer on the next request, cookies within the validation interval – without a
  sign-out. The security stamp gets a claims part (`<security>.<claims>`, no schema change); every stamp comparison
  ignores it (`SlimUser.IsSameSecurityState`), so links, refresh tokens and remembered devices stay valid. Claims are
  reloaded only for a changed user. Guide "Roles and permissions" and a groups-to-permissions example in the EF Core
  template (`Enterprise/GroupEndpoints.cs`).
- Forced password change: `SlimUser.PasswordChangeRequired` (new column for stores, checked by the conformance kit),
  `401 password_change_required` at `/login` and `POST /auth/login/password-change`; TypeScript client support.
- `UseSlimErrorRedirects()` for remote handlers (Google, OpenID Connect, …): a sign-in cancelled at the provider
  returns to the front end with `?slim_error=access_denied`, an answer that cannot be matched with
  `?slim_error=external_login_failed` – instead of the back end's error page. Log 5015, metric results `cancelled` and
  `failed`.
- Guide "Google and Microsoft Entra ID" (step by step, including when to trust a provider's address), and an opt-in
  "Sign in with Google" button in the playground.

### Security (external review round 1)

Every finding was first proven by a failing test (`ReviewRound1Tests`, `SharedContextTests`,
`HostEndpoint.R7_*` / `Q3_*`); details in [attack scenarios](docs/attack-scenarios.md).

- External login no longer creates an account for an e-mail address the provider has not verified
  (`slim_error=email_not_verified`); the owner's first mailbox proof also removes external logins linked before.
- Bearer external login uses PKCE (S256): `code_challenge` is required, the exchange needs the `codeVerifier`.
  Exchange codes and 2FA challenges travel in the URL fragment, never in the query. **Breaking** for bearer clients.
- `/2fa/enable` requires the current password, and its setup token dies with the security stamp. **Breaking.**
- Parallel password and 2FA guesses beyond the lockout threshold are no longer evaluated (attempts of one account run
  one after another per instance).
- The account endpoints accept cookies and bearer tokens only; a user-bound API key can no longer act as the user or
  mint a session there.
- EF Core stores work on their own `DbContext` instance per request (`SlimEfContext<TContext>`) instead of the host's:
  they no longer save the host's pending changes or detach its entities. The EF Core template uses `IdentityDb`.
- `ElevateSessionAsync` refuses to elevate anyone but the signed-in user.
- Workflow tokens (links, challenges, exchange codes, refresh tokens) carry their own expiry, checked against the
  injected `TimeProvider`. Tokens issued before this change are no longer accepted.

### Security (external review round 2)

- The attempt queue of an account is keyed by its user id: spellings of one address (`User@…`, `USER@…`) no longer
  get queues of their own. At most 8 attempts wait per account; further ones are refused without being evaluated
  (metric result `attempts_queued`), and refused attempts burn their dummy hash outside the queue.
- Every answer under `/auth` carries `Cache-Control: no-store`.
- Pre-account hijacking through the verification link: the owner's click confirmed the address but not who set the
  password, and a later verified external login joined the account – the registrant kept a password to it. Accounts
  with a password are no longer joined automatically (`account_conflict`); signed-in users link providers with the new
  PKCE-bound link flow (`/login/{provider}?link=true`, `POST /link/external`, TypeScript `linkWith` /
  `completeLink`). **Breaking** for users who relied on automatic linking of password accounts.
- A second factor requires a confirmed address (`403 email_not_confirmed`, not with `WithoutEmail()`): neither can a
  registrant plant one, nor can a password reset through a compromised mailbox strip one from a legitimate user.

### Security (external review round 3)

- The first proof of the mailbox (password reset of an unconfirmed account, verified external sign-in) also removes
  the account's passkeys – relevant for accounts imported or created while mail was off. `ISlimPasskeyStore` gains
  `RemovePasskeysAsync` (checked by the conformance kit). **Breaking** for passkey stores.
- RS256 passkeys need a modulus of at least 2048 bit; a weak key zero-padded to 256 bytes is refused.
- A passkey sign-in checks the account (active, confirmed) before it records the use on the passkey.
- `ISlimAuthManager.SignInAsync` applies the rules of `/login` after the first factor: inactive, locked, unconfirmed
  (with `RequireConfirmedEmail`) accounts and administrator-set passwords are refused; with 2FA no session is issued –
  `SlimAuthResult.TwoFactorChallenge` holds the challenge the client completes at `/login/2fa`. New parameters
  `authenticationMethod` (the session's `amr`, e.g. `cert`) and `secondFactorVerified`. Before, a host endpoint could
  issue a session for a locked account or skip the second factor; the client-certificate template did not check
  confirmation and forced password changes. **Breaking** for callers that relied on the old behaviour.
- The "remember this device" proof is taken only from its own mode: the cookie for cookie sign-ins, the token in the
  body for bearer sign-ins – a browser's cookie no longer lets a token request skip the second factor.
- The in-memory one-time-code registry (link codes, back-channel logout tokens, exchange codes without a refresh-token
  store) is bounded (100,000 entries, purged at most once per second, full = refused) instead of growing and scanning
  on every request.
- EF Core package and template: counting a failed sign-in of a user deleted in the meantime returns 0 instead of
  throwing.
- One clock for every expiry: JWTs are validated against the registered `TimeProvider` they were issued with (before:
  the system clock); `SlimAuthResult.ToResponse()` computes `expiresIn` from the issue time and no longer takes a
  `DateTimeOffset` (callers passed `DateTimeOffset.UtcNow`); sudo windows come from
  `ISlimAuthManager.ElevateToSudoAsync(user, duration, useCookies)`, and `SlimClaims.SudoFor` requires the
  `TimeProvider`. **Breaking.**
- Validation errors carry `"code": "validation_failed"` next to the field errors (their `status` is the HTTP status
  number per RFC 9457); the TypeScript client reports that code.
- A user without a security stamp (seeded or imported by the host) gets one at the first sign-in (log event 3011)
  instead of being signed out at the first validation.
- The conformance kit checks that `FindByIdAsync` returns `null` for malformed ids.

### Security (external review round 4)

- Accounts without a password (external login, passkeys) confirm sensitive changes – adding or removing a sign-in
  method, every 2FA change, an e-mail change – with a sign-in within the last 5 minutes instead of a password they do
  not have (`403 reauthentication_required`). Before, a stolen session cookie could add the attacker's passkey and
  remove the owner's external login without any proof, and the 2FA page counted the missing password as failed
  attempts until the account was locked. `ISlimCustomPasswordValidator.HasPasswordAsync` (default `true`) tells which
  accounts a custom validator considers to have a password; `ISlimAuthManager.ConfirmPasswordAsync` follows the same rule.
- Addresses must be plain: `Name <addr>` and `addr (comment)` – accepted by `MailAddress` and delivered to the inner
  address – no longer bypass the mail limit per recipient or create look-alike accounts (`/register`, `/change-email`,
  `RegisterAsync`, external logins).
- Back-channel logout tokens without `jti` are rejected (required by the specification; needed for single use).
- Ending an impersonation returns to the administrator's own sign-in (`auth_time`, absolute lifetime) instead of a
  fresh session chain.
- Without `ISlimSessionStore`, refreshes and other renewals were reported as new sign-ins (guard stage `SignIn`, event
  `signed_in`); the stage now follows the original sign-in time.
- A forced password change (start password set by an administrator) is no longer skipped with a passkey or an
  external login: both answer `password_change_required` without a session until the start password is replaced, and
  the session issuance refuses new sign-ins with a pending change as a backstop.
- Mutation fuzzing of the WebAuthn parsers (`WebAuthnFuzzTests`, several million inputs before the release) found three
  inputs that ended in an exception – HTTP 500 instead of "invalid": client data with invalid UTF-8, an EC point off the
  curve, CBOR integers beyond 32 bits. All are answered as invalid now.
- An authenticator can be enabled right after a sign-in with an e-mail code (both share the "last code" marker).
- LDAP template: password reset and registration are switched off as in the guide; the legacy-migration example handles
  accounts without a hash.
- TypeScript client: the bearer flow gains 2FA setup (`setupAuthenticator`, `enableAuthenticator`,
  `enableEmailTwoFactor`, storing the renewed tokens), `twoFactorStatus`, `me`, `changeEmail`, `confirmEmailChange`,
  `logoutAll`, `sessions`, `revokeSession`, `invitationInfo`, `acceptInvitation`, `forgetAllDevices`; the cookie flow
  `twoFactorStatus` and `enableEmailTwoFactor`.

### Security (external review round 5)

- Multi-tenancy: `UseTenantKey(http => …)` binds cookies and access tokens to the tenant they were issued in
  (`slim_tenant` claim, checked on every request before any validation interval). Before, a cookie of tenant A was
  accepted by tenant B within `SecurityStampValidationInterval` – with ids colliding across tenants even as B's user.
  Required with a store per tenant; the multi-tenancy guide no longer claims cookies were rejected without it.
- An impersonation is bound to the administrator's session it was started from (with `ISlimSessionStore`): revoking
  that session ends the impersonation, and `EndImpersonationAsync` resumes it instead of issuing a fresh admin session.
  `SlimActor.SessionId` names it.
- **Breaking:** `ImpersonateAsync(target, ct)`, `ElevateToSudoAsync(user, duration, ct)` and
  `ElevateSessionAsync(user, claims, ct)` take the administrator and the mode (cookie / bearer) from the current
  session; the free `impersonatorId` and `useCookies` parameters are gone (a wrong value shortened cookie sessions or
  set cookies for bearer clients).
- Wrong passwords no longer count towards the lockout of accounts without a password, so a stranger cannot lock out
  an external-login or passkey account; claiming an account through a verified external login clears a pending start
  password (`PasswordChangeRequired`) and the lockout state.
- An impersonation never counts as the owner's recent sign-in (`ConfirmPasswordAsync`, sudo, sign-in method changes).
- **Breaking:** without `app.UseRateLimiter()` the rate-limited endpoints fail with an `InvalidOperationException`
  naming the missing call, instead of running without brute-force protection.
- `email_verified` of an external provider only vouches for a real `email` claim, not for fallback claims.
- `PreviousJwtSecrets` work for real tokens: every secret gets its own key id (`kid`). Tokens issued before this
  version (old common key id) are still accepted.
- **Breaking:** `SlimAuthResult.ToResponse()` throws for a failed result instead of reporting `status: "success"` with
  no token. `/change-password`, `/2fa/disable` and `/2fa/forget-all-devices` answer `401 session_expired` ("the change
  was saved, sign in again") when the session cannot be renewed – e.g. at the end of the refresh chain; `/2fa/enable`
  returns the recovery codes without a session then.
- **Breaking:** records carrying passwords, tokens or codes (requests, `SlimAuthResult`, `SlimPasswordReset`,
  `SlimInvitation`, 2FA setup and recovery-code responses, passkey requests) print `***` for them in `ToString()`, so
  a logged request no longer leaks secrets.
- **Breaking:** one name per account state: `account_disabled` and `locked_out` everywhere (`SlimAuthResult.Error`,
  HTTP, external-login `slim_error`, event and metric reasons) – before also `account_inactive`, `inactive` and
  `account_locked`. The error codes are documented in the endpoint reference.
- **Breaking (store contract):** `ISlimUserStore.UpdateSecurityStampAsync(user, expectedStamp, newStamp, ct)` – a
  compare-and-set on the stamp only. Sign out everywhere, `RefreshClaimsAsync` and `/2fa/forget-all-devices` use it
  and no longer write back a whole user read earlier (a password change in the meantime could be undone, e.g. by
  `RefreshClaimsAsync` in a loop over group members). The remaining whole-state writers are listed under known
  limitations.
- The `JwtSecret` placeholder of the getting-started guide (`<…>`) is rejected at startup.
- The remember-device cookie includes `PathBase` (it was never sent back under `UsePathBase`).
- `SlimEmailAddress` is public, so host endpoints (admin create-user) can normalize addresses like SlimIdentity.
- Conformance kit: parallel registrations with different casings, the initial state of a new user, clearing values
  in `UpdateSecurityStateAsync`, the new stamp compare-and-set, `TouchAsync` not reviving revoked sessions, external
  identities staying with their first user, single-use challenges of synced passkeys (counter 0), and
  `ISlimApiKeyStore` (with `SlimConformanceOptions.ApiKey` also a valid key).
- EF Core package: the change tracker is cleared after failed saves too, so a failed operation cannot leak entities
  into the next one.
- EF Core template: recovery codes are stored inside the execution strategy (500 with `EnableRetryOnFailure` before);
  foreign keys with cascade delete to the user (**migration needed**); API-key expiry works on SQLite.
- Outbox template: delivery is at-least-once with retries, not "guaranteed" – exponential backoff for about 9 hours,
  given-up rows stay with `LastError`, an atomic lease makes it safe with several instances, the link or code is
  erased after sending, and worker errors no longer stop the host. **Breaking:** the worker is
  `OutboxMailWorker<TTransport>`, `OutboxMail` gains `NextAttemptAt`, `LockedUntil` and `LastError` (migration).
- Admin template: create-user normalizes the address and checks the start password before creating the account – no
  orphan account on a retry.
- TypeScript client: sends `X-CSRF` on anonymous requests (403 `csrf_validation_failed` on register, verification and
  password reset before), `loginRecoveryCode`, and a failed refresh clears the token only on 400/401 (not on 429 or
  5xx). **Breaking:** an invitation accepted without a session returns `sign_in_required`; `changeEmail` and
  `confirmEmailChange` return a `FormResult`; the 2FA calls return a success-or-error result instead of `[]`.
- **Breaking:** a pure SSO account (no password, an external login) gets no local sign-in method by self-service:
  `/change-password` only changes an existing password (`409 password_not_set` – before, a fresh sign-in set a first
  one), a self-service reset sends no link (`409 external_sign_in_only` for an older one), and a passkey needs a
  password on the account (`403 password_required`). Accounts with a password keep password and passkeys when a
  provider is linked; administrators can still set a password.
- **Breaking:** sign-in and registration guards also run when `ISlimAuthManager` is called outside a request (a
  background job, an import) – before, they were silently skipped. They are resolved from a scope of their own, and
  `SlimSignInContext.HttpContext` / `SlimRegistrationContext.HttpContext` are now nullable: a guard that reads the
  request must handle `null` and decides itself whether such a call is trusted.
- EF Core stores: a write while the host holds an open transaction (on its context or a `TransactionScope`) is not
  part of it and may wait for its locks. It now throws at once on SQLite (instead of waiting until it times out) and
  logs a warning once (event id 8101) on other providers; the package README explains it (commit first).
- Tests: the EF Core conformance runs also cover `long` and `string` keys (SQLite, PostgreSQL, SQL Server).
- Docs: the Data Protection guide and template warn that the database and Redis variants store the key ring
  unencrypted – with EF Core next to the TOTP secrets it protects – and show `ProtectKeysWithCertificate` for production.
- Docs: the Entra ID guide no longer trusts every address of a single tenant (`TrustedEmailProviders`) – only members'
  (optional claim `acct` = `0`); B2B guests bring addresses from other directories and are matched by `sub` only.
- Docs: getting-started starts with the null mail sender and without a refresh-token store; minimal-setup installs
  the EF provider and tooling and creates the database; hooks.md states that the session renewal after a password or
  2FA change skips the guards.

### Changed

- **Breaking** (`ISlimUserStore`, user entity): password and second factor have separate attempt counters
  (`SlimUser.FailedSecondFactorAttempts`, `SecondFactorLockoutEndUtc`; new columns in the EF Core entity and the
  templates). An attempt is reserved in the store before it is evaluated: `TryBeginAttemptAsync` counts and, at the
  threshold, sets the lockout end in one atomic step, so the lockout also holds across instances; on success the
  factor starts over. `ResetFailedAttemptsAsync(user, factor)` replaces `IncrementFailedLoginAttemptsAsync`,
  `SetLockoutEndAsync` and `ResetFailedLoginAttemptsAsync`; `UpdateSecurityStateAsync` no longer writes the counters.
  `/login` and `/login/2fa` no longer use the per-instance attempt gate.
- A correct password no longer resets the second-factor counter; while the second factor is locked, `/login` answers
  `423` after a correct password instead of sending a new code. A remembered device still signs in.
- A lockout no longer blocks external logins or `ISlimAuthManager.SignInAsync` (`locked_out` is no longer returned
  there), as for passkeys: there is nothing to guess. Block an account with `IsActive`.
- Resetting the password by mail and `SetPasswordAsync` reset the password counter; `ResetTwoFactorAsync` resets the
  second-factor counter; `UnlockAsync` resets both.

### Fixed

- The email sender templates no longer write recipient addresses, verification or reset links, or two-factor codes to
  logs; the SendGrid failure log also omits the recipient, and impersonation audit values escape line breaks.
- The demo Dockerfile pins its .NET images by digest, CI restores NuGet packages in locked mode, and the release
  workflow limits write permissions to the release job.
- The external-login guide trusted Google's addresses through `TrustedEmailProviders`; it now maps Google's own
  `email_verified` (`ClaimActions.MapJsonKey`), which the ASP.NET Core handler drops by default.
- `POST /auth/login/password-change` runs in the per-account attempt gate and answers `423` during a lockout, like
  `/login/2fa`; before, the forced change ignored a lockout that started after the token was issued and lifted it.
- A correct password confirmation (`/change-email`, `/2fa/*`, `ConfirmPasswordAsync`) now resets the failed-attempt
  counter and upgrades an outdated hash, like a sign-in. Before, a few typos stayed on the counter for good, and later
  ones locked the account early; endpoints that write the security state afterwards no longer write the old counter
  back.
- The per-recipient mail limit no longer switches itself off when its table is full: 100,000 fresh addresses within
  15 minutes (a distributed flood) let every later recipient be flooded. It now fails closed for new recipients
  (warning 7006) and frees expired entries at most once a minute.
- `/auth/logout` with a genuine but dead refresh token – already rotated, or issued before a password change on the
  same device – no longer ends the session that continues with new tokens; only a valid token ends its session.
- `GET /auth/2fa` reports `method: recovery` (like the sign-in challenge) when e-mail codes are switched off and the
  account has no authenticator; it said `email` before. The endpoint reference no longer lists password-policy fields
  that do not exist (`require*`).

All packages of the repository (`SlimIdentity`, `SlimIdentity.EntityFrameworkCore`, `SlimIdentity.Passkeys`,
`SlimIdentity.Testing`) are released together with the same version.

[Unreleased]: https://github.com/SlimIdentity/SlimIdentity/commits/main
