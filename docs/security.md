# Security model

This page describes what SlimIdentity defends against, how, and which responsibilities stay with the host.
If you find a gap, please report it privately ([SECURITY.md](../SECURITY.md)).

## Assumptions

- **Transport:** browsers talk to the application via **HTTPS** (directly or through a TLS-terminating proxy that
  forwards the real scheme and client IP – see [reverse proxy](guides/reverse-proxy.md)). The auth cookie is always
  `Secure`, so browsers only send it over HTTPS (and to `http://localhost` during development).
  Bearer tokens and API keys are *not* tied to HTTPS – machine-to-machine calls over plain HTTP work, e.g. between
  services on the same host or inside a private network. Over HTTP the credentials travel in clear text, so only use
  it on loopback or networks you trust (or protect them otherwise, e.g. a service mesh with mTLS).
- The **Data Protection key ring** is persisted, protected and shared between instances
  ([guide](guides/data-protection.md)). It encrypts cookies, refresh tokens, all mail links and the TOTP secrets.
- `Tokens.JwtSecret` is random (≥ 32 bytes) and kept secret.
- The stores honour their contracts – in particular case-insensitive e-mail lookup, a unique e-mail constraint,
  **atomic** consumption of refresh tokens, recovery codes, 2FA time steps and sign-in challenges, and **narrow,
  atomic** updates of the lockout counter and rehashed passwords.

## Threats and mitigations

| Threat | Mitigation |
| :--- | :--- |
| Online password guessing | Per-client rate limit (IPv6 grouped by /64) + progressive account lockout (1 min, 2, 4, … ≤ 1 h). Attempts during a lockout are not evaluated. Host endpoints that re-confirm a password use `ISlimAuthManager.ConfirmPasswordAsync` and count towards the same lockout. |
| Credential stuffing (one attempt per account from many IPs) | Lockout counts per account; optional lockout notification mail; optional breached-password rule for new passwords. A botnet with fresh IPs remains a residual risk – combine with 2FA or a WAF if you are a target. |
| Weak or breached new passwords | Minimum length (NIST SP 800-63B, no composition rules) + pluggable `ISlimPasswordRule`s (sample: Have I Been Pwned with k-anonymity). |
| Locking out a victim on purpose | Lockouts are short and grow slowly; the counter only matters after `MaxFailedAttempts` failures. (Device cookies are not implemented.) |
| Account enumeration | Identical answers for `/register`, `/forgot-password`, `/resend-verification`, `/change-email`; mails sent in the background; dummy hashing for unknown, inactive and locked accounts; `/login` hides inactive/locked state by default. |
| Timing attacks on secrets | Constant-time comparison of tokens, stamps, TOTP codes; passwords via `PasswordHasher` (PBKDF2). |
| Hash-flooding / DoS with huge passwords | Passwords longer than `Password.MaximumLength` are rejected before hashing. |
| CSRF on cookie sessions | `SameSite=Strict` by default + mandatory custom header (`X-CSRF`, forces a CORS preflight) + `Origin` check – also for the 2FA step of a cookie sign-in, which is recognized by its signed challenge. |
| Cookie theft via XSS | Cookies are `HttpOnly` and `Secure`. (XSS itself must be prevented by the front end.) |
| Stolen refresh token | Rotation (single use) + reuse detection: replay of a used token revokes the token family (or all sessions). Absolute chain lifetime of 30 days. |
| Stolen access token | Short lifetime (15 min); with server-side sessions and per-request validation a revoked session stops working immediately. |
| Replayed 2FA code (phishing proxy, shoulder surfing) | Every TOTP time step and every e-mail code is accepted at most once (RFC 6238 §5.2, atomic store update). Every wrong code counts towards the lockout. Installing or replacing the authenticator requires the current password; a setup token dies with the security stamp. |
| Reused sign-in challenge (`preAuthToken`) | The challenge stands for the verified password; it completes at most one sign-in (atomic store update), so a captured token cannot mint further sessions with later codes or recovery codes. |
| Parallel requests (races) | Credential attempts (password, second factor, password confirmation) of one account run one after another per instance – lockout check, evaluation and counting form one step, so parallel guesses beyond the threshold are not evaluated. The queue is keyed by the user id (every spelling of an address is one account) and holds at most 8 waiting attempts; further ones get the answer of a failed attempt without being evaluated; failures are counted with an atomic increment; sign-in bookkeeping never writes back a whole user, so a failed login or a rehash cannot undo a concurrent password change; a duplicate registration gets the uniform answer. |
| Stolen "remember this device" token | Off by default; the password is still required; the token is bound to user and security stamp, expires (≤ 90 days) and is revoked by password change, sign out everywhere, 2FA changes and "forget all devices". Never issued after a recovery code. |
| Database leak → 2FA bypass | TOTP secrets are encrypted with Data Protection before they reach the store; recovery codes have 80 bits of entropy and are stored as SHA-256 salted per user. A database dump alone yields neither. |
| Sessions after password change, ban, 2FA or e-mail change | Security stamp rotation invalidates cookies, JWTs, refresh tokens and pending links; validated on every bearer request and every `SecurityStampValidationInterval` for cookies. |
| Replay of reset / verification / invitation / e-mail-change links | Links are bound to the security stamp and expire; reset, invitation and e-mail change rotate the stamp, so they work once. |
| Account takeover via e-mail change | Requires the current password; the new address must confirm; the old address is notified; all sessions end. |
| Credentialed CORS for any origin | `AddCorsPolicy()` builds CORS from the same trusted origins as the CSRF check and the redirect rule: exactly the requesting origin, never `*` with credentials. |
| Tenants trusting each other's front ends | With `AddOriginPolicy<T>()` every request decides its trusted origins (CSRF, `returnUrl`, CORS); `AddLinkBuilder<T>()` keeps mail links on the tenant's domain – built from your tenant directory, never from an unchecked `Host` header. |
| Open redirect in external login | `returnUrl` must be a local path or a trusted origin; control characters and surrounding whitespace (which browsers strip, turning `/\t/evil` into `//evil`), user info and non-HTTP schemes are rejected, and the redirect uses the URL as parsed by .NET. Covered by property-based tests. |
| Account takeover via external login | Auto-linking and auto-registration only for **verified** e-mails (`email_verified` or explicitly trusted provider), and auto-linking only to accounts without a password of their own; otherwise `account_conflict` (the user signs in and links with the PKCE-bound link flow) or `email_not_verified` – no account is created for an address the provider has not verified. |
| Pre-account hijacking (attacker registers the victim's address first) | An unconfirmed account can neither set up a second factor nor link an external login. The first proof of the mailbox through a password reset or a verified external login removes the registrant's password, 2FA, sessions and external logins. A click on the verification link confirms the address but proves nothing about who set the password – so an account with a password is never joined to an external login automatically. |
| Look-alike addresses | Addresses are trimmed and Unicode-normalized (NFC) before they reach the store, so precomposed and decomposed forms are one account; case-insensitive lookup is a store rule. `+tag` and homoglyphs are different addresses. |
| Mail bombing | At most 3 mails per recipient and kind within 15 minutes (5 for 2FA codes); further requests get the same answer without a mail. Per instance. The table is bounded (100,000 recipients): filled by a flood of fresh addresses, it fails closed – new recipients get no mail until entries expire (warning 7006), tracked ones keep their limit. |
| Dev mail sender in production | `AddNullEmailSender()` stops the start in the `Production` environment (it would log live links and codes) unless explicitly allowed. |
| Cached answers with secrets | Every answer under `/auth` carries `Cache-Control: no-store` (RFC 6749 §5.1) – tokens, recovery codes and TOTP secrets never land in a browser, proxy or CDN cache. |
| Tokens in URLs / logs | After an external login, secrets travel in the URL **fragment** (never sent to servers, logs or referrers): bearer clients get a short-lived (1 min), single-use code that is bound to their PKCE challenge (S256) – worthless without the verifier –, cookie sign-ins with 2FA get their challenge there. Only error codes use the query. E-mail links carry their token by nature (single use, stamp-bound, short-lived); a link template like `https://app/reset#token={token}` keeps it out of server logs and referrers. Logs and metrics contain user ids at most, never passwords, tokens or codes. |
| Administrator-set passwords | A start password (`SetPasswordAsync`) yields no session – not even on a remembered device – until the user has chosen an own one (`password_change_required`, single-use token bound to the stamp). Reset links an administrator hands over are no proof of the mailbox: an unconfirmed account stays unconfirmed and keeps its second factor. |
| E-mail as second factor | Optional (`TwoFactor.AllowEmailCodes = false`, always off without mail): whoever controls the mailbox can also reset the password. Accounts with e-mail codes then sign in with a recovery code or are reset by an administrator. |
| Host extensions weakening the flow | Hooks only tighten: sign-in and registration guards can refuse, event observers only watch, password rules only reject, claims are only added. A throwing guard fails closed; a throwing observer is ignored. A sign-in guard also re-validates running sessions. |
| Sessions outliving the identity provider's logout | With `AddBackChannelLogout`, a signed logout token from an enterprise provider ends every session of the user. The token is validated like a credential (signature, issuer, audience, back-channel event, no `nonce`, at most 5 minutes old, single use), so nobody else can sign users out. |
| Abuse of impersonation | The impersonation session carries the admin's id and stamp (`act`); it ends as soon as the admin is banned or signs out everywhere. Never persistent, no refresh token, sensitive actions (`/change-password`, `/change-email`, 2FA changes, …) are blocked. |
| Leaked API keys | Only SHA-256 hashes are stored; keys have 256 bits of entropy and a recognizable prefix for secret scanners. |
| API key acting as its user | The account endpoints (`/auth/*`) accept cookies and bearer tokens only – a (possibly narrowly scoped) key bound to a user can neither act as that user there nor mint a session. |

## Host responsibilities

- HTTPS for browsers, HSTS and security headers (CSP!) for the front end.
- Persisting and protecting the Data Protection keys and `JwtSecret`; rotating them if leaked
  ([JWT secret rotation](configuration.md#rotating-the-jwt-secret)), and keeping configured API-key hashes out of
  source control. Losing the key ring
  invalidates all sessions and links, and TOTP secrets can no longer be decrypted – affected users sign in with a
  recovery code and set up their authenticator again.
- Store implementations: atomic deletes / compare-and-set, case-insensitive and unique e-mail, cleanup of expired rows.
- CORS configuration that matches `TrustedOrigins` (credentials only for trusted origins).
- Authorizing the administration calls of `ISlimAuthManager` (`SetPasswordAsync`, `CreatePasswordResetAsync`,
  `ResetTwoFactorAsync`, `UnlockAsync`) – ideally behind sudo mode – and handing reset links over on a trusted channel.
- Re-confirming passwords on your own endpoints (sudo mode) with `ISlimAuthManager.ConfirmPasswordAsync` – never with
  `IPasswordHasher` directly, which bypasses the lockout.
- Protecting your own endpoints: `.RequireAuthorization()`, `.RequireSlimCsrf()` for cookie-authenticated
  state-changing endpoints, `.RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)` for login-like endpoints.
- Secure mail templates (HTML-encode user-controlled data such as e-mail addresses) and a trustworthy sender domain (SPF/DKIM).
- Monitoring of the logged warnings and [metrics](guides/observability.md) (lockouts, refresh-token reuse, replayed codes, impersonation).

## Known limitations

- Without `ISlimSessionStore` sessions are stateless: a copied cookie stays valid until it expires or the stamp
  rotates (`/logout-all`).
- Cookie revocation takes effect at the next validation (`Cookies.SecurityStampValidationInterval`, default 1 min).
- The external-login exchange code is made single use through `ISlimRefreshTokenStore` (shared, atomic). Without a
  refresh-token store an in-memory registry is used, which is per instance – run several instances only with a store.
- `/register` performs one database write for new addresses only; this can make the response measurably slower than
  for existing addresses.
- Rate limiting is per client IP (or your custom key) and per instance (in-memory); a hard global limit belongs in the
  gateway. The account lockout is stored in the database and therefore global
  ([several instances](guides/multiple-instances.md)).
- The mail limit per recipient is kept in memory per instance; with several instances the effective limit is a multiple.
- Credential attempts of one account are serialized per instance. With several instances, attempts that arrive on
  different instances at the very moment the threshold is reached can each still be evaluated – at most one extra
  guess per additional instance and lockout cycle.
- E-mail verification, e-mail change confirmation and claiming an account via external login write the security
  fields of a user read at the start of the request. A password change that completes in the same instant can be
  overwritten (the narrow-update store methods protect sign-in bookkeeping, not these rare flows).
- With an `ISlimCustomPasswordValidator` (LDAP, legacy hashes) unknown accounts burn a local dummy hash while known
  accounts wait for the directory – the response time can reveal whether an account exists.
- The code has not been independently audited yet. The [attack scenarios](attack-scenarios.md) list what is covered by
  tests and what is still open.
