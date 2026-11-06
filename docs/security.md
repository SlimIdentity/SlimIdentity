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
| Online password guessing | Per-client rate limit (IPv6 grouped by /64) + progressive account lockout (1 min, 2, 4, … ≤ 1 h). Attempts during a lockout are not evaluated. |
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
| Replayed 2FA code (phishing proxy, shoulder surfing) | Every TOTP time step and every e-mail code is accepted at most once (RFC 6238 §5.2, atomic store update). Every wrong code counts towards the lockout. |
| Reused sign-in challenge (`preAuthToken`) | The challenge stands for the verified password; it completes at most one sign-in (atomic store update), so a captured token cannot mint further sessions with later codes or recovery codes. |
| Parallel requests (races) | Failed attempts are counted with an atomic increment, so parallel guesses cannot slip past the lockout; sign-in bookkeeping never writes back a whole user, so a failed login or a rehash cannot undo a concurrent password change; a duplicate registration gets the uniform answer. |
| Stolen "remember this device" token | Off by default; the password is still required; the token is bound to user and security stamp, expires (≤ 90 days) and is revoked by password change, sign out everywhere, 2FA changes and "forget all devices". Never issued after a recovery code. |
| Database leak → 2FA bypass | TOTP secrets are encrypted with Data Protection before they reach the store; recovery codes have 80 bits of entropy and are stored as SHA-256 salted per user. A database dump alone yields neither. |
| Sessions after password change, ban, 2FA or e-mail change | Security stamp rotation invalidates cookies, JWTs, refresh tokens and pending links; validated on every bearer request and every `SecurityStampValidationInterval` for cookies. |
| Replay of reset / verification / invitation / e-mail-change links | Links are bound to the security stamp and expire; reset, invitation and e-mail change rotate the stamp, so they work once. |
| Account takeover via e-mail change | Requires the current password; the new address must confirm; the old address is notified; all sessions end. |
| Open redirect in external login | `returnUrl` must be a local path or a trusted origin; control characters and surrounding whitespace (which browsers strip, turning `/\t/evil` into `//evil`), user info and non-HTTP schemes are rejected, and the redirect uses the URL as parsed by .NET. Covered by property-based tests. |
| Account takeover via external login | Auto-linking only for **verified** e-mails (`email_verified` or explicitly trusted provider); otherwise `account_conflict`. |
| Tokens in URLs / logs | Bearer clients get a short-lived (1 min), single-use code after external login, never tokens in a URL – a code leaked via history, logs or a referrer is worthless once exchanged. Logs and metrics contain user ids at most, never passwords, tokens or codes. |
| Abuse of impersonation | The impersonation session carries the admin's id and stamp (`act`); it ends as soon as the admin is banned or signs out everywhere. Never persistent, no refresh token, sensitive actions (`/change-password`, `/change-email`, 2FA changes, …) are blocked. |
| Leaked API keys | Only SHA-256 hashes are stored; keys have 256 bits of entropy and a recognizable prefix for secret scanners. |

## Host responsibilities

- HTTPS for browsers, HSTS and security headers (CSP!) for the front end.
- Persisting and protecting the Data Protection keys and `JwtSecret`; rotating them if leaked. Losing the key ring
  invalidates all sessions and links, and TOTP secrets can no longer be decrypted – affected users sign in with a
  recovery code and set up their authenticator again.
- Store implementations: atomic deletes / compare-and-set, case-insensitive and unique e-mail, cleanup of expired rows.
- CORS configuration that matches `TrustedOrigins` (credentials only for trusted origins).
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
- Rate limiting is per client IP (or your custom key) and per instance (in-memory); distributed rate limiting needs
  your own policy or a gateway.
- The code has not been independently audited yet.
