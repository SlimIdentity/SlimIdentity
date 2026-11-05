# Security model

This page describes what SlimIdentity defends against, how, and which responsibilities stay with the host.
If you find a gap, please report it privately ([SECURITY.md](../SECURITY.md)).

## Assumptions

- The application is only reachable via **HTTPS** (directly or behind a TLS-terminating proxy that forwards the real
  scheme and client IP – see [reverse proxy](guides/reverse-proxy.md)).
- The **Data Protection key ring** is persisted and protected (shared between instances, survives restarts).
  It encrypts cookies, refresh tokens and all workflow links.
- `Tokens.JwtSecret` is random (≥ 32 bytes) and kept secret.
- The stores honour their contracts – in particular case-insensitive e-mail lookup and **atomic** consumption of
  refresh tokens and recovery codes.

## Threats and mitigations

| Threat | Mitigation |
| :--- | :--- |
| Online password guessing | Per-client rate limit (IPv6 grouped by /64) + progressive account lockout (1 min, 2, 4, … ≤ 1 h). Attempts during a lockout are not evaluated. |
| Credential stuffing (one attempt per account from many IPs) | Lockout counts per account; optional lockout notification mail. A botnet with fresh IPs remains a residual risk – combine with breached-password checks, 2FA or a WAF if you are a target. |
| Locking out a victim on purpose | Lockouts are short and grow slowly; the counter only matters after `MaxFailedAttempts` failures. (Device cookies are not implemented.) |
| Account enumeration | Identical answers for `/register`, `/forgot-password`, `/resend-verification`; mails sent in the background; dummy hashing for unknown, inactive and locked accounts; `/login` hides inactive/locked state by default. |
| Timing attacks on secrets | Constant-time comparison of tokens, stamps, TOTP codes; passwords via `PasswordHasher` (PBKDF2). |
| Hash-flooding / DoS with huge passwords | Passwords longer than `Password.MaximumLength` are rejected before hashing. |
| CSRF on cookie sessions | `SameSite=Strict` by default + mandatory custom header (`X-CSRF`, forces a CORS preflight) + `Origin` check. |
| Cookie theft via XSS | Cookies are `HttpOnly` and `Secure`. (XSS itself must be prevented by the front end.) |
| Stolen refresh token | Rotation (single use) + reuse detection: replay of a used token revokes the token family (or all sessions). Absolute chain lifetime of 30 days. |
| Stolen access token | Short lifetime (15 min); with server-side sessions and per-request validation a revoked session stops working immediately. |
| Sessions after password change, ban, 2FA change | Security stamp rotation invalidates cookies, JWTs, refresh tokens and pending links; validated on every bearer request and every `SecurityStampValidationInterval` for cookies. |
| Replay of reset / verification / invitation links | Links are bound to the security stamp and expire; reset and invitation rotate the stamp, so they work once. |
| Open redirect in external login | `returnUrl` must be a local path or an explicitly allowed origin. |
| Account takeover via external login | Auto-linking only for **verified** e-mails (`email_verified` or explicitly trusted provider); otherwise `account_conflict`. |
| Tokens in URLs / logs | Bearer clients get a short-lived one-time code after external login, never tokens in a URL. |
| Abuse of impersonation | The impersonation session carries the admin's id and stamp (`act`); it ends as soon as the admin is banned or signs out everywhere. Never persistent, no refresh token, sensitive actions (`/change-password`, 2FA changes, …) are blocked. |
| Leaked API keys | Only SHA-256 hashes are stored; keys have 256 bits of entropy and a recognizable prefix for secret scanners. |

## Host responsibilities

- HTTPS, HSTS and security headers (CSP!) for the front end.
- Persisting and protecting the Data Protection keys and `JwtSecret`; rotating them if leaked.
- Store implementations: atomic deletes, case-insensitive e-mail lookup, cleanup of expired rows.
- CORS configuration that matches `Csrf.AllowedOrigins` (credentials only for trusted origins).
- Protecting your own endpoints: `.RequireAuthorization()`, `.RequireSlimCsrf()` for cookie-authenticated
  state-changing endpoints, `.RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)` for login-like endpoints.
- Secure mail templates (no HTML injection of user-controlled data) and a trustworthy sender domain (SPF/DKIM).
- Monitoring of the warnings SlimIdentity logs (lockouts, refresh-token reuse, impersonation).

## Known limitations

- TOTP and e-mail codes are not protected against replay within their 30–90 second window; the `preAuthToken` can be
  reused until it expires. Every wrong code counts towards the lockout.
- Without `ISlimSessionStore` sessions are stateless: a copied cookie stays valid until it expires or the stamp
  rotates (`/logout-all`).
- Cookie revocation takes effect at the next validation (`Cookies.SecurityStampValidationInterval`, default 1 min).
- `/register` performs one database write for new addresses only; this can make the response measurably slower than
  for existing addresses.
- Rate limiting is per client IP (or your custom key) and per instance (in-memory); distributed rate limiting needs
  your own policy or a gateway.
- The code has not been independently audited yet.
