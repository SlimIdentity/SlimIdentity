# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

First public release (1.0.0) in preparation.

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
  (`IncrementFailedLoginAttemptsAsync`, `SetLockoutEndAsync`, `ResetFailedLoginAttemptsAsync`,
  `UpdatePasswordHashAsync`) so parallel failures are all counted and never undo a password change; `CreateAsync`
  returns `null` for a taken address (uniform answer for concurrent registrations); CSRF check for the 2FA step of a
  cookie sign-in.
- Lean configuration: most apps set only `Tokens.JwtSecret` (enables bearer tokens), `Links.BaseUrl` (all mail links)
  and `TrustedOrigins` (CSRF origin check and external-login return URLs in one list). Security-relevant protocol
  details (CSRF, refresh-token reuse detection, challenge and code lifetimes, TOTP tolerance, recovery codes) are fixed
  by design; passwords follow NIST SP 800-63B (length, no composition rules).
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
- Native AOT and trimming compatibility.
- Samples for EF Core, Dapper, MailKit, SendGrid, outbox delivery, LDAP, client certificates (mTLS), Data Protection
  key ring persistence, Have I Been Pwned, admin endpoints and a TypeScript client (incl. QR code for TOTP setup).

All packages of the repository (`SlimIdentity`, `SlimIdentity.Testing`) are released together with the same version.

[Unreleased]: https://github.com/timmkautz/slimidentity/commits/main
