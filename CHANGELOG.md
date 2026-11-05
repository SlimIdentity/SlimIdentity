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
- E-mail change: `/change-email` (password confirmation) and `/confirm-email-change` (link to the new address,
  notification of the old one, all sessions end).
- Pluggable password rules (`ISlimPasswordRule`, `AddPasswordRule<T>()`), e.g. a breached-password check, and
  `GET /password-policy` so front ends can show and live-check the active rules.
- Metrics on the meter `SlimIdentity` (System.Diagnostics.Metrics, OpenTelemetry-ready) and source-generated logs with
  stable event ids.
- Native AOT and trimming compatibility.
- Samples for EF Core, Dapper, MailKit, SendGrid, outbox delivery, LDAP, client certificates (mTLS), Data Protection
  key ring persistence, Have I Been Pwned, admin endpoints and a TypeScript client (incl. QR code for TOTP setup).

[Unreleased]: https://github.com/timmkautz/slimidentity/commits/main
