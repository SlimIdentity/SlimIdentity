# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

First public release (0.9.0): feature-complete preview. The API may still change before 1.0; version 1.0 follows an
independent security audit and feedback from first production use. From then on, breaking changes only with a new
major version.

### Added

- JSON endpoints under `/auth` for cookie and bearer (JWT + refresh token) clients: sign-in, registration, e-mail
  verification, password reset and change, e-mail change, invitations, sessions, sign-in methods, `/me`.
- One sign-in flow for every way in: the answer is either a session or `action_required` with the open steps
  (`verify_email`, `set_credential`, `change_password`, `second_factor`, `setup_second_factor`, …) and a `flowToken`.
- Two-factor authentication (TOTP, e-mail codes, recovery codes, remembered devices), optional mandatory second factor
  per sign-in (`ISlimSecondFactorPolicy`).
- External login (OAuth/OIDC) with back-channel logout, passkeys (`SlimIdentity.Passkeys`), API keys, custom password
  validators (LDAP, legacy hashes).
- `ISlimAuthManager` for host endpoints: invitations, start passwords, impersonation, step-up "sudo" mode, bans.
- Hooks that can only tighten a flow: sign-in guards, registration profiles, event observers.
- Tenants: tenant key in every token, origin policies, link builders, tenant-scoped stores.
- Store interfaces with atomic security writes and `ISlimSharedState` for single-use markers and counters across
  instances; EF Core stores (`SlimIdentity.EntityFrameworkCore`) and conformance checks (`SlimIdentity.Testing`).
- RFC 9457 problem answers with a machine-readable `code` (`SlimErrorCodes`), OpenAPI metadata, metrics and log event
  ids, Native AOT support for the core and passkey packages.