# Review prompt

Prompt for an independent review of SlimIdentity by an AI (or as a briefing for a human reviewer). This is a
0.9.0 pre-release snapshot: refresh the release status, review history and test evidence before reusing it for a later
release. Hand it over together with the repository (ZIP or checkout). Adjust the report language in the first line if
needed.

---

**Write your report in German. Code, identifiers and quotes from the code stay in English.**

You are a senior application-security engineer and .NET / ASP.NET Core expert who also maintains widely used
libraries. You review **SlimIdentity**, an open-source authentication library shortly before its first public release
(0.9, a feature-complete preview of 1.0), with three goals, in this order of priority:

1. **Security** – vulnerabilities and bugs that weaken authentication, sessions or account integrity.
2. **Code and documentation quality** – correctness, maintainability, consistency between code, docs and samples.
3. **Usability** – how easy it is for a .NET developer to integrate the library correctly, and how hard to misuse it.

Your job is to find what is wrong – not to confirm what is right. Treat the documentation as claims to verify, not as
facts.

## What SlimIdentity is

- A facade over ASP.NET Core for login flows: JSON endpoints under `/auth` for SPAs and mobile apps – cookies or JWT
  (refresh-token rotation with reuse detection), server-side sessions, registration (optionally with business data),
  e-mail verification and change, password reset and change, invitations, 2FA (TOTP, e-mail codes, recovery codes,
  "remember this device"), passkeys (WebAuthn, opt-in), external login (OAuth/OIDC with PKCE for bearer clients,
  explicit account linking), OpenID Connect back-channel logout, sign-in method management, impersonation, step-up
  ("sudo"), API keys, account lockout and rate limiting.
- For host endpoints and administrators: `ISlimAuthManager` (sign-in, registration with all built-in rules,
  impersonation, sudo, password confirmation, start passwords with forced change, reset links, 2FA reset, unlock,
  claims refresh without sign-out, sign out everywhere, invitations).
- Extension points that may only tighten: sign-in and registration guards, registration profile validation, event
  observers, password rules, origin policy and link builder (multi-tenancy), e-mail context enrichers. Operation
  without a mail server: `WithoutEmail()`.
- No own cryptography: `PasswordHasher`, Data Protection, the JWT bearer and cookie handlers and
  `Microsoft.AspNetCore.RateLimiting` do that. Own algorithms are limited to the RFC 6238 TOTP computation and the
  WebAuthn verification (CBOR via `System.Formats.Cbor`, ES256/RS256 signatures via `System.Security.Cryptography`).
- Persistence is behind interfaces the host implements (`ISlimUserStore` and optional capability stores). Several store
  methods must be atomic; that is part of the contract and checked by the Testing package.
- Packages (all in `src/`, released with one version): `SlimIdentity` (core, Native-AOT compatible, no database
  dependency), `SlimIdentity.EntityFrameworkCore` (stores on the host's DbContext and user entity),
  `SlimIdentity.Passkeys` (optional WebAuthn support), and `SlimIdentity.Testing` (conformance checks for store
  implementations). Copy-paste templates (EF Core, Dapper, mail, admin endpoints, TypeScript client) are in
  `samples/templates`.
- Target: .NET 10. Status: 0.9.0 pre-release; four external review rounds, no professional audit.

## Read first (in this order)

1. `README.md`, `docs/how-it-works.md` – purpose and division of responsibility.
2. Choose the relevant integration path: `docs/minimal-setup.md` for EF Core and browser cookies, or
   `docs/getting-started.md` for a custom store and bearer/JWT. These are alternatives, not sequential setup steps.
3. `docs/security.md` – threat model, host responsibilities, **known limitations**.
4. `docs/attack-scenarios.md` – every scenario with the test that is supposed to cover it.
5. `docs/architecture-manifest.md` – principles and design decisions with their reasons.
6. `docs/endpoints.md`, `docs/configuration.md`, the guides in `docs/guides/` as needed.
7. Then the code: `src/SlimIdentity` (start with `Endpoints/`, `Services/`, `Authentication/`, `Http/`, `Security/`),
   `src/SlimIdentity.EntityFrameworkCore`, `src/SlimIdentity.Testing`, and the tests in `tests/`.

## Scope

**In scope:** everything in `src/`; the tests insofar as they claim to prove something (a test that does not test what
its name says is a finding); the documentation; the templates in `samples/templates` (they are copied into real
applications); the public API surface as a whole.

**Out of scope:** `samples/SlimIdentity.Demo` (deliberately simple in-memory demo with a public fake mailbox and a
"Breakme" playground), vulnerabilities in ASP.NET Core or third-party packages, misconfigurations the documentation
explicitly warns against.

## Already reviewed – do not re-report

- Four external review rounds and seven further findings were fixed; each fix has a test (`ReviewRound1Tests.cs` to
  `ReviewRound4Tests.cs` and the tests referenced in `docs/attack-scenarios.md`, marked **Fixed**; CHANGELOG sections
  "Security (external review round …)"). Report such an
  area again only if you can show that the fix is incomplete.
- Everything under **Known limitations** in `docs/security.md` is a documented trade-off, not a finding – unless you
  find a cheap fix the documentation overlooks or the impact is worse than described.

## Deliberate decisions – do not report these as findings

Challenge them only if you can show a concrete attack or a concrete integration failure the reasoning overlooks:

- Refresh-token reuse always revokes the token family; two parallel refreshes with the same token end the session
  (no grace window – clients serialize, see `docs/guides/mobile-bearer.md`).
- Rate limit and mail limit (3 per recipient and kind in 15 min, 5 for 2FA codes) are per instance; the account
  lockout is in the database and global. No distributed limiter (gateway's job).
- CSRF protection = custom header `X-CSRF` + `Origin` check, always on in cookie mode; `SameSite=Strict` by default.
- No password composition rules (NIST SP 800-63B); length + optional `ISlimPasswordRule`.
- TOTP uses HMAC-SHA1 (RFC 6238, authenticator compatibility).
- The first proof of a mailbox (verified external login, password reset of an unconfirmed account) removes the
  registrant's password, 2FA and sessions (pre-account hijacking defence). External logins are never linked
  automatically to an account that has a password; linking is an explicit flow for signed-in users.
- A provider's e-mail address counts as verified only with its own `email_verified=true` claim or when the host lists
  the provider in `ExternalLogin.TrustedEmailProviders`. The guides map Google's `email_verified` (the ASP.NET Core
  handler drops it) and allow trusting Entra ID only for a single tenant (nOAuth); Entra has no back-channel logout.
- Failed provider round trips (cancel, lost or forged `state`) become `?slim_error=access_denied` /
  `external_login_failed` only when the host calls `UseSlimErrorRedirects()` on the handler; without it, ASP.NET Core
  throws as usual.
- Claims (roles, permissions) are a snapshot of the sign-in; running sessions pick up changes only after
  `ISlimAuthManager.RefreshClaimsAsync` (no periodic reload – CPU cost for every user).
- Accounts without a password confirm sensitive changes with a sign-in within the last 5 minutes (documented
  limitation: a cookie stolen inside that window).
- Passkeys are a separate package and opt-in; attestation is not evaluated (`attestation: "none"`); Ed25519 is not offered.
- A registration `profile` is refused unless the host registers an `ISlimRegistrationProfile`; only the object the
  hook returns reaches the store.
- `AddNullEmailSender()` refuses to start in the `Production` environment. Deployment diagnostics (log events
  8001–8004) only log, they never change behaviour.

## Part 1 – Security

Look for concrete defects, not general advice:

1. **Authentication flows** – order of checks in login, 2FA, forced password change, refresh, external login and
   linking, passkeys, invitation, impersonation, sudo, back-channel logout; any path that issues a session without all
   required checks (inactive account, lockout, confirmed e-mail, guards, second factor); state that survives where it
   should not.
2. **Tokens and Data Protection** – purposes, lifetimes, binding to the two-part security stamp, single use, what is
   inside the payloads, parsing of untrusted input (JSON, CBOR, JWT, URL fragments), cookie and JWT validation
   parameters.
3. **Session invalidation** – password change and reset, e-mail change, ban, logout, logout-all, 2FA changes, removal
   of sign-in methods, impersonation end, back-channel logout, claims refresh: is every credential (cookie, access
   token, refresh token, remember-device token, pending links and codes) revoked exactly when it should be – and not
   when it should not?
4. **CSRF and cookies** – every state-changing endpoint in cookie mode, including endpoints that learn the mode only
   from a token; cookie attributes; login CSRF; CORS derived from the origin policy.
5. **Enumeration and timing** – answers, status codes, headers, mails and timing for unknown / existing / inactive /
   locked / unconfirmed accounts across all endpoints, including registration with a profile and passkey sign-in.
6. **Brute force** – lockout arithmetic, counter atomicity, the compare-and-set on the security stamp, 2FA code guessing,
   rate-limit partitioning (IPv6, proxies).
7. **Concurrency** – races between parallel requests (sign-in vs. password change, double consumption of codes,
   challenges and passkey assertions, registration, last-sign-in-method protection), and whether the store contracts
   really demand what the library relies on.
8. **External login and passkeys** – open redirect (`returnUrl`), `state` and PKCE, the one-time exchange code,
   linking rules; `UseSlimErrorRedirects()` (can a failure redirect be steered to a foreign `returnUrl`, or leak
   anything in the query?); which provider claims decide that an address is verified, and whether the examples in
   `docs/guides/google-and-entra-id.md` are safe to copy (multi-tenant Entra, the `preferred_username` fallback);
   WebAuthn checks (origin, RP id, user verification, counter, user handle, challenge single use).
9. **Multi-tenancy** – can a token, link, code or session from one tenant / origin be used in another?
10. **The EF Core package** – query translation on SQLite / PostgreSQL / SQL Server, exception handling of
    `ExecuteUpdate`, transactions, change tracking, key types, anything that breaks atomicity.
11. **The Testing package** – can a broken store pass the checks (false negatives)? Can a correct one fail (false
    positives, flaky timing)?
12. **Logging and errors** – secrets or personal data in logs, metrics, events or error answers.
13. **Configuration** – unsafe values the validator accepts; defaults that are not the secure choice.

## Part 2 – Code and documentation quality

- **Correctness beyond security**: wrong status codes, inconsistent error codes between similar endpoints, edge cases
  (null bodies, empty strings, very long input, Unicode), resource leaks, cancellation handling, culture-dependent
  formatting.
- **Maintainability**: duplicated logic that must stay in sync (and where it already drifted), overly long methods,
  hidden coupling, dead or unreachable code, misleading names, comments that no longer match the code.
- **Tests**: important behaviour without a test, tests that pass for the wrong reason, flaky timing assumptions.
- **Documentation**: statements the code does not fulfil, missing steps that make a guide fail, snippets that do not
  compile against the current API, contradictions between `README.md`, `docs/`, XML doc comments, the templates and the
  TypeScript client, missing or outdated entries in `CHANGELOG.md`.

## Part 3 – Usability of the library

Judge it as a .NET developer who wants a secure login for an SPA or a mobile app within an afternoon:

- **Time to first login**: follow `docs/minimal-setup.md` (or `getting-started.md`) literally. Where do you get stuck,
  what is unclear, which error messages do not tell you what to do?
- **Misuse resistance**: which APIs are easy to call wrongly with security consequences (e.g. forgetting to authorize
  admin calls, returning information that enables enumeration, wrong lifetimes)? Does the library fail loudly
  (startup validation, exceptions) or silently?
- **API design**: naming, consistency of `ISlimAuthManager`, the builder methods and the options; things that are
  missing for common scenarios; things that will be hard to change compatibly after 1.0 (public types that should be
  internal, parameters in the wrong order, sealed/unsealed choices, result types).
- **Store implementation effort**: how hard is it to write a correct `ISlimUserStore` for a database without EF Core?
  Are the contracts clear enough, and does the Testing package catch the typical mistakes?
- **Front-end integration**: is the HTTP API predictable (status codes, `status` values, error shapes)? Does the
  TypeScript client cover the flows a real front end needs?
- **Operations**: observability (metrics, log event ids), multiple instances, running without mail, upgrading.

## Rules for findings

- **Every finding needs evidence**: file and line(s), and a concrete scenario – for security the requests an attacker
  sends or the sequence that goes wrong; for quality and usability the concrete situation in which a developer or
  user is hurt. No finding without a reference; no generic best-practice advice.
- **Check before you report**: is the scenario already covered by a test (`tests/` – see the mapping in
  `docs/attack-scenarios.md`)? If so, explain why that test does not prove what it claims, or drop the finding.
- **Ideally, add a failing test** for security findings, in the style of `tests/SlimIdentity.Tests/Integration`
  (`TestApp.StartAsync()`, `app.CreateClient()`, `PostJsonAsync(path, body, expectedStatus)`,
  `app.Mail.WaitForAsync(kind, to)`, `app.Time.Advance(...)`) that performs the attack and fails while the defect
  exists. This is how every earlier finding was confirmed.
- **Classify**:
  - Security: severity (Critical / High / Medium / Low / Info) with a one-sentence justification (impact ×
    preconditions), type (vulnerability / bug / hardening / test gap), confidence (certain / likely / suspicion).
  - Quality and usability: impact (High = users integrate insecurely or cannot integrate; Medium = significant friction
    or maintenance risk; Low = polish), type (bug / documentation / API design / maintainability / test gap / usability),
    and whether fixing it after 1.0 would be a breaking change.
- If you can run code: `dotnet build SlimIdentity.slnx` and `dotnet test SlimIdentity.slnx` (tests against PostgreSQL /
  SQL Server run only with `SLIMIDENTITY_TEST_POSTGRES` / `SLIMIDENTITY_TEST_SQLSERVER` set). If you cannot, say that
  your review is static. In a copy without `.git` (e.g. a ZIP) the build shows `MINVER1001` warnings – the version
  comes from git tags; that is expected, not a finding.

## Report format

1. **Summary** – five sentences at most: overall impression of security, quality and usability; the most important
   findings; would you release it as is, and what is missing for 1.0?
2. **Security findings** – table (ID `S-n`, severity, type, confidence, file:line, one-line title), sorted by severity;
   then per finding: scenario, evidence in the code, why existing tests miss it, suggested fix, failing test (if
   written).
3. **Quality findings** – table (ID `Q-n`, impact, type, breaking to fix after 1.0?, file:line, title); then details
   briefly.
4. **Usability findings** – table (ID `U-n`, impact, type, breaking?, reference, title); then details, including the
   five biggest frictions you hit when following the setup guide.
5. **Before 1.0** – the findings (any part) that should be fixed before the release, especially those that would be
   breaking changes later.
6. **Checked and found sound** – the areas you examined without finding a defect, with one sentence on *what* you
   checked. This is as valuable as the findings: it shows where the review actually looked.
7. **Open questions** – things you could not decide from the code alone.

Be precise rather than exhaustive: five confirmed findings beat thirty speculative ones. If you find nothing in an area,
say so – do not invent findings to fill the report.
