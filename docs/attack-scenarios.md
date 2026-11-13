# Attack scenarios

A checklist for reviews – by people and by AI agents – and the current state of each scenario.

**Rule:** a finding is real only once a failing test demonstrates it. Every confirmed defence gets a permanent
regression test.

Status: **covered** – a test proves the defence · **design** – deliberate behaviour, documented · **host** – the
responsibility of the application (only our templates are reviewed) · **open** – not yet proven by a test.

The tests live in `tests/SlimIdentity.Tests` and in the conformance kit `SlimIdentity.Testing` (run against the test
stores and the EF Core templates).

## A. Login, lockout, enumeration

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| A1 | Many parallel wrong passwords → counter exact, lockout applies, no guess beyond the threshold is evaluated | covered |
| A2 | Locked account + correct password → not evaluated, answer identical to a wrong password | covered |
| A3 | Unknown / known / inactive / locked → same answer and statistically same time | covered (timing: opt-in with `SLIMIDENTITY_TIMING=1` before a release) |
| A4 | Address variants: case, Unicode normalization, whitespace, `+tag`, homoglyphs | covered |
| A5 | Password longer than the maximum, huge bodies → rejected before hashing | covered |
| A6 | Permanent lockout of a victim → growth capped (≤ 1 h) | covered |
| A7 | `X-Forwarded-For` spoofing to evade the rate limit → ignored without configured proxies | covered |
| A8 | IPv6 rotation within a /64 → one bucket | covered |
| A9 | `/register` timing (write only for new addresses) | design – with mail `/register` writes nothing (the account is created after the mailbox is proven); without mail a known limitation in the [security model](security.md#known-limitations), only measurable against the real database of a deployment, not in-process |
| A10 | A registration profile: its validation, or the profile itself, reveals or changes an existing account | covered |
| A11 | Display-name addresses (`n1 <victim@x>`, `victim@x <attacker@evil>`): one inbox behind endless "different" addresses, look-alike confirmed accounts | covered |
| A12 | `/register` reveals registered or throttled addresses; the code is guessed; a registration token signs in, or a sign-in token completes a registration; the link is replayed or used in another tenant | covered |

## B. Cookies and CSRF

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| B1 | State-changing request without `X-CSRF` → 403 | covered |
| B2 | Wrong / missing / `null` origin, subdomain, port or scheme variants | covered |
| B3 | `/login/2fa` in cookie mode from a foreign origin | covered |
| B4 | Login CSRF (victim signed into the attacker's account) | covered |
| B5 | Cookie attributes on all responses incl. the 2FA device cookie | covered |
| B6 | Session fixation: cookie set before login → new cookie after login | covered |
| B7 | Stolen cookie after password change / ban / logout-all → invalid after `SecurityStampValidationInterval` | covered |

## C. JWT, refresh tokens, sessions

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| C1 | JWT manipulation: `alg=none`, algorithm switch, expired, wrong issuer / audience, future `nbf` | covered |
| C2 | Too short `JwtSecret` → start fails | covered |
| C3 | Refresh-token replay after rotation → token family revoked | covered |
| C4 | Two parallel refreshes with the same token | design – exactly one wins, the other is treated as theft (no grace window); clients serialize, across tabs with Web Locks ([guide](guides/mobile-bearer.md#refreshing-correctly)); conformance proves single use |
| C5 | Bypass the absolute lifetime by continuous rotation | covered |
| C6 | Access token after session revocation / stamp rotation → rejected immediately | covered |
| C7 | Token of one user against the session of another | covered |
| C8 | `DELETE /sessions/{id}` for a foreign session (IDOR) → 404 | covered |
| C9 | `/logout` with someone else's, a garbage or a dead refresh token (rotated away, or from before a password change on the same device) | covered |

## D. Two-factor authentication

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| D1 | Same TOTP code twice, also in parallel → accepted once | covered |
| D2 | Older time step after a newer one → rejected | covered |
| D3 | Brute force of the 6-digit code → counts towards its own lockout, rate limited, parallel guesses beyond the threshold not evaluated | covered |
| D3b | Brute force of the mailed `verify_email` code | covered |
| D4 | `flowToken` reused, parallel, expired, of another user | covered |
| D5 | Recovery code reused, parallel, brute force, format variants | covered |
| D6 | Mail bombing by requesting codes / links repeatedly | covered |
| D7 | Remember token of another user, after password / 2FA change, after a recovery code | covered |
| D8 | Login with a remember token but without password | covered |
| D9 | Disable 2FA / regenerate codes without password or during impersonation | covered |
| D10 | Database dump alone → TOTP secrets unreadable; key ring lost → defined behaviour | covered |
| D11 | Stolen session replaces the authenticator (locks the owner out) | covered |
| D12 | Forged passkey registration (foreign / outside origin, cross-origin, wrong RP id, type, challenge, no user verification, other account's or stale state) | covered |
| D13 | Forged passkey sign-in (origin, RP id, type, challenge, no user verification, foreign signature, foreign user handle, unknown credential, inconsistent or changed backup flags) | covered |
| D14 | Replayed passkey assertion, cloned authenticator (counter goes back) | covered |
| D15 | Stolen session adds a passkey, or removes the last way in | covered |
| D16 | Passkey of a pre-registered account survives the owner's mailbox proof; weak RSA key padded to look like 2048 bit; refused sign-in leaves a trace on the passkey | covered |
| D17 | A browser's "remember this device" cookie lets a bearer sign-in of the same browser skip the second factor | covered |
| D18 | Stolen session of an account **without** password swaps its sign-in methods (attacker's passkey in, owner's provider out) or locks it with failed "password" confirmations | covered |
| D19 | Malformed WebAuthn data (CBOR, COSE keys, client data, signatures) crashes a parser – 500 instead of "invalid" | covered |

## E. Workflow tokens (reset, verification, invitation, e-mail change)

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| E1 | Token reuse → second use fails | covered |
| E2 | Purpose confusion (reset token as verification token) | covered |
| E3 | Expired, tampered, truncated token, other user | covered |
| E4 | Reset link, then password changed elsewhere → link invalid | covered |
| E5 | Host-header injection into mail links | design – links come from `Links.BaseUrl`, never from request headers |
| E6 | E-mail change to a taken address → uniform answer, no takeover | covered |
| E7 | Invitation for an existing / accepted account | covered |
| E8 | Pre-account hijacking: attacker registers the victim's address first | covered |
| E10 | Administrator's reset link used as mailbox proof (confirms an attacker's pre-registered account, drops its 2FA) | covered |
| E11 | Start password set by an administrator used as a normal password (session without own password) | covered |
| E12 | Owner clicks the verification link of an account the attacker registered, then signs in with a verified provider → shared account (attacker keeps the password) | covered |
| E9 | HTML / header injection in mails via address or display name | host – mail templates must encode user data ([security model](security.md#host-responsibilities)) |

## F. External login

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| F1 | Open redirect via `returnUrl` (`//evil`, `\\evil`, `https:evil`, user info, Unicode, control characters) | covered |
| F1b | Tenant A's front end used against tenant B (CSRF origin, `returnUrl`, CORS, mail links) | covered |
| F1c | Credential of tenant A presented to tenant B (shared keys, colliding ids, validation interval) | covered |
| F2 | Auto-linking with an unverified provider e-mail → `account_conflict` | covered |
| F2b | Auto-registration with an unverified provider e-mail (attacker's IdP account claims the victim's address) → no account, `email_not_verified` | covered |
| F2c | A Google account carrying an address Google has not verified (another domain) creates or joins an account → only with Google's own `email_verified` mapped, never by trusting the provider | covered |
| F3 | Same provider key at another provider → no mix-up | covered |
| F4 | Exchange code reused, parallel, after expiry | covered |
| F4b | Intercepted exchange code (deep link, history, malicious app) | covered |
| F5 | Missing or forged `state` / correlation (OAuth CSRF) | design – handled by the ASP.NET Core remote handlers; with `UseSlimErrorRedirects()` it ends at the default page with `external_login_failed`, never at a `returnUrl` from the forged request (tested) |
| F6 | Several instances without a shared store → replay window | covered |
| F8 | Answers with tokens or secrets stored by a browser, proxy or CDN cache | covered |
| F7 | Credentials or codes in logs, referrers, URL history | covered |
| F9 | Link CSRF: an attacker's link code planted in the victim's URL links the attacker's provider account | covered |
| F10 | Forged, foreign, replayed or stale back-channel logout tokens sign users out | covered |
| F11 | Stolen session removes the owner's sign-in methods, or the last one is removed (in parallel) | covered |
| F12 | Replayed back-channel logout token without `jti` | covered |

## G. Admin, impersonation, API keys

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| G1 | Impersonation without admin rights | host – authorization of the host endpoint; template `Enterprise/AdminEndpoints.cs` |
| G2 | Impersonated session performs sensitive actions (password, e-mail, 2FA) → 403 | covered |
| G3 | Admin banned / signs out everywhere → impersonation ends | covered |
| G4 | Impersonation + refresh token → none issued | covered |
| G5 | Impersonating a more privileged user | host – rules belong in the host endpoint (documented in the template) |
| G6 | Sudo window: expiry, transfer to another session or account | covered |
| G6b | Password guessing on the host's sudo endpoint with a stolen session | covered |
| G7 | API key: prefix brute force, timing, revoked / expired key, key in logs | covered |
| G8 | User-bound API key acts as the user on `/auth/*` (mints a session, signs out everywhere) | covered |
| G9 | A host endpoint signs a user in with `ISlimAuthManager.SignInAsync` after its own first factor (client certificate): locked, unconfirmed (mailbox not proven), forced password change, 2FA skipped | covered |
| G10 | Ending an impersonation starts a fresh session chain for the administrator (new `auth_time`, new absolute lifetime) | covered |
| G11 | A forced password change (start password set by an administrator) skipped with a passkey or an external login – the known start password stays valid | covered |

## H. Stores and infrastructure

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| H1 | Non-atomic store (refresh, recovery, 2FA step) | covered |
| H1b | EF stores and the host share one `DbContext` (host changes saved early or detached) | covered |
| H2 | Non-unique / case-sensitive addresses in the templates | covered |
| H3 | SQL injection in the Dapper template | covered |
| H4 | Data Protection key ring lost / changed | design – documented failure modes ([guide](guides/data-protection.md)); TOTP secrets: recovery codes |
| H5 | Misconfiguration: defaults, dev mailer in production, HTTP | covered |
| H6 | PII, tokens, codes or passwords in logs or metrics | covered |
| H7 | Error answers, stack traces or headers revealing internals | covered |
| H8 | Vulnerable dependencies, supply chain | covered |
| H9 | A host hook weakens the flow (skips a check, issues a session, breaks sign-ins when it fails) | covered |
| H10 | Revoked role still usable in a running session | covered |
| H11 | Unvalidated profile fields reach the database (mass assignment); half-created accounts (account without profile, orphaned profile rows after a lost race) | covered |
| H12 | Unbounded in-memory state (one-time codes, mail counters) – memory growth, a full scan per request | covered |
| H13 | Without a session store every refresh is reported as a new sign-in (guards see `SignIn`, observers `signed_in` every 15 minutes) | covered |

## Prompt template for one scenario

> You are the attacker. Goal: *&lt;scenario&gt;*. Read *&lt;files&gt;*. Describe a concrete attack with requests. Name the
> line of code that prevents it, or explain why nothing does. Write an xUnit integration test in the style of
> `tests/SlimIdentity.Tests/Integration` that performs the attack and fails if the attack succeeds.

No scenario is open at the moment. New scenarios start as **open** and are closed by a test – never by a comment.
