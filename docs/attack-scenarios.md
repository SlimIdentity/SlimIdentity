# Attack scenarios

A checklist for reviews – by people and by AI agents – and the current state of each scenario.

**Rule:** a finding is real only once a failing test demonstrates it. Every defence that is confirmed gets a permanent
regression test. (This is how the findings marked *fixed* below were handled.)

Status: **covered** – a test proves the defence · **design** – deliberate behaviour, documented · **host** – the
responsibility of the application (only our templates are reviewed) · **open** – not yet proven by a test.

Test names refer to `tests/SlimIdentity.Tests` (`Integration/…`, `Unit/PropertyTests`) and the conformance kit
`SlimIdentity.Testing` (run against the test stores and the EF Core templates).

## A. Login, lockout, enumeration

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| A1 | Many parallel wrong passwords → counter exact, lockout applies | covered – `Concurrency.Parallel_failed_logins_are_all_counted`, conformance (atomic increment) |
| A2 | Locked account + correct password → not evaluated, answer identical to a wrong password | covered – `Login.Lockout_is_progressive_and_hidden_by_default` |
| A3 | Unknown / known / inactive / locked → same answer and statistically same time | answers covered – `Login.Wrong_password_unknown_user_and_inactive_user_get_identical_answers`; timing: **open** (manual benchmark before a release, ≥ 1000 runs, Mann-Whitney – too noisy for CI) |
| A4 | Address variants: case, Unicode normalization, whitespace, `+tag`, homoglyphs | covered – `AttackScenario.A4_*`. **Fixed:** NFC and NFD forms of one address created two accounts; addresses are now trimmed and NFC-normalized. `+tag` and homoglyphs are different addresses by design. |
| A5 | Password longer than the maximum, huge bodies → rejected before hashing | covered – `Login.Oversized_password_is_rejected_without_distinguishing_accounts` (body size: Kestrel limits, host) |
| A6 | Permanent lockout of a victim → growth capped (≤ 1 h) | covered – `Login.Lockout_is_progressive_and_hidden_by_default`, unit `LockoutDuration` |
| A7 | `X-Forwarded-For` spoofing to evade the rate limit → ignored without configured proxies | design – SlimIdentity reads `RemoteIpAddress` only; forwarded headers are the host's `UseForwardedHeaders` with known proxies ([guide](guides/reverse-proxy.md)). Test: **open** |
| A8 | IPv6 rotation within a /64 → one bucket | covered – `PropertyTests.All_addresses_of_one_ipv6_network_share_a_rate_limit_key` |
| A9 | `/register` timing (write only for new addresses) | design – known limitation in the [security model](security.md#known-limitations); measurement **open** |

## B. Cookies and CSRF

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| B1 | State-changing request without `X-CSRF` → 403 | covered – `CookieAndCsrf.Cookie_login_requires_the_csrf_header`, `HostEndpoint.RequireSlimCsrf_protects_host_endpoints_in_cookie_mode` |
| B2 | Wrong / missing / `null` origin, subdomain, port or scheme variants | covered – `CookieAndCsrf.Origin_is_checked_in_cookie_mode`, `PropertyTests.Only_exact_trusted_origins_are_trusted` |
| B3 | `/login/2fa` in cookie mode from a foreign origin | covered – `Concurrency.Cookie_mode_2fa_step_requires_csrf_even_if_bearer_is_the_default` (**fixed** in review) |
| B4 | Login CSRF (victim signed into the attacker's account) | covered – cookie login requires `X-CSRF` (B1) |
| B5 | Cookie attributes on all responses incl. the 2FA device cookie | covered – `CookieAndCsrf.Cookie_is_HttpOnly_Secure_and_SameSite_strict`, `RememberDevice.Browsers_remember_the_device_with_a_cookie` |
| B6 | Session fixation: cookie set before login → new cookie after login | design – the ASP.NET Core cookie handler issues a new ticket on every sign-in; test **open** |
| B7 | Stolen cookie after password change / ban / logout-all → invalid after `SecurityStampValidationInterval` | covered – `CookieAndCsrf.Copied_cookie_is_rejected_after_logout`, `…Without_session_store_logout_all_still_invalidates_copied_cookies` |

## C. JWT, refresh tokens, sessions

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| C1 | JWT manipulation: `alg=none`, algorithm switch, expired, wrong issuer / audience, future `nbf` | design – validated by ASP.NET Core JWT bearer (explicit algorithm, issuer, audience, lifetime); tests **open** |
| C2 | Too short `JwtSecret` → start fails | covered – unit `A_jwt_secret_must_have_32_bytes` |
| C3 | Refresh-token replay after rotation → token family revoked | covered – `RefreshAndSession.Refresh_token_reuse_revokes_only_the_affected_session`, `…without_session_store_signs_out_everywhere` |
| C4 | Two parallel refreshes with the same token | design – exactly one wins, the other is treated as theft (no grace window); clients serialize, across tabs with Web Locks ([guide](guides/mobile-bearer.md#refreshing-correctly)); conformance proves single use |
| C5 | Bypass the absolute lifetime by continuous rotation | covered – `RefreshAndSession.Refresh_chain_is_capped_by_the_absolute_lifetime` |
| C6 | Access token after session revocation / stamp rotation → rejected immediately | covered – `RefreshAndSession.Logout_revokes_the_current_session_server_side`, `…Logout_all_ends_every_session` |
| C7 | Token of one user against the session of another | design – the session's user id is compared with the token's `sub` (`SlimSecurityStampValidator`); test **open** |
| C8 | `DELETE /sessions/{id}` for a foreign session (IDOR) → 404 | covered – `RefreshAndSession.Sessions_of_other_users_cannot_be_revoked` |
| C9 | `/logout` with someone else's refresh token | open |

## D. Two-factor authentication

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| D1 | Same TOTP code twice, also in parallel → accepted once | covered – `TwoFactor.A_totp_code_is_accepted_only_once`, conformance (parallel) |
| D2 | Older time step after a newer one → rejected | covered – `TwoFactor.A_totp_code_is_accepted_only_once` |
| D3 | Brute force of the 6-digit code → counts towards lockout, rate limited | covered – `TwoFactor.Failed_second_factors_count_towards_the_lockout` |
| D4 | `preAuthToken` reused, parallel, expired, of another user | covered – `Concurrency.A_sign_in_challenge_completes_only_one_sign_in` (**fixed** in review), conformance (parallel); property tests for tampered tokens |
| D5 | Recovery code reused, parallel, brute force, format variants | covered – `TwoFactor.Recovery_code_works_exactly_once`, conformance (parallel); 80-bit codes |
| D6 | Mail bombing by requesting codes / links repeatedly | covered – `AttackScenario.D6_one_inbox_cannot_be_flooded_with_mails`. **Fixed:** at most 3 mails per recipient and kind in 15 minutes (5 for 2FA codes), silently, per instance |
| D7 | Remember token of another user, after password / 2FA change, after a recovery code | covered – `RememberDevice.Remember_token_belongs_to_one_user`, `…Password_change_invalidates_remembered_devices`, `…Recovery_codes_never_remember_the_device` |
| D8 | Login with a remember token but without password | covered – the password is always verified first (`RememberDevice.*`) |
| D9 | Disable 2FA / regenerate codes without password or during impersonation | design – every `/2fa/*` change confirms the password and refuses impersonation sessions; dedicated tests **open** |
| D10 | Database dump alone → TOTP secrets unreadable; key ring lost → defined behaviour | covered – `TwoFactor.Totp_secret_and_recovery_codes_are_never_stored_in_clear_text`; key loss documented ([guide](guides/data-protection.md)) |

## E. Workflow tokens (reset, verification, invitation, e-mail change)

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| E1 | Token reuse → second use fails | covered – `Account.Reset_password_is_single_use_and_ends_all_sessions`, `InvitationAndImpersonation.Invitation_…_is_single_use` |
| E2 | Purpose confusion (reset token as verification token) | covered – `PropertyTests.A_token_is_bound_to_its_purpose` |
| E3 | Expired, tampered, truncated token, other user | covered – `PropertyTests.Tampered_tokens_are_rejected`, `…Arbitrary_strings_are_never_accepted_as_tokens` |
| E4 | Reset link, then password changed elsewhere → link invalid | design – links are bound to the security stamp; test **open** |
| E5 | Host-header injection into mail links | design – links come from `Links.BaseUrl`, never from request headers |
| E6 | E-mail change to a taken address → uniform answer, no takeover | covered – `EmailChangeAndPasswordRule.Taken_address_answers_identically_and_informs_its_owner` |
| E7 | Invitation for an existing / accepted account | covered – `InvitationAndImpersonation.Invitation_cannot_be_created_for_users_with_a_password` |
| E8 | Pre-account hijacking: attacker registers the victim's address first | covered – `ExternalLogin.Pre_registered_unverified_account_is_taken_over_by_the_verified_owner_not_shared`, `AttackScenario.E8_*`. **Fixed:** the first proof of the mailbox (verified external login, password reset) removes the registrant's password, 2FA and sessions |
| E9 | HTML / header injection in mails via address or display name | host – mail templates must encode user data ([security model](security.md#host-responsibilities)) |

## F. External login

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| F1 | Open redirect via `returnUrl` (`//evil`, `\\evil`, `https:evil`, user info, Unicode, control characters) | covered – `PropertyTests.Return_url_never_leaves_the_trusted_origins`, `…Known_open_redirect_tricks_are_rejected`. **Fixed:** `/\t/evil` passed (browsers strip the tab) |
| F2 | Auto-linking with an unverified provider e-mail → `account_conflict` | covered – `ExternalLogin.Unverified_email_of_an_existing_account_is_not_linked` |
| F3 | Same provider key at another provider → no mix-up | covered – conformance (external-login store) |
| F4 | Exchange code reused, parallel, after expiry | covered – `ExternalLogin.The_exchange_code_works_only_once` (both modes); parallel / expiry **open** |
| F5 | Missing or forged `state` / correlation (OAuth CSRF) | design – handled by the ASP.NET Core remote handlers |
| F6 | Several instances without a shared store → replay window | design – documented in the [security model](security.md#known-limitations) |
| F7 | Credentials or codes in logs, referrers, URL history | covered – `ExternalLogin.New_external_user_…` (no tokens in URLs), `LogSecrecy.No_secret_or_address_is_ever_logged` |

## G. Admin, impersonation, API keys

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| G1 | Impersonation without admin rights | host – authorization of the host endpoint; template `Enterprise/AdminEndpoints.cs` |
| G2 | Impersonated session performs sensitive actions (password, e-mail, 2FA) → 403 | covered in part – guards in all sensitive endpoints; a test per endpoint is **open** |
| G3 | Admin banned / signs out everywhere → impersonation ends | covered – `InvitationAndImpersonation.Impersonation_dies_when_the_admin_signs_out_everywhere` |
| G4 | Impersonation + refresh token → none issued | design – impersonation sessions are never persistent; test **open** |
| G5 | Impersonating a more privileged user | host – rules belong in the host endpoint (documented in the template) |
| G6 | Sudo window: expiry, transfer to another session | covered – `HostEndpoint.Sudo_policy_requires_an_elevated_session_that_expires` |
| G7 | API key: prefix brute force, timing, revoked / expired key, key in logs | covered in part – `HostEndpoint.Api_key_authenticates_machine_clients`; 256-bit keys, only hashes stored and compared by lookup |

## H. Stores and infrastructure

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| H1 | Non-atomic store (refresh, recovery, 2FA step) | covered – `SlimIdentity.Testing` conformance, incl. parallel checks |
| H2 | Non-unique / case-sensitive addresses in the templates | covered for EF Core (SQLite, CI); Dapper template: **open** (needs PostgreSQL) |
| H3 | SQL injection in the Dapper template | reviewed – parameterized statements only; no automated test |
| H4 | Data Protection key ring lost / changed | design – documented failure modes ([guide](guides/data-protection.md)); TOTP secrets: recovery codes |
| H5 | Misconfiguration: defaults, dev mailer in production, HTTP | covered – options validation at start (unit tests), `NullEmailSenderGuard.*` (**new:** the null sender stops the start in `Production`) |
| H6 | PII, tokens, codes or passwords in logs or metrics | covered – `LogSecrecy.No_secret_or_address_is_ever_logged`, `HostEndpoint.Sign_in_attempts_are_counted_without_personal_data` |
| H7 | Error answers, stack traces or headers revealing internals | open |
| H8 | Vulnerable dependencies, supply chain | covered – vulnerability check in CI, actions pinned to commit SHAs, Dependabot, CodeQL, NuGet Trusted Publishing |

## Prompt template for one scenario

> You are the attacker. Goal: *&lt;scenario&gt;*. Read *&lt;files&gt;*. Describe a concrete attack with requests. Name the
> line of code that prevents it, or explain why nothing does. Write an xUnit integration test in the style of
> `tests/SlimIdentity.Tests/Integration` that performs the attack and fails if the attack succeeds.

Suggested order for the remaining **open** items: C1, C7/C9, G2/G4, E4, F4 (parallel / expiry), B6, H7, A7, then the
timing measurements A3/A9.
