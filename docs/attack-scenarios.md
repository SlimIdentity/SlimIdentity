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
| A1 | Many parallel wrong passwords → counter exact, lockout applies, no guess beyond the threshold is evaluated | covered – `Concurrency.Parallel_failed_logins_are_all_counted`, `ReviewRound1.R3_parallel_password_guesses_beyond_the_threshold_are_not_evaluated` (40 parallel), conformance (atomic increment). **Fixed** (review round 1): up to 14 of 40 parallel guesses were verified; `ReviewRound2.Different_spellings_of_one_address_share_the_attempt_gate` (**fixed** in round 2: 40 spellings of one address bypassed the gate) |
| A1b | Many parallel attempts keep an account's queue busy | covered – `ReviewRound2.The_queue_of_one_account_is_limited` (at most 8 waiting, the rest refused unevaluated; refused attempts burn their dummy hash outside the queue) |
| A2 | Locked account + correct password → not evaluated, answer identical to a wrong password | covered – `Login.Lockout_is_progressive_and_hidden_by_default` |
| A3 | Unknown / known / inactive / locked → same answer and statistically same time | covered – `Login.Wrong_password_unknown_user_and_inactive_user_get_identical_answers`; timing `Timing.A3_…` (opt-in before a release: `SLIMIDENTITY_TIMING=1`, Mann-Whitney over interleaved requests). Last run: medians 47.8–47.9 ms, \|z\| ≤ 0.95 |
| A4 | Address variants: case, Unicode normalization, whitespace, `+tag`, homoglyphs | covered – `AttackScenario.A4_*`. **Fixed:** NFC and NFD forms of one address created two accounts; addresses are now trimmed and NFC-normalized. `+tag` and homoglyphs are different addresses by design. |
| A5 | Password longer than the maximum, huge bodies → rejected before hashing | covered – `Login.Oversized_password_is_rejected_without_distinguishing_accounts` (body size: Kestrel limits, host) |
| A6 | Permanent lockout of a victim → growth capped (≤ 1 h) | covered – `Login.Lockout_is_progressive_and_hidden_by_default`, unit `LockoutDuration` |
| A7 | `X-Forwarded-For` spoofing to evade the rate limit → ignored without configured proxies | covered – `OpenScenario.A7_spoofed_forwarded_headers_do_not_reset_the_rate_limit`; trusted proxies are the host's `UseForwardedHeaders` ([guide](guides/reverse-proxy.md)); a forgotten configuration is reported (`8001`, `DeploymentDiagnostics.*`) |
| A8 | IPv6 rotation within a /64 → one bucket | covered – `PropertyTests.All_addresses_of_one_ipv6_network_share_a_rate_limit_key` |
| A9 | `/register` timing (write only for new addresses) | design – known limitation in the [security model](security.md#known-limitations); only measurable against the real database of a deployment, not in-process |

## B. Cookies and CSRF

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| B1 | State-changing request without `X-CSRF` → 403 | covered – `CookieAndCsrf.Cookie_login_requires_the_csrf_header`, `HostEndpoint.RequireSlimCsrf_protects_host_endpoints_in_cookie_mode` |
| B2 | Wrong / missing / `null` origin, subdomain, port or scheme variants | covered – `CookieAndCsrf.Origin_is_checked_in_cookie_mode`, `PropertyTests.Only_exact_trusted_origins_are_trusted` |
| B3 | `/login/2fa` in cookie mode from a foreign origin | covered – `Concurrency.Cookie_mode_2fa_step_requires_csrf_even_if_bearer_is_the_default` (**fixed** in review) |
| B4 | Login CSRF (victim signed into the attacker's account) | covered – cookie login requires `X-CSRF` (B1) |
| B5 | Cookie attributes on all responses incl. the 2FA device cookie | covered – `CookieAndCsrf.Cookie_is_HttpOnly_Secure_and_SameSite_strict`, `RememberDevice.Browsers_remember_the_device_with_a_cookie` |
| B6 | Session fixation: cookie set before login → new cookie after login | covered – `OpenScenario.B6_a_planted_cookie_never_becomes_the_victims_session` |
| B7 | Stolen cookie after password change / ban / logout-all → invalid after `SecurityStampValidationInterval` | covered – `CookieAndCsrf.Copied_cookie_is_rejected_after_logout`, `…Without_session_store_logout_all_still_invalidates_copied_cookies` |

## C. JWT, refresh tokens, sessions

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| C1 | JWT manipulation: `alg=none`, algorithm switch, expired, wrong issuer / audience, future `nbf` | covered – `OpenScenario.C1_manipulated_jwts_are_rejected` (10 variants incl. a re-signed control token, missing `exp`, swapped stamp) |
| C2 | Too short `JwtSecret` → start fails | covered – unit `A_jwt_secret_must_have_32_bytes` |
| C3 | Refresh-token replay after rotation → token family revoked | covered – `RefreshAndSession.Refresh_token_reuse_revokes_only_the_affected_session`, `…without_session_store_signs_out_everywhere` |
| C4 | Two parallel refreshes with the same token | design – exactly one wins, the other is treated as theft (no grace window); clients serialize, across tabs with Web Locks ([guide](guides/mobile-bearer.md#refreshing-correctly)); conformance proves single use |
| C5 | Bypass the absolute lifetime by continuous rotation | covered – `RefreshAndSession.Refresh_chain_is_capped_by_the_absolute_lifetime` |
| C6 | Access token after session revocation / stamp rotation → rejected immediately | covered – `RefreshAndSession.Logout_revokes_the_current_session_server_side`, `…Logout_all_ends_every_session` |
| C7 | Token of one user against the session of another | covered – `OpenScenario.C7_a_token_bound_to_another_users_session_is_rejected` (even with the signing key) |
| C8 | `DELETE /sessions/{id}` for a foreign session (IDOR) → 404 | covered – `RefreshAndSession.Sessions_of_other_users_cannot_be_revoked` |
| C9 | `/logout` with someone else's or a garbage refresh token | covered – `OpenScenario.C9_logout_cannot_end_other_users_sessions` |

## D. Two-factor authentication

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| D1 | Same TOTP code twice, also in parallel → accepted once | covered – `TwoFactor.A_totp_code_is_accepted_only_once`, conformance (parallel) |
| D2 | Older time step after a newer one → rejected | covered – `TwoFactor.A_totp_code_is_accepted_only_once` |
| D3 | Brute force of the 6-digit code → counts towards lockout, rate limited, parallel guesses beyond the threshold not evaluated | covered – `TwoFactor.Failed_second_factors_count_towards_the_lockout`, `ReviewRound1.R3_parallel_second_factor_guesses_beyond_the_threshold_are_not_evaluated`. **Fixed** (review round 1) |
| D6 | Stolen session replaces the authenticator (locks the owner out) | covered – `ReviewRound1.R2_replacing_the_authenticator_needs_the_password`, `…R2_a_setup_token_dies_with_the_security_stamp`. **Fixed** (review round 1): `/2fa/enable` needed no password |
| D4 | `preAuthToken` reused, parallel, expired, of another user | covered – `Concurrency.A_sign_in_challenge_completes_only_one_sign_in` (**fixed** in review), conformance (parallel); property tests for tampered tokens |
| D5 | Recovery code reused, parallel, brute force, format variants | covered – `TwoFactor.Recovery_code_works_exactly_once`, conformance (parallel); 80-bit codes |
| D6 | Mail bombing by requesting codes / links repeatedly | covered – `AttackScenario.D6_one_inbox_cannot_be_flooded_with_mails`. **Fixed:** at most 3 mails per recipient and kind in 15 minutes (5 for 2FA codes), silently, per instance |
| D7 | Remember token of another user, after password / 2FA change, after a recovery code | covered – `RememberDevice.Remember_token_belongs_to_one_user`, `…Password_change_invalidates_remembered_devices`, `…Recovery_codes_never_remember_the_device` |
| D8 | Login with a remember token but without password | covered – the password is always verified first (`RememberDevice.*`) |
| D9 | Disable 2FA / regenerate codes without password or during impersonation | covered – `OpenScenario.D9_two_factor_changes_need_the_password`, `…G2_*` |
| D10 | Database dump alone → TOTP secrets unreadable; key ring lost → defined behaviour | covered – `TwoFactor.Totp_secret_and_recovery_codes_are_never_stored_in_clear_text`; key loss documented ([guide](guides/data-protection.md)) |

## E. Workflow tokens (reset, verification, invitation, e-mail change)

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| E1 | Token reuse → second use fails | covered – `Account.Reset_password_is_single_use_and_ends_all_sessions`, `InvitationAndImpersonation.Invitation_…_is_single_use` |
| E2 | Purpose confusion (reset token as verification token) | covered – `PropertyTests.A_token_is_bound_to_its_purpose` |
| E3 | Expired, tampered, truncated token, other user | covered – `PropertyTests.Tampered_tokens_are_rejected`, `…Arbitrary_strings_are_never_accepted_as_tokens` |
| E4 | Reset link, then password changed elsewhere → link invalid | covered – `OpenScenario.E4_a_reset_link_dies_when_the_password_is_changed_elsewhere` |
| E5 | Host-header injection into mail links | design – links come from `Links.BaseUrl`, never from request headers |
| E6 | E-mail change to a taken address → uniform answer, no takeover | covered – `EmailChangeAndPasswordRule.Taken_address_answers_identically_and_informs_its_owner` |
| E7 | Invitation for an existing / accepted account | covered – `InvitationAndImpersonation.Invitation_cannot_be_created_for_users_with_a_password` |
| E8 | Pre-account hijacking: attacker registers the victim's address first | covered – `ExternalLogin.Pre_registered_unverified_account_is_taken_over_by_the_verified_owner_not_shared`, `AttackScenario.E8_*`. **Fixed:** the first proof of the mailbox (verified external login, password reset) removes the registrant's password, 2FA and sessions – and, since review round 1, external logins linked before (`ReviewRound1.R1_the_owners_mailbox_proof_removes_external_logins_linked_before`) |
| E10 | Administrator's reset link used as mailbox proof (confirms an attacker's pre-registered account, drops its 2FA) | covered – `Administrator.An_administrators_reset_link_is_no_proof_of_the_mailbox` |
| E11 | Start password set by an administrator used as a normal password (session without own password) | covered – `Administrator.A_start_password_must_be_changed_before_any_session_exists`, `…The_change_token_is_no_session_and_dies_with_the_stamp`, `…The_forced_change_is_followed_by_the_second_factor` |
| E9 | HTML / header injection in mails via address or display name | host – mail templates must encode user data ([security model](security.md#host-responsibilities)) |

## F. External login

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| F1 | Open redirect via `returnUrl` (`//evil`, `\\evil`, `https:evil`, user info, Unicode, control characters) | covered – `PropertyTests.Return_url_never_leaves_the_trusted_origins`, `…Known_open_redirect_tricks_are_rejected`. **Fixed:** `/\t/evil` passed (browsers strip the tab) |
| F1b | Tenant A's front end used against tenant B (CSRF origin, `returnUrl`, CORS, mail links) | covered – `Tenant.Cookie_requests_are_accepted_only_from_the_tenants_own_front_end`, `…A_return_url_must_belong_to_the_tenant`, `…Cors_allows_credentials_for_the_tenants_front_end_only`, `…Mail_links_point_to_the_tenants_front_end` |
| F2 | Auto-linking with an unverified provider e-mail → `account_conflict` | covered – `ExternalLogin.Unverified_email_of_an_existing_account_is_not_linked` |
| F2b | Auto-registration with an unverified provider e-mail (attacker's IdP account claims the victim's address) → no account, `email_not_verified` | covered – `ReviewRound1.R1_no_account_is_created_for_an_unverified_provider_address`. **Fixed** (review round 1) |
| F3 | Same provider key at another provider → no mix-up | covered – conformance (external-login store) |
| F4 | Exchange code reused, parallel, after expiry | covered – `ExternalLogin.The_exchange_code_works_only_once` (both modes), `OpenScenario.F4_*` (8 parallel redemptions, expiry with and without refresh-token store – **fixed** in review round 1: token expiry followed the system clock, not `TimeProvider`) |
| F4b | Intercepted exchange code (deep link, history, malicious app) | covered – `ReviewRound1.C1_bearer_external_login_requires_a_pkce_challenge`, `…C1_the_exchange_code_travels_in_the_fragment_and_is_worthless_without_the_verifier`. **Fixed** (review round 1): the code is bound to a PKCE challenge (S256) and travels in the fragment |
| F5 | Missing or forged `state` / correlation (OAuth CSRF) | design – handled by the ASP.NET Core remote handlers |
| F6 | Several instances without a shared store → replay window | covered – with a refresh-token store the code is single-use across instances; without one, start-up warning `8004` ([several instances](guides/multiple-instances.md)), `DeploymentDiagnostics.External_login_without_refresh_store_is_reported_in_production` |
| F8 | Answers with tokens or secrets stored by a browser, proxy or CDN cache | covered – `ReviewRound2.Responses_with_secrets_are_never_cached` (`Cache-Control: no-store` on `/auth`; **fixed** in review round 2) |
| F7 | Credentials or codes in logs, referrers, URL history | covered – `ExternalLogin.New_external_user_…`, `ReviewRound1.R6_no_pre_auth_token_in_the_query_after_external_login_with_2fa` (secrets only in the fragment – **fixed** in review round 1), `LogSecrecy.No_secret_or_address_is_ever_logged` |

## G. Admin, impersonation, API keys

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| G1 | Impersonation without admin rights | host – authorization of the host endpoint; template `Enterprise/AdminEndpoints.cs` |
| G2 | Impersonated session performs sensitive actions (password, e-mail, 2FA) → 403 | covered – `OpenScenario.G2_…` for all eight sensitive endpoints |
| G3 | Admin banned / signs out everywhere → impersonation ends | covered – `InvitationAndImpersonation.Impersonation_dies_when_the_admin_signs_out_everywhere` |
| G4 | Impersonation + refresh token → none issued | covered – `OpenScenario.G4_impersonation_issues_no_refresh_token` |
| G5 | Impersonating a more privileged user | host – rules belong in the host endpoint (documented in the template) |
| G6 | Sudo window: expiry, transfer to another session or account | covered – `HostEndpoint.Sudo_policy_requires_an_elevated_session_that_expires`, `HostEndpoint.Q3_a_session_is_never_elevated_to_another_account` |
| G6b | Password guessing on the host's sudo endpoint with a stolen session | covered – `HostEndpoint.R7_password_confirmation_on_host_endpoints_counts_towards_the_lockout` (`ISlimAuthManager.ConfirmPasswordAsync`; **fixed** in review round 1: the template verified with `IPasswordHasher`, without lockout) |
| G7 | API key: prefix brute force, timing, revoked / expired key, key in logs | covered in part – `HostEndpoint.Api_key_authenticates_machine_clients`; 256-bit keys, only hashes stored and compared by lookup |
| G8 | User-bound API key acts as the user on `/auth/*` (mints a session, signs out everywhere) | covered – `ReviewRound1.R5_an_api_key_cannot_act_as_the_user_on_the_account_endpoints`. **Fixed** (review round 1): account endpoints accept cookies and bearer tokens only |

## H. Stores and infrastructure

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| H9 | A host hook weakens the flow (skips a check, issues a session, breaks sign-ins when it fails) | covered – by design hooks can only refuse or observe; `Hook.A_veto_ends_running_sessions_and_refreshes`, `…An_external_sign_in_is_vetoed_as_well`, `…A_failing_event_handler_changes_nothing`, `…Only_allowed_addresses_can_register` |
| H1 | Non-atomic store (refresh, recovery, 2FA step) | covered – `SlimIdentity.Testing` conformance, incl. parallel checks |
| H1b | EF stores and the host share one `DbContext` (host changes saved early or detached) | covered – `SharedContextTests` (EF Core package), template on its own context (`IdentityDb`). **Fixed** (review round 1) |
| H2 | Non-unique / case-sensitive addresses in the templates | covered – conformance of the EF Core stores on SQLite, PostgreSQL and SQL Server and of the Dapper stores on PostgreSQL (service containers in CI; locally via `SLIMIDENTITY_TEST_POSTGRES` / `SLIMIDENTITY_TEST_SQLSERVER`) |
| H3 | SQL injection in the Dapper template | covered – conformance check with quotes, comment characters and LIKE wildcards in addresses (all templates and any host store) |
| H4 | Data Protection key ring lost / changed | design – documented failure modes ([guide](guides/data-protection.md)); TOTP secrets: recovery codes |
| H5 | Misconfiguration: defaults, dev mailer in production, HTTP | covered – options validation at start (unit tests), `NullEmailSenderGuard.*` (**new:** the null sender stops the start in `Production`) |
| H6 | PII, tokens, codes or passwords in logs or metrics | covered – `LogSecrecy.No_secret_or_address_is_ever_logged`, `HostEndpoint.Sign_in_attempts_are_counted_without_personal_data` |
| H7 | Error answers, stack traces or headers revealing internals | covered – `OpenScenario.H7_error_answers_reveal_no_internals` for every error answer SlimIdentity produces; unhandled exceptions (e.g. a failing store) go through the host's exception handler – 500 without details in `Production` |
| H8 | Vulnerable dependencies, supply chain | covered – vulnerability check in CI, actions pinned to commit SHAs, Dependabot, CodeQL, NuGet Trusted Publishing |

## Prompt template for one scenario

> You are the attacker. Goal: *&lt;scenario&gt;*. Read *&lt;files&gt;*. Describe a concrete attack with requests. Name the
> line of code that prevents it, or explain why nothing does. Write an xUnit integration test in the style of
> `tests/SlimIdentity.Tests/Integration` that performs the attack and fails if the attack succeeds.

No scenario is open at the moment. New scenarios start as **open** and are closed by a test – never by a comment.
