# Attack scenarios

A checklist for reviews – by people and by AI agents – and the current state of each scenario.

**Rule:** a finding is real only once a failing test demonstrates it. Every defence that is confirmed gets a permanent
regression test. (This is how the findings marked *fixed* below were handled.)

Entries marked **Fixed** record historical context for a resolved issue; the test named in that row is the current
regression check. They are not a list of open findings.

Status: **covered** – a test proves the defence · **design** – deliberate behaviour, documented · **host** – the
responsibility of the application (only our templates are reviewed) · **open** – not yet proven by a test.

Test names refer to `tests/SlimIdentity.Tests` (`Integration/…`, `Unit/PropertyTests`) and the conformance kit
`SlimIdentity.Testing` (run against the test stores and the EF Core templates).

## A. Login, lockout, enumeration

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| A1 | Many parallel wrong passwords → counter exact, lockout applies, no guess beyond the threshold is evaluated | covered – `Concurrency.Parallel_failed_logins_are_all_counted`, `ReviewRound1.R3_parallel_password_guesses_beyond_the_threshold_are_not_evaluated` (40 parallel), conformance (atomic reservation, exactly one attempt locks at the threshold). **Fixed** (review round 1): up to 14 of 40 parallel guesses were verified; `ReviewRound2.Different_spellings_of_one_address_share_the_attempt_gate` (**fixed** in round 2: 40 spellings of one address bypassed the gate) |
| A2 | Locked account + correct password → not evaluated, answer identical to a wrong password | covered – `Login.Lockout_is_progressive_and_hidden_by_default` |
| A3 | Unknown / known / inactive / locked → same answer and statistically same time | covered – `Login.Wrong_password_unknown_user_and_inactive_user_get_identical_answers`; timing `Timing.A3_…` (opt-in before a release: `SLIMIDENTITY_TIMING=1`, Mann-Whitney over interleaved requests). Record fresh results, runtime and environment when running the timing check; previous measurements are not a release guarantee. |
| A4 | Address variants: case, Unicode normalization, whitespace, `+tag`, homoglyphs | covered – `AttackScenario.A4_*`. **Fixed:** NFC and NFD forms of one address created two accounts; addresses are now trimmed and NFC-normalized. `+tag` and homoglyphs are different addresses by design. |
| A5 | Password longer than the maximum, huge bodies → rejected before hashing | covered – `Login.Oversized_password_is_rejected_without_distinguishing_accounts` (body size: Kestrel limits, host) |
| A6 | Permanent lockout of a victim → growth capped (≤ 1 h) | covered – `Login.Lockout_is_progressive_and_hidden_by_default`, unit `LockoutDuration` |
| A7 | `X-Forwarded-For` spoofing to evade the rate limit → ignored without configured proxies | covered – `OpenScenario.A7_spoofed_forwarded_headers_do_not_reset_the_rate_limit`; trusted proxies are the host's `UseForwardedHeaders` ([guide](guides/reverse-proxy.md)); a forgotten configuration is reported (`8001`, `DeploymentDiagnostics.*`) |
| A8 | IPv6 rotation within a /64 → one bucket | covered – `PropertyTests.All_addresses_of_one_ipv6_network_share_a_rate_limit_key` |
| A9 | `/register` timing (write only for new addresses) | design – known limitation in the [security model](security.md#known-limitations); only measurable against the real database of a deployment, not in-process |
| A10 | `/register` with a profile: its validation, or the profile itself, reveals or changes an existing account | covered – `RegistrationProfile.An_invalid_profile_answers_400_before_anything_is_looked_up` (same answer, no mail), `…An_existing_address_gets_the_uniform_answer_and_its_profile_is_dropped`, `…RegisterAsync_creates_the_account_with_its_profile_by_the_rules_of_register` (host endpoints) |
| A11 | Display-name addresses (`n1 <victim@x>`, `victim@x <attacker@evil>`): one inbox behind endless "different" addresses, look-alike confirmed accounts | covered – `ReviewRound4Address.Q_a_display_name_form_is_not_accepted_as_an_address`, `…S_display_names_do_not_bypass_the_per_recipient_mail_limit`. **Fixed** (external review round 4) |

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
| C9 | `/logout` with someone else's, a garbage or a dead refresh token (rotated away, or from before a password change on the same device) | covered – `OpenScenario.C9_logout_cannot_end_other_users_sessions`, `ReviewRound2.F06_*` (**fixed**: a dead but genuine token ended the renewed session) |

## D. Two-factor authentication

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| D1 | Same TOTP code twice, also in parallel → accepted once | covered – `TwoFactor.A_totp_code_is_accepted_only_once`, conformance (parallel) |
| D2 | Older time step after a newer one → rejected | covered – `TwoFactor.A_totp_code_is_accepted_only_once` |
| D3 | Brute force of the 6-digit code → counts towards its own lockout, rate limited, parallel guesses beyond the threshold not evaluated | covered – `TwoFactor.Failed_second_factors_lock_only_the_second_factor`, `ReviewRound1.R3_parallel_second_factor_guesses_beyond_the_threshold_are_not_evaluated`. **Fixed** (review round 1) |
| D3b | Brute force of the mailed `verify_email` code | covered – `VerifyEmailStep.A_flow_allows_five_attempts`, `…An_address_allows_ten_attempts_across_flows`, `…A_flow_without_a_delivered_code_accepts_no_code`; codes are bound to the flow and the stamp, the address is confirmed only by the right one |
| D4 | `flowToken` reused, parallel, expired, of another user | covered – `Concurrency.A_sign_in_challenge_completes_only_one_sign_in` (**fixed** in review), conformance (parallel); property tests for tampered tokens |
| D5 | Recovery code reused, parallel, brute force, format variants | covered – `TwoFactor.Recovery_code_works_exactly_once`, conformance (parallel); 80-bit codes |
| D6 | Mail bombing by requesting codes / links repeatedly | covered – `AttackScenario.D6_one_inbox_cannot_be_flooded_with_mails`. **Fixed:** at most 3 mails per recipient and kind in 15 minutes (5 for sign-in codes), silently, counted in `ISlimSharedState` (across instances with a shared one – `MultiInstance.The_mail_limit_per_recipient_spans_instances`); `ReviewRound2.F05_*` (**fixed**: a table filled with fresh addresses switched the limit off for everyone – it now fails closed for new recipients) |
| D7 | Remember token of another user, after password / 2FA change, after a recovery code | covered – `RememberDevice.Remember_token_belongs_to_one_user`, `…Password_change_invalidates_remembered_devices`, `…Recovery_codes_never_remember_the_device` |
| D8 | Login with a remember token but without password | covered – the password is always verified first (`RememberDevice.*`) |
| D9 | Disable 2FA / regenerate codes without password or during impersonation | covered – `OpenScenario.D9_two_factor_changes_need_the_password`, `…G2_*` |
| D10 | Database dump alone → TOTP secrets unreadable; key ring lost → defined behaviour | covered – `TwoFactor.Totp_secret_and_recovery_codes_are_never_stored_in_clear_text`; key loss documented ([guide](guides/data-protection.md)) |
| D11 | Stolen session replaces the authenticator (locks the owner out) | covered – `ReviewRound1.R2_replacing_the_authenticator_needs_the_password`, `…R2_a_setup_token_dies_with_the_security_stamp`. **Fixed** (review round 1): `/2fa/enable` needed no password |
| D12 | Forged passkey registration (foreign / outside origin, cross-origin, wrong RP id, type, challenge, no user verification, other account's or stale state) | covered – `Passkey.Forged_registrations_are_rejected`, `…A_registration_state_belongs_to_its_account_and_stamp` |
| D13 | Forged passkey sign-in (origin, RP id, type, challenge, no user verification, foreign signature, foreign user handle, unknown credential, inconsistent or changed backup flags) | covered – `Passkey.Forged_sign_ins_are_rejected`, `…An_unknown_passkey_is_rejected` |
| D14 | Replayed passkey assertion, cloned authenticator (counter goes back) | covered – `Passkey.A_replayed_sign_in_is_rejected`, `…A_counter_that_goes_back_is_rejected`, conformance (`TryRecordUseAsync` single use and compare-and-set, also parallel) |
| D15 | Stolen session adds a passkey, or removes the last way in | covered – `Passkey.Adding_a_passkey_needs_the_password_a_confirmed_address_and_no_impersonation`, `…The_last_way_in_stays_across_passkeys_and_external_logins`, `…Someone_elses_passkey_cannot_be_renamed_or_removed` |
| D16 | Passkey of a pre-registered account survives the owner's mailbox proof; weak RSA key padded to look like 2048 bit; refused sign-in leaves a trace on the passkey | covered – `Passkey.The_registrants_passkeys_do_not_survive_the_owners_mailbox_proof`, `…a_verified_external_sign_in_of_the_owner`, `…A_weak_rsa_key_is_refused_even_when_padded_to_2048_bit`, `…Inconsistent_backup_flags_are_rejected`, `…An_inactive_account_and_a_vetoing_guard_get_no_session`, conformance (`RemovePasskeysAsync`). **Fixed** (external review round 3) |
| D17 | A browser's "remember this device" cookie lets a bearer sign-in of the same browser skip the second factor | covered – `ReviewRound3.S3_a_bearer_sign_in_never_uses_the_browsers_remember_cookie`. **Fixed** (external review round 3) |
| D18 | Stolen session of an account **without** password swaps its sign-in methods (attacker's passkey in, owner's provider out) or locks it with failed "password" confirmations | covered – `ReviewRound4.S1_a_stolen_session_of_a_passwordless_account_cannot_swap_its_sign_in_methods`, `…S1_after_a_fresh_sign_in_a_passwordless_owner_adds_and_removes_methods`, `…U_a_passwordless_account_is_not_locked_out_by_the_2fa_settings_page`. **Fixed** (external review round 4) – known limitation: the 5-minute window after a sign-in ([security](security.md#known-limitations)) |
| D19 | Malformed WebAuthn data (CBOR, COSE keys, client data, signatures) crashes a parser – 500 instead of "invalid" | covered – `WebAuthnFuzz.The_parsers_never_throw_whatever_arrives` (mutation fuzzing; `SLIMIDENTITY_FUZZ_ROUNDS` for long runs). **Fixed:** invalid UTF-8, EC point off the curve, CBOR integers beyond 32 bits |

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
| E8 | Pre-account hijacking: attacker registers the victim's address first | covered – `ExternalLogin.Pre_registered_unverified_account_is_taken_over_by_the_verified_owner_not_shared`, `AttackScenario.E8_*`. **Fixed:** the first proof of the mailbox (verified external login, password reset) removes the registrant's password, 2FA and sessions – and, since review round 1, external logins linked before (`ReviewRound1.R1_the_owners_mailbox_proof_removes_external_logins_linked_before`); since review round 2 an unconfirmed account cannot set up 2FA (`AttackScenario.E8_a_second_factor_…`, `ReviewRound2.F01_*`); the registrant gets no session before the mailbox is proven (`verify_email`) |
| E10 | Administrator's reset link used as mailbox proof (confirms an attacker's pre-registered account, drops its 2FA) | covered – `Administrator.An_administrators_reset_link_is_no_proof_of_the_mailbox` |
| E11 | Start password set by an administrator used as a normal password (session without own password) | covered – `Administrator.A_start_password_must_be_changed_before_any_session_exists`, `…The_change_token_is_no_session_and_dies_with_the_stamp`, `…The_forced_change_is_followed_by_the_second_factor`, `ReviewRound2.F03_*` (**fixed**: a lockout between sign-in and change was lifted by the new password) |
| E12 | Owner clicks the verification link of an account the attacker registered, then signs in with a verified provider → shared account (attacker keeps the password) | covered – `ReviewRound2.F02_a_verification_click_does_not_hand_the_owners_social_sign_in_to_the_registrant`, `…F02_the_registrant_cannot_link_an_external_login_to_an_unconfirmed_account`. **Fixed** (review round 2): accounts with a password are no longer joined automatically |
| E9 | HTML / header injection in mails via address or display name | host – mail templates must encode user data ([security model](security.md#host-responsibilities)) |

## F. External login

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| F1 | Open redirect via `returnUrl` (`//evil`, `\\evil`, `https:evil`, user info, Unicode, control characters) | covered – `PropertyTests.Return_url_never_leaves_the_trusted_origins`, `…Known_open_redirect_tricks_are_rejected`. **Fixed:** `/\t/evil` passed (browsers strip the tab) |
| F1b | Tenant A's front end used against tenant B (CSRF origin, `returnUrl`, CORS, mail links) | covered – `Tenant.Cookie_requests_are_accepted_only_from_the_tenants_own_front_end`, `…A_return_url_must_belong_to_the_tenant`, `…Cors_allows_credentials_for_the_tenants_front_end_only`, `…Mail_links_point_to_the_tenants_front_end` |
| F1c | Credential of tenant A presented to tenant B (shared keys, colliding ids, validation interval) | covered – `ReviewRound5.A_cookie_of_one_tenant_is_not_accepted_by_another`, `…A_bearer_token_of_one_tenant_is_not_accepted_by_another`, `Tenant.Links_and_tokens_of_one_tenant_do_not_decrypt_in_another` (reset link, refresh token); with `UseTenantKey` the tenant is a claim of every session and part of every token's Data Protection purpose |
| F2 | Auto-linking with an unverified provider e-mail → `account_conflict` | covered – `ExternalLogin.Unverified_email_of_an_existing_account_is_not_linked` |
| F2b | Auto-registration with an unverified provider e-mail (attacker's IdP account claims the victim's address) → no account, `email_not_verified` | covered – `ReviewRound1.R1_no_account_is_created_for_an_unverified_provider_address`. **Fixed** (review round 1) |
| F2c | A Google account carrying an address Google has not verified (another domain) creates or joins an account → only with Google's own `email_verified` mapped, never by trusting the provider | covered – `ProviderGuide.A_new_account_is_created_only_for_an_address_google_verified`; guide [Google and Entra ID](guides/google-and-entra-id.md) |
| F3 | Same provider key at another provider → no mix-up | covered – conformance (external-login store) |
| F4 | Exchange code reused, parallel, after expiry | covered – `ExternalLogin.The_exchange_code_works_only_once` (both modes), `OpenScenario.F4_*` (8 parallel redemptions, expiry – **fixed** in review round 1: token expiry followed the system clock, not `TimeProvider`) |
| F4b | Intercepted exchange code (deep link, history, malicious app) | covered – `ReviewRound1.C1_bearer_external_login_requires_a_pkce_challenge`, `…C1_the_exchange_code_travels_in_the_fragment_and_is_worthless_without_the_verifier`. **Fixed** (review round 1): the code is bound to a PKCE challenge (S256) and travels in the fragment |
| F5 | Missing or forged `state` / correlation (OAuth CSRF) | design – handled by the ASP.NET Core remote handlers; with `UseSlimErrorRedirects()` it ends at the default page with `external_login_failed`, never at a `returnUrl` from the forged request – `RemoteFailure.An_answer_without_a_valid_state_returns_to_the_default_page_with_external_login_failed` |
| F6 | Several instances without a shared store → replay window | covered – with a shared `ISlimSharedState` the code is single-use across instances (conformance kit: parallel `TryAddAsync`); without one, start-up information `8004` ([several instances](guides/multiple-instances.md)), `DeploymentDiagnostics.In_memory_shared_state_is_reported_in_production` |
| F8 | Answers with tokens or secrets stored by a browser, proxy or CDN cache | covered – `ReviewRound2.Responses_with_secrets_are_never_cached` (`Cache-Control: no-store` on `/auth`; **fixed** in review round 2) |
| F7 | Credentials or codes in logs, referrers, URL history | covered – `ExternalLogin.New_external_user_…`, `ReviewRound1.R6_no_pre_auth_token_in_the_query_after_external_login_with_2fa` (secrets only in the fragment – **fixed** in review round 1), `LogSecrecy.No_secret_or_address_is_ever_logged` |
| F9 | Link CSRF: an attacker's link code planted in the victim's URL links the attacker's provider account | covered – `ExternalLink.An_attackers_link_code_cannot_be_planted_in_the_victims_session` (PKCE verifier of the victim's tab), `…The_link_code_needs_the_verifier_the_session_and_the_password` |
| F10 | Forged, foreign, replayed or stale back-channel logout tokens sign users out | covered – `BackChannelLogout.Forged_or_unfit_tokens_are_rejected` (foreign key, audience, issuer, no event, nonce, no sub, old, expired), `…A_replayed_token_is_rejected`, `…An_unknown_subject_is_acknowledged_without_effect` |
| F11 | Stolen session removes the owner's sign-in methods, or the last one is removed (in parallel) | covered – `SignInMethod.An_external_login_is_removed_with_the_password`, `…The_last_sign_in_method_cannot_be_removed`, `…Parallel_removals_never_remove_both_last_methods`, `…Someone_elses_link_is_not_found` |
| F12 | Replayed back-channel logout token without `jti` | covered – `BackChannelLogout.A_logout_token_without_jti_is_rejected`. **Fixed** (external review round 4) |

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
| G9 | A host endpoint signs a user in with `ISlimAuthManager.SignInAsync` after its own first factor (client certificate): locked, unconfirmed (mailbox not proven), forced password change, 2FA skipped | covered – `ReviewRound3.S2_SignInAsync_refuses_accounts_that_may_not_sign_in`, `…S2_SignInAsync_asks_for_the_second_factor_and_the_built_in_flow_completes_it`. **Fixed** (external review round 3) |
| G10 | Ending an impersonation starts a fresh session chain for the administrator (new `auth_time`, new absolute lifetime) | covered – `ReviewRound4.S4_ending_an_impersonation_keeps_the_administrators_sign_in_time`. **Fixed** (external review round 4) |
| G11 | A forced password change (start password set by an administrator) skipped with a passkey or an external login – the known start password stays valid | covered – `Passkey.A_forced_password_change_is_not_skipped_with_a_passkey`, `ReviewRound4.A_forced_password_change_is_not_skipped_with_an_external_login`; backstop in the session issuance. **Fixed** (after review round 4) |

## H. Stores and infrastructure

| ID | Attack → expected | Status |
| :--- | :--- | :--- |
| H1 | Non-atomic store (refresh, recovery, 2FA step) | covered – `SlimIdentity.Testing` conformance, incl. parallel checks |
| H1b | EF stores and the host share one `DbContext` (host changes saved early or detached) | covered – `SharedContextTests` (EF Core package), template on its own context (`IdentityDb`). **Fixed** (review round 1) |
| H2 | Non-unique / case-sensitive addresses in the templates | covered – conformance of the EF Core stores on SQLite, PostgreSQL and SQL Server and of the Dapper stores on PostgreSQL (service containers in CI; locally via `SLIMIDENTITY_TEST_POSTGRES` / `SLIMIDENTITY_TEST_SQLSERVER`) |
| H3 | SQL injection in the Dapper template | covered – conformance check with quotes, comment characters and LIKE wildcards in addresses (all templates and any host store) |
| H4 | Data Protection key ring lost / changed | design – documented failure modes ([guide](guides/data-protection.md)); TOTP secrets: recovery codes |
| H5 | Misconfiguration: defaults, dev mailer in production, HTTP | covered – options validation at start (unit tests), `NullEmailSenderGuard.*` (**new:** the null sender stops the start in `Production`) |
| H6 | PII, tokens, codes or passwords in logs or metrics | covered – `LogSecrecy.No_secret_or_address_is_ever_logged`, `HostEndpoint.Sign_in_attempts_are_counted_without_personal_data` |
| H7 | Error answers, stack traces or headers revealing internals | covered – `OpenScenario.H7_error_answers_reveal_no_internals` for every error answer SlimIdentity produces; unhandled exceptions (e.g. a failing store) go through the host's exception handler – 500 without details in `Production` |
| H8 | Vulnerable dependencies, supply chain | covered – vulnerability check in CI, actions pinned to commit SHAs, Dependabot, CodeQL, NuGet Trusted Publishing |
| H9 | A host hook weakens the flow (skips a check, issues a session, breaks sign-ins when it fails) | covered – by design hooks can only refuse or observe; `Hook.A_veto_ends_running_sessions_and_refreshes`, `…An_external_sign_in_is_vetoed_as_well`, `…A_failing_event_handler_changes_nothing`, `…Only_allowed_addresses_can_register` |
| H10 | Revoked role still usable in a running session | covered – `ClaimsRefresh.A_cookie_session_loses_a_revoked_role_without_being_signed_out`, `…A_bearer_session_loses_a_revoked_role_at_once_and_its_refresh_issues_the_new_claims` (after `RefreshClaimsAsync`); without it the documented snapshot applies (`…Without_RefreshClaimsAsync_a_session_keeps_its_snapshot`) |
| H11 | Unvalidated profile fields reach the database (mass assignment); half-created accounts (account without profile, orphaned profile rows after a lost race) | covered – `RegistrationProfile.Without_a_profile_hook_a_profile_is_refused`, `…A_valid_profile_reaches_the_store_with_the_account` (only the hook's object); EF Core package `A_registration_profile_is_saved_with_the_account_or_not_at_all`, `…A_profile_without_a_user_factory_is_refused_instead_of_lost` |
| H12 | Unbounded in-memory state (one-time codes, mail counters) – memory growth, a full scan per request | covered – `ReviewRound3.S4_the_in_memory_shared_state_is_bounded_and_stays_fast` (200,000 entries, fail closed). **Fixed** (external review round 3) |
| H13 | Without a session store every refresh is reported as a new sign-in (guards see `SignIn`, observers `signed_in` every 15 minutes) | covered – `ReviewRound4.Q_without_a_session_store_a_refresh_is_not_reported_as_a_new_sign_in`. **Fixed** (external review round 4) |

## Prompt template for one scenario

> You are the attacker. Goal: *&lt;scenario&gt;*. Read *&lt;files&gt;*. Describe a concrete attack with requests. Name the
> line of code that prevents it, or explain why nothing does. Write an xUnit integration test in the style of
> `tests/SlimIdentity.Tests/Integration` that performs the attack and fails if the attack succeeds.

No scenario is open at the moment. New scenarios start as **open** and are closed by a test – never by a comment.
