# Endpoint reference

`app.MapSlimIdentityApi()` maps all routes under `RoutePrefix` (default `/auth`) with OpenAPI metadata (tag
`SlimIdentity`). ⏱ = rate limited, 🔒 = requires a cookie or bearer session (policy scheme `SlimIdentity.User`; API
keys are not accepted).

## Conventions

- JSON bodies, camelCase. Errors are RFC 9457 problem details (`application/problem+json`) with a machine-readable
  `code`: `{ "status": 401, "code": "invalid_credentials", "title": "Unauthorized", "detail": "…" }`. Success answers
  carry a text `status` (`"success"`, `"sent"`, …). `detail` is an English developer hint – map `code` to your texts.
  All codes are constants in `SlimErrorCodes`.
- `400 validation_failed` adds field errors in `errors`; `423 locked_out` adds `lockoutEndUtc` and `Retry-After`;
  `429 rate_limited` adds `Retry-After`. Cookie sessions answer `401 unauthenticated` / `403 forbidden` instead of
  redirecting.
- **Mode:** endpoints that sign in accept `?useCookies=true|false` (default `Endpoints.DefaultUseCookies`). Cookie mode
  answers `{ "status": "success", "mode": "cookie" }` and sets the cookie; bearer mode returns `accessToken`,
  `expiresIn`, `refreshToken` and expiry timestamps. A disabled mode answers `400 cookie_auth_disabled`
  (`Endpoints.AllowCookieAuth = false`) or `400 jwt_auth_disabled` (no `Tokens.JwtSecret`).
- **CSRF:** cookie-mode state-changing requests need the header `X-CSRF` (any value) and, if sent, an allowed `Origin`
  – otherwise `403 csrf_validation_failed`.
- **Confirming sensitive changes:** where a `password` is asked, accounts without one (external login, passkeys only)
  send none and need a sign-in within the last 5 minutes, otherwise `403 reauthentication_required`.
- **Addresses:** plain addresses only – `Name <addr>` or `addr (comment)` are invalid.
- **Rate limiting:** ⏱ uses the policy `SlimIdentity_BruteForce`, `/refresh` uses `SlimIdentity_Refresh`.

## Sign-in

| Endpoint | Body | Success | Errors |
| :--- | :--- | :--- | :--- |
| `POST /login` ⏱ | `email`, `password`, `rememberMe`, `twoFactorRememberToken` (bearer, optional) | session, or `action_required` | `400 invalid_request`; `401 invalid_credentials`; `403 <veto>` of a sign-in guard; with `RevealAccountState`: `403 account_disabled`, `423 locked_out` |
| `POST /login/verify-email` ⏱ | `flowToken`, `code` (mail kind `verification-code`) | session or remaining steps; address confirmed | `401 invalid_token`, `401 invalid_verification_code`, `429 too_many_attempts` (5 wrong codes per flow, 10 per address in 24 h) |
| `POST /login/2fa` ⏱ | `flowToken` + `code` or `recoveryCode`, `rememberDevice` | session (+ `twoFactorRememberToken` in bearer mode / cookie `SlimAuth.2fa` when remembered) or remaining steps | `401 invalid_token`, `401 invalid_two_factor_code`, `423 locked_out` |
| `POST /login/2fa/setup` ⏱ | `flowToken` (step `setup_second_factor`) | `sharedKey`, `authenticatorUri`, `setupToken` – nothing stored yet | `401 invalid_token`, `423` |
| `POST /login/2fa/enable` ⏱ | `flowToken`, `setupToken`, `code` | `action_required` `["confirm_recovery_codes"]` with `details.recoveryCodes` (shown once); authenticator enabled, every other session ends | `400 invalid_two_factor_code`, `401 invalid_token`, `423` |
| `POST /login/2fa/recovery-codes-saved` ⏱ | `flowToken` (step `confirm_recovery_codes`) | session or remaining steps | `401 invalid_token` |
| `POST /login/password-change` ⏱ | `flowToken`, `newPassword` | session or remaining steps | `400 password_unchanged`, `400` validation, `401 invalid_token`, `423` |
| `POST /flow?useCookies=…` ⏱ | `flowToken`, or `token` of a registration, reset or invitation link | `flowToken`: the open steps (read only, nothing sent or consumed). `token`: continues the [registration](#registration), [reset](#password-reset) or [invitation](#invitations) in the mode of this request (the link may open on another device) | `401 invalid_token` (also for a completed, expired or outdated flow, or an address that has an account by now) |
| `POST /refresh` | `refreshToken` | new token pair | `400 invalid_request`, `401 invalid_token`, `401 session_expired` |
| `POST /logout` | `refreshToken` (optional) | `logged_out` – ends the caller's session; a refresh token ends its session only while valid | – |
| `POST /logout-all` 🔒 | – | `logged_out_everywhere` | `401`, `403 not_allowed_while_impersonating` |

When the first factor is right but steps follow, the answer is `200` without a session:

```json
{ "status": "action_required", "actions": ["second_factor", "change_password"], "flowToken": "CfDJ8…", "expiresIn": 900,
  "details": { "secondFactor": { "methods": ["totp", "recovery"] } } }
```

`actions` lists the open steps in order; the first is next. Each step answers with the session or the remaining steps
and a new `flowToken`; a flow lasts 15 minutes from the first factor, completes once and keeps the mode chosen at its
start. `/login/external/exchange`, `/passkeys/login` and `ISlimAuthManager.SignInAsync` answer the same way.

| Step | When | Completed at |
| :--- | :--- | :--- |
| `verify_email` | with mail, every sign-in of an account with an unconfirmed address; the code is mailed when the step comes up (5 code mails per recipient in 15 minutes, shared with second-factor codes) | `/login/verify-email` |
| `second_factor` | 2FA enabled; `methods[0]` is the one asked for, `recovery` alone means no code can be sent | `/login/2fa` |
| `change_password` | a password set by an administrator with `mustChange` ([without e-mail](guides/without-email.md#the-forced-password-change)) | `/login/password-change` |
| `setup_second_factor`, `confirm_recovery_codes` | an [`ISlimSecondFactorPolicy`](guides/two-factor.md#requiring-a-second-factor) requires a factor the account lacks; `details.setupSecondFactor.methods` lists `totp` (and `passkey` with passkeys) | `/login/2fa/setup`, `/login/2fa/enable`, `/login/2fa/recovery-codes-saved` |
| `set_credential` | registration, password reset, invitation | `/register/password` or `/register/passkey` |

`/refresh` exists only with `ISlimRefreshTokenStore` and a `JwtSecret`; the `/login/2fa…` routes only with
`ISlimTwoFactorStore`; `/login/verify-email` not with `WithoutEmail()`.

## External login (`ISlimExternalLoginStore`)

| Endpoint | Description |
| :--- | :--- |
| `GET /login/{provider}?returnUrl=…&useCookies=…&code_challenge=…&code_challenge_method=S256` ⏱ | Browser navigation (not `fetch`) to the identity provider. Bearer mode requires PKCE. `404 unknown_provider`, `400 invalid_return_url`, `400 code_challenge_required`, `400 invalid_code_challenge`. |
| `GET /login/{provider}/callback` | Handled internally; redirects to `returnUrl`. |
| `POST /login/external/exchange` ⏱ | Bearer clients (only with `JwtSecret`): `{ "code", "codeVerifier", "twoFactorRememberToken"? }` → token pair or `action_required`. `401 invalid_token`, `403 account_disabled`. |
| `POST /link/external` ⏱ 🔒 | Links the identity of a link flow (`GET /login/{provider}?link=true&code_challenge=…`, code in `#slim_link_code=…`): `{ "code", "codeVerifier", "password" }` → `external_login_linked`. `400 invalid_password`, `401 invalid_token`, `403 email_not_confirmed`, `409 external_login_taken`, `423`. |
| `GET /sign-in-methods` 🔒 | `hasPassword`, `externalLogins` (`provider`, `providerKey`), `passkeys` with the passkey package. Always mapped. |
| `POST /sign-in-methods/external/remove` ⏱ 🔒 | `{ "provider", "providerKey", "password" }` → new session for this client, other sessions end. `400 invalid_password`, `403` during impersonation, `404 external_login_not_found`, `409 last_sign_in_method` / `concurrent_change`, `423`. |
| `POST /backchannel-logout/{provider}` | OIDC Back-Channel Logout (only with `AddBackChannelLogout`): form field `logout_token` → `200`, every session of the user linked to its `sub` ends. `400 invalid_request`, `404 unknown_provider`, `503` if discovery fails. No `X-CSRF`. |

Redirect results on `returnUrl`: cookie mode – cookie set, no parameters; bearer mode – `#code=…`; steps follow in
cookie mode – `#slim_status=action_required&flowToken=…` (`POST /flow` names them); errors – `?slim_error=` one of
`account_conflict`, `email_not_verified`, `registration_disabled`, `email_required`, `account_disabled`, `locked_out`,
`provider_mismatch`, `missing_provider_key`, `code_challenge_required`, `two_factor_unavailable`, the veto code of a
guard, `sign_in_failed`, and with `UseSlimErrorRedirects()` on the handler `access_denied` and
`external_login_failed`.

## Account

| Endpoint | Body | Success | Errors |
| :--- | :--- | :--- | :--- |
| `POST /register?useCookies=…` ⏱ | `email`, `rememberMe` | `action_required` `["verify_email", "set_credential"]` – always, also for taken or throttled addresses | `400` validation (also for `password` or `profile` – they belong to `/register/password`), `403 <veto>` of a registration guard |
| `POST /register/verify` ⏱ | `flowToken`, `code` | `action_required` `["set_credential"]` | `401 invalid_token`, `401 invalid_verification_code`, `429 too_many_attempts` (5 per flow, 10 per address in 24 h – the link still works) |
| `POST /register/password` ⏱ | `flowToken`, `password`, `profile` (optional, [business data](guides/registration-profile.md); refused after a reset or invitation) | session – account created with confirmed address; after a reset or invitation the password is set and all other sessions end | `400` validation (`profile.<field>`; `profile` if no profile hook is registered), `401 invalid_token`, `403 <veto>` (the flow stays open), `409 email_taken` |
| `POST /forgot-password` ⏱ | `email` | `reset_requested` – always; no link for a pure SSO account | – |
| `POST /change-password` ⏱ 🔒 | `currentPassword`, `newPassword` | new session for this device, others end | `400 invalid_password`, `400` validation, `403 not_allowed_while_impersonating`, `409 password_not_set`, `423` |
| `POST /change-email` ⏱ 🔒 | `newEmail`, `password` | `email_change_requested` + `token`, `expiresIn` – always, also for taken addresses; a 6-digit code goes to the new address | `400 email_unchanged`, `400 invalid_password`, `400` validation, `403` during impersonation, `423` |
| `POST /change-email/confirm` ⏱ 🔒 | `token`, `code` | session – address changed and confirmed, other sessions end, old address notified; any session of the account may confirm | `400 invalid_token`, `400 invalid_verification_code` (also for a taken address), `400 email_taken`, `403` during impersonation, `409 concurrent_change`, `429 too_many_attempts` |
| `GET /password-policy` | – | `minimumLength`, `maximumLength`, `hasAdditionalRules` | – |
| `GET /me` 🔒 | – | `id`, `email`, `isImpersonating`, `impersonatorId`, `authenticationMethod`, `sudoUntil`, `claims` | `401` |

Switches: `/register` needs `Endpoints.EnableRegistration`, `/forgot-password` `EnablePasswordReset`, `/change-password`
`EnableChangePassword`, `/change-email…` `EnableChangeEmail`. `/flow`, `/register/password` and `/register/verify` stay
mapped with `EnableRegistration = false` (for host-started flows).

With `WithoutEmail()` these routes are not mapped: `/forgot-password`, `/register/verify`, `/login/verify-email`,
`/change-email`, `/change-email/confirm`, `/2fa/enable-email` and – unless `allowSelfRegistration` – `/register`. Then
`/register` takes `email` (any identifier), `password` and `profile` and answers `200 registration_accepted`; the
address stays unconfirmed. `/flow` and `/register/password` stay for reset links handed over by an administrator.

### Registration

The mailbox is proven before the account exists; the account is created with its first way to sign in:
`POST /register { email }` → `/register/verify { flowToken, code }` (or the mailed link's `token` at `/flow`) →
`/register/password { flowToken, password, profile? }` or `/register/passkey/options` + `/register/passkey` → session.

`/register` answers every address alike; the mail differs: a free address gets a 6-digit code and a link
(`Links.EmailVerificationUrl`, default `/verify-email?token=…`), a taken one the "account exists" mail, beyond the
per-recipient mail limit nothing is sent. Nothing is stored before the last step. The flow lasts 15 minutes from the
proof of the mailbox; the link itself is valid for `Tokens.EmailVerificationTokenLifetime`. Registration and sign-in
flow tokens are not interchangeable. `details.setCredential.kinds` is `["password"]` or `["password", "passkey"]`; an
account created with a passkey has no password until it uses `/forgot-password`. A host endpoint can replace the first
step with `ISlimAuthManager.BeginRegistrationAsync` (same answer and rules).

### Password reset

A reset link – mailed by `/forgot-password` or created with `ISlimAuthManager.CreatePasswordResetAsync` – continues as
a flow: `POST /flow { token }` → `["verify_email"?, "second_factor"?, "set_credential"]` → `/register/password` or
`/register/passkey` (the passkey replaces the password) → session; all other sessions end.

A mailed link proves the mailbox; an administrator's link does not (`verify_email` by code while confirmation is
required). An account with a second factor passes `second_factor` without the mailed-code option. If the address was
not confirmed yet, a mailed reset takes the account over: second factor, passkeys and external logins are removed and
no `second_factor` is asked. `details.setCredential` names `email` and `kinds`. The link works once and only until the
security stamp changes. A confirmed pure SSO account gets `409 external_sign_in_only`; with an
`ISlimCustomPasswordValidator` and no passkeys there is nothing to set (`400 password_managed_externally`).

### Invitations

Links are created with `ISlimAuthManager.CreateInvitationAsync` ([guide](guides/invitations.md)) and continue like a
reset: `POST /flow { token }` → `["second_factor"?, "set_credential"]` → `/register/password` or `/register/passkey`;
the address is confirmed and all other sessions end. The link proves the mailbox (a mailed second-factor code is
allowed). It works once, only until the security stamp changes and only while the account has no password and the
same address; otherwise `401 invalid_token`. With an `ISlimCustomPasswordValidator` and no passkeys:
`400 password_managed_externally`.

## Sessions (`ISlimSessionStore`)

| Endpoint | Success | Errors |
| :--- | :--- | :--- |
| `GET /sessions` 🔒 | list of `id`, `mode`, `authenticationMethod`, `isCurrent`, `isImpersonation`, `createdUtc`, `lastSeenUtc`, `expiresUtc`, `userAgent`, `ipAddress` | `401` |
| `DELETE /sessions/{id}` 🔒 | `session_revoked` (the current one also deletes the cookie) | `404 session_not_found`, `403 not_allowed_while_impersonating` |

## Passkeys (package `SlimIdentity.Passkeys`)

| Endpoint | Body | Success | Errors |
| :--- | :--- | :--- | :--- |
| `POST /passkeys/register/options` ⏱ 🔒 | `password` (if the account has one) | `options` (base64url), `state` | `400 invalid_password`, `403 password_required` (neither password nor passkey), `403 reauthentication_required`, `403 email_not_confirmed`, `403` during impersonation, `423` |
| `POST /passkeys/register` ⏱ 🔒 | `state`, `credential` (`navigator.credentials.create`), `name` | `id`, `name`, `createdUtc`, `backupEligible`, `backedUp` | `400 invalid_passkey`, `409 passkey_exists` |
| `POST /register/passkey/options` ⏱ | `flowToken` (step `set_credential`) | `options`, `state` | `401 invalid_token`, `403 csrf_validation_failed` |
| `POST /register/passkey` ⏱ | `flowToken`, `state`, `credential`, `name`, `profile` | session (`amr: passkey`) – account created with confirmed address and passkey, without password | `400 invalid_passkey`, `400` profile validation, `401 invalid_token`, `403 <veto>`, `409 passkey_exists` (no account created), `409 email_taken` |
| `POST /passkeys/login/options` ⏱ | – | `options`, `state` | – |
| `POST /passkeys/login?useCookies=…` ⏱ | `state`, `credential` (`navigator.credentials.get`), `rememberMe` | session (`amr: passkey`, no second factor) or `action_required` (`verify_email`, `change_password`) | `401 invalid_passkey`, `403 account_disabled`, `403 <veto>` |
| `POST /sign-in-methods/passkeys/rename` 🔒 | `id`, `name` (1–64 characters) | `passkey_renamed` | `400 invalid_name`, `404 passkey_not_found` |
| `POST /sign-in-methods/passkeys/remove` ⏱ 🔒 | `id`, `password` (if any) | new session for this client, other sessions end | `400 invalid_password`, `404 passkey_not_found`, `409 last_sign_in_method` / `concurrent_change` |

`GET /sign-in-methods` lists `passkeys` (`id`, `name`, `createdUtc`, `lastUsedUtc`, `backupEligible`, `backedUp`).
Guide: [passkeys](guides/passkeys.md).

## Two-factor management (`ISlimTwoFactorStore`) 🔒

| Endpoint | Body | Success | Errors |
| :--- | :--- | :--- | :--- |
| `GET /2fa` | – | `enabled`, `method` (`totp`, `email`, or `recovery` = no codes can be sent), `hasAuthenticator` | – |
| `POST /2fa/setup` | – | `sharedKey`, `authenticatorUri`, `setupToken` (nothing stored yet) | `403` during impersonation, `403 email_not_confirmed` |
| `POST /2fa/enable` ⏱ | `setupToken`, `code`, `password` | `recoveryCodes` + refreshed `session` | `400 invalid_password`, `400 invalid_token`, `400 invalid_two_factor_code`, `403 email_not_confirmed`, `423` |
| `POST /2fa/enable-email` ⏱ | `password` | `recoveryCodes` + `session` | `400 invalid_password`, `403 email_not_confirmed`, `423` |
| `POST /2fa/disable` ⏱ | `password` | refreshed session | `400 invalid_password`, `423` |
| `POST /2fa/recovery-codes` ⏱ | `password` | new `recoveryCodes` | `400 two_factor_disabled`, `400 invalid_password`, `423` |
| `POST /2fa/forget-device` (anonymous) | – | `device_forgotten` – this browser asks again | – |
| `POST /2fa/forget-all-devices` | – | renewed session – all remembered devices ask again, other sessions end | `403` during impersonation |

Enabling or disabling 2FA rotates the security stamp: other devices are signed out, the caller gets a new session.
Every TOTP time step and e-mail code is accepted once (also the one used for `/2fa/enable`). Every change needs the
current password (or a recent sign-in), so a stolen session alone cannot replace the second factor; a setup token dies
with the security stamp.
