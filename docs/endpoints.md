# Endpoint reference

All routes are mapped by `app.MapSlimIdentityApi()` under `RoutePrefix` (default `/auth`) and carry OpenAPI
metadata (tag `SlimIdentity`), so typed clients can be generated from `/openapi/v1.json`.

**Conventions**

- JSON bodies, camelCase. Errors are RFC 9457 problem details (`application/problem+json`) with a machine-readable
  `code`: `{ "status": 401, "code": "invalid_credentials", "title": "Unauthorized", "detail": "…" }`. `status` is the
  HTTP status number here, while success answers carry a text `status` (`"success"`, `"sent"`, …). `detail` is an
  English hint for developers, not meant for display – map `code` to your own texts. Validation errors (400) add the
  field errors in `errors` (`code` `validation_failed`), `423 locked_out` adds `lockoutEndUtc` and a `Retry-After`
  header, the rate limiter answers `429 rate_limited` with `Retry-After`, and cookie sessions answer `401 unauthenticated`
  or `403 forbidden` instead of redirecting. All codes are available as constants in `SlimErrorCodes`.
- **Mode:** endpoints that sign in accept `?useCookies=true|false` (default `Endpoints.DefaultUseCookies`).
  Cookie mode answers `{ "status": "success", "mode": "cookie" }` and sets the cookie; bearer mode returns
  `accessToken`, `expiresIn`, `refreshToken` and expiry timestamps. A mode that is switched off answers
  `400 cookie_auth_disabled` (`Endpoints.AllowCookieAuth = false`) or `400 jwt_auth_disabled` (no `Tokens.JwtSecret`).
- **CSRF:** in cookie mode every state-changing request needs the header `X-CSRF` (any value) and, if present, an
  allowed `Origin` – otherwise `403 csrf_validation_failed`.
- **Confirmation of sensitive changes:** where a `password` is asked (2FA, sign-in methods, e-mail change), accounts
  without a password – external login, passkeys – send none; they need a sign-in within the last 5 minutes instead,
  otherwise `403 reauthentication_required` (sign in again, then repeat).
- **Addresses:** plain addresses only – `Name <addr>` or `addr (comment)` are rejected as invalid.
- **Rate limiting:** endpoints marked ⏱ use the `SlimIdentity_BruteForce` policy, `/refresh` uses
  `SlimIdentity_Refresh`; exceeding them returns `429` with `Retry-After`.

## Sign-in

| Endpoint | Body | Success | Errors |
| :--- | :--- | :--- | :--- |
| `POST /login` ⏱ | `email`, `password`, `rememberMe`, `twoFactorRememberToken` (bearer, optional) | `200` session, or `200 action_required` (see below) | `400 invalid_request`; `401 invalid_credentials`; `403 <veto>` of a sign-in guard; with `RevealAccountState`: `403 account_disabled`, `423 locked_out` |
| `POST /login/2fa` ⏱ | `flowToken` + `code` or `recoveryCode`, `rememberDevice` | `200` session (+ `twoFactorRememberToken` in bearer mode / cookie `SlimAuth.2fa` in cookie mode when remembered), or `200 action_required` with the remaining steps | `401 invalid_token`, `401 invalid_two_factor_code`, `423 locked_out` |
| `POST /login/2fa/setup` ⏱ | `flowToken` (step `setup_second_factor`) | `200` `sharedKey`, `authenticatorUri`, `setupToken` – nothing is stored yet | `401 invalid_token`, `423 locked_out` |
| `POST /login/2fa/enable` ⏱ | `flowToken`, `setupToken`, `code` | `200 action_required` `["confirm_recovery_codes"]` with `details.recoveryCodes` (shown once); the authenticator is enabled and every other session ends | `400 invalid_two_factor_code`, `401 invalid_token`, `423 locked_out` |
| `POST /login/2fa/recovery-codes-saved` ⏱ | `flowToken` (step `confirm_recovery_codes`) | `200` session, or `200 action_required` with the remaining steps | `401 invalid_token` |
| `POST /login/verify-email` ⏱ | `flowToken`, `code` (from the mail of kind `verification-code`) | `200` session, or `200 action_required` with the remaining steps; the address is confirmed | `401 invalid_token`, `401 invalid_verification_code`, `429 too_many_attempts` (5 wrong codes per flow, 10 per address in 24 hours) |
| `POST /login/password-change` ⏱ | `flowToken`, `newPassword` | `200` session, or `200 action_required` with the remaining steps | `400 password_unchanged`, `400` validation, `401 invalid_token`, `423 locked_out` |
| `POST /flow?useCookies=…` ⏱ | `flowToken`, or `token` of a registration, reset or invitation link | `flowToken`: `200 action_required` with the open steps of the token – read only, nothing is sent or consumed. `token`: proves the mailbox of a [registration](#registration) and continues it in the mode of this request (the link may open on another device) | `401 invalid_token` (also for a completed, expired or outdated flow, and for an address that has an account by now) |
| `POST /refresh` | `refreshToken` | `200` new token pair | `400 invalid_request`, `401 invalid_token`, `401 session_expired` |
| `POST /logout` | `refreshToken` (optional) | `200 logged_out` – ends the caller's session; a refresh token ends its session only while it is valid (unused, current security stamp) | – |
| `POST /logout-all` 🔒 | – | `200 logged_out_everywhere` | `401`, `403 not_allowed_while_impersonating` |

When the first factor is right but steps follow, the answer is `200` without a session:

```json
{ "status": "action_required", "actions": ["second_factor", "change_password"], "flowToken": "CfDJ8…", "expiresIn": 900,
  "details": { "secondFactor": { "methods": ["totp", "recovery"] } } }
```

`actions` are the open steps in their order; the first one is next. `verify_email` – with mail, every sign-in of an
account with an unconfirmed address – is completed at `/login/verify-email` with the code mailed when the step comes up
(5 code mails per recipient in 15 minutes, shared with second-factor codes; beyond that no code is sent and none is
accepted). `second_factor` is completed at `/login/2fa`
(`methods[0]` is the one asked for; `recovery` alone means no code can be sent – only a recovery code helps),
`change_password` at `/login/password-change` (a password set by an administrator with `mustChange`,
[running without e-mail](guides/without-email.md#the-forced-password-change)), `setup_second_factor` and
`confirm_recovery_codes` at `/login/2fa/setup`, `/login/2fa/enable` and `/login/2fa/recovery-codes-saved` (an
[`ISlimSecondFactorPolicy`](guides/two-factor.md#requiring-a-second-factor) requires a second factor the account
does not have yet; `details.setupSecondFactor.methods` lists `totp` and, with passkeys, `passkey`). Every step answers with the session or
with the remaining steps and a new `flowToken`; a flow lasts 15 minutes from the first factor and completes once. A
[registration](#registration) answers the same way with the steps `verify_email` and `set_credential`. The
same answer comes from `/login/external/exchange`, `/passkeys/login` and
`ISlimAuthManager.SignInAsync`. `/login/verify-email`, `/login/2fa…` and `/login/password-change` use the mode chosen at the start. `/refresh` only exists with `ISlimRefreshTokenStore`; `/login/2fa` only
with `ISlimTwoFactorStore` (as do the three setup steps); `/login/verify-email` not with `WithoutEmail()`.

## External login (`ISlimExternalLoginStore`)

| Endpoint | Description |
| :--- | :--- |
| `GET /login/{provider}?returnUrl=…&useCookies=…&code_challenge=…&code_challenge_method=S256` ⏱ | Browser navigation (not `fetch`). Redirects to the identity provider. Bearer mode requires the PKCE challenge. `404 unknown_provider`, `400 invalid_return_url`, `400 code_challenge_required`, `400 invalid_code_challenge`. |
| `GET /login/{provider}/callback` | Handled internally; redirects to `returnUrl`. |
| `POST /login/external/exchange` ⏱ | Bearer clients: `{ "code", "codeVerifier", "twoFactorRememberToken"? }` – `code` from the redirect's fragment, `codeVerifier` from the PKCE challenge → token pair, or `200 action_required`. `401 invalid_token`, `403 account_disabled`. |
| `POST /link/external` ⏱ 🔒 | Links the identity of a link flow (`GET /login/{provider}?link=true&code_challenge=…`, code in `#slim_link_code=…`) to the signed-in account: `{ "code", "codeVerifier", "password" }` → `200 external_login_linked`. `400 invalid_password`, `401 invalid_token`, `403 email_not_confirmed`, `409 external_login_taken`, `423`. |
| `GET /sign-in-methods` 🔒 | `200` `hasPassword`, `externalLogins` (`provider`, `providerKey`). |
| `POST /sign-in-methods/external/remove` ⏱ 🔒 | `{ "provider", "providerKey", "password" }` (password if the account has one) → `200` with a new session for this client (other sessions end, like on a password change). `400 invalid_password`, `403` during impersonation, `404 external_login_not_found`, `409 last_sign_in_method` / `concurrent_change`, `423`. |
| `POST /backchannel-logout/{provider}` | OpenID Connect Back-Channel Logout (only with `AddBackChannelLogout`): form field `logout_token` from the identity provider → `200`, every session of the user linked to its `sub` ends. `400 invalid_request` (signature, issuer, audience, event, `nonce`, age, replay, no `sub`), `404 unknown_provider`, `503` if the discovery document cannot be loaded. No `X-CSRF` needed. |

Redirect results on `returnUrl`: cookie mode – cookie set, no parameters; bearer mode – `#code=…` (fragment); steps
follow in cookie mode – `#slim_status=action_required&flowToken=…` (`POST /flow` names them); errors – `?slim_error=` one of
`account_conflict`, `email_not_verified`, `registration_disabled`, `email_required`, `account_disabled`, `locked_out`,
`provider_mismatch`, `missing_provider_key`, `code_challenge_required` (bearer mode or link flow without PKCE),
`two_factor_unavailable`, the veto code of a registration or sign-in guard, `sign_in_failed` (no session could be
issued) – and, with `UseSlimErrorRedirects()` on the
handler, `access_denied` (cancelled at the provider) and `external_login_failed` (the provider's answer could not be
matched).

## Account

| Endpoint | Body | Success | Errors |
| :--- | :--- | :--- | :--- |
| `POST /register?useCookies=…` ⏱ | `email`, `rememberMe` | `200 action_required` `["verify_email", "set_credential"]` (always – also for existing and throttled addresses) – see [registration](#registration) | `400` validation (also for a `password` or `profile`: they come with `/register/password`), `403 <veto>` of a registration guard |
| `POST /register/verify` ⏱ | `flowToken`, `code` (from the verification mail) | `200 action_required` `["set_credential"]` | `401 invalid_token`, `401 invalid_verification_code`, `429 too_many_attempts` (5 wrong codes per flow, 10 per address in 24 hours – the link of the mail still works) |
| `POST /register/password` ⏱ | `flowToken`, `password`, `profile` (optional object – [business data](guides/registration-profile.md); refused after a reset) | `200` session – the account is created with its address confirmed; after a [reset](#password-reset) the new password is set and all other sessions end | `400` validation (`profile.<field>` from your profile hook; `profile` if none is registered), `401 invalid_token`, `403 <veto>` of a registration guard (the flow stays open), `409 email_taken` (completed already, or the address got an account meanwhile) |
| `POST /forgot-password` ⏱ | `email` | `200 reset_requested` (always; no link for a pure SSO account) – the link continues at `/flow`, see [password reset](#password-reset) | – |
| `POST /change-password` ⏱ 🔒 | `currentPassword`, `newPassword` | `200` new session for this device – others end | `400 invalid_password`, `400` validation, `403 not_allowed_while_impersonating`, `409 password_not_set`, `423 locked_out` |
| `POST /change-email` ⏱ 🔒 | `newEmail`, `password` | `200 email_change_requested` + `token`, `expiresIn` (always – also for taken addresses); a 6-digit code goes to the new address | `400 email_unchanged`, `400 invalid_password`, `400` validation, `403` during impersonation, `423 locked_out` |
| `POST /change-email/confirm` ⏱ 🔒 | `token`, `code` | `200` session (cookie or tokens) – address changed and confirmed, all other sessions end, old address notified; any session of the account may confirm | `400 invalid_token`, `400 invalid_verification_code` (also for a taken address), `400 email_taken`, `403` during impersonation, `409 concurrent_change`, `429 too_many_attempts` |
| `GET /password-policy` | – | `200` `minimumLength`, `maximumLength`, `hasAdditionalRules` – for hints and live validation in the front end (no composition rules, NIST SP 800-63B) | – |
| `GET /me` 🔒 | – | `200` `id`, `email`, `isImpersonating`, `impersonatorId`, `authenticationMethod`, `sudoUntil`, `claims` | `401` |

With `WithoutEmail()` the mail-based routes are not mapped: `/forgot-password`, `/register/verify`,
`/change-email`, `/change-email/confirm`, `/2fa/enable-email` and – unless `allowSelfRegistration` – `/register`.
`/flow` and `/register/password` (or `/register/passkey`) stay for reset links an administrator hands over. Without mail, `/register` takes `email` (any identifier),
`password` and `profile` and answers `200 registration_accepted`; the address stays unconfirmed.

### Registration

With mail, the mailbox is proven before the account exists, and the account is created with its first way to sign in:

```
POST /register           { "email" }                                → action_required ["verify_email", "set_credential"], flowToken
POST /register/verify    { "flowToken", "code" }                    → action_required ["set_credential"], flowToken
  or POST /flow          { "token" }  (the link of the mail)         → action_required ["set_credential"], flowToken
POST /register/password  { "flowToken", "password", "profile"? }    → session
  or with a passkey (package SlimIdentity.Passkeys):
     POST /register/passkey/options  { "flowToken" }                       → options, state
     POST /register/passkey          { "flowToken", "state", "credential", "name"?, "profile"? } → session
```

`/register` answers every address the same way; the mail decides: a free address gets a 6-digit code and a link
(`Links.EmailVerificationTemplate`, default `/verify-email?token=…`), a taken one the "account exists" mail, and beyond the
mail limit per recipient nothing is sent. Nothing is stored before the last step. The flow lasts 15 minutes – from the
proof of the mailbox on, the link itself is valid for `Tokens.EmailVerificationTokenLifetime`. In cookie mode
`/register/verify` and `/register/password` need `X-CSRF` like every cookie request. A flow token of a registration is
accepted by no sign-in step, and a sign-in flow token by no registration step. `details.setCredential.kinds` lists the
ways the account can start with: `["password"]`, or `["password", "passkey"]` with the passkey package – an account
created with a passkey has no password until it sets one with `/forgot-password`. A host endpoint can replace the first
step with `ISlimAuthManager.BeginRegistrationAsync` (same answer, same rules); the following steps stay mapped,
also with `EnableRegistration = false` (`/register/verify` only while mail is on).

### Password reset

A reset link – mailed by `/forgot-password` or created with `ISlimAuthManager.CreatePasswordResetAsync` – continues as a
flow and ends in the same step `set_credential`:

```
POST /flow               { "token" }                  → action_required [ "verify_email"?, "second_factor"?, "set_credential"], flowToken
POST /register/password  { "flowToken", "password" }  → session; all other sessions of the account end
  or POST /register/passkey/options + /register/passkey (package SlimIdentity.Passkeys) – the passkey replaces the password
```

The steps before `set_credential` follow from the account: a mailed link proves the mailbox, an administrator's link
does not (`verify_email` by mailed code while confirmation is required). An account with a second factor passes
`second_factor` – a mailed code is never offered there, the mailbox being the reset's own proof. If the address was
not confirmed yet, a mailed reset takes the account over instead: second factor, passkeys and external logins are
removed, and no `second_factor` step is asked. `details.setCredential` names the `email` and the `kinds`. The link
works once and only until the security stamp changes; afterwards `/flow` answers `401 invalid_token`. A confirmed pure
SSO account gets `409 external_sign_in_only`; with an `ISlimCustomPasswordValidator` and no passkeys there is nothing
to set (`400 password_managed_externally`). `profile` is refused in this flow.

## Invitations

Links are created by the host with `ISlimAuthManager.CreateInvitationAsync` – see [Invitations](guides/invitations.md).
An invitation link continues as a flow like a [password reset](#password-reset):

```
POST /flow               { "token" }                  → action_required [ "second_factor"?, "set_credential"], flowToken
POST /register/password  { "flowToken", "password" }  → session; the address is confirmed, all other sessions end
  or POST /register/passkey/options + /register/passkey (package SlimIdentity.Passkeys)
```

The link proves the mailbox: an account with a second factor (enabled by the host beforehand) passes `second_factor`,
a mailed code included. `details.setCredential` names the `email`. The link works once, only until the security stamp
changes and only while the account has no password and its address is unchanged; otherwise `/flow` answers
`401 invalid_token`. With an `ISlimCustomPasswordValidator` and no passkeys there is nothing to set
(`400 password_managed_externally`).

## Sessions (`ISlimSessionStore`)

| Endpoint | Success | Errors |
| :--- | :--- | :--- |
| `GET /sessions` 🔒 | `200` list of `id`, `mode`, `authenticationMethod`, `isCurrent`, `isImpersonation`, `createdUtc`, `lastSeenUtc`, `expiresUtc`, `userAgent`, `ipAddress` | `401` |
| `DELETE /sessions/{id}` 🔒 | `200 session_revoked` (revoking the current one also deletes the cookie) | `404 session_not_found`, `403 not_allowed_while_impersonating` |

## Passkeys (package `SlimIdentity.Passkeys`, `ISlimPasskeyStore`)

| Endpoint | Body | Success | Errors |
| :--- | :--- | :--- | :--- |
| `POST /passkeys/register/options` ⏱ 🔒 | `password` (if the account has one) | `200` `options` (creation options, base64url), `state` | `400 invalid_password`, `403 password_required` (account with neither a password nor a passkey), `403 reauthentication_required` (no password and no sign-in within 5 minutes), `403 email_not_confirmed`, `403` during impersonation, `423` |
| `POST /passkeys/register` ⏱ 🔒 | `state`, `credential` (result of `navigator.credentials.create`), `name` | `200` `id`, `name`, `createdUtc`, `backupEligible`, `backedUp` | `400 invalid_passkey`, `409 passkey_exists` |
| `POST /register/passkey/options` ⏱ | `flowToken` (registration, mailbox proven) | `200` `options` (creation options for the new account), `state` | `401 invalid_token`, `403 csrf_validation_failed` |
| `POST /register/passkey` ⏱ | `flowToken`, `state`, `credential`, `name`, `profile` (as for `/register/password`) | `200` session (`amr: passkey`) – the account is created with its address confirmed and the passkey, without a password | `400 invalid_passkey`, `400` profile validation, `401 invalid_token`, `403 <veto>` of a registration guard, `409 passkey_exists` (no account is created), `409 email_taken` |
| `POST /passkeys/login/options` ⏱ | – | `200` `options` (request options), `state` | – |
| `POST /passkeys/login?useCookies=…` ⏱ | `state`, `credential` (result of `navigator.credentials.get`), `rememberMe` | `200` session (`amr: passkey`, no second factor), or `200 action_required` (`verify_email`, `change_password`) | `401 invalid_passkey`, `403 account_disabled`, `403 <veto>` |
| `POST /sign-in-methods/passkeys/rename` 🔒 | `id`, `name` (1–64 characters) | `200 passkey_renamed` | `400 invalid_name`, `404 passkey_not_found` |
| `POST /sign-in-methods/passkeys/remove` ⏱ 🔒 | `id`, `password` (if the account has one) | `200` with a new session for this client (other sessions end) | `400 invalid_password`, `404 passkey_not_found`, `409 last_sign_in_method` / `concurrent_change` |

`GET /sign-in-methods` lists passkeys as `passkeys` (`id`, `name`, `createdUtc`, `lastUsedUtc`, `backupEligible`,
`backedUp`). Details:
[passkeys](guides/passkeys.md).

## Two-factor management (`ISlimTwoFactorStore`) 🔒

| Endpoint | Body | Success | Errors |
| :--- | :--- | :--- | :--- |
| `GET /2fa` | – | `200` `enabled`, `method` (`totp`, `email` or `recovery` – no codes can be sent, set up an authenticator), `hasAuthenticator` | – |
| `POST /2fa/setup` | – | `200` `sharedKey`, `authenticatorUri`, `setupToken` (nothing stored yet) | `403` during impersonation, `403 email_not_confirmed` |
| `POST /2fa/enable` ⏱ | `setupToken`, `code`, `password` | `200` `recoveryCodes` + refreshed `session` | `400 invalid_password`, `400 invalid_token`, `400 invalid_two_factor_code`, `423`, `403 email_not_confirmed` |
| `POST /2fa/enable-email` ⏱ | `password` | `200` `recoveryCodes` + `session` | `400 invalid_password`, `423`, `403 email_not_confirmed` |
| `POST /2fa/disable` ⏱ | `password` | `200` refreshed session | `400 invalid_password`, `423` |
| `POST /2fa/recovery-codes` ⏱ | `password` | `200` new `recoveryCodes` | `400 two_factor_disabled`, `400 invalid_password`, `423` |
| `POST /2fa/forget-device` (anonymous) | – | `200 device_forgotten` – this browser asks for the second factor again | – |
| `POST /2fa/forget-all-devices` | – | `200` renewed session – all remembered devices ask again, all other sessions end | `403` during impersonation |

Enabling or disabling 2FA rotates the security stamp: all other devices are signed out, the calling device receives a
new session. Every TOTP time step and e-mail code is accepted only once (replay protection) – including the code used
for `/2fa/enable`. Every 2FA change needs the current password (accounts without one: a sign-in within the last 5 minutes) – a stolen
session alone cannot install or replace the second factor; a setup token dies with the security stamp (password change, logout-all).

🔒 = requires authentication (cookie or bearer token via the `SlimIdentity.User` policy scheme – API keys are machine-to-machine credentials and are not accepted here).
