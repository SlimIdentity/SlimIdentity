# Endpoint reference

All routes are mapped by `app.MapSlimIdentityApi()` under `RoutePrefix` (default `/auth`) and carry OpenAPI
metadata (tag `SlimIdentity`), so typed clients can be generated from `/openapi/v1.json`.

**Conventions**

- JSON bodies, camelCase. Errors use `{ "status": "<snake_case_code>", "message": "…" }`; validation errors are
  RFC 7807 `ValidationProblem` responses.
- **Mode:** endpoints that sign in accept `?useCookies=true|false` (default `Endpoints.DefaultUseCookies`).
  Cookie mode answers `{ "status": "success", "mode": "cookie" }` and sets the cookie; bearer mode returns
  `accessToken`, `expiresIn`, `refreshToken` and expiry timestamps.
- **CSRF:** in cookie mode every state-changing request needs the header `X-CSRF` (any value) and, if present, an
  allowed `Origin` – otherwise `403 csrf_validation_failed`.
- **Rate limiting:** endpoints marked ⏱ use the `SlimIdentity_BruteForce` policy, `/refresh` uses
  `SlimIdentity_Refresh`; exceeding them returns `429` with `Retry-After`.

## Sign-in

| Endpoint | Body | Success | Errors |
| :--- | :--- | :--- | :--- |
| `POST /login` ⏱ | `email`, `password`, `rememberMe`, `twoFactorRememberToken` (bearer, optional) | `200` session | `400 invalid_request`; `401 invalid_credentials`; `401 requires_two_factor` (+ `preAuthToken`, `twoFactorMethod` `totp`/`email`/`recovery`); `401 password_change_required` (+ `passwordChangeToken`); `403 email_not_confirmed`; `403 <veto>` of a sign-in guard; with `RevealAccountState`: `403 account_disabled`, `423 locked_out` |
| `POST /login/2fa` ⏱ | `preAuthToken` + `code` or `recoveryCode`, `rememberDevice` | `200` session (+ `twoFactorRememberToken` in bearer mode / cookie `SlimAuth.2fa` in cookie mode when remembered) | `401 invalid_token`, `401 invalid_two_factor_code`, `423 locked_out` |
| `POST /login/password-change` ⏱ | `token` (`passwordChangeToken`), `newPassword` | `200` session, or `401 requires_two_factor` | `400 password_unchanged`, `400` validation, `401 invalid_token`, `423 locked_out` |
| `POST /refresh` | `refreshToken` | `200` new token pair | `400 invalid_request`, `401 invalid_token`, `401 session_expired` |
| `POST /logout` | `refreshToken` (optional) | `200 logged_out` – ends the caller's session; a refresh token ends its session only while it is valid (unused, current security stamp) | – |
| `POST /logout-all` 🔒 | – | `200 logged_out_everywhere` | `401`, `403 not_allowed_while_impersonating` |

`/login/2fa` and `/login/password-change` use the mode chosen at `/login`. `password_change_required` follows a password
set by an administrator with `mustChange` ([running without e-mail](guides/without-email.md#the-forced-password-change)).
`twoFactorMethod: recovery` means no code can be sent (e-mail codes switched off) – only a recovery code helps. `/refresh` only exists with `ISlimRefreshTokenStore`; `/login/2fa` only
with `ISlimTwoFactorStore`.

## External login (`ISlimExternalLoginStore`)

| Endpoint | Description |
| :--- | :--- |
| `GET /login/{provider}?returnUrl=…&useCookies=…&code_challenge=…&code_challenge_method=S256` ⏱ | Browser navigation (not `fetch`). Redirects to the identity provider. Bearer mode requires the PKCE challenge. `404 unknown_provider`, `400 invalid_return_url`, `400 code_challenge_required`, `400 invalid_code_challenge`. |
| `GET /login/{provider}/callback` | Handled internally; redirects to `returnUrl`. |
| `POST /login/external/exchange` ⏱ | Bearer clients: `{ "code", "codeVerifier", "twoFactorRememberToken"? }` – `code` from the redirect's fragment, `codeVerifier` from the PKCE challenge → token pair, or `401 requires_two_factor` with `preAuthToken`. `401 invalid_token`. |
| `POST /link/external` ⏱ 🔒 | Links the identity of a link flow (`GET /login/{provider}?link=true&code_challenge=…`, code in `#slim_link_code=…`) to the signed-in account: `{ "code", "codeVerifier", "password" }` → `200 external_login_linked`. `400 invalid_password`, `401 invalid_token`, `403 email_not_confirmed`, `409 external_login_taken`, `423`. |

Redirect results on `returnUrl`: cookie mode – cookie set, no parameters; bearer mode – `#code=…` (fragment); 2FA
required in cookie mode – `#slim_status=requires_two_factor&preAuthToken=…&method=…`; errors – `?slim_error=` one of
`account_conflict`, `email_not_verified`, `registration_disabled`, `email_required`, `account_disabled`, `account_locked`, `email_not_confirmed`,
`provider_mismatch`, `missing_provider_key`, `two_factor_unavailable`.

## Account

| Endpoint | Body | Success | Errors |
| :--- | :--- | :--- | :--- |
| `POST /register` ⏱ | `email`, `password` | `200 registration_accepted` (always, also for existing addresses) | `400` validation, `403 <veto>` of a registration guard |
| `POST /verify-email` ⏱ | `token` | `200 email_confirmed` | `400 invalid_token` |
| `POST /resend-verification` ⏱ | `email` | `200 verification_sent` (always) | – |
| `POST /forgot-password` ⏱ | `email` | `200 reset_requested` (always) | – |
| `POST /reset-password` ⏱ | `token`, `newPassword` | `200 password_reset` – all sessions end | `400 invalid_token`, `400` validation |
| `POST /change-password` ⏱ 🔒 | `currentPassword`, `newPassword` | `200` new session for this device – others end | `400 invalid_password`, `400` validation, `403 not_allowed_while_impersonating`, `423 locked_out` |
| `POST /change-email` ⏱ 🔒 | `newEmail`, `password` | `200 email_change_requested` (always – also for taken addresses); link goes to the new address | `400 email_unchanged`, `400 invalid_password`, `400` validation, `403` during impersonation, `423 locked_out` |
| `POST /confirm-email-change` ⏱ | `token` | `200 email_changed` – address changed, confirmed, all sessions end, old address notified | `400 invalid_token`, `400 email_taken` |
| `GET /password-policy` | – | `200` `minimumLength`, `maximumLength`, `hasAdditionalRules` – for hints and live validation in the front end (no composition rules, NIST SP 800-63B) | – |
| `GET /me` 🔒 | – | `200` `id`, `email`, `isImpersonating`, `impersonatorId`, `authenticationMethod`, `sudoUntil`, `claims` | `401` |

With `WithoutEmail()` the mail-based routes are not mapped: `/forgot-password`, `/verify-email`, `/resend-verification`,
`/change-email`, `/confirm-email-change`, `/2fa/enable-email` and – unless `allowSelfRegistration` – `/register`.
`/reset-password` stays for links an administrator hands over.

## Invitations

| Endpoint | Body | Success | Errors |
| :--- | :--- | :--- | :--- |
| `POST /invitation/info` ⏱ | `token` | `200` `email`, `expiresAt` | `400 invalid_token` |
| `POST /invitation/accept` ⏱ | `token`, `password` | `200` session (or `200 invitation_accepted` for users with 2FA) | `400 invalid_token`, `400 password_managed_externally`, `400` validation |

Links are created by the host with `ISlimAuthManager.CreateInvitationAsync` – see [Invitations](guides/invitations.md).

## Sessions (`ISlimSessionStore`)

| Endpoint | Success | Errors |
| :--- | :--- | :--- |
| `GET /sessions` 🔒 | `200` list of `id`, `mode`, `authenticationMethod`, `isCurrent`, `isImpersonation`, `createdUtc`, `lastSeenUtc`, `expiresUtc`, `userAgent`, `ipAddress` | `401` |
| `DELETE /sessions/{id}` 🔒 | `200 session_revoked` (revoking the current one also deletes the cookie) | `404 session_not_found`, `403 not_allowed_while_impersonating` |

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
for `/2fa/enable`. Every 2FA change needs the current password – a stolen session alone cannot install or replace the
second factor; a setup token dies with the security stamp (password change, logout-all).

🔒 = requires authentication (cookie or bearer token via the `SlimIdentity.User` policy scheme – API keys are machine-to-machine credentials and are not accepted here).
