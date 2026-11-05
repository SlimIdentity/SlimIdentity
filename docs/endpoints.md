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
| `POST /login` ⏱ | `email`, `password`, `rememberMe` | `200` session | `400 invalid_request`; `401 invalid_credentials`; `401 requires_two_factor` (+ `preAuthToken`, `twoFactorMethod`); `403 email_not_confirmed`; with `RevealAccountState`: `403 account_disabled`, `423 locked_out` |
| `POST /login/2fa` ⏱ | `preAuthToken` + `code` or `recoveryCode` | `200` session | `401 invalid_token`, `401 invalid_two_factor_code`, `423 locked_out` |
| `POST /refresh` | `refreshToken` | `200` new token pair | `400 invalid_request`, `401 invalid_token`, `401 session_expired` |
| `POST /logout` | `refreshToken` (optional) | `200 logged_out` | – |
| `POST /logout-all` 🔒 | – | `200 logged_out_everywhere` | `401`, `403 not_allowed_while_impersonating` |

`/login/2fa` uses the mode chosen at `/login`. `/refresh` only exists with `ISlimRefreshTokenStore`; `/login/2fa` only
with `ISlimTwoFactorStore`.

## External login (`ISlimExternalLoginStore`)

| Endpoint | Description |
| :--- | :--- |
| `GET /login/{provider}?returnUrl=…&useCookies=…` ⏱ | Browser navigation (not `fetch`). Redirects to the identity provider. `404 unknown_provider`, `400 invalid_return_url`. |
| `GET /login/{provider}/callback` | Handled internally; redirects to `returnUrl`. |
| `POST /login/external/exchange` ⏱ | Bearer clients: `{ "code" }` from the redirect → token pair. `401 invalid_token`. |

Redirect results on `returnUrl`: cookie mode – cookie set, no parameters; bearer mode – `?code=…`; 2FA required –
`?slim_status=requires_two_factor&preAuthToken=…&method=…`; errors – `?slim_error=` one of `account_conflict`,
`registration_disabled`, `email_required`, `account_disabled`, `account_locked`, `email_not_confirmed`,
`provider_mismatch`, `missing_provider_key`, `two_factor_unavailable`.

## Account

| Endpoint | Body | Success | Errors |
| :--- | :--- | :--- | :--- |
| `POST /register` ⏱ | `email`, `password` | `200 registration_accepted` (always, also for existing addresses) | `400` validation |
| `POST /verify-email` ⏱ | `token` | `200 email_confirmed` | `400 invalid_token` |
| `POST /resend-verification` ⏱ | `email` | `200 verification_sent` (always) | – |
| `POST /forgot-password` ⏱ | `email` | `200 reset_requested` (always) | – |
| `POST /reset-password` ⏱ | `token`, `newPassword` | `200 password_reset` – all sessions end | `400 invalid_token`, `400` validation |
| `POST /change-password` ⏱ 🔒 | `currentPassword`, `newPassword` | `200` new session for this device – others end | `400 invalid_password`, `400` validation, `403 not_allowed_while_impersonating`, `423 locked_out` |
| `GET /me` 🔒 | – | `200` `id`, `email`, `isImpersonating`, `impersonatorId`, `authenticationMethod`, `sudoUntil`, `claims` | `401` |

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
| `GET /2fa` | – | `200` `enabled`, `method`, `hasAuthenticator` | – |
| `POST /2fa/setup` | – | `200` `sharedKey`, `authenticatorUri`, `setupToken` (nothing stored yet) | `403` during impersonation |
| `POST /2fa/enable` ⏱ | `setupToken`, `code` | `200` `recoveryCodes` + refreshed `session` | `400 invalid_token`, `400 invalid_two_factor_code` |
| `POST /2fa/enable-email` ⏱ | `password` | `200` `recoveryCodes` + `session` | `400 invalid_password`, `423` |
| `POST /2fa/disable` ⏱ | `password` | `200` refreshed session | `400 invalid_password`, `423` |
| `POST /2fa/recovery-codes` ⏱ | `password` | `200` new `recoveryCodes` | `400 two_factor_disabled`, `400 invalid_password`, `423` |

Enabling or disabling 2FA rotates the security stamp: all other devices are signed out, the calling device receives a
new session.

🔒 = requires authentication (cookie, bearer or API key via the `SlimIdentity` policy scheme).
