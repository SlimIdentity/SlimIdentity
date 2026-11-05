# Configuration reference

Options can be set in code, bound from configuration, or both (configuration first, code overrides):

```csharp
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"), o =>
{
    o.Tokens.JwtSecret = builder.Configuration["Jwt:Secret"]!;
});
```

Everything is validated at startup (`ValidateOnStart`); invalid security settings stop the application with a message
naming the option. In JSON, `TimeSpan` values use the `d.hh:mm:ss` format (`"00:15:00"`, `"7.00:00:00"`).

## Root

| Option | Default | Description |
| :--- | :--- | :--- |
| `RoutePrefix` | `/auth` | Prefix of all endpoints. |

## `Endpoints`

| Option | Default | Description |
| :--- | :--- | :--- |
| `EnableRegistration` | `true` | `/register`. Disable for invite-only apps or custom registration. |
| `EnableEmailVerification` | `true` | `/verify-email`, `/resend-verification`, verification mail after registration. |
| `EnablePasswordReset` | `true` | `/forgot-password`, `/reset-password`. |
| `EnableChangePassword` | `true` | `/change-password`. Disable for LDAP-only setups. |
| `EnableChangeEmail` | `true` | `/change-email`, `/confirm-email-change`. Disable if the login identifier is managed elsewhere (LDAP, SSO). |
| `EnableLogout` | `true` | `/logout`, `/logout-all`. |
| `EnableMe` | `true` | `/me`. |
| `EnableInvitations` | `true` | `/invitation/info`, `/invitation/accept`. |
| `EnablePasswordPolicy` | `true` | `GET /password-policy` (anonymous) – exposes the `Password` options to the front end. |
| `AllowCookieAuth` | `true` | Allows cookie sessions. |
| `AllowJwtAuth` | `true` | Allows JWTs (requires `Tokens.JwtSecret`). |
| `DefaultUseCookies` | `false` | Mode when the request has no `?useCookies=`. |
| `ConfigureDefaultAuthenticationScheme` | `true` | Makes the `SlimIdentity` policy scheme the default, so plain `[Authorize]` works. |

## `SignIn`

| Option | Default | Description |
| :--- | :--- | :--- |
| `RequireConfirmedEmail` | `false` | Rejects logins (`403 email_not_confirmed`) until the e-mail is verified. |
| `RevealAccountState` | `false` | `false`: inactive/locked accounts answer like a wrong password (401). `true`: `403 account_disabled` / `423` with `lockoutEndUtc`. |

## `Lockout`

| Option | Default | Description |
| :--- | :--- | :--- |
| `Enabled` | `true` | Account lockout on/off. |
| `MaxFailedAttempts` | `5` | Failed attempts per lockout step. |
| `Duration` | `00:01:00` | First lockout; doubles with every further step. |
| `MaxDuration` | `01:00:00` | Upper bound of the doubling (= `Duration` for a constant lockout). |

The failure counter is only reset by a successful sign-in (with 2FA: after the second factor).

## `RateLimit`

| Option | Default | Description |
| :--- | :--- | :--- |
| `PermitLimit` / `Window` | `10` / `00:01:00` | Policy `SlimIdentity_BruteForce`: login, 2FA, register, reset, invitations, external login, … per client. |
| `RefreshPermitLimit` / `RefreshWindow` | `60` / `00:01:00` | Policy `SlimIdentity_Refresh` for `/refresh`. |
| `IPv6PrefixLength` | `64` | IPv6 clients are grouped by network prefix (32–128). |

The client is identified by IP address. Behind a reverse proxy you need `UseForwardedHeaders()`
([guide](guides/reverse-proxy.md)). A custom key (e.g. a tenant header set by your gateway) can be configured with
`.UseRateLimitPartitionKey(context => …)` on the builder.

## `Password`

| Option | Default | Description |
| :--- | :--- | :--- |
| `MinimumLength` | `8` | At least 6. |
| `MaximumLength` | `256` | Longer passwords are never hashed (DoS protection). |
| `RequireDigit` / `RequireLowercase` / `RequireUppercase` | `true` | Character classes. |
| `RequireNonAlphanumeric` | `false` | Special character. |

Additional rules (e.g. a breached-password check) are added with `.AddPasswordRule<T>()` – see
[`samples/templates/Security/PwnedPasswordRule.cs`](../samples/templates/Security/PwnedPasswordRule.cs).

Front ends read the active rules from `GET /auth/password-policy`, so hints ("at least 16 characters") and live
validation never drift from the server. Custom rules cannot be evaluated in the browser – the response only reports
`hasAdditionalRules`; their errors come back on submit. A strength meter (e.g. `zxcvbn-ts`) is a front-end concern.

Current guidance (NIST SP 800-63B) favours **length over composition**: e.g. `MinimumLength: 12`–`16`, the `Require*`
flags off, plus a breached-password rule.

## `Tokens`

| Option | Default | Description |
| :--- | :--- | :--- |
| `JwtSecret` | – | HMAC-SHA256 key, at least 32 bytes. **Required** when `AllowJwtAuth`. Keep it out of source control. |
| `Issuer` / `Audience` | `SlimIdentity` / `SlimIdentityClient` | JWT `iss` / `aud`. |
| `AccessTokenLifetime` | `00:15:00` | Access token lifetime. |
| `RefreshTokenLifetime` | `7.00:00:00` | Sliding lifetime of each refresh token. |
| `RefreshTokenAbsoluteLifetime` | `30.00:00:00` | Maximum length of a refresh chain from the original sign-in. |
| `RevokeSessionsOnRefreshTokenReuse` | `true` | Treats a reused refresh token as stolen (revokes the session, or all sessions without a session store). |
| `ClockSkew` | `00:00:30` | JWT clock tolerance (0–5 min). |
| `ValidateSecurityStampOnEachRequest` | `true` | Checks stamp, `IsActive` and server-side session on every bearer request. |
| `EmailVerificationTokenLifetime` | `1.00:00:00` | Verification links. |
| `PasswordResetTokenLifetime` | `01:00:00` | Reset links (max. 24 h). |
| `PreAuthTokenLifetime` | `00:05:00` | Time between password and second factor (max. 30 min). |
| `InvitationTokenLifetime` | `7.00:00:00` | Default validity of invitation links (max. 30 days). |

## `Cookies`

`HttpOnly` and `Secure` are always enforced.

| Option | Default | Description |
| :--- | :--- | :--- |
| `CookieName` | `SlimAuth` | Cookie name. |
| `Domain` | – | e.g. `.example.com` for cross-subdomain SPAs. |
| `ExpireTimeSpan` | `08:00:00` | Session lifetime. |
| `SlidingExpiration` | `true` | Renews the cookie while it is used. |
| `SameSite` | `Strict` | `Lax` for `app.example.com → api.example.com`; `None` requires CSRF protection. |
| `SecurityStampValidationInterval` | `00:01:00` | How often cookies are re-validated against the store (`0` = every request). |

## `TwoFactor`

| Option | Default | Description |
| :--- | :--- | :--- |
| `AuthenticatorIssuer` | `SlimIdentity` | Name shown in authenticator apps – set your product name. |
| `RecoveryCodeCount` | `10` | 1–50. |
| `TotpTimeStepTolerance` | `1` | Accepted 30-second steps before/after now (0–3). |
| `SetupTokenLifetime` | `00:10:00` | Time between `/2fa/setup` and `/2fa/enable`. |
| `RememberDeviceLifetime` | `null` (off) | "Remember this device": skip the second factor on a device for this long (max. 90 days). See the [2FA guide](guides/two-factor.md#remember-this-device-optional). |

## `ExternalLogin`

| Option | Default | Description |
| :--- | :--- | :--- |
| `AutoLinkVerifiedEmails` | `true` | Links an external login to an existing account with the same **verified** e-mail. |
| `AllowAutoRegistration` | `true` | Creates password-less users for unknown external identities. |
| `TrustedEmailProviders` | `[]` | Providers whose e-mail counts as verified without `email_verified=true` (e.g. `Google`). |
| `AllowedReturnUrls` | `[]` | Absolute origins allowed as `returnUrl` (local paths are always allowed). |
| `DefaultReturnUrl` | `/` | Redirect target without `returnUrl`. |
| `ExchangeCodeLifetime` | `00:01:00` | One-time code for bearer clients after the redirect (max. 10 min). |

## `Links`

Templates must contain `{token}`. Without a template the raw token is passed to the e-mail sender.

| Option | Example |
| :--- | :--- |
| `EmailVerificationUrl` | `https://app.example.com/verify-email?token={token}` |
| `PasswordResetUrl` | `https://app.example.com/reset-password?token={token}` |
| `InvitationUrl` | `https://app.example.com/accept-invitation?token={token}` |
| `EmailChangeUrl` | `https://app.example.com/confirm-email-change?token={token}` (sent to the new address) |

## `Csrf`

| Option | Default | Description |
| :--- | :--- | :--- |
| `Enabled` | `true` | Requires the header on state-changing cookie requests. |
| `HeaderName` | `X-CSRF` | Any value is accepted; the header itself forces a CORS preflight for cross-origin callers. |
| `AllowedOrigins` | `[]` | Additional allowed `Origin` values besides the API itself. |

## `Email`

| Option | Default | Description |
| :--- | :--- | :--- |
| `SendInBackground` | `true` | Verification, reset, "account exists" and lockout mails are queued (uniform response times). |
| `QueueCapacity` | `1000` | Mails beyond this are dropped and logged. |

## Builder methods

| Method | Effect |
| :--- | :--- |
| `AddUserStore<T>()` | **Required.** |
| `AddEmailSender<T>()` / `AddNullEmailSender()` | **Required** (null sender for development only). |
| `AddRefreshTokenStore<T>()` | `/refresh`, refresh tokens in bearer responses. |
| `AddSessionStore<T>()` | Server-side sessions, `/sessions`. |
| `AddTwoFactorStore<T>()` | `/login/2fa`, `/2fa/*`. |
| `AddExternalLoginStore<T>()` | `/login/{provider}`, `/login/external/exchange`. |
| `AddApiKeyStore<T>()` | `X-API-Key` authentication. |
| `AddCustomPasswordValidator<T>()` | LDAP / legacy password check. |
| `AddPasswordRule<T>()` | Additional rule for new passwords (can be called several times). |
| `UseRateLimitPartitionKey(Func<HttpContext, string?>)` | Custom rate-limit client key. |
| `.Authentication` | The `AuthenticationBuilder` – add OAuth/OIDC handlers here. |

All store methods take an optional `ServiceLifetime` (default `Scoped`).

## Observability

Metrics are published on the meter `SlimIdentity` (`SlimIdentityDefaults.MeterName`); logs use the categories
`SlimIdentity.*` with stable event ids. See [Observability](guides/observability.md).
