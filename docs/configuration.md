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

All defaults are the secure choice. The options are listed in three tiers – most applications only need the first.

## 1. What you set

| Option | Default | Description |
| :--- | :--- | :--- |
| `Tokens.JwtSecret` | – | HMAC-SHA256 key, at least 32 bytes. **Setting it enables JWT bearer tokens** (mobile apps, SPAs with tokens, service clients); without it only cookie sessions exist and cookie mode is the default. Keep it out of source control. |
| `Links.BaseUrl` | – | Your front end, e.g. `https://app.example.com`. Mail links then point to `/verify-email`, `/reset-password`, `/accept-invitation` and `/confirm-email-change` (each `?token=…`). Its origin counts as trusted. Without it the raw token is passed to the e-mail sender. |
| `TrustedOrigins` | `[]` | Further front-end origins (e.g. `https://admin.example.com`). Used for the CSRF `Origin` check in cookie mode and as allowed `returnUrl` targets after external login. Configure CORS for the same origins. |
| `TwoFactor.AuthenticatorIssuer` | `SlimIdentity` | Name shown in authenticator apps – set your product name. |

```json
"SlimIdentity": {
  "Links": { "BaseUrl": "https://app.example.com" },
  "TwoFactor": { "AuthenticatorIssuer": "My Product" }
}
```

## 2. Commonly adjusted

| Option | Default | Description |
| :--- | :--- | :--- |
| `Endpoints.EnableRegistration` | `true` | `/register`. Disable for invite-only apps or custom registration. |
| `Endpoints.DefaultUseCookies` | `false` | Mode when the request has no `?useCookies=` (only relevant if both modes are available). |
| `Password.MinimumLength` | `8` | At least 6; 12 or more is recommended without 2FA. |
| `Tokens.AccessTokenLifetime` | `00:15:00` | Access token lifetime. |
| `Tokens.RefreshTokenLifetime` | `7.00:00:00` | Sliding lifetime of each refresh token. |
| `Tokens.RefreshTokenAbsoluteLifetime` | `30.00:00:00` | Maximum length of a refresh chain from the original sign-in. |
| `Cookies.ExpireTimeSpan` | `08:00:00` | Cookie session lifetime. |
| `Cookies.Domain` | – | e.g. `.example.com` for cross-subdomain SPAs. |
| `Cookies.SameSite` | `Strict` | `Lax` for `app.example.com → api.example.com`. |
| `TwoFactor.RememberDeviceLifetime` | `null` (off) | "Remember this device": skip the second factor on a device for this long (max. 90 days). See the [2FA guide](guides/two-factor.md#remember-this-device-optional). |
| `Links.EmailVerificationUrl`, `PasswordResetUrl`, `InvitationUrl`, `EmailChangeUrl` | – | Override single links (must contain `{token}`), e.g. `https://app.example.com/reset?token={token}`. |
| `ExternalLogin.TrustedEmailProviders` | `[]` | Providers whose e-mail counts as verified without `email_verified=true` (e.g. `Google`). |

## 3. Rarely needed

| Option | Default | Description |
| :--- | :--- | :--- |
| `RoutePrefix` | `/auth` | Prefix of all endpoints. |
| `Endpoints.EnableEmailVerification` | `true` | `/verify-email`, `/resend-verification`, verification mail after registration. |
| `Endpoints.EnablePasswordReset` | `true` | `/forgot-password`, `/reset-password`. |
| `Endpoints.EnableChangePassword` | `true` | `/change-password`. Disable for LDAP-only setups. |
| `Endpoints.EnableChangeEmail` | `true` | `/change-email`, `/confirm-email-change`. Disable if the login identifier is managed elsewhere (LDAP, SSO). |
| `Endpoints.AllowCookieAuth` | `true` | Cookie sessions on/off (e.g. off for pure APIs). |
| `Endpoints.ConfigureDefaultAuthenticationScheme` | `true` | Makes the `SlimIdentity` policy scheme the default, so plain `[Authorize]` works. |
| `SignIn.RevealAccountState` | `false` | `false`: inactive/locked accounts answer like a wrong password (401). `true`: `403 account_disabled` / `423` with `lockoutEndUtc`. |
| `Lockout.MaxFailedAttempts` | `5` | Failed attempts per lockout step; `0` disables the lockout (not recommended). |
| `Lockout.Duration` / `MaxDuration` | `00:01:00` / `01:00:00` | First lockout, doubled with every further step up to the maximum. Password and second factor have separate counters with this policy. The password counter is reset by a correct password (sign-in or confirmation in a session: `/change-email`, `/2fa/*`, `ConfirmPasswordAsync`), a password reset by mail, `SetPasswordAsync` and `UnlockAsync`; the second-factor counter by a correct code, `ResetTwoFactorAsync` and `UnlockAsync`. Passkeys, external logins and `SignInAsync` ignore both. |
| `RateLimit.PermitLimit` / `Window` | `10` / `00:01:00` | Policy `SlimIdentity_BruteForce` (login, 2FA, register, reset, invitations, external login, …) per client. |
| `RateLimit.RefreshPermitLimit` | `60` | Policy `SlimIdentity_Refresh` for `/refresh` (same window). |
| `RateLimit.IPv6PrefixLength` | `64` | IPv6 clients are grouped by network prefix (32–128). |
| `Password.MaximumLength` | `256` | Longer passwords are never hashed (DoS protection). |
| `Tokens.PreviousJwtSecrets` | – | Earlier signing secrets still accepted for validation (never for signing) – see [rotating the JWT secret](#rotating-the-jwt-secret). |
| `Tokens.Issuer` / `Audience` | `SlimIdentity` / `SlimIdentityClient` | JWT `iss` / `aud`. |
| `Tokens.ClockSkew` | `00:00:30` | JWT clock tolerance (0–5 min). |
| `Tokens.ValidateSecurityStampOnEachRequest` | `true` | Checks stamp, `IsActive` and server-side session on every bearer request. |
| `Tokens.EmailVerificationTokenLifetime` | `1.00:00:00` | Verification links. |
| `Tokens.PasswordResetTokenLifetime` | `01:00:00` | Reset links (max. 24 h). |
| `Tokens.InvitationTokenLifetime` | `7.00:00:00` | Default validity of invitation links (max. 30 days). |
| `Cookies.CookieName` | `SlimAuth` | Cookie name. |
| `Cookies.SlidingExpiration` | `true` | Renews the cookie while it is used. |
| `Cookies.SecurityStampValidationInterval` | `00:01:00` | How often cookies are re-validated against the store (`0` = every request). |
| `ExternalLogin.AutoLinkVerifiedEmails` | `true` | Links an external login to an existing account with the same **verified** e-mail – only if that account has no password of its own. Accounts with a password link with the [link flow](guides/external-login.md#linking-while-signed-in). |
| `ExternalLogin.AllowAutoRegistration` | `true` | Creates password-less users for unknown external identities. |
| `ExternalLogin.DefaultReturnUrl` | `/` | Redirect target without `returnUrl`. |
| `Email.SendInBackground` | `true` | Verification, reset, "account exists" and lockout mails are queued (uniform response times). Turn off only with an outbox sender. |
| `Email.QueueCapacity` | `1000` | Mails beyond this are dropped and logged. |
| `TwoFactor.AllowEmailCodes` | `true` | 6-digit codes by e-mail as second factor. `false` leaves authenticator apps only (e-mail is the weakest factor); always off with `WithoutEmail()`. |

## Fixed by design

These are deliberately not configurable – changing them would only weaken the protection or break interoperability:

| Behaviour | Value |
| :--- | :--- |
| CSRF protection in cookie mode | always on: header `X-CSRF` (`SlimIdentityDefaults.CsrfHeaderName`) + `Origin` check |
| Refresh-token reuse | always treated as theft (RFC 9700): the session – or without a session store all sessions – is revoked |
| Password composition rules | none (NIST SP 800-63B): length counts; add a breached-password rule with `.AddPasswordRule<T>()` |
| Sign-in flow (`flowToken`, `SlimIdentityDefaults.SignInFlowLifetime`) | 15 minutes from the first factor, single use |
| 2FA setup token | 10 minutes |
| External-login exchange code | 1 minute, single use |
| TOTP | RFC 6238, 30-second steps, ±1 step tolerance |
| Recovery codes | 10 codes of 80 bits each |
| Always mapped | `/login`, `/logout`, `/logout-all`, `/me`, `/password-policy`, `/invitation/*` (invitation links can only be created by the host) |

## Passwords

New passwords are hashed with ASP.NET Core's `PasswordHasher` (PBKDF2-HMAC-SHA512) at **210,000 iterations**
(`SlimIdentityDefaults.PasswordHashIterations`, the OWASP recommendation) instead of the framework's 100,000. That
roughly doubles the CPU time of a sign-in. Existing hashes with fewer iterations are upgraded transparently at the next
successful sign-in. Your own value always wins, whether configured before or after `AddSlimIdentity`:

```csharp
builder.Services.Configure<PasswordHasherOptions>(o => o.IterationCount = 300_000);
```

Additional rules (e.g. a breached-password check) are added with `.AddPasswordRule<T>()` – see
[`samples/templates/Security/PwnedPasswordRule.cs`](../samples/templates/Security/PwnedPasswordRule.cs). If you need
classic composition rules (digit, upper case, …), implement them as such a rule.

Front ends read the active rules from `GET /auth/password-policy`, so hints ("at least 12 characters") and live
validation never drift from the server. Custom rules cannot be evaluated in the browser – the response only reports
`hasAdditionalRules`; their errors come back on submit. A strength meter (e.g. `zxcvbn-ts`) is a front-end concern.

## Rate limiting

The client is identified by IP address. Behind a reverse proxy you need `UseForwardedHeaders()`
([guide](guides/reverse-proxy.md)). A custom key (e.g. a tenant header set by your gateway) can be configured with
`.UseRateLimitPartitionKey(context => …)` on the builder.

## Rotating the JWT secret

Refresh tokens are protected with Data Protection, not with the JWT secret – a new secret only invalidates access
tokens (15 minutes), and clients simply refresh. To avoid even that during a rolling deployment:

1. Set the new `Tokens.JwtSecret` and add the old one to `Tokens.PreviousJwtSecrets`; deploy everywhere.
2. After `Tokens.AccessTokenLifetime`, remove the old secret from `PreviousJwtSecrets`.

If the old secret leaked, do not list it in `PreviousJwtSecrets` – every token signed with it must die at once.

## Builder methods

| Method | Effect |
| :--- | :--- |
| `AddUserStore<T>()` | **Required.** |
| `AddEmailSender<T>()` / `AddNullEmailSender()` | **Required** unless `WithoutEmail()`. The null sender logs links and codes; it stops the start in the `Production` environment unless `AddNullEmailSender(allowInProduction: true)`. |
| `WithoutEmail(allowSelfRegistration = false)` | Host without mail server: no sender, no mail-based endpoints – [guide](guides/without-email.md). |
| `AddEmailContextEnricher<T>()` | Adds host data (tenant, brand) to the `SlimEmailContext` of every mail. |
| `AddBackChannelLogout(provider, o => …)` | OpenID Connect Back-Channel Logout from an enterprise identity provider – [external login](guides/external-login.md#signing-out-at-the-provider). |
| `AddCorsPolicy()` | CORS policy `SlimIdentityDefaults.CorsPolicy` built from the trusted origins (credentials, `X-CSRF`) – `app.UseCors(SlimIdentityDefaults.CorsPolicy)`. |
| `AddOriginPolicy<T>()` | Trusted origins decided per request (tenants with their own domains) – replaces `TrustedOrigins`; [guide](guides/multi-tenancy.md). |
| `AddLinkBuilder<T>()` | Mail, reset and invitation links per request (tenant domains). |
| `AddRefreshTokenStore<T>()` | `/refresh`, refresh tokens in bearer responses. |
| `AddSessionStore<T>()` | Server-side sessions, `/sessions`. |
| `AddTwoFactorStore<T>()` | `/login/2fa`, `/2fa/*`. |
| `AddExternalLoginStore<T>()` | `/login/{provider}`, `/login/external/exchange`. |
| `AddPasskeyStore<T>()` / `AddPasskeys(o => …)` | Package `SlimIdentity.Passkeys`: `/passkeys/*` – [guide](guides/passkeys.md). Options `RelyingPartyId` (default: host of `Links.BaseUrl`; never change it later) and `RelyingPartyName` (default: `TwoFactor.AuthenticatorIssuer`). |
| `AddApiKeyStore<T>()` | `X-API-Key` authentication. |
| `AddConfigurationApiKeys(section)` | `X-API-Key` authentication for a fixed set of clients from configuration (hashes, scopes, roles, expiry) – no database. |
| `AddCustomPasswordValidator<T>()` | LDAP / legacy password check. |
| `AddPasswordRule<T>()` | Additional rule for new passwords (can be called several times). |
| `AddSignInGuard<T>()` / `AddRegistrationGuard<T>()` | Vetoes for sessions and new accounts – [hooks](guides/hooks.md). |
| `AddEventObserver<T>()` | Security events for audit trails and alerts. |
| `AddRegistrationProfile<T>()` | Business data at `/register`, written with the account – [guide](guides/registration-profile.md). |
| `UseRateLimitPartitionKey(Func<HttpContext, string?>)` | Custom rate-limit client key. |
| `UseTenantKey(Func<HttpContext, string?>)` | Binds cookies and access tokens to the request's tenant ([multi-tenancy](guides/multi-tenancy.md#2-sessions-usetenantkey)). |
| `.Authentication` | The `AuthenticationBuilder` – add OAuth/OIDC handlers here. |

All store methods take an optional `ServiceLifetime` (default `Scoped`).

## Observability

Metrics are published on the meter `SlimIdentity` (`SlimIdentityDefaults.MeterName`); logs use the categories
`SlimIdentity.*` with stable event ids. See [Observability](guides/observability.md).
