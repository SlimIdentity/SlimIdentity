# SlimIdentity

[![CI](https://github.com/timmkautz/slimidentity/actions/workflows/ci.yml/badge.svg)](https://github.com/timmkautz/slimidentity/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/vpre/SlimIdentity.svg)](https://www.nuget.org/packages/SlimIdentity)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/timmkautz/slimidentity/blob/main/LICENSE)

**Hardened authentication endpoints for ASP.NET Core – without Identity tables, generics or base classes.**

SlimIdentity gives SPAs (Blazor, React, Vue, …) and mobile apps a complete, best-practice login API in a few lines,
while your project keeps full control over its database, ORM and user model. It sits between hand-written login
endpoints (easy to get wrong) and `Microsoft.AspNetCore.Identity` / `MapIdentityApi` (a fixed table schema).

> **Status: preview (0.x).** The API may still change and the code has not been independently audited yet.
> Please report security issues privately – see [SECURITY.md](https://github.com/timmkautz/slimidentity/blob/main/SECURITY.md).

## Features

- **Bring your own database** – implement one small interface (`ISlimUserStore`); no EF Core, Dapper or driver dependency.
- **Cookies or JWT** per request (`?useCookies=true`): HttpOnly/Secure/SameSite cookies with CSRF protection, or
  access + refresh tokens with rotation, reuse detection and an absolute session lifetime.
- **Server-side sessions** (optional): real per-device logout, "your devices" list, sign out everywhere.
- **Brute-force protection**: per-IP rate limiting plus progressive account lockout; uniform answers and timing
  against account enumeration.
- **2FA**: TOTP (authenticator apps), e-mail codes, recovery codes.
- **External login**: any ASP.NET Core OAuth/OIDC handler (Google, Microsoft Entra ID, Keycloak, …) with safe account linking.
- **Workflows**: registration, e-mail verification, password reset/change, invitations – stateless, single-use links.
- **Admin tooling**: impersonation (RFC 8693 `act` claim), step-up "sudo" mode, API keys for machine-to-machine access.
- **Framework native**: uses the built-in cookie/JWT handlers, `PasswordHasher`, Data Protection and rate limiter;
  `[Authorize]` and policies just work. Full OpenAPI metadata for client generation.
- **Fail-fast configuration**: options from code and/or `appsettings.json`, validated at startup.

## Quickstart

```bash
dotnet add package SlimIdentity --prerelease
```

```csharp
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"), o =>
    {
        o.Tokens.JwtSecret = builder.Configuration["Jwt:Secret"]!; // >= 32 bytes
    })
    .AddUserStore<MyUserStore>()              // required: your database
    .AddEmailSender<MyEmailSender>()          // required (or .AddNullEmailSender() for development)
    .AddRefreshTokenStore<MyTokenStore>()     // optional → /auth/refresh
    .AddSessionStore<MySessionStore>()        // optional → per-device logout, /auth/sessions
    .AddTwoFactorStore<MyTotpStore>()         // optional → /auth/login/2fa, /auth/2fa/*
    .AddExternalLoginStore<MyOAuthStore>()    // optional → /auth/login/{provider}
    .AddApiKeyStore<MyApiKeyStore>()          // optional → X-API-Key authentication
    .AddCustomPasswordValidator<MyLdap>();    // optional → LDAP / legacy hashes

var app = builder.Build();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapSlimIdentityApi();   // /auth/login, /auth/refresh, /auth/me, …
```

Ready-to-copy store implementations for **EF Core** and **Dapper**, mail senders (**MailKit**, **SendGrid**, outbox),
LDAP, admin endpoints and a **TypeScript client** are in [`samples/`](https://github.com/timmkautz/slimidentity/tree/main/samples).

Try it locally: `dotnet run --project tests/SlimIdentityDemo` and use `SlimIdentityDemo.http`
(admin: `admin@demo.local` / `Admin123!`, OpenAPI at `/openapi/v1.json`).

## Endpoints (prefix `/auth`)

| Route | Method | Available when |
| :--- | :--- | :--- |
| `/login` | POST | always – `?useCookies=true` for cookie mode |
| `/login/2fa` | POST | `ISlimTwoFactorStore` |
| `/login/{provider}` (+ `/callback`) | GET | `ISlimExternalLoginStore` + a remote handler (Google, OIDC, …) |
| `/login/external/exchange` | POST | `ISlimExternalLoginStore` + JWT enabled |
| `/logout` | POST | `Endpoints.EnableLogout` – current session |
| `/logout-all` | POST | `Endpoints.EnableLogout` (authenticated) – all devices |
| `/refresh` | POST | `ISlimRefreshTokenStore` + JWT enabled |
| `/sessions`, `/sessions/{id}` | GET / DELETE | `ISlimSessionStore` (authenticated) |
| `/register` | POST | `Endpoints.EnableRegistration` |
| `/verify-email`, `/resend-verification` | POST | `Endpoints.EnableEmailVerification` |
| `/forgot-password`, `/reset-password` | POST | `Endpoints.EnablePasswordReset` |
| `/invitation/info`, `/invitation/accept` | POST | `Endpoints.EnableInvitations` |
| `/change-password` | POST | `Endpoints.EnableChangePassword` (authenticated) |
| `/me` | GET | `Endpoints.EnableMe` (authenticated) |
| `/2fa`, `/2fa/setup`, `/2fa/enable`, `/2fa/enable-email`, `/2fa/disable`, `/2fa/recovery-codes` | GET / POST | `ISlimTwoFactorStore` (authenticated) |

## Things worth knowing

- **Claims** are identical and short in cookies and JWTs: `sub`, `email`, `role`, `amr`, `auth_time`, `sid`, `act`,
  `sudo_until`, `slim_stamp`. Helpers: `User.GetSlimUserId()`, `GetImpersonatorId()`, `IsInSudoMode()`.
- **Authentication schemes:** the policy scheme `SlimIdentity` (default) forwards to `SlimIdentity.Bearer`,
  `SlimIdentity.ApiKey` or `SlimIdentity.Cookie`. Disable with `Endpoints.ConfigureDefaultAuthenticationScheme = false`.
- **CSRF (cookie mode):** state-changing requests need the header `X-CSRF` (any value); a present `Origin` must be
  the API itself or listed in `Csrf.AllowedOrigins`. Protect your own endpoints with `.RequireSlimCsrf()`.
- **Security stamp:** bearer requests are re-validated on every request, cookies every
  `Cookies.SecurityStampValidationInterval` (default 1 min, `0` = every request). Rotating the stamp ends all sessions.
- **Login answers:** by default wrong password, unknown, inactive and locked accounts all get the same
  `401 invalid_credentials` (and the same hashing time). `SignIn.RevealAccountState = true` returns
  `403 account_disabled` / `423` with `lockoutEndUtc` instead.
- **Progressive lockout:** every `Lockout.MaxFailedAttempts` failures lock the account – 1 min, then 2, 4, 8 … up to
  `Lockout.MaxDuration` (1 h). Only a successful sign-in resets the counter. Optional notification mail on the first
  lockout of a series. With 2FA the counter is reset only after the second factor.
- **Refresh tokens** are Data Protection payloads bound to the security stamp; the store only sees a SHA-256 hash.
  Single use; a reused token is treated as stolen (`Tokens.RevokeSessionsOnRefreshTokenReuse`): with a session store
  that session is revoked, otherwise the stamp rotates (all devices signed out). Sliding lifetime
  `Tokens.RefreshTokenLifetime` (7 days), absolute `Tokens.RefreshTokenAbsoluteLifetime` (30 days from sign-in).
  `/refresh` has its own, generous rate limit (`RateLimit.RefreshPermitLimit`, 60/min).
  Clients must not refresh the same token in parallel (see the TypeScript sample) – the second call would look like a replay.
- **Sessions:** without `ISlimSessionStore` sessions are stateless – `/logout` only deletes the cookie / consumes the
  refresh token, a copied cookie stays valid until it expires, but `/logout-all` still ends everything.
  With a session store every sign-in gets a `sid` that is checked on every validation. Use
  `ISlimAuthManager.SignOutEverywhereAsync(user)` when banning users.
- **Invitations:** create the user without a password (`CreateAsync(email, "")`), call
  `ISlimAuthManager.CreateInvitationAsync(user)` and send the returned link yourself (`Links.InvitationUrl`, default
  validity 7 days). The SPA calls `/invitation/info` and `/invitation/accept`. Single use, survives restarts.
- **External login:** errors redirect to the `returnUrl` with `?slim_error=<code>` (`account_conflict` for an
  unverified e-mail that already has an account). Bearer clients receive `?code=…` and exchange it at
  `/login/external/exchange`; with 2FA they receive `?slim_status=requires_two_factor&preAuthToken=…`.
- **Mails without timing leaks:** verification, reset, "account exists" and lockout mails are sent by a background
  queue (`Email.SendInBackground`, default `true`), so response times do not depend on the mail server. The queue is
  drained on a regular shutdown (`HostOptions.ShutdownTimeout`); only a crash loses mails. For guaranteed delivery
  use an outbox (`samples/Email/OutboxEmailSender.cs`) with `SendInBackground = false`. 2FA codes are sent directly.
- **Impersonation:** the `act` claim contains the admin's id **and security stamp** – banning the admin or rotating
  their stamp ends all impersonation sessions immediately. Return via `ISlimAuthManager.EndImpersonationAsync()`.
- **Data Protection:** persist the key ring (`PersistKeysTo…`) in multi-instance or container deployments, otherwise
  cookies, links and refresh tokens are tied to one instance and lost on restart.

## Running behind a reverse proxy (TLS termination)

The auth cookie always gets the `Secure` flag, so it works even if the proxy talks plain HTTP to the app.
Everything else needs the real values from `X-Forwarded-*`:

| Without `UseForwardedHeaders()` | Effect |
| :--- | :--- |
| `Request.Scheme` is `http` | CSRF origin check fails (`403 csrf_validation_failed` on every cookie POST) |
| OAuth `redirect_uri` is `http://…` | The identity provider rejects the login |
| `UseHttpsRedirection()` | Redirect loop, or `307` for POSTs |
| `RemoteIpAddress` is the proxy | All users share **one** rate-limit bucket |

```csharp
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    o.KnownProxies.Add(IPAddress.Parse("10.0.0.5"));                    // or:
    o.KnownIPNetworks.Add(System.Net.IPNetwork.Parse("10.0.0.0/8"));   // Docker/K8s network of the proxy
});
app.UseForwardedHeaders();   // before UseHttpsRedirection, UseRateLimiter, UseAuthentication
```

- By default only loopback proxies are trusted – in Docker/Kubernetes the headers are otherwise **silently ignored**.
- `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` enables For + Proto but trusts **every** sender – only use it if the app
  is reachable exclusively through the proxy.
- The proxy must pass the `Host` header (nginx: `proxy_set_header Host $host;`) or set `X-Forwarded-Host`.
- Alternative for the CSRF check only: add the public origin to `Csrf.AllowedOrigins`.

## Known limitations

- TOTP and e-mail codes are not protected against replay within their time window (the `preAuthToken` can be reused
  until `Tokens.PreAuthTokenLifetime`); failed codes count towards the lockout.
- `/register` writes a row for new addresses (`CreateAsync`); this single database write can still make the response
  slightly slower than for existing addresses.
- Rate limiting is partitioned by client IP only.
- mTLS client certificates are not built in – see the
  [guide in the architecture document](https://github.com/timmkautz/slimidentity/blob/main/docs/architecture-manifest.md#9-mtls--client-certificates-documented-not-built-in).

## Documentation

- [Architecture & design specification](https://github.com/timmkautz/slimidentity/blob/main/docs/architecture-manifest.md)
- [Samples](https://github.com/timmkautz/slimidentity/tree/main/samples)
- [Security policy](https://github.com/timmkautz/slimidentity/blob/main/SECURITY.md)

## License

[MIT](https://github.com/timmkautz/slimidentity/blob/main/LICENSE) © Timm Kautz
