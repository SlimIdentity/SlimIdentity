# SlimIdentity

[![CI](https://github.com/timmkautz/slimidentity/actions/workflows/ci.yml/badge.svg)](https://github.com/timmkautz/slimidentity/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/vpre/SlimIdentity.svg)](https://www.nuget.org/packages/SlimIdentity)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/timmkautz/slimidentity/blob/main/LICENSE)

**Hardened authentication endpoints for ASP.NET Core – without Identity tables, generics or base classes.**

SlimIdentity gives SPAs (Blazor, React, Vue, …) and mobile apps a complete, best-practice login API in a few lines,
while your project keeps full control over its database, ORM and user model. It sits between hand-written login
endpoints (easy to get wrong) and `Microsoft.AspNetCore.Identity` / `MapIdentityApi` (a fixed table schema).

**A facade, not a crypto library.** SlimIdentity implements no cryptography of its own: password hashing, cookies, JWTs,
encryption and rate limiting are the ASP.NET Core building blocks you already trust. What it adds are the *flows* –
the order of checks, uniform answers, single-use tokens, safe behaviour under parallel requests. The data stays in
your database, behind small interfaces you implement; a few of their methods carry security guarantees, so start from
the provided samples and verify your stores with the
[`SlimIdentity.Testing`](https://www.nuget.org/packages/SlimIdentity.Testing) conformance checks
([how it works](https://github.com/timmkautz/slimidentity/blob/main/docs/how-it-works.md)).

> **Status: pre-release.** Working towards 1.0 – the API may still change until then, and the code has not been
> independently audited yet. Please report security issues privately – see
> [SECURITY.md](https://github.com/timmkautz/slimidentity/blob/main/SECURITY.md).

## Features

- **Your database, your user entity** – the `SlimIdentity.EntityFrameworkCore` package stores everything in your
  `DbContext` (verified on SQLite, PostgreSQL and SQL Server); any other database via one interface
  (`ISlimUserStore`, ready-to-copy for Dapper). The core package has no database dependency at all.
- **Cookies or JWT** per request: HttpOnly/Secure/SameSite cookies with CSRF protection, or access + refresh tokens
  with rotation, reuse detection and an absolute session lifetime.
- **Server-side sessions** (optional): real per-device logout, device list, sign out everywhere.
- **Brute-force protection**: per-client rate limiting plus progressive account lockout; uniform answers and timing
  against account enumeration; pluggable password rules (e.g. breached-password check).
- **2FA**: TOTP (authenticator apps), e-mail codes, recovery codes – secrets encrypted at rest, every code usable once.
- **External login**: any ASP.NET Core OAuth/OIDC handler (Google, Microsoft Entra ID, Keycloak, …) with safe account linking.
- **Workflows**: registration, e-mail verification, password reset/change, e-mail change, invitations – stateless,
  single-use links.
- **Admin tooling**: impersonation, step-up "sudo" mode, bans, start passwords with forced change, reset links,
  2FA reset, API keys for machine-to-machine access.
- **With or without mail**: localized mails with full context for your templates – or `WithoutEmail()` for internal
  services where an administrator manages the accounts.
- **Your database stays boring**: it only ever sees hashes and ciphertext – no usable tokens, codes or 2FA secrets.
- **Framework native**: built-in cookie/JWT handlers, `PasswordHasher`, Data Protection and rate limiter;
  `[Authorize]` and policies just work. Full OpenAPI metadata for client generation.
- **Observable**: OpenTelemetry-ready metrics and structured logs with stable event ids – no extra dependency.
- **Native AOT** and trimming compatible; options validated at startup.

**Not an identity provider.** SlimIdentity signs users in to *your* application. It issues no tokens for other
applications and has no consent screens, client registration or discovery document. For single sign-on across several
applications, run an identity provider (Keycloak, Microsoft Entra ID, Duende IdentityServer, OpenIddict, …) and connect
it through [external login](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/external-login.md).

## Quickstart

```bash
dotnet add package SlimIdentity --prerelease
dotnet add package SlimIdentity.EntityFrameworkCore --prerelease   # or bring your own store
```

```csharp
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))
    .AddEntityFrameworkStores<AppDbContext, AppUser, Guid>()   // your DbContext, your user entity
    .AddNullEmailSender();                    // development; production: .AddEmailSender<MyEmailSender>()

var app = builder.Build();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapSlimIdentityApi();   // /auth/register, /auth/login, /auth/me, …
```

```json
{ "SlimIdentity": { "Links": { "BaseUrl": "https://app.example.com" } } }
```

That is a complete cookie-based setup. Add `Tokens.JwtSecret` for bearer tokens, and further capabilities – refresh
tokens, sessions, 2FA, external login – with one line each. Step by step: **[minimal setup](https://github.com/timmkautz/slimidentity/blob/main/docs/minimal-setup.md)**.

Ready-to-copy stores for **Dapper** (and EF Core, if you need full control), mail senders (**MailKit**, **SendGrid**,
outbox), LDAP, admin endpoints and a **TypeScript client** are in [`samples/`](https://github.com/timmkautz/slimidentity/tree/main/samples).

## Try it

```bash
docker compose up --build      # → http://localhost:8080
```

A playground for every flow – cookies and bearer tokens, 2FA with a virtual authenticator, sessions, password reset,
impersonation – with a fake mailbox and a request log. Want to attack it? [`BREAKME.md`](https://github.com/timmkautz/slimidentity/blob/main/BREAKME.md).
Without Docker: `dotnet run --project samples/SlimIdentity.Demo` → <http://localhost:5209> (seeded users
`admin@demo.local` / `Admin123!` and `user@demo.local` / `User1234!`; requests in `SlimIdentity.Demo.http`).

## Packages

| Package | Purpose |
| :--- | :--- |
| `SlimIdentity` | The endpoints, flows and security mechanisms. No database dependency; Native AOT compatible. |
| `SlimIdentity.EntityFrameworkCore` | All stores on your `DbContext` and user entity (EF Core itself is not AOT compatible). |
| `SlimIdentity.Testing` | Conformance checks for your own store implementations – for test projects. |

All packages are released together with the same version.

## Documentation

- [Minimal setup](https://github.com/timmkautz/slimidentity/blob/main/docs/minimal-setup.md) ·
  [Getting started](https://github.com/timmkautz/slimidentity/blob/main/docs/getting-started.md) ·
  [How it works](https://github.com/timmkautz/slimidentity/blob/main/docs/how-it-works.md)
- [Configuration reference](https://github.com/timmkautz/slimidentity/blob/main/docs/configuration.md) ·
  [Endpoint reference](https://github.com/timmkautz/slimidentity/blob/main/docs/endpoints.md) ·
  [Security model](https://github.com/timmkautz/slimidentity/blob/main/docs/security.md)
- Guides: [SPA with cookies](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/spa-cookies.md) ·
  [mobile / bearer](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/mobile-bearer.md) ·
  [sessions](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/sessions-and-logout.md) ·
  [2FA](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/two-factor.md) ·
  [external login](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/external-login.md) ·
  [invitations](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/invitations.md) ·
  [admin features](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/admin-features.md) ·
  [without e-mail](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/without-email.md) ·
  [LDAP](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/ldap-and-legacy-passwords.md) ·
  [client certificates](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/client-certificates.md) ·
  [Data Protection](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/data-protection.md) ·
  [reverse proxy](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/reverse-proxy.md) ·
  [several instances](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/multiple-instances.md) ·
  [observability](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/observability.md) ·
  [Native AOT](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/native-aot.md) ·
  [migrating from ASP.NET Core Identity](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/migrating-from-aspnet-identity.md)
- [Architecture and design principles](https://github.com/timmkautz/slimidentity/blob/main/docs/architecture-manifest.md)

## Roadmap

After 1.0, roughly in this order – nothing here needs a breaking change:

- **Passkeys (1.1)** – WebAuthn as a new capability (`ISlimPasskeyStore`); password-less accounts and a free-form
  `amr` already exist.
- OIDC back-channel logout: an enterprise identity provider ends the local sessions of a user it signs out or blocks.
- Device-bound tokens (DPoP) for bearer clients.
- Adapter for the ASP.NET Core Identity table schema (`AspNetUsers`), turning a migration into a configuration step.
- API-key entity in the EF Core package; npm package of the TypeScript client if there is demand.

## Contributing

Issues and pull requests are welcome – see [CONTRIBUTING.md](https://github.com/timmkautz/slimidentity/blob/main/CONTRIBUTING.md).

## License

[MIT](https://github.com/timmkautz/slimidentity/blob/main/LICENSE) © Timm Kautz
