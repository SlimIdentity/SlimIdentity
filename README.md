# SlimIdentity

[![CI](https://github.com/SlimIdentity/SlimIdentity/actions/workflows/ci.yml/badge.svg)](https://github.com/SlimIdentity/SlimIdentity/actions/workflows/ci.yml)
[![NuGet](https://img.shields.io/nuget/vpre/SlimIdentity.svg)](https://www.nuget.org/packages/SlimIdentity)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/SlimIdentity/SlimIdentity/blob/main/LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/SlimIdentity/SlimIdentity/badge)](https://scorecard.dev/viewer/?uri=github.com/SlimIdentity/SlimIdentity)

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
([how it works](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/how-it-works.md)).

> **Status: 0.9 – feature-complete preview.** The API may still change until 1.0, and the code has not been
> independently audited yet; 1.0 follows the audit and feedback from first production use. Please report security issues privately – see
> [SECURITY.md](https://github.com/SlimIdentity/SlimIdentity/blob/main/SECURITY.md).

## In the box – the five-minute setup

What `AddSlimIdentity()` + `MapSlimIdentityApi()` give you, with the EF Core package or one store of your own:

- **Your database, your user entity** – the `SlimIdentity.EntityFrameworkCore` package stores everything in your
  `DbContext` (verified on SQLite, PostgreSQL and SQL Server); any other database via one interface
  (`ISlimUserStore`, ready-to-copy for Dapper). The core package has no database dependency at all.
- **Cookies or JWT** per request: HttpOnly/Secure/SameSite cookies with CSRF protection, or access + refresh tokens
  with rotation, reuse detection and an absolute session lifetime.
- **Server-side sessions**: real per-device logout, device list, sign out everywhere (EF Core package: included; own
  stores: `ISlimSessionStore`).
- **The account flows**: registration, e-mail verification, password reset and change, e-mail change – one
  step-by-step sign-in flow with single-use codes and links, no state in the database.
- **Brute-force protection**: per-client rate limiting plus progressive account lockout; uniform answers and timing
  against account enumeration; pluggable password rules (e.g. breached-password check).
- **2FA**: TOTP (authenticator apps), e-mail codes, recovery codes – secrets encrypted at rest, every code usable once.
- **Your database stays boring**: it only ever sees hashes and ciphertext – no usable tokens, codes or 2FA secrets.
- **Framework native**: built-in cookie/JWT handlers, `PasswordHasher`, Data Protection and rate limiter;
  `[Authorize]` and policies just work. Full OpenAPI metadata, a TypeScript client to copy.
- **Observable and lean**: OpenTelemetry-ready metrics, structured logs with stable event ids, Native AOT, options
  validated at startup.

## Switch on when you need it

Each one is a line of configuration – nothing of it runs, or has to be understood, before you add it:

| Capability | Add | Guide |
| :--- | :--- | :--- |
| Sign-in with Google, Entra ID, Keycloak, … | an OAuth/OIDC handler on `.Authentication` | [external login](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/guides/external-login.md), [Google and Entra ID step by step](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/guides/google-and-entra-id.md) |
| Passkeys (Face ID, fingerprint, device PIN) | package `SlimIdentity.Passkeys` | [passkeys](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/guides/passkeys.md) |
| Business data at registration | `.AddRegistrationProfile<T>()` | [registration with business data](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/guides/registration-profile.md) |
| Invitations, start passwords, reset links, impersonation, sudo mode | `ISlimAuthManager` in your admin endpoints | [admin features](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/guides/admin-features.md) |
| Internal services without a mail server | `.WithoutEmail()` | [without e-mail](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/guides/without-email.md) |
| Tenants with their own domains | `.AddOriginPolicy<T>()`, `.AddLinkBuilder<T>()`, `.AddCorsPolicy()` | [multi-tenancy](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/guides/multi-tenancy.md) |
| Vetoes and an audit trail (tenants, IP allow-lists, company domains) | `.AddSignInGuard<T>()`, `.AddEventObserver<T>()` | [hooks](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/guides/hooks.md) |
| Sessions ended by the company's identity provider | `.AddBackChannelLogout(…)` | [external login](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/guides/external-login.md) |
| API keys for machine-to-machine calls | `.AddApiKeyStore<T>()` | [admin features](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/guides/admin-features.md) |
| LDAP / Active Directory, legacy password hashes | `.AddCustomPasswordValidator<T>()` | [LDAP](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/guides/ldap-and-legacy-passwords.md) |
| Smart cards and client certificates | a template to copy | [client certificates](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/guides/client-certificates.md) |

Hooks can only tighten the flow: a guard can refuse, an observer can only watch – none of them can skip a check.

**Not an identity provider.** SlimIdentity signs users in to *your* application. It issues no tokens for other
applications and has no consent screens, client registration or discovery document. For single sign-on across several
applications, run an identity provider (Keycloak, Microsoft Entra ID, Duende IdentityServer, OpenIddict, …) and connect
it through [external login](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/guides/external-login.md).

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
tokens, sessions, 2FA, external login – with one line each. Step by step: **[minimal setup](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/minimal-setup.md)**.

Ready-to-copy stores for **Dapper** (and EF Core, if you need full control), mail senders (**MailKit**, **SendGrid**,
outbox), LDAP, admin endpoints and a **TypeScript client** are in [`samples/`](https://github.com/SlimIdentity/SlimIdentity/tree/main/samples).

## Try it

```bash
docker compose up --build      # → http://localhost:8080
```

A playground for every flow – cookies and bearer tokens, 2FA with a virtual authenticator, passkeys with a virtual
passkey (sign-in, autofill, sign-in methods), sessions, password reset, impersonation – with a fake mailbox and a request
log. Want to attack it? [`BREAKME.md`](https://github.com/SlimIdentity/SlimIdentity/blob/main/BREAKME.md).
Without Docker: `dotnet run --project samples/SlimIdentity.Demo` → <http://localhost:5209> (seeded users
`admin@demo.local` / `Admin123!` and `user@demo.local` / `User1234!`; requests in `SlimIdentity.Demo.http`).

## Packages

| Package | Purpose |
| :--- | :--- |
| `SlimIdentity` | The endpoints, flows and security mechanisms. No database dependency; Native AOT compatible. |
| `SlimIdentity.EntityFrameworkCore` | All stores on your `DbContext` and user entity (EF Core itself is not AOT compatible). |
| `SlimIdentity.Passkeys` | Passkeys (WebAuthn) – optional; the core contains no WebAuthn code. Native AOT compatible. |
| `SlimIdentity.Testing` | Conformance checks for your own store implementations – for test projects. |

All packages are released together with the same version.

## Documentation

Choose the path that matches your application; the [documentation index](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/README.md)
links to every guide and reference.

- **Same-site browser app with EF Core:** [minimal setup](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/minimal-setup.md)
- **Custom store or bearer/JWT client:** [getting started](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/getting-started.md)
- **Coding agents integrating SlimIdentity:** [agent integration guide](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/agent-integration.md)
- **Look up a route, option or security responsibility:** [endpoints](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/endpoints.md) ·
  [configuration](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/configuration.md) ·
  [security model](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/security.md)

## Roadmap

After 1.0, roughly in this order:

- Device-bound tokens (DPoP) for bearer clients.
- Passkeys: a relying party per tenant domain.
- API-key entity in the EF Core package; npm package of the TypeScript client if there is demand.

## Contributing

Issues and pull requests are welcome – see [CONTRIBUTING.md](https://github.com/SlimIdentity/SlimIdentity/blob/main/CONTRIBUTING.md).

## License

[MIT](https://github.com/SlimIdentity/SlimIdentity/blob/main/LICENSE) © Timm Kautz
