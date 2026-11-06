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
the provided samples ([how it works](https://github.com/timmkautz/slimidentity/blob/main/docs/how-it-works.md)).

> **Status: pre-release.** Working towards 1.0 – the API may still change until then, and the code has not been
> independently audited yet. Please report security issues privately – see
> [SECURITY.md](https://github.com/timmkautz/slimidentity/blob/main/SECURITY.md).

## Features

- **Bring your own database** – one required store (`ISlimUserStore`, ready-to-copy for EF Core and Dapper); no EF
  Core, Dapper or driver dependency.
- **Cookies or JWT** per request: HttpOnly/Secure/SameSite cookies with CSRF protection, or access + refresh tokens
  with rotation, reuse detection and an absolute session lifetime.
- **Server-side sessions** (optional): real per-device logout, device list, sign out everywhere.
- **Brute-force protection**: per-client rate limiting plus progressive account lockout; uniform answers and timing
  against account enumeration; pluggable password rules (e.g. breached-password check).
- **2FA**: TOTP (authenticator apps), e-mail codes, recovery codes – secrets encrypted at rest, every code usable once.
- **External login**: any ASP.NET Core OAuth/OIDC handler (Google, Microsoft Entra ID, Keycloak, …) with safe account linking.
- **Workflows**: registration, e-mail verification, password reset/change, e-mail change, invitations – stateless,
  single-use links.
- **Admin tooling**: impersonation, step-up "sudo" mode, bans, API keys for machine-to-machine access.
- **Your database stays boring**: it only ever sees hashes and ciphertext – no usable tokens, codes or 2FA secrets.
- **Framework native**: built-in cookie/JWT handlers, `PasswordHasher`, Data Protection and rate limiter;
  `[Authorize]` and policies just work. Full OpenAPI metadata for client generation.
- **Observable**: OpenTelemetry-ready metrics and structured logs with stable event ids – no extra dependency.
- **Native AOT** and trimming compatible; options validated at startup.

## Quickstart

```bash
dotnet add package SlimIdentity --prerelease
```

```csharp
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))
    .AddUserStore<MyUserStore>()              // required: your database (copy from samples/templates)
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

Ready-to-copy stores for **EF Core** and **Dapper**, mail senders (**MailKit**, **SendGrid**, outbox), LDAP, admin
endpoints and a **TypeScript client** are in [`samples/`](https://github.com/timmkautz/slimidentity/tree/main/samples).
A runnable demo: `dotnet run --project samples/SlimIdentity.Demo` (users and requests in `SlimIdentity.Demo.http`).

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
  [LDAP](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/ldap-and-legacy-passwords.md) ·
  [client certificates](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/client-certificates.md) ·
  [Data Protection](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/data-protection.md) ·
  [reverse proxy](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/reverse-proxy.md) ·
  [observability](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/observability.md) ·
  [Native AOT](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/native-aot.md) ·
  [migrating from ASP.NET Core Identity](https://github.com/timmkautz/slimidentity/blob/main/docs/guides/migrating-from-aspnet-identity.md)
- [Architecture and design principles](https://github.com/timmkautz/slimidentity/blob/main/docs/architecture-manifest.md)

## Contributing

Issues and pull requests are welcome – see [CONTRIBUTING.md](https://github.com/timmkautz/slimidentity/blob/main/CONTRIBUTING.md).

## License

[MIT](https://github.com/timmkautz/slimidentity/blob/main/LICENSE) © Timm Kautz
