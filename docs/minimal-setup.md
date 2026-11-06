# Minimal setup

The shortest path to a working, secure login: one table, one class, a few lines in `Program.cs`. Everything else –
2FA, sessions, refresh tokens, external login – can be added later without changing what you build here.

**What you get:** `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/me`, e-mail verification, password reset and
change, e-mail change, invitations – with rate limiting, account lockout, CSRF protection and enumeration resistance
already active.

**What you provide:**

| | Effort |
| :--- | :--- |
| A user table with nine security columns | one migration |
| `ISlimUserStore` – the bridge to that table | copy one class from the samples |
| `ISlimEmailSender` – sends the mails | `AddNullEmailSender()` while developing |

## 1. Install

```bash
dotnet add package SlimIdentity --prerelease
```

## 2. Program.cs

```csharp
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SlimIdentity;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(o => o.UseSqlite("Data Source=app.db"));   // your database
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))
    .AddUserStore<EfCoreUserStore>()
    .AddNullEmailSender();          // development: links and codes go to the log

var app = builder.Build();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapSlimIdentityApi();           // everything under /auth
app.MapGet("/api/hello", (ClaimsPrincipal user) => $"Hello {user.GetSlimEmail()}").RequireAuthorization();

app.Run();
```

```json
{
  "SlimIdentity": {
    "Links": { "BaseUrl": "https://localhost:5173" }
  }
}
```

That is the complete configuration. Without a `Tokens.JwtSecret` the app uses **cookie sessions** – the right default
for a browser front end on the same site. For mobile apps or token-based SPAs add a secret (at least 32 random bytes,
from user secrets or a key vault) and JWT bearer tokens are enabled as well:

```bash
dotnet user-secrets set "SlimIdentity:Tokens:JwtSecret" "$(openssl rand -base64 48)"
```

## 3. The user table and the store

Your user entity keeps its own shape – it only needs these columns (names are up to you):

| Column | Type | Note |
| :--- | :--- | :--- |
| `Id` | `Guid` / `int` / `string` | |
| `Email` | `string` | |
| `NormalizedEmail` | `string` | upper-cased, **unique index** – lookups are case-insensitive and duplicates impossible |
| `PasswordHash` | `string` | empty for external-login and invited users |
| `SecurityStamp` | `string` | |
| `IsActive` | `bool` | `false` = banned / deactivated |
| `EmailConfirmed` | `bool` | |
| `FailedLoginAttempts` | `int` | |
| `LockoutEndUtc` | `DateTimeOffset?` | |
| `TwoFactorEnabled` | `bool` | stays `false` until you add 2FA |

Then copy **`EfCoreUserStore`** from
[`samples/templates/EfCore/EfCoreStores.cs`](../samples/templates/EfCore/EfCoreStores.cs) (only this class – the others
belong to optional features) and adapt the entity name. If you have no roles yet, let `GetClaimsAsync` return an empty
list. Using Dapper instead? Take `DapperUserStore` and the `users` table from
[`samples/templates/Dapper`](../samples/templates/Dapper).

> Copy the store rather than writing it from scratch: several of its methods must be **atomic single statements**
> (e.g. `IncrementFailedLoginAttemptsAsync`), and the security guarantees depend on that – see
> [How SlimIdentity works](how-it-works.md#your-part-the-stores).

## 4. Try it

```http
POST https://localhost:5001/auth/register
Content-Type: application/json
X-CSRF: 1

{ "email": "me@example.com", "password": "correct horse battery staple" }
```

The verification link appears in the log (null sender). Then sign in – the response sets the `HttpOnly` cookie:

```http
POST https://localhost:5001/auth/login
Content-Type: application/json
X-CSRF: 1

{ "email": "me@example.com", "password": "correct horse battery staple" }
```

`GET /api/hello` now answers with your address. Every state-changing cookie request needs the `X-CSRF` header (any
value); the [TypeScript client](../samples/templates/Frontend/slimIdentityClient.ts) does that for you.

## Before production

1. **Real mail sender** instead of `AddNullEmailSender()` – MailKit, SendGrid or an outbox:
   [`samples/templates/Email`](../samples/templates/Email).
2. **Persist the Data Protection key ring** – otherwise every restart signs everybody out and invalidates all links
   ([guide](guides/data-protection.md)).
3. **HTTPS** for the browser; behind a reverse proxy also `UseForwardedHeaders()` ([guide](guides/reverse-proxy.md)).
4. `JwtSecret` (if used) only from a secret store, never from `appsettings.json` in the repository.
5. Front end on another origin? Add it to `TrustedOrigins` and configure CORS ([guide](guides/spa-cookies.md)).

## Adding more later

Each capability is one line plus its store – nothing above changes:

| Feature | Add | Guide |
| :--- | :--- | :--- |
| Refresh tokens (mobile / bearer) | `.AddRefreshTokenStore<T>()` + `Tokens.JwtSecret` | [mobile / bearer](guides/mobile-bearer.md) |
| Device list, per-device logout | `.AddSessionStore<T>()` | [sessions](guides/sessions-and-logout.md) |
| Two-factor authentication | `.AddTwoFactorStore<T>()` | [2FA](guides/two-factor.md) |
| Google, Entra ID, Keycloak, … | `.AddExternalLoginStore<T>()` + an OAuth handler | [external login](guides/external-login.md) |
| Breached-password check | `.AddPasswordRule<PwnedPasswordRule>()` | [configuration](configuration.md#passwords) |
| API keys for services | `.AddApiKeyStore<T>()` | [admin features](guides/admin-features.md) |
