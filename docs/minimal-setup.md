# Minimal setup

The shortest path to a working, secure login with Entity Framework Core: your user entity, three small additions, a
few lines in `Program.cs`. Not using EF Core? Then step 3 is one copied store class instead – see
[without EF Core](#without-ef-core).

**What you get:** `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/me`, e-mail verification, password reset and
change, e-mail change, invitations, server-side sessions, 2FA and external login (once you add a provider) – with rate
limiting, account lockout, CSRF protection and enumeration resistance already active.

**What you provide:**

| | Effort |
| :--- | :--- |
| Thirteen properties besides `Id` on your user entity | copy-paste |
| One line in `OnModelCreating`, one migration | `ApplySlimIdentity<AppUser, Guid>()` |
| `ISlimEmailSender` – sends the mails | `AddNullEmailSender()` while developing; `WithoutEmail()` for hosts without mail ([guide](guides/without-email.md)) |

## 1. Install

```bash
dotnet add package SlimIdentity --prerelease
dotnet add package SlimIdentity.EntityFrameworkCore --prerelease
```

## 2. Program.cs

```csharp
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SlimIdentity;
using SlimIdentity.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(o => o.UseSqlite("Data Source=app.db"));   // your database
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))
    .AddEntityFrameworkStores<AppDbContext, AppUser, Guid>()
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

**Front-end dev server on another port** (Vite on 5173, the API on 5001) – that is another origin, and the browser
blocks the calls without CORS. Either let the dev server proxy `/auth` and `/api` to the API (one origin, nothing to
configure – Vite: `server.proxy`), or allow the front end in the API – `Links.BaseUrl` is already a trusted origin:

```csharp
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))
    .AddEntityFrameworkStores<AppDbContext, AppUser, Guid>()
    .AddNullEmailSender()
    .AddCorsPolicy();                               // credentialed CORS for the trusted origins
// …
app.UseCors(SlimIdentityDefaults.CorsPolicy);       // before UseAuthentication()
```

That is the complete configuration. Without a `Tokens.JwtSecret` the app uses **cookie sessions** – the right default
for a browser front end on the same site. For mobile apps or token-based SPAs add a secret (at least 32 random bytes,
from user secrets or a key vault) and JWT bearer tokens are enabled as well:

```bash
dotnet user-secrets set "SlimIdentity:Tokens:JwtSecret" "$(openssl rand -base64 48)"
```

## 3. The user entity and the model

Your user entity keeps its own shape and business data – it implements `ISlimUserEntity<TKey>` with plain public
properties (keys: `Guid`, `int`, `long` or `string`):

```csharp
public class AppUser : ISlimUserEntity<Guid>
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Email { get; set; } = "";
    public string NormalizedEmail { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string SecurityStamp { get; set; } = SlimUser.NewSecurityStamp();   // also when you add users yourself
    public bool IsActive { get; set; } = true;
    public bool EmailConfirmed { get; set; }
    public int FailedLoginAttempts { get; set; }
    public DateTimeOffset? LockoutEndUtc { get; set; }
    public bool TwoFactorEnabled { get; set; }
    public bool PasswordChangeRequired { get; set; }
    public string? TotpSecret { get; set; }
    public long? LastTwoFactorCodeAt { get; set; }
    public long? LastTwoFactorChallengeAt { get; set; }

    public string? DisplayName { get; set; }   // yours – SlimIdentity never sees it
}

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<AppUser> Users => Set<AppUser>();
    protected override void OnModelCreating(ModelBuilder b) => b.ApplySlimIdentity<AppUser, Guid>();
}
```

`ApplySlimIdentity` adds the unique index on the normalized address and five small tables (refresh tokens, sessions,
recovery codes, external logins, passkeys – the last one stays empty unless you opt in). Create the migration: `dotnet ef migrations add SlimIdentity`. Roles or other claims
for cookies and tokens come from an `ISlimUserClaimsProvider<AppUser>` you register – see the
[package README](../src/SlimIdentity.EntityFrameworkCore/README.md).

The package is verified in CI against SQLite, PostgreSQL and SQL Server with the
[store conformance checks](how-it-works.md#verify-your-stores) – atomic counters, single-use tokens and unique addresses
included.

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

1. **Real mail sender** instead of `AddNullEmailSender()` (which refuses to start in the `Production` environment) –
   MailKit, SendGrid or an outbox:
   [`samples/templates/Email`](../samples/templates/Email).
2. **Persist the Data Protection key ring** – otherwise every restart signs everybody out and invalidates all links
   ([guide](guides/data-protection.md)).
3. **HTTPS** for the browser; behind a reverse proxy also `UseForwardedHeaders()` ([guide](guides/reverse-proxy.md)).
4. `JwtSecret` (if used) only from a secret store, never from `appsettings.json` in the repository.
5. Front end on another origin? Add it to `TrustedOrigins` and configure CORS ([guide](guides/spa-cookies.md)).
6. **The first administrator** – created by code at start-up, with a start password or a reset link
   ([seeding](guides/seeding.md)).

## Adding more later

With the EF Core package, sessions, refresh tokens, 2FA and external-login storage are already in place (leave stores
out with `AddEntityFrameworkStores<…>(o => o.TwoFactor = false)`). What remains is configuration:

| Feature | Add | Guide |
| :--- | :--- | :--- |
| Bearer tokens (mobile apps, token SPAs) | `Tokens.JwtSecret` | [mobile / bearer](guides/mobile-bearer.md) |
| Two-factor authentication | nothing – the `/auth/2fa/*` endpoints are active | [2FA](guides/two-factor.md) |
| Google, Entra ID, Keycloak, … | an OAuth handler on `.Authentication` | [external login](guides/external-login.md) |
| Breached-password check | `.AddPasswordRule<PwnedPasswordRule>()` | [configuration](configuration.md#passwords) |
| API keys for services | `.AddApiKeyStore<T>()` | [admin features](guides/admin-features.md) |

## Without EF Core

Dapper, another ORM or a REST service: implement `ISlimUserStore` yourself – start from the ready-made
[Dapper](../samples/templates/Dapper) or [EF Core](../samples/templates/EfCore) templates rather than from scratch,
because several methods must be **atomic single statements** (e.g. `IncrementFailedLoginAttemptsAsync`) and the
security guarantees depend on that ([why](how-it-works.md#your-part-the-stores)). Register it with
`.AddUserStore<MyUserStore>()` and verify it against your database with one call from `SlimIdentity.Testing`
([how](how-it-works.md#verify-your-stores)). The optional stores (`AddSessionStore`, `AddTwoFactorStore`,
`AddRefreshTokenStore`, `AddExternalLoginStore`) follow the same pattern.
