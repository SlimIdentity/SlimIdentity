# Minimal setup

The shortest path for an **EF Core-backed browser app with cookies**. For an own store or bearer clients see
[Getting started](getting-started.md).

You get every built-in flow with rate limiting, lockout, CSRF protection and enumeration resistance. You provide the
user entity's security properties, one line in `OnModelCreating` and an `ISlimEmailSender` (`AddNullEmailSender()`
while developing, [`WithoutEmail()`](guides/without-email.md) for hosts without mail).

## 1. Install

```bash
dotnet add package SlimIdentity --prerelease
dotnet add package SlimIdentity.EntityFrameworkCore --prerelease
dotnet add package Microsoft.EntityFrameworkCore.Sqlite      # your provider (Npgsql, SqlServer, …)
dotnet add package Microsoft.EntityFrameworkCore.Design      # for the migration
```

## 2. Program.cs

```csharp
builder.Services.AddDbContext<AppDbContext>(o => o.UseSqlite("Data Source=app.db"));
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
{ "SlimIdentity": { "Links": { "BaseUrl": "https://localhost:5173" } } }
```

Without `Tokens.JwtSecret` the app uses cookie sessions only. For bearer clients add a secret of at least 32 random
bytes from a secret store: `dotnet user-secrets set "SlimIdentity:Tokens:JwtSecret" "$(openssl rand -base64 48)"`.

**Front-end dev server on another port** (Vite 5173, API 5001) is another origin: proxy `/auth` and `/api` through
the dev server (Vite `server.proxy`), or enable credentialed CORS for the trusted origins (`Links.BaseUrl` is one):
`.AddCorsPolicy()` plus `app.UseCors(SlimIdentityDefaults.CorsPolicy)` before `UseAuthentication()`.

## 3. The user entity and the model

Your entity implements `ISlimUserEntity<TKey>` (keys `Guid`, `int`, `long` or `string`) and keeps its own data:

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
    public int FailedSecondFactorAttempts { get; set; }
    public DateTimeOffset? SecondFactorLockoutEndUtc { get; set; }
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

`ApplySlimIdentity` adds the unique index on the normalized address and tables for refresh tokens, sessions, recovery
codes, external logins and passkeys. Then `dotnet ef migrations add SlimIdentity` and `dotnet ef database update`.
Roles and other claims come from an `ISlimUserClaimsProvider<AppUser>`
([package README](../src/SlimIdentity.EntityFrameworkCore/README.md)). The package passes the
[store conformance checks](how-it-works.md#verify-your-stores) on SQLite, PostgreSQL and SQL Server.

## 4. Try it

```http
POST https://localhost:5001/auth/register
X-CSRF: 1

{ "email": "me@example.com" }
```

Send the logged 6-digit code with the answer's `flowToken` to `POST /auth/register/verify`, then the password to
`POST /auth/register/password` ([registration](endpoints.md#registration)); the response sets the `HttpOnly` cookie.
Later sign-ins: `POST /auth/login` with `{ "email", "password" }`. Every state-changing cookie request needs the
`X-CSRF` header (any value); the [TypeScript client](../samples/templates/Frontend/slimIdentityClient.ts) sends it.

## Before production

1. A real mail sender ([`samples/templates/Email`](../samples/templates/Email)); `AddNullEmailSender()` refuses to
   start in `Production`.
2. A persisted, shared Data Protection key ring ([guide](guides/data-protection.md)).
3. HTTPS; behind a proxy `UseForwardedHeaders()` ([guide](guides/reverse-proxy.md)).
4. `JwtSecret` and mail credentials only from a secret store.
5. Front end on another origin: `TrustedOrigins` and CORS ([guide](guides/spa-cookies.md)).
6. The first administrator ([seeding](guides/seeding.md)).

## Adding more later

The EF Core package already provides sessions, refresh tokens, 2FA and external-login storage (opt out per store, e.g.
`AddEntityFrameworkStores<…>(o => o.TwoFactor = false)`), so `/auth/2fa/*` is active. Bearer tokens need
`Tokens.JwtSecret` ([mobile / bearer](guides/mobile-bearer.md)); external providers an OAuth handler on
`.Authentication` ([external login](guides/external-login.md)); a breached-password check
`.AddPasswordRule<PwnedPasswordRule>()` ([configuration](configuration.md#passwords)); API keys
`.AddApiKeyStore<T>()` ([admin features](guides/admin-features.md)).
