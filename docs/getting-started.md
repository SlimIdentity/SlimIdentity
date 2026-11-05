# Getting started

This walks through a minimal setup: JWT login for a SPA or mobile app, backed by your own database.

## 1. Install

```bash
dotnet add package SlimIdentity --prerelease
```

## 2. Implement the user store

SlimIdentity never touches a database. You implement `ISlimUserStore` against whatever you use
(EF Core, Dapper, a REST service, …). Complete EF Core and Dapper versions are in
[`samples/`](https://github.com/timmkautz/slimidentity/tree/main/samples); the contract is small:

```csharp
public interface ISlimUserStore
{
    Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct);              // case-insensitive!
    Task<SlimUser?> FindByIdAsync(string userId, CancellationToken ct);
    Task<SlimUser> CreateAsync(string email, string passwordHash, CancellationToken ct);
    Task UpdateSecurityStateAsync(SlimUser user, CancellationToken ct);                // persist the security fields only
    Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct); // roles, tenant id, …
}
```

`SlimUser` is a plain transfer object with the security fields only (`Id`, `Email`, `PasswordHash`, `SecurityStamp`,
`IsActive`, `EmailConfirmed`, `FailedLoginAttempts`, `LockoutEndUtc`, `TwoFactorEnabled`). Your own user entity stays
yours – map it in the store.

## 3. Implement (or stub) the e-mail sender

```csharp
builder.Services.AddSlimIdentity(...)
    .AddEmailSender<MyEmailSender>();     // production: MailKit, SendGrid, … (see samples/Email)
    // .AddNullEmailSender();             // development: writes links and codes to the log
```

## 4. Register and map

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))
    .AddUserStore<MyUserStore>()
    .AddEmailSender<MyEmailSender>()
    .AddRefreshTokenStore<MyRefreshTokenStore>();   // optional, enables /auth/refresh

var app = builder.Build();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapSlimIdentityApi();
app.MapGet("/api/hello", (ClaimsPrincipal user) => $"Hello {user.GetSlimEmail()}").RequireAuthorization();

app.Run();
```

```json
{
  "SlimIdentity": {
    "Tokens": {
      "JwtSecret": "<at least 32 random bytes – use user secrets / a key vault, never commit it>",
      "Issuer": "MyApp",
      "Audience": "MyAppClients"
    },
    "Links": {
      "EmailVerificationUrl": "https://app.example.com/verify-email?token={token}",
      "PasswordResetUrl": "https://app.example.com/reset-password?token={token}"
    }
  }
}
```

The options are validated at startup – a missing or too short `JwtSecret`, for example, stops the application with
a clear message instead of failing later.

## 5. Try it

```http
POST /auth/register
Content-Type: application/json

{ "email": "me@example.com", "password": "Secret123!" }
```

```http
POST /auth/login
Content-Type: application/json

{ "email": "me@example.com", "password": "Secret123!" }
```

The answer contains `accessToken` and `refreshToken`. Send `Authorization: Bearer <accessToken>` to protected
endpoints; when it expires, exchange the refresh token at `POST /auth/refresh`.

For a browser SPA on the same site, cookies are usually the better choice: `POST /auth/login?useCookies=true` with
the header `X-CSRF: 1` – see [SPA with cookies](guides/spa-cookies.md).

## Next steps

- Persist the Data Protection key ring (`builder.Services.AddDataProtection().PersistKeysTo…`) as soon as you run more
  than one instance or in containers – cookies, links and refresh tokens are encrypted with it.
- Choose the capabilities you need: [sessions](guides/sessions-and-logout.md), [2FA](guides/two-factor.md),
  [external login](guides/external-login.md), [invitations](guides/invitations.md).
- Read the [security model](security.md).
