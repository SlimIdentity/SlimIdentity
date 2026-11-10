# Getting started

This walks through a setup with JWT login for a SPA or mobile app, backed by your own database, and explains each
step. Just want it running? See the [minimal setup](minimal-setup.md). How the pieces fit together – and why some
store methods must be atomic – is described in [How SlimIdentity works](how-it-works.md).

## 1. Install

```bash
dotnet add package SlimIdentity --prerelease
```

## 2. Implement the user store

> **Using EF Core?** Skip this step: the `SlimIdentity.EntityFrameworkCore` package implements every store on your own
> `DbContext` and user entity – see the [minimal setup](minimal-setup.md). This section explains the contract for
> everything else.

SlimIdentity's core never touches a database. You implement `ISlimUserStore` against whatever you use
(Dapper, another ORM, a REST service, …). Complete Dapper and EF Core versions are in
[`samples/`](https://github.com/SlimIdentity/SlimIdentity/tree/main/samples); the contract is small:

```csharp
public interface ISlimUserStore
{
    Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct);              // case-insensitive!
    Task<SlimUser?> FindByIdAsync(string userId, CancellationToken ct);
    Task<SlimUser?> CreateAsync(SlimNewUser newUser, CancellationToken ct);            // null if the address is taken
    Task UpdateSecurityStateAsync(SlimUser user, CancellationToken ct);                // persist the security fields only
    Task<bool> UpdateEmailAsync(SlimUser user, string newEmail, CancellationToken ct); // false if the address is taken
    Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct); // roles, tenant id, …

    // sign-in bookkeeping – narrow, atomic statements (one UPDATE each)
    Task<int> IncrementFailedLoginAttemptsAsync(SlimUser user, CancellationToken ct);  // returns the new count
    Task SetLockoutEndAsync(SlimUser user, DateTimeOffset? lockoutEndUtc, CancellationToken ct);
    Task ResetFailedLoginAttemptsAsync(SlimUser user, CancellationToken ct);
    Task UpdatePasswordHashAsync(SlimUser user, string currentHash, string newHash, CancellationToken ct); // only if unchanged
}
```

The narrow methods exist because sign-in requests are slow (password hashing) and run in parallel: they must never
write back a whole, possibly outdated `SlimUser` – that could undo a password change that happened in the meantime.
Copy the store from the samples rather than writing it from scratch – the rules that matter for security are listed in
[How SlimIdentity works](how-it-works.md#your-part-the-stores).

`SlimUser` is a plain transfer object with the security fields only (`Id`, `Email`, `PasswordHash`, `SecurityStamp`,
`IsActive`, `EmailConfirmed`, `FailedLoginAttempts`, `LockoutEndUtc`, `TwoFactorEnabled`, `PasswordChangeRequired`). Your own user entity stays
yours – map it in the store.

## 3. Implement (or stub) the e-mail sender

```csharp
builder.Services.AddSlimIdentity(...)
    .AddEmailSender<MyEmailSender>();     // production: MailKit, SendGrid, … (see samples/templates/Email)
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
      "BaseUrl": "https://app.example.com"
    }
  }
}
```

That is the whole configuration for most apps: the `JwtSecret` enables bearer tokens (leave it out for a cookie-only
app), `Links.BaseUrl` makes mail links point to `/verify-email`, `/reset-password`, … of your front end. Everything else
has secure defaults ([configuration reference](configuration.md)). The options are validated at startup – a too short
`JwtSecret`, for example, stops the application with a clear message instead of failing later.

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

**HTTPS:** browsers only send the (always `Secure`) cookie over HTTPS – and to `http://localhost` during development.
Bearer tokens and API keys also work over plain HTTP, e.g. for service-to-service calls on the same host or in a
private network; they travel in clear text there, so do not use HTTP across untrusted networks.

## Next steps

- **Persist the Data Protection key ring** before going to production ([guide](guides/data-protection.md)) – cookies,
  links, refresh tokens and TOTP secrets are encrypted with it.
- Choose the capabilities you need: [sessions](guides/sessions-and-logout.md), [2FA](guides/two-factor.md),
  [external login](guides/external-login.md), [invitations](guides/invitations.md),
  [breached-password check](configuration.md#passwords).
- Add [metrics](guides/observability.md) to your monitoring.
- Read the [security model](security.md).
