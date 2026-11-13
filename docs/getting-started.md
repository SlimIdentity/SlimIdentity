# Getting started (own store, bearer tokens)

The path for hosts without EF Core and for SPA or mobile clients with JWTs. For an EF Core app with cookies see
[Minimal setup](minimal-setup.md); the rules every store must follow are in
[How SlimIdentity works](how-it-works.md#your-part-the-stores).

## 1. Install and implement the user store

```bash
dotnet add package SlimIdentity --prerelease
```

The core never touches a database. Implement `ISlimUserStore` against what you use (Dapper, another ORM, a REST
service) – start from the [Dapper or EF Core templates](../samples/templates), not from scratch:

```csharp
public interface ISlimUserStore
{
    Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct);              // case-insensitive
    Task<SlimUser?> FindByIdAsync(string userId, CancellationToken ct);
    Task<SlimUser?> CreateAsync(SlimNewUser newUser, CancellationToken ct);            // null if the address is taken
    Task<bool> UpdateSecurityStateAsync(SlimUser user, string expectedStamp, CancellationToken ct); // only while the stamp is unchanged
    Task<bool> UpdateSecurityStampAsync(SlimUser user, string expectedStamp, string newStamp, CancellationToken ct);
    Task<SlimEmailUpdateResult> UpdateEmailAsync(SlimUser user, string newEmail, string expectedStamp, string newStamp, CancellationToken ct);
    Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct); // roles, tenant id, …

    // sign-in bookkeeping – narrow, atomic operations on their own columns
    Task<SlimAttemptReservation?> TryBeginAttemptAsync(SlimUser user, SlimAttemptRequest attempt, CancellationToken ct);
    Task ResetFailedAttemptsAsync(SlimUser user, SlimAttemptFactor factor, CancellationToken ct);
    Task UpdatePasswordHashAsync(SlimUser user, string currentHash, string newHash, CancellationToken ct); // only if unchanged
}
```

`SlimUser` carries only the [security fields](architecture-manifest.md#3-core-data-model-slimuser); your own user
entity is mapped in the store.

## 2. Register and map

```csharp
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))
    .AddUserStore<MyUserStore>()
    .AddNullEmailSender();                          // development: links and codes go to the log
    // .AddEmailSender<MyEmailSender>()             // production (samples/templates/Email)
    // .AddRefreshTokenStore<MyRefreshTokenStore>() // optional: enables /auth/refresh

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
    "Tokens": { "JwtSecret": "<openssl rand -base64 48 – from user secrets / a key vault>", "Issuer": "MyApp", "Audience": "MyAppClients" },
    "Links": { "BaseUrl": "https://app.example.com" }
  }
}
```

`JwtSecret` enables bearer tokens (omit it for cookie-only apps); `Links.BaseUrl` points mail links to your front end
(`/verify-email`, `/reset-password`, …). Options are validated at startup – a short or placeholder secret stops the
application. All other options: [configuration](configuration.md).

## 3. Try it

`POST /auth/register { "email" }` answers `action_required` (`verify_email`, `set_credential`) with a `flowToken`; the
null sender logs a 6-digit code and a link. Send `{ "flowToken", "code" }` to `/auth/register/verify` (or the link's
`token` to `/auth/flow`), then `{ "flowToken", "password" }` to `/auth/register/password`
([registration](endpoints.md#registration)). Later: `POST /auth/login { "email", "password" }`.

The sign-in answer contains `accessToken` (and `refreshToken` with a refresh-token store). Send
`Authorization: Bearer <accessToken>`; renew at `POST /auth/refresh`. Browser SPAs on the same site are better served
by cookies: [SPA with cookies](guides/spa-cookies.md).

Cookies are always `Secure` (browsers send them over HTTPS and to `http://localhost`). Bearer tokens also work over
plain HTTP but then travel in clear text – only on trusted networks.

Before production: see the checklist in [Minimal setup](minimal-setup.md#before-production).
