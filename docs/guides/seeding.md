# The first administrator (seeding)

A fresh database has no users – and on hosts without self-registration nobody can create the first one through the
API. Create it by code at start-up. SlimIdentity's own APIs work outside a request, so the account gets everything a
regular one has: a security stamp, a password hash with the configured hasher, the password rules.

## With a start password

```csharp
var app = builder.Build();

await SeedAdministratorAsync(app.Services,
    builder.Configuration["Admin:Email"]!,
    builder.Configuration["Admin:StartPassword"]!,   // a secret (user secrets, environment, vault) – never in the repository
    CancellationToken.None);

app.Run();

static async Task SeedAdministratorAsync(IServiceProvider services, string email, string startPassword, CancellationToken ct)
{
    await using var scope = services.CreateAsyncScope();
    var store = scope.ServiceProvider.GetRequiredService<ISlimUserStore>();
    var auth = scope.ServiceProvider.GetRequiredService<ISlimAuthManager>();

    if (await store.FindByEmailAsync(email, ct) is not null) return;                  // already there: nothing to do
    var admin = await store.CreateAsync(new SlimNewUser { Email = email }, ct);        // Profile = your data (role, name)
    if (admin is null) return;                                                         // created in parallel by another instance

    admin.EmailConfirmed = true;                                                       // you vouch for the address
    await store.UpdateSecurityStateAsync(admin, admin.SecurityStamp, ct);
    if (await auth.SetPasswordAsync(admin, startPassword, mustChange: true, ct) is not null)   // 400 with the violated rules
        throw new InvalidOperationException("The start password does not meet the password rules.");
}
```

- **Runs on every start** and does nothing once the account exists; with several instances the unique address decides
  (`CreateAsync` returns `null` for the loser).
- **`mustChange: true`** – the first sign-in answers `action_required` (`change_password`) and issues no session until the
  administrator has chosen an own password (TypeScript: `completePasswordChange`). The start password is then worthless;
  remove it from the configuration.
- **The role** – your business data: pass it as `Profile` and write it in your store (EF Core package:
  `ISlimUserFactory<AppUser>`, see [registration with business data](registration-profile.md)), or insert it into your
  roles table after `CreateAsync`. Claims come from `GetClaimsAsync` / `ISlimUserClaimsProvider<AppUser>` as usual
  ([roles and permissions](roles-and-permissions.md)).

```csharp
// EF Core package: the factory turns the profile into entity fields
var admin = await store.CreateAsync(new SlimNewUser { Email = email, Profile = new SeededRole("admin") }, ct);

public sealed record SeededRole(string Role);
public sealed class AppUsers : ISlimUserFactory<AppUser>
{
    public AppUser Create(SlimNewUser user) => new() { Role = user.Profile is SeededRole r ? r.Role : "member" };
}
```

## Without a password anyone knows

Create the account without a password and hand over a reset link – the administrator chooses the password, nobody
else ever sees it:

```csharp
var admin = await store.CreateAsync(new SlimNewUser { Email = email }, ct);
var reset = await auth.CreatePasswordResetAsync(admin!, TimeSpan.FromDays(1), ct);
logger.LogWarning("First administrator: set the password within 24 hours at {Link}", reset.Link);   // once, on the console
```

The link works once and only until the account's security stamp changes. Write it somewhere only operators see – it
is as good as the password for its lifetime.

## Data seeding by the database (EF Core `HasData`, SQL scripts)

Possible for the account itself, not for the password: leave `PasswordHash` empty and hand over a reset link as above.
Fill the SlimIdentity fields like SlimIdentity would:

| Field | Value |
| :--- | :--- |
| `Email` / `NormalizedEmail` | the address / `ToUpperInvariant()` of it (EF Core package; your own store: whatever your lookup compares) |
| `SecurityStamp` | `SlimUser.NewSecurityStamp()` – a fixed value in a migration is fine, the first password replaces it |
| `IsActive` | `true` |
| `EmailConfirmed` | `true` if you vouch for the address |

An empty `SecurityStamp` is repaired at the first sign-in (log event 3011), but initialize it anyway.

Never hash a password yourself with another algorithm or another `PasswordHasher` configuration – SlimIdentity could
not verify it.
