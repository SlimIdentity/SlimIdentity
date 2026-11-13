# The first administrator (seeding)

A fresh database has no users, and without self-registration nobody can create the first one through the API. Create
it at startup; `ISlimAuthManager` works outside a request, so the account gets a security stamp, a hash from the
configured hasher and the password rules.

```csharp
var app = builder.Build();

await using (var scope = app.Services.CreateAsyncScope())
{
    var auth = scope.ServiceProvider.GetRequiredService<ISlimAuthManager>();
    var created = await auth.CreateUserAsync(
        builder.Configuration["Admin:Email"]!,
        builder.Configuration["Admin:StartPassword"],     // a secret – never in the repository
        profile: new SeededRole("admin"));                // your business data, written by your store / user factory
    // 409 email_taken: already seeded (or created in parallel by another instance) – nothing to do
}

app.Run();
```

- **Runs on every start**; the unique address makes it idempotent across instances.
- **Start password:** checked against the password rules (`400` otherwise); the first sign-in answers
  `action_required` `["change_password"]` ([forced password change](without-email.md#the-forced-password-change)).
  Remove it from the configuration afterwards.
- **Role:** the profile reaches `ISlimUserStore.CreateAsync` as `SlimNewUser.Profile`; with the EF Core package an
  `ISlimUserFactory<AppUser>` maps it to entity fields ([registration with business data](registration-profile.md)).
  Claims come from your store as usual ([roles and permissions](roles-and-permissions.md)).

## Without a password anyone knows

Omit the start password and hand out a reset link; nobody but the administrator ever sees the password:

```csharp
var reset = await auth.CreatePasswordResetAsync(created.User!, TimeSpan.FromDays(1));
logger.LogWarning("First administrator: set the password within 24 hours at {Link}", reset.Link);
```

The link works once and until the security stamp changes. Write it only where operators see it.

## Seeding by the database (EF Core `HasData`, SQL scripts)

Possible for the account, not the password: leave `PasswordHash` empty and hand out a reset link as above.

| Field | Value |
| :--- | :--- |
| `Email` / `NormalizedEmail` | the address / its `ToUpperInvariant()` (EF Core package; own store: whatever your lookup compares) |
| `SecurityStamp` | `SlimUser.NewSecurityStamp()` – a fixed value in a migration is fine |
| `IsActive` | `true` |
| `EmailConfirmed` | `true` if you vouch for the address |

An empty `SecurityStamp` is repaired at the first sign-in (log event 3011). Never hash a password with another
algorithm or `PasswordHasher` configuration – SlimIdentity could not verify it.
