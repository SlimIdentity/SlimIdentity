# SlimIdentity.EntityFrameworkCore

Entity Framework Core stores for [SlimIdentity](https://www.nuget.org/packages/SlimIdentity): your user entity, your
`DbContext`, three small additions – and every SlimIdentity store contract (atomic counters, single-use tokens, unique
addresses) is taken care of. Verified in CI against SQLite, PostgreSQL and SQL Server.

```bash
dotnet add package SlimIdentity.EntityFrameworkCore --prerelease
```

**1. Your user entity implements `ISlimUserEntity<TKey>`** – plain public properties next to your own:

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

    public string? DisplayName { get; set; }   // your business data – SlimIdentity never sees it
}
```

**2. One line in `OnModelCreating`:**

```csharp
protected override void OnModelCreating(ModelBuilder b) => b.ApplySlimIdentity<AppUser, Guid>();
```

**3. One line in the registration:**

```csharp
builder.Services.AddDbContext<AppDbContext>(o => o.UseNpgsql(connectionString));
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))
    .AddEntityFrameworkStores<AppDbContext, AppUser, Guid>()
    .AddEmailSender<MyEmailSender>();
```

Then create a migration (`dotnet ef migrations add SlimIdentity`). Besides the columns on your user table it adds
`SlimRefreshTokens`, `SlimSessions`, `SlimRecoveryCodes`, `SlimExternalLogins`, `SlimSharedState` (single-use codes
and mail limits of all instances, cleaned up by the store itself) and `SlimPasskeys` (passkeys are
opt-in: `AddEntityFrameworkStores<…>(o => o.Passkeys = true)` with `Links.BaseUrl` or
`.AddPasskeys(o => o.RelyingPartyId = …)` from the referenced `SlimIdentity.Passkeys` package).

The stores use their own `AppDbContext` instance per request (from `IDbContextFactory<AppDbContext>` if registered,
otherwise from the same options), never the one your endpoints resolve: signing a user in never saves your pending
changes or detaches your entities.

**Transactions:** for the same reason SlimIdentity's writes are never part of a transaction you opened (on your
context or with a `TransactionScope`) – a rollback does not undo them, and they wait for rows your transaction locks.
Commit first, then call `ISlimAuthManager` (create the company, commit, then `CreateUserAsync`). To create account and
business data together, use the registration profile below – it is written in the store's own `SaveChanges`. A write
inside an open transaction throws on SQLite (one writer per database – it would wait until it times out) and logs
a warning once (event id 8101) on other providers.

## Options and extension points

- Keys: `Guid`, `int`, `long` or `string`.
- `AddEntityFrameworkStores<…>(o => { o.TwoFactor = false; o.StoreClientInfo = false; })` – leave out stores (each one
  activates its endpoints) or drop user agent / IP address of sessions (personal data).
- `ISlimUserClaimsProvider<AppUser>` (register it in DI) – roles, tenant id or other claims for cookies and tokens.
- `ISlimUserFactory<AppUser>` – creates new users (registration, external login): tenant, defaults and the
  [registration profile](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/guides/registration-profile.md)
  (`SlimNewUser.Profile`) – related entities are inserted in the same `SaveChanges` as the account.
- Expired sessions and refresh tokens are not deleted automatically: run
  `DELETE FROM "SlimSessions" WHERE "ExpiresUtc" < now()` (and the same for `SlimRefreshTokens."ExpiresAt"`) periodically.
- Prefer the copy-paste templates in the repository only if you need full control over the mapping.
