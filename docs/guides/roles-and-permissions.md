# Roles and permissions

SlimIdentity has no permission model; groups, hierarchies and resource rights stay in your database. It carries the
result as **claims** in every cookie and token, so standard ASP.NET Core authorization works, and keeps them current.

## From your data to a policy

**1. Claims from your store** – `ISlimUserStore.GetClaimsAsync` (EF Core package: `ISlimUserClaimsProvider<TUser>`):

```csharp
claims.Add(new Claim("tenant_id", user.TenantId.ToString()));
claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));            // becomes "role"
claims.AddRange(permissions.Select(p => new Claim("permission", p)));         // "reports.read", "invoices.approve"
```

Groups resolving to permissions: [`EfCoreModel.cs`](../../samples/templates/EfCore/EfCoreModel.cs),
[`EfCoreStores.cs`](../../samples/templates/EfCore/EfCoreStores.cs),
[`GroupEndpoints.cs`](../../samples/templates/Enterprise/GroupEndpoints.cs).

**2. Policies:**

```csharp
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("reports.read", p => p.RequireClaim("permission", "reports.read"))
    .AddPolicy("admin", p => p.RequireRole("Admin"));

app.MapGet("/api/reports", …).RequireAuthorization("reports.read");
```

**3. Resources and tenants** are checked against the resource, in the endpoint or an
`AuthorizationHandler<TRequirement, TResource>`:
`if (document.TenantId.ToString() != user.FindFirst("tenant_id")?.Value) return Results.NotFound();`

Claim rules: a JWT is signed, **not encrypted** – no secrets or unneeded personal data. Claims travel with every
request – short codes, not long lists. SlimIdentity's own claims (`sub`, `email`, `amr`, `sid`, `act`, `iss`, `exp`,
…) cannot be overwritten; `/auth/me` shows the others.

## Keeping claims current

Claims are a snapshot taken at sign-in, refresh and step-up. After changing a user's roles, groups or permissions:

```csharp
await auth.RefreshClaimsAsync(user, ct);
```

| Session | Without `RefreshClaimsAsync` | With `RefreshClaimsAsync` | With `SignOutEverywhereAsync` |
| :--- | :--- | :--- | :--- |
| Cookie | old claims until the next sign-in | new claims at the next validation (`Cookies.SecurityStampValidationInterval`, default 1 minute) | signed out within the same interval |
| Bearer | old claims until the next refresh | new claims on the next request; the next refresh issues them into a token | rejected on the next request |
| Links, refresh tokens, remembered devices | – | stay valid | invalidated |

The security stamp carries a small claims part; validation loads the user anyway, and `GetClaimsAsync` runs only when
that part differs. Bearer tokens need `ValidateSecurityStampOnEachRequest` (default) for the immediate effect. A sudo
window survives a claims refresh; other `ElevateSessionAsync` claims do not.

A group change needs `RefreshClaimsAsync` for every member (large groups: in a background job). Rights that must never
lag behind belong in a live authorization handler; a [sign-in guard](hooks.md) can refuse whole sessions.

The stamp is an opaque string of at most 64 characters. Compare stamps only with `SlimUser.IsSameSecurityState(a, b)`
(ignores the claims part); never parse it.
