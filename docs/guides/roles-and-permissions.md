# Roles and permissions

SlimIdentity has no permission model of its own – groups, hierarchies, tenants and resource rights belong to your
domain and your database. What it does: carry the result as **claims** in every cookie and token, so the ASP.NET Core
authorization you already know works – and keep those claims current.

## From your data to a policy

```
your groups / roles / permissions  →  GetClaimsAsync  →  claims in cookie / JWT  →  policies, [Authorize], handlers
```

**1. Claims from your store.** `ISlimUserStore.GetClaimsAsync` (or `ISlimUserClaimsProvider<TUser>` with the EF Core
package) returns whatever your endpoints need:

```csharp
claims.Add(new Claim("tenant_id", user.TenantId.ToString()));
claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));            // becomes "role"
claims.AddRange(permissions.Select(p => new Claim("permission", p)));         // "reports.read", "invoices.approve"
```

A complete example with groups that resolve to permissions is in the EF Core template
([`EfCoreModel.cs`](../../samples/templates/EfCore/EfCoreModel.cs), [`EfCoreStores.cs`](../../samples/templates/EfCore/EfCoreStores.cs))
and [`Enterprise/GroupEndpoints.cs`](../../samples/templates/Enterprise/GroupEndpoints.cs).

**2. Policies.**

```csharp
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("reports.read", p => p.RequireClaim("permission", "reports.read"))
    .AddPolicy("admin", p => p.RequireRole("Admin"));

app.MapGet("/api/reports", …).RequireAuthorization("reports.read");
```

**3. Resources and tenants.** A claim says what someone may do *in general*. Whether they may edit *this* document or
see data of *this* tenant is a check against the resource – in the endpoint or an `AuthorizationHandler<TRequirement,
TResource>`:

```csharp
if (document.TenantId.ToString() != user.FindFirst("tenant_id")?.Value) return Results.NotFound();
```

**Rules for claims:**

- A JWT is signed, **not encrypted** – anyone holding it can read it. No secrets, no unnecessary personal data.
- Every claim travels with every request: short permission codes, not long lists or documents. Hundreds of
  fine-grained rights belong in a lookup, not in the token.
- Claims come from your store only. SlimIdentity's own claims (`sub`, `email`, `amr`, `sid`, `act`, `iss`, `exp`, …)
  cannot be overwritten; `/auth/me` shows the others to the front end.

## Keeping claims current

Claims are a **snapshot**: they are built when a session is issued – sign-in, refresh, step-up. When you change a
user's roles, groups or permissions, tell SlimIdentity:

```csharp
await auth.RefreshClaimsAsync(user, ct);
```

| Session | Without `RefreshClaimsAsync` | With `RefreshClaimsAsync` | With `SignOutEverywhereAsync` |
| :--- | :--- | :--- | :--- |
| Cookie | old claims until the next sign-in | new claims at the next validation (`Cookies.SecurityStampValidationInterval`, default 1 minute) – no sign-out | signed out within the same interval |
| Bearer | old claims until the next refresh (≤ `AccessTokenLifetime`, default 15 minutes) | new claims on the **next request**; the refresh issues them into a new token – no sign-out | rejected on the next request |
| Links, refresh tokens, remembered devices | – | stay valid | invalidated |

How it works, and why it costs nothing: the security stamp carries a small *claims part*. Every session validation
loads the user anyway (that is how a password change or a ban ends sessions); a claims part that differs from the one
in the session means "reload the claims" – `GetClaimsAsync` runs only then, for that one user. As long as nothing
changed, no claims are reloaded.

Bearer tokens need `Tokens.ValidateSecurityStampOnEachRequest` (the default) for the immediate effect; without it they
get the new claims at their next refresh. A step-up window (`SudoFor`) survives a claims refresh; other claims added by
`ElevateSessionAsync` do not.

**Changing a group** affects all its members – call `RefreshClaimsAsync` for each (for large groups in a background
job). **Revoking everything at once** (suspected compromise, ban): `SignOutEverywhereAsync`.

**Rights that change constantly** or must never lag behind by even a request – check them live in an authorization
handler against your data instead of carrying them as claims. A [sign-in guard](hooks.md) can additionally refuse
running sessions as a whole (suspended tenant).

## Your own code and the stamp

The stamp is an opaque string of at most 64 characters (`<security part>.<claims part>`). If your code compares stamps
itself, use `SlimUser.IsSameSecurityState(a, b)` – it ignores the claims part. Store it as is; never parse it.
