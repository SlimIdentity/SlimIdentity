# Multi-tenancy

SlimIdentity has no tenant concept of its own – and needs none. Tenants live where your data lives: in your stores.
SlimIdentity adds four per-request decisions for tenants with their own domains, so one deployment can serve
`https://a.example.com` and `https://b.example.com` without trusting one tenant's front end on the other's API.

## 1. Data: scoped stores

Register your stores scoped and filter every query by the current tenant (resolved from the host name, a claim or
a header your gateway sets):

```csharp
public sealed class TenantUserStore(AppDbContext db, ITenantContext tenant) : ISlimUserStore
{
    public Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct) =>
        db.Users.Where(u => u.TenantId == tenant.Id && u.NormalizedEmail == …) …;
    public Task<SlimUser?> FindByIdAsync(string id, CancellationToken ct) =>
        db.Users.Where(u => u.TenantId == tenant.Id && u.Id == …) …;
    // CreateAsync sets TenantId; every other method filters the same way
}
```

With the EF Core package, a global query filter on your user entity (`HasQueryFilter(u => u.TenantId == …)`) does the
same for all stores.

What follows from it:

- **Unique per tenant or globally** – your choice, expressed by the unique index: `(TenantId, NormalizedEmail)` lets
  the same address have an account in each tenant; `NormalizedEmail` alone makes it global.
- **Claims:** add the tenant as a claim in `GetClaimsAsync`, so your endpoints can authorize by it.

## 2. Sessions: `UseTenantKey`

Scoped stores keep the *data* apart – not the *credentials*. Every tenant shares the cookie key ring, the JWT secret
and the audience, so a cookie or access token of tenant A also decrypts and validates at tenant B. With ids that
collide across tenants (`1`, `2`, … in each tenant database) or with an interval between security-stamp checks
(cookies: `SecurityStampValidationInterval`, default 1 minute; bearer: `ValidateSecurityStampOnEachRequest = false`)
it would be accepted there. Tell SlimIdentity how a request names its tenant:

```csharp
builder.Services.AddSlimIdentity(…)
    .AddUserStore<TenantUserStore>(ServiceLifetime.Scoped)
    .UseTenantKey(http => http.Request.Host.Host);   // or the tenant id your resolver puts on the request
```

Every cookie and access token then carries the tenant (`slim_tenant` claim). A credential presented to another tenant
is rejected on every request – before any interval or per-request switch applies – and a cookie is signed out. With
`UseTenantKey` the tokens stay in their tenant regardless of id collisions, intervals or validation switches. Keep the
key stable (a tenant id rather than an alias host name), or a renamed host signs its users out.

## 3. Origins: `ISlimOriginPolicy`

Which browser origins are trusted decides three things: the `Origin` check of cookie requests (CSRF), the `returnUrl`
after external login (open redirect) and – with `AddCorsPolicy()` – credentialed cross-origin calls. By default that
is `TrustedOrigins` plus the origin of `Links.BaseUrl`. With tenants, decide per request:

```csharp
public sealed class TenantOriginPolicy(TenantDirectory tenants) : ISlimOriginPolicy
{
    // origin arrives normalized: "https://a.example.com" (lower case, no trailing slash)
    public bool IsTrusted(HttpContext httpContext, string origin) =>
        tenants.FindByApiHost(httpContext.Request.Host.Host) is { } tenant && tenant.FrontEndOrigins.Contains(origin);
}

builder.Services.AddSlimIdentity(…)
    .AddOriginPolicy<TenantOriginPolicy>()      // replaces TrustedOrigins
    .AddCorsPolicy();                            // CORS from the same decision
app.UseCors(SlimIdentityDefaults.CorsPolicy);    // before the endpoints
```

The policy runs on every cookie request – keep it synchronous and in memory (a dictionary refreshed in the
background, not a database query).

## 4. Links: `ISlimLinkBuilder`

Mails, administrator reset links and invitations must lead to the tenant's own front end:

```csharp
public sealed class TenantLinkBuilder(TenantDirectory tenants) : ISlimLinkBuilder
{
    public string? BuildLink(SlimLinkKind kind, string token, HttpContext? httpContext)
    {
        if (httpContext is null || tenants.FindByApiHost(httpContext.Request.Host.Host) is not { } tenant) return null;
        var path = kind switch
        {
            SlimLinkKind.EmailVerification => "verify-email",
            SlimLinkKind.PasswordReset => "reset-password",
            SlimLinkKind.Invitation => "accept-invitation",
            _ => "confirm-email-change",
        };
        return $"{tenant.FrontEndOrigin}/{path}#token={Uri.EscapeDataString(token)}";
    }
}

.AddLinkBuilder<TenantLinkBuilder>()
```

`null` falls back to `Links.*`. Build links only from your own tenant directory: a `Host` header is attacker-controlled
unless `AllowedHosts` (or your proxy) restricts it – a reset link pointing to a foreign domain hands the token to that
domain's owner. Mails carry the tenant in their [context](../configuration.md#builder-methods) as well
(`AddEmailContextEnricher<T>()`), for branding.

## What stays global

- **A store per tenant with colliding ids** (`1`, `2`, … in every tenant database) is supported: links, codes and
  refresh tokens carry the user's security stamp, so a reset link or token of tenant A is refused by user `1` of
  tenant B (`TenantStoreTests`); cookies and access tokens are kept apart by `UseTenantKey` (section 2).
- **The mail limit per recipient** (3 mails per kind and 15 minutes, 5 for sign-in codes) counts per address across tenants – it protects
  the mailbox, which is the same.
- **Rate limiting** is per client IP. For a limit per tenant, use `.UseRateLimitPartitionKey(…)` with the tenant.
- **Signing keys** (`JwtSecret`, Data Protection) are shared; credentials are kept apart by `UseTenantKey` and the
  scoped stores, not by keys. Separate keys per tenant need separate deployments.
- **Options** (lockout, lifetimes, password rules) are the same for all tenants. A sign-in guard
  ([hooks](hooks.md)) can still refuse per tenant – e.g. a suspended tenant or an IP allow-list.
