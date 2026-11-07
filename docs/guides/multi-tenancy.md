# Multi-tenancy

SlimIdentity has no tenant concept of its own – and needs none. Tenants live where your data lives: in your stores.
SlimIdentity adds three per-request decisions for tenants with their own domains, so one deployment can serve
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

- **Tokens stay in their tenant.** Cookies, access and refresh tokens, reset and invitation links carry the user id;
  looked up in another tenant's scope the user does not exist, so they are rejected like a deleted account.
- **Unique per tenant or globally** – your choice, expressed by the unique index: `(TenantId, NormalizedEmail)` lets
  the same address have an account in each tenant; `NormalizedEmail` alone makes it global.
- **Claims:** add the tenant as a claim in `GetClaimsAsync`, so your endpoints can authorize by it.

## 2. Origins: `ISlimOriginPolicy`

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

## 3. Links: `ISlimLinkBuilder`

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

- **The mail limit per recipient** (3 mails per kind and 15 minutes) counts per address across tenants – it protects
  the mailbox, which is the same.
- **Rate limiting** is per client IP. For a limit per tenant, use `.UseRateLimitPartitionKey(…)` with the tenant.
- **Signing keys** (`JwtSecret`, Data Protection) are shared; tokens are kept apart by the scoped stores, not by keys.
  Separate keys per tenant need separate deployments.
- **Options** (lockout, lifetimes, password rules) are the same for all tenants. A sign-in guard
  ([hooks](hooks.md)) can still refuse per tenant – e.g. a suspended tenant or an IP allow-list.
