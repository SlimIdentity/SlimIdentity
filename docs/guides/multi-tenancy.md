# Multi-tenancy

SlimIdentity has no tenant concept; tenants live in your stores. Four per-request decisions let one deployment serve
`https://a.example.com` and `https://b.example.com` without trusting one tenant's front end on the other's API.

## 1. Data: scoped stores

Register stores scoped and filter every query by the current tenant (host name, claim or gateway header):

```csharp
public sealed class TenantUserStore(AppDbContext db, ITenantContext tenant) : ISlimUserStore
{
    public Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct) =>
        db.Users.Where(u => u.TenantId == tenant.Id && u.NormalizedEmail == …) …;
    // CreateAsync sets TenantId; every other method filters the same way
}
```

With EF Core a global query filter (`HasQueryFilter(u => u.TenantId == …)`) does the same. The unique index decides
whether an address is unique per tenant (`(TenantId, NormalizedEmail)`) or globally. Add the tenant as a claim in
`GetClaimsAsync` to authorize by it.

## 2. Sessions: `UseTenantKey`

Scoped stores separate data, not credentials: all tenants share the key ring, the JWT secret and the audience, so with
colliding user ids or a security-stamp check interval a credential of tenant A would be accepted at tenant B. Name the
tenant of a request:

```csharp
builder.Services.AddSlimIdentity(…)
    .AddUserStore<TenantUserStore>(ServiceLifetime.Scoped)
    .UseTenantKey(http => http.Request.Host.Host);   // or the tenant id your resolver puts on the request
```

- Cookies and access tokens carry a `slim_tenant` claim; a credential presented to another tenant is rejected on every
  request (a cookie is signed out), independent of validation intervals.
- The tenant is part of the Data Protection purpose of every other token (mail links, invitations, flow tokens,
  refresh tokens, remembered devices, exchange codes, passkey states).
- Tokens issued outside a request carry no tenant and are only accepted outside every tenant – create invitations and
  reset links within a request of the tenant.
- Keep the key stable (a tenant id, not an alias host), or renaming a host signs its users out.

## 3. Origins: `ISlimOriginPolicy`

Trusted origins drive the CSRF `Origin` check, the external-login `returnUrl` and – with `AddCorsPolicy()` – CORS.
Default: `TrustedOrigins` plus the origin of `Links.BaseUrl`. Per tenant:

```csharp
public sealed class TenantOriginPolicy(TenantDirectory tenants) : ISlimOriginPolicy
{
    // origin arrives normalized: "https://a.example.com" (lower case, no trailing slash)
    public bool IsTrusted(HttpContext httpContext, string origin) =>
        tenants.FindByApiHost(httpContext.Request.Host.Host) is { } tenant && tenant.FrontEndOrigins.Contains(origin);
}

builder.Services.AddSlimIdentity(…)
    .AddOriginPolicy<TenantOriginPolicy>()      // replaces TrustedOrigins
    .AddCorsPolicy();
app.UseCors(SlimIdentityDefaults.CorsPolicy);
```

It runs on every cookie request – keep it synchronous and in memory.

## 4. Links: `ISlimLinkBuilder`

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
            _ => "accept-invitation",
        };
        return $"{tenant.FrontEndOrigin}/{path}#token={Uri.EscapeDataString(token)}";
    }
}

.AddLinkBuilder<TenantLinkBuilder>()
```

`null` falls back to `Links.*`. Build links only from your tenant directory – the `Host` header is attacker-controlled
unless `AllowedHosts` or the proxy restricts it. `AddEmailContextEnricher<T>()` adds tenant branding to the mail
context ([builder methods](../configuration.md#builder-methods)).

## What stays global

- **Separate stores with colliding ids** are supported: links, codes and refresh tokens carry the security stamp, and
  `UseTenantKey` binds every credential to its tenant.
- **Mail limit per recipient** (3 per kind and 15 minutes, 5 for sign-in codes) counts per address across tenants.
- **Rate limiting** is per client IP; use `.UseRateLimitPartitionKey(…)` for a per-tenant limit.
- **Keys** (`JwtSecret`, key ring) and **options** are shared; separate keys need separate deployments. A sign-in guard
  ([hooks](hooks.md)) can refuse per tenant.
