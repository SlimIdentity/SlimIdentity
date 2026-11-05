# SPA with cookies

For browser front ends served from the same site as the API, an `HttpOnly` cookie is the most robust choice:
no token handling in JavaScript, nothing for XSS to read.

## Same origin or same site

```csharp
builder.Services.AddSlimIdentity(o =>
{
    o.Endpoints.DefaultUseCookies = true;   // or pass ?useCookies=true
    o.Endpoints.AllowJwtAuth = false;       // cookie-only: no JwtSecret needed
});
```

Every state-changing request (`POST`, `PUT`, `DELETE`, …) needs the header `X-CSRF` with any value. A cross-site page
cannot set custom headers without a CORS preflight, so this blocks CSRF – together with `SameSite=Strict`.

```ts
const api = (path: string, init: RequestInit = {}) =>
  fetch(path, { ...init, credentials: "include", headers: { "Content-Type": "application/json", "X-CSRF": "1", ...init.headers } });

await api("/auth/login?useCookies=true", { method: "POST", body: JSON.stringify({ email, password, rememberMe: true }) });
const me = await (await api("/auth/me")).json();   // restore state after F5
await api("/auth/logout", { method: "POST", body: "{}" });
```

A complete client is in [`samples/Frontend/slimIdentityClient.ts`](../../samples/Frontend/slimIdentityClient.ts).

## `app.example.com` → `api.example.com`

Both are the same *site*, but different *origins*:

```csharp
o.Cookies.SameSite = SameSiteMode.Lax;            // the cookie must be sent on cross-origin requests within the site
o.Cookies.Domain = ".example.com";                // optional: share the cookie between subdomains
o.Csrf.AllowedOrigins.Add("https://app.example.com");

builder.Services.AddCors(c => c.AddDefaultPolicy(p => p
    .WithOrigins("https://app.example.com")
    .AllowCredentials()
    .AllowAnyMethod()
    .WithHeaders("Content-Type", "X-CSRF")));
// app.UseCors() before UseAuthentication()
```

## Completely different sites

`app.foo.com` → `api.bar.net` needs `SameSite=None`, which browsers increasingly restrict (third-party cookies).
Use [bearer tokens](mobile-bearer.md) instead, or put the API behind the front end's domain (reverse proxy).

## Your own endpoints

Cookie-authenticated, state-changing host endpoints should require the same CSRF header:

```csharp
app.MapPost("/api/orders", CreateOrder).RequireAuthorization().RequireSlimCsrf();
```
