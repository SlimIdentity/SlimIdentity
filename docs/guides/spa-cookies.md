# SPA with cookies

For browser front ends on the same site as the API, an `HttpOnly` cookie is the most robust choice: no token handling
in JavaScript, nothing for XSS to read.

## Same origin or same site

```csharp
builder.Services.AddSlimIdentity(o =>
{
    // no Tokens.JwtSecret → cookie-only, cookie mode is the default
    o.Links.BaseUrl = "https://example.com";
});
```

Every state-changing request needs the header `X-CSRF` (any value); with `SameSite=Strict` this blocks CSRF, since a
cross-site page cannot set custom headers without a CORS preflight.

```ts
const api = (path: string, init: RequestInit = {}) =>
  fetch(path, { ...init, credentials: "include", headers: { "Content-Type": "application/json", "X-CSRF": "1", ...init.headers } });

await api("/auth/login?useCookies=true", { method: "POST", body: JSON.stringify({ email, password, rememberMe: true }) });
const me = await (await api("/auth/me")).json();   // restore state after F5
await api("/auth/logout", { method: "POST", body: "{}" });
```

Complete client: [`slimIdentityClient.ts`](../../samples/templates/Frontend/slimIdentityClient.ts). Own
cookie-authenticated endpoints that change state add `.RequireSlimCsrf()`.

## `app.example.com` → `api.example.com`

Same *site*, different *origins*:

```csharp
o.Cookies.SameSite = SameSiteMode.Lax;            // sent on cross-origin requests within the site
o.Cookies.Domain = ".example.com";                // optional: share the cookie between subdomains
o.Links.BaseUrl = "https://app.example.com";      // mail links – and a trusted origin

builder.Services.AddSlimIdentity(…).AddCorsPolicy();
app.UseCors(SlimIdentityDefaults.CorsPolicy);           // before UseAuthentication()
```

`AddCorsPolicy()` allows credentials for exactly the trusted origins and the headers `Content-Type`, `Authorization`
and `X-CSRF`. Never combine credentials with `SetIsOriginAllowed(_ => true)`.

## Different sites

`app.foo.com` → `api.bar.net` needs `SameSite=None`, which browsers increasingly block. Use
[bearer tokens](mobile-bearer.md) or put the API behind the front end's domain.
