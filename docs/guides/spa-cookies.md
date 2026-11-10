# SPA with cookies

For browser front ends served from the same site as the API, an `HttpOnly` cookie is the most robust choice:
no token handling in JavaScript, nothing for XSS to read.

## Same origin or same site

```csharp
builder.Services.AddSlimIdentity(o =>
{
    // no Tokens.JwtSecret → cookie-only, and cookie mode is the default (no ?useCookies=true needed)
    o.Links.BaseUrl = "https://example.com";
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

A complete client is in [`samples/templates/Frontend/slimIdentityClient.ts`](../../samples/templates/Frontend/slimIdentityClient.ts).

## `app.example.com` → `api.example.com`

Both are the same *site*, but different *origins*:

```csharp
o.Cookies.SameSite = SameSiteMode.Lax;            // the cookie must be sent on cross-origin requests within the site
o.Cookies.Domain = ".example.com";                // optional: share the cookie between subdomains
o.Links.BaseUrl = "https://app.example.com";      // mail links – and this origin is trusted (CSRF Origin check)

builder.Services.AddSlimIdentity(…).AddCorsPolicy();   // CORS from the same trusted origins
app.UseCors(SlimIdentityDefaults.CorsPolicy);           // before UseAuthentication()
```

`AddCorsPolicy()` allows credentials for exactly the trusted origins (`TrustedOrigins`, `Links.BaseUrl`) and the
headers `Content-Type`, `Authorization` and `X-CSRF` – one list for CSRF, redirects and CORS. Never combine
credentials with `SetIsOriginAllowed(_ => true)`: every website could then call your API with the user's cookie.

## Completely different sites

`app.foo.com` → `api.bar.net` needs `SameSite=None`, which browsers increasingly restrict (third-party cookies).
Use [bearer tokens](mobile-bearer.md) instead, or put the API behind the front end's domain (reverse proxy).

## Your own endpoints

Cookie-authenticated, state-changing host endpoints should require the same CSRF header:

```csharp
app.MapPost("/api/orders", CreateOrder).RequireAuthorization().RequireSlimCsrf();
```
