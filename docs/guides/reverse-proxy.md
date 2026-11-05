# Running behind a reverse proxy

Typical production setup: nginx, Traefik, an Azure/AWS load balancer or a Kubernetes ingress terminates TLS and talks
plain HTTP to the app.

## What works anyway

The auth cookie always gets the `Secure` flag (`CookieSecurePolicy.Always`), independent of the scheme the app sees.
The browser talks HTTPS to the proxy, so the cookie is sent normally.

## What needs forwarded headers

| Without `UseForwardedHeaders()` | Effect |
| :--- | :--- |
| `Request.Scheme` is `http` | CSRF origin check fails (`403 csrf_validation_failed` on every cookie POST). SlimIdentity logs a warning pointing at this. |
| OAuth `redirect_uri` is `http://…` | The identity provider rejects the login. |
| `UseHttpsRedirection()` | Redirect loop, or `307` for POSTs. |
| `RemoteIpAddress` is the proxy | All users share **one** rate-limit bucket – a handful of logins block everyone. |

```csharp
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    o.KnownProxies.Add(IPAddress.Parse("10.0.0.5"));                    // or:
    o.KnownIPNetworks.Add(System.Net.IPNetwork.Parse("10.0.0.0/8"));   // Docker/Kubernetes network of the proxy
    o.AllowedHosts.Add("api.example.com");                             // accepted X-Forwarded-Host values
});

var app = builder.Build();
app.UseForwardedHeaders();      // first – before UseHttpsRedirection, UseRateLimiter, UseAuthentication
```

- By default only **loopback** proxies are trusted. In Docker/Kubernetes the headers are otherwise **silently ignored**.
- `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` enables For + Proto but trusts **every** sender – only if the app is
  reachable exclusively through the proxy.
- The proxy must pass the original host (nginx: `proxy_set_header Host $host;`) or set `X-Forwarded-Host`, and set
  `X-Forwarded-For` / `X-Forwarded-Proto` (nginx: `proxy_set_header X-Forwarded-Proto $scheme;`).
- For the CSRF check alone, adding the public origin to `Csrf.AllowedOrigins` also works.
- The demo reads `ReverseProxy:KnownProxies`, `ReverseProxy:KnownNetworks` and `ReverseProxy:AllowedHosts` from
  configuration ([`samples/SlimIdentity.Demo/Program.cs`](../../samples/SlimIdentity.Demo/Program.cs)).

## Path prefixes

If the proxy maps `https://example.com/api/` to the app root, call `app.UsePathBase("/api")` (or forward
`X-Forwarded-Prefix`) so that external-login callback URLs are generated correctly.

## Multiple instances

- Persist the Data Protection key ring in a shared location (`PersistKeysToDbContext`, `PersistKeysToAzureBlobStorage`,
  `PersistKeysToStackExchangeRedis`, a shared volume, …) – otherwise a cookie or link from one instance is invalid on
  another, and all sessions are lost on restart.
- The built-in rate limiter is per instance. With N instances the effective limit is N × `PermitLimit`.
