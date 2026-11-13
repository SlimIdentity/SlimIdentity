# Running behind a reverse proxy

When a proxy or load balancer terminates TLS, the auth cookie still gets `Secure` (`CookieSecurePolicy.Always`). The
rest needs forwarded headers:

| Without `UseForwardedHeaders()` | Effect |
| :--- | :--- |
| `Request.Scheme` is `http` | CSRF origin check fails (`403 csrf_validation_failed` on cookie POSTs; log event 1004). |
| OAuth `redirect_uri` is `http://…` | The identity provider rejects the login. |
| `UseHttpsRedirection()` | Redirect loop, or `307` for POSTs. |
| `RemoteIpAddress` is the proxy | All users share one rate-limit bucket. |

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

- Only loopback proxies are trusted by default; ignored headers are logged once per proxy address (event 8001).
- `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` trusts **every** sender – only if the app is reachable solely via the proxy.
- The proxy must pass the original host (nginx `proxy_set_header Host $host;`) or `X-Forwarded-Host`, plus
  `X-Forwarded-For` / `X-Forwarded-Proto`.
- For the CSRF check alone, adding the public origin to `TrustedOrigins` also works.
- The demo reads `ReverseProxy:KnownProxies`, `KnownNetworks` and `AllowedHosts` from configuration
  ([`Program.cs`](../../samples/SlimIdentity.Demo/Program.cs)).
- If the proxy maps `https://example.com/api/` to the app root, use `app.UsePathBase("/api")` (or forward
  `X-Forwarded-Prefix`) so external-login callbacks are correct.

Several instances behind the proxy: [running several instances](multiple-instances.md).
