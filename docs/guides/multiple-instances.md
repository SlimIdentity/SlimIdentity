# Running several instances

SlimIdentity needs **no sticky sessions**. Cookies, access tokens, mail links, 2FA challenges and "remember this
device" tokens are self-contained (signed and encrypted with Data Protection); everything stateful – users, lockout,
refresh tokens, sessions, replay markers – lives in your database and is updated atomically. Any instance can serve any
request.

This is not just a claim: `tests/SlimIdentity.Tests/Integration/MultiInstanceTests.cs` runs two separate hosts on one
database and proves that a cookie from instance A works on B, that a refresh token rotated on B and replayed on A
revokes the session, that a 2FA challenge issued on A is completed once on B, that a reset link from A works once on B,
and that "sign out everywhere" on A ends sessions on B immediately.

## Checklist

| | What | Why |
| :--- | :--- | :--- |
| 1 | **Share the Data Protection key ring** and set the **same application name** everywhere | Otherwise B cannot read A's cookies, tokens and links: random sign-outs, "invalid" links, refresh tokens rejected. Keys are isolated by the content-root path unless `SetApplicationName` is used. [Guide](data-protection.md) |
| 2 | Use the **same `Tokens.JwtSecret`** on every instance | Access tokens are signed with it. |
| 3 | Use a **shared database** for the stores | The in-memory stores of the demo are per process. The EF Core package and the templates use your database. |
| 4 | Configure **forwarded headers** for your load balancer | Otherwise every client appears with the balancer's address: one shared rate-limit bucket for everybody (a few failed logins block all users), wrong scheme for CSRF and OAuth. [Guide](reverse-proxy.md) |
| 5 | Keep the **clocks in sync** (NTP) | TOTP codes, token lifetimes and single-use markers compare times issued by different machines. Seconds of drift are tolerated; 30 s and more break 2FA. |
| 6 | Register a **refresh-token store** when you use external login | It also makes the one-time exchange codes single-use across instances (the EF Core package registers it by default). |
| 7 | For durable mail delivery use an **outbox** | The built-in mail queue is in memory: drained on a regular shutdown, lost on a crash. The outbox survives crashes and delivers at least once, with retries over several hours – not guaranteed: watch for rows it gave up on. [Template](../../samples/templates/Email/OutboxEmailSender.cs) |

```csharp
// 1 + 2: one key ring, one name, one secret – e.g. in your database
// (package Microsoft.AspNetCore.DataProtection.EntityFrameworkCore; Redis, Azure Blob etc. in the Data Protection guide)
builder.Services.AddDataProtection()
    .PersistKeysToDbContext<AppDbContext>()
    .SetApplicationName("my-app");
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))   // Tokens:JwtSecret from a secret store
    .AddEntityFrameworkStores<AppDbContext, AppUser, Guid>();

// 4: trust exactly your balancer / ingress network
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownIPNetworks.Add(System.Net.IPNetwork.Parse("10.0.0.0/8"));
});
var app = builder.Build();
app.UseForwardedHeaders();   // first in the pipeline
```

## Built-in diagnostics

SlimIdentity reports the typical mistakes in the log – it never changes behaviour because of them:

| Event | When | Meaning |
| :--- | :--- | :--- |
| `8001` warning | a request still carries `X-Forwarded-For` that was not applied (once per proxy address) | Forwarded headers missing or the proxy is not trusted – see checklist item 4. |
| `8002` warning | start in `Production` with the framework's local key storage (user profile, registry, in-memory) | Key ring not shared and lost with the container – item 1. |
| `8003` information | start in `Production` without an application name | Keys are isolated by path – item 1. Harmless for one instance. |
| `8004` warning | start in `Production` with external login but no refresh-token store | Exchange codes single-use per instance only – item 6. |

A single instance with locally persisted keys is a valid setup – then 8002/8003 can be ignored.

## Limits that are per instance

- **Rate limiting** (`RateLimit.*`): every instance has its own buckets, so the effective limit is
  instances × `PermitLimit`. The protection that matters most is not affected: the **account lockout** counts failures
  in the database and applies across all instances (also proven by `MultiInstanceTests`).
- **Mail limit per recipient** (3 per kind and 15 minutes, 5 for 2FA codes): likewise per instance.

If you need a hard global limit per client, put it in front of the instances – the gateway sees every request:

```nginx
# nginx: 10 requests per minute and client on the auth endpoints, short burst allowed
limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/m;
location /auth/ { limit_req zone=auth burst=5 nodelay; proxy_pass http://app; }
```

Managed load balancers offer the same (Azure Front Door / Application Gateway WAF rate-limit rules, AWS WAF
rate-based rules, Cloudflare rate limiting). SlimIdentity deliberately ships no distributed limiter: a shared cache has
no atomic counters, the result would be approximate, and it would add a dependency for a job the gateway does better.
