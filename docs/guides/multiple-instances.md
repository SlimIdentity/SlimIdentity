# Running several instances

SlimIdentity needs **no sticky sessions**. Cookies, access tokens, mail links, flow tokens and remembered devices are
self-contained (Data Protection); users, lockout, refresh tokens, sessions, replay markers, single-use codes and mail
limits live in your stores and are updated atomically.

## Checklist

| | What | Why |
| :--- | :--- | :--- |
| 1 | **Shared Data Protection key ring** and the **same application name** | Otherwise instances cannot read each other's cookies, tokens and links. [Guide](data-protection.md) |
| 2 | **Same `Tokens.JwtSecret`** | Access tokens are signed with it. |
| 3 | **Shared database** for the stores | In-memory demo stores are per process. |
| 4 | **Forwarded headers** for the load balancer | Otherwise all clients share the balancer's rate-limit bucket, and scheme checks fail. [Guide](reverse-proxy.md) |
| 5 | **Synchronized clocks** (NTP) | 30 s of drift and more break TOTP and single-use markers. |
| 6 | **Shared state** (`ISlimSharedState`) | Single-use codes (exchange and link codes, logout tokens) and the per-recipient mail limit hold across instances. Registered by the EF Core package (table `SlimSharedState`); otherwise `AddSharedState<T>()`. |
| 7 | **Outbox** for durable mail | The built-in queue is in memory: drained on shutdown, lost on a crash. [Template](../../samples/templates/Email/OutboxEmailSender.cs) (at-least-once with retries; watch for rows it gave up on). |

```csharp
builder.Services.AddDataProtection()
    .PersistKeysToDbContext<AppDbContext>()        // Microsoft.AspNetCore.DataProtection.EntityFrameworkCore
    .SetApplicationName("my-app");
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))   // Tokens:JwtSecret from a secret store
    .AddEntityFrameworkStores<AppDbContext, AppUser, Guid>();
```

## Built-in diagnostics

Logged only; behaviour never changes:

| Event | When | Item |
| :--- | :--- | :--- |
| `8001` warning | `X-Forwarded-For` arrives but is not applied (once per proxy address) | 4 |
| `8002` warning | `Production` with local key storage (profile, registry, in-memory) | 1 |
| `8003` information | `Production` without an application name | 1 |
| `8004` information | `Production` with the in-memory shared state | 6 |
| `8005` warning | in-memory shared state full (200,000 entries): new codes rejected, new recipients get no mail until entries expire | 6 |
| `8006` error | `ISlimSharedState` throws: codes rejected, mail limits per instance until it recovers | 6 |

A single instance with locally persisted keys may ignore 8002–8004.

## Limits that are per instance

- **Rate limiting** (`RateLimit.*`) has buckets per instance: the effective limit is instances × `PermitLimit`. The
  account lockout counts in the database and applies across instances.
- **Without a shared state** single-use codes can be redeemed once per instance within their lifetime (exchange and
  link codes 1 minute and PKCE-bound, logout tokens 5 minutes), and the mail limit (3 per kind and 15 minutes, 5 for
  sign-in codes) multiplies.

For a hard global limit per client, limit at the gateway (nginx `limit_req`, Azure Front Door / Application Gateway
WAF, AWS WAF, Cloudflare). SlimIdentity ships no distributed request limiter.
