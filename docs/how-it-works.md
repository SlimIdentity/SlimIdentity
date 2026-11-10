# How SlimIdentity works

SlimIdentity is a **facade**. It does not invent security – it wires the building blocks that ASP.NET Core and .NET
already ship into a complete, hardened set of login flows, and it leaves the data where it belongs: in your database,
behind interfaces you implement.

## Who does what

| Concern | Done by |
| :--- | :--- |
| Password hashing | ASP.NET Core `PasswordHasher<T>` (PBKDF2) – the same as ASP.NET Core Identity |
| Cookies | ASP.NET Core cookie authentication |
| Access tokens | ASP.NET Core JWT bearer authentication (`Microsoft.IdentityModel`, HMAC-SHA256) |
| Encrypted links, refresh tokens, 2FA secrets | ASP.NET Core Data Protection |
| OAuth / OIDC | the regular ASP.NET Core remote handlers (Google, Entra ID, OpenID Connect, …) |
| Rate limiting | `Microsoft.AspNetCore.RateLimiting` |
| Random values, hashes, constant-time comparison | `RandomNumberGenerator`, `SHA256`, `CryptographicOperations.FixedTimeEquals` |
| **The flows** – login state machine, 2FA, lockout, rotation and reuse detection, enumeration resistance, CSRF rules, single-use links, session invalidation | **SlimIdentity** |
| Storing users, tokens, sessions | **your stores** |
| Sending mails | **your e-mail sender** |
| HTTPS, CORS, Data Protection key storage, the front end | **your application** |

**No custom cryptography.** SlimIdentity contains no cipher, no hash function and no signature scheme of its own. The
only algorithm it implements itself is the RFC 6238 TOTP calculation – a few lines on top of .NET's `HMACSHA1`,
verified against the RFC's test vectors. Everything secret-related is either encrypted by Data Protection or stored as
a SHA-256 hash, so a copy of your database yields no usable tokens, codes or 2FA secrets.

What SlimIdentity adds is the part that is easy to get wrong in hand-written login code: the *order* of checks, the
*uniformity* of answers, the *single use* of every token and code, and what happens when requests race each other.

## Your part: the stores

The library can only be as correct as the stores below it. Most store methods are ordinary reads and writes, but a
few carry a security guarantee – if they are implemented naively, everything still *works*, and the protection is
silently gone:

| Rule | If it is violated |
| :--- | :--- |
| `FindByEmailAsync` compares case-insensitively; the address column has a **unique index** | `Me@x.com` and `me@x.com` become two accounts; duplicate registrations |
| `CreateAsync` returns `null` when the address is taken (let the unique index decide) | concurrent registrations end in an error that reveals the account |
| `IncrementFailedLoginAttemptsAsync` is **one atomic statement** (`SET n = n + 1 … RETURNING n`) | parallel password guesses are not counted – the lockout can be bypassed |
| The sign-in bookkeeping methods touch **only their own columns** | a failed login can restore an old password hash after a password change |
| `UpdatePasswordHashAsync` writes only if the hash is unchanged | a rehash can undo a password change |
| Refresh tokens, recovery codes, 2FA codes and challenges are consumed **atomically** (`DELETE … RETURNING`, compare-and-set) | a stolen token or code can be used twice in parallel |
| Secrets are stored exactly as received | – (they arrive already hashed or encrypted; nothing to do but not to transform them) |

With EF Core, the `SlimIdentity.EntityFrameworkCore` package implements all of this for you – verified on SQLite,
PostgreSQL and SQL Server. Otherwise, the [samples](../samples) implement it for Dapper and EF Core – **copy them
instead of starting from scratch**. The complete rules are listed in the [samples README](../samples/README.md#rules-for-your-own-stores);
each interface member documents its contract in IntelliSense.

### Verify your stores

Whether you copied or wrote them: check them with **`SlimIdentity.Testing`** – one call in your test project, against
a real database of the production kind (a test instance or a container):

```bash
dotnet add package SlimIdentity.Testing --prerelease
```

```csharp
await using var services = new ServiceCollection()
    .AddDbContext<AppDbContext>(o => o.UseNpgsql(testDatabase))
    .AddScoped<ISlimUserStore, MyUserStore>()          // every registered store is checked
    .AddScoped<ISlimTwoFactorStore, MyTwoFactorStore>()
    .BuildServiceProvider();

await SlimStoreConformance.VerifyAsync(services);      // throws with one line per violated rule and a fix hint
```

It checks every rule above – including the parallel ones, by firing concurrent calls from separate DI scopes like
separate HTTP requests – and runs with any test framework. In-memory database providers enforce neither unique
indexes nor locks, so a green run there proves nothing; the checks create test users under `@conformance.invalid`
and never belong anywhere near production data. Details: [package README](../src/SlimIdentity.Testing/README.md).

The checks are not theory: run against the EF Core sample on SQLite, they found two bugs before the first release – a unique
violation from `ExecuteUpdate` that escaped as an exception, and GUIDs converted to upper-case text by the database,
which would have invalidated every session on SQL Server. Since then CI runs them against the EF Core samples on
SQLite, PostgreSQL and SQL Server and against the Dapper sample on PostgreSQL.

## Your part: the application

- **Data Protection key ring** persisted and shared between instances ([guide](guides/data-protection.md)) – it
  encrypts cookies, links, refresh tokens and 2FA secrets.
- **HTTPS** for browsers, and forwarded headers behind a proxy ([guide](guides/reverse-proxy.md)).
- **Secrets** (`JwtSecret`, mail credentials) from a secret store.
- **A real mail sender** with trustworthy sender domain (SPF/DKIM) and HTML-encoded templates.
- **The front end**: no XSS (Content Security Policy), CORS only for your own origins.

The full threat model – what is defended, how, and the known limitations – is in the [security model](security.md).
