# How SlimIdentity works

SlimIdentity wires the security building blocks of ASP.NET Core and .NET into complete login flows. The data stays in
your database, behind interfaces you implement.

## Who does what

| Concern | Done by |
| :--- | :--- |
| Password hashing | ASP.NET Core `PasswordHasher<T>` (PBKDF2), same format as ASP.NET Core Identity |
| Cookies / access tokens | ASP.NET Core cookie and JWT bearer authentication (HMAC-SHA256) |
| Encrypted links, refresh tokens, 2FA secrets | ASP.NET Core Data Protection |
| OAuth / OIDC | the regular ASP.NET Core remote handlers |
| Rate limiting | `Microsoft.AspNetCore.RateLimiting` |
| Random values, hashes, constant-time comparison | `RandomNumberGenerator`, `SHA256`, `CryptographicOperations.FixedTimeEquals` |
| The flows: sign-in steps, 2FA, lockout, token rotation and reuse detection, enumeration resistance, CSRF, single-use links, session invalidation | **SlimIdentity** |
| Storing users, tokens, sessions | **your stores** |
| Sending mails | **your e-mail sender** |
| HTTPS, CORS, Data Protection key storage, the front end | **your application** |

SlimIdentity contains no cryptography of its own except the RFC 6238 TOTP calculation on top of `HMACSHA1` (checked
against the RFC test vectors). Secrets are either encrypted with Data Protection or stored as SHA-256 hashes, so a copy
of the database yields no usable tokens, codes or 2FA secrets.

## Your part: the stores

Most store methods are plain reads and writes, but some carry a security guarantee. A naive implementation still
*works* – the protection is silently gone:

| Rule | If it is violated |
| :--- | :--- |
| `FindByEmailAsync` compares case-insensitively; the address column has a **unique index** | `Me@x.com` and `me@x.com` become two accounts |
| `CreateAsync` returns `null` when the address is taken (let the unique index decide) | concurrent registrations end in an error that reveals the account |
| `TryBeginAttemptAsync` reads and writes counter and lockout end in **one atomic step** (row lock or compare-and-set) | parallel guesses bypass the lockout |
| `UpdateSecurityStateAsync` never writes the attempt counters | an outdated copy of the user lifts a lockout |
| The sign-in bookkeeping methods touch **only their own columns** | a failed login restores an old password hash after a password change |
| `UpdatePasswordHashAsync` writes only if the hash is unchanged | a rehash undoes a password change |
| Refresh tokens, recovery codes, 2FA codes and challenges are consumed **atomically** (`DELETE … RETURNING`, compare-and-set) | a stolen token or code is used twice in parallel |
| Secrets are stored exactly as received | – (they arrive hashed or encrypted) |

The `SlimIdentity.EntityFrameworkCore` package implements all of this. Otherwise copy the Dapper or EF Core
[samples](../samples); the complete rules are in the [samples README](../samples/README.md#rules-for-your-own-stores)
and in the IntelliSense of each interface member.

### Verify your stores

`SlimIdentity.Testing` checks every rule above, including the concurrent ones, against a real database of the
production kind:

```csharp
// dotnet add package SlimIdentity.Testing --prerelease
await using var services = new ServiceCollection()
    .AddDbContext<AppDbContext>(o => o.UseNpgsql(testDatabase))
    .AddScoped<ISlimUserStore, MyUserStore>()          // every registered store is checked
    .AddScoped<ISlimTwoFactorStore, MyTwoFactorStore>()
    .BuildServiceProvider();

await SlimStoreConformance.VerifyAsync(services);      // throws with one line per violated rule and a fix hint
```

It runs with any test framework. In-memory database providers enforce neither unique indexes nor locks, so a green run
there proves nothing. The checks create users under `@conformance.invalid` – never run them against production data.
Details: [package README](../src/SlimIdentity.Testing/README.md).

## Your part: the application

See the [production checklist](minimal-setup.md#before-production) and the
[host responsibilities](security.md#host-responsibilities).
