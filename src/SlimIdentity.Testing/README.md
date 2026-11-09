# SlimIdentity.Testing

Conformance checks for your [SlimIdentity](https://www.nuget.org/packages/SlimIdentity) store implementations.

SlimIdentity is a facade: it leaves your data in your database, behind interfaces you implement. A few of their
methods carry security guarantees – atomic counters, single-use tokens, unique addresses. Implemented naively,
everything still *works*, and the protection is silently gone. This package finds that out in one call.

```bash
dotnet add package SlimIdentity.Testing --prerelease   # in your test project
```

```csharp
[Fact]
public async Task Stores_honour_the_SlimIdentity_contracts()
{
    await using var services = new ServiceCollection()
        .AddDbContextFactory<AppDbContext>(o => o.UseNpgsql(TestDatabase.ConnectionString))
        .AddScoped<IdentityDb>()                                     // the template's own context per scope
        .AddScoped<ISlimUserStore, EfCoreUserStore>()
        .AddScoped<ISlimTwoFactorStore, EfCoreTwoFactorStore>()     // every registered store is checked
        .AddScoped<ISlimRefreshTokenStore, EfCoreRefreshTokenStore>()
        .AddSingleton(TimeProvider.System)
        .BuildServiceProvider();

    await SlimStoreConformance.VerifyAsync(services);   // throws with one line per violated rule
}
```

Works with xUnit, NUnit, MSTest or a console app – the package has no test-framework dependency.

## What is checked

| Store | Rules |
| :--- | :--- |
| `ISlimUserStore` | create / find; case-insensitive lookup; `CreateAsync` returns `null` for a taken address – also for parallel registrations; all security fields persisted; **parallel** `IncrementFailedLoginAttemptsAsync` counts every failure; bookkeeping never overwrites hash or stamp; conditional rehash; e-mail change refuses taken addresses |
| `ISlimTwoFactorStore` | TOTP secret stored unchanged (length!); recovery codes single use, per user, **also in parallel**; code and challenge markers monotonic, per user, **also in parallel**, on separate columns |
| `ISlimRefreshTokenStore` | single use, **also in parallel**; expired tokens rejected |
| `ISlimSessionStore` | round trip; touch; revoke one / all / all but current |
| `ISlimExternalLoginStore` | lookup by provider and key; list per user; remove only the user's own link |
| `ISlimPasskeyStore` | credential ids unique, **also in parallel**; `TryRecordUseAsync` single use per challenge and compare-and-set on the counter, **also in parallel**; list, rename and remove per user |

A failed run reads like this:

```
SlimIdentity store conformance: 21 of 22 checks passed.
  ...
  FAIL  ISlimUserStore: IncrementFailedLoginAttemptsAsync counts parallel failures atomically
          FailedLoginAttempts after 8 parallel increments: expected 8, got 3.
          fix: One statement: UPDATE users SET failed_login_attempts = failed_login_attempts + 1 …
```

## Important

- **Use a real database of the production kind** (a test instance or a container). In-memory providers do not
  enforce unique indexes or row locks – a green run there proves nothing about atomicity.
- Every operation resolves the store from a **new DI scope**, like a separate HTTP request – register your stores and
  their `DbContext` / connection as you do in the application.
- The checks create users under `@conformance.invalid` (configurable) and **do not delete them**. Never run them
  against production data.
- `SlimStoreConformance.RunAsync` returns the report without throwing, e.g. to print it.
