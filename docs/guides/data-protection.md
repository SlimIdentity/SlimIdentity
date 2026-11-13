# Data Protection key ring

Data Protection encrypts and signs auth cookies, refresh tokens, mail links, flow and setup tokens, and the TOTP
secrets in your database. Its default key storage (memory or user profile) is fine for development only: a restart or
new container signs everyone out, invalidates mailed links and makes TOTP secrets unreadable (users need recovery
codes); several instances reject each other's cookies and links.

## Setup

Variants to copy: [`DataProtectionSetup.cs`](../../samples/templates/DataProtection/DataProtectionSetup.cs).

```csharp
// EF Core (Microsoft.AspNetCore.DataProtection.EntityFrameworkCore)
builder.Services.AddDataProtection()
    .SetApplicationName("MyApp")
    .PersistKeysToDbContext<AppDbContext>()          // AppDbContext : IDataProtectionKeyContext
    .ProtectKeysWithCertificate(certificate);

// instead of PersistKeysToDbContext – Redis (Microsoft.AspNetCore.DataProtection.StackExchangeRedis) or a volume:
//  .PersistKeysToStackExchangeRedis(ConnectionMultiplexer.Connect(redis), "DataProtection-Keys")
//  .PersistKeysToFileSystem(new DirectoryInfo("/keys"))
```

## Rules

- **Encrypt the keys at rest** (`ProtectKeysWithCertificate`, Azure Key Vault, DPAPI on a single Windows server).
  EF Core and Redis store them unencrypted; with EF Core next to the TOTP secrets, a database dump alone decrypts every
  2FA secret and forges cookies. After certificate renewal keep the old one (`UnprotectKeysWithAnyCertificate`).
  Without encryption, at least restrict access to the key table and backups.
- **Same application name** (`SetApplicationName`) on every instance and deployment slot.
- **Back up** the key ring with the database.
- Keys rotate automatically (90 days); never delete old ones.

See also the [ASP.NET Core documentation](https://learn.microsoft.com/aspnet/core/security/data-protection/configuration/overview).
