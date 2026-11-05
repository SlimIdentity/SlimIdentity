# Data Protection key ring

ASP.NET Core Data Protection encrypts and signs everything SlimIdentity hands out or stores:

- auth cookies,
- refresh tokens,
- verification, reset, invitation and e-mail-change links, 2FA pre-auth and setup tokens,
- TOTP secrets in your database.

By default the key ring lives in memory or in the user profile. That is fine on a developer machine, but in production:

| Situation | Consequence without persisted keys |
| :--- | :--- |
| Restart / new container | All users are signed out, all links in sent mails are invalid, TOTP secrets cannot be decrypted (users need recovery codes). |
| Several instances | A cookie or link created on one instance is rejected by the others. |

## Setup

Ready-to-copy variants are in [`samples/templates/DataProtection`](../../samples/templates/DataProtection/DataProtectionSetup.cs):

```csharp
// EF Core – simplest, works everywhere (package Microsoft.AspNetCore.DataProtection.EntityFrameworkCore)
builder.Services.AddDataProtection()
    .SetApplicationName("MyApp")
    .PersistKeysToDbContext<AppDbContext>();          // AppDbContext : IDataProtectionKeyContext

// Redis – many instances (package Microsoft.AspNetCore.DataProtection.StackExchangeRedis)
builder.Services.AddDataProtection()
    .SetApplicationName("MyApp")
    .PersistKeysToStackExchangeRedis(ConnectionMultiplexer.Connect(redis), "DataProtection-Keys");

// Shared volume, encrypted at rest with a certificate
builder.Services.AddDataProtection()
    .SetApplicationName("MyApp")
    .PersistKeysToFileSystem(new DirectoryInfo("/keys"))
    .ProtectKeysWithCertificate(certificate);
```

## Rules

- **Same application name everywhere** (`SetApplicationName`) – otherwise instances or deployment slots cannot read
  each other's data.
- **Protect the keys:** whoever has the key ring can forge cookies and decrypt TOTP secrets. Restrict access to the
  table / Redis / volume, and encrypt at rest (`ProtectKeysWithCertificate`, Azure Key Vault, DPAPI on Windows).
- **Back it up** together with the database – a restored database without its key ring cannot decrypt the 2FA secrets.
- Keys rotate automatically (default 90 days); old keys are kept for decryption. Do not delete them manually.

Further reading: [ASP.NET Core Data Protection configuration](https://learn.microsoft.com/aspnet/core/security/data-protection/configuration/overview).
