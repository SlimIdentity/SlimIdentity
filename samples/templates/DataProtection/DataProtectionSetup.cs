// SlimIdentity sample – persisting the Data Protection key ring.
//
// Data Protection encrypts SlimIdentity's cookies, refresh tokens, all mail links (verification, reset, invitation,
// e-mail change) and the TOTP secrets in your database. The default key ring lives in memory or in the user profile:
// in containers, on restart or with several instances every session and link breaks – and 2FA users would need their
// recovery codes. Persist it, protect it, and use the same application name everywhere.
//
// Pick ONE of the variants below:
//   builder.Services.AddDataProtectionInDatabase<AppDbContext>();               // EF Core (simple, works everywhere)
//   builder.Services.AddDataProtectionInRedis(redisConnectionString);           // Redis (many instances)
//   builder.Services.AddDataProtectionOnDisk("/keys", certificate);             // shared volume + certificate
//
// WARNING: the database and Redis variants store the keys UNENCRYPTED. With the database variant the keys sit next to
// the TOTP secrets they protect – a database dump or backup alone is enough to decrypt every 2FA secret and to forge
// cookies. For production add encryption at rest (.ProtectKeysWithCertificate(...), Azure Key Vault, or DPAPI on a
// single Windows server) to the returned builder, or at least keep the key table out of shared dumps and backups.
//
// Packages: Microsoft.AspNetCore.DataProtection.EntityFrameworkCore or Microsoft.AspNetCore.DataProtection.StackExchangeRedis

using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using StackExchange.Redis;

namespace MyApp.Security;

/// <summary>
/// Add this to your DbContext (or use a separate one): <c>public class AppDbContext : DbContext, IDataProtectionKeyContext</c>
/// with <c>public DbSet&lt;DataProtectionKey&gt; DataProtectionKeys =&gt; Set&lt;DataProtectionKey&gt;();</c> – then create a migration.
/// </summary>
public class KeyRingDbContext(DbContextOptions<KeyRingDbContext> options) : DbContext(options), IDataProtectionKeyContext
{
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();
}

public static class DataProtectionSetup
{
    // The application name isolates your keys and must be identical on every instance / deployment slot.
    private const string ApplicationName = "MyApp";

    /// <summary>
    /// Keys in your database, stored <b>unencrypted</b> next to the TOTP secrets they protect: a dump or backup of this
    /// database alone decrypts every 2FA secret. In production chain <c>.ProtectKeysWithCertificate(certificate)</c>
    /// (or Azure Key Vault / DPAPI) onto the result, and restrict database and backup access accordingly.
    /// </summary>
    public static IDataProtectionBuilder AddDataProtectionInDatabase<TContext>(this IServiceCollection services)
        where TContext : DbContext, IDataProtectionKeyContext =>
        services.AddDataProtection()
            .SetApplicationName(ApplicationName)
            .PersistKeysToDbContext<TContext>();

    /// <summary>
    /// Keys in Redis – for many instances. Stored <b>unencrypted</b>: protect the Redis instance (TLS, password, no public
    /// access) and, in production, chain <c>.ProtectKeysWithCertificate(certificate)</c> onto the result.
    /// </summary>
    public static IDataProtectionBuilder AddDataProtectionInRedis(this IServiceCollection services, string redisConnectionString) =>
        services.AddDataProtection()
            .SetApplicationName(ApplicationName)
            .PersistKeysToStackExchangeRedis(ConnectionMultiplexer.Connect(redisConnectionString), "DataProtection-Keys");

    /// <summary>
    /// Keys on a shared volume, encrypted at rest with a certificate (the private key must be available on every
    /// instance; keep the certificate when you renew it, via <c>UnprotectKeysWithAnyCertificate</c>).
    /// On Windows servers <c>.ProtectKeysWithDpapi()</c> is an alternative for a single machine.
    /// </summary>
    public static IDataProtectionBuilder AddDataProtectionOnDisk(this IServiceCollection services, string directory, X509Certificate2 certificate) =>
        services.AddDataProtection()
            .SetApplicationName(ApplicationName)
            .PersistKeysToFileSystem(new DirectoryInfo(directory))
            .ProtectKeysWithCertificate(certificate);
}
