// SlimIdentity sample – EF Core persistence (PostgreSQL / SQLite / SQL Server)
// Copy into your project. Packages: Microsoft.EntityFrameworkCore + provider
// (Npgsql.EntityFrameworkCore.PostgreSQL or Microsoft.EntityFrameworkCore.Sqlite).
//
// Your own AppUser stays YOUR domain model – SlimIdentity only sees the mapped SlimUser.

using Microsoft.EntityFrameworkCore;

namespace MyApp.Data;

public class AppUser
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Email { get; set; } = "";
    public string NormalizedEmail { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string SecurityStamp { get; set; } = "";
    public bool IsActive { get; set; } = true;
    public bool EmailConfirmed { get; set; }
    public int FailedLoginAttempts { get; set; }
    public DateTimeOffset? LockoutEndUtc { get; set; }
    public bool TwoFactorEnabled { get; set; }
    public string? TotpSecret { get; set; }

    // --- your business data – SlimIdentity never sees it
    public string? DisplayName { get; set; }
    public Guid TenantId { get; set; }
    public List<AppUserRole> Roles { get; set; } = new();
}

public class AppUserRole
{
    public Guid UserId { get; set; }
    public string Role { get; set; } = "";
}

public class RefreshToken
{
    public string TokenHash { get; set; } = "";   // SHA-256 hex, primary key
    public Guid UserId { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
}

public class RecoveryCode
{
    public Guid UserId { get; set; }
    public string CodeHash { get; set; } = "";
}

public class ExternalLogin
{
    public string Provider { get; set; } = "";
    public string ProviderKey { get; set; } = "";
    public Guid UserId { get; set; }
}

public class ApiKey
{
    public string KeyHash { get; set; } = "";     // SlimApiKeys.Hash(key)
    public string ClientId { get; set; } = "";
    public string[] Scopes { get; set; } = [];
    public DateTimeOffset? ExpiresAt { get; set; }
    public bool Revoked { get; set; }
}

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<AppUserRole> UserRoles => Set<AppUserRole>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<RecoveryCode> RecoveryCodes => Set<RecoveryCode>();
    public DbSet<ExternalLogin> ExternalLogins => Set<ExternalLogin>();
    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<AppUser>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.NormalizedEmail).IsUnique();
            e.Property(x => x.Email).HasMaxLength(256);
            e.Property(x => x.NormalizedEmail).HasMaxLength(256);
            e.Property(x => x.SecurityStamp).HasMaxLength(64).IsConcurrencyToken();
            e.HasMany(x => x.Roles).WithOne().HasForeignKey(r => r.UserId);
        });
        b.Entity<AppUserRole>().HasKey(x => new { x.UserId, x.Role });
        b.Entity<RefreshToken>(e => { e.HasKey(x => x.TokenHash); e.HasIndex(x => x.UserId); });
        b.Entity<RecoveryCode>().HasKey(x => new { x.UserId, x.CodeHash });
        b.Entity<ExternalLogin>(e => { e.HasKey(x => new { x.Provider, x.ProviderKey }); e.HasIndex(x => x.UserId); });
        b.Entity<ApiKey>().HasKey(x => x.KeyHash);
    }
}
