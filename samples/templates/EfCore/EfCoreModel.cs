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
    public string? TotpSecret { get; set; }            // encrypted by SlimIdentity
    public long? LastTwoFactorCodeAt { get; set; }     // replay protection (unix milliseconds)
    public long? LastTwoFactorChallengeAt { get; set; } // single-use sign-in challenge (unix milliseconds)

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

public class UserSession
{
    public string Id { get; set; } = "";          // 32 hex chars, primary key
    public Guid UserId { get; set; }
    public string Mode { get; set; } = "";
    public string AuthenticationMethod { get; set; } = "";
    public string? ImpersonatorId { get; set; }
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset LastSeenUtc { get; set; }
    public DateTimeOffset ExpiresUtc { get; set; }
    public string? UserAgent { get; set; }
    public string? IpAddress { get; set; }
}

/// <summary>Outbox row for guaranteed mail delivery (see samples/templates/Email/OutboxEmailSender.cs).</summary>
public class OutboxMail
{
    public long Id { get; set; }
    public string Kind { get; set; } = "";         // verification, password-reset, …
    public string To { get; set; } = "";
    public string Payload { get; set; } = "";      // link / code
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset? SentUtc { get; set; }
    public int Attempts { get; set; }
}

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<AppUserRole> UserRoles => Set<AppUserRole>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<RecoveryCode> RecoveryCodes => Set<RecoveryCode>();
    public DbSet<ExternalLogin> ExternalLogins => Set<ExternalLogin>();
    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();
    public DbSet<UserSession> Sessions => Set<UserSession>();
    public DbSet<OutboxMail> OutboxMails => Set<OutboxMail>();

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
        b.Entity<UserSession>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasMaxLength(32);
            e.Property(x => x.UserAgent).HasMaxLength(256);
            e.HasIndex(x => x.UserId);
            e.HasIndex(x => x.ExpiresUtc); // cleanup job: DELETE WHERE ExpiresUtc < now
        });
        b.Entity<OutboxMail>(e => { e.HasKey(x => x.Id); e.HasIndex(x => x.SentUtc); });
    }
}
