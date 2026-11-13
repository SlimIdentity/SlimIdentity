// SlimIdentity sample – EF Core persistence (PostgreSQL / SQLite / SQL Server)
// Copy into your project. Packages: Microsoft.EntityFrameworkCore + provider
// (Npgsql.EntityFrameworkCore.PostgreSQL or Microsoft.EntityFrameworkCore.Sqlite).
//
// Your own AppUser stays YOUR domain model – SlimIdentity only sees the mapped SlimUser.

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

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
    public int FailedSecondFactorAttempts { get; set; }
    public DateTimeOffset? SecondFactorLockoutEndUtc { get; set; }
    public bool TwoFactorEnabled { get; set; }
    public bool PasswordChangeRequired { get; set; }   // set by an administrator, cleared by the next own password
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

// --- groups and permissions (your model – SlimIdentity only sees the resulting claims; see Enterprise/GroupEndpoints.cs)
public class Group
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid TenantId { get; set; }
    public string Name { get; set; } = "";
    public List<GroupPermission> Permissions { get; set; } = new();
}

public class GroupMember
{
    public Guid GroupId { get; set; }
    public Guid UserId { get; set; }
}

public class GroupPermission
{
    public Guid GroupId { get; set; }
    public string Permission { get; set; } = "";   // short codes: "reports.read", "invoices.approve"
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

public class UserPasskey
{
    public byte[] CredentialIdHash { get; set; } = [];   // SHA-256 of the credential id – the key (ids may be up to 1023 bytes)
    public byte[] CredentialId { get; set; } = [];
    public Guid UserId { get; set; }
    public byte[] PublicKey { get; set; } = [];          // COSE key; the private key never leaves the device
    public byte[]? UserHandle { get; set; }              // WebAuthn user handle (random, shared by the user's passkeys)
    public long SignCount { get; set; }
    public bool BackupEligible { get; set; }             // may be synced (iCloud Keychain, password manager) – fixed
    public bool BackedUp { get; set; }                   // currently synced, updated at every sign-in
    public long? LastChallengeAt { get; set; }           // each sign-in challenge counts once
    public string Name { get; set; } = "";
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset? LastUsedUtc { get; set; }
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

/// <summary>Outbox row for at-least-once mail delivery with retries (see samples/templates/Email/OutboxEmailSender.cs).</summary>
public class OutboxMail
{
    public long Id { get; set; }
    public string Kind { get; set; } = "";         // verification, password-reset, …
    public string To { get; set; } = "";
    public string Payload { get; set; } = "";      // link / code – erased once the mail is sent
    public string? UserId { get; set; }            // SlimEmailContext – persisted, the worker runs after the request
    public string Culture { get; set; } = "";
    public string ItemsJson { get; set; } = "{}";
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset? SentUtc { get; set; }
    public int Attempts { get; set; }
    public long NextAttemptAt { get; set; }        // unix milliseconds – exponential backoff
    public long? LockedUntil { get; set; }         // unix milliseconds – lease of the worker instance sending it
    public string? LastError { get; set; }         // why the last attempt failed (rows with Attempts = MaxAttempts were given up)
}

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<AppUserRole> UserRoles => Set<AppUserRole>();
    public DbSet<Group> Groups => Set<Group>();
    public DbSet<GroupMember> GroupMembers => Set<GroupMember>();
    public DbSet<GroupPermission> GroupPermissions => Set<GroupPermission>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<RecoveryCode> RecoveryCodes => Set<RecoveryCode>();
    public DbSet<ExternalLogin> ExternalLogins => Set<ExternalLogin>();
    public DbSet<UserPasskey> Passkeys => Set<UserPasskey>();
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
        b.Entity<Group>(e => { e.HasKey(x => x.Id); e.HasMany(x => x.Permissions).WithOne().HasForeignKey(p => p.GroupId); });
        b.Entity<GroupMember>(e =>
        {
            e.HasKey(x => new { x.GroupId, x.UserId });
            e.HasIndex(x => x.UserId);
            e.HasOne<Group>().WithMany().HasForeignKey(x => x.GroupId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<AppUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<GroupPermission>().HasKey(x => new { x.GroupId, x.Permission });
        // every identity row belongs to a user and goes with it: a deleted account leaves no external login behind
        // that would otherwise block the person's next sign-in with that provider
        b.Entity<RefreshToken>(e => { e.HasKey(x => x.TokenHash); e.HasIndex(x => x.UserId); OwnedByUser(e); });
        b.Entity<RecoveryCode>(e => { e.HasKey(x => new { x.UserId, x.CodeHash }); OwnedByUser(e); });
        b.Entity<ExternalLogin>(e => { e.HasKey(x => new { x.Provider, x.ProviderKey }); e.HasIndex(x => x.UserId); OwnedByUser(e); });
        b.Entity<UserPasskey>(e =>
        {
            e.HasKey(x => x.CredentialIdHash);
            e.Property(x => x.CredentialIdHash).HasMaxLength(32);
            e.Property(x => x.CredentialId).HasMaxLength(1023);
            e.Property(x => x.Name).HasMaxLength(64);
            e.Property(x => x.UserHandle).HasMaxLength(64);
            e.HasIndex(x => x.UserId);
            OwnedByUser(e);
        });
        b.Entity<ApiKey>().HasKey(x => x.KeyHash);
        b.Entity<UserSession>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Id).HasMaxLength(32);
            e.Property(x => x.UserAgent).HasMaxLength(256);
            e.HasIndex(x => x.UserId);
            e.HasIndex(x => x.ExpiresUtc); // cleanup job: DELETE WHERE ExpiresUtc < now
            OwnedByUser(e);
        });
        b.Entity<OutboxMail>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.LastError).HasMaxLength(500);
            e.HasIndex(x => new { x.SentUtc, x.NextAttemptAt });
        });
    }

    private static void OwnedByUser<T>(EntityTypeBuilder<T> e) where T : class =>
        e.HasOne<AppUser>().WithMany().HasForeignKey("UserId").OnDelete(DeleteBehavior.Cascade);
}
