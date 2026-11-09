// SlimIdentity sample – LDAP / Active Directory password check.
// Package: System.DirectoryServices.Protocols (cross-platform)
//
//   builder.Services.Configure<LdapSettings>(builder.Configuration.GetSection("Ldap"));
//   builder.Services.AddSlimIdentity(o =>
//       {
//           // the password lives in AD: a local change or reset would set a hash nobody ever checks
//           o.Endpoints.EnableChangePassword = false;
//           o.Endpoints.EnablePasswordReset = false;
//           o.Endpoints.EnableRegistration = false;
//       })
//       .AddUserStore<MyUserStore>()          // users still exist locally (lockout, 2FA, claims)
//       .AddCustomPasswordValidator<LdapPasswordValidator>();
//
// Brute-force protection, lockout and 2FA of SlimIdentity stay fully active.

using System.DirectoryServices.Protocols;
using System.Net;
using SlimIdentity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MyApp.Enterprise;

public sealed class LdapSettings
{
    public string Server { get; set; } = "dc01.corp.local";
    public int Port { get; set; } = 636;
    public bool UseSsl { get; set; } = true;
    /// <summary>e.g. "{0}@corp.local" (UPN) or "CORP\\{0}".</summary>
    public string BindFormat { get; set; } = "{0}";
}

public sealed class LdapPasswordValidator(IOptions<LdapSettings> settings, ILogger<LdapPasswordValidator> logger)
    : ISlimCustomPasswordValidator
{
    public Task<bool> ValidateAsync(SlimUser user, string providedPassword, CancellationToken ct)
    {
        var s = settings.Value;
        if (string.IsNullOrEmpty(providedPassword)) return Task.FromResult(false); // never allow anonymous binds

        return Task.Run(() =>
        {
            try
            {
                using var connection = new LdapConnection(new LdapDirectoryIdentifier(s.Server, s.Port));
                connection.SessionOptions.SecureSocketLayer = s.UseSsl;
                connection.SessionOptions.ProtocolVersion = 3;
                connection.AuthType = AuthType.Basic;
                connection.Timeout = TimeSpan.FromSeconds(5);
                connection.Bind(new NetworkCredential(string.Format(s.BindFormat, user.Email), providedPassword));
                return true;
            }
            catch (LdapException ex) when (ex.ErrorCode == 49) // invalid credentials
            {
                return false;
            }
            catch (LdapException ex)
            {
                logger.LogError(ex, "LDAP bind for {User} failed with an infrastructure error.", user.Email);
                return false;
            }
        }, ct);
    }
}

// ---------------------------------------------------------------------------------------
// Legacy hash migration with the same interface: verify old hash, then upgrade in place.
// ---------------------------------------------------------------------------------------
public sealed class LegacyMd5MigrationValidator(
    Microsoft.AspNetCore.Identity.IPasswordHasher<SlimUser> hasher,
    ISlimUserStore store) : ISlimCustomPasswordValidator
{
    public async Task<bool> ValidateAsync(SlimUser user, string providedPassword, CancellationToken ct)
    {
        if (!user.PasswordHash.StartsWith("md5:", StringComparison.Ordinal))
            return hasher.VerifyHashedPassword(user, user.PasswordHash, providedPassword)
                   != Microsoft.AspNetCore.Identity.PasswordVerificationResult.Failed;

        var legacy = Convert.ToHexStringLower(System.Security.Cryptography.MD5.HashData(System.Text.Encoding.UTF8.GetBytes(providedPassword)));
        if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(
                System.Text.Encoding.ASCII.GetBytes(legacy), System.Text.Encoding.ASCII.GetBytes(user.PasswordHash[4..])))
            return false;

        // upgrade to PBKDF2 – conditional, so a password change in the meantime is never undone
        var upgraded = hasher.HashPassword(user, providedPassword);
        await store.UpdatePasswordHashAsync(user, user.PasswordHash, upgraded, ct);
        user.PasswordHash = upgraded;
        return true;
    }
}
