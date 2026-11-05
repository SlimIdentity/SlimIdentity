# LDAP and legacy passwords

`ISlimCustomPasswordValidator` replaces the built-in `PasswordHasher` check of `/login`. Everything else – rate
limiting, lockout, 2FA, sessions – stays the same.

## LDAP / Active Directory

```csharp
builder.Services.AddSlimIdentity(o =>
    {
        o.Endpoints.EnableChangePassword = false;    // the password lives in the directory
        o.Endpoints.EnablePasswordReset = false;
        o.Endpoints.EnableRegistration = false;
    })
    .AddUserStore<MyUserStore>()                     // users still exist locally (lockout, 2FA, roles)
    .AddCustomPasswordValidator<LdapPasswordValidator>();
```

The validator binds against the directory with the user's credentials (LDAPS); a complete implementation using
`System.DirectoryServices.Protocols` is in [`samples/Enterprise/LdapPasswordValidator.cs`](../../samples/Enterprise/LdapPasswordValidator.cs).
Return `false` on infrastructure errors and log them – never allow anonymous binds (empty password).

Invitations cannot set a password in this mode (`400 password_managed_externally`).

## Migrating legacy hashes

The same interface can verify old hashes once and upgrade them in place:

```csharp
public sealed class LegacyHashMigrationValidator(IPasswordHasher<SlimUser> hasher, ISlimUserStore store) : ISlimCustomPasswordValidator
{
    public async Task<bool> ValidateAsync(SlimUser user, string password, CancellationToken ct)
    {
        if (!user.PasswordHash.StartsWith("legacy:", StringComparison.Ordinal))
            return hasher.VerifyHashedPassword(user, user.PasswordHash, password) != PasswordVerificationResult.Failed;

        if (!VerifyLegacy(user.PasswordHash, password)) return false;   // your old algorithm, constant-time compare
        user.PasswordHash = hasher.HashPassword(user, password);        // upgrade to PBKDF2
        await store.UpdateSecurityStateAsync(user, ct);
        return true;
    }
}
```

Once all active users have signed in, remove the validator. Hashes created by ASP.NET Core Identity are already in the
`PasswordHasher` format and need no migration (see [Migrating from ASP.NET Core Identity](migrating-from-aspnet-identity.md)).
