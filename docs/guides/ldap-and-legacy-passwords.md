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
`System.DirectoryServices.Protocols` is in [`samples/templates/Enterprise/LdapPasswordValidator.cs`](../../samples/templates/Enterprise/LdapPasswordValidator.cs).
Return `false` on infrastructure errors and log them – never allow anonymous binds (empty password).

Invitations cannot set a password in this mode (`400 password_managed_externally`). Keep the three switches above:
a local password change or reset would store a hash the directory check never reads – the user would be told it worked.

Every account counts as having a password (in the directory), so sensitive changes ask for it. Accounts that sign in
only externally override `HasPasswordAsync` (below) and confirm such changes with a fresh sign-in instead.

## Migrating legacy hashes

The same interface can verify old hashes once and upgrade them in place:

```csharp
public sealed class LegacyHashMigrationValidator(IPasswordHasher<SlimUser> hasher, ISlimUserStore store) : ISlimCustomPasswordValidator
{
    // accounts without any hash (external login, passkeys only) have no password to ask for
    public ValueTask<bool> HasPasswordAsync(SlimUser user, CancellationToken ct) =>
        ValueTask.FromResult(!string.IsNullOrEmpty(user.PasswordHash));

    public async Task<bool> ValidateAsync(SlimUser user, string password, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(user.PasswordHash)) return false;
        if (!user.PasswordHash.StartsWith("legacy:", StringComparison.Ordinal))
            return hasher.VerifyHashedPassword(user, user.PasswordHash, password) != PasswordVerificationResult.Failed;

        if (!VerifyLegacy(user.PasswordHash, password)) return false;   // your old algorithm, constant-time compare
        var upgraded = hasher.HashPassword(user, password);              // upgrade to PBKDF2
        await store.UpdatePasswordHashAsync(user, user.PasswordHash, upgraded, ct); // only if unchanged meanwhile
        user.PasswordHash = upgraded;
        return true;
    }
}
```

Once all active users have signed in, remove the validator. Hashes created by ASP.NET Core Identity are already in the
`PasswordHasher` format and need no migration (see [Migrating from ASP.NET Core Identity](migrating-from-aspnet-identity.md)).
