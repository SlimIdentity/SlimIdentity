# LDAP and legacy passwords

`ISlimCustomPasswordValidator` replaces the built-in `PasswordHasher` check. Rate limiting, lockout, 2FA and sessions
stay the same.

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

The validator binds with the user's credentials over LDAPS
([`LdapPasswordValidator.cs`](../../samples/templates/Enterprise/LdapPasswordValidator.cs)). Return `false` on
infrastructure errors and log them; never allow anonymous binds (empty password).

Keep the three switches: a local change or reset would store a hash the directory check never reads. Invitations
cannot set a password (`400 password_managed_externally`). Every account counts as having a password, so sensitive
changes ask for it; to treat external-only accounts differently, override `HasPasswordAsync` (below).

## Migrating legacy hashes

```csharp
public sealed class LegacyHashMigrationValidator(IPasswordHasher<SlimUser> hasher, ISlimUserStore store) : ISlimCustomPasswordValidator
{
    public ValueTask<bool> HasPasswordAsync(SlimUser user, CancellationToken ct) =>
        ValueTask.FromResult(!string.IsNullOrEmpty(user.PasswordHash));

    public async Task<bool> ValidateAsync(SlimUser user, string password, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(user.PasswordHash)) return false;
        if (!user.PasswordHash.StartsWith("legacy:", StringComparison.Ordinal))
            return hasher.VerifyHashedPassword(user, user.PasswordHash, password) != PasswordVerificationResult.Failed;

        if (!VerifyLegacy(user.PasswordHash, password)) return false;   // your old algorithm, constant-time compare
        var upgraded = hasher.HashPassword(user, password);
        await store.UpdatePasswordHashAsync(user, user.PasswordHash, upgraded, ct); // only if unchanged meanwhile
        user.PasswordHash = upgraded;
        return true;
    }
}
```

Remove the validator once all active users have signed in. ASP.NET Core Identity hashes need no migration
([migrating from ASP.NET Core Identity](migrating-from-aspnet-identity.md)).
