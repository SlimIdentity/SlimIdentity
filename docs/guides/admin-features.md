# Admin features

All of these are built with `ISlimAuthManager` in your own endpoints, protected by your own policies.
A complete example is [`samples/templates/Enterprise/AdminEndpoints.cs`](../../samples/templates/Enterprise/AdminEndpoints.cs).

## Impersonation

```csharp
admin.MapPost("/impersonate/{userId}", async (string userId, ClaimsPrincipal me, ISlimUserStore store,
        ISlimAuthManager auth, CancellationToken ct) =>
    {
        var target = await store.FindByIdAsync(userId, ct);
        if (target is null) return Results.NotFound();
        var result = await auth.ImpersonateAsync(target, me.GetSlimUserId()!, me.IsSlimCookieSession(), ct);
        return result.Succeeded ? Results.Ok(result.ToResponse()) : Results.BadRequest(result.Error);
    });

app.MapPost("/api/impersonation/stop", async (ISlimAuthManager auth, CancellationToken ct) =>
    (await auth.EndImpersonationAsync(ct)) is { Succeeded: true } r ? Results.Ok(r.ToResponse()) : Results.Unauthorized())
    .RequireAuthorization().RequireSlimCsrf();
```

- The session belongs to the target user; the admin is kept in the RFC 8693 `act` claim (`User.GetImpersonatorId()`,
  `/auth/me` → `isImpersonating`). Log it for your audit trail.
- The `act` claim contains the admin's security stamp: banning the admin or signing them out everywhere ends the
  impersonation immediately. `EndImpersonationAsync` checks it again before signing the admin back in – into the
  admin's own sign-in (its `auth_time` and absolute lifetime), not a fresh session chain.
- Never persistent, no refresh token. Password change, 2FA changes, `/logout-all` and session management are blocked
  during impersonation.
- Consider requiring sudo mode (below) before impersonating.

## Step-up ("sudo") mode

Re-confirm the password before dangerous actions:

```csharp
app.MapPost("/api/sudo", async (SudoRequest req, ClaimsPrincipal me, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
    {
        var user = await store.FindByIdAsync(me.GetSlimUserId()!, ct);
        if (user is null) return Results.Unauthorized();
        if (await auth.ConfirmPasswordAsync(user, req.Password, ct) is { } failure) return failure;   // 400 / 423
        var result = await auth.ElevateToSudoAsync(user, TimeSpan.FromMinutes(10), me.IsSlimCookieSession(), ct);
        return Results.Ok(result.ToResponse());
    })
    .RequireAuthorization().RequireSlimCsrf().RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);

app.MapDelete("/api/account", DeleteAccount).RequireAuthorization(SlimIdentityDefaults.SudoPolicy);
```

`ConfirmPasswordAsync` applies the rules of the built-in endpoints: an active lockout is honoured, wrong passwords
count towards it (with the lockout notification), parallel guesses are serialized and an
`ISlimCustomPasswordValidator` (LDAP, legacy hashes) is used. Never verify the password with `IPasswordHasher`
yourself – a stolen session could then guess it without limit. `ElevateSessionAsync` only accepts the signed-in user
of the request.

## Passwords, reset links, 2FA reset, unlock

`ISlimAuthManager` has the administrator's tools for accounts whose owners cannot help themselves – essential on hosts
without mail: `CreatePasswordResetAsync` (a link the user sets the password with), `SetPasswordAsync` (a start
password, by default with a forced change at the next sign-in), `ResetTwoFactorAsync` and `UnlockAsync`. See
[running without e-mail](without-email.md); endpoints for all of them are in the admin template.

## Changing roles and permissions

After changing a user's roles, groups or permissions in your data, call `await auth.RefreshClaimsAsync(user, ct)`:
running sessions pick up the new claims at their next validation, without a sign-out –
[roles and permissions](roles-and-permissions.md).

## Banning a user

```csharp
await auth.SignOutEverywhereAsync(user, ct);   // ends all sessions and tokens immediately
// then set IsActive = false in your store
```

Inactive users cannot sign in (they get the same answer as for a wrong password by default).

## API keys (machine-to-machine)

```csharp
.AddApiKeyStore<MyApiKeyStore>()

var (key, hash) = SlimApiKeys.Generate("sk");   // show `key` once, store only `hash`
```

Clients send `X-API-Key: sk_…`; `ISlimApiKeyStore.ValidateApiKeyAsync(hash)` returns the claims of the client (or
null).

**A few fixed clients, no database:** configure the hashes and let SlimIdentity read them.

```bash
dotnet run tools/new-api-key.cs -- reports   # prints the key (for the client) and its hash (for you)
```

```json
"SlimIdentity": {
  "ApiKeys": [
    { "ClientId": "reports", "Hash": "63a5fd58…", "Scopes": [ "reports:read" ], "ExpiresUtc": "2027-06-30T00:00:00Z" }
  ]
}
```

```csharp
.AddConfigurationApiKeys(builder.Configuration.GetSection("SlimIdentity:ApiKeys"))
```

The principal's `sub` is `client:{ClientId}`, scopes become `scope` claims, roles `role` claims. Entries are validated
at startup (a key pasted instead of its hash stops the start) and followed on reload – remove or change an entry to
revoke a key. Keep the hashes out of source control like any other credential material.

**Machine-to-machine only:** an API that has no users at all needs neither a user store nor a mail sender – call
`AddSlimIdentity()` with `AddConfigurationApiKeys(…)` (or `AddApiKeyStore<T>()`), leave out `MapSlimIdentityApi()`, and
protect the endpoints with the API-key scheme as shown below. Protect M2M endpoints with `.RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = SlimIdentityDefaults.ApiKeyScheme })`
or rely on the default policy scheme, which forwards requests with an `X-API-Key` header to the API-key handler.
