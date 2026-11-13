# Admin features

All of these are built with `ISlimAuthManager` in your own endpoints, behind your own policies (complete example:
[`AdminEndpoints.cs`](../../samples/templates/Enterprise/AdminEndpoints.cs)). The account tools – `CreateUserAsync`,
`CreatePasswordResetAsync`, `SetPasswordAsync`, `ResetTwoFactorAsync`, `UnlockAsync` – are listed in
[running without e-mail](without-email.md#the-administrators-tools).

## Impersonation

```csharp
admin.MapPost("/impersonate/{userId}", async (string userId, ISlimUserStore store,
        ISlimAuthManager auth, CancellationToken ct) =>
    {
        var target = await store.FindByIdAsync(userId, ct);
        if (target is null) return Results.NotFound();
        var result = await auth.ImpersonateAsync(target, ct);   // the signed-in admin, in the mode of their session
        return result.Succeeded ? Results.Ok(result.ToResponse()) : Results.BadRequest(result.Error);
    });

app.MapPost("/api/impersonation/stop", async (ISlimAuthManager auth, CancellationToken ct) =>
    (await auth.EndImpersonationAsync(ct)) is { Succeeded: true } r ? Results.Ok(r.ToResponse()) : Results.Unauthorized())
    .RequireAuthorization().RequireSlimCsrf();
```

- The session belongs to the target user; the admin is kept in the RFC 8693 `act` claim (`User.GetImpersonatorId()`,
  `/auth/me` → `isImpersonating`). Log it for your audit trail.
- `act` carries the admin's security stamp and – with `ISlimSessionStore` – the admin's session: banning the admin,
  signing them out everywhere or revoking that session ends the impersonation. `EndImpersonationAsync` checks both
  again and resumes that session (its `auth_time` and absolute lifetime).
- Never persistent, no refresh token. Password change, 2FA changes, `/logout-all` and session management are blocked.
- Errors: `impersonator_invalid`, `already_impersonating`, `cannot_impersonate_self`. Consider sudo mode first.

## Step-up ("sudo") mode

```csharp
app.MapPost("/api/sudo", async (SudoRequest req, ClaimsPrincipal me, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
    {
        var user = await store.FindByIdAsync(me.GetSlimUserId()!, ct);
        if (user is null) return Results.Unauthorized();
        if (await auth.ConfirmPasswordAsync(user, req.Password, ct) is { } failure) return failure;   // 400 / 423 / 403
        var result = await auth.ElevateToSudoAsync(user, TimeSpan.FromMinutes(10), ct);           // ≤ 1 hour
        return result.Succeeded ? Results.Ok(result.ToResponse()) : Results.Json(new { status = result.Error }, statusCode: 403);
    })
    .RequireAuthorization().RequireSlimCsrf().RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);

app.MapDelete("/api/account", DeleteAccount).RequireAuthorization(SlimIdentityDefaults.SudoPolicy);
```

`ConfirmPasswordAsync` applies the rules of the built-in endpoints: lockout, counting failures, serialized parallel
attempts, `ISlimCustomPasswordValidator`; accounts without a password need a sign-in within 5 minutes. Never verify
the password with `IPasswordHasher` yourself – a stolen session could guess without limit. `ElevateToSudoAsync` and
`ElevateSessionAsync` (additional temporary claims) accept only the signed-in user of the request.

## Roles, bans

After changing roles or permissions call `RefreshClaimsAsync(user)` ([roles and permissions](roles-and-permissions.md)).
To ban: `SignOutEverywhereAsync(user)`, then set `IsActive = false` in your store; inactive users get the
wrong-password answer by default.

## API keys (machine-to-machine)

```csharp
.AddApiKeyStore<MyApiKeyStore>()

var (key, hash) = SlimApiKeys.Generate("sk");   // show `key` once, store only `hash`
```

Clients send `X-API-Key: sk_…`; `ISlimApiKeyStore.ValidateApiKeyAsync(hash)` returns the client's claims (or null).

**A few fixed clients, no database:** `dotnet run tools/new-api-key.cs -- reports` prints a key and its hash.

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

`sub` is `client:{ClientId}`, scopes become `scope` claims, roles `role` claims. Entries are validated at startup (a
key pasted instead of its hash stops the start) and followed on reload – change or remove an entry to revoke. Keep the
hashes out of source control.

An API without users needs neither user store nor mail sender: `AddSlimIdentity()` with `AddConfigurationApiKeys(…)`
or `AddApiKeyStore<T>()`, no `MapSlimIdentityApi()`. Protect endpoints with
`.RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = SlimIdentityDefaults.ApiKeyScheme })`, or rely
on the default policy scheme, which forwards requests with `X-API-Key` to the API-key handler.
