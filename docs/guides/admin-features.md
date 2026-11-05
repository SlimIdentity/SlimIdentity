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
        return result.Succeeded ? Results.Ok(result.ToResponse(DateTimeOffset.UtcNow)) : Results.BadRequest(result.Error);
    });

app.MapPost("/api/impersonation/stop", async (ISlimAuthManager auth, CancellationToken ct) =>
    (await auth.EndImpersonationAsync(ct)) is { Succeeded: true } r ? Results.Ok(r.ToResponse(DateTimeOffset.UtcNow)) : Results.Unauthorized())
    .RequireAuthorization().RequireSlimCsrf();
```

- The session belongs to the target user; the admin is kept in the RFC 8693 `act` claim (`User.GetImpersonatorId()`,
  `/auth/me` → `isImpersonating`). Log it for your audit trail.
- The `act` claim contains the admin's security stamp: banning the admin or signing them out everywhere ends the
  impersonation immediately. `EndImpersonationAsync` checks it again before signing the admin back in.
- Never persistent, no refresh token. Password change, 2FA changes, `/logout-all` and session management are blocked
  during impersonation.
- Consider requiring sudo mode (below) before impersonating.

## Step-up ("sudo") mode

Re-confirm the password before dangerous actions:

```csharp
app.MapPost("/api/sudo", async (SudoRequest req, ClaimsPrincipal me, ISlimUserStore store,
        IPasswordHasher<SlimUser> hasher, ISlimAuthManager auth, CancellationToken ct) =>
    {
        var user = await store.FindByIdAsync(me.GetSlimUserId()!, ct);
        if (user is null || hasher.VerifyHashedPassword(user, user.PasswordHash, req.Password) == PasswordVerificationResult.Failed)
            return Results.BadRequest();
        var result = await auth.ElevateSessionAsync(user, [SlimClaims.SudoFor(TimeSpan.FromMinutes(10))], me.IsSlimCookieSession(), ct);
        return Results.Ok(result.ToResponse(DateTimeOffset.UtcNow));
    })
    .RequireAuthorization().RequireSlimCsrf().RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);

app.MapDelete("/api/account", DeleteAccount).RequireAuthorization(SlimIdentityDefaults.SudoPolicy);
```

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
null). Protect M2M endpoints with `.RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = SlimIdentityDefaults.ApiKeyScheme })`
or rely on the default policy scheme, which forwards requests with an `X-API-Key` header to the API-key handler.
