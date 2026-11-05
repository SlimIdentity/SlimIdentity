# Mobile apps and bearer tokens

Native apps and cross-site SPAs use JWT access tokens plus rotating refresh tokens.

```csharp
builder.Services.AddSlimIdentity(o => o.Tokens.JwtSecret = secret)
    .AddUserStore<MyUserStore>()
    .AddEmailSender<MyEmailSender>()
    .AddRefreshTokenStore<MyRefreshTokenStore>()   // required for /refresh
    .AddSessionStore<MySessionStore>();            // recommended: per-device logout, precise reuse detection
```

## Flow

1. `POST /auth/login` → `accessToken` (15 min), `refreshToken` (7 days sliding, 30 days absolute).
2. Send `Authorization: Bearer <accessToken>`.
3. On `401`, call `POST /auth/refresh` with the refresh token → **new** pair. The old refresh token is now invalid.
4. `POST /auth/logout` with the refresh token (and the access token in the header) ends the session.

## Storage

- Mobile: refresh token in the platform's secure storage (Keychain / Android Keystore); access token in memory.
- Browser: access token in memory only; refresh token in `sessionStorage` at most – or prefer cookies for same-site SPAs.

## Refreshing correctly

Refresh tokens are **single use**. If two requests refresh the same token in parallel, the second one looks like a
replay and the session is revoked (reuse detection). Serialize refreshes in the client:

```ts
let refreshing: Promise<boolean> | null = null;
function refresh() {
  refreshing ??= doRefresh().finally(() => (refreshing = null));
  return refreshing;
}
```

If a refresh response is lost (network error), the client cannot retry with the old token – the user has to sign in
again. This is the intended trade-off of rotation.

## Why reuse detection matters

An attacker who steals a refresh token and uses it first gets a new pair; the legitimate client then presents the old
token. SlimIdentity recognizes this replay and revokes the whole token family (the session) – the attacker's tokens
included. Without a session store the family cannot be identified, so all sessions of the user end (security stamp
rotation). Disable with `Tokens.RevokeSessionsOnRefreshTokenReuse = false` only if you have a good reason.
