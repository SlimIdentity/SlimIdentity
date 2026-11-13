# Mobile apps and bearer tokens

Native apps and cross-site SPAs use JWT access tokens plus rotating refresh tokens.

```csharp
builder.Services.AddSlimIdentity(o => o.Tokens.JwtSecret = secret)
    .AddUserStore<MyUserStore>()
    .AddEmailSender<MyEmailSender>()
    .AddRefreshTokenStore<MyRefreshTokenStore>()   // required for /refresh
    .AddSessionStore<MySessionStore>();            // recommended: per-device logout, precise reuse detection
```

1. `POST /auth/login` → `accessToken` (15 min), `refreshToken` (7 days sliding, 30 days absolute).
2. Send `Authorization: Bearer <accessToken>`.
3. On `401`, `POST /auth/refresh { refreshToken }` → a **new** pair; the old refresh token is invalid.
4. `POST /auth/logout` with the refresh token (and the access token in the header) ends the session.

Storage: on mobile, the refresh token in Keychain / Android Keystore and the access token in memory. In browsers the
access token in memory and the refresh token in web storage – or, for same-site SPAs, [cookies](spa-cookies.md).

## Refreshing correctly

Refresh tokens are **single use**, without a grace period. A second refresh with the same token looks like theft: the
whole token family (the session) is revoked – without a session store, all sessions of the user. A lost refresh
response cannot be retried; the user signs in again. Serialize refreshes in the client.

**One app instance:** share one in-flight promise.

```ts
let refreshing: Promise<boolean> | null = null;
function refresh() {
  refreshing ??= doRefresh().finally(() => (refreshing = null));
  return refreshing;
}
```

**Several browser tabs:** keep the refresh token in `localStorage`, serialize with the
[Web Locks API](https://developer.mozilla.org/docs/Web/API/Web_Locks_API) and read the token *inside* the lock:

```ts
function refresh() {
  refreshing ??= navigator.locks.request("slim-refresh", async () => {
    const token = localStorage.getItem("slim.refresh");
    if (!token) return false;
    const r = await fetch("/auth/refresh", { method: "POST", headers: { "Content-Type": "application/json" },
                                              body: JSON.stringify({ refreshToken: token }) });
    if (!r.ok) return false;
    const auth = await r.json();
    localStorage.setItem("slim.refresh", auth.refreshToken);  // before the lock is released
    accessToken = auth.accessToken;                           // per tab, in memory
    return true;
  }).finally(() => (refreshing = null));
  return refreshing;
}
```

The [TypeScript client](../../samples/templates/Frontend/slimIdentityClient.ts) does exactly this.
