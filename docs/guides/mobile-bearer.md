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
- Browser: access token in memory only; the refresh token in web storage (see below for several tabs) – or, better
  for same-site SPAs, the cookie flow, which has no refresh tokens at all.

## Refreshing correctly

Refresh tokens are **single use**. If two requests refresh the same token in parallel, the second one looks like a
replay and the session is revoked (reuse detection – deliberately without a grace period). Serialize refreshes in the
client.

**One app instance** (mobile app, single tab): share one in-flight promise.

```ts
let refreshing: Promise<boolean> | null = null;
function refresh() {
  refreshing ??= doRefresh().finally(() => (refreshing = null));
  return refreshing;
}
```

**Several browser tabs** sharing one session: keep the refresh token in `localStorage` and serialize across tabs with
the [Web Locks API](https://developer.mozilla.org/docs/Web/API/Web_Locks_API). Read the token *inside* the lock – the
tab before may have rotated it in the meantime:

```ts
function refresh() {
  refreshing ??= navigator.locks.request("slim-refresh", async () => {
    const token = localStorage.getItem("slim.refresh");      // newest token, never one another tab already used
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

If a refresh response is lost (network error), the client cannot retry with the old token – the user has to sign in
again. This is the intended trade-off of rotation.

## Why reuse detection matters

An attacker who steals a refresh token and uses it first gets a new pair; the legitimate client then presents the old
token. SlimIdentity recognizes this replay and revokes the whole token family (the session) – the attacker's tokens
included. Without a session store the family cannot be identified, so all sessions of the user end (security stamp
rotation). This is always on – a client that legitimately reuses refresh tokens has a bug (e.g. two parallel refresh
calls; serialize them, as the sample client does).
