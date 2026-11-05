# Sessions and logout

## Without a session store (default)

Cookies and JWTs are **stateless**: everything needed to validate them is inside the token, checked against the
user's security stamp.

- `POST /auth/logout` deletes the cookie (cookie mode) and consumes the refresh token (bearer mode).
  A copy of the cookie or access token keeps working until it expires.
- `POST /auth/logout-all` rotates the security stamp: every cookie, JWT and refresh token of the user becomes invalid
  (cookies at the next validation, default within 1 minute; bearer tokens immediately).
- Password reset/change and 2FA changes rotate the stamp, too.

## With `ISlimSessionStore`

```csharp
.AddSessionStore<MySessionStore>()   // EF Core and Dapper implementations in samples/
```

Every sign-in creates a row (id, user, mode, method, created/last seen/expiry, optionally user agent and IP).
The id travels as the `sid` claim and is checked whenever the principal is validated.

- `POST /auth/logout` revokes the current session server-side – copied cookies/tokens stop working.
- `GET /auth/sessions` lists the user's devices, `DELETE /auth/sessions/{id}` signs one out.
- Refresh-token reuse revokes just the affected session instead of all sessions.
- Password change and 2FA changes keep the current session and revoke all others.

Cost: one store lookup per bearer request (with `Tokens.ValidateSecurityStampOnEachRequest`, default on) and per
cookie validation interval. Use an indexed primary key; a cache in front of `FindAsync` is possible if you invalidate
it in `RevokeAsync` / `RevokeAllAsync`.

Housekeeping: delete expired rows regularly (`DELETE … WHERE expires_utc < now()`). `UserAgent` and `IpAddress`
are personal data – leave the columns out if your device list does not need them.

## Ending all sessions from your code

```csharp
// e.g. when banning a user or after a suspected compromise
await authManager.SignOutEverywhereAsync(user, ct);   // rotates the stamp and revokes all server-side sessions
// then mark the user inactive in your own store
```
