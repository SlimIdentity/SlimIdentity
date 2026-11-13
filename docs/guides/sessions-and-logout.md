# Sessions and logout

## Without a session store (default)

Cookies and JWTs are stateless and checked against the user's security stamp.

- `POST /auth/logout` deletes the cookie or consumes the refresh token; a copied cookie or access token keeps working
  until it expires.
- `POST /auth/logout-all` and `SignOutEverywhereAsync(user)` rotate the stamp: every cookie, JWT and refresh token
  becomes invalid (cookies at the next validation, default within 1 minute; bearer tokens immediately). Password
  reset/change and 2FA changes rotate it too.

## With `ISlimSessionStore`

```csharp
.AddSessionStore<MySessionStore>()   // EF Core and Dapper templates in samples/
```

Each sign-in creates a row (id, user, mode, method, created / last seen / expiry, optionally user agent and IP); the
id travels as the `sid` claim and is checked at every validation.

- `/logout` revokes the session server-side – copies stop working.
- `GET /auth/sessions` lists devices; `DELETE /auth/sessions/{id}` signs one out.
- Refresh-token reuse revokes only the affected session.
- Password and 2FA changes keep the current session and revoke the others.

Cost: one lookup per bearer request (with `ValidateSecurityStampOnEachRequest`, default on) and per cookie validation
interval – use an indexed key; a cache in front of `FindAsync` must be invalidated in `RevokeAsync` / `RevokeAllAsync`.
Delete expired rows regularly. `UserAgent` and `IpAddress` are personal data – omit the columns if not needed.
