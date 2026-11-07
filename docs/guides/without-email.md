# Running without e-mail

Internal tools, back-office applications and services on a closed network often have no mail server – and need
none: an administrator creates the accounts. SlimIdentity supports that explicitly:

```csharp
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))
    .AddEntityFrameworkStores<AppDbContext, AppUser, Guid>()
    .WithoutEmail();                       // no ISlimEmailSender needed – and none allowed
```

The switch is deliberately explicit: a host that simply forgot its mail sender still stops at startup instead of
silently losing password resets.

## What changes

| | With mail | `WithoutEmail()` |
| :--- | :--- | :--- |
| Sign-in, sessions, 2FA with an authenticator app, `/change-password` | ✓ | ✓ |
| `/register` | ✓ | off – `WithoutEmail(allowSelfRegistration: true)` keeps it (accounts stay unconfirmed) |
| `/forgot-password` | ✓ | off – an administrator hands out a reset link |
| `/reset-password`, `/invitation/*` | ✓ | ✓ – for links the administrator hands over |
| `/verify-email`, `/resend-verification`, `/change-email`, `/confirm-email-change` | ✓ | off |
| 2FA with e-mail codes (`/2fa/enable-email`) | ✓ (unless `TwoFactor.AllowEmailCodes = false`) | off |
| Lockout notification, "account exists" notice | ✓ | dropped |

Contradictions stop the start: a registered mail sender next to `WithoutEmail()`, or
`allowSelfRegistration: true` together with `SignIn.RequireConfirmedEmail` (nobody could ever confirm).

## The administrator's tools

All on `ISlimAuthManager` – **you** decide who may call them (role, [sudo mode](admin-features.md#step-up-sudo-mode)):

| Method | Use |
| :--- | :--- |
| `CreatePasswordResetAsync(user, lifetime?)` | A single-use link (≤ 7 days) with which the user chooses a password. **Preferred** – the administrator never knows it. |
| `SetPasswordAsync(user, password, mustChange: true)` | A start password, e.g. read out on the phone. With `mustChange` (default) the next sign-in yields no session until the user has chosen an own password. |
| `CreateInvitationAsync(user, lifetime?)` | For accounts without a password: the link sets the first password. |
| `ResetTwoFactorAsync(user)` | Phone and recovery codes lost: removes authenticator, recovery codes and remembered devices; all sessions end. |
| `UnlockAsync(user)` | Ends a lockout. |
| `SignOutEverywhereAsync(user)` | Ends every session (ban, suspected compromise). |

Every call is logged (event ids 4007–4011) without passwords or links. A complete set of admin endpoints is in
[`samples/templates/Enterprise/AdminEndpoints.cs`](../../samples/templates/Enterprise/AdminEndpoints.cs).

**Creating an account:**

```csharp
if (await store.CreateAsync(email, passwordHash: string.Empty, ct) is not { } user)
    return Results.Conflict();                  // address taken
user.EmailConfirmed = true;                     // the administrator vouches for the address
await store.UpdateSecurityStateAsync(user, ct);
var reset = await auth.CreatePasswordResetAsync(user, TimeSpan.FromDays(3), ct);
// hand reset.Link to the new colleague – or: await auth.SetPasswordAsync(user, startPassword, mustChange: true, ct);
```

**Links and the mailbox:** a reset link the administrator hands over proves nothing about the mailbox. Unlike a mailed
reset, it leaves an unconfirmed account unconfirmed and keeps its second factor and external logins (the
[pre-account hijacking](../security.md) defence only trusts mail).

## The forced password change

With `mustChange: true`, `/auth/login` answers the correct start password with **401** and no session:

```json
{ "status": "password_change_required", "passwordChangeToken": "CfDJ8…", "expiresIn": 300 }
```

The front end asks for a new password and calls

```http
POST /auth/login/password-change
{ "token": "CfDJ8…", "newPassword": "…" }
```

The answer is the session – or, with 2FA, the usual `requires_two_factor` challenge. The new password must follow the
password rules and differ from the start password; the token works once, for 5 minutes, and dies when the
administrator sets another password. The TypeScript client handles it as `{ kind: "password_change" }` and
`completePasswordChange(token, newPassword)`.

## Second factor without mail

Authenticator apps need no mail. Recovery codes cover a lost phone; `ResetTwoFactorAsync` covers lost recovery codes.
Accounts that still have e-mail codes from a time with mail (or after `TwoFactor.AllowEmailCodes = false`) get the
challenge method `recovery`: they sign in with a recovery code, or an administrator resets their second factor.

`TwoFactor.AllowEmailCodes = false` is worth considering with mail, too: e-mail is the weakest second factor – whoever
controls the mailbox can reset the password as well.
