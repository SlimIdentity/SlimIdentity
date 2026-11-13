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
| `/register` | ✓ – code or link, then the password ([registration](../endpoints.md#registration)) | off – `WithoutEmail(allowSelfRegistration: true)` keeps it in one step (`email`, `password`, `profile`; accounts stay unconfirmed) |
| `/forgot-password` | ✓ | off – an administrator hands out a reset link |
| `/flow`, `/register/password` | ✓ | ✓ – for links the administrator hands over |
| `/register/verify`, `/change-email`, `/change-email/confirm` | ✓ | off |
| 2FA with e-mail codes (`/2fa/enable-email`) | ✓ (unless `TwoFactor.AllowEmailCodes = false`) | off |
| Lockout notification, "account exists" notice | ✓ | dropped |

A registered mail sender next to `WithoutEmail()` stops the start. Without mail, addresses are never asked to be
confirmed at sign-in.

The very first administrator is created by code at start-up – see [seeding](seeding.md).

## The administrator's tools

All on `ISlimAuthManager` – **you** decide who may call them (role, [sudo mode](admin-features.md#step-up-sudo-mode)):

| Method | Use |
| :--- | :--- |
| `CreatePasswordResetAsync(user, lifetime?)` | A single-use link (≤ 7 days) with which the user chooses a password. **Preferred** – the administrator never knows it. |
| `CreateUserAsync(email, startPassword?, profile?)` | A new account, address confirmed (the administrator vouches for it); with a start password it must be changed at the first sign-in. `400` invalid address or password, `409 email_taken`. |
| `SetPasswordAsync(user, password, mustChange: true)` | A start password, e.g. read out on the phone. With `mustChange` (default) the next sign-in yields no session until the user has chosen an own password. |
| `CreateInvitationAsync(user, lifetime?)` | For accounts without a password: the link sets the first password. |
| `ResetTwoFactorAsync(user)` | Phone and recovery codes lost: removes authenticator, recovery codes and remembered devices; all sessions end. |
| `UnlockAsync(user)` | Ends the lockout of password and second factor. |
| `SignOutEverywhereAsync(user)` | Ends every session (ban, suspected compromise). |

The administrator calls are logged without passwords or links: 4007 password set, 4008 reset link created, 4009 2FA
reset, 4010 unlocked, 4012 account created; 3004 when all sessions are revoked, 4011 when the user replaces an administrator's password. A complete set of admin endpoints is in
[`samples/templates/Enterprise/AdminEndpoints.cs`](../../samples/templates/Enterprise/AdminEndpoints.cs).

**Creating an account:**

```csharp
var created = await auth.CreateUserAsync(email, profile: new Employee(…), ct: ct);   // or with a start password
if (!created.Succeeded) return created.Failure;                                      // 400 / 409 email_taken
var reset = await auth.CreatePasswordResetAsync(created.User, TimeSpan.FromDays(3), ct);
// hand reset.Link to the new colleague
```

**Links and the mailbox:** a reset link the administrator hands over proves nothing about the mailbox. Unlike a mailed
reset, it leaves an unconfirmed account unconfirmed and keeps its second factor and external logins (the
[pre-account hijacking](../security.md) defence only trusts mail).

## The forced password change

With `mustChange: true`, `/auth/login` answers the correct start password without a session:

```json
{ "status": "action_required", "actions": ["change_password"], "flowToken": "CfDJ8…", "expiresIn": 900 }
```

The front end asks for a new password and calls

```http
POST /auth/login/password-change
{ "flowToken": "CfDJ8…", "newPassword": "…" }
```

With 2FA the second factor comes first (`["second_factor", "change_password"]`) – no own password before the account is
proven completely. The new password must follow the password rules and differ from the start password; the flow
completes once, within 15 minutes, and dies when the administrator sets another password. A lockout of the password
that starts in between holds (`423`) – the new password does not lift it. The TypeScript client handles it as
`{ kind: "action_required" }` and `completePasswordChange(flowToken, newPassword)`.

Every other way in waits as well: a passkey or an external login of the account answers `change_password` without a
session – the passkey or provider proves the account, the start password is not needed – until it has been replaced – it stays known to whoever set or read it, so it must
not outlive the first sign-in.

## Second factor without mail

Authenticator apps need no mail. Recovery codes cover a lost phone; `ResetTwoFactorAsync` covers lost recovery codes.
Accounts that still have e-mail codes from a time with mail (or after `TwoFactor.AllowEmailCodes = false`) get the
challenge method `recovery`: they sign in with a recovery code, or an administrator resets their second factor.

`TwoFactor.AllowEmailCodes = false` is worth considering with mail, too: e-mail is the weakest second factor – whoever
controls the mailbox can reset the password as well.
