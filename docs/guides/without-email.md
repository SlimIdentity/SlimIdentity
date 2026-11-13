# Running without e-mail

Internal tools and services on a closed network often have no mail server; an administrator creates the accounts.

```csharp
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))
    .AddEntityFrameworkStores<AppDbContext, AppUser, Guid>()
    .WithoutEmail();                       // no ISlimEmailSender needed – and none allowed
```

The switch is explicit so that a host that forgot its mail sender still stops at startup. A registered mail sender
next to `WithoutEmail()` stops the start as well.

| | With mail | `WithoutEmail()` |
| :--- | :--- | :--- |
| Sign-in, sessions, authenticator 2FA, `/change-password` | ✓ | ✓ |
| `/register` | code or link, then a credential ([registration](../endpoints.md#registration)) | off – `WithoutEmail(allowSelfRegistration: true)` keeps it as one step (`email`, `password`, `profile`; accounts stay unconfirmed) |
| `/forgot-password` | ✓ | off – an administrator hands out a reset link |
| `/flow`, `/register/password` | ✓ | ✓ – for links the administrator hands over |
| `/register/verify`, `/login/verify-email`, `/change-email`, `/change-email/confirm` | ✓ | off |
| E-mail 2FA codes (`/2fa/enable-email`) | ✓ (unless `TwoFactor.AllowEmailCodes = false`) | off |
| Lockout notification, "account exists" notice | ✓ | dropped |

Addresses are never required to be confirmed at sign-in. The first administrator is created at startup –
see [seeding](seeding.md).

## The administrator's tools

All on `ISlimAuthManager`; **you** decide who may call them (role, [sudo mode](admin-features.md#step-up-sudo-mode)):

| Method | Use |
| :--- | :--- |
| `CreatePasswordResetAsync(user, lifetime?)` | Single-use link (≤ 7 days) with which the user chooses a password. **Preferred** – the administrator never knows it. |
| `CreateUserAsync(email, startPassword?, profile?)` | New account with confirmed address; a start password must be changed at the first sign-in. `400` invalid address or password, `409 email_taken`. |
| `SetPasswordAsync(user, password, mustChange: true)` | Start password, e.g. read out on the phone; with `mustChange` (default) the next sign-in yields no session until the user chose an own one. |
| `CreateInvitationAsync(user, lifetime?)` | For accounts without a password: the link sets the first credential ([invitations](invitations.md)). |
| `ResetTwoFactorAsync(user)` | Removes authenticator, recovery codes and remembered devices; all sessions end. |
| `UnlockAsync(user)` | Ends the lockout of password and second factor. |
| `SignOutEverywhereAsync(user)` | Ends every session (ban, suspected compromise). |

Logged without passwords or links: 4007 password set, 4008 reset link created, 4009 2FA reset, 4010 unlocked, 4012
account created, 3004 all sessions revoked, 4011 user replaced an administrator's password. Endpoints for all of them:
[`AdminEndpoints.cs`](../../samples/templates/Enterprise/AdminEndpoints.cs).

```csharp
var created = await auth.CreateUserAsync(email, profile: new Employee(…), ct: ct);
if (!created.Succeeded) return created.Failure;
var reset = await auth.CreatePasswordResetAsync(created.User!, TimeSpan.FromDays(3), ct);   // hand over reset.Link
```

A handed-over reset link proves nothing about the mailbox: unlike a mailed reset it leaves an unconfirmed account
unconfirmed and keeps its second factor and external logins.

## The forced password change

After a start password, `/auth/login` answers the correct password without a session: `action_required`
`["change_password"]` with a `flowToken`.
The client continues with `POST /auth/login/password-change { flowToken, newPassword }` (TypeScript:
`completePasswordChange`). With 2FA the second factor comes first (`["second_factor", "change_password"]`). The new
password must follow the rules and differ from the start password; the flow token is single-use, valid 15 minutes, and
dies when the administrator sets another password. A lockout that starts in between holds (`423`). Passkeys and
external logins of the account also answer `change_password` until the start password is replaced.

## Second factor without mail

Authenticator apps need no mail; recovery codes cover a lost phone, `ResetTwoFactorAsync` lost recovery codes.
Accounts that still have e-mail codes (or after `TwoFactor.AllowEmailCodes = false`) get the challenge method
`recovery`: sign in with a recovery code or have the second factor reset. `AllowEmailCodes = false` is worth
considering with mail, too – whoever controls the mailbox can reset the password anyway.
