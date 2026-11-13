# Two-factor authentication

```csharp
builder.Services.AddSlimIdentity(o => o.TwoFactor.AuthenticatorIssuer = "My Product")
    .AddTwoFactorStore<MyTwoFactorStore>();
```

`ISlimTwoFactorStore` keeps nothing in clear text (EF Core and Dapper templates in
[`samples/templates`](../../samples/templates)):

| Data | What the store receives | Store requirement |
| :--- | :--- | :--- |
| TOTP secret | Encrypted with Data Protection (purpose `SlimIdentity.TotpSecret.v1`) | Store the string as is |
| Recovery codes | SHA-256 hashes, salted per user (80-bit codes) | `ValidateAndConsumeRecoveryCodeAsync` deletes **atomically** |
| Last used code | Unix ms of the last accepted TOTP step / e-mail code (`bigint`) | `TryMarkCodeUsedAsync`: **atomic compare-and-set** |
| Last used challenge | Unix ms of the last completed sign-in challenge (`bigint`, own column) | `TryMarkChallengeUsedAsync`: **atomic compare-and-set** |

The key ring must be persisted ([Data Protection](data-protection.md)); if it is lost, users sign in with a recovery
code and set up the authenticator again.

## Enabling (signed-in user)

The address must be confirmed (`403 email_not_confirmed`; not checked with `WithoutEmail()`).

**Authenticator app (TOTP, RFC 6238, SHA-1, 6 digits, 30 s, ±1 step):**

1. `POST /auth/2fa/setup` → `sharedKey`, `authenticatorUri` (`otpauth://…`), `setupToken`. Nothing is stored yet.
2. Render `authenticatorUri` as a QR code in the front end (e.g. the `qrcode` npm package:
   `img.src = await QRCode.toDataURL(setup.authenticatorUri)`); SlimIdentity ships no image generation.
3. `POST /auth/2fa/enable { setupToken, code, password }` → `recoveryCodes` (`xxxx-xxxx-xxxx-xxxx`, **show once**) and
   a refreshed `session`.

**E-mail codes:** `POST /auth/2fa/enable-email { password }`. E-mail is the weakest factor – whoever controls the
mailbox can reset the password. With `TwoFactor.AllowEmailCodes = false` (always with
[`WithoutEmail()`](without-email.md)) accounts that use e-mail codes get the method `recovery`.

Enabling and disabling rotate the security stamp (other devices are signed out, the caller gets a new session).
`POST /auth/2fa/recovery-codes` (password required) replaces the codes; sessions stay.

## Signing in

`POST /auth/login` answers `action_required` `["second_factor"]` with `details.secondFactor.methods` (e.g.
`["totp", "recovery"]`; the first is asked for, e-mail codes are sent now, `["recovery"]` alone means only a recovery
code helps). `POST /auth/login/2fa { flowToken, code | recoveryCode }` completes it; wrong codes can be retried with
the same `flowToken` (they count towards the lockout), and completing a newer challenge invalidates an older open one.
External logins ask for the second factor too.

## Requiring a second factor

By default 2FA is the user's choice. A policy makes it mandatory – for everyone, a role, a tenant or one sign-in method:

```csharp
public sealed class StaffNeedsSecondFactor(IStaffDirectory staff) : ISlimSecondFactorPolicy
{
    public async ValueTask<bool> IsRequiredAsync(SlimSecondFactorPolicyContext context, CancellationToken ct)
        => await staff.IsStaffAsync(context.User.Id, ct);
}

builder.Services.AddSlimIdentity(…)
    .AddTwoFactorStore<MyTwoFactorStore>()          // required – startup fails without it
    .AddSecondFactorPolicy<StaffNeedsSecondFactor>();
```

The context carries the user, the first factor's method (`pwd`, `ext`, `passkey`, …), the external provider and the
`HttpContext`. Policies are asked when a sign-in starts; one `true` suffices; existing sessions stay valid.

Only a phishing-resistant or possession-bound factor counts: authenticator or recovery code, passkey, a remembered
device of an account with an authenticator, or `SignInAsync(…, secondFactorVerified: true)`. An e-mail code does not.
Accounts without such a factor get these steps (after `second_factor` if they use e-mail codes):

1. `setup_second_factor`: `POST /auth/login/2fa/setup { flowToken }` → `sharedKey`, `authenticatorUri`, `setupToken`.
   `details.setupSecondFactor.methods` lists `totp` and, for accounts with passkeys, `passkey` (signing in with one
   also fulfils the policy).
2. `POST /auth/login/2fa/enable { flowToken, setupToken, code }` → authenticator enabled, stamp rotated, answer
   `["confirm_recovery_codes"]` with `details.recoveryCodes` – **show once**; reading the flow again does not repeat them.
3. `confirm_recovery_codes`: `POST /auth/login/2fa/recovery-codes-saved { flowToken }` → session.

## Remember this device (optional)

Off by default; the password is still required every time:

```csharp
o.TwoFactor.RememberDeviceLifetime = TimeSpan.FromDays(30);   // max. 90 days
```

- `POST /auth/login/2fa` with `"rememberDevice": true` (TOTP or e-mail code, never a recovery code).
- **Cookie mode:** SlimIdentity sets the `HttpOnly`/`Secure` cookie `SlimAuth.2fa`, scoped to the auth routes.
  **Bearer mode:** the response contains `twoFactorRememberToken`; keep it in secure storage and send it with
  `/auth/login`. Each proof counts only in its own mode.
- Later sign-ins on that device skip the second factor (`amr` = `mfa_remembered`), also external logins in the same
  browser. Under a [policy](#requiring-a-second-factor) only for accounts with an authenticator.

Forgetting: `POST /auth/2fa/forget-device` deletes this browser's cookie (apps delete their token);
`POST /auth/2fa/forget-all-devices` (authenticated) rotates the stamp, ending all remembered devices and other
sessions; a password change or reset, sign out everywhere, 2FA on/off and a ban do the same. Remembered devices are
signed tokens without a per-device list and expire after `RememberDeviceLifetime`.

## Protections

- **Replay:** each TOTP step and e-mail code is accepted once, including the enabling code.
- **Lockout:** wrong codes count towards a separate lockout (`FailedSecondFactorAttempts`), reset only by a successful
  second factor. While it lasts, a correct password gets `423`; a remembered device still signs in.
- Migrating authenticator keys from another system:
  `dataProtectionProvider.CreateProtector(SlimIdentityDefaults.TotpSecretProtectionPurpose).Protect(base32Key)`.
