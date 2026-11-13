# Two-factor authentication

Enable with a store for the 2FA state:

```csharp
builder.Services.AddSlimIdentity(o => o.TwoFactor.AuthenticatorIssuer = "My Product")
    .AddTwoFactorStore<MyTwoFactorStore>();
```

`ISlimTwoFactorStore` keeps four things – none of them in clear text:

| Data | What the store receives | Store requirement |
| :--- | :--- | :--- |
| TOTP secret | Encrypted with Data Protection (purpose `SlimIdentity.TotpSecret.v1`) | Store the string as is |
| Recovery codes | SHA-256 hashes, salted per user (codes have 80 bits of entropy) | `ValidateAndConsumeRecoveryCodeAsync` deletes **atomically** |
| Last used code | Unix milliseconds of the last accepted TOTP step / e-mail code (`bigint`) | `TryMarkCodeUsedAsync` is an **atomic compare-and-set** |
| Last used challenge | Unix milliseconds at which the last completed sign-in challenge was issued (`bigint`, own column) | `TryMarkChallengeUsedAsync` is an **atomic compare-and-set** |

EF Core and Dapper implementations are in [`samples/templates`](../../samples/templates).

> Because the TOTP secrets are encrypted with the Data Protection key ring, the key ring must be persisted
> ([guide](data-protection.md)). If it is lost, users sign in with a recovery code and set up their authenticator again.

## Enabling (signed-in user)

**Authenticator app (TOTP):**

1. `POST /auth/2fa/setup` → `sharedKey` (for manual entry), `authenticatorUri` (`otpauth://…`) and `setupToken`.
   The address must be confirmed first (`403 email_not_confirmed`, not with `WithoutEmail()`): on an unconfirmed
   account a second factor may have been set up by whoever registered someone else's address.
   Nothing is stored yet.
2. Render `authenticatorUri` as a QR code **in the front end**, e.g. with the [`qrcode`](https://www.npmjs.com/package/qrcode) package:
   ```ts
   import QRCode from "qrcode";
   img.src = await QRCode.toDataURL(setup.authenticatorUri);
   ```
   (SlimIdentity deliberately ships no image generation – no dependency, and the front end controls size and styling.)
3. The user enters the first 6-digit code: `POST /auth/2fa/enable` with `setupToken`, `code` and the current `password` → `recoveryCodes`
   (format `xxxx-xxxx-xxxx-xxxx`, **show them once**) and a refreshed `session`.

**E-mail codes:** `POST /auth/2fa/enable-email` with the current `password`. E-mail is the weakest second factor –
whoever controls the mailbox can reset the password as well. `TwoFactor.AllowEmailCodes = false` (always off with
[`WithoutEmail()`](without-email.md)) leaves authenticator apps only; accounts that already use e-mail codes then get
the challenge method `recovery` and sign in with a recovery code, or an administrator resets their second factor.

Enabling and disabling rotate the security stamp: other devices are signed out, the calling device gets new
tokens/cookie in the response. Regenerating recovery codes (`POST /auth/2fa/recovery-codes`, password required) only
replaces the codes – the old ones stop working at once, sessions stay as they are.

## Signing in

1. `POST /auth/login` → `200 { "status": "action_required", "actions": ["second_factor"], "flowToken": "…",
   "details": { "secondFactor": { "methods": ["totp", "recovery"] } } }` – the first method is the one asked for.
   For e-mail 2FA the code has just been sent; `["recovery"]` alone means neither an authenticator nor e-mail codes are available
   (`TwoFactor.AllowEmailCodes = false`), so only a recovery code helps.
2. `POST /auth/login/2fa` with `flowToken` and `code` – or `recoveryCode` – → session, or the remaining steps
   (e.g. `change_password`) with a new `flowToken`.
   A wrong code can be corrected with the same `flowToken` (failures count towards the lockout); after a successful
   step the challenge is used up. If a user has two challenges open at once (two devices), completing the
   newer one invalidates the older one – that device signs in again.
   In cookie mode (`/login?useCookies=true`) this step needs the CSRF header like every other cookie request.

## Remember this device (optional)

Users who sign in daily on the same device can skip the second factor there for a while – the password is still
required every time. Off by default:

```csharp
o.TwoFactor.RememberDeviceLifetime = TimeSpan.FromDays(30);   // max. 90 days
```

1. The user ticks "Remember this device" → `POST /auth/login/2fa` with `"rememberDevice": true` (TOTP or e-mail code;
   never after a recovery code).
2. **Browser (cookie mode):** SlimIdentity sets the `HttpOnly`/`Secure` cookie `SlimAuth.2fa`, scoped to the auth
   routes. **Apps (bearer mode):** the response contains `twoFactorRememberToken` – store it in secure storage and send
   it as `twoFactorRememberToken` with `/auth/login`.
3. Later sign-ins on that device with the correct password skip the second factor (`amr` = `mfa_remembered`), also
   for external logins in the same browser. Each proof counts only in its own mode: the cookie for cookie sign-ins,
   the token for bearer sign-ins – a token request from a browser that has the cookie still asks for the second factor.

Forgetting:

| Action | Effect |
| :--- | :--- |
| `POST /auth/2fa/forget-device` | This browser asks again (deletes the cookie). Apps simply delete their token. |
| `POST /auth/2fa/forget-all-devices` (authenticated) | **All** remembered devices ask again. Implemented by rotating the security stamp, so all *other* sessions end as well; the calling device gets a renewed session. |
| Password change / reset, sign out everywhere, enabling / disabling 2FA, ban | All remembered devices are forgotten automatically. |
| Expiry | After `RememberDeviceLifetime`. |

Remembered devices are stateless (signed tokens), so there is no list of individual devices – like most providers,
SlimIdentity offers "forget this device" and "forget all devices".

## Protections

- **Replay protection:** each TOTP time step and each e-mail code is accepted only once – also the code used to
  enable the authenticator. A code captured by a phishing proxy cannot be used a second time.
- **Lockout:** wrong codes count towards a lockout of their own (`FailedSecondFactorAttempts`); it is reset only after
  the second factor succeeded, so a known password does not allow unlimited code guessing. While it lasts, a correct
  password gets `423` instead of a new challenge; a remembered device still signs in.
- **At rest:** encrypted TOTP secrets and salted recovery-code hashes – a database dump does not allow generating codes.

## Notes

- TOTP: RFC 6238, SHA-1, 6 digits, 30 s, ±1 step tolerance – works with all common
  authenticator apps.
- External logins (Google, …) also require the second factor if the user has 2FA enabled.
- Migrating authenticator keys from another system: encrypt them once with
  `dataProtectionProvider.CreateProtector(SlimIdentityDefaults.TotpSecretProtectionPurpose).Protect(base32Key)`.
