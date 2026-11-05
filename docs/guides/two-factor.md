# Two-factor authentication

Enable with a store for the 2FA state:

```csharp
builder.Services.AddSlimIdentity(o => o.TwoFactor.AuthenticatorIssuer = "My Product")
    .AddTwoFactorStore<MyTwoFactorStore>();
```

`ISlimTwoFactorStore` keeps three things – none of them in clear text:

| Data | What the store receives | Store requirement |
| :--- | :--- | :--- |
| TOTP secret | Encrypted with Data Protection (purpose `SlimIdentity.TotpSecret.v1`) | Store the string as is |
| Recovery codes | SHA-256 hashes, salted per user (codes have 80 bits of entropy) | `ValidateAndConsumeRecoveryCodeAsync` deletes **atomically** |
| Last used code | Unix seconds of the last accepted TOTP step / e-mail code | `TryMarkCodeUsedAsync` is an **atomic compare-and-set** |

EF Core and Dapper implementations are in [`samples/templates`](../../samples/templates).

> Because the TOTP secrets are encrypted with the Data Protection key ring, the key ring must be persisted
> ([guide](data-protection.md)). If it is lost, users sign in with a recovery code and set up their authenticator again.

## Enabling (signed-in user)

**Authenticator app (TOTP):**

1. `POST /auth/2fa/setup` → `sharedKey` (for manual entry), `authenticatorUri` (`otpauth://…`) and `setupToken`.
   Nothing is stored yet.
2. Render `authenticatorUri` as a QR code **in the front end**, e.g. with the [`qrcode`](https://www.npmjs.com/package/qrcode) package:
   ```ts
   import QRCode from "qrcode";
   img.src = await QRCode.toDataURL(setup.authenticatorUri);
   ```
   (SlimIdentity deliberately ships no image generation – no dependency, and the front end controls size and styling.)
3. The user enters the first 6-digit code: `POST /auth/2fa/enable` with `setupToken` and `code` → `recoveryCodes`
   (format `xxxx-xxxx-xxxx-xxxx`, **show them once**) and a refreshed `session`.

**E-mail codes:** `POST /auth/2fa/enable-email` with the current `password`.

Enabling, disabling and regenerating codes rotate the security stamp: other devices are signed out, the calling device
gets new tokens/cookie in the response.

## Signing in

1. `POST /auth/login` → `401 { "status": "requires_two_factor", "preAuthToken": "…", "twoFactorMethod": "totp" | "email" }`.
   For e-mail 2FA the code has just been sent.
2. `POST /auth/login/2fa` with `preAuthToken` and `code` – or `recoveryCode` – → session.

## Protections

- **Replay protection:** each TOTP time step and each e-mail code is accepted only once – also the code used to
  enable the authenticator. A code captured by a phishing proxy cannot be used a second time.
- **Lockout:** wrong codes count towards the account lockout; the failure counter is reset only after the second
  factor succeeded, so a known password does not allow unlimited code guessing.
- **At rest:** encrypted TOTP secrets and salted recovery-code hashes – a database dump does not allow generating codes.

## Notes

- TOTP: RFC 6238, SHA-1, 6 digits, 30 s, ±1 step tolerance (`TwoFactor.TotpTimeStepTolerance`) – works with all common
  authenticator apps.
- External logins (Google, …) also require the second factor if the user has 2FA enabled.
- Migrating authenticator keys from another system: encrypt them once with
  `dataProtectionProvider.CreateProtector(SlimIdentityDefaults.TotpSecretProtectionPurpose).Protect(base32Key)`.
