# Two-factor authentication

Enable with a store for TOTP secrets and recovery codes:

```csharp
builder.Services.AddSlimIdentity(o => o.TwoFactor.AuthenticatorIssuer = "My Product")
    .AddTwoFactorStore<MyTwoFactorStore>();
```

`ISlimTwoFactorStore` keeps the Base32 TOTP secret (consider encrypting it at rest, e.g. with `IDataProtector`) and the
SHA-256 hashes of the recovery codes. `ValidateAndConsumeRecoveryCodeAsync` must delete atomically.

## Enabling (signed-in user)

**Authenticator app (TOTP):**

1. `POST /auth/2fa/setup` → `sharedKey`, `authenticatorUri` (render as QR code), `setupToken`. Nothing is stored yet.
2. The user scans the code and enters the first 6-digit code.
3. `POST /auth/2fa/enable` with `setupToken` and `code` → `recoveryCodes` (show once!) and a refreshed `session`.

**E-mail codes:** `POST /auth/2fa/enable-email` with the current `password`.

Enabling, disabling and regenerating codes rotate the security stamp: other devices are signed out, the calling device
gets new tokens/cookie in the response.

## Signing in

1. `POST /auth/login` → `401 { "status": "requires_two_factor", "preAuthToken": "…", "twoFactorMethod": "totp" | "email" }`.
   For e-mail 2FA the code has just been sent.
2. `POST /auth/login/2fa` with `preAuthToken` and `code` – or `recoveryCode` – → session.

Wrong codes count towards the account lockout; the failure counter is reset only after the second factor succeeded,
so a known password does not allow unlimited code guessing.

## Notes

- TOTP: RFC 6238, SHA-1, 6 digits, 30 s, ±1 step tolerance (`TwoFactor.TotpTimeStepTolerance`) – works with all common
  authenticator apps.
- A code can be reused within its time window (no replay store). Every attempt is rate limited and counted.
- External logins (Google, …) also require the second factor if the user has 2FA enabled.
