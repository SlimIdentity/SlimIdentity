# Passkeys

Passkeys (WebAuthn) sign users in with Face ID, a fingerprint or a device PIN. A passkey with user verification is
multi-factor on its own, so no second factor follows.

## Setup

```bash
dotnet add package SlimIdentity.Passkeys --prerelease   # same version as SlimIdentity
```

```csharp
builder.Services.AddSlimIdentity(o => o.Links.BaseUrl = "https://app.example.com")   // trusted origin, default RP id
    .AddEntityFrameworkStores<AppDbContext, AppUser, Guid>(o => o.Passkeys = true)   // or .AddPasskeyStore<MyPasskeyStore>()
    .AddPasskeys(o =>                                                                // optional
    {
        o.RelyingPartyId = "example.com";     // parent domain of several front ends (default: host of Links.BaseUrl)
        o.RelyingPartyName = "Example";       // shown by the authenticator (default: TwoFactor.AuthenticatorIssuer)
    });
```

- **Opt-in:** off until a passkey store is registered. The package checks at startup that it matches the core version.
- **RP id:** the front end's host or a parent domain. **Choose it once** – changing it makes all passkeys unusable.
  Without it the start fails.
- **Origins:** the page running the ceremony must be a trusted origin (`TrustedOrigins`, `Links.BaseUrl` or an
  [origin policy](multi-tenancy.md)) within the RP id.

## Flows

Bodies are WebAuthn's JSON form with base64url fields; the TypeScript client converts them. Each ceremony is an
`…/options` call returning `options` and a `state` (valid 5 minutes) followed by the call with `state` and
`credential` – routes and bodies in the [endpoint reference](../endpoints.md#passkeys-package-slimidentitypasskeys).

- **Adding** requires an existing local sign-in method (password or passkey; a pure SSO account gets
  `403 password_required`), the password or a sign-in within 5 minutes (`403 reauthentication_required`), a confirmed
  address, and no impersonation.
- **Registering** ([registration](../endpoints.md#registration); step `set_credential` with `passkey` in
  `details.setCredential.kinds`) creates a confirmed account with the passkey as its
  only way in. The ceremony is bound to the flow; an already registered credential is refused before the account is
  created. Recovery is `/forgot-password`.
- **Signing in** gives `amr: passkey`. Guards, inactive accounts, `verify_email` and `change_password` apply as for
  every sign-in; a password or second-factor lockout does not block passkeys.
- **Autofill** (conditional UI): mark the e-mail input `autocomplete="username webauthn"` and start
  `loginWithPasskeyAutofill(signal)` when the page opens; it refreshes the challenge every 4 minutes. Abort the signal
  before any other sign-in on the page – browsers run one WebAuthn request at a time.
- **Synced or device-bound:** `backupEligible` (may sync) is fixed per passkey – a sign-in reporting a change is
  refused; `backedUp` is updated at each sign-in.
- **Manage** via `GET /auth/sign-in-methods`, `/sign-in-methods/passkeys/rename` and `/remove` (password or recent
  sign-in; the last way in is never removed).
- A mailed password reset that first confirms an account removes all its passkeys with the password, 2FA and external
  logins (pre-account hijacking).

TypeScript: `addPasskey(name, password)`, `completeRegistrationWithPasskey(flowToken, name, profile)`,
`loginWithPasskey()`, `loginWithPasskeyAutofill(signal)`, `signInMethods()`, `renamePasskey(id, name)`,
`removePasskey(id, password)`.

## What is checked

Following Web Authentication Level 2 (§7.1, §7.2):

| Check | Registration | Sign-in |
| :--- | :---: | :---: |
| `type`, challenge from the signed state, not `crossOrigin` | ✓ | ✓ |
| Origin trusted and within the RP id; RP id hash in the authenticator data | ✓ | ✓ |
| User present **and** verified | ✓ | ✓ |
| Backup flags consistent; eligibility unchanged since registration | ✓ | ✓ |
| ES256 (P-256) or RS256 (≥ 2048-bit modulus, padding not counted); credential id unique | ✓ | |
| State bound to the account and its security stamp, or to the registration flow | ✓ | |
| Signature with the stored key; user handle matches the owner | | ✓ |
| Account active, address confirmed – before the use is recorded | | ✓ |
| Signature counter increases (if counted) – else a cloned key is assumed | | ✓ |
| Each challenge counts once per passkey (atomic in the store) | | ✓ |

Attestation is not evaluated (`attestation: "none"`). Ed25519 is not offered (no built-in .NET support).

## Your own store

Start from the templates (`EfCorePasskeyStore`, `DapperPasskeyStore`) and verify with `SlimIdentity.Testing`:

- credential ids are unique – `AddPasskeyAsync` returns `false`, also under concurrency;
- `TryRecordUseAsync` is one compare-and-set (same counter **and** newer challenge) and updates `BackedUp`;
- `RemovePasskeysAsync` removes every passkey of the user;
- store `BackupEligible`, `BackedUp` and `UserHandle` (≤ 64 bytes; rows without one use the UTF-8 user id);
- key the table by the SHA-256 of the credential id (ids reach 1023 bytes).
