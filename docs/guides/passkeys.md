# Passkeys

Passkeys (WebAuthn) sign users in with Face ID, a fingerprint or a device PIN – no password, nothing to phish:
the browser only offers a passkey to the site it was created for. A passkey with user verification is **multi-factor
on its own** (possession of the device + biometrics / PIN), so no second factor follows.

## Setup

Passkeys are a package of their own – the core contains no WebAuthn code:

```bash
dotnet add package SlimIdentity.Passkeys --prerelease   # always the same version as SlimIdentity
```

```csharp
builder.Services.AddSlimIdentity(o => o.Links.BaseUrl = "https://app.example.com")   // front end – trusted origin, default RP id
    .AddEntityFrameworkStores<AppDbContext, AppUser, Guid>(o => o.Passkeys = true)   // opt in; the SlimPasskeys table is always in the model
    // or .AddPasskeyStore<MyPasskeyStore>() – templates for EF Core and Dapper in samples/templates
    .AddPasskeys(o =>                                                                // optional
    {
        o.RelyingPartyId = "example.com";     // a parent domain shared by several front ends (default: host of Links.BaseUrl)
        o.RelyingPartyName = "Example";       // shown by the authenticator (default: TwoFactor.AuthenticatorIssuer)
    });
```

- **Opt-in** – passkeys are off until you register a passkey store (EF Core: `o.Passkeys = true`): they need the
  decision below and a front end that offers them. The package checks at start-up that it has the core's version.
- **Relying party id (RP id)** – the domain passkeys are bound to: the front end's host or a parent domain of it.
  **Choose it once:** changing it later makes every registered passkey unusable. Without it the start fails.
- **Origins** – the page that runs the ceremony must be a trusted origin ([`TrustedOrigins`, `Links.BaseUrl` or your
  origin policy](multi-tenancy.md)) and lie within the RP id.

## Flows

All bodies are WebAuthn's JSON form with base64url fields; the TypeScript client converts them.

**Add a passkey** (signed in):

```http
POST /auth/passkeys/register/options   { "password": "…" }        → { "options": { …creation options… }, "state": "…" }
     navigator.credentials.create({ publicKey: options })
POST /auth/passkeys/register            { "state", "credential", "name": "Laptop" }   → { "id", "name", "createdUtc", "backupEligible", "backedUp" }
```

The password is required for accounts that have one, a sign-in within the last 5 minutes for accounts without one
(`403 reauthentication_required`) – a stolen session must not add a permanent way in; the address
must be confirmed, and not during an impersonation – the same rules as for 2FA and linking.

**Sign in** (anonymous, no e-mail needed – discoverable credentials):

```http
POST /auth/passkeys/login/options                                   → { "options": { …request options… }, "state": "…" }
     navigator.credentials.get({ publicKey: options })
POST /auth/passkeys/login?useCookies=true|false   { "state", "credential", "rememberMe" }   → session
```

The session has `amr: passkey`. Sign-in guards, inactive accounts, `RequireConfirmedEmail` and a forced password
change (`403 password_change_required` – sign in with the start password once) apply as for every
sign-in; a running password lockout does not block passkeys (there is nothing to guess).

**Autofill** (conditional UI) – the browser offers the passkeys of the site right in the e-mail field, no extra button:
mark the input `autocomplete="username webauthn"` and start `loginWithPasskeyAutofill(signal)` of the TypeScript client
when the sign-in page opens. It calls the same two endpoints with `mediation: "conditional"`, fetches a fresh challenge
every 4 minutes (a state lives 5) and returns once the user picks a passkey. Abort the signal before any other sign-in on
the page – the browser runs one WebAuthn request at a time.

```html
<input type="email" name="email" autocomplete="username webauthn">
```

```ts
const autofill = new AbortController();
cookieAuth.loginWithPasskeyAutofill(autofill.signal).then(r => r.kind === "ok" && goHome());
// password form or "sign in with passkey" button: autofill.abort() first
```

**Synced or device-bound** – `backupEligible` says whether a passkey may be synced to other devices (iCloud Keychain,
Google Password Manager, password managers) or stays on one device (security key); `backedUp` whether it currently is
(updated at every sign-in). Show it next to the name ("synced" / "this device only"). Eligibility is fixed for a
passkey: a sign-in that reports a change is refused.

**Manage** – passkeys appear in `GET /auth/sign-in-methods` and are renamed or removed there
(`/sign-in-methods/passkeys/rename`, `/sign-in-methods/passkeys/remove`); removing needs the password (or a recent sign-in) if the account has
one and never removes the last way in.

TypeScript: `addPasskey(name, password)`, `loginWithPasskey()`, `loginWithPasskeyAutofill(signal)`, `signInMethods()`,
`renamePasskey(id, name)`, `removePasskey(id, password)`.

**Taking over an account** – when the owner of an address proves the mailbox for the first time (password reset of an
unconfirmed account, verified external sign-in), every passkey of the account is removed together with the password,
2FA and external logins: whoever registered the address before keeps no way in. Passkeys can only be added to confirmed
accounts anyway; this covers accounts imported or created while mail was off.

## What is checked

Following Web Authentication Level 2 (§7.1 registration, §7.2 authentication):

| Check | Registration | Sign-in |
| :--- | :---: | :---: |
| `type` (`webauthn.create` / `webauthn.get`), challenge from the signed state, not `crossOrigin` | ✓ | ✓ |
| Origin trusted and within the RP id | ✓ | ✓ |
| RP id hash in the authenticator data | ✓ | ✓ |
| User present **and** verified (biometrics / PIN) | ✓ | ✓ |
| Backup flags consistent (backed up only if eligible); eligibility unchanged since registration | ✓ | ✓ |
| Public key: ES256 (P-256) or RS256 (modulus of at least 2048 bit – zero padding does not count); credential id unique | ✓ | |
| Registration state bound to the account and its security stamp | ✓ | |
| Signature over authenticator data + client data hash with the stored key | | ✓ |
| Account active and (with `RequireConfirmedEmail`) confirmed – before the use is recorded | | ✓ |
| User handle matches the passkey's owner | | ✓ |
| Signature counter increases (if the authenticator counts) – else a cloned key is assumed | | ✓ |
| Each challenge counts once per passkey (atomic in the store) – no replay | | ✓ |

Attestation is not evaluated (`attestation: "none"`): SlimIdentity does not decide which authenticator models are
acceptable. Ed25519 keys are not offered – .NET has no built-in support, and passkeys use ES256.

## Your own store

`ISlimPasskeyStore` – start from the templates (`EfCorePasskeyStore`, `DapperPasskeyStore`) and verify it with
`SlimIdentity.Testing`. Three rules matter: credential ids are unique (`AddPasskeyAsync` returns `false`, also under
concurrency), `TryRecordUseAsync` is a single compare-and-set statement (same counter **and** a newer challenge), and
`RemovePasskeysAsync` removes every passkey of the user (account takeover above). Store `BackupEligible` and
`BackedUp`; `TryRecordUseAsync` updates `BackedUp` in the same statement.
Key the table by the SHA-256 of the credential id – ids can be up to 1023 bytes, more than SQL Server allows in a key.
