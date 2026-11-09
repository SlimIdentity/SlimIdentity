# Passkeys

Passkeys (WebAuthn) sign users in with Face ID, a fingerprint or a device PIN – no password, nothing to phish:
the browser only offers a passkey to the site it was created for. A passkey with user verification is **multi-factor
on its own** (possession of the device + biometrics / PIN), so no second factor follows.

## Setup

```csharp
builder.Services.AddSlimIdentity(o =>
    {
        o.Links.BaseUrl = "https://app.example.com";        // front end – trusted origin, and the default RP id
        // o.Passkeys.RelyingPartyId = "example.com";        // optional: a parent domain shared by several front ends
        // o.Passkeys.RelyingPartyName = "Example";          // shown by the authenticator (default: TwoFactor.AuthenticatorIssuer)
    })
    .AddEntityFrameworkStores<AppDbContext, AppUser, Guid>(o => o.Passkeys = true)   // opt in; the SlimPasskeys table is always in the model
    // or .AddPasskeyStore<MyPasskeyStore>() – templates for EF Core and Dapper in samples/templates
```

- **Opt-in** – passkeys are off until you register a passkey store (EF Core: `o.Passkeys = true`): they need the
  decision below and a front end that offers them.
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
POST /auth/passkeys/register            { "state", "credential", "name": "Laptop" }   → { "id", "name", "createdUtc" }
```

The password is required for accounts that have one (a stolen session must not add a permanent way in); the address
must be confirmed, and not during an impersonation – the same rules as for 2FA and linking.

**Sign in** (anonymous, no e-mail needed – discoverable credentials):

```http
POST /auth/passkeys/login/options                                   → { "options": { …request options… }, "state": "…" }
     navigator.credentials.get({ publicKey: options })
POST /auth/passkeys/login?useCookies=true|false   { "state", "credential", "rememberMe" }   → session
```

The session has `amr: passkey`. Sign-in guards, inactive accounts and `RequireConfirmedEmail` apply as for every
sign-in; a running password lockout does not block passkeys (there is nothing to guess).

**Manage** – passkeys appear in `GET /auth/sign-in-methods` and are renamed or removed there
(`/sign-in-methods/passkeys/rename`, `/sign-in-methods/passkeys/remove`); removing needs the password if the account has
one and never removes the last way in.

TypeScript: `addPasskey(name, password)`, `loginWithPasskey()`, `signInMethods()`, `renamePasskey(id, name)`,
`removePasskey(id, password)`.

## What is checked

Following Web Authentication Level 2 (§7.1 registration, §7.2 authentication):

| Check | Registration | Sign-in |
| :--- | :---: | :---: |
| `type` (`webauthn.create` / `webauthn.get`), challenge from the signed state, not `crossOrigin` | ✓ | ✓ |
| Origin trusted and within the RP id | ✓ | ✓ |
| RP id hash in the authenticator data | ✓ | ✓ |
| User present **and** verified (biometrics / PIN) | ✓ | ✓ |
| Public key: ES256 (P-256) or RS256 (≥ 2048 bit); credential id unique | ✓ | |
| Registration state bound to the account and its security stamp | ✓ | |
| Signature over authenticator data + client data hash with the stored key | | ✓ |
| User handle matches the passkey's owner | | ✓ |
| Signature counter increases (if the authenticator counts) – else a cloned key is assumed | | ✓ |
| Each challenge counts once per passkey (atomic in the store) – no replay | | ✓ |

Attestation is not evaluated (`attestation: "none"`): SlimIdentity does not decide which authenticator models are
acceptable. Ed25519 keys are not offered – .NET has no built-in support, and passkeys use ES256.

## Your own store

`ISlimPasskeyStore` – start from the templates (`EfCorePasskeyStore`, `DapperPasskeyStore`) and verify it with
`SlimIdentity.Testing`. Two rules matter: credential ids are unique (`AddPasskeyAsync` returns `false`, also under
concurrency), and `TryRecordUseAsync` is a single compare-and-set statement (same counter **and** a newer challenge).
Key the table by the SHA-256 of the credential id – ids can be up to 1023 bytes, more than SQL Server allows in a key.
