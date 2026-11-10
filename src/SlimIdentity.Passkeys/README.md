# SlimIdentity.Passkeys

Passkeys (WebAuthn) for [SlimIdentity](https://www.nuget.org/packages/SlimIdentity): sign-in with Face ID, fingerprint
or device PIN – phishing-resistant, multi-factor on its own, no user name needed.

```bash
dotnet add package SlimIdentity.Passkeys --prerelease   # same version as SlimIdentity
```

```csharp
builder.Services.AddSlimIdentity(o => o.Links.BaseUrl = "https://app.example.com")   // default relying party id
    .AddEntityFrameworkStores<AppDbContext, AppUser, Guid>(o => o.Passkeys = true)   // or .AddPasskeyStore<MyPasskeyStore>()
    .AddPasskeys(o => o.RelyingPartyId = "example.com");                             // optional: a parent domain
```

`MapSlimIdentityApi()` then maps `/auth/passkeys/*`, and passkeys appear in `/auth/sign-in-methods`.

- ES256 and RS256 (≥ 2048 bit); every check of Web Authentication Level 2 §7.1/§7.2 without attestation; user
  verification required; atomic single use per challenge; clone detection by the signature counter.
- No third-party dependency (`System.Formats.Cbor` is part of ASP.NET Core), Native AOT compatible.
- Your own store: implement `ISlimPasskeyStore` and verify it with `SlimIdentity.Testing`.

Guide: [passkeys](https://github.com/SlimIdentity/SlimIdentity/blob/main/docs/guides/passkeys.md).
