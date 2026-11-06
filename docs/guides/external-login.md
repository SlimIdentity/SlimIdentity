# External login (OAuth / OIDC)

SlimIdentity does not implement OAuth itself – it orchestrates the regular ASP.NET Core remote handlers and maps the
external identity to your users.

```csharp
var slim = builder.Services.AddSlimIdentity(o =>
    {
        o.TrustedOrigins.Add("https://app.example.com");   // allowed returnUrl targets (besides local paths)
        o.ExternalLogin.TrustedEmailProviders.Add("Google");
    })
    .AddUserStore<MyUserStore>()
    .AddEmailSender<MyEmailSender>()
    .AddExternalLoginStore<MyExternalLoginStore>();

// any remote handler; its SignInScheme must be SlimIdentity's external scheme (the default once the store is added)
slim.Authentication.AddGoogle("Google", o =>
{
    o.ClientId = builder.Configuration["Google:ClientId"]!;
    o.ClientSecret = builder.Configuration["Google:ClientSecret"]!;
});
slim.Authentication.AddOpenIdConnect("EntraId", o => { /* Authority, ClientId, … */ });
```

Register the callback URL of the handler (e.g. `/signin-google`) at the provider as usual.

## Flow

The front end **navigates** (not `fetch`) to `/auth/login/{provider}?returnUrl=…&useCookies=true|false`.
After the provider round trip SlimIdentity redirects to `returnUrl`:

| Situation | Redirect |
| :--- | :--- |
| Cookie mode, success | `returnUrl` – the cookie is set |
| Bearer mode, success | `returnUrl?code=…` → `POST /auth/login/external/exchange { code }` returns the token pair |
| 2FA enabled | `returnUrl?slim_status=requires_two_factor&preAuthToken=…&method=…` → continue with `/auth/login/2fa` |
| Error | `returnUrl?slim_error=<code>` |

Tokens never appear in URLs; the exchange code is valid for 1 minute and works exactly once (registered in
`ISlimRefreshTokenStore`, or in memory when no refresh-token store is registered – then per instance only).

## Account matching

1. Known external identity (`provider` + subject) → that user.
2. Otherwise, an existing account with the same e-mail:
   - linked automatically if the e-mail is **verified** (`email_verified=true`, or the provider is listed in
     `TrustedEmailProviders`) and `AutoLinkVerifiedEmails` is on;
   - otherwise `slim_error=account_conflict` – the user signs in with the password and links the account in your app.
3. Otherwise a new password-less user is created (`AllowAutoRegistration`), or `slim_error=registration_disabled`.

Inactive, locked and (with `RequireConfirmedEmail`) unconfirmed accounts are rejected with matching error codes.

## Enterprise SSO and certificates

Entra ID, Keycloak, Okta, ADFS work through `AddOpenIdConnect` / `AddWsFederation`. Client certificates (mTLS) are not
built in – see the [architecture document](../architecture-manifest.md#9-mtls--client-certificates-documented-not-built-in).
