# External login (OAuth / OIDC)

SlimIdentity orchestrates the regular ASP.NET Core remote handlers and maps the external identity to your users.
Provider walkthroughs (consoles, front end, troubleshooting): **[Google and Microsoft Entra ID](google-and-entra-id.md)**.

```csharp
var slim = builder.Services.AddSlimIdentity(o => o.TrustedOrigins.Add("https://app.example.com"))   // returnUrl targets
    .AddUserStore<MyUserStore>()
    .AddEmailSender<MyEmailSender>()
    .AddExternalLoginStore<MyExternalLoginStore>();

// any remote handler; its SignInScheme defaults to SlimIdentity's external scheme once the store is added
slim.Authentication.AddOpenIdConnect("EntraId", o => { /* Authority, ClientId, … */ o.UseSlimErrorRedirects(); });
```

Register the handler's callback URL at the provider as usual. `UseSlimErrorRedirects()` turns a *Cancel* at the
provider into `?slim_error=access_denied` and an unmatched answer (state lost or forged, correlation cookie gone,
provider error) into `?slim_error=external_login_failed`; without it the user ends on the back end's error page.

## Flow

The front end **navigates** (not `fetch`) to `/auth/login/{provider}?returnUrl=…&useCookies=true|false`. Bearer
clients add PKCE (RFC 7636): a random `code_verifier` (43–128 characters) kept e.g. in `sessionStorage`, and
`code_challenge=BASE64URL(SHA256(verifier))&code_challenge_method=S256` – otherwise `400 code_challenge_required`.

| Situation | Redirect |
| :--- | :--- |
| Cookie mode, success | `returnUrl` – the cookie is set |
| Cookie mode, steps follow (2FA, own password) | `returnUrl#slim_status=action_required&flowToken=…` → `POST /auth/flow` names the steps |
| Bearer mode | `returnUrl#code=…` → `POST /auth/login/external/exchange { code, codeVerifier, twoFactorRememberToken? }` returns the tokens or `action_required` |
| Error | `returnUrl?slim_error=<code>` |

Secrets travel only in the URL fragment; only error codes use the query. The exchange code is valid for 1 minute,
single-use (`ISlimSharedState`, see [several instances](multiple-instances.md)) and useless without the verifier. The
TypeScript client (`samples/templates/Frontend/slimIdentityClient.ts`) does all of this: `loginWith(provider)`,
`readExternalLoginResult()` (cookie) and `completeExternalLogin()` (bearer).

## Account matching

1. Known external identity (provider + subject) → that user.
2. Otherwise an existing account with the same address. "Verified" means `email_verified=true` from the provider, or
   the provider is in `ExternalLogin.TrustedEmailProviders` (only for providers whose addresses you control, e.g. your
   single-tenant Entra ID); linking also requires `AutoLinkVerifiedEmails` (default on).
   - Unconfirmed account **without** any way in (no password, external login or passkey – e.g. created by an
     administrator): confirmed and linked if the address is verified.
   - Confirmed account **without** a password (other provider, LDAP): linked if the address is verified.
   - Everything else – in particular every account **with** a password – `slim_error=account_conflict`: the user signs
     in and [links the provider](#linking-while-signed-in); the owner of an unconfirmed account proves the mailbox with a
     password reset. Linking automatically would let whoever set the password keep access (pre-account hijacking).
3. Otherwise a new password-less user (`AllowAutoRegistration`, default on) – only for a verified address, else
   `slim_error=email_not_verified`; with auto-registration off `slim_error=registration_disabled`.

Inactive and locked accounts are rejected with their error codes. A linked account with an unconfirmed address
continues with the `verify_email` step.

## Linking while signed in

Navigate to `/auth/login/{provider}?link=true&returnUrl=…&code_challenge=…&code_challenge_method=S256`; the return
page receives `#slim_link_code=…` and posts `{ code, codeVerifier, password }` to `POST /auth/link/external` (signed
in: cookie + `X-CSRF`, or bearer) → `200 external_login_linked`.

- `password` is required for accounts that have one; others need a sign-in within 5 minutes
  (`403 reauthentication_required`).
- The address must be confirmed (`403 email_not_confirmed`). An external account linked to another user:
  `409 external_login_taken`. The code lives 1 minute, works once and only with the verifier.
- TypeScript: `linkWith(provider)`, then `completeLink(password)` on the return page.

Own code calling `ISlimExternalLoginStore.LinkExternalLoginAsync` must apply the same proofs and only link confirmed
accounts.

## Managing sign-in methods

`GET /auth/sign-in-methods` lists `hasPassword` and `externalLogins`; `POST /auth/sign-in-methods/external/remove
{ provider, providerKey, password }` removes one (TypeScript: `signInMethods()`, `removeExternalLogin(…)`).

- Removing needs the password, or a sign-in within 5 minutes for accounts without one. Not during impersonation (`403`).
- The last way in is never removed (`409 last_sign_in_method`), also under parallel requests.
- A pure SSO account (external login, no password) gets no password via `/change-password` (`409 password_not_set`)
  or self-service reset (no link is sent; an older link answers `409 external_sign_in_only` at `/flow`), and no
  passkey (`403 password_required`). An administrator can still set one.

## Signing out at the provider

Signing out at the provider or revoking the app's access does not end the application's session. Providers with
**OpenID Connect Back-Channel Logout** (Keycloak, Okta, Auth0, Duende, …) can end it:

```csharp
.AddBackChannelLogout("Keycloak", o =>          // the scheme name of your OIDC handler
{
    o.MetadataAddress = "https://keycloak.example.com/realms/corp/.well-known/openid-configuration";
    o.ClientId = "my-app";                      // the audience of the logout token
})
```

Register `https://api.example.com/auth/backchannel-logout/Keycloak` at the provider. Its signed `logout_token` ends
every session of the user linked to its `sub`. Checked: signature (keys from discovery, cached), issuer, audience,
back-channel event, no `nonce`, issued within 5 minutes, single use; tokens with only a `sid` are rejected. No
`X-CSRF` needed. Without back-channel logout, call `SignOutEverywhereAsync` when the provider reports a sign-out, or
use a sign-in guard ([hooks](hooks.md)) that asks the directory.

WS-Federation works through `AddWsFederation`; client certificates: [client-certificates.md](client-certificates.md).
