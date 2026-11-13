# External login (OAuth / OIDC)

SlimIdentity does not implement OAuth itself – it orchestrates the regular ASP.NET Core remote handlers and maps the
external identity to your users.

```csharp
var slim = builder.Services.AddSlimIdentity(o =>
    {
        o.TrustedOrigins.Add("https://app.example.com");   // allowed returnUrl targets (besides local paths)
    })
    .AddUserStore<MyUserStore>()
    .AddEmailSender<MyEmailSender>()
    .AddExternalLoginStore<MyExternalLoginStore>();

// any remote handler; its SignInScheme must be SlimIdentity's external scheme (the default once the store is added)
slim.Authentication.AddGoogle("Google", o =>
{
    o.ClientId = builder.Configuration["Google:ClientId"]!;
    o.ClientSecret = builder.Configuration["Google:ClientSecret"]!;
    o.ClaimActions.MapJsonKey("email_verified", "email_verified");   // Google's verification of the address
    o.UseSlimErrorRedirects();                                       // cancel / failure → ?slim_error= instead of an error page
});
slim.Authentication.AddOpenIdConnect("EntraId", o => { /* Authority, ClientId, … */ o.UseSlimErrorRedirects(); });
```

Register the callback URL of the handler (e.g. `/signin-google`) at the provider as usual. Complete walkthroughs,
including the provider consoles, the front end and the pitfalls: **[Google and Microsoft Entra ID](google-and-entra-id.md)**.

`UseSlimErrorRedirects()` covers what happens before SlimIdentity sees a user: a *Cancel* at the provider returns to
the `returnUrl` with `?slim_error=access_denied`, an answer that cannot be matched (state lost or forged, correlation
cookie gone, provider error) with `?slim_error=external_login_failed`. Without it, ASP.NET Core throws and the user ends
on the back end's error page.

## Flow

The front end **navigates** (not `fetch`) to `/auth/login/{provider}?returnUrl=…&useCookies=true|false`.
Bearer clients add a PKCE challenge (RFC 7636): they create a random `code_verifier` (43–128 characters), keep it
(e.g. in `sessionStorage`) and send `code_challenge=BASE64URL(SHA256(verifier))&code_challenge_method=S256` –
without it the request is rejected with `400 code_challenge_required`.
After the provider round trip SlimIdentity redirects to `returnUrl`:

| Situation | Redirect |
| :--- | :--- |
| Cookie mode, success | `returnUrl` – the cookie is set |
| Cookie mode, steps follow (2FA, own password) | `returnUrl#slim_status=action_required&flowToken=…` → `POST /auth/flow` names the steps, continue with `/auth/login/2fa` or `/auth/login/password-change` |
| Bearer mode | `returnUrl#code=…` → `POST /auth/login/external/exchange { code, codeVerifier, twoFactorRememberToken? }` returns the token pair – or `200 action_required` with the steps |
| Error | `returnUrl?slim_error=<code>` |

Secrets travel only in the URL **fragment**, which browsers never send to servers, logs or referrers; only error codes
use the query. The exchange code is valid for 1 minute, works exactly once (`ISlimSharedState` – across instances with a shared one, see
[several instances](multiple-instances.md)) and only together with the
verifier – an intercepted code (deep link, history, another app) is worthless. The front-end client
(`samples/templates/Frontend/slimIdentityClient.ts`) does all of this: `loginWith(provider)` and
`completeExternalLogin()`.

## Account matching

1. Known external identity (`provider` + subject) → that user.
2. Otherwise, an existing account with the same e-mail:
   - never confirmed (someone registered the address without proving the mailbox): the verified owner takes it over –
     the registrant's password, 2FA, sessions and external logins are removed;
   - confirmed and **without** a password of its own (created by another provider, LDAP): linked automatically if the
     e-mail is **verified** (`email_verified=true`, or the provider is listed in `TrustedEmailProviders` – only for
     providers whose addresses you control, e.g. your company's single-tenant Entra ID) and
     `AutoLinkVerifiedEmails` is on;
   - otherwise – in particular for every account **with** a password – `slim_error=account_conflict`: the user signs in
     with the password and links the provider ([below](#linking-while-signed-in)). A click on a verification link proves
     the mailbox, not who set the password; joining such an account automatically would let whoever registered the
     address keep a password to the account the owner now uses (pre-account hijacking).
3. Otherwise a new password-less user is created (`AllowAutoRegistration`) – only for a **verified** e-mail, else
   `slim_error=email_not_verified` –, or `slim_error=registration_disabled`.

Inactive, locked and (with `RequireConfirmedEmail`) unconfirmed accounts are rejected with matching error codes.

## Linking while signed in

Signed-in users link a provider themselves – the PKCE-bound link code ends up only with the client that started the
flow, and the password confirms it:

```http
GET /auth/login/Google?link=true&returnUrl=https://app.example.com/settings&code_challenge=…&code_challenge_method=S256
→ provider round trip → https://app.example.com/settings#slim_link_code=…

POST /auth/link/external          (signed in: cookie + X-CSRF, or bearer)
{ "code": "…", "codeVerifier": "…", "password": "…" }
→ 200 external_login_linked
```

- `password` is required for accounts that have one; accounts without one need a sign-in within the last 5 minutes
  (`403 reauthentication_required` – sign in again, then repeat): a stolen session alone must not add a permanent way in.
- The account's address must be confirmed (`403 email_not_confirmed`), like for setting up 2FA.
- An external account already linked to another user answers `409 external_login_taken`.
- A link code planted in someone else's URL (link CSRF) fails at the verifier. Codes live 1 minute and work once.

The TypeScript client does it with `linkWith(provider)` and, on the return page, `completeLink(password)`.

If your own code links identities (`ISlimExternalLoginStore.LinkExternalLoginAsync`), do it only for confirmed accounts
and only after the same proofs.

## Managing sign-in methods

```http
GET  /auth/sign-in-methods                    → { "hasPassword": true, "externalLogins": [ { "provider": "Google", "providerKey": "1093…" } ] }
POST /auth/sign-in-methods/external/remove    { "provider": "Google", "providerKey": "1093…", "password": "…" }
```

- Removing needs the current password – or, for accounts without one, a sign-in within the last 5 minutes: a stolen
  session alone must not cut the owner's ways in.
- **The last way in is never removed:** an account without a password keeps at least one external login or passkey
  (`409 last_sign_in_method` – link another provider first). Parallel removals cannot get around it.
- **A pure SSO account stays without local credentials:** an account without a password but with an external login
  gets no password via `/change-password` (`409 password_not_set`) or a self-service reset (`/forgot-password` sends
  no link, `/reset-password` answers `409 external_sign_in_only`), and no passkey (`403 password_required`). An
  administrator can still set one (`SetPasswordAsync`, `CreatePasswordResetAsync`). Linking a provider to an account
  with a password changes nothing – password and passkeys stay.
- Not during an impersonation (`403`). Event `external_login_removed`.

TypeScript: `signInMethods()` and `removeExternalLogin(provider, providerKey, password)`.

## Signing out at the provider

After the sign-in, the session lives in your application. Signing out at the provider – or revoking the app's access in
the Google or Microsoft account – does not end it; that is how social logins work everywhere.

Enterprise identity providers (Keycloak, Okta, Auth0, Duende, …) can tell the application through **OpenID Connect
Back-Channel Logout** when they sign a user out or block them:

```csharp
.AddBackChannelLogout("Keycloak", o =>          // the scheme name of your OIDC handler
{
    o.MetadataAddress = "https://keycloak.example.com/realms/corp/.well-known/openid-configuration";
    o.ClientId = "my-app";                      // the audience of the logout token
})
```

Register `https://api.example.com/auth/backchannel-logout/Keycloak` as the client's back-channel logout URL at the
provider. It posts a signed `logout_token`; every session of the user linked to its `sub` ends (all devices – the
provider ended the user's single sign-on). The token is checked like any credential: signature with the provider's
keys (from the discovery document, cached), issuer, audience, the back-channel event, no `nonce`, issued within the last
5 minutes, single use. Tokens that carry only a `sid` are rejected – configure the provider to send `sub` (Keycloak and
the others do by default). The endpoint is authenticated by the token, not by a cookie, so it needs no `X-CSRF` header.

For providers without back-channel logout, end a user's sessions from your own code with
`ISlimAuthManager.SignOutEverywhereAsync` when the provider reports a sign-out or a block – or use a sign-in guard
([hooks](hooks.md)) that asks your directory whether the account is still enabled.

## Enterprise SSO and certificates

Entra ID, Keycloak, Okta, ADFS work through `AddOpenIdConnect` / `AddWsFederation`. Client certificates (mTLS) are not
built in – see the [architecture document](../architecture-manifest.md#9-mtls--client-certificates-documented-not-built-in).
