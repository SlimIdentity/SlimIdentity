# Step by step: Google and Microsoft Entra ID

Two examples for [external login](external-login.md): "Sign in with Google" for everyone, and Microsoft Entra ID for
the employees of one company. Each needs an external-login store (`.AddExternalLoginStore<T>()`; the EF Core package
has one), a client registered at the provider, the handler, and a button in the front end.

## Google

### 1. Register the client

In the [Google Cloud Console](https://console.cloud.google.com/apis/credentials):

1. Set up the **OAuth consent screen** with the scopes `openid`, `email`, `profile`. In *Testing*, only listed test
   users can sign in.
2. **Credentials → Create credentials → OAuth client ID**, type *Web application*.
3. **Authorized redirect URIs** – the back end's callback: `https://api.example.com/signin-google`, and
   `http://localhost:5209/signin-google` for development (plain `http` only for `localhost`).
4. Keep ID and secret out of the repository (`dotnet user-secrets set "Google:ClientId" "…"`, a secret store in
   production).

### 2. The back end

Package `Microsoft.AspNetCore.Authentication.Google`, on the builder from [external login](external-login.md):

```csharp
slim.Authentication.AddGoogle("Google", o =>
{
    o.ClientId = builder.Configuration["Google:ClientId"]!;
    o.ClientSecret = builder.Configuration["Google:ClientSecret"]!;
    o.ClaimActions.MapJsonKey("email_verified", "email_verified");
    o.UseSlimErrorRedirects();
});
```

The ASP.NET Core handler drops Google's `email_verified`; mapped, accounts are created and linked only for addresses
Google verified ([account matching](external-login.md#account-matching)). Do **not** list Google in
`TrustedEmailProviders` instead – a Google account can carry an unverified address of another domain.

### 3. The front end

A page navigation, not a `fetch`. With the TypeScript client (`samples/templates/Frontend/slimIdentityClient.ts`) the
button calls `auth.loginWith("Google")`; the return page calls `readExternalLoginResult()` (cookie mode) or
`completeExternalLogin()` (bearer mode, PKCE handled) and gets `kind` `ok`, `action_required` (`steps`, continue with
`loginTwoFactor(…)` / `completePasswordChange(…)`) or `error` (`status` = the `slim_error`):

| `slim_error` | Show the user |
| :--- | :--- |
| `access_denied` | Nothing, or "Sign-in cancelled." |
| `external_login_failed` | "Sign-in did not complete. Please try again." |
| `account_conflict` | "An account with this address exists. Sign in with your password and link Google in your settings." |
| `email_not_verified` | "Google has not verified this address." |
| `registration_disabled` | "There is no account for this address." |
| `account_disabled`, `locked_out` | as for a password sign-in |

All codes: [endpoint reference](../endpoints.md#external-login-islimexternalloginstore).

### Troubleshooting

| Symptom | Cause |
| :--- | :--- |
| `redirect_uri_mismatch` at Google | The sent callback differs from the registered one – often `http` behind a proxy: [forwarded headers](reverse-proxy.md). |
| `external_login_failed` right after Google | The correlation cookie was lost (cross-site cookie restrictions, more than 15 minutes at Google). See log event 5015. |
| `email_not_verified` for everyone | `MapJsonKey("email_verified", …)` is missing. |
| "app not verified" at Google | Consent screen in *Testing*, account not a test user. |
| `400 invalid_return_url` | The front end's origin is not in `TrustedOrigins`. |

## Microsoft Entra ID

### 1. Register the app

[Entra admin center](https://entra.microsoft.com) → **App registrations → New registration**:

1. **Supported account types:** *this organizational directory only* (single tenant) – read
   [trusting the address](#trusting-the-address) before choosing anything else.
2. **Redirect URI:** *Web*, `https://api.example.com/signin-entra` (plus a localhost one for development).
3. **Certificates & secrets:** a client secret (the sign-in stops on its expiry date), or a certificate / federated
   credential.
4. **Token configuration → optional ID claims `email` and `acct`.** Without `email`, SlimIdentity falls back to
   `preferred_username`; `acct` tells members (`0`) from guests (`1`).

### 2. The back end

Package `Microsoft.AspNetCore.Authentication.OpenIdConnect`:

```csharp
slim.Authentication.AddOpenIdConnect("EntraId", "Microsoft", o =>
{
    o.Authority = $"https://login.microsoftonline.com/{builder.Configuration["EntraId:TenantId"]}/v2.0";
    o.ClientId = builder.Configuration["EntraId:ClientId"];
    o.ClientSecret = builder.Configuration["EntraId:ClientSecret"];
    o.ResponseType = "code";
    o.CallbackPath = "/signin-entra";
    o.Scope.Add("email");
    o.UseSlimErrorRedirects();
    o.Events.OnTokenValidated = context =>
    {
        // single tenant: members' addresses come from your directory – guests' do not
        var identity = (ClaimsIdentity)context.Principal!.Identity!;
        if (identity.FindFirst(ClaimTypes.Email) is not null && identity.FindFirst("acct")?.Value == "0")
            identity.AddClaim(new Claim("email_verified", "true"));
        return Task.CompletedTask;
    };
});
```

The front end uses the scheme name: `auth.loginWith("EntraId")`. Accounts are matched by `sub`, which Entra issues per
user and application and never reuses.

### Trusting the address

Entra ID sends no `email_verified`:

- **Single tenant, members:** your administrators assign the addresses – trust them when `acct` is `0` (snippet above).
- **Guests (`acct` = `1`):** never trust the address; it comes from another tenant or a personal account, and an
  invitation can be redeemed with another account. Guests are matched by `sub` only and link Entra to an existing
  account themselves. Do not put the scheme into `TrustedEmailProviders` – that trusts guests too.
- **Multi-tenant:** never trust the address – any tenant administrator can assign any address (*nOAuth*). Match by
  `sub` only, or add the optional claim `xms_edov` (domain owner verified) and map it:

```csharp
if (identity.FindFirst(ClaimTypes.Email) is not null && identity.FindFirst("xms_edov")?.Value is "true" or "True" or "1")
    identity.AddClaim(new Claim("email_verified", "true"));
```

### Signing out

Entra ID has no back-channel logout: when an employee leaves, call `SignOutEverywhereAsync` and deactivate the
account, or check the directory in a sign-in guard ([hooks](hooks.md)).

## Playground

`samples/SlimIdentity.Demo` shows a Google button once `Google:ClientId` and `Google:ClientSecret` are set as user
secrets (`--project samples/SlimIdentity.Demo`). Register `http://localhost:5209/signin-google` and start the `http`
profile; it works in cookie and bearer mode.
