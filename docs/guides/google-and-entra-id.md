# Step by step: Google and Microsoft Entra ID

Two complete examples for [external login](external-login.md): "Sign in with Google" for everyone with a Google
account, and Microsoft Entra ID (formerly Azure AD) for the employees of one company. Both use the regular ASP.NET Core
handlers; SlimIdentity maps the result to your users.

You need an external-login store (`.AddExternalLoginStore<T>()` – the EF Core package brings one) and, for every
provider, three things: a client registered at the provider, the handler in `Program.cs`, and a button in the front end.

## Google

### 1. Register the client

In the [Google Cloud Console](https://console.cloud.google.com/apis/credentials):

1. Create a project (or pick one) and set up the **OAuth consent screen**: app name, support e-mail, and the scopes
   `openid`, `email`, `profile` – nothing else is needed. While the app is in *Testing*, only the test users you list
   there can sign in.
2. **Credentials → Create credentials → OAuth client ID**, type *Web application*.
3. **Authorized redirect URIs** – the handler's callback path on your back end (not your front end):
   - `https://api.example.com/signin-google` (production)
   - `http://localhost:5209/signin-google` (development – Google allows plain `http` only for `localhost`)
4. Keep the client ID and the client secret out of the repository:

```bash
dotnet user-secrets set "Google:ClientId" "1234-abc.apps.googleusercontent.com"
dotnet user-secrets set "Google:ClientSecret" "GOCSPX-…"
```

In production, use your secret store (Key Vault, environment variables, …).

### 2. The back end

Package `Microsoft.AspNetCore.Authentication.Google`:

```csharp
var slim = builder.Services.AddSlimIdentity(o =>
    {
        o.TrustedOrigins.Add("https://app.example.com");   // where the front end lives (returnUrl targets)
    })
    .AddUserStore<MyUserStore>()
    .AddEmailSender<MyEmailSender>()
    .AddExternalLoginStore<MyExternalLoginStore>();

slim.Authentication.AddGoogle("Google", o =>
{
    o.ClientId = builder.Configuration["Google:ClientId"]!;
    o.ClientSecret = builder.Configuration["Google:ClientSecret"]!;
    o.ClaimActions.MapJsonKey("email_verified", "email_verified");
    o.UseSlimErrorRedirects();
});
```

The two lines at the end matter:

- **`MapJsonKey("email_verified", …)`** – Google says for every address whether it verified it, but the ASP.NET Core
  handler drops that field. Mapped, SlimIdentity creates and links accounts only for addresses Google has verified
  ([account matching](external-login.md#account-matching)). Do **not** put Google into
  `ExternalLogin.TrustedEmailProviders` instead: a Google account can carry an address of another domain that was
  never verified.
- **`UseSlimErrorRedirects()`** – without it, a user who clicks *Cancel* on Google's consent screen ends on your
  back end's error page. With it, they come back to the front end with `?slim_error=access_denied`; an answer that
  cannot be matched (the sign-in took too long, cookies were blocked, a forged request) brings
  `?slim_error=external_login_failed`.

### 3. The front end

A sign-in with Google is a **page navigation**, not a `fetch`. With the TypeScript client
(`samples/templates/Frontend/slimIdentityClient.ts`):

```ts
// login page
button.onclick = () => auth.loginWith("Google");

// the /after-login page
const result = auth.readExternalLoginResult();          // cookie mode
// const result = await auth.completeExternalLogin();   // bearer mode (PKCE is handled by the client)
switch (result.kind) {
  case "ok":         router.go("/"); break;
  case "two_factor": showCodeInput(result.preAuthToken, result.method); break;   // then auth.loginTwoFactor(…)
  case "error":      showMessage(messages[result.status] ?? "Sign-in failed."); break;
}
```

Messages for the errors a user can actually run into:

| `slim_error` | Show the user |
| :--- | :--- |
| `access_denied` | Nothing, or "Sign-in cancelled." – they clicked *Cancel* |
| `external_login_failed` | "Sign-in did not complete. Please try again." |
| `account_conflict` | "An account with this address already exists. Sign in with your password and link Google in your settings." |
| `email_not_verified` | "Google has not verified this address. Verify it at Google or register with your e-mail." |
| `registration_disabled` | "There is no account for this address." |
| `account_disabled`, `locked_out` | as for a password sign-in |
| `password_change_required` | "Sign in with your password once – you have to change it." |

The full list is in the [endpoint reference](../endpoints.md#external-login-islimexternalloginstore).

### Troubleshooting

| Symptom | Cause |
| :--- | :--- |
| Google shows `redirect_uri_mismatch` | The callback the handler sends differs from the registered one – often `http` instead of `https` behind a reverse proxy: configure forwarded headers ([reverse proxy](reverse-proxy.md)). The error page at Google shows the URI that was sent. |
| `slim_error=external_login_failed` right after Google | The correlation cookie did not survive the round trip: the back end on another site with `SameSite`/third-party cookie restrictions, or more than 15 minutes on Google's page. The log entry 5015 and the handler's log say which. |
| `slim_error=email_not_verified` for every user | `MapJsonKey("email_verified", …)` is missing. |
| `403 access_denied` at Google, "app not verified" | The consent screen is in *Testing* and the account is not a test user. |
| `400 invalid_return_url` before Google opens | The front end's origin is not in `TrustedOrigins`. |

## Microsoft Entra ID

The typical case: the employees of **your** company sign in with their work account. Entra ID speaks OpenID Connect,
so the generic handler does the work.

### 1. Register the app

In the [Entra admin center](https://entra.microsoft.com) → **App registrations → New registration**:

1. **Supported account types:** *Accounts in this organizational directory only* (single tenant). See
   [below](#trusting-the-address) before you pick anything else.
2. **Redirect URI:** platform *Web*, `https://api.example.com/signin-entra` (and `https://localhost:7069/signin-entra`
   for development).
3. **Certificates & secrets → New client secret.** Note the expiry date – the sign-in stops working the day it
   expires. A certificate or a managed identity (federated credential) avoids the secret altogether.
4. **Token configuration → Add optional claim → ID → `email`.** Without it, the ID token carries no address and
   SlimIdentity falls back to `preferred_username` (the sign-in name, often but not always a mailbox).
5. Note the **tenant ID** and the **application (client) ID** from the overview.

### 2. The back end

Package `Microsoft.AspNetCore.Authentication.OpenIdConnect`:

```csharp
var tenantId = builder.Configuration["EntraId:TenantId"];

var slim = builder.Services.AddSlimIdentity(o =>
    {
        o.TrustedOrigins.Add("https://app.example.com");
        o.ExternalLogin.TrustedEmailProviders.Add("EntraId");   // single tenant only – see below
    })
    // … stores …
    ;

slim.Authentication.AddOpenIdConnect("EntraId", "Microsoft", o =>
{
    o.Authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";
    o.ClientId = builder.Configuration["EntraId:ClientId"];
    o.ClientSecret = builder.Configuration["EntraId:ClientSecret"];
    o.ResponseType = "code";                      // authorization code flow with PKCE
    o.CallbackPath = "/signin-entra";
    o.Scope.Add("email");                         // openid and profile are there by default
    o.UseSlimErrorRedirects();
});
```

The scheme name (`EntraId`) is what the front end uses: `auth.loginWith("EntraId")`. The display name (`Microsoft`)
is only for you. Everything about the front end from the Google section applies unchanged.

The account is matched by the token's subject (`sub`) – Entra issues it per user **and** application and never reuses
it, so renaming a user or changing their address does not hand the account to someone else.

### Trusting the address

Entra ID does not send `email_verified`. Whether SlimIdentity may create or link an account by the address depends on
who controls the addresses in the tenant:

- **Single tenant (your company):** your administrators assign the addresses, so the address is as trustworthy as
  your directory – put the scheme into `TrustedEmailProviders`, as above.
- **Multi-tenant ("any organization"):** **never** trust the address. Any tenant's administrator can give a user any
  address, including one of your customers' – that is the *nOAuth* attack. Either match only by `sub` (no
  `TrustedEmailProviders`; users link Entra to their existing account themselves), or add the optional claim
  `xms_edov` ("email domain owner verified") and turn it into `email_verified`:

```csharp
o.Events.OnTokenValidated = context =>
{
    var identity = (ClaimsIdentity)context.Principal!.Identity!;
    // only when Entra confirms that the tenant owns the address's domain – and only for a real e-mail claim
    if (identity.FindFirst(ClaimTypes.Email) is not null && identity.FindFirst("xms_edov")?.Value is "true" or "True" or "1")
        identity.AddClaim(new Claim("email_verified", "true"));
    return Task.CompletedTask;
};
```

  Without the `email` claim, SlimIdentity falls back to `preferred_username`; the snippet adds `email_verified` only
  for a real `email` claim, so such a user is not created (`email_not_verified`).

### Signing out

Entra ID does not support OpenID Connect Back-Channel Logout, so `AddBackChannelLogout` does not help here – signing
out at Microsoft or disabling the user in Entra does not end the session in your application. When an employee leaves,
call `ISlimAuthManager.SignOutEverywhereAsync` and deactivate the account, or check the directory in a sign-in guard
([hooks](hooks.md)) so that the next refresh fails.

## Trying it in the playground

The demo (`samples/SlimIdentity.Demo`) shows a *Sign in with Google* button as soon as credentials are configured:

```bash
dotnet user-secrets set "Google:ClientId" "…" --project samples/SlimIdentity.Demo
dotnet user-secrets set "Google:ClientSecret" "…" --project samples/SlimIdentity.Demo
```

Register `http://localhost:5209/signin-google` as a redirect URI and start the demo with the `http` profile. The button
works in both modes (cookie and bearer with PKCE); a cancelled sign-in shows up as `slim_error=access_denied` in the log.
