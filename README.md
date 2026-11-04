# SlimIdentity

Pragmatische, datenbankagnostische Authentifizierungs- und Security-Fassade für ASP.NET Core (.NET 10).
Gehärtete JSON-Endpoints für SPAs und Mobile-Apps – ohne Identity-Tabellen, ohne Generics, ohne Basisklassen.
Die Spezifikation steht im Architektur-Manifest v1.1.

## Quickstart

```csharp
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"), o =>
    {
        o.Tokens.JwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET")!;
    })
    .AddUserStore<MyUserStore>()              // Pflicht
    .AddEmailSender<MyEmailSender>()          // Pflicht (oder .AddNullEmailSender())
    .AddRefreshTokenStore<MyTokenStore>()     // optional → /refresh
    .AddTwoFactorStore<MyTotpStore>()         // optional → /login/2fa, /2fa/*
    .AddExternalLoginStore<MyOAuthStore>()    // optional → /login/{provider}
    .AddApiKeyStore<MyApiKeyStore>()          // optional → X-API-Key Handler
    .AddCustomPasswordValidator<MyLdap>();    // optional → LDAP / Legacy

var app = builder.Build();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapSlimIdentityApi();
```

Demo starten: `dotnet run --project tests/SlimIdentityDemo` und `SlimIdentityDemo.http` verwenden
(Admin: `admin@demo.local` / `Admin123!`). OpenAPI: `/openapi/v1.json`.

## Endpoints (Prefix `/auth`)

| Route | Methode | Aktiv wenn |
| :--- | :--- | :--- |
| `/login` | POST | immer – `?useCookies=true` für Cookie-Modus |
| `/login/2fa` | POST | `ISlimTwoFactorStore` |
| `/login/{provider}` (+ `/callback`) | GET | `ISlimExternalLoginStore` + Remote-Handler (Google, OIDC, …) |
| `/login/external/exchange` | POST | `ISlimExternalLoginStore` + JWT erlaubt |
| `/logout` | POST | `Endpoints.EnableLogout` |
| `/refresh` | POST | `ISlimRefreshTokenStore` + JWT erlaubt |
| `/register` | POST | `Endpoints.EnableRegistration` |
| `/verify-email`, `/resend-verification` | POST | `Endpoints.EnableEmailVerification` |
| `/forgot-password`, `/reset-password` | POST | `Endpoints.EnablePasswordReset` |
| `/change-password` | POST | `Endpoints.EnableChangePassword` (authentifiziert) |
| `/me` | GET | `Endpoints.EnableMe` (authentifiziert) |
| `/2fa`, `/2fa/setup`, `/2fa/enable`, `/2fa/enable-email`, `/2fa/disable`, `/2fa/recovery-codes` | GET/POST | `ISlimTwoFactorStore` (authentifiziert) |

## Verhalten, das man kennen sollte

- **Claims** sind in Cookie und JWT identisch und kurz: `sub`, `email`, `role`, `amr`, `act`, `sudo_until`, `slim_stamp`.
  `User.GetSlimUserId()`, `GetImpersonatorId()`, `IsInSudoMode()` helfen beim Auslesen.
- **Authentication-Schemes:** `SlimIdentity` (Policy-Scheme, Default) leitet je nach Request an
  `SlimIdentity.Bearer`, `SlimIdentity.ApiKey` oder `SlimIdentity.Cookie` weiter. Abschaltbar über
  `Endpoints.ConfigureDefaultAuthenticationScheme = false`.
- **CSRF (Cookie-Modus):** Zustandsändernde Requests brauchen den Header `X-CSRF` (beliebiger Wert);
  ein vorhandener `Origin` muss die API selbst oder in `Csrf.AllowedOrigins` sein. Eigene Endpoints: `.RequireSlimCsrf()`.
- **Security-Stamp:** Bearer-Requests werden bei jedem Request geprüft, Cookies alle
  `Cookies.SecurityStampValidationInterval` (Default 1 min, `0` = jeder Request).
- **Lockout + 2FA:** Bei aktivem 2FA wird der Fehlversuchszähler erst nach dem zweiten Faktor zurückgesetzt.
- **Refresh-Tokens** sind DataProtector-Payloads, an den Security-Stamp gebunden; der Store sieht nur den SHA-256-Hash.
- **External Login:** Fehler kommen als Redirect auf die `returnUrl` mit `?slim_error=<code>` (`account_conflict` = 409-Fall).
  Bearer-Clients erhalten `?code=…` und tauschen ihn über `/login/external/exchange`. Ist 2FA aktiv, kommt
  `?slim_status=requires_two_factor&preAuthToken=…`.
- **DataProtection:** In Multi-Instance-Deployments Key-Ring persistieren (`PersistKeysTo…`), sonst sind
  Cookies, Reset-Links und Refresh-Tokens instanzgebunden.
- **Rate-Limiter:** Partitioniert nach `RemoteIpAddress` – hinter Reverse-Proxies `UseForwardedHeaders()` vorschalten.
- **Mails ohne Timing-Leck:** Verifizierungs-, Reset- und „Konto existiert bereits“-Mails gehen über eine
  In-Memory-Queue an einen Hintergrund-Service (`Email.SendInBackground`, Default `true`). Die Antwortzeit von
  `/register`, `/forgot-password` und `/resend-verification` hängt damit nicht vom Mailserver ab.
  Fehler beim Versand werden geloggt; beim Herunterfahren gehen ungesendete Mails verloren
  (wer das nicht will: eigener Outbox-Sender + `SendInBackground = false`). 2FA-Codes werden weiterhin direkt verschickt.
- **`/register` mit existierender Adresse:** gleiche Antwort wie bei neuen Konten, der echte Postfachinhaber erhält
  `SendAccountExistsEmailAsync` (Default-Interface-Methode – ohne Implementierung wird keine Mail verschickt).
- **Impersonation:** Der `act`-Claim enthält ID **und Security-Stamp** des Admins. Wird der Admin deaktiviert oder
  rotiert sein Stamp, sind alle von ihm gestarteten Impersonation-Sessions sofort ungültig.
  Zurück zum Admin nur über `ISlimAuthManager.EndImpersonationAsync()` (prüft Stamp und `IsActive` erneut).

## Betrieb hinter einem Reverse-Proxy (TLS-Terminierung)

Das Cookie bekommt immer das `Secure`-Flag (`SecurePolicy = Always`) und funktioniert daher auch, wenn intern
HTTP gesprochen wird. Alles andere braucht die echten Werte aus `X-Forwarded-*`:

| Ohne `UseForwardedHeaders()` | Folge |
| :--- | :--- |
| `Request.Scheme` = `http` | CSRF-Origin-Check schlägt fehl (403 `csrf_validation_failed` bei jedem Cookie-POST) |
| OAuth-`redirect_uri` = `http://…` | Identity Provider lehnt den Login ab |
| `UseHttpsRedirection()` | Redirect-Schleife bzw. 307 bei POSTs |
| `RemoteIpAddress` = Proxy-IP | Alle Nutzer teilen sich **einen** Rate-Limit-Bucket |

```csharp
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    o.KnownProxies.Add(IPAddress.Parse("10.0.0.5"));                    // or:
    o.KnownIPNetworks.Add(System.Net.IPNetwork.Parse("10.0.0.0/8"));   // Docker/K8s network of the proxy
});
app.UseForwardedHeaders();   // before UseHttpsRedirection, UseRateLimiter, UseAuthentication
```

- Default vertraut nur Loopback. In Docker/Kubernetes werden die Header sonst **stillschweigend ignoriert**.
- `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` aktiviert For + Proto, vertraut aber **jedem** Absender –
  nur verwenden, wenn die App ausschließlich über den Proxy erreichbar ist.
- Der Proxy muss den `Host` weiterreichen (nginx: `proxy_set_header Host $host;`) oder `X-Forwarded-Host` setzen.
- Die Demo liest `ReverseProxy:KnownProxies`, `ReverseProxy:KnownNetworks` und `ReverseProxy:AllowedHosts` aus der Konfiguration.
- Alternative nur für die CSRF-Prüfung: öffentliche Adresse in `Csrf.AllowedOrigins` eintragen.
- DataProtection-Key-Ring persistieren, sonst sind nach jedem Container-Neustart alle Cookies/Tokens ungültig.

## Bekannte Grenzen (bewusst stateless)

- TOTP-Codes und E-Mail-Codes sind innerhalb ihres Zeitfensters nicht gegen Replay geschützt
  (das `preAuthToken` ist bis zu `Tokens.PreAuthTokenLifetime` wiederverwendbar).
- `/register` legt bei neuen Adressen einen Datensatz an (`CreateAsync`) – diese eine Datenbank-Schreiboperation
  kann die Antwortzeit gegenüber existierenden Adressen noch leicht verändern. Der Mailversand spielt keine Rolle mehr.
- mTLS-Client-Zertifikate: Host registriert `AddCertificate()` und nutzt `ISlimAuthManager.SignInAsync`.
