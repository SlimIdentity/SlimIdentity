# SlimIdentity

Pragmatische, datenbankagnostische Authentifizierungs- und Security-Fassade für ASP.NET Core (.NET 10).
Gehärtete JSON-Endpoints für SPAs und Mobile-Apps – ohne Identity-Tabellen, ohne Generics, ohne Basisklassen.
Die Spezifikation steht im [Architektur-Manifest v1.2](docs/architecture-manifest.md)
(inkl. Änderungen gegenüber dem Entwurf v1.1 und mTLS-Leitfaden).

## Quickstart

```csharp
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"), o =>
    {
        o.Tokens.JwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET")!;
    })
    .AddUserStore<MyUserStore>()              // Pflicht
    .AddEmailSender<MyEmailSender>()          // Pflicht (oder .AddNullEmailSender())
    .AddRefreshTokenStore<MyTokenStore>()     // optional → /refresh
    .AddSessionStore<MySessionStore>()        // optional → /logout pro Gerät, /sessions
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
| `/logout` | POST | `Endpoints.EnableLogout` – aktuelle Session |
| `/logout-all` | POST | `Endpoints.EnableLogout` (authentifiziert) – alle Geräte |
| `/refresh` | POST | `ISlimRefreshTokenStore` + JWT erlaubt |
| `/sessions`, `/sessions/{id}` | GET/DELETE | `ISlimSessionStore` (authentifiziert) |
| `/register` | POST | `Endpoints.EnableRegistration` |
| `/invitation/info`, `/invitation/accept` | POST | `Endpoints.EnableInvitations` |
| `/verify-email`, `/resend-verification` | POST | `Endpoints.EnableEmailVerification` |
| `/forgot-password`, `/reset-password` | POST | `Endpoints.EnablePasswordReset` |
| `/change-password` | POST | `Endpoints.EnableChangePassword` (authentifiziert) |
| `/me` | GET | `Endpoints.EnableMe` (authentifiziert) |
| `/2fa`, `/2fa/setup`, `/2fa/enable`, `/2fa/enable-email`, `/2fa/disable`, `/2fa/recovery-codes` | GET/POST | `ISlimTwoFactorStore` (authentifiziert) |

## Verhalten, das man kennen sollte

- **Claims** sind in Cookie und JWT identisch und kurz: `sub`, `email`, `role`, `amr`, `auth_time`, `sid`, `act`, `sudo_until`, `slim_stamp`.
  `User.GetSlimUserId()`, `GetImpersonatorId()`, `IsInSudoMode()` helfen beim Auslesen.
- **Authentication-Schemes:** `SlimIdentity` (Policy-Scheme, Default) leitet je nach Request an
  `SlimIdentity.Bearer`, `SlimIdentity.ApiKey` oder `SlimIdentity.Cookie` weiter. Abschaltbar über
  `Endpoints.ConfigureDefaultAuthenticationScheme = false`.
- **CSRF (Cookie-Modus):** Zustandsändernde Requests brauchen den Header `X-CSRF` (beliebiger Wert);
  ein vorhandener `Origin` muss die API selbst oder in `Csrf.AllowedOrigins` sein. Eigene Endpoints: `.RequireSlimCsrf()`.
- **Security-Stamp:** Bearer-Requests werden bei jedem Request geprüft, Cookies alle
  `Cookies.SecurityStampValidationInterval` (Default 1 min, `0` = jeder Request).
- **Lockout (progressiv):** Alle `Lockout.MaxFailedAttempts` Fehlversuche wird gesperrt – 1 min, 2, 4, 8 … bis
  `Lockout.MaxDuration` (1 h). Zurückgesetzt wird nur durch einen erfolgreichen Login. Optional
  `SendLockoutNotificationEmailAsync` bei der ersten Sperre einer Serie.
  Bei aktivem 2FA wird der Zähler erst nach dem zweiten Faktor zurückgesetzt.
- **Login-Antworten:** Default einheitlich 401 `invalid_credentials` für falsches Passwort, inaktives und gesperrtes
  Konto (keine Enumeration). `SignIn.RevealAccountState = true` liefert 403 `account_disabled` bzw. 423 mit `lockoutEndUtc`.
- **Refresh-Tokens** sind DataProtector-Payloads, an den Security-Stamp gebunden; der Store sieht nur den SHA-256-Hash.
  Einmal verwendbar; ein wiederverwendetes Token gilt als gestohlen (`Tokens.RevokeSessionsOnRefreshTokenReuse`):
  mit Session-Store wird die Session widerrufen, sonst rotiert der Stamp (alle Geräte abgemeldet).
  Gleitend `Tokens.RefreshTokenLifetime` (7 Tage), absolut `Tokens.RefreshTokenAbsoluteLifetime` (30 Tage ab Login).
  `/refresh` hat ein eigenes, großzügiges Rate-Limit (`RateLimit.RefreshPermitLimit`, 60/min).
  Clients müssen parallele Refreshes bündeln (siehe `samples/Frontend`), sonst löst der zweite die Reuse-Erkennung aus.
- **Sessions:** Ohne `ISlimSessionStore` sind Sessions zustandslos – `/logout` löscht nur Cookie bzw. Refresh-Token,
  ein kopiertes Cookie bleibt bis zum Ablauf gültig; `/logout-all` beendet trotzdem alles (Stamp-Rotation).
  Mit Session-Store bekommt jede Anmeldung eine `sid`, die bei jeder Prüfung (Bearer: jeder Request,
  Cookie: alle `SecurityStampValidationInterval`) gegen den Store geht. `ISlimAuthManager.SignOutEverywhereAsync(user)` für Banns.
- **Einladungen:** User ohne Passwort anlegen (`CreateAsync(email, "")`), `ISlimAuthManager.CreateInvitationAsync(user)`
  liefert Link + Ablauf (`Links.InvitationUrl`, Default 7 Tage), Versand macht der Host. Die SPA nutzt
  `/invitation/info` und `/invitation/accept`. Einmalig (Stamp-Bindung), überlebt Neustarts.
- **External Login:** Fehler kommen als Redirect auf die `returnUrl` mit `?slim_error=<code>` (`account_conflict` = 409-Fall).
  Bearer-Clients erhalten `?code=…` und tauschen ihn über `/login/external/exchange`. Ist 2FA aktiv, kommt
  `?slim_status=requires_two_factor&preAuthToken=…`.
- **DataProtection:** In Multi-Instance-Deployments Key-Ring persistieren (`PersistKeysTo…`), sonst sind
  Cookies, Reset-Links und Refresh-Tokens instanzgebunden.
- **Rate-Limiter:** Partitioniert nach `RemoteIpAddress` – hinter Reverse-Proxies `UseForwardedHeaders()` vorschalten.
- **Mails ohne Timing-Leck:** Verifizierungs-, Reset- und „Konto existiert bereits“-Mails gehen über eine
  In-Memory-Queue an einen Hintergrund-Service (`Email.SendInBackground`, Default `true`). Die Antwortzeit von
  `/register`, `/forgot-password` und `/resend-verification` hängt damit nicht vom Mailserver ab.
  Fehler beim Versand werden geloggt. Beim regulären Herunterfahren wird die Queue innerhalb von
  `HostOptions.ShutdownTimeout` geleert; nur ein Absturz verliert Mails (garantierte Zustellung:
  `samples/Email/OutboxEmailSender.cs` + `SendInBackground = false`). 2FA-Codes werden weiterhin direkt verschickt.
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
- mTLS-Client-Zertifikate sind nicht im Kern – Leitfaden in [Manifest, Abschnitt 9](docs/architecture-manifest.md#9-mtls--client-zertifikate-dokumentiert-nicht-im-kern).
