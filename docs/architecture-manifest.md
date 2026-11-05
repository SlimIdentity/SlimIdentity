# SlimIdentity – Architektur-Manifest & Design-Spezifikation (v1.2)

> v1.2 ist der Stand der Implementierung. Abweichungen und Ergänzungen gegenüber dem Entwurf v1.1 stehen in
> [Anhang A](#anhang-a--änderungen-gegenüber-v11).

## 1. Vision & Zweck
**SlimIdentity** ist eine pragmatische, datenbankagnostische Authentifizierungs- und Security-Fassade für ASP.NET Core. Sie schließt die Lücke zwischen dem fehleranfälligen Eigenbau von Login-Endpoints und dem überladenen Tabellen-Zwang von `Microsoft.AspNetCore.Identity` (`MapIdentityApi`).

SlimIdentity stellt in wenigen Minuten fertig gehärtete, Best-Practice-konforme JSON-Endpoints für moderne Web-Frontends (Blazor, Vue, React) und Mobile-Apps bereit, überlässt die Hoheit über Datenbanken, ORMs (EF Core, Dapper) und Domain-Modelle aber zu 100 % dem Host-Projekt.

---

## 2. Eiserne Architektur-Prinzipien (Das Manifest)
1. **Zero Persistence (Der Datenbank-Bann):** Das Kern-NuGet-Paket enthält keinerlei Referenzen auf EF Core, Dapper oder Datenbanktreiber. Es kommuniziert ausschließlich über flache C#-Interfaces mit dem Host-Projekt. Auch interne Hilfsstrukturen (z. B. die Mail-Queue) bleiben im Speicher; wer Dauerhaftigkeit braucht, implementiert sie hinter einem Interface (Outbox-Pattern).
2. **Keine Generics-Hölle & kein Basisklassen-Zwang:** SlimIdentity erzwingt keine generischen Typ-Parameter und verlangt keine Vererbung. Die Library arbeitet intern strikt mit einem einzigen, schlanken Transfer-Objekt (`SlimUser`).
3. **Framework Native:** SlimIdentity erfindet keine eigene Kryptografie. Es orchestriert `Microsoft.Extensions.Identity.Core` (`PasswordHasher`, `IDataProtector`), das native `ClaimsPrincipal`-System, `Microsoft.AspNetCore.RateLimiting` sowie die Standard-Authentication-Handler (Cookies, JwtBearer, OAuth/OIDC). Alle `[Authorize]`-Attribute und Policies funktionieren out-of-the-box.
4. **Explicit & Validated Configuration:** Code-Konfiguration (Fluent API) und/oder `IConfigurationSection` über `IOptions<T>`. `ValidateOnStart()` prüft beim Booten alle sicherheitskritischen Parameter (Fail-Fast).
5. **Opt-In Complexity (Capability Pattern):** Erweiterte Funktionen (2FA, Social Logins/OIDC, Refresh-Tokens, Server-Sessions, API-Keys, LDAP/Custom-Auth) sind inaktiv, bis der Entwickler das entsprechende Interface registriert.
6. **OpenAPI / Swagger First:** Alle Endpoints liefern vollständige OpenAPI-Metadaten (`.Produces<T>()`, `.WithTags()`, präzise DTOs) – inklusive der 403-Antwort der CSRF-Prüfung.
7. **Secure by Default (neu):** Wo Sicherheit und Komfort kollidieren, ist der sichere Wert der Default und der komfortable ein bewusstes Opt-In (z. B. `SignIn.RevealAccountState`).

---

## 3. Das Kern-Datenmodell (`SlimUser` DTO)

| Eigenschaft | Typ | Zweck |
| :--- | :--- | :--- |
| **`Id`** | `string` | Eindeutige User-ID (in der Host-DB `Guid`, `int` oder `string`). |
| **`Email`** | `string` | Primärer Login-Identifikator (oder Benutzername/UPN bei LDAP). |
| **`PasswordHash`** | `string` | Hash via `PasswordHasher<SlimUser>`. Leer bei OAuth-/LDAP-Nutzern und bei **eingeladenen** Nutzern, die ihre Einladung noch nicht angenommen haben. |
| **`SecurityStamp`** | `string` | Zufallswert. Rotiert bei Passwortwechsel, „Überall abmelden“, 2FA-Änderungen, Refresh-Token-Diebstahl; invalidiert sofort alle Cookies, JWTs, Refresh-Tokens und Workflow-Links. |
| **`IsActive`** | `bool` | Login-Blocker (Bann, Soft-Delete, Freigabe ausstehend). |
| **`EmailConfirmed`** | `bool` | E-Mail-Adresse verifiziert. |
| **`FailedLoginAttempts`** | `int` | Aufeinanderfolgende Fehlversuche seit dem letzten erfolgreichen Login (Basis für die progressive Sperre). |
| **`LockoutEndUtc`** | `DateTimeOffset?` | Ende der aktuellen Sperre. |
| **`TwoFactorEnabled`** | `bool` | Nach erfolgreicher Passwortprüfung greift der 2FA-Zustandsautomat. |

---

## 4. Die Verträge (Interfaces & Services)

### 4.1 Zwingende Basis-Interfaces

**`ISlimUserStore`** – unverändert gegenüber v1.1:
```csharp
public interface ISlimUserStore
{
    Task<SlimUser?> FindByEmailAsync(string email, CancellationToken ct);
    Task<SlimUser?> FindByIdAsync(string userId, CancellationToken ct);
    Task<SlimUser> CreateAsync(string email, string passwordHash, CancellationToken ct);
    Task UpdateSecurityStateAsync(SlimUser user, CancellationToken ct);
    Task<IReadOnlyCollection<Claim>> GetClaimsAsync(SlimUser user, CancellationToken ct);
}
```

**`ISlimEmailSender`** – drei Pflicht-Methoden, zwei optionale (Default-Interface-Methoden, ohne Implementierung wird nichts verschickt):
```csharp
public interface ISlimEmailSender
{
    Task SendVerificationEmailAsync(string email, string verificationTokenOrLink, CancellationToken ct);
    Task SendPasswordResetEmailAsync(string email, string resetTokenOrLink, CancellationToken ct);
    Task SendTwoFactorCodeAsync(string email, string code, CancellationToken ct);

    // optional
    Task SendAccountExistsEmailAsync(string email, CancellationToken ct) => Task.CompletedTask;
    Task SendLockoutNotificationEmailAsync(string email, DateTimeOffset lockoutEndUtc, CancellationToken ct) => Task.CompletedTask;
}
```
Verifizierungs-, Reset-, „Konto existiert“- und Sperr-Mails laufen über eine begrenzte In-Memory-Queue mit Hintergrund-Dienst (`Email.SendInBackground`, Default `true`). Beim regulären Herunterfahren wird die Queue innerhalb von `HostOptions.ShutdownTimeout` geleert; nur ein Absturz verliert Mails. Für garantierte Zustellung: Outbox-Sender + `SendInBackground = false` (Sample).

### 4.2 Optionale Capability-Interfaces
* **`ISlimRefreshTokenStore`** – aktiviert `/auth/refresh`:
  * `StoreRefreshTokenAsync(userId, tokenHash, expiresAt, ct)`
  * `ValidateAndConsumeRefreshTokenAsync(tokenHash, ct)` – liefert `userId` und löscht **atomar**.
* **`ISlimSessionStore`** *(neu)* – aktiviert serverseitige Sessions (siehe 5.7):
  * `CreateAsync(SlimSession)`, `FindAsync(sessionId)`, `ListAsync(userId)`, `TouchAsync(sessionId, lastSeen, expires)`, `RevokeAsync(sessionId)`, `RevokeAllAsync(userId, exceptSessionId)`
* **`ISlimTwoFactorStore`** – aktiviert `/auth/login/2fa` und `/auth/2fa/*` (TOTP, Mail-Codes, Recovery-Codes). Unverändert.
* **`ISlimExternalLoginStore`** – aktiviert OAuth/OIDC (Google, Apple, Entra ID, Keycloak). Unverändert. mTLS siehe Abschnitt 9.
* **`ISlimApiKeyStore`** – aktiviert den `X-API-Key`-Handler. Unverändert.
* **`ISlimCustomPasswordValidator`** – LDAP/AD/Legacy-Hashes; Brute-Force-Schutz, Lockout und 2FA bleiben aktiv. Unverändert.

### 4.3 Bereitgestellte Library-Services
```csharp
public interface ISlimAuthManager
{
    Task<SlimAuthResult> SignInAsync(SlimUser user, bool useCookies, bool isPersistent = false, CancellationToken ct = default);

    // Impersonation: 'act'-Claim enthält ID UND Security-Stamp des Admins; wird der Admin gesperrt
    // oder rotiert sein Stamp, endet die Impersonation sofort.
    Task<SlimAuthResult> ImpersonateAsync(SlimUser targetUser, string impersonatorUserId, bool useCookies, CancellationToken ct = default);
    Task<SlimAuthResult> EndImpersonationAsync(CancellationToken ct = default);                       // neu

    Task<SlimAuthResult> ElevateSessionAsync(SlimUser user, IEnumerable<Claim> additionalClaims, bool useCookies, CancellationToken ct = default);

    Task SignOutAsync(string? refreshToken = null, CancellationToken ct = default);                    // aktuelle Session
    Task SignOutEverywhereAsync(SlimUser user, CancellationToken ct = default);                        // neu: alle Sessions (z. B. Bann)

    Task<SlimInvitation> CreateInvitationAsync(SlimUser user, TimeSpan? lifetime = null, CancellationToken ct = default); // neu
}
```

---

## 5. Sicherheits- & Härtungs-Mechanismen („The Shield“)

1. **Mehrstufiger Brute-Force-Schutz**
   * *Layer 1 – IP-Rate-Limiting:* Policy `SlimIdentity_BruteForce` (Default 10/min) für Login, 2FA, Register, Reset, Einladungen; eigene, großzügige Policy `SlimIdentity_Refresh` (Default 60/min) für `/refresh`, weil Refresh-Tokens nicht erratbar sind.
   * *Layer 2 – progressive Kontosperre (NIST SP 800-63B: bremsen statt hart sperren):* Alle `MaxFailedAttempts` Fehlversuche wird gesperrt, beginnend mit `Lockout.Duration` (Default 1 min), jede weitere Sperre doppelt so lang bis `Lockout.MaxDuration` (Default 1 h). Der Zähler wird nur durch einen erfolgreichen Login zurückgesetzt. Versuche während einer Sperre werden weder geprüft noch gezählt. Bei der ersten Sperre einer Serie geht optional eine Benachrichtigungs-Mail raus.
2. **Timing-Attack Mitigation:** Unbekannte E-Mail, inaktives und gesperrtes Konto führen ein Dummy-Hashing durch. Überlange Passwörter (> `Password.MaximumLength`) werden nie gehasht – für bekannte und unbekannte Konten identisch. Vergleiche von Tokens, Stamps und Codes nutzen `CryptographicOperations.FixedTimeEquals`.
3. **Enumeration Prevention:**
   * `/register`, `/forgot-password`, `/resend-verification` antworten immer identisch; Mails werden im Hintergrund verschickt, die Antwortzeit hängt nicht vom Mailserver ab. Bei `/register` mit existierender Adresse erhält der echte Inhaber optional „Sie haben bereits ein Konto“.
   * `/login` unterscheidet standardmäßig **nicht** zwischen falschem Passwort, inaktivem und gesperrtem Konto (einheitlich 401 `invalid_credentials`). Mit `SignIn.RevealAccountState = true` gibt es 403 `account_disabled` bzw. 423 mit Sperrende.
4. **Transparentes Password-Rehashing** bei `SuccessRehashNeeded`.
5. **Stateless Workflow-Tokens:** Verifizierung, Passwort-Reset, Einladung, 2FA-Pre-Auth, Refresh – alle über `IDataProtector`, mit Ablaufdatum und gebunden an den `SecurityStamp` (Einmalnutzung durch Stamp-Rotation).
6. **Cookie-, CORS- & CSRF-Sicherheit:**
   * Cookie immer `HttpOnly` + `Secure` (auch hinter TLS-terminierenden Proxies korrekt).
   * `SameSite = Strict` Default, `Lax` für Cross-Subdomain-SPAs.
   * Zustandsändernde Cookie-Requests brauchen den Header `X-CSRF`; ein vorhandener `Origin` muss die API selbst oder in `Csrf.AllowedOrigins` sein.
7. **Sessions & Logout (neu):**
   * `/logout` beendet die **aktuelle** Session: Cookie löschen, Refresh-Token verbrauchen und – mit `ISlimSessionStore` – die serverseitige Session widerrufen, sodass auch kopierte Cookies/Tokens sofort ungültig sind.
   * `/logout-all` beendet **alle** Sessions auf allen Geräten (Stamp-Rotation + `RevokeAllAsync`), funktioniert auch ohne Session-Store.
   * Ohne Session-Store bleiben Sessions zustandslos: Ein einzelnes kopiertes Cookie lässt sich dann nur über `/logout-all` entwerten.
8. **Refresh-Token-Härtung (RFC 9700 / OAuth 2.1, neu):**
   * Rotation: jedes Token ist genau einmal verwendbar.
   * Reuse Detection: Ein gültiges, aber bereits verbrauchtes Token gilt als gestohlen → mit Session-Store wird die betroffene Session (Token-Familie) widerrufen, sonst rotiert der Stamp (alle Sessions enden). Abschaltbar über `Tokens.RevokeSessionsOnRefreshTokenReuse`.
   * Gleitende Laufzeit (`RefreshTokenLifetime`, 7 Tage) mit absoluter Obergrenze ab dem ursprünglichen Login (`RefreshTokenAbsoluteLifetime`, 30 Tage, Claim `auth_time`).
9. **Impersonation-Bindung (neu):** Der `act`-Claim enthält ID und Stamp des Admins; jede Anfrage prüft auch den Admin. Rückkehr nur über `EndImpersonationAsync` (erneute Prüfung).

---

## 6. Die REST-API (Außenfassade)
Aufruf über `app.MapSlimIdentityApi()`. Dual-Mode über `?useCookies=true` bzw. `Endpoints.DefaultUseCookies`.

| Route (Prefix `/auth`) | Methode | Aktiv wenn | Beschreibung |
| :--- | :--- | :--- | :--- |
| `/login` | POST | immer | 200 (Cookie/JWT), 401 `invalid_credentials` oder `requires_two_factor` (+ `preAuthToken`); 403/423 nur mit `RevealAccountState`. |
| `/login/2fa` | POST | `ISlimTwoFactorStore` | `preAuthToken` + TOTP/Mail-Code oder Recovery-Code → Session. |
| `/login/{provider}` (+ `/callback`) | GET | `ISlimExternalLoginStore` | OAuth/OIDC-Flow. Fehler (auch der Split-Account-Konflikt) als Redirect `?slim_error=<code>` – es ist eine Browser-Navigation, kein `fetch`, daher kein `409`. |
| `/login/external/exchange` | POST | `ISlimExternalLoginStore` + JWT | Einmal-Code aus dem Redirect gegen JWT-Paar (Tokens nie in URLs). |
| `/logout` | POST | `EnableLogout` | Aktuelle Session beenden. |
| `/logout-all` | POST | `EnableLogout` (authentifiziert) | Alle Sessions beenden. |
| `/refresh` | POST | `ISlimRefreshTokenStore` + JWT | Rotation mit Reuse Detection. |
| `/sessions` | GET | `ISlimSessionStore` (authentifiziert) | Aktive Geräte/Sessions inkl. „aktuell“. |
| `/sessions/{id}` | DELETE | `ISlimSessionStore` (authentifiziert) | Ein Gerät abmelden. |
| `/register` | POST | `EnableRegistration` | Nur `email` + `password`; immer 200. |
| `/verify-email`, `/resend-verification` | POST | `EnableEmailVerification` | |
| `/forgot-password`, `/reset-password` | POST | `EnablePasswordReset` | Reset rotiert den Stamp und widerruft alle Sessions. |
| `/invitation/info` | POST | `EnableInvitations` | Prüft den Einladungslink, liefert die eingeladene Adresse und das Ablaufdatum. |
| `/invitation/accept` | POST | `EnableInvitations` | Passwort setzen, E-Mail bestätigen, anmelden (Cookie/JWT). |
| `/change-password` | POST | `EnableChangePassword` (authentifiziert) | Andere Geräte werden abgemeldet, das aktuelle bleibt. |
| `/me` | GET | `EnableMe` (authentifiziert) | Id, E-Mail, Impersonation-Info, Claims. |
| `/2fa`, `/2fa/setup`, `/2fa/enable`, `/2fa/enable-email`, `/2fa/disable`, `/2fa/recovery-codes` | GET/POST | `ISlimTwoFactorStore` (authentifiziert) | |

### 6.1 Einladungen / „Registrierung vervollständigen“
1. Host legt den User mit Business-Daten, aber **ohne Passwort** an (`CreateAsync(email, "")`).
2. `ISlimAuthManager.CreateInvitationAsync(user, lifetime)` liefert Token, Link (`Links.InvitationUrl`) und Ablaufdatum. Den Versand übernimmt der Host (eigener Mailtext, Absender, Branding).
3. Die SPA ruft `/invitation/info` (Formular zeigt die Adresse) und `/invitation/accept` (Passwort nach Policy) auf.
4. Der Link ist zustandslos, an den Stamp gebunden und damit einmalig; er überlebt Neustarts. Default-Gültigkeit 7 Tage (max. 30).
5. Mit `ISlimCustomPasswordValidator` (LDAP) gibt es kein lokales Passwort – Einladungen werden dann abgelehnt (`password_managed_externally`).

---

## 7. Integration & Developer Experience (Setup)
Die Middleware-Reihenfolge bleibt in der Hand des Entwicklers:

```csharp
builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"), options =>
    {
        options.Endpoints.EnableRegistration = false;              // z. B. Invite-Only B2B
        options.Links.InvitationUrl = "https://app.domain.de/accept-invitation?token={token}";
        options.Tokens.JwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET")!;
    })
    .AddUserStore<MyUserStore>()                // Pflicht
    .AddEmailSender<MyEmailSender>()            // Pflicht (oder .AddNullEmailSender())
    .AddRefreshTokenStore<MyTokenStore>()       // optional → /refresh
    .AddSessionStore<MySessionStore>()          // optional → echtes /logout pro Gerät, /sessions
    .AddTwoFactorStore<MyTotpStore>()           // optional → 2FA
    .AddExternalLoginStore<MyOAuthStore>()      // optional → Social Login / OIDC
    .AddApiKeyStore<MyApiKeyStore>()            // optional → X-API-Key
    .AddCustomPasswordValidator<MyLdap>();      // optional → LDAP / Legacy

var app = builder.Build();
app.UseForwardedHeaders();   // nur hinter Reverse-Proxy – vor allem anderen (siehe README)
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapSlimIdentityApi();
```

---

## 8. Repository-Struktur & Ökosystem
```
docs/architecture-manifest.md   dieses Dokument
src/SlimIdentity/               Kern-Paket (keine DB-, SMTP- oder ORM-Abhängigkeiten)
tests/SlimIdentityDemo/         lauffähige Demo mit In-Memory-Stores + .http-Datei
samples/                        Copy-Paste-Vorlagen (nicht im Build)
  EfCore/       alle Stores inkl. Sessions, AppDbContext
  Dapper/       User- und Refresh-Store, schema.sql
  Email/        MailKit, SendGrid, Logging, Outbox (garantierte Zustellung)
  Enterprise/   LDAP, Legacy-Hash-Migration, Admin-Endpoints (Impersonation, Sudo, Einladungen, Bann, API-Keys)
  Frontend/     TypeScript-Client (Cookie- und Bearer-Flow, Geräteliste, Einladungen)
```

---

## 9. mTLS / Client-Zertifikate (dokumentiert, nicht im Kern)
Bewusst nicht eingebaut; so wird es mit den vorhandenen Bausteinen umgesetzt:

1. **Paket:** `Microsoft.AspNetCore.Authentication.Certificate` im Host (nicht im Shared Framework).
2. **Transport:**
   * Kestrel direkt: `ClientCertificateMode.RequireCertificate` (oder `AllowCertificate` nur für bestimmte Routen).
   * Hinter einem TLS-Proxy: Der Proxy prüft das Zertifikat und reicht es im Header weiter (nginx `proxy_set_header X-Client-Cert $ssl_client_escaped_cert;`). In der App `AddCertificateForwarding(o => o.CertificateHeader = "X-Client-Cert")` + `UseCertificateForwarding()` – Header nur von vertrauenswürdigen Proxies akzeptieren (wie bei `UseForwardedHeaders`).
3. **Validierung:** `AddCertificate(o => { o.AllowedCertificateTypes = CertificateTypes.Chained; o.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust; o.CustomTrustStore = …; o.RevocationMode = X509RevocationMode.Online; })`.
4. **Zuordnung Zertifikat → User:** über `ISlimExternalLoginStore` mit Provider `"certificate"` und dem SHA-256-Fingerprint (oder SAN/UPN) als `providerKey` – im Event `OnCertificateValidated`.
5. **Varianten:**
   * *M2M:* Zertifikat bei jedem Request als eigenes Schema (wie API-Keys); im eigenen `[Authorize(AuthenticationSchemes = …)]`.
   * *Benutzer-Login:* eigener Host-Endpoint `POST /api/login/certificate`, der nach erfolgreicher Zertifikatsprüfung `ISlimAuthManager.SignInAsync(user, useCookies)` aufruft. Lockout, 2FA-Pflicht und Sessions verhalten sich wie bei jedem Login.
6. Zertifikatsgebundene Tokens (RFC 8705, `cnf`/`x5t#S256`) sind nicht vorgesehen.

---

## Anhang A – Änderungen gegenüber v1.1

| Bereich | v1.1 | v1.2 | Grund |
| :--- | :--- | :--- | :--- |
| `/logout` | „löscht das Cookie serverseitig“ | Aktuelle Session; serverseitig nur mit `ISlimSessionStore`. Neu `/logout-all`. | Zustandslose Cookies sind nicht einzeln widerrufbar; Abmelden am Laptop soll das Handy nicht abmelden. |
| Server-Sessions | – | `ISlimSessionStore`, `/sessions`, `DELETE /sessions/{id}` | Echte Abmeldung pro Gerät, Geräteliste. |
| `/refresh` | Rotation | + Reuse Detection, absolute Laufzeit, eigene Rate-Limit-Policy | RFC 9700 / OAuth 2.1. |
| Lockout | feste Dauer, Zähler-Reset bei Sperre | progressiv (verdoppelnd, gedeckelt), Reset nur bei Erfolg, optionale Mail | NIST SP 800-63B, weniger Aussperr-Risiko. |
| `/login` bei inaktiv/gesperrt | 423 `Locked`, inaktiv ohne Hashing | Default einheitlich 401 + Dummy-Hash; 403/423 per `RevealAccountState` | OWASP: keine Konto-Enumeration über den Login. |
| `/login/{provider}` Split-Account | `409 Conflict` | Redirect `?slim_error=account_conflict` | Browser-Navigation, kein JSON-Client. |
| Mails | synchron | Hintergrund-Queue, Drain beim Shutdown, Outbox-Sample | Antwortzeit verrät sonst existierende Konten. |
| `ISlimEmailSender` | 3 Methoden | + `SendAccountExistsEmailAsync`, `SendLockoutNotificationEmailAsync` (optional) | Siehe oben. |
| Impersonation | `act` = Admin-ID | `act` = Admin-ID + Stamp + amr; `EndImpersonationAsync` | Gesperrter Admin darf nicht über eine laufende Impersonation zurückkehren. |
| `ISlimAuthManager` | 3 Methoden | + `SignOutAsync`, `SignOutEverywhereAsync`, `EndImpersonationAsync`, `CreateInvitationAsync` | Einladungen, Bann, Rückkehr aus Impersonation. |
| Einladungen | nur Sample mit Invite-Code | `CreateInvitationAsync` + `/invitation/info` + `/invitation/accept` | Häufiger B2B-Fall, sollte nicht jeder selbst bauen. |
| mTLS | bei `ISlimExternalLoginStore` genannt | dokumentiert (Abschnitt 9), nicht im Kern | Abhängigkeit + stark Deployment-spezifisch. |
| Reverse Proxy | – | Doku + Demo (`UseForwardedHeaders`), CSRF-Diagnose-Log | Origin-Prüfung, OAuth-Redirects und Rate-Limits brauchen echtes Schema/IP. |
| Prinzip 7 | – | „Secure by Default“ | |
