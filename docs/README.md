# SlimIdentity documentation

**Choose a path**

- [Minimal setup](minimal-setup.md) – quickest route for an EF Core app with browser cookies
- [Getting started](getting-started.md) – implement your own store and set up a bearer/JWT client
- [Agent integration](agent-integration.md) – compact instructions for coding agents
- [How SlimIdentity works](how-it-works.md) – responsibilities, store contracts and conformance checks

**References**

- [Configuration reference](configuration.md) – every option with its default
- [Endpoint reference](endpoints.md) – routes, request/response bodies, status codes
- [Security model](security.md) – threat model, assumptions and host responsibilities

**Guides**

- [SPA with cookies](guides/spa-cookies.md) – same-site and cross-subdomain setups, CSRF
- [Mobile apps and bearer tokens](guides/mobile-bearer.md) – access/refresh tokens, rotation
- [Sessions and logout](guides/sessions-and-logout.md) – server-side sessions, device list, sign out everywhere
- [Two-factor authentication](guides/two-factor.md) – TOTP with QR code, e-mail codes, recovery codes, replay protection
- [Passkeys](guides/passkeys.md) – WebAuthn sign-in without password, setup, flows, what is checked
- [External login (OAuth / OIDC)](guides/external-login.md) – Google, Entra ID, Keycloak, account linking
- [Google and Microsoft Entra ID](guides/google-and-entra-id.md) – step by step, provider console to front end
- [Invitations](guides/invitations.md) – invite-only registration, "complete your registration"
- [Admin features](guides/admin-features.md) – impersonation, sudo mode, bans, API keys
- [Running without e-mail](guides/without-email.md) – internal services; administrators issue start passwords and resets
- [Registration with business data](guides/registration-profile.md) – validated profile, own sign-up endpoints
- [The first administrator](guides/seeding.md) – seeding by code: start password or reset link, roles, database seeds
- [Hooks: guards and events](guides/hooks.md) – tenant and IP vetoes, registration rules, audit trail
- [Roles and permissions](guides/roles-and-permissions.md) – groups to claims to policies, keeping claims current
- [Multi-tenancy](guides/multi-tenancy.md) – scoped stores, trusted origins and links per tenant domain
- [LDAP and legacy passwords](guides/ldap-and-legacy-passwords.md)
- [Client certificates (mTLS)](guides/client-certificates.md)
- [Data Protection key ring](guides/data-protection.md) – required for production
- [Running behind a reverse proxy](guides/reverse-proxy.md) – TLS termination, forwarded headers
- [Running several instances](guides/multiple-instances.md) – load balancer checklist, no sticky sessions, diagnostics
- [Observability](guides/observability.md) – metrics (OpenTelemetry) and log event ids
- [Native AOT](guides/native-aot.md)
- [Migrating from ASP.NET Core Identity](guides/migrating-from-aspnet-identity.md)

**Background**

- [Architecture and design principles](architecture-manifest.md)
- [Attack scenarios](attack-scenarios.md) – review checklist mapped to tests
- [Review prompt](review-prompt.md) – maintainer briefing for an independent (AI or human) review
