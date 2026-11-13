# Integrating SlimIdentity with a coding agent

A compact brief for coding agents adding SlimIdentity to an application. It indexes the references; it does not
replace them.

## Pick the path

| Application | Start with |
| :--- | :--- |
| EF Core, browser app on the same site | [Minimal setup](minimal-setup.md) (cookies) |
| Mobile app, cross-site SPA, bearer API | [Mobile and bearer tokens](guides/mobile-bearer.md) |
| Other database or own user store | [Getting started](getting-started.md), [store rules](how-it-works.md#your-part-the-stores) |
| OAuth/OIDC, passkeys, invitations, … | the guide in the [documentation index](README.md) |

Packages: `SlimIdentity` (core), `SlimIdentity.EntityFrameworkCore` (EF Core stores), `SlimIdentity.Passkeys` (only
for passkeys), `SlimIdentity.Testing` (store tests). Keep their versions aligned; check the current version instead of
copying one from an example.

## Guardrails

- **Use the documented API only** – [endpoints](endpoints.md), [configuration](configuration.md) and
  [`samples/templates`](../samples/README.md). Do not invent routes, options, interfaces or builder methods.
- **Cookie vs. bearer is explicit:** without `Tokens.JwtSecret` only cookie sessions exist; refresh needs an
  `ISlimRefreshTokenStore`.
- **Middleware order:** `UseRateLimiter()`, `UseAuthentication()`, `UseAuthorization()` before
  `MapSlimIdentityApi()`; `UseCors(SlimIdentityDefaults.CorsPolicy)` before authentication.
- **CSRF:** cookie requests that change state send `X-CSRF`; own endpoints use `.RequireSlimCsrf()`.
- **Store guarantees:** custom stores follow the [store rules](how-it-works.md#your-part-the-stores) and are verified
  with `SlimIdentity.Testing` against a disposable database of the production provider (in-memory providers prove
  nothing).
- **Host endpoints:** `ISlimAuthManager` does not authorize callers. Add your authorization policy, CSRF protection and
  rate limiting ([admin features](guides/admin-features.md)).
- **Production:** HTTPS, secrets from a secret store, trusted origins, a persisted and protected
  [Data Protection key ring](guides/data-protection.md), [forwarded headers](guides/reverse-proxy.md) behind a proxy.

## Done when

1. The host builds and its tests pass.
2. Every mapped endpoint and option exists in the current references.
3. The [security model](security.md) host responsibilities and known limitations are addressed.
4. Custom stores pass the conformance checks.

Changes to SlimIdentity itself: [CONTRIBUTING.md](../CONTRIBUTING.md).
