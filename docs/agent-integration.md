# Integrating SlimIdentity with a coding agent

Use this page as a compact starting brief when asking a coding agent to add SlimIdentity to an application. It is an
index and a set of guardrails, not a replacement for the API references or the security model.

## Pick the application path

| Application | Start with |
| :--- | :--- |
| EF Core and a browser app served from the same site | [Minimal setup](minimal-setup.md) – cookie authentication |
| Mobile app, cross-site SPA or bearer-token API | [Mobile and bearer tokens](guides/mobile-bearer.md) |
| Database other than EF Core, or a custom user store | [Getting started](getting-started.md) and [store contracts](how-it-works.md#your-part-the-stores) |
| OAuth / OIDC, passkeys, invitations or other optional capability | The matching guide in the [documentation index](README.md) |

Use the `SlimIdentity` package for the core. Add `SlimIdentity.EntityFrameworkCore` for the supplied EF Core stores,
`SlimIdentity.Passkeys` only when passkeys are needed, and `SlimIdentity.Testing` to test custom store implementations.
Keep all SlimIdentity package versions aligned. Check the current package versions and prerelease status rather than
copying a version number from an old example.

## Integration guardrails

- **Follow the documented API.** Use the [endpoint reference](endpoints.md), [configuration reference](configuration.md)
  and current [`samples/templates`](../samples/README.md) for exact names, request shapes and registration methods.
  Do not invent routes, options, interfaces or builder methods.
- **Keep cookie and bearer choices explicit.** Without `Tokens.JwtSecret`, SlimIdentity uses cookie sessions.
  Adding a JWT secret enables bearer authentication; bearer refresh requires an `ISlimRefreshTokenStore`.
- **Keep the middleware and endpoint wiring.** Register `UseRateLimiter()`, `UseAuthentication()` and
  `UseAuthorization()` before mapping `MapSlimIdentityApi()`. If using CORS, configure the trusted origins and call
  `UseCors(SlimIdentityDefaults.CorsPolicy)` in the order shown in [Minimal setup](minimal-setup.md).
- **Protect cookie requests.** State-changing cookie-authenticated requests require `X-CSRF`. Apply
  `.RequireSlimCsrf()` to your own state-changing cookie endpoints; do not disable the built-in CSRF protection.
- **Do not weaken store guarantees.** Custom stores must implement atomic counters and single-use consumption as
  specified in [How SlimIdentity works](how-it-works.md#your-part-the-stores). Verify them with
  `SlimIdentity.Testing` against a disposable database of the production provider; an in-memory provider is not proof
  of atomicity.
- **Secure host-owned endpoints.** Calls to `ISlimAuthManager` do not authorize callers for you. Add the application's
  own authorization policy, CSRF protection for cookie requests, and rate limiting for password-confirmation or
  sign-in-like actions. See [Admin features](guides/admin-features.md).
- **Prepare production infrastructure.** Use HTTPS, load secrets from a secret store, configure trusted origins and
  persist/protect the Data Protection key ring. Follow [Data Protection](guides/data-protection.md) and
  [reverse proxy](guides/reverse-proxy.md) guidance where applicable.

## Verify the result

Before calling the integration complete:

1. Build and run the relevant tests in the host application.
2. Verify that every mapped endpoint and option exists in the current references.
3. Check the [security model](security.md), especially its host responsibilities and known limitations.
4. For a custom store, run the conformance checks against a disposable production-kind database.

For pull requests that change SlimIdentity itself, use [CONTRIBUTING.md](../CONTRIBUTING.md); this page is for agents
integrating the library into a consuming application.
