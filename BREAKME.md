# Break SlimIdentity

You are invited to attack SlimIdentity – on your own machine.

```bash
BREAKME=true docker compose up --build        # PowerShell: $env:BREAKME="true"; docker compose up --build
```

Open <http://localhost:8080>. The playground shows every flow (cookies and bearer tokens, 2FA with a virtual
authenticator, sessions, password reset, e-mail change, impersonation) and a request log. Mails to addresses you
register land in its fake mailbox. The API itself is at `/auth/*` (OpenAPI: `/openapi/v1.json`) – use curl, Burp,
ZAP or your own scripts as you like.

In Breakme mode the two seeded accounts get **random passwords** that only the operator sees in the container log:

| Account | Role |
| :--- | :--- |
| `admin@demo.local` | `Admin` |
| `user@demo.local` | – |

## Goals

1. **Sign in as `user@demo.local`** – without its password.
2. **Become admin**: call `GET /api/admin` successfully with a session that is not `admin@demo.local`'s own, or as `admin@demo.local` without its password.
3. **Take over a session** of another account you created (in a second browser) without its password.
4. **Keep access after a reset**: get access to an account, let its owner reset the password or sign out everywhere – and still be in.
5. **Read someone else's secret**: a reset or verification link, a 2FA code, a refresh token of an account that is not yours.
6. **Get past the guards**: more than 10 sign-in attempts per minute from one client, more than 5 wrong passwords without a lockout, or a usable 2FA code reused.
7. **Forge**: make the server accept a token, cookie or link you created yourself.
8. **Learn what you should not**: find out whether an address is registered, or whether an account is locked, from answers or timing.

Anything that breaks one of the rules in the [security model](docs/security.md) counts – the
[attack scenarios](docs/attack-scenarios.md) list what is already covered by tests.

## Rules

- **Your machine only.** This invitation covers the container you run locally – never attack anyone else's deployment.
- Out of scope: the fake mailbox (it deliberately shows mails of every non-seeded address), the demo-only host
  endpoints' business logic beyond authentication, denial of service by brute load, and the deliberately simple
  in-memory demo stores (real stores are covered by `SlimIdentity.Testing`).
- **Report findings privately** as described in [SECURITY.md](SECURITY.md) – please do not open public issues. A short
  description, the requests and, ideally, a failing test in the style of `tests/SlimIdentity.Tests/Integration` are
  perfect: every confirmed finding becomes a permanent regression test.
