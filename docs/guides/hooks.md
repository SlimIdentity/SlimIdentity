# Hooks: guards and events

SlimIdentity's flows are fixed – the order of checks is what makes them safe. Hooks let you add your own rules
without touching that order, under one rule: **hooks only tighten.** A guard can refuse, an observer can only watch.
No hook can skip a check, change the order of the flow or issue tokens itself.

| Hook | Register | Can |
| :--- | :--- | :--- |
| `ISlimSignInGuard` | `AddSignInGuard<T>()` | refuse a new session, a renewal or a running session |
| `ISlimRegistrationGuard` | `AddRegistrationGuard<T>()` | refuse a new account (`/register`, external auto-registration) |
| `ISlimRegistrationProfile` | `AddRegistrationProfile<T>()` | validate business data of `/register` – [guide](registration-profile.md) |
| `ISlimEventObserver` | `AddEventObserver<T>()` | watch security events (audit trail, alerts) |
| `ISlimPasswordRule` | `AddPasswordRule<T>()` | refuse a new password |
| `GetClaimsAsync` of your user store | – | add claims |

All of them can be registered several times; the default lifetime is scoped, so they may use your `DbContext`.

## Sign-in guard

Asked after all of SlimIdentity's own checks passed – the password and the second factor were correct, the account
is active – right before a session is issued, when it is renewed and while it runs:

```csharp
public sealed class TenantGuard(TenantDirectory tenants) : ISlimSignInGuard
{
    public async ValueTask<SlimVeto?> CheckAsync(SlimSignInContext context, CancellationToken ct) =>
        await tenants.IsSuspendedAsync(context.User.Id, ct)
            ? new SlimVeto("tenant_suspended", "Your organization's access is suspended.")
            : null;
}

builder.Services.AddSlimIdentity(…).AddSignInGuard<TenantGuard>();
```

`SlimSignInContext` carries the user, the authentication method (`pwd`, `mfa`, `mfa_remembered`, `ext`,
`impersonation`, …), the impersonating administrator if any, the `HttpContext` (client IP, host name) and the
`Stage`:

| Stage | When | A veto means |
| :--- | :--- | :--- |
| `SignIn` | password, second factor, external login, invitation, impersonation, end of an impersonation | `403` with your code and message (`slim_error` for an external cookie sign-in); no session |
| `Renewal` | `/refresh`, step-up (`ElevateSessionAsync`) | `403`; the client signs in again |
| `Revalidation` | every bearer request, cookies every `Cookies.SecurityStampValidationInterval` | the running session ends (`401`) |

Re-validation runs often – **keep the check cheap** and cache what you look up (a few seconds of cache are fine:
re-validation is not the only gate). A guard that throws fails closed: no session.

Typical uses: suspended tenants or licences, IP allow-lists for administrators, business hours, "only from the
corporate network for impersonation" (`context.ImpersonatorId is not null`).

## Registration guard

Asked before anything is looked up or stored:

```csharp
public sealed class CompanyDomainGuard : ISlimRegistrationGuard
{
    public ValueTask<SlimVeto?> CheckAsync(SlimRegistrationContext context, CancellationToken ct) =>
        ValueTask.FromResult(context.Email.EndsWith("@example.com", StringComparison.OrdinalIgnoreCase)
            ? null
            : new SlimVeto("registration_not_allowed", "Please register with your company address."));
}
```

`/register` answers a veto with `403` and your code; an external auto-registration redirects with
`slim_error=<code>`. **Decide from the request only** (address, `Provider`, headers such as a captcha token or an
invitation code) – never from whether the address already has an account, or the answer reveals it.

Business data for the new account (company, name, terms) is not a guard's job: `ISlimRegistrationProfile` validates
it and your store writes it with the account – see [registration with business data](registration-profile.md).

## Events

```csharp
public sealed class AuditTrail(AppDbContext db) : ISlimEventObserver
{
    public async ValueTask HandleAsync(SlimEvent e, CancellationToken ct)
    {
        db.Audit.Add(new AuditEntry(e.Type, e.UserId, e.ActorId, e.Method, e.Reason, e.Timestamp,
            e.HttpContext?.Connection.RemoteIpAddress?.ToString()));
        await db.SaveChangesAsync(ct);
    }
}
```

| Type (`SlimEventTypes`) | `Method` / `Reason` |
| :--- | :--- |
| `claims_changed` | – (`RefreshClaimsAsync`) |
| `signed_in` | method (`pwd`, `mfa`, `ext`, …); `ActorId` during an impersonation |
| `sign_in_failed` | reason: `invalid_password`, `unknown_user` (no `UserId`), `locked_out`, `inactive`, `attempts_queued`, `invalid_two_factor_code`, a guard's veto code |
| `locked_out`, `unlocked` | – |
| `user_created` | reason `registration` or `external` (method = provider) |
| `email_confirmed`, `email_changed` | – |
| `password_changed` | reason `changed`, `reset`, `invitation`, `forced_change`, `set_by_administrator` |
| `two_factor_enabled` / `two_factor_disabled` | method `totp`/`email` / reason `user`, `administrator` |
| `external_login_linked`, `external_login_removed` | method = provider |
| `passkey_added`, `passkey_removed` | method `passkey` |
| `sessions_revoked`, `refresh_token_reuse` | – |
| `impersonation_started`, `impersonation_ended` | `ActorId` = administrator |

Events are raised after the fact, in the request, one observer after the other. They contain ids only – never
passwords, tokens, codes or addresses. An observer that throws is logged (event id 3009) and ignored: a failing
audit sink never blocks a sign-in. If every event must survive a crash, write it to an outbox table in the same
database and process it from there.
