# Hooks: guards and events

Hooks add rules without changing the order of SlimIdentity's checks: **hooks only tighten.** A guard can refuse, an
observer can only watch; no hook skips a check or issues tokens.

| Hook | Register | Can |
| :--- | :--- | :--- |
| `ISlimSignInGuard` | `AddSignInGuard<T>()` | refuse a new session, a renewal or a running session |
| `ISlimRegistrationGuard` | `AddRegistrationGuard<T>()` | refuse a new account (`/register`, external auto-registration) |
| `ISlimRegistrationProfile` | `AddRegistrationProfile<T>()` | validate business data – [guide](registration-profile.md) |
| `ISlimEventObserver` | `AddEventObserver<T>()` | watch security events (audit trail, alerts) |
| `ISlimPasswordRule` | `AddPasswordRule<T>()` | refuse a new password |
| `GetClaimsAsync` of your user store | – | add claims |

All can be registered several times except `ISlimRegistrationProfile`. Default lifetime is scoped (a `DbContext` is
fine).

## Sign-in guard

Asked after SlimIdentity's own checks passed, right before a session is issued, when it is renewed and while it runs:

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
`impersonation`, …), `ImpersonatorId`, the `HttpContext` (`null` outside a request) and the `Stage`:

| Stage | When | A veto means |
| :--- | :--- | :--- |
| `SignIn` | password, second factor, external login, invitation, impersonation and its end | `403` with your code (`slim_error` for external cookie sign-ins); no session |
| `Renewal` | `/refresh`, step-up (`ElevateSessionAsync`) | `403`; the client signs in again |
| `Revalidation` | every bearer request; cookies every `Cookies.SecurityStampValidationInterval` | the session ends (`401`) |

The session re-issued to the caller after its own password or 2FA change is not asked; the next revalidation is.
Revalidation runs often – keep the check cheap and cache lookups for a few seconds. A throwing guard fails closed.

## Registration guard

| Stage | When | Known | A veto means |
| :--- | :--- | :--- | :--- |
| `Begin` | `/register`, before anything is looked up | `Email`, the request | `403` with your code; no mail |
| `Complete` | before the account is written (`/register/password`, `/register/passkey`) | also `CredentialKind` (`password`, `passkey`) and the validated `Profile` | `403`; nothing stored, the flow stays open for a corrected request |
| `External` | auto-registration by an external login | `Provider`, `CredentialKind` `external` | redirect with `slim_error=<code>` |

Without mail, `/register` is one step and asks `Begin`, then `Complete`. Return `null` for stages you ignore:

```csharp
public sealed class CompanyDomainGuard : ISlimRegistrationGuard
{
    public ValueTask<SlimVeto?> CheckAsync(SlimRegistrationContext context, CancellationToken ct) =>
        ValueTask.FromResult(context.Email.EndsWith("@example.com", StringComparison.OrdinalIgnoreCase)
            ? null
            : new SlimVeto("registration_not_allowed", "Please register with your company address."));
}
```

At `Begin` decide from the request only (address, captcha header, invitation code) – never from whether the address
has an account, or the answer reveals it. At `Complete` the mailbox is proven, so deciding on the profile or the
credential kind is safe. Validating business data belongs in `ISlimRegistrationProfile`.

## Calls without a request

Guards also run when your code calls `ISlimAuthManager.BeginRegistrationAsync` outside a request (background job,
import); `CreateUserAsync` asks no guard. They are resolved from their own scope and `context.HttpContext` is `null`:

```csharp
public ValueTask<SlimVeto?> CheckAsync(SlimRegistrationContext context, CancellationToken ct) =>
    ValueTask.FromResult(context.HttpContext is null ? null : new SlimVeto("registration_not_allowed"));   // own import: trusted
```

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
| `sign_in_failed` | reason: `invalid_password`, `unknown_user` (no `UserId`), `locked_out`, `account_disabled`, `invalid_two_factor_code`, a guard's veto code |
| `locked_out`, `unlocked` | – |
| `user_created` | reason `registration`, `external` (method = provider) or `administrator` |
| `email_confirmed`, `email_changed` | – |
| `password_changed` | reason `changed`, `reset`, `invitation`, `forced_change`, `set_by_administrator` |
| `two_factor_enabled` / `two_factor_disabled` | method `totp`/`email` / reason `user`, `administrator` |
| `external_login_linked`, `external_login_removed` | method = provider |
| `passkey_added`, `passkey_removed` | method `passkey` |
| `sessions_revoked`, `refresh_token_reuse` | – |
| `impersonation_started`, `impersonation_ended` | `ActorId` = administrator |

Events are raised after the fact, in the request, sequentially. They carry ids only – no passwords, tokens, codes or
addresses. A throwing observer is logged (event id 3009) and ignored. For guaranteed delivery write to an outbox table
in the same database.
