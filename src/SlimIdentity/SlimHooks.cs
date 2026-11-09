namespace SlimIdentity;

// Hooks only ever tighten: a guard can refuse, an event handler can only watch. None of them can skip a check, change
// the order of the flow or issue tokens itself.

/// <summary>The answer of a guard that refuses: a machine-readable code and an optional message for the user.</summary>
/// <param name="Error">Snake-case code returned as <c>status</c> (403) or <c>slim_error</c>, e.g. <c>tenant_suspended</c>.</param>
/// <param name="Message">Optional human-readable explanation, returned as <c>message</c>.</param>
public sealed record SlimVeto(string Error, string? Message = null);

/// <summary>When <see cref="ISlimSignInGuard"/> is asked.</summary>
public enum SlimSignInStage
{
    /// <summary>A new session is about to be issued (password, second factor, external login, invitation, impersonation, …).</summary>
    SignIn,
    /// <summary>An existing session is renewed (refresh token, step-up / sudo, end of an impersonation).</summary>
    Renewal,
    /// <summary>A running session is re-validated (every bearer request, cookies every <c>SecurityStampValidationInterval</c>).</summary>
    Revalidation,
}

/// <summary>What <see cref="ISlimSignInGuard"/> decides about.</summary>
public sealed class SlimSignInContext
{
    /// <summary>The account (current state from the store).</summary>
    public required SlimUser User { get; init; }
    /// <summary>How the session was authenticated (<c>amr</c>): <c>pwd</c>, <c>mfa</c>, <c>mfa_remembered</c>, <c>ext</c>, <c>impersonation</c>, <c>api_key</c>, …</summary>
    public required string AuthenticationMethod { get; init; }
    /// <summary>New session, renewal or re-validation.</summary>
    public required SlimSignInStage Stage { get; init; }
    /// <summary>The administrator during an impersonation, else <c>null</c>.</summary>
    public string? ImpersonatorId { get; init; }
    /// <summary>The request (client IP, host name / tenant, headers).</summary>
    public required HttpContext HttpContext { get; init; }
}

/// <summary>
/// Optional veto before any session exists and while it runs: suspended tenants, IP allow-lists, business hours,
/// expired licences. Asked after all of SlimIdentity's own checks passed; can only refuse. Register with
/// <c>AddSignInGuard&lt;T&gt;()</c> (several are allowed – each one can refuse).
/// </summary>
/// <remarks>
/// Re-validation runs on every bearer request (<c>Tokens.ValidateSecurityStampOnEachRequest</c>) and for cookies every
/// <c>Cookies.SecurityStampValidationInterval</c> – keep the check cheap (cache what you look up). A refused sign-in
/// answers <c>403</c> with the veto's code and message (the password was correct, so nothing is revealed); a refused
/// running session ends like a revoked one (<c>401</c>).
/// </remarks>
public interface ISlimSignInGuard
{
    /// <summary><c>null</c> to allow, a <see cref="SlimVeto"/> to refuse.</summary>
    ValueTask<SlimVeto?> CheckAsync(SlimSignInContext context, CancellationToken ct);
}

/// <summary>What <see cref="ISlimRegistrationGuard"/> decides about.</summary>
public sealed class SlimRegistrationContext
{
    /// <summary>The normalized address of the new account.</summary>
    public required string Email { get; init; }
    /// <summary><c>null</c> for <c>/register</c>, the provider for an automatic registration through external login.</summary>
    public string? Provider { get; init; }
    /// <summary>The request (client IP, captcha header, invitation code, …).</summary>
    public required HttpContext HttpContext { get; init; }
}

/// <summary>
/// Optional veto against new accounts: company domains only, invitation codes, captcha checks. Asked before anything is
/// looked up or stored – decide from the request only, never from whether the address already has an account, or the
/// answer reveals it. A refused <c>/register</c> answers <c>403</c> with the veto's code; a refused external
/// auto-registration redirects with <c>slim_error</c>. Register with <c>AddRegistrationGuard&lt;T&gt;()</c>.
/// </summary>
public interface ISlimRegistrationGuard
{
    /// <summary><c>null</c> to allow, a <see cref="SlimVeto"/> to refuse.</summary>
    ValueTask<SlimVeto?> CheckAsync(SlimRegistrationContext context, CancellationToken ct);
}

/// <summary>A security event – reported after it happened. Contains ids only: no passwords, tokens, codes or addresses.</summary>
public sealed class SlimEvent
{
    /// <summary>One of <see cref="SlimEventTypes"/>.</summary>
    public required string Type { get; init; }
    /// <summary>The account concerned; <c>null</c> only for a failed sign-in with an unknown address.</summary>
    public string? UserId { get; init; }
    /// <summary>Who acted on behalf of or on the account: the impersonating administrator.</summary>
    public string? ActorId { get; init; }
    /// <summary>Authentication method (<c>amr</c>) or provider, where it applies.</summary>
    public string? Method { get; init; }
    /// <summary>Why / how, e.g. <c>invalid_password</c>, <c>registration</c>, <c>reset</c>, a guard's veto code.</summary>
    public string? Reason { get; init; }
    /// <summary>When it happened (the injected <see cref="TimeProvider"/>).</summary>
    public required DateTimeOffset Timestamp { get; init; }
    /// <summary>The request it happened in (client IP, user agent) – <c>null</c> outside a request.</summary>
    public HttpContext? HttpContext { get; init; }
}

/// <summary>The event types of <see cref="SlimEvent.Type"/>.</summary>
public static class SlimEventTypes
{
    /// <summary>A new session was issued. <c>Method</c> = amr.</summary>
    public const string SignedIn = "signed_in";
    /// <summary>A sign-in failed. <c>Reason</c>: <c>invalid_password</c>, <c>unknown_user</c>, <c>locked_out</c>, <c>inactive</c>, <c>invalid_two_factor_code</c> or a guard's veto code.</summary>
    public const string SignInFailed = "sign_in_failed";
    /// <summary>The account was locked after repeated failures.</summary>
    public const string LockedOut = "locked_out";
    /// <summary>An administrator ended a lockout.</summary>
    public const string Unlocked = "unlocked";
    /// <summary>An account was created. <c>Reason</c>: <c>registration</c> or <c>external</c> (<c>Method</c> = provider).</summary>
    public const string UserCreated = "user_created";
    /// <summary>The e-mail address was confirmed.</summary>
    public const string EmailConfirmed = "email_confirmed";
    /// <summary>The e-mail address was changed.</summary>
    public const string EmailChanged = "email_changed";
    /// <summary>The password changed. <c>Reason</c>: <c>changed</c>, <c>reset</c>, <c>invitation</c>, <c>forced_change</c> or <c>set_by_administrator</c>.</summary>
    public const string PasswordChanged = "password_changed";
    /// <summary>Two-factor authentication was enabled. <c>Method</c>: <c>totp</c> or <c>email</c>.</summary>
    public const string TwoFactorEnabled = "two_factor_enabled";
    /// <summary>Two-factor authentication was disabled. <c>Reason</c>: <c>user</c> or <c>administrator</c>.</summary>
    public const string TwoFactorDisabled = "two_factor_disabled";
    /// <summary>An external login was linked to the account. <c>Method</c> = provider.</summary>
    public const string ExternalLoginLinked = "external_login_linked";
    /// <summary>The host's claims of the account changed (<c>RefreshClaimsAsync</c>); sessions reload them.</summary>
    public const string ClaimsChanged = "claims_changed";
    /// <summary>An external login was removed from the account. <c>Method</c> = provider.</summary>
    public const string ExternalLoginRemoved = "external_login_removed";
    /// <summary>All sessions of the account were ended (sign out everywhere, ban).</summary>
    public const string SessionsRevoked = "sessions_revoked";
    /// <summary>A used refresh token came back – treated as theft, sessions revoked.</summary>
    public const string RefreshTokenReuse = "refresh_token_reuse";
    /// <summary>An administrator (<c>ActorId</c>) started impersonating the account.</summary>
    public const string ImpersonationStarted = "impersonation_started";
    /// <summary>An impersonation ended (<c>ActorId</c> = administrator).</summary>
    public const string ImpersonationEnded = "impersonation_ended";
}

/// <summary>
/// Optional observer of security events – audit trail, alerts, creating a profile for a new account. Called after the
/// event happened, in the request; it cannot change the outcome. Exceptions are logged and swallowed, so a failing
/// audit sink never breaks a sign-in (write to a durable queue if you need guaranteed delivery). Register with
/// <c>AddEventHandler&lt;T&gt;()</c>; several are allowed.
/// </summary>
public interface ISlimEventObserver
{
    /// <summary>Handles one event.</summary>
    ValueTask HandleAsync(SlimEvent e, CancellationToken ct);
}
