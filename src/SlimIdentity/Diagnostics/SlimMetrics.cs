using System.Diagnostics.Metrics;
using SlimIdentity.Services;

namespace SlimIdentity.Diagnostics;

/// <summary>
/// Metrics of the meter <see cref="SlimIdentityDefaults.MeterName"/> (System.Diagnostics.Metrics – no dependency).
/// Collect them with OpenTelemetry (<c>.WithMetrics(m =&gt; m.AddMeter("SlimIdentity"))</c>), <c>dotnet-counters</c>
/// or any other listener. Tags never contain user ids or e-mail addresses.
/// </summary>
internal sealed class SlimMetrics
{
    private readonly Counter<long> _logins;
    private readonly Counter<long> _twoFactor;
    private readonly Counter<long> _lockouts;
    private readonly Counter<long> _refreshes;
    private readonly Counter<long> _signOuts;
    private readonly Counter<long> _registrations;
    private readonly Counter<long> _passwordResets;
    private readonly Counter<long> _emailChanges;
    private readonly Counter<long> _invitations;
    private readonly Counter<long> _externalLogins;
    private readonly Counter<long> _impersonations;
    private readonly Counter<long> _mails;
    private readonly Counter<long> _rateLimited;

    public SlimMetrics(IMeterFactory meterFactory, SlimEmailQueue queue)
    {
#pragma warning disable CA2000 // meters created by IMeterFactory are owned and disposed by the factory
        var meter = meterFactory.Create(SlimIdentityDefaults.MeterName);
#pragma warning restore CA2000
        _logins = meter.CreateCounter<long>("slimidentity.logins", "{attempt}",
            "Password sign-in attempts by result (success, invalid_credentials, requires_two_factor, email_not_confirmed) and mode.");
        _twoFactor = meter.CreateCounter<long>("slimidentity.two_factor.verifications", "{attempt}",
            "Second-factor verifications by method (totp, email, recovery) and result (success, failure, replay).");
        _lockouts = meter.CreateCounter<long>("slimidentity.lockouts", "{lockout}", "Account lockouts.");
        _refreshes = meter.CreateCounter<long>("slimidentity.token_refreshes", "{refresh}",
            "Refresh-token rotations by result (success, invalid, reuse_detected, session_expired).");
        _signOuts = meter.CreateCounter<long>("slimidentity.sign_outs", "{sign_out}", "Sign-outs by scope (session, everywhere).");
        _registrations = meter.CreateCounter<long>("slimidentity.registrations", "{registration}",
            "Registrations by result (created, existing_account).");
        _passwordResets = meter.CreateCounter<long>("slimidentity.password_resets", "{reset}", "Password resets by stage (requested, completed).");
        _emailChanges = meter.CreateCounter<long>("slimidentity.email_changes", "{change}", "E-mail changes by stage (requested, completed).");
        _invitations = meter.CreateCounter<long>("slimidentity.invitations", "{invitation}", "Invitations by stage (created, accepted).");
        _externalLogins = meter.CreateCounter<long>("slimidentity.external_logins", "{login}",
            "External logins by provider and result (success, linked, created, conflict, rejected).");
        _impersonations = meter.CreateCounter<long>("slimidentity.impersonations", "{impersonation}", "Impersonations by stage (started, ended).");
        _mails = meter.CreateCounter<long>("slimidentity.mails", "{mail}", "Mails by kind and result (sent, failed, dropped).");
        _rateLimited = meter.CreateCounter<long>("slimidentity.rate_limit.rejections", "{request}", "Requests rejected by a SlimIdentity rate-limit policy.");
        meter.CreateObservableGauge("slimidentity.mail_queue.length", () => queue.Count, "{mail}", "Mails waiting in the background queue.");
    }

    public void Login(string result, bool cookies) =>
        _logins.Add(1, new("result", result), new("mode", cookies ? "cookie" : "bearer"));

    public void TwoFactor(string method, string result) => _twoFactor.Add(1, new("method", method), new("result", result));
    public void Lockout() => _lockouts.Add(1);
    public void Refresh(string result) => _refreshes.Add(1, new KeyValuePair<string, object?>("result", result));
    public void SignOut(string scope) => _signOuts.Add(1, new KeyValuePair<string, object?>("scope", scope));
    public void Registration(string result) => _registrations.Add(1, new KeyValuePair<string, object?>("result", result));
    public void PasswordReset(string stage) => _passwordResets.Add(1, new KeyValuePair<string, object?>("stage", stage));
    public void EmailChange(string stage) => _emailChanges.Add(1, new KeyValuePair<string, object?>("stage", stage));
    public void Invitation(string stage) => _invitations.Add(1, new KeyValuePair<string, object?>("stage", stage));
    public void ExternalLogin(string provider, string result) => _externalLogins.Add(1, new("provider", provider), new("result", result));
    public void Impersonation(string stage) => _impersonations.Add(1, new KeyValuePair<string, object?>("stage", stage));
    public void Mail(string kind, string result) => _mails.Add(1, new("kind", kind), new("result", result));
    public void RateLimited(string policy) => _rateLimited.Add(1, new KeyValuePair<string, object?>("policy", policy));
}
