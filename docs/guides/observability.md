# Observability: metrics and logs

Metrics via `System.Diagnostics.Metrics` (meter `SlimIdentity`, `SlimIdentityDefaults.MeterName`) and logs with stable
event ids – no extra package. Tags and log messages never contain addresses, passwords, tokens or codes (messages may
contain user ids). Logger categories are `SlimIdentity.*`.

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(m => m.AddMeter("SlimIdentity").AddAspNetCoreInstrumentation().AddOtlpExporter());
```

Live: `dotnet-counters monitor -n MyApp --counters SlimIdentity`.

## Metrics

| Instrument | Tags | Meaning |
| :--- | :--- | :--- |
| `slimidentity.logins` | `result` (`success`, `invalid_password`, `unknown_user`, `account_disabled`, `locked_out`, `requires_two_factor`, `email_not_confirmed`, `invalid_verification_code`, `too_many_attempts`, `password_change_required`, `rejected`, `passkey_rejected`), `mode` (`cookie`, `bearer`) | Sign-in attempts (password and passkey) |
| `slimidentity.two_factor.verifications` | `method` (`totp`, `email`, `recovery`, `remembered_device`), `result` (`success`, `failure`, `challenge_reused`) | Second-factor attempts |
| `slimidentity.lockouts` | – | Account lockouts |
| `slimidentity.token_refreshes` | `result` (`success`, `invalid`, `reuse_detected`, `session_expired`) | Refresh-token rotations |
| `slimidentity.sign_outs` | `scope` (`session`, `everywhere`) | Logouts and revocations |
| `slimidentity.registrations` | `result` (`started`, `existing_account`, `invalid_verification_code`, `too_many_attempts`, `created`) | Registration steps |
| `slimidentity.password_resets`, `slimidentity.email_changes` | `stage` (`requested`, `completed`) | Resets, address changes |
| `slimidentity.invitations` | `stage` (`created`, `accepted`) | Invitations |
| `slimidentity.external_logins` | `provider`, `result` (`success`, `linked`, `created`, `conflict`, `rejected`, `removed`, `cancelled`, `failed`) | OAuth / OIDC |
| `slimidentity.impersonations` | `stage` (`started`, `ended`) | Impersonation |
| `slimidentity.mails` | `kind`, `result` (`sent`, `failed`, `dropped`, `throttled`) | Mails handed to `ISlimEmailSender` |
| `slimidentity.rate_limit.rejections` | `policy` | `429` answers |
| `slimidentity.mail_queue.length` (gauge) | – | Mails in the background queue |

The `logins` result distinguishes unknown, inactive and locked accounts; the HTTP answer does not. Keep metrics
internal.

Alerts worth having: `token_refreshes{result="reuse_detected"}` > 0 (replayed refresh token); spikes of
`invalid_password` / `unknown_user` or `lockouts` (credential stuffing); rising `rate_limit.rejections` (limits too
tight or proxy hides client IPs); `mails` `failed` / `dropped` or a growing queue; `impersonations` for the audit trail.

## Log event ids

| Range | Area | Examples |
| :--- | :--- | :--- |
| 1xxx | Sign-in | 1001 lockout, 1002 password rehashed, 1004 CSRF scheme mismatch (proxy misconfiguration) |
| 2xxx | Two-factor | 2002 recovery code used, 2005 replayed code, 2006 TOTP secret undecryptable, 2007 remembered devices forgotten, 2008 reused challenge |
| 3xxx | Tokens and sessions | 3002/3003 refresh-token reuse, 3004 all sessions revoked, 3007/3008 guard vetoes, 3009 failing observer, 3010 claims refreshed, 3011 missing security stamp created |
| 4xxx | Account | 4002 password reset, 4003 invitation accepted, 4004/4005 e-mail change, 4006 registration race lost, 4007–4012 administrator actions ([list](without-email.md#the-administrators-tools)) |
| 5xxx | External login | 5001 conflict, 5002 linked, 5003 user created, 5010 back-channel logout, 5011 logout token rejected, 5012 discovery unavailable, 5013 link removed, 5015 round trip cancelled or failed |
| 6xxx | Impersonation | 6001 started, 6002 ended, 6003 return denied |
| 7xxx | Mail | 7001 queue full, 7002 send failed, 7004 unsent at shutdown, 7005 per-recipient limit |
| 8xxx | Deployment | 8001–8006, see [several instances](multiple-instances.md#built-in-diagnostics) |
| 9xxx | Passkeys | 9001 registered, 9002 removed, 9003 ceremony rejected, 9004 counter regression (possibly cloned) |
