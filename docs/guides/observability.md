# Observability: metrics and logs

SlimIdentity reports metrics via `System.Diagnostics.Metrics` and logs with stable event ids. Both are part of .NET –
no additional package is required. Tags and log messages never contain e-mail addresses, passwords, tokens or codes
(log messages may contain user ids).

## OpenTelemetry

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(m => m
        .AddMeter("SlimIdentity")            // SlimIdentityDefaults.MeterName
        .AddAspNetCoreInstrumentation()
        .AddOtlpExporter());
```

Without OpenTelemetry you can watch the counters live: `dotnet-counters monitor -n MyApp --counters SlimIdentity`.

## Metrics

| Instrument | Tags | Meaning |
| :--- | :--- | :--- |
| `slimidentity.logins` | `result` (`success`, `invalid_password`, `unknown_user`, `inactive`, `locked_out`, `requires_two_factor`, `email_not_confirmed`, `rejected`, `attempts_queued`), `mode` (`cookie`, `bearer`) | Password sign-in attempts |
| `slimidentity.two_factor.verifications` | `method` (`totp`, `email`, `recovery`, `remembered_device`), `result` (`success`, `failure`, `challenge_reused`, `attempts_queued`) | Second-factor attempts and skips on remembered devices |
| `slimidentity.lockouts` | – | Account lockouts |
| `slimidentity.token_refreshes` | `result` (`success`, `invalid`, `reuse_detected`, `session_expired`) | Refresh-token rotations |
| `slimidentity.sign_outs` | `scope` (`session`, `everywhere`) | Logouts and session revocations |
| `slimidentity.registrations` | `result` (`created`, `existing_account`) | `/register` calls |
| `slimidentity.password_resets` | `stage` (`requested`, `completed`) | Password resets |
| `slimidentity.email_changes` | `stage` (`requested`, `completed`) | E-mail changes |
| `slimidentity.invitations` | `stage` (`created`, `accepted`) | Invitations |
| `slimidentity.external_logins` | `provider`, `result` (`success`, `linked`, `created`, `conflict`, `rejected`) | OAuth / OIDC logins |
| `slimidentity.impersonations` | `stage` (`started`, `ended`) | Admin impersonation |
| `slimidentity.mails` | `kind`, `result` (`sent`, `failed`, `dropped`) | Mails handed to `ISlimEmailSender` |
| `slimidentity.rate_limit.rejections` | `policy` | Requests rejected with 429 |
| `slimidentity.mail_queue.length` (gauge) | – | Mails waiting in the background queue |

Note that the internal `result` of `slimidentity.logins` distinguishes unknown, inactive and locked accounts – the HTTP
answer does not (enumeration protection). Keep metrics internal.

### Suggested alerts

- `token_refreshes{result="reuse_detected"}` > 0 – a refresh token was replayed (theft or a buggy client).
- Spikes of `logins{result="invalid_password"|"unknown_user"}` or `lockouts` – credential stuffing.
- `attempts_queued` – many parallel attempts against one account (more than 8 waiting); they were refused unevaluated.
- `rate_limit.rejections` rising for normal traffic – limits too tight, or the proxy hides client IPs.
- `mails{result="failed"|"dropped"}` > 0 or a growing `mail_queue.length` – mail delivery problem.
- `impersonations` – for the audit trail.

## Log event ids

| Range | Area | Examples |
| :--- | :--- | :--- |
| 1xxx | Sign-in | 1001 lockout, 1002 password rehashed, 1004 CSRF scheme mismatch (proxy misconfiguration) |
| 2xxx | Two-factor | 2002 recovery code used, 2005 replayed code rejected, 2006 TOTP secret cannot be decrypted, 2007 all remembered devices forgotten, 2008 reused sign-in challenge rejected |
| 3xxx | Tokens and sessions | 3002/3003 refresh-token reuse, 3004 all sessions revoked, 3007/3008 guard vetoes, 3009 failing event observer |
| 4xxx | Account | 4002 password reset, 4004/4005 e-mail change, 4003 invitation accepted, 4006 registration race lost |
| 5xxx | External login | 5001 account conflict, 5002 linked, 5003 user created |
| 6xxx | Impersonation | 6001 started, 6002 ended, 6003 return denied |
| 7xxx | Mail | 7001 queue full, 7002 send failed, 7004 unsent mails at shutdown, 7005 per-recipient limit reached |
| 8xxx | Deployment | 8001 forwarded headers not applied, 8002 local key ring, 8003 no Data Protection application name, 8004 exchange codes per instance – see [several instances](multiple-instances.md) |

The logger categories are the SlimIdentity class names (`SlimIdentity.*`), so `"Logging:LogLevel:SlimIdentity"` controls all of them.
