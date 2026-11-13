// SlimIdentity sample – durable mail delivery with the outbox pattern (survives restarts and crashes).
//
// SlimIdentity's built-in queue lives in memory: it is drained on a regular shutdown, but a crash loses unsent
// mails. If that is not acceptable, let the sender only write a row (fast, so response times stay uniform)
// and deliver it from your own worker:
//
//   builder.Services.AddSlimIdentity(config, o => o.Email.SendInBackground = false) // the outbox IS the queue
//       .AddEmailSender<OutboxEmailSender>();
//   builder.Services.AddScoped<MailKitEmailSender>();   // the real transport (EmailSenders.cs)
//   builder.Services.AddHostedService<OutboxMailWorker<MailKitEmailSender>>();
//
// Delivery is at-least-once with retries, not guaranteed: failed sends are retried with exponential backoff for
// about nine hours; after that the row stays in the table with Attempts = MaxAttempts and LastError for inspection
// (alert on it, resend or delete it). A crash between sending and recording the success sends the mail again.
// Several instances may run the worker – each row is claimed with a short lease before it is sent. After a
// successful send the link / code is erased from the row.
//
// Entity: OutboxMail in samples/templates/EfCore/EfCoreModel.cs. Packages: Microsoft.EntityFrameworkCore + provider.

using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SlimIdentity;
using MyApp.Data;

namespace MyApp.Mail;

/// <summary>Writes every mail into the outbox table – nothing is sent inside the request.</summary>
public sealed class OutboxEmailSender(AppDbContext db, TimeProvider time) : ISlimEmailSender
{
    public Task SendVerificationEmailAsync(SlimEmailContext context, string email, string code, string link, CancellationToken ct) => AddAsync(context, email, code + " " + link, ct);
    public Task SendPasswordResetEmailAsync(SlimEmailContext context, string email, string link, CancellationToken ct) => AddAsync(context, email, link, ct);
    public Task SendTwoFactorCodeAsync(SlimEmailContext context, string email, string code, CancellationToken ct) => AddAsync(context, email, code, ct);
    public Task SendEmailVerificationCodeAsync(SlimEmailContext context, string email, string code, CancellationToken ct) => AddAsync(context, email, code, ct);
    public Task SendEmailChangeConfirmationAsync(SlimEmailContext context, string newEmail, string link, CancellationToken ct) => AddAsync(context, newEmail, link, ct);
    public Task SendEmailChangedNotificationAsync(SlimEmailContext context, string oldEmail, string newEmail, CancellationToken ct) => AddAsync(context, oldEmail, newEmail, ct);
    public Task SendAccountExistsEmailAsync(SlimEmailContext context, string email, CancellationToken ct) => AddAsync(context, email, "", ct);
    public Task SendLockoutNotificationEmailAsync(SlimEmailContext context, string email, DateTimeOffset lockoutEndUtc, CancellationToken ct) =>
        AddAsync(context, email, lockoutEndUtc.ToString("O"), ct);

    // the context (language, account, tenant) is persisted with the mail – the worker runs long after the request
    private async Task AddAsync(SlimEmailContext context, string to, string payload, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        db.OutboxMails.Add(new OutboxMail
        {
            Kind = context.Kind, To = to, Payload = payload, CreatedUtc = now, NextAttemptAt = now.ToUnixTimeMilliseconds(),
            UserId = context.UserId, Culture = context.Culture.Name, ItemsJson = JsonSerializer.Serialize(context.Items),
        });
        await db.SaveChangesAsync(ct);
    }
}

/// <summary>
/// Delivers outbox rows with the real transport <typeparamref name="TTransport"/>: at least once, with exponential
/// backoff, safe to run on several instances.
/// </summary>
public sealed class OutboxMailWorker<TTransport>(IServiceScopeFactory scopes, TimeProvider time, ILogger<OutboxMailWorker<TTransport>> logger)
    : BackgroundService
    where TTransport : ISlimEmailSender
{
    /// <summary>Attempts before a mail is given up (~9 hours with the backoff below); the row stays for inspection.</summary>
    public const int MaxAttempts = 16;

    private static readonly TimeSpan Lease = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MaxDelay = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        do
        {
            try
            {
                await DeliverDueAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
            {
                // database down, deadlock, …: an exception escaping ExecuteAsync would stop the host – try again later
                logger.LogError(ex, "Outbox delivery failed; retrying on the next tick.");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    /// <summary>Claims and sends the mails that are due; returns how many were sent.</summary>
    public async Task<int> DeliverDueAsync(CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var transport = scope.ServiceProvider.GetRequiredService<TTransport>();

        // unix milliseconds: comparable in SQL on every provider (SQLite cannot compare DateTimeOffset)
        var now = time.GetUtcNow().ToUnixTimeMilliseconds();
        var due = await db.OutboxMails.AsNoTracking()
            .Where(m => m.SentUtc == null && m.Attempts < MaxAttempts && m.NextAttemptAt <= now && (m.LockedUntil == null || m.LockedUntil < now))
            .OrderBy(m => m.Id).Select(m => m.Id).Take(20).ToListAsync(ct);

        var sent = 0;
        foreach (var id in due)
        {
            // atomic claim: of several instances only the one whose UPDATE hits the row sends it
            var leaseEnd = time.GetUtcNow().Add(Lease).ToUnixTimeMilliseconds();
            var claimed = await db.OutboxMails
                .Where(m => m.Id == id && m.SentUtc == null && (m.LockedUntil == null || m.LockedUntil < now))
                .ExecuteUpdateAsync(s => s.SetProperty(m => m.LockedUntil, leaseEnd), ct);
            if (claimed != 1) continue;

            var mail = await db.OutboxMails.AsNoTracking().FirstAsync(m => m.Id == id, ct);
            try
            {
                await SendAsync(transport, mail, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                var attempts = mail.Attempts + 1;
                var next = time.GetUtcNow().Add(Backoff(attempts)).ToUnixTimeMilliseconds();
                var error = ex.Message.Length > 500 ? ex.Message[..500] : ex.Message;
                await db.OutboxMails.Where(m => m.Id == id).ExecuteUpdateAsync(s => s
                    .SetProperty(m => m.Attempts, attempts)
                    .SetProperty(m => m.NextAttemptAt, next)
                    .SetProperty(m => m.LastError, error)
                    .SetProperty(m => m.LockedUntil, (long?)null), ct);
                if (attempts >= MaxAttempts)
                    logger.LogError(ex, "Outbox mail {Id} ({Kind}) given up after {Attempts} attempts.", mail.Id, mail.Kind, attempts);
                else
                    logger.LogWarning(ex, "Outbox mail {Id} ({Kind}) failed, attempt {Attempts}.", mail.Id, mail.Kind, attempts);
                continue;
            }

            // sent: links and codes must not stay readable in the table
            await db.OutboxMails.Where(m => m.Id == id).ExecuteUpdateAsync(s => s
                .SetProperty(m => m.SentUtc, time.GetUtcNow())
                .SetProperty(m => m.Payload, "")
                .SetProperty(m => m.ItemsJson, "{}")
                .SetProperty(m => m.LastError, (string?)null)
                .SetProperty(m => m.LockedUntil, (long?)null), CancellationToken.None);
            sent++;
        }
        return sent;
    }

    /// <summary>30 s, 1 min, 2 min, … capped at one hour.</summary>
    public static TimeSpan Backoff(int attempts) =>
        TimeSpan.FromSeconds(Math.Min(30 * Math.Pow(2, Math.Max(attempts - 1, 0)), MaxDelay.TotalSeconds));

    private static Task SendAsync(TTransport transport, OutboxMail mail, CancellationToken ct)
    {
        var context = new SlimEmailContext
        {
            Kind = mail.Kind,
            UserId = mail.UserId,
            Culture = CultureInfo.GetCultureInfo(mail.Culture),
            Items = JsonSerializer.Deserialize<Dictionary<string, string>>(mail.ItemsJson) ?? [],
        };
        return mail.Kind switch
        {
            SlimEmailKinds.Verification => transport.SendVerificationEmailAsync(context, mail.To,
                mail.Payload[..mail.Payload.IndexOf(' ')], mail.Payload[(mail.Payload.IndexOf(' ') + 1)..], ct),
            SlimEmailKinds.PasswordReset => transport.SendPasswordResetEmailAsync(context, mail.To, mail.Payload, ct),
            SlimEmailKinds.TwoFactorCode => transport.SendTwoFactorCodeAsync(context, mail.To, mail.Payload, ct),
            SlimEmailKinds.VerificationCode => transport.SendEmailVerificationCodeAsync(context, mail.To, mail.Payload, ct),
            SlimEmailKinds.EmailChange => transport.SendEmailChangeConfirmationAsync(context, mail.To, mail.Payload, ct),
            SlimEmailKinds.EmailChanged => transport.SendEmailChangedNotificationAsync(context, mail.To, mail.Payload, ct),
            SlimEmailKinds.AccountExists => transport.SendAccountExistsEmailAsync(context, mail.To, ct),
            SlimEmailKinds.LockoutNotification => transport.SendLockoutNotificationEmailAsync(context, mail.To,
                DateTimeOffset.Parse(mail.Payload, CultureInfo.InvariantCulture), ct),
            _ => throw new InvalidOperationException($"Unknown mail kind '{mail.Kind}'."),
        };
    }
}
