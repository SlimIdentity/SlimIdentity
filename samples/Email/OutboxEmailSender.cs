// SlimIdentity sample – guaranteed mail delivery with the outbox pattern (survives restarts and crashes).
//
// SlimIdentity's built-in queue lives in memory: it is drained on a regular shutdown, but a crash loses unsent
// mails. If that is not acceptable, let the sender only write a row (fast, so response times stay uniform)
// and deliver it from your own worker:
//
//   builder.Services.AddSlimIdentity(config, o => o.Email.SendInBackground = false) // the outbox IS the queue
//       .AddEmailSender<OutboxEmailSender>();
//   builder.Services.AddScoped<MailKitEmailSender>();   // the real transport (EmailSenders.cs)
//   builder.Services.AddHostedService<OutboxMailWorker>();
//
// Entity: OutboxMail in samples/EfCore/EfCoreModel.cs. Packages: Microsoft.EntityFrameworkCore + provider.

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using MyApp.Data;
using SlimIdentity.Abstractions;

namespace MyApp.Mail;

/// <summary>Writes every mail into the outbox table – nothing is sent inside the request.</summary>
public sealed class OutboxEmailSender(AppDbContext db, TimeProvider time) : ISlimEmailSender
{
    public Task SendVerificationEmailAsync(string email, string link, CancellationToken ct) => AddAsync("verification", email, link, ct);
    public Task SendPasswordResetEmailAsync(string email, string link, CancellationToken ct) => AddAsync("password-reset", email, link, ct);
    public Task SendTwoFactorCodeAsync(string email, string code, CancellationToken ct) => AddAsync("two-factor", email, code, ct);
    public Task SendAccountExistsEmailAsync(string email, CancellationToken ct) => AddAsync("account-exists", email, "", ct);
    public Task SendLockoutNotificationEmailAsync(string email, DateTimeOffset lockoutEndUtc, CancellationToken ct) =>
        AddAsync("lockout", email, lockoutEndUtc.ToString("O"), ct);

    private async Task AddAsync(string kind, string to, string payload, CancellationToken ct)
    {
        db.OutboxMails.Add(new OutboxMail { Kind = kind, To = to, Payload = payload, CreatedUtc = time.GetUtcNow() });
        await db.SaveChangesAsync(ct);
    }
}

/// <summary>Delivers outbox rows with the real transport; retries failed mails up to 5 times.</summary>
public sealed class OutboxMailWorker(IServiceScopeFactory scopes, TimeProvider time, ILogger<OutboxMailWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        do
        {
            await using var scope = scopes.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var transport = scope.ServiceProvider.GetRequiredService<MailKitEmailSender>();

            var batch = await db.OutboxMails.Where(m => m.SentUtc == null && m.Attempts < 5)
                .OrderBy(m => m.Id).Take(20).ToListAsync(stoppingToken);

            foreach (var mail in batch)
            {
                try
                {
                    await (mail.Kind switch
                    {
                        "verification" => transport.SendVerificationEmailAsync(mail.To, mail.Payload, stoppingToken),
                        "password-reset" => transport.SendPasswordResetEmailAsync(mail.To, mail.Payload, stoppingToken),
                        "two-factor" => transport.SendTwoFactorCodeAsync(mail.To, mail.Payload, stoppingToken),
                        "account-exists" => transport.SendAccountExistsEmailAsync(mail.To, stoppingToken),
                        _ => Task.CompletedTask,
                    });
                    mail.SentUtc = time.GetUtcNow();
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    mail.Attempts++;
                    logger.LogWarning(ex, "Outbox mail {Id} ({Kind}) failed, attempt {Attempts}.", mail.Id, mail.Kind, mail.Attempts);
                }
            }
            await db.SaveChangesAsync(stoppingToken);
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
