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
    public Task SendVerificationEmailAsync(SlimEmailContext context, string email, string link, CancellationToken ct) => AddAsync(context, email, link, ct);
    public Task SendPasswordResetEmailAsync(SlimEmailContext context, string email, string link, CancellationToken ct) => AddAsync(context, email, link, ct);
    public Task SendTwoFactorCodeAsync(SlimEmailContext context, string email, string code, CancellationToken ct) => AddAsync(context, email, code, ct);
    public Task SendEmailChangeConfirmationAsync(SlimEmailContext context, string newEmail, string link, CancellationToken ct) => AddAsync(context, newEmail, link, ct);
    public Task SendEmailChangedNotificationAsync(SlimEmailContext context, string oldEmail, string newEmail, CancellationToken ct) => AddAsync(context, oldEmail, newEmail, ct);
    public Task SendAccountExistsEmailAsync(SlimEmailContext context, string email, CancellationToken ct) => AddAsync(context, email, "", ct);
    public Task SendLockoutNotificationEmailAsync(SlimEmailContext context, string email, DateTimeOffset lockoutEndUtc, CancellationToken ct) =>
        AddAsync(context, email, lockoutEndUtc.ToString("O"), ct);

    // the context (language, account, tenant) is persisted with the mail – the worker runs long after the request
    private async Task AddAsync(SlimEmailContext context, string to, string payload, CancellationToken ct)
    {
        db.OutboxMails.Add(new OutboxMail
        {
            Kind = context.Kind, To = to, Payload = payload, CreatedUtc = time.GetUtcNow(),
            UserId = context.UserId, Culture = context.Culture.Name, ItemsJson = JsonSerializer.Serialize(context.Items),
        });
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
                    var context = new SlimEmailContext
                    {
                        Kind = mail.Kind,
                        UserId = mail.UserId,
                        Culture = CultureInfo.GetCultureInfo(mail.Culture),
                        Items = JsonSerializer.Deserialize<Dictionary<string, string>>(mail.ItemsJson) ?? [],
                    };
                    await (mail.Kind switch
                    {
                        SlimEmailKinds.Verification => transport.SendVerificationEmailAsync(context, mail.To, mail.Payload, stoppingToken),
                        SlimEmailKinds.PasswordReset => transport.SendPasswordResetEmailAsync(context, mail.To, mail.Payload, stoppingToken),
                        SlimEmailKinds.TwoFactorCode => transport.SendTwoFactorCodeAsync(context, mail.To, mail.Payload, stoppingToken),
                        SlimEmailKinds.EmailChange => transport.SendEmailChangeConfirmationAsync(context, mail.To, mail.Payload, stoppingToken),
                        SlimEmailKinds.EmailChanged => transport.SendEmailChangedNotificationAsync(context, mail.To, mail.Payload, stoppingToken),
                        SlimEmailKinds.AccountExists => transport.SendAccountExistsEmailAsync(context, mail.To, stoppingToken),
                        SlimEmailKinds.LockoutNotification => transport.SendLockoutNotificationEmailAsync(context, mail.To,
                            DateTimeOffset.Parse(mail.Payload, CultureInfo.InvariantCulture), stoppingToken),
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
