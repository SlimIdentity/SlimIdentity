using System.Threading.Channels;
using Microsoft.Extensions.Hosting;

namespace SlimIdentity.Services;

/// <summary>
/// Sends enumeration-relevant mails (verification, password reset, "account exists", lockout, e-mail change) without
/// the request waiting for the mail server, so that "account exists" and "account unknown" answer equally fast.
/// With <see cref="SlimEmailOptions.SendInBackground"/> = false the mail is sent inline instead.
/// </summary>
internal sealed class SlimEmailDispatcher(
    SlimEmailQueue queue,
    SlimMailThrottle throttle,
    IServiceProvider services,
    IHttpContextAccessor httpContextAccessor,
    IOptions<SlimIdentityOptions> options,
    SlimMetrics metrics,
    ILogger<SlimEmailDispatcher> logger)
{
    /// <summary>
    /// The context of a mail, captured now – in the request that causes it: the culture and the enricher's host data
    /// would be gone by the time the background queue sends it.
    /// </summary>
    public SlimEmailContext CreateContext(string kind, string? userId)
    {
        Dictionary<string, string>? items = null;
        if (httpContextAccessor.HttpContext is { } http)
        {
            foreach (var enricher in services.GetServices<ISlimEmailContextEnricher>())
                enricher.Enrich(http, kind, userId, items ??= new Dictionary<string, string>(StringComparer.Ordinal));
        }
        var context = new SlimEmailContext { Kind = kind, UserId = userId, Culture = CultureInfo.CurrentUICulture };
        return items is { Count: > 0 } ? new SlimEmailContext
        {
            Kind = kind, UserId = userId, Culture = context.Culture,
            Items = new System.Collections.ObjectModel.ReadOnlyDictionary<string, string>(items),
        } : context;
    }

    /// <summary>Sends (or queues) a mail to <paramref name="recipient"/> – unless the per-recipient limit is reached.</summary>
    public async Task SendAsync(string kind, string recipient, string? userId,
        Func<ISlimEmailSender, SlimEmailContext, CancellationToken, Task> send, CancellationToken ct)
    {
        if (!options.Value.Email.Enabled) return;   // WithoutEmail(): nothing is ever sent

        if (!await throttle.TryAcquireAsync(kind, recipient, ct))
        {
            Log.MailThrottled(logger, kind);
            metrics.Mail(kind, "throttled");
            return;
        }

        var context = CreateContext(kind, userId);
        if (!options.Value.Email.SendInBackground)
        {
            await send(services.GetRequiredService<ISlimEmailSender>(), context, ct);
            metrics.Mail(kind, "sent");
            return;
        }

        if (!queue.TryEnqueue(new SlimEmailJob(kind, context, send)))
        {
            Log.MailDropped(logger, kind);
            metrics.Mail(kind, "dropped");
        }
    }
}

internal sealed record SlimEmailJob(string Kind, SlimEmailContext Context, Func<ISlimEmailSender, SlimEmailContext, CancellationToken, Task> Send);

/// <summary>Bounded in-memory queue (a flood of requests can never grow memory without limit).</summary>
internal sealed class SlimEmailQueue(IOptions<SlimIdentityOptions> options)
{
    private readonly Channel<SlimEmailJob> _channel = Channel.CreateBounded<SlimEmailJob>(
        new BoundedChannelOptions(options.Value.Email.QueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait, // TryWrite returns false when full
            SingleReader = true,
        });

    public bool TryEnqueue(SlimEmailJob job) => _channel.Writer.TryWrite(job);

    public ChannelReader<SlimEmailJob> Reader => _channel.Reader;

    public int Count => _channel.Reader.Count;
}

/// <summary>
/// Background worker that hands queued mails to the host's <see cref="ISlimEmailSender"/> (one scope per mail).
/// On shutdown it drains the queue within the host's shutdown timeout (<c>HostOptions.ShutdownTimeout</c>),
/// so regular restarts and deployments lose no mail – only a crash does.
/// </summary>
internal sealed class SlimEmailBackgroundService(
    SlimEmailQueue queue,
    IServiceScopeFactory scopes,
    SlimMetrics metrics,
    ILogger<SlimEmailBackgroundService> logger) : BackgroundService
{
    private CancellationToken _shutdownDeadline = CancellationToken.None;

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        _shutdownDeadline = cancellationToken; // fires when the host's shutdown timeout is exceeded
        return base.StopAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var job in queue.Reader.ReadAllAsync(stoppingToken))
                await SendAsync(job, CancellationToken.None);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // fall through to draining
        }

        var drained = 0;
        while (!_shutdownDeadline.IsCancellationRequested && queue.Reader.TryRead(out var job))
        {
            await SendAsync(job, _shutdownDeadline);
            drained++;
        }

        if (drained > 0) Log.MailDrained(logger, drained);
        if (queue.Count > 0) Log.MailLost(logger, queue.Count);
    }

    private async Task SendAsync(SlimEmailJob job, CancellationToken ct)
    {
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            var sender = scope.ServiceProvider.GetRequiredService<ISlimEmailSender>();
            await job.Send(sender, job.Context, ct);
            metrics.Mail(job.Kind, "sent");
        }
        catch (Exception ex)
        {
            Log.MailFailed(logger, ex, job.Kind);
            metrics.Mail(job.Kind, "failed");
        }
    }
}
