using System.Threading.Channels;
using Microsoft.Extensions.Hosting;

namespace SlimIdentity.Services;

/// <summary>
/// Sends enumeration-relevant mails (verification, password reset, "account exists") without the request
/// waiting for the mail server, so that "account exists" and "account unknown" answer equally fast.
/// With <see cref="SlimEmailOptions.SendInBackground"/> = false the mail is sent inline instead.
/// </summary>
internal sealed class SlimEmailDispatcher(
    SlimEmailQueue queue,
    IServiceProvider services,
    IOptions<SlimIdentityOptions> options,
    ILogger<SlimEmailDispatcher> logger)
{
    public async Task SendAsync(string kind, Func<ISlimEmailSender, CancellationToken, Task> send, CancellationToken ct)
    {
        if (!options.Value.Email.SendInBackground)
        {
            await send(services.GetRequiredService<ISlimEmailSender>(), ct);
            return;
        }

        if (!queue.TryEnqueue(new SlimEmailJob(kind, send)))
            logger.LogError("SlimIdentity: mail queue is full – {Kind} mail dropped.", kind);
    }
}

internal sealed record SlimEmailJob(string Kind, Func<ISlimEmailSender, CancellationToken, Task> Send);

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
}

/// <summary>
/// Background worker that hands queued mails to the host's <see cref="ISlimEmailSender"/> (one scope per mail).
/// On shutdown it drains the queue within the host's shutdown timeout (<c>HostOptions.ShutdownTimeout</c>),
/// so regular restarts and deployments lose no mail – only a crash does.
/// </summary>
internal sealed class SlimEmailBackgroundService(
    SlimEmailQueue queue,
    IServiceScopeFactory scopes,
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

        if (drained > 0) logger.LogInformation("SlimIdentity: sent {Count} queued mail(s) during shutdown.", drained);
        if (queue.Reader.Count > 0)
            logger.LogWarning("SlimIdentity: shutdown timeout reached with {Count} unsent mail(s) in the queue.", queue.Reader.Count);
    }

    private async Task SendAsync(SlimEmailJob job, CancellationToken ct)
    {
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            var sender = scope.ServiceProvider.GetRequiredService<ISlimEmailSender>();
            await job.Send(sender, ct);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "SlimIdentity: sending {Kind} mail failed.", job.Kind);
        }
    }
}
