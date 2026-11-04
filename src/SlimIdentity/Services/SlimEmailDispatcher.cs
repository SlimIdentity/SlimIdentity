using System.Threading.Channels;
using Microsoft.Extensions.Hosting;
using SlimIdentity.Abstractions;

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

/// <summary>Background worker that hands queued mails to the host's <see cref="ISlimEmailSender"/> (one scope per mail).</summary>
internal sealed class SlimEmailBackgroundService(
    SlimEmailQueue queue,
    IServiceScopeFactory scopes,
    ILogger<SlimEmailBackgroundService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var job in queue.Reader.ReadAllAsync(stoppingToken))
            {
                try
                {
                    await using var scope = scopes.CreateAsyncScope();
                    var sender = scope.ServiceProvider.GetRequiredService<ISlimEmailSender>();
                    await job.Send(sender, stoppingToken);
                }
                catch (Exception ex) when (ex is not OperationCanceledException || !stoppingToken.IsCancellationRequested)
                {
                    logger.LogError(ex, "SlimIdentity: sending {Kind} mail failed.", job.Kind);
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            if (queue.Reader.Count > 0)
                logger.LogWarning("SlimIdentity: shutting down with {Count} unsent mail(s) in the queue.", queue.Reader.Count);
        }
    }
}
