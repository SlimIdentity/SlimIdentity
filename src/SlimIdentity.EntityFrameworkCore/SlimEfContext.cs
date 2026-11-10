using Microsoft.Extensions.Logging;

namespace SlimIdentity.EntityFrameworkCore;

/// <summary>
/// SlimIdentity's own <typeparamref name="TContext"/> instance per scope (request). The stores never use the host's
/// scoped context: their <c>SaveChanges</c> must not save the host's pending changes along with their own, and nothing
/// they do may detach or alter entities the host tracks. Created through <see cref="IDbContextFactory{TContext}"/>
/// when the host registered one, otherwise from the same <c>DbContextOptions</c> as the host's context.
/// </summary>
/// <remarks>
/// Consequence: the stores' writes are never part of a transaction the host opened on its own context or with a
/// <c>TransactionScope</c> – they may wait for the host's locks. On SQLite (one writer per database) such a write
/// throws at once; on other providers a warning (event id 8101) is logged once. Commit first, then call SlimIdentity.
/// </remarks>
public sealed class SlimEfContext<TContext> : IDisposable, IAsyncDisposable
    where TContext : DbContext
{
    private static int s_warned;
    private readonly IServiceProvider _services;
    private readonly Lazy<TContext> _db;

    /// <summary>Called by the container; the context itself is created on first use.</summary>
    public SlimEfContext(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        _services = services;
        _db = new Lazy<TContext>(() =>
            services.GetService<IDbContextFactory<TContext>>()?.CreateDbContext()
            ?? ActivatorUtilities.CreateInstance<TContext>(services), LazyThreadSafetyMode.None);
    }

    /// <summary>The context the stores work on – separate from the one the host resolves as <typeparamref name="TContext"/>.</summary>
    public TContext Db => _db.Value;

    /// <summary>
    /// Called before every write: a transaction the host holds open (on its scoped <typeparamref name="TContext"/> or
    /// an ambient <c>TransactionScope</c>) does not include this write and may block it.
    /// </summary>
    internal T Writing<T>(T target)
    {
        BeforeWrite();
        return target;
    }

    /// <inheritdoc cref="Writing{T}(T)"/>
    internal void BeforeWrite()
    {
        var where = System.Transactions.Transaction.Current is not null ? "a TransactionScope"
            : _services.GetService<TContext>()?.Database.CurrentTransaction is not null ? $"the host's {typeof(TContext).Name}"
            : null;
        if (where is null) return;
        if (Db.Database.ProviderName == "Microsoft.EntityFrameworkCore.Sqlite")
            throw new InvalidOperationException(
                $"SlimIdentity: a write of the EF stores while {where} holds an open transaction. The stores use a context " +
                "of their own, so the write is not part of that transaction – and SQLite allows only one writer, it would " +
                "wait until it times out. Commit your transaction first, then call SlimIdentity.");
        if (Interlocked.Exchange(ref s_warned, 1) == 0
            && _services.GetService<ILoggerFactory>()?.CreateLogger("SlimIdentity.EntityFrameworkCore") is { } logger)
            HostTransactionLog(logger, where, null);
    }

    private static readonly Action<ILogger, string, Exception?> HostTransactionLog = LoggerMessage.Define<string>(
        LogLevel.Warning, new EventId(8101, "HostTransaction"),
        "SlimIdentity: the EF stores write while {Where} holds an open transaction. They use a context of their own: the " +
        "write is not part of that transaction (a rollback does not undo it) and waits for rows the transaction locks. " +
        "Commit first, then call SlimIdentity – see the README of SlimIdentity.EntityFrameworkCore. Logged once.");

    /// <inheritdoc />
    public void Dispose()
    {
        if (_db.IsValueCreated) _db.Value.Dispose();
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync() => _db.IsValueCreated ? _db.Value.DisposeAsync() : ValueTask.CompletedTask;
}
