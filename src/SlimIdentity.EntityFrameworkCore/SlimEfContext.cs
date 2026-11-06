namespace SlimIdentity.EntityFrameworkCore;

/// <summary>
/// SlimIdentity's own <typeparamref name="TContext"/> instance per scope (request). The stores never use the host's
/// scoped context: their <c>SaveChanges</c> must not save the host's pending changes along with their own, and nothing
/// they do may detach or alter entities the host tracks. Created through <see cref="IDbContextFactory{TContext}"/>
/// when the host registered one, otherwise from the same <c>DbContextOptions</c> as the host's context.
/// </summary>
public sealed class SlimEfContext<TContext> : IDisposable, IAsyncDisposable
    where TContext : DbContext
{
    private readonly Lazy<TContext> _db;

    /// <summary>Called by the container; the context itself is created on first use.</summary>
    public SlimEfContext(IServiceProvider services)
    {
        ArgumentNullException.ThrowIfNull(services);
        _db = new Lazy<TContext>(() =>
            services.GetService<IDbContextFactory<TContext>>()?.CreateDbContext()
            ?? ActivatorUtilities.CreateInstance<TContext>(services), LazyThreadSafetyMode.None);
    }

    /// <summary>The context the stores work on – separate from the one the host resolves as <typeparamref name="TContext"/>.</summary>
    public TContext Db => _db.Value;

    /// <inheritdoc />
    public void Dispose()
    {
        if (_db.IsValueCreated) _db.Value.Dispose();
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync() => _db.IsValueCreated ? _db.Value.DisposeAsync() : ValueTask.CompletedTask;
}
