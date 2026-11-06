using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using MyApp.Data;
using SlimIdentity.Testing;

namespace SlimIdentity.Samples.Tests;

/// <summary>
/// The EF Core templates must honour every store contract – including the parallel ones. SQLite (a real file database
/// with unique indexes and locking, not the in-memory provider) runs them without external infrastructure.
/// </summary>
public sealed class EfCoreTemplateConformanceTests : IAsyncLifetime
{
    private readonly string _file = Path.Combine(Path.GetTempPath(), $"slimidentity-conformance-{Guid.NewGuid():N}.db");
    private ServiceProvider _services = null!;

    public async Task InitializeAsync()
    {
        var connectionString = new SqliteConnectionStringBuilder { DataSource = _file, DefaultTimeout = 30, Pooling = false }.ToString();
        _services = new ServiceCollection()
            .AddDbContext<AppDbContext>(o => o.UseSqlite(connectionString))
            .AddSingleton(TimeProvider.System)
            .AddScoped<ISlimUserStore, EfCoreUserStore>()
            .AddScoped<ISlimTwoFactorStore, EfCoreTwoFactorStore>()
            .AddScoped<ISlimRefreshTokenStore, EfCoreRefreshTokenStore>()
            .AddScoped<ISlimSessionStore, EfCoreSessionStore>()
            .AddScoped<ISlimExternalLoginStore, EfCoreExternalLoginStore>()
            .BuildServiceProvider();

        await using var scope = _services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await db.Database.EnsureCreatedAsync();
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;");   // concurrent readers while one writes
    }

    public async Task DisposeAsync()
    {
        await _services.DisposeAsync();
        foreach (var f in new[] { _file, _file + "-wal", _file + "-shm" })
            if (File.Exists(f)) File.Delete(f);
    }

    [Fact]
    public async Task EfCore_templates_honour_all_store_contracts()
    {
        var report = await SlimStoreConformance.VerifyAsync(_services);
        Assert.Contains(report.Results, r => r.Store == nameof(ISlimSessionStore));   // every capability was checked
    }
}
