using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using MyApp.Data;
using SlimIdentity.Testing;

namespace SlimIdentity.Samples.Tests;

/// <summary>
/// The EF Core templates must honour every store contract – including the parallel ones – on every database they are
/// meant for. SQLite (a real file database with unique indexes and locking, not the in-memory provider) always runs;
/// PostgreSQL and SQL Server run when a connection string to a disposable server is set (CI starts service containers):
/// <c>SLIMIDENTITY_TEST_POSTGRES</c>, <c>SLIMIDENTITY_TEST_SQLSERVER</c>. The database is dropped and recreated.
/// </summary>
public sealed class EfCoreTemplateConformanceTests
{
    [Fact]
    public async Task EfCore_templates_honour_all_store_contracts_on_SQLite()
    {
        var file = Path.Combine(Path.GetTempPath(), $"slimidentity-conformance-{Guid.NewGuid():N}.db");
        var connectionString = new SqliteConnectionStringBuilder { DataSource = file, DefaultTimeout = 30 }.ToString();
        try
        {
            await VerifyAsync(o => o.UseSqlite(connectionString), async db => await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;"));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var f in new[] { file, file + "-wal", file + "-shm" })
                if (File.Exists(f)) File.Delete(f);
        }
    }

    [SkippableFact]
    public async Task EfCore_templates_honour_all_store_contracts_on_PostgreSQL()
    {
        var server = Environment.GetEnvironmentVariable("SLIMIDENTITY_TEST_POSTGRES");
        Skip.If(string.IsNullOrEmpty(server), "SLIMIDENTITY_TEST_POSTGRES is not set.");
        var connectionString = new Npgsql.NpgsqlConnectionStringBuilder(server) { Database = "conformance_efcore" }.ToString();
        await VerifyAsync(o => o.UseNpgsql(connectionString));
    }

    [SkippableFact]
    public async Task EfCore_templates_honour_all_store_contracts_on_SQL_Server()
    {
        var server = Environment.GetEnvironmentVariable("SLIMIDENTITY_TEST_SQLSERVER");
        Skip.If(string.IsNullOrEmpty(server), "SLIMIDENTITY_TEST_SQLSERVER is not set.");
        var connectionString = new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(server) { InitialCatalog = "conformance_efcore" }.ToString();
        await VerifyAsync(o => o.UseSqlServer(connectionString));
    }

    private static async Task VerifyAsync(Action<DbContextOptionsBuilder> provider, Func<AppDbContext, Task>? prepare = null)
    {
        await using var services = new ServiceCollection()
            .AddDbContextFactory<AppDbContext>(provider)
            .AddScoped<IdentityDb>()
            .AddSingleton(TimeProvider.System)
            .AddScoped<ISlimUserStore, EfCoreUserStore>()
            .AddScoped<ISlimTwoFactorStore, EfCoreTwoFactorStore>()
            .AddScoped<ISlimRefreshTokenStore, EfCoreRefreshTokenStore>()
            .AddScoped<ISlimSessionStore, EfCoreSessionStore>()
            .AddScoped<ISlimExternalLoginStore, EfCoreExternalLoginStore>()
            .AddScoped<ISlimPasskeyStore, EfCorePasskeyStore>()
            .BuildServiceProvider();

        await using (var scope = services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await db.Database.EnsureDeletedAsync();
            await db.Database.EnsureCreatedAsync();
            if (prepare is not null) await prepare(db);
        }

        var report = await SlimStoreConformance.VerifyAsync(services);
        Assert.Contains(report.Results, r => r.Store == nameof(ISlimSessionStore));   // every capability was checked
    }
}
