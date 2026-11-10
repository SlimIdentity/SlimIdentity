using Microsoft.Extensions.DependencyInjection;
using MyApp.Data;
using Npgsql;
using SlimIdentity.Testing;

namespace SlimIdentity.Samples.Tests;

/// <summary>
/// The Dapper templates against a real PostgreSQL. Runs when <c>SLIMIDENTITY_TEST_POSTGRES</c> holds a connection string
/// to an empty, disposable database (CI starts a PostgreSQL service container); skipped otherwise.
/// </summary>
public sealed class DapperTemplateConformanceTests
{
    private static readonly string? ConnectionString = Environment.GetEnvironmentVariable("SLIMIDENTITY_TEST_POSTGRES");

    [SkippableFact]
    public async Task Dapper_templates_honour_all_store_contracts_on_PostgreSQL()
    {
        Skip.If(string.IsNullOrEmpty(ConnectionString), "SLIMIDENTITY_TEST_POSTGRES is not set.");

        var dataSource = NpgsqlDataSource.Create(ConnectionString!);
        await using (var connection = await dataSource.OpenConnectionAsync())
        await using (var command = connection.CreateCommand())
        {
            // fresh schema per run (the database is disposable)
            command.CommandText = "DROP SCHEMA public CASCADE; CREATE SCHEMA public; CREATE EXTENSION IF NOT EXISTS pgcrypto;\n"
                                  + await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "schema.sql"));
            await command.ExecuteNonQueryAsync();
        }

        await using var services = new ServiceCollection()
            .AddSingleton(dataSource)
            .AddScoped<ISlimUserStore, DapperUserStore>()
            .AddScoped<ISlimTwoFactorStore, DapperTwoFactorStore>()
            .AddScoped<ISlimRefreshTokenStore, DapperRefreshTokenStore>()
            .AddScoped<ISlimSessionStore, DapperSessionStore>()
            .AddScoped<ISlimExternalLoginStore, DapperExternalLoginStore>()
            .AddScoped<ISlimPasskeyStore, DapperPasskeyStore>()
            .BuildServiceProvider();

        var report = await SlimStoreConformance.VerifyAsync(services);
        Assert.Contains(report.Results, r => r.Store == nameof(ISlimSessionStore));
    }
}
