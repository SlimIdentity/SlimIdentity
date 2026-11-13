using System.Globalization;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using MyApp.Data;
using MyApp.Mail;

namespace SlimIdentity.Samples.Tests;

/// <summary>The EF Core templates outside the store conformance kit: API keys and the mail outbox, on SQLite.</summary>
public sealed class EfCoreTemplateExtrasTests : IAsyncLifetime
{
    private readonly string _file = Path.Combine(Path.GetTempPath(), $"slimidentity-extras-{Guid.NewGuid():N}.db");
    private readonly ManualTime _time = new(new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero));
    private readonly FailingTransport _transport = new();
    private ServiceProvider _services = null!;

    public async Task InitializeAsync()
    {
        var connectionString = new SqliteConnectionStringBuilder { DataSource = _file, Pooling = false }.ToString();
        _services = new ServiceCollection()
            .AddDbContextFactory<AppDbContext>(o => o.UseSqlite(connectionString))
            .AddScoped<IdentityDb>()
            .AddSingleton<TimeProvider>(_time)
            .AddScoped<EfCoreApiKeyStore>()
            .AddScoped<OutboxEmailSender>()
            .AddSingleton(_transport)
            .AddLogging()
            .AddSingleton<OutboxMailWorker<FailingTransport>>()
            .BuildServiceProvider();
        await using var db = await Factory.CreateDbContextAsync();
        await db.Database.EnsureCreatedAsync();
    }

    public async Task DisposeAsync()
    {
        await _services.DisposeAsync();
        if (File.Exists(_file)) File.Delete(_file);
    }

    private IDbContextFactory<AppDbContext> Factory => _services.GetRequiredService<IDbContextFactory<AppDbContext>>();

    [Fact]
    public async Task Api_keys_validate_on_SQLite_and_honour_expiry_and_revocation()
    {
        await using (var db = await Factory.CreateDbContextAsync())
        {
            db.ApiKeys.AddRange(
                new ApiKey { KeyHash = "valid", ClientId = "billing", Scopes = ["invoices.read"], ExpiresAt = _time.GetUtcNow().AddDays(1) },
                new ApiKey { KeyHash = "forever", ClientId = "export" },
                new ApiKey { KeyHash = "expired", ClientId = "old", ExpiresAt = _time.GetUtcNow().AddSeconds(-1) },
                new ApiKey { KeyHash = "revoked", ClientId = "gone", Revoked = true });
            await db.SaveChangesAsync();
        }

        await using var scope = _services.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<EfCoreApiKeyStore>();

        var claims = await store.ValidateApiKeyAsync("valid", default);
        Assert.NotNull(claims);
        Assert.Contains(claims, c => c.Type == SlimClaimTypes.UserId && c.Value == "client:billing");
        Assert.Contains(claims, c => c.Type == "scope" && c.Value == "invoices.read");
        Assert.NotNull(await store.ValidateApiKeyAsync("forever", default));
        Assert.Null(await store.ValidateApiKeyAsync("expired", default));
        Assert.Null(await store.ValidateApiKeyAsync("revoked", default));
        Assert.Null(await store.ValidateApiKeyAsync("unknown", default));
    }

    [Fact]
    public async Task Outbox_retries_with_backoff_and_erases_the_payload_once_sent()
    {
        await QueueAsync("https://app/verify?token=secret");
        var worker = _services.GetRequiredService<OutboxMailWorker<FailingTransport>>();

        _transport.Fail = true;
        Assert.Equal(0, await worker.DeliverDueAsync(default));
        var failed = await SingleMailAsync();
        Assert.Equal(1, failed.Attempts);
        Assert.Null(failed.SentUtc);
        Assert.Null(failed.LockedUntil);
        Assert.Equal("smtp down", failed.LastError);
        Assert.Equal(_time.GetUtcNow().Add(OutboxMailWorker<FailingTransport>.Backoff(1)).ToUnixTimeMilliseconds(), failed.NextAttemptAt);

        _transport.Fail = false;
        Assert.Equal(0, await worker.DeliverDueAsync(default));   // not due yet
        _time.Advance(OutboxMailWorker<FailingTransport>.Backoff(1));
        Assert.Equal(1, await worker.DeliverDueAsync(default));

        var sent = await SingleMailAsync();
        Assert.NotNull(sent.SentUtc);
        Assert.Equal("", sent.Payload);
        Assert.Null(sent.LastError);
        Assert.Equal(["https://app/verify?token=secret"], _transport.Sent);

        Assert.Equal(0, await worker.DeliverDueAsync(default));   // sent once, never again
        Assert.Single(_transport.Sent);
    }

    [Fact]
    public async Task Outbox_rows_leased_by_another_instance_are_not_sent_twice()
    {
        await QueueAsync("code-123");
        await using (var db = await Factory.CreateDbContextAsync())
        {
            var leaseEnd = _time.GetUtcNow().AddMinutes(5).ToUnixTimeMilliseconds();
            await db.OutboxMails.ExecuteUpdateAsync(s => s.SetProperty(m => m.LockedUntil, leaseEnd));
        }

        var worker = _services.GetRequiredService<OutboxMailWorker<FailingTransport>>();
        Assert.Equal(0, await worker.DeliverDueAsync(default));
        Assert.Empty(_transport.Sent);

        _time.Advance(TimeSpan.FromMinutes(6));   // the other instance died: its lease runs out
        Assert.Equal(1, await worker.DeliverDueAsync(default));
        Assert.Single(_transport.Sent);
    }

    [Fact]
    public void Outbox_backoff_grows_exponentially_and_is_capped_at_one_hour()
    {
        Assert.Equal(TimeSpan.FromSeconds(30), OutboxMailWorker<FailingTransport>.Backoff(1));
        Assert.Equal(TimeSpan.FromMinutes(1), OutboxMailWorker<FailingTransport>.Backoff(2));
        Assert.Equal(TimeSpan.FromHours(1), OutboxMailWorker<FailingTransport>.Backoff(OutboxMailWorker<FailingTransport>.MaxAttempts));
        var total = Enumerable.Range(1, OutboxMailWorker<FailingTransport>.MaxAttempts - 1)
            .Aggregate(TimeSpan.Zero, (sum, n) => sum + OutboxMailWorker<FailingTransport>.Backoff(n));
        Assert.True(total > TimeSpan.FromHours(6), $"retry horizon {total}");
    }

    private async Task QueueAsync(string link)
    {
        await using var scope = _services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<IDbContextFactory<AppDbContext>>().CreateDbContext();
        await using (db)
        {
            var sender = new OutboxEmailSender(db, _time);
            var context = new SlimEmailContext { Kind = SlimEmailKinds.Verification, Culture = CultureInfo.InvariantCulture };
            await sender.SendVerificationEmailAsync(context, "user@example.com", "123456", link, default);
        }
    }

    private async Task<OutboxMail> SingleMailAsync()
    {
        await using var db = await Factory.CreateDbContextAsync();
        return await db.OutboxMails.AsNoTracking().SingleAsync();
    }

    public sealed class FailingTransport : ISlimEmailSender
    {
        public bool Fail { get; set; }
        public List<string> Sent { get; } = [];

        public Task SendVerificationEmailAsync(SlimEmailContext context, string email, string code, string link, CancellationToken ct) => Send(link);
        public Task SendPasswordResetEmailAsync(SlimEmailContext context, string email, string link, CancellationToken ct) => Send(link);
        public Task SendTwoFactorCodeAsync(SlimEmailContext context, string email, string code, CancellationToken ct) => Send(code);
        public Task SendEmailVerificationCodeAsync(SlimEmailContext context, string email, string code, CancellationToken ct) => Send(code);
        public Task SendEmailChangeCodeAsync(SlimEmailContext context, string newEmail, string code, CancellationToken ct) => Send(code);

        private Task Send(string payload)
        {
            if (Fail) throw new InvalidOperationException("smtp down");
            Sent.Add(payload);
            return Task.CompletedTask;
        }
    }

    private sealed class ManualTime(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }
}
