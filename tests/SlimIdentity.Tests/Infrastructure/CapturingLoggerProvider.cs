using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace SlimIdentity.Tests.Infrastructure;

/// <summary>Records every log entry (message, structured state, exception) – for assertions on logging.</summary>
public sealed class CapturingLoggerProvider : ILoggerProvider
{
    public ConcurrentQueue<string> Entries { get; } = new();
    public ConcurrentQueue<int> EventIds { get; } = new();

    public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);
    public void Dispose() { }

    private sealed class Logger(CapturingLoggerProvider owner, string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            owner.Entries.Enqueue($"[scope {category}] {state}");
            return null;
        }

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            var structured = state is IEnumerable<KeyValuePair<string, object?>> kv ? string.Join(" | ", kv.Select(p => $"{p.Key}={p.Value}")) : "";
            owner.EventIds.Enqueue(eventId.Id);
            owner.Entries.Enqueue($"[{logLevel} {category} {eventId.Id}] {formatter(state, exception)} {structured} {exception}");
        }
    }
}
