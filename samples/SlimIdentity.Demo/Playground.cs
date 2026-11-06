using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace SlimIdentity.Demo;

/// <summary>
/// Demo settings (section <c>Demo</c>). In Breakme mode the seeded accounts get random passwords that are only printed
/// to the console – the challenge is to get into them anyway.
/// </summary>
public sealed class DemoSettings
{
    public DemoSettings(IConfiguration configuration)
    {
        Breakme = configuration.GetValue<bool>("Demo:Breakme");
        AdminPassword = Breakme ? RandomPassword() : "Admin123!";
        UserPassword = Breakme ? RandomPassword() : "User1234!";
    }

    public bool Breakme { get; }
    public string AdminPassword { get; }
    public string UserPassword { get; }

    /// <summary>Addresses whose mails stay private (console only) – the seeded accounts.</summary>
    public static bool IsSeeded(string address) => address.EndsWith("@demo.local", StringComparison.OrdinalIgnoreCase);

    private static string RandomPassword() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
}

/// <summary>Fake mailbox of the playground: the last mails per address, readable in the browser.</summary>
public sealed class DemoMailbox(TimeProvider time)
{
    private const int MaxPerAddress = 20;
    private const int MaxAddresses = 1000;
    private readonly ConcurrentDictionary<string, ConcurrentQueue<DemoMail>> _mails = new(StringComparer.OrdinalIgnoreCase);

    public void Deliver(string to, string subject, string body)
    {
        if (DemoSettings.IsSeeded(to)) return;   // the seeded accounts' mail is private
        if (_mails.Count >= MaxAddresses && !_mails.ContainsKey(to)) return;
        var queue = _mails.GetOrAdd(to, _ => new ConcurrentQueue<DemoMail>());
        queue.Enqueue(new DemoMail(to, subject, body, time.GetUtcNow()));
        while (queue.Count > MaxPerAddress) queue.TryDequeue(out _);
    }

    public IReadOnlyList<DemoMail> For(string address) =>
        _mails.TryGetValue(address.Trim(), out var queue) ? queue.Reverse().ToList() : [];
}

public sealed record DemoMail(string To, string Subject, string Body, DateTimeOffset SentAt);
public sealed record DemoInfo(bool Breakme, bool JwtEnabled, string[] SeededAccounts);
