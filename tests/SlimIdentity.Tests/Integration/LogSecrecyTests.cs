using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SlimIdentity.Security;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>
/// Attack scenario H6: logs end up in log aggregators, tickets and screenshots. Run every flow that handles a secret
/// with all log levels on, then check that no password, token, link, recovery code, 2FA secret or e-mail address
/// appears anywhere – neither in messages nor in structured state nor in logged exceptions.
/// </summary>
public sealed class LogSecrecyTests
{
    [Fact]
    public async Task No_secret_or_address_is_ever_logged()
    {
        var logs = new CapturingLoggerProvider();
        await using var app = await TestApp.StartAsync(new TestAppOptions { LoggerProvider = logs });
        var secrets = new List<string>();
        var client = app.CreateClient();
        const string email = "secret-owner@test.local";
        const string password = "Initial-Pass-123";
        const string newPassword = "Changed-Pass-456";
        secrets.AddRange([email, password, newPassword]);

        // registration, verification, login with wrong passwords (lockout path) and correct password
        var started = await client.PostJsonAsync("/auth/register", new { email });
        var mail = await app.Mail.WaitForAsync("verification", email);
        var verify = TestApp.LinkToken(mail.Link!);
        var verified = await client.PostJsonAsync("/auth/register/verify", new { flowToken = started.Str("flowToken"), code = mail.Payload });
        await client.PostJsonAsync("/auth/register/password", new { flowToken = verified.Str("flowToken"), password });
        secrets.AddRange([mail.Payload, started.Str("flowToken"), verified.Str("flowToken")]);
        for (var i = 0; i < 3; i++)
            await client.PostAsync("/auth/login", new { email, password = "wrong-" + password });
        var tokens = await client.PostJsonAsync("/auth/login", new { email, password });
        Collect(tokens);

        // refresh, also a replay (reuse detection logs a warning)
        var refreshed = await client.PostJsonAsync("/auth/refresh", new { refreshToken = tokens.Str("refreshToken") });
        Collect(refreshed);
        await client.PostAsync("/auth/refresh", new { refreshToken = tokens.Str("refreshToken") });
        await client.PostAsync("/auth/flow", new { token = "tampered" + verify });

        // password reset
        await client.PostAsync("/auth/forgot-password", new { email });
        var reset = (await app.Mail.WaitForAsync("password-reset", email)).Payload;
        await client.PostJsonAsync("/auth/reset-password", new { token = reset, newPassword });
        secrets.AddRange([verify, reset]);

        // 2FA: setup, enable, challenge, wrong code, recovery code
        var session = await client.PostJsonAsync("/auth/login", new { email, password = newPassword });
        Collect(session);
        var me = app.CreateClient();
        me.BearerToken = session.Str("accessToken");
        var setup = await me.PostJsonAsync("/auth/2fa/setup");
        secrets.AddRange([setup.Str("sharedKey").Replace(" ", ""), setup.Str("setupToken")]);
        var code = SlimTotp.Compute(SlimBase32.Decode(setup.Str("sharedKey")), app.Time.GetUtcNow().ToUnixTimeSeconds() / 30);
        var enabled = await me.PostJsonAsync("/auth/2fa/enable", new { setupToken = setup.Str("setupToken"), code, password = newPassword });
        var recovery = enabled.GetProperty("recoveryCodes").EnumerateArray().Select(c => c.GetString()!).ToArray();
        secrets.AddRange(recovery);
        var challenge = await client.PostJsonAsync("/auth/login", new { email, password = newPassword });
        secrets.Add(challenge.Str("flowToken"));
        await client.PostAsync("/auth/login/2fa", new { flowToken = challenge.Str("flowToken"), code = "000000" });
        Collect(await client.PostJsonAsync("/auth/login/2fa", new { flowToken = challenge.Str("flowToken"), recoveryCode = recovery[0] }));

        await Task.Delay(200);   // background mail queue
        var all = string.Join("\n", logs.Entries);
        // the capture really sees SlimIdentity's own events (reuse detection, recovery code) – the test is not vacuous
        Assert.Contains(logs.Entries, e => e.Contains("refresh token reuse", StringComparison.Ordinal));
        Assert.Contains(logs.Entries, e => e.Contains("signed in with a recovery code", StringComparison.Ordinal));
        foreach (var secret in secrets.Where(s => s.Length >= 8).Distinct())
            Assert.False(all.Contains(secret, StringComparison.OrdinalIgnoreCase), $"A secret was logged: {secret[..8]}…\n{FirstLineWith(all, secret)}");

        void Collect(JsonElement auth)
        {
            foreach (var name in new[] { "accessToken", "refreshToken" })
                if (auth.TryGetProperty(name, out var v) && v.GetString() is { } s) secrets.Add(s);
        }
    }

    private static string FirstLineWith(string all, string secret) =>
        all.Split('\n').FirstOrDefault(l => l.Contains(secret, StringComparison.OrdinalIgnoreCase)) ?? "";
}
