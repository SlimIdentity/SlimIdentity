using System.Collections.Concurrent;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Hosting;

namespace SlimIdentity.Http;

/// <summary>
/// Spots deployment mistakes that do not fail loudly but undermine the protection – mostly relevant behind load
/// balancers and with several instances. Only logs; never changes behaviour.
/// </summary>
internal sealed class SlimDeploymentDiagnostics(ILogger<SlimDeploymentDiagnostics> logger)
{
    private const int MaxReportedProxies = 16;
    private readonly ConcurrentDictionary<string, bool> _reportedProxies = new(StringComparer.Ordinal);

    /// <summary>
    /// A request still carries <c>X-Forwarded-For</c> although the forwarded-headers middleware did not apply it (it sets
    /// <c>X-Original-For</c> when it does): the app sees the proxy's address, so every client behind it shares one
    /// rate-limit bucket and the scheme may be wrong. Logged once per proxy address.
    /// </summary>
    public void InspectRequest(HttpContext context)
    {
        var headers = context.Request.Headers;
        if (!headers.ContainsKey("X-Forwarded-For") || headers.ContainsKey("X-Original-For")) return;

        var proxy = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (_reportedProxies.Count >= MaxReportedProxies || !_reportedProxies.TryAdd(proxy, true)) return;
        Log.ForwardedHeadersNotApplied(logger, proxy);
    }

    /// <summary>Start-up checks for setups with several instances (Production only – single instances are fine).</summary>
    public void InspectStartup(IServiceProvider services)
    {
        if (services.GetService<IHostEnvironment>() is not { } environment || !environment.IsProduction()) return;

        // Default key storage = local to this machine / container; and keys are isolated by content-root path unless an
        // application name is set. Either breaks cookies and links across instances (or after a container restart).
        var keyManagement = services.GetService<IOptions<KeyManagementOptions>>()?.Value;
        if (keyManagement is not null && IsLocalKeyStorage(keyManagement.XmlRepository))
            Log.DataProtectionKeysLocal(logger);
        // without SetApplicationName the host fills in the content-root path – different paths, different key isolation
        var discriminator = services.GetService<IOptions<DataProtectionOptions>>()?.Value.ApplicationDiscriminator;
        if (string.IsNullOrEmpty(discriminator)
            || string.Equals(Path.TrimEndingDirectorySeparator(discriminator), Path.TrimEndingDirectorySeparator(environment.ContentRootPath), StringComparison.OrdinalIgnoreCase))
            Log.DataProtectionNoApplicationName(logger);

        // with the in-memory default, one-time codes and mail limits hold per instance only
        try
        {
            using var scope = services.CreateScope();
            if (scope.ServiceProvider.GetService<ISlimSharedState>() is Services.SlimMemorySharedState)
                Log.SharedStatePerInstance(logger);
        }
        catch (InvalidOperationException)
        {
            // a host-registered state that cannot be built here is not the default
        }
    }

    /// <summary>
    /// The framework's fallbacks when nothing is configured: in-memory, the Windows registry, or the user-profile
    /// directory (<c>%LOCALAPPDATA%\ASP.NET\DataProtection-Keys</c>, <c>~/.aspnet/DataProtection-Keys</c>).
    /// </summary>
    internal static bool IsLocalKeyStorage(Microsoft.AspNetCore.DataProtection.Repositories.IXmlRepository? repository)
    {
        switch (repository)
        {
            case null:
                return true;
            case Microsoft.AspNetCore.DataProtection.Repositories.FileSystemXmlRepository fileSystem:
                var path = Path.TrimEndingDirectorySeparator(fileSystem.Directory.FullName);
                return DefaultKeyDirectories().Any(d => string.Equals(path, d, StringComparison.OrdinalIgnoreCase));
            default:
                return repository.GetType().Name is "EphemeralXmlRepository" or "RegistryXmlRepository";
        }
    }

    private static IEnumerable<string> DefaultKeyDirectories()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrEmpty(localAppData)) yield return Path.Combine(localAppData, "ASP.NET", "DataProtection-Keys");
        var home = Environment.GetEnvironmentVariable("HOME");
        if (!string.IsNullOrEmpty(home)) yield return Path.Combine(home, ".aspnet", "DataProtection-Keys");
    }
}
