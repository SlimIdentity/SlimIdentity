using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;

namespace BFS.SlimIdentity;

public class SlimIdentityBuilder
{
    public IServiceCollection Services { get; }
    public SlimIdentityBuilder(IServiceCollection services) => Services = services;

    public SlimIdentityBuilder AddUserStore<TStore>() where TStore : class, ISlimUserStore
    {
        Services.AddScoped<ISlimUserStore, TStore>();
        return this;
    }
}

public static class SlimIdentityServiceExtensions
{
    public static SlimIdentityBuilder AddSlimIdentity(
        this IServiceCollection services,
        Action<SlimIdentityOptions>? configureOptions = null)
    {
        // 1. Optionen konfigurieren und als Singleton registrieren
        var options = new SlimIdentityOptions();
        configureOptions?.Invoke(options);
        services.AddSingleton(options);

        // 2. Den nativen Microsoft Passwort-Hasher registrieren (ohne EF Core Abhängigkeit!)
        services.AddScoped<IPasswordHasher<SlimUser>, PasswordHasher<SlimUser>>();

        // 3. Den Rate-Limiter für die API-Härtung (Brute-Force-Schutz) konfigurieren
        services.AddRateLimiter(limiterOptions =>
        {
            limiterOptions.AddFixedWindowLimiter("SlimIdentity_BruteForce", opt =>
            {
                opt.Window = TimeSpan.FromMinutes(1);
                opt.PermitLimit = options.Lockout.MaxLoginRequestsPerMinute;
                opt.QueueLimit = 0;
            });
        });

        return new SlimIdentityBuilder(services);
    }
}
