using Microsoft.Extensions.DependencyInjection.Extensions;

namespace SlimIdentity.EntityFrameworkCore;

/// <summary>Which stores <c>AddEntityFrameworkStores</c> registers (every registered store activates its endpoints).</summary>
public sealed class SlimEntityFrameworkOptions
{
    /// <summary><see cref="ISlimTwoFactorStore"/>: <c>/login/2fa</c>, <c>/2fa/*</c>. Default <c>true</c>.</summary>
    public bool TwoFactor { get; set; } = true;
    /// <summary><see cref="ISlimRefreshTokenStore"/>: <c>/refresh</c> (only relevant with JWT). Default <c>true</c>.</summary>
    public bool RefreshTokens { get; set; } = true;
    /// <summary><see cref="ISlimSessionStore"/>: per-device logout, <c>/sessions</c>. Default <c>true</c>.</summary>
    public bool Sessions { get; set; } = true;
    /// <summary><see cref="ISlimExternalLoginStore"/>: <c>/login/{provider}</c>. Default <c>true</c>.</summary>
    public bool ExternalLogins { get; set; } = true;
    /// <summary>Persist user agent and IP address of sessions (personal data, shown in the device list). Default <c>true</c>.</summary>
    public bool StoreClientInfo { get; set; } = true;
}

/// <summary>Service registration of the EF Core stores.</summary>
public static class SlimEntityFrameworkBuilderExtensions
{
    /// <summary>
    /// Registers the EF Core stores on <typeparamref name="TContext"/> (scoped). The stores work on their own context
    /// instance per request (<see cref="SlimEfContext{TContext}"/>), never on the one the host's code resolves. Requires
    /// <c>modelBuilder.ApplySlimIdentity&lt;TUser, TKey&gt;()</c> in <c>OnModelCreating</c> and an
    /// <c>AddDbContext&lt;TContext&gt;</c> registration.
    /// </summary>
    /// <example><code>
    /// builder.Services.AddSlimIdentity(builder.Configuration.GetSection("SlimIdentity"))
    ///     .AddEntityFrameworkStores&lt;AppDbContext, AppUser, Guid&gt;()
    ///     .AddEmailSender&lt;MyEmailSender&gt;();
    /// </code></example>
    public static SlimIdentityBuilder AddEntityFrameworkStores<TContext, TUser, TKey>(
        this SlimIdentityBuilder builder, Action<SlimEntityFrameworkOptions>? configure = null)
        where TContext : DbContext
        where TUser : class, ISlimUserEntity<TKey>, new()
        where TKey : IEquatable<TKey>, IParsable<TKey>
    {
        ArgumentNullException.ThrowIfNull(builder);
        var options = new SlimEntityFrameworkOptions();
        configure?.Invoke(options);
        builder.Services.AddSingleton(options);
        builder.Services.TryAddScoped<SlimEfContext<TContext>>();   // own context instance, never the host's scoped one

        builder.AddUserStore<SlimEfUserStore<TContext, TUser, TKey>>();
        if (options.TwoFactor) builder.AddTwoFactorStore<SlimEfTwoFactorStore<TContext, TUser, TKey>>();
        if (options.RefreshTokens) builder.AddRefreshTokenStore<SlimEfRefreshTokenStore<TContext, TKey>>();
        if (options.Sessions) builder.AddSessionStore<SlimEfSessionStore<TContext, TKey>>();
        if (options.ExternalLogins) builder.AddExternalLoginStore<SlimEfExternalLoginStore<TContext, TKey>>();
        return builder;
    }
}
