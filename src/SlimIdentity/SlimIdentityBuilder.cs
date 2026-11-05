using System.Diagnostics.CodeAnalysis;
using SlimIdentity.Authentication;
using SlimIdentity.Endpoints;
using SlimIdentity.Services;

namespace SlimIdentity;

/// <summary>
/// Fluent builder returned by <c>AddSlimIdentity</c>. Every optional capability is activated simply by registering
/// its interface (opt-in complexity).
/// </summary>
public sealed class SlimIdentityBuilder
{
    private const DynamicallyAccessedMemberTypes Ctors = DynamicallyAccessedMemberTypes.PublicConstructors;

    internal SlimIdentityBuilder(IServiceCollection services, AuthenticationBuilder authentication)
    {
        Services = services;
        Authentication = authentication;
    }

    /// <summary>The service collection SlimIdentity was added to.</summary>
    public IServiceCollection Services { get; }

    /// <summary>
    /// The underlying authentication builder – register OAuth/OIDC providers here, e.g.
    /// <c>builder.Authentication.AddGoogle(o =&gt; o.SignInScheme = SlimIdentityDefaults.ExternalScheme)</c>.
    /// </summary>
    public AuthenticationBuilder Authentication { get; }

    // ---------------------------------------------------------------- mandatory

    /// <summary>Registers the mandatory user store (your database bridge).</summary>
    public SlimIdentityBuilder AddUserStore<[DynamicallyAccessedMembers(Ctors)] TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TStore : class, ISlimUserStore => Register<ISlimUserStore, TStore>(lifetime);

    /// <summary>Registers the mandatory e-mail sender.</summary>
    public SlimIdentityBuilder AddEmailSender<[DynamicallyAccessedMembers(Ctors)] TSender>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TSender : class, ISlimEmailSender => Register<ISlimEmailSender, TSender>(lifetime);

    /// <summary>Logs mails (including tokens and codes!) instead of sending them. Development only.</summary>
    public SlimIdentityBuilder AddNullEmailSender() => AddEmailSender<SlimNullEmailSender>(ServiceLifetime.Singleton);

    // ---------------------------------------------------------------- optional capabilities

    /// <summary>Activates <c>/refresh</c> and refresh tokens in bearer responses.</summary>
    public SlimIdentityBuilder AddRefreshTokenStore<[DynamicallyAccessedMembers(Ctors)] TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TStore : class, ISlimRefreshTokenStore => Register<ISlimRefreshTokenStore, TStore>(lifetime);

    /// <summary>
    /// Activates server-side sessions: real per-device <c>/logout</c>, <c>GET /sessions</c>, <c>DELETE /sessions/{id}</c>
    /// and session-scoped refresh-token reuse detection.
    /// </summary>
    public SlimIdentityBuilder AddSessionStore<[DynamicallyAccessedMembers(Ctors)] TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TStore : class, ISlimSessionStore => Register<ISlimSessionStore, TStore>(lifetime);

    /// <summary>Activates <c>/login/2fa</c> and <c>/2fa/*</c>.</summary>
    public SlimIdentityBuilder AddTwoFactorStore<[DynamicallyAccessedMembers(Ctors)] TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TStore : class, ISlimTwoFactorStore
    {
        Register<ISlimTwoFactorStore, TStore>(lifetime);
        Services.TryAddScoped<SlimTwoFactorService>();
        Services.TryAddScoped<SlimTwoFactorHandlers>();
        return this;
    }

    /// <summary>
    /// Activates <c>/login/{provider}</c>. Remote handlers without explicit <c>SignInScheme</c> sign in to
    /// <see cref="SlimIdentityDefaults.ExternalScheme"/>.
    /// </summary>
    public SlimIdentityBuilder AddExternalLoginStore<[DynamicallyAccessedMembers(Ctors)] TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TStore : class, ISlimExternalLoginStore
    {
        Register<ISlimExternalLoginStore, TStore>(lifetime);
        Services.TryAddScoped<SlimExternalLoginHandlers>();
        Services.TryAddSingleton<SlimLocalNonceRegistry>();
        Services.Configure<AuthenticationOptions>(o => o.DefaultSignInScheme ??= SlimIdentityDefaults.ExternalScheme);
        return this;
    }

    /// <summary>Activates the <c>X-API-Key</c> authentication handler.</summary>
    public SlimIdentityBuilder AddApiKeyStore<[DynamicallyAccessedMembers(Ctors)] TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TStore : class, ISlimApiKeyStore
    {
        Register<ISlimApiKeyStore, TStore>(lifetime);
        if (!Services.Any(d => d.ServiceType == typeof(SlimApiKeyMarker)))
        {
            Services.AddSingleton<SlimApiKeyMarker>();
            Authentication.AddScheme<AuthenticationSchemeOptions, SlimApiKeyHandler>(SlimIdentityDefaults.ApiKeyScheme, _ => { });
        }
        return this;
    }

    /// <summary>Delegates the password check of <c>/login</c> to LDAP / AD / legacy validation.</summary>
    public SlimIdentityBuilder AddCustomPasswordValidator<[DynamicallyAccessedMembers(Ctors)] TValidator>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TValidator : class, ISlimCustomPasswordValidator => Register<ISlimCustomPasswordValidator, TValidator>(lifetime);

    /// <summary>
    /// Adds a rule for new passwords on top of <see cref="SlimPasswordOptions"/> (e.g. a breached-password check).
    /// Can be called several times; all rules must pass.
    /// </summary>
    public SlimIdentityBuilder AddPasswordRule<[DynamicallyAccessedMembers(Ctors)] TRule>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TRule : class, ISlimPasswordRule
    {
        Services.TryAddEnumerable(new ServiceDescriptor(typeof(ISlimPasswordRule), typeof(TRule), lifetime));
        return this;
    }

    // ---------------------------------------------------------------- tuning

    /// <summary>
    /// Replaces the client key of the built-in rate limiters (default: client IP, IPv6 grouped by
    /// <see cref="SlimRateLimitOptions.IPv6PrefixLength"/>). Return <c>null</c> to fall back to the default,
    /// e.g. partition known corporate networks by a header your gateway sets.
    /// </summary>
    /// <param name="keySelector">Returns the partition key for a request, or null for the default key.</param>
    public SlimIdentityBuilder UseRateLimitPartitionKey(Func<HttpContext, string?> keySelector)
    {
        ArgumentNullException.ThrowIfNull(keySelector);
        Services.Replace(ServiceDescriptor.Singleton(new Http.SlimRateLimitPartitioner(keySelector)));
        return this;
    }

    private SlimIdentityBuilder Register<TService, [DynamicallyAccessedMembers(Ctors)] TImplementation>(ServiceLifetime lifetime)
        where TService : class
        where TImplementation : class, TService
    {
        Services.Replace(new ServiceDescriptor(typeof(TService), typeof(TImplementation), lifetime));
        return this;
    }
}
