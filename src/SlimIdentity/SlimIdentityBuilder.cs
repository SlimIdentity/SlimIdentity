using SlimIdentity.Abstractions;
using SlimIdentity.Authentication;
using SlimIdentity.Endpoints;
using SlimIdentity.Services;

namespace SlimIdentity;

/// <summary>
/// Fluent builder. Every optional capability is activated simply by registering its interface (opt-in complexity).
/// </summary>
public sealed class SlimIdentityBuilder
{
    internal SlimIdentityBuilder(IServiceCollection services, AuthenticationBuilder authentication)
    {
        Services = services;
        Authentication = authentication;
    }

    public IServiceCollection Services { get; }

    /// <summary>
    /// The underlying authentication builder – register OAuth/OIDC providers here, e.g.
    /// <c>builder.Authentication.AddGoogle(o =&gt; o.SignInScheme = SlimIdentityDefaults.ExternalScheme)</c>.
    /// </summary>
    public AuthenticationBuilder Authentication { get; }

    // ---------------------------------------------------------------- mandatory

    public SlimIdentityBuilder AddUserStore<TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TStore : class, ISlimUserStore => Register<ISlimUserStore, TStore>(lifetime);

    public SlimIdentityBuilder AddEmailSender<TSender>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TSender : class, ISlimEmailSender => Register<ISlimEmailSender, TSender>(lifetime);

    /// <summary>Logs mails instead of sending them. Development only.</summary>
    public SlimIdentityBuilder AddNullEmailSender() => AddEmailSender<SlimNullEmailSender>(ServiceLifetime.Singleton);

    // ---------------------------------------------------------------- optional capabilities

    /// <summary>Activates <c>/refresh</c> and refresh tokens in bearer responses.</summary>
    public SlimIdentityBuilder AddRefreshTokenStore<TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TStore : class, ISlimRefreshTokenStore => Register<ISlimRefreshTokenStore, TStore>(lifetime);

    /// <summary>
    /// Activates server-side sessions: real per-device <c>/logout</c>, <c>GET /sessions</c>, <c>DELETE /sessions/{id}</c>
    /// and session-scoped refresh-token reuse detection.
    /// </summary>
    public SlimIdentityBuilder AddSessionStore<TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TStore : class, ISlimSessionStore => Register<ISlimSessionStore, TStore>(lifetime);

    /// <summary>Activates <c>/login/2fa</c> and <c>/2fa/*</c>.</summary>
    public SlimIdentityBuilder AddTwoFactorStore<TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TStore : class, ISlimTwoFactorStore
    {
        Register<ISlimTwoFactorStore, TStore>(lifetime);
        Services.TryAddScoped<SlimTwoFactorHandlers>();
        return this;
    }

    /// <summary>
    /// Activates <c>/login/{provider}</c>. Remote handlers without explicit <c>SignInScheme</c> sign in to
    /// <see cref="SlimIdentityDefaults.ExternalScheme"/>.
    /// </summary>
    public SlimIdentityBuilder AddExternalLoginStore<TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TStore : class, ISlimExternalLoginStore
    {
        Register<ISlimExternalLoginStore, TStore>(lifetime);
        Services.TryAddScoped<SlimExternalLoginHandlers>();
        Services.Configure<AuthenticationOptions>(o => o.DefaultSignInScheme ??= SlimIdentityDefaults.ExternalScheme);
        return this;
    }

    /// <summary>Activates the <c>X-API-Key</c> authentication handler.</summary>
    public SlimIdentityBuilder AddApiKeyStore<TStore>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
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
    public SlimIdentityBuilder AddCustomPasswordValidator<TValidator>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TValidator : class, ISlimCustomPasswordValidator => Register<ISlimCustomPasswordValidator, TValidator>(lifetime);

    private SlimIdentityBuilder Register<TService, TImplementation>(ServiceLifetime lifetime)
        where TService : class
        where TImplementation : class, TService
    {
        Services.Replace(new ServiceDescriptor(typeof(TService), typeof(TImplementation), lifetime));
        return this;
    }
}
