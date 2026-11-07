using Microsoft.Extensions.Configuration;
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
        where TSender : class, ISlimEmailSender
    {
        Services.RemoveAll<SlimNullEmailSenderGuard>();
        return Register<ISlimEmailSender, TSender>(lifetime);
    }

    /// <summary>
    /// Logs mails – including live links and codes – instead of sending them. Development only:
    /// <c>MapSlimIdentityApi</c> refuses to start in the <c>Production</c> environment unless
    /// <paramref name="allowInProduction"/> is <c>true</c> (e.g. for a production-like test system without mail).
    /// </summary>
    /// <param name="allowInProduction">Explicitly allow the null sender in the <c>Production</c> environment.</param>
    public SlimIdentityBuilder AddNullEmailSender(bool allowInProduction = false)
    {
        Register<ISlimEmailSender, SlimNullEmailSender>(ServiceLifetime.Singleton);
        Services.Replace(ServiceDescriptor.Singleton(new SlimNullEmailSenderGuard(allowInProduction)));
        return this;
    }

    /// <summary>
    /// Runs without a mail server (internal services where an administrator creates accounts): no mail is ever sent and
    /// no sender is required. Not mapped: <c>/forgot-password</c>, <c>/verify-email</c>, <c>/resend-verification</c>,
    /// <c>/change-email</c>, <c>/confirm-email-change</c>, <c>/2fa/enable-email</c> and – unless
    /// <paramref name="allowSelfRegistration"/> – <c>/register</c>. Lockout and "account exists" notices are dropped.
    /// Passwords are changed with <c>/change-password</c>; forgotten passwords are reset by an administrator
    /// (<see cref="ISlimAuthManager"/>), whose links use <c>/reset-password</c> and <c>/invitation/accept</c>.
    /// </summary>
    /// <param name="allowSelfRegistration">Keeps <c>/register</c> (accounts without a confirmed address).</param>
    public SlimIdentityBuilder WithoutEmail(bool allowSelfRegistration = false)
    {
        Services.PostConfigure<SlimIdentityOptions>(o =>
        {
            o.Email.Enabled = false;
            o.Endpoints.EnableEmailVerification = false;
            o.Endpoints.EnableChangeEmail = false;
            if (!allowSelfRegistration) o.Endpoints.EnableRegistration = false;
        });
        return this;
    }

    /// <summary>
    /// Adds host data (tenant, brand, front-end origin, …) to the <see cref="SlimEmailContext"/> of every mail, captured
    /// in the request that causes it. Can be called several times.
    /// </summary>
    public SlimIdentityBuilder AddEmailContextEnricher<[DynamicallyAccessedMembers(Ctors)] TEnricher>()
        where TEnricher : class, ISlimEmailContextEnricher
    {
        Services.TryAddEnumerable(ServiceDescriptor.Singleton<ISlimEmailContextEnricher, TEnricher>());
        return this;
    }

    // ---------------------------------------------------------------- hooks (they can only tighten)

    /// <summary>Adds a veto before every new session and while it runs (see <see cref="ISlimSignInGuard"/>). Can be called several times.</summary>
    public SlimIdentityBuilder AddSignInGuard<[DynamicallyAccessedMembers(Ctors)] TGuard>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TGuard : class, ISlimSignInGuard
    {
        Services.TryAddEnumerable(ServiceDescriptor.Describe(typeof(ISlimSignInGuard), typeof(TGuard), lifetime));
        return this;
    }

    /// <summary>Adds a veto against new accounts (see <see cref="ISlimRegistrationGuard"/>). Can be called several times.</summary>
    public SlimIdentityBuilder AddRegistrationGuard<[DynamicallyAccessedMembers(Ctors)] TGuard>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TGuard : class, ISlimRegistrationGuard
    {
        Services.TryAddEnumerable(ServiceDescriptor.Describe(typeof(ISlimRegistrationGuard), typeof(TGuard), lifetime));
        return this;
    }

    /// <summary>Adds an observer of security events (see <see cref="ISlimEventObserver"/>). Can be called several times.</summary>
    public SlimIdentityBuilder AddEventObserver<[DynamicallyAccessedMembers(Ctors)] TObserver>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TObserver : class, ISlimEventObserver
    {
        Services.TryAddEnumerable(ServiceDescriptor.Describe(typeof(ISlimEventObserver), typeof(TObserver), lifetime));
        return this;
    }

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

    /// <summary>
    /// Activates the <c>X-API-Key</c> handler for a fixed set of machine clients from configuration – no database.
    /// <paramref name="section"/> is a list of <see cref="SlimConfiguredApiKey"/> (client id, hash, scopes, roles,
    /// expiry). It is validated at startup and followed on reload: removing or changing an entry revokes the key.
    /// </summary>
    /// <example><code>
    /// // "SlimIdentity": { "ApiKeys": [ { "ClientId": "reports", "Hash": "9f2c…", "Scopes": [ "reports:read" ] } ] }
    /// builder.Services.AddSlimIdentity(…).AddConfigurationApiKeys(builder.Configuration.GetSection("SlimIdentity:ApiKeys"));
    /// </code></example>
    public SlimIdentityBuilder AddConfigurationApiKeys(IConfiguration section)
    {
        ArgumentNullException.ThrowIfNull(section);
        Services.AddOptions<SlimConfiguredApiKeyOptions>()
            .Configure(o => o.Keys = section.Get<List<SlimConfiguredApiKey>>() ?? [])
            .ValidateOnStart();
        Services.AddSingleton<IOptionsChangeTokenSource<SlimConfiguredApiKeyOptions>>(
            new ConfigurationChangeTokenSource<SlimConfiguredApiKeyOptions>(section));
        Services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<SlimConfiguredApiKeyOptions>, SlimConfiguredApiKeyValidator>());
        return AddApiKeyStore<SlimConfigurationApiKeyStore>(ServiceLifetime.Singleton);
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

    internal sealed record SlimNullEmailSenderGuard(bool AllowInProduction);

    private SlimIdentityBuilder Register<TService,[DynamicallyAccessedMembers(Ctors)] TImplementation>(ServiceLifetime lifetime)
        where TService : class
        where TImplementation : class, TService
    {
        Services.Replace(new ServiceDescriptor(typeof(TService), typeof(TImplementation), lifetime));
        return this;
    }
}
