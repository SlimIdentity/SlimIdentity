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
    /// no sender is required. Not mapped: <c>/forgot-password</c>, <c>/register/verify</c>, <c>/register/password</c>,
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

    // ---------------------------------------------------------------- back-channel logout

    /// <summary>
    /// OpenID Connect Back-Channel Logout for <paramref name="provider"/> (the scheme name of its handler): the provider
    /// posts a signed logout token to <c>{RoutePrefix}/backchannel-logout/{provider}</c> when it signs a user out or
    /// blocks them, and every session of the user linked to its <c>sub</c> ends. Register that URL at the provider
    /// (Keycloak, Okta, Auth0, …). Requires an <see cref="ISlimExternalLoginStore"/>.
    /// </summary>
    /// <example><code>
    /// .AddBackChannelLogout("Keycloak", o =>
    /// {
    ///     o.MetadataAddress = "https://keycloak.example.com/realms/corp/.well-known/openid-configuration";
    ///     o.ClientId = "my-app";
    /// })
    /// </code></example>
    public SlimIdentityBuilder AddBackChannelLogout(string provider, Action<SlimBackChannelLogoutOptions> configure)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(provider);
        ArgumentNullException.ThrowIfNull(configure);
        Services.AddOptions<SlimBackChannelLogoutOptions>(provider)
            .Configure(configure)
            .Validate(o => !string.IsNullOrWhiteSpace(o.ClientId), $"SlimIdentity: back-channel logout for '{provider}' needs ClientId (the expected audience).")
            .Validate(o => o.Configuration is not null || Uri.TryCreate(o.MetadataAddress, UriKind.Absolute, out _),
                $"SlimIdentity: back-channel logout for '{provider}' needs MetadataAddress (or a fixed Configuration).")
            .ValidateOnStart();

        if (Services.FirstOrDefault(d => d.ServiceType == typeof(SlimBackChannelProviders))?.ImplementationInstance is not SlimBackChannelProviders names)
        {
            names = new SlimBackChannelProviders();
            Services.AddSingleton(names);
            Services.TryAddSingleton<SlimBackChannelConfigurations>();
            Services.TryAddScoped<SlimBackChannelLogoutHandler>();
        }
        names.Names.Add(provider);
        return this;
    }

    // ---------------------------------------------------------------- tenants

    /// <summary>
    /// Replaces the trusted origins (<c>TrustedOrigins</c>, <c>Links.BaseUrl</c>) with your per-request decision – e.g.
    /// each tenant trusts its own front end (see <see cref="ISlimOriginPolicy"/>).
    /// </summary>
    public SlimIdentityBuilder AddOriginPolicy<[DynamicallyAccessedMembers(Ctors)] TPolicy>()
        where TPolicy : class, ISlimOriginPolicy
    {
        Services.Replace(ServiceDescriptor.Singleton<ISlimOriginPolicy, TPolicy>());
        return this;
    }

    /// <summary>Builds mail, reset and invitation links per request, e.g. on the tenant's domain (see <see cref="ISlimLinkBuilder"/>).</summary>
    public SlimIdentityBuilder AddLinkBuilder<[DynamicallyAccessedMembers(Ctors)] TBuilder>(ServiceLifetime lifetime = ServiceLifetime.Singleton)
        where TBuilder : class, ISlimLinkBuilder
    {
        Services.Replace(ServiceDescriptor.Describe(typeof(ISlimLinkBuilder), typeof(TBuilder), lifetime));
        return this;
    }

    /// <summary>
    /// Registers the CORS policy <see cref="SlimIdentityDefaults.CorsPolicy"/>, built per request from the
    /// <see cref="ISlimOriginPolicy"/>: credentials allowed, exactly the requesting origin if trusted, headers
    /// <c>Content-Type</c>, <c>Authorization</c> and <c>X-CSRF</c>. One list for CSRF, redirects and CORS instead of two
    /// that drift apart. Activate it with <c>app.UseCors(SlimIdentityDefaults.CorsPolicy)</c> before the endpoints.
    /// </summary>
    public SlimIdentityBuilder AddCorsPolicy()
    {
        Services.AddCors();
        Services.Replace(ServiceDescriptor.Transient<Microsoft.AspNetCore.Cors.Infrastructure.ICorsPolicyProvider, SlimCorsPolicyProvider>());
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

    /// <summary>
    /// Accepts business data at <c>/register</c> (see <see cref="ISlimRegistrationProfile"/>): validates the
    /// <c>profile</c> object and passes the result to <see cref="ISlimUserStore.CreateAsync"/>. One per application – a
    /// second call replaces the first.
    /// </summary>
    public SlimIdentityBuilder AddRegistrationProfile<[DynamicallyAccessedMembers(Ctors)] TProfile>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TProfile : class, ISlimRegistrationProfile
    {
        Services.Replace(ServiceDescriptor.Describe(typeof(ISlimRegistrationProfile), typeof(TProfile), lifetime));
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

    /// <summary>
    /// Shares single-use markers and mail counters between instances (see <see cref="ISlimSharedState"/>). Without it they
    /// are kept in memory per instance – fine for one instance.
    /// </summary>
    public SlimIdentityBuilder AddSharedState<[DynamicallyAccessedMembers(Ctors)] TState>(ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TState : class, ISlimSharedState => Register<ISlimSharedState, TState>(lifetime);

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

    /// <summary>
    /// Binds every session to the tenant it was issued in. The key of the request (e.g. the tenant id resolved from the
    /// host name) is written to the <see cref="SlimClaimTypes.Tenant"/> claim at sign-in and compared on every request –
    /// before any validation interval and also for access tokens with
    /// <see cref="SlimTokenOptions.ValidateSecurityStampOnEachRequest"/> = false. A cookie or token presented to another
    /// tenant is rejected. Links, flow, refresh and other Data Protection tokens get the tenant in their purpose and do not
    /// decrypt in another tenant. Required with a store per tenant (see the multi-tenancy guide); keep the selector
    /// synchronous and in memory.
    /// </summary>
    /// <param name="keySelector">Returns the tenant of a request; <c>null</c> for requests outside any tenant.</param>
    public SlimIdentityBuilder UseTenantKey(Func<HttpContext, string?> keySelector)
    {
        ArgumentNullException.ThrowIfNull(keySelector);
        Services.Replace(ServiceDescriptor.Singleton(new Authentication.SlimTenantBinding(keySelector)));
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
