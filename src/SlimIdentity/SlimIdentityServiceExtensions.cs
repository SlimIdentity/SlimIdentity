using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SlimIdentity.Authentication;
using SlimIdentity.Contracts;
using SlimIdentity.Endpoints;
using SlimIdentity.Http;
using SlimIdentity.Security;
using SlimIdentity.Services;

namespace SlimIdentity;

/// <summary>Service registration: <c>builder.Services.AddSlimIdentity(…)</c>.</summary>
public static class SlimIdentityServiceExtensions
{
    private static readonly int FrameworkIterationCount = new PasswordHasherOptions().IterationCount;

    /// <summary>Registers SlimIdentity configured purely in code.</summary>
    public static SlimIdentityBuilder AddSlimIdentity(this IServiceCollection services, Action<SlimIdentityOptions>? configure = null) =>
        services.AddSlimIdentity(configuration: null, configure);

    /// <summary>
    /// Registers SlimIdentity. <paramref name="configuration"/> (e.g. <c>GetSection("SlimIdentity")</c>) is bound first,
    /// <paramref name="configure"/> is applied afterwards as override. All options are validated at startup.
    /// </summary>
    public static SlimIdentityBuilder AddSlimIdentity(
        this IServiceCollection services,
        IConfiguration? configuration,
        Action<SlimIdentityOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        // ---------------------------------------------------------------- options (explicit & validated)
        var optionsBuilder = services.AddOptions<SlimIdentityOptions>();
        if (configuration is not null) optionsBuilder.Bind(configuration);
        if (configure is not null) optionsBuilder.Configure(configure);
        optionsBuilder.ValidateOnStart();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<SlimIdentityOptions>, SlimIdentityOptionsValidator>());

        // ---------------------------------------------------------------- framework-native building blocks
        services.TryAddSingleton(TimeProvider.System);
        services.AddHttpContextAccessor();
        // AOT: request/response DTOs via source-generated metadata (in front of the host's own resolvers)
        services.ConfigureHttpJsonOptions(o => o.SerializerOptions.TypeInfoResolverChain.Insert(0, SlimJsonContext.Default));
        services.AddDataProtection();
        services.TryAddScoped<IPasswordHasher<SlimUser>, PasswordHasher<SlimUser>>();
        // OWASP: 210,000 iterations for PBKDF2-HMAC-SHA512 (Identity V3) instead of the framework's 100,000. PostConfigure
        // and only while untouched: a host value wins regardless of the order of the calls. Older hashes are upgraded at
        // the next sign-in (SuccessRehashNeeded → rehash path).
        services.PostConfigure<PasswordHasherOptions>(o =>
        {
            if (o.IterationCount == FrameworkIterationCount) o.IterationCount = SlimIdentityDefaults.PasswordHashIterations;
        });

        // ---------------------------------------------------------------- internal services
        services.TryAddSingleton<SlimWorkflowTokens>();
        services.TryAddSingleton<SlimJwtTokenFactory>();
        services.TryAddScoped<SlimPasswordPolicy>();   // scoped: password rules may be scoped
        services.TryAddScoped<SlimCredentialService>();
        services.TryAddScoped<SlimAuthManager>();
        services.TryAddScoped<ISlimAuthManager>(sp => sp.GetRequiredService<SlimAuthManager>());
        services.TryAddScoped<SlimLoginHandlers>();
        services.TryAddScoped<SlimAccountHandlers>();

        // ---------------------------------------------------------------- mail dispatch (enumeration-safe timing)
        services.TryAddSingleton<SlimEmailQueue>();
        services.TryAddSingleton<SlimMailThrottle>();
        services.TryAddSingleton<SlimAttemptGate>();
        services.TryAddSingleton<SlimHookRunner>();
        services.TryAddSingleton<ISlimOriginPolicy, SlimTrustedOriginsPolicy>();
        services.TryAddSingleton<SlimLinks>();
        services.TryAddSingleton<Http.SlimDeploymentDiagnostics>();
        services.TryAddScoped<SlimEmailDispatcher>();
        services.AddHostedService<SlimEmailBackgroundService>();

        // ---------------------------------------------------------------- observability (System.Diagnostics.Metrics)
        services.AddMetrics();
        services.TryAddSingleton<SlimMetrics>();

        // ---------------------------------------------------------------- layer 1: IP rate limiting
        services.AddRateLimiter(o =>
        {
            o.AddPolicy<string, SlimBruteForceRateLimiterPolicy>(SlimIdentityDefaults.BruteForcePolicy);
            o.AddPolicy<string, SlimRefreshRateLimiterPolicy>(SlimIdentityDefaults.RefreshPolicy);
        });

        // ---------------------------------------------------------------- authentication
        services.AddOptions<AuthenticationOptions>().Configure<IOptions<SlimIdentityOptions>>((auth, slim) =>
        {
            if (!slim.Value.Endpoints.ConfigureDefaultAuthenticationScheme) return;
            auth.DefaultScheme = SlimIdentityDefaults.AuthenticationScheme;
            auth.DefaultChallengeScheme = SlimIdentityDefaults.AuthenticationScheme;
            auth.DefaultForbidScheme = SlimIdentityDefaults.AuthenticationScheme;
        });

        var authentication = services.AddAuthentication()
            .AddPolicyScheme(SlimIdentityDefaults.AuthenticationScheme, "SlimIdentity", o =>
            {
                o.ForwardDefaultSelector = context =>
                {
                    var authorization = context.Request.Headers.Authorization.ToString();
                    if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                        return SlimIdentityDefaults.BearerScheme;
                    if (context.Request.Headers.ContainsKey(SlimIdentityDefaults.ApiKeyHeaderName)
                        && context.RequestServices.GetService<SlimApiKeyMarker>() is not null)
                        return SlimIdentityDefaults.ApiKeyScheme;
                    return SlimIdentityDefaults.CookieScheme;
                };
            })
            .AddPolicyScheme(SlimIdentityDefaults.UserScheme, "SlimIdentity (user)", o =>
            {
                o.ForwardDefaultSelector = context =>
                    context.Request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                        ? SlimIdentityDefaults.BearerScheme
                        : SlimIdentityDefaults.CookieScheme;
            })
            .AddCookie(SlimIdentityDefaults.CookieScheme)
            .AddCookie(SlimIdentityDefaults.ExternalScheme)
            .AddJwtBearer(SlimIdentityDefaults.BearerScheme);

        services.AddOptions<CookieAuthenticationOptions>(SlimIdentityDefaults.CookieScheme)
            .Configure<IOptions<SlimIdentityOptions>>((cookie, slim) =>
            {
                var c = slim.Value.Cookies;
                cookie.Cookie.Name = c.CookieName;
                cookie.Cookie.HttpOnly = true;                              // enforced
                cookie.Cookie.SecurePolicy = CookieSecurePolicy.Always;     // enforced
                cookie.Cookie.SameSite = c.SameSite;
                cookie.Cookie.Domain = c.Domain;
                cookie.Cookie.IsEssential = true;
                cookie.ExpireTimeSpan = c.ExpireTimeSpan;
                cookie.SlidingExpiration = c.SlidingExpiration;
                cookie.Events.OnValidatePrincipal = SlimSecurityStampValidator.ValidateCookieAsync;
                // JSON API: never redirect to a login page
                cookie.Events.OnRedirectToLogin = ctx => { ctx.Response.StatusCode = StatusCodes.Status401Unauthorized; return Task.CompletedTask; };
                cookie.Events.OnRedirectToAccessDenied = ctx => { ctx.Response.StatusCode = StatusCodes.Status403Forbidden; return Task.CompletedTask; };
            });

        services.AddOptions<CookieAuthenticationOptions>(SlimIdentityDefaults.ExternalScheme)
            .Configure<IOptions<SlimIdentityOptions>>((cookie, slim) =>
            {
                cookie.Cookie.Name = slim.Value.Cookies.CookieName + ".External";
                cookie.Cookie.HttpOnly = true;
                cookie.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                cookie.Cookie.SameSite = SameSiteMode.Lax; // must survive the top-level redirect back from the IdP
                cookie.Cookie.IsEssential = true;
                cookie.ExpireTimeSpan = TimeSpan.FromMinutes(10);
                cookie.SlidingExpiration = false;
                cookie.Events.OnRedirectToLogin = ctx => { ctx.Response.StatusCode = StatusCodes.Status401Unauthorized; return Task.CompletedTask; };
            });

        services.AddOptions<JwtBearerOptions>(SlimIdentityDefaults.BearerScheme)
            .Configure<IOptions<SlimIdentityOptions>>((bearer, slim) =>
            {
                var t = slim.Value.Tokens;
                bearer.MapInboundClaims = false; // keep short claim names (sub, email, role)
                bearer.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = t.Issuer,
                    ValidateAudience = true,
                    ValidAudience = t.Audience,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    ValidateIssuerSigningKey = true,
                    // the current secret signs and validates; previous ones only validate (rotation without rejected tokens)
                    IssuerSigningKeys = string.IsNullOrEmpty(t.JwtSecret)
                        ? []
                        : [SlimJwtTokenFactory.CreateSigningKey(t.JwtSecret), .. t.PreviousJwtSecrets.Select(SlimJwtTokenFactory.CreateSigningKey)],
                    ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
                    ClockSkew = t.ClockSkew,
                    NameClaimType = SlimClaimTypes.Email,
                    RoleClaimType = SlimClaimTypes.Role,
                    AuthenticationType = SlimIdentityDefaults.BearerScheme,
                };
                bearer.Events = new JwtBearerEvents { OnTokenValidated = SlimSecurityStampValidator.ValidateBearerAsync };
            });

        // ---------------------------------------------------------------- authorization: sudo policy
        services.AddAuthorizationBuilder()
            .AddPolicy(SlimIdentityDefaults.SudoPolicy, policy => policy
                .RequireAuthenticatedUser()
                .RequireAssertion(ctx => ctx.User.IsInSudoMode(
                    (ctx.Resource as HttpContext)?.RequestServices.GetService<TimeProvider>())));

        return new SlimIdentityBuilder(services, authentication);
    }
}
