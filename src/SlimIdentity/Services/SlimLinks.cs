using Microsoft.AspNetCore.Cors.Infrastructure;

namespace SlimIdentity.Services;

/// <summary>Default <see cref="ISlimOriginPolicy"/>: <c>TrustedOrigins</c> plus the origin of <c>Links.BaseUrl</c>.</summary>
internal sealed class SlimTrustedOriginsPolicy(IOptions<SlimIdentityOptions> options) : ISlimOriginPolicy
{
    public bool IsTrusted(HttpContext httpContext, string origin) => options.Value.IsTrustedOrigin(origin);
}

/// <summary>Resolves the host's link builder and origin policy, with the configured defaults as fallback.</summary>
internal sealed class SlimLinks(IOptions<SlimIdentityOptions> options, IHttpContextAccessor httpContextAccessor, IServiceProvider services)
{
    public string Build(SlimLinkKind kind, string token)
    {
        var http = httpContextAccessor.HttpContext;
        if ((http?.RequestServices ?? services).GetService<ISlimLinkBuilder>()?.BuildLink(kind, token, http) is { } link) return link;

        var links = options.Value.Links;
        var template = kind switch
        {
            SlimLinkKind.EmailVerification => links.EmailVerificationTemplate,
            SlimLinkKind.PasswordReset => links.PasswordResetTemplate,
            _ => links.InvitationTemplate,
        };
        return SlimWorkflowTokens.BuildLink(template, token);
    }

    public static bool IsTrustedOrigin(HttpContext http, string origin) =>
        SlimIdentityOptions.NormalizeOrigin(origin) is { } normalized
        && http.RequestServices.GetRequiredService<ISlimOriginPolicy>().IsTrusted(http, normalized);
}

/// <summary>
/// <c>AddCorsPolicy()</c>: the policy <see cref="SlimIdentityDefaults.CorsPolicy"/> is built per request from the
/// <see cref="ISlimOriginPolicy"/> – one source of truth for CSRF, redirects and CORS. Other policies are untouched.
/// </summary>
internal sealed class SlimCorsPolicyProvider(IOptions<CorsOptions> corsOptions) : ICorsPolicyProvider
{
    private readonly DefaultCorsPolicyProvider _inner = new(corsOptions);

    public Task<CorsPolicy?> GetPolicyAsync(HttpContext context, string? policyName)
    {
        if (!string.Equals(policyName, SlimIdentityDefaults.CorsPolicy, StringComparison.Ordinal))
            return _inner.GetPolicyAsync(context, policyName);

        var policy = new CorsPolicyBuilder()
            .AllowCredentials()
            .WithMethods("GET", "POST", "PUT", "PATCH", "DELETE")
            .WithHeaders("Content-Type", "Authorization", SlimIdentityDefaults.CsrfHeaderName)
            .WithExposedHeaders("Retry-After")
            .SetPreflightMaxAge(TimeSpan.FromMinutes(10));
        var origin = context.Request.Headers.Origin.ToString();
        if (origin.Length > 0 && SlimLinks.IsTrustedOrigin(context, origin))
            policy.WithOrigins(origin);   // exactly the requesting origin – never "*" with credentials
        return Task.FromResult<CorsPolicy?>(policy.Build());
    }
}
