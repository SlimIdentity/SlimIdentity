using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using SlimIdentity.Contracts;

namespace SlimIdentity.Http;

/// <summary>
/// CSRF protection for cookie-based, state-changing requests: requires a custom header
/// (forces a CORS preflight for cross-origin callers) and checks the <c>Origin</c> header.
/// </summary>
internal sealed class SlimCsrfEndpointFilter(IOptions<SlimIdentityOptions> options, ILogger<SlimCsrfEndpointFilter> logger) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var o = options.Value;
        var request = context.HttpContext.Request;

        if (!o.Csrf.Enabled
            || HttpMethods.IsGet(request.Method)
            || HttpMethods.IsHead(request.Method)
            || HttpMethods.IsOptions(request.Method)
            || !IsCookieContext(request, o))
        {
            return await next(context);
        }

        if (!request.Headers.ContainsKey(o.Csrf.HeaderName))
            return SlimResults.Status("csrf_validation_failed", $"Missing anti-forgery header '{o.Csrf.HeaderName}'.", StatusCodes.Status403Forbidden);

        var origin = request.Headers.Origin.ToString();
        if (!string.IsNullOrEmpty(origin) && !IsAllowedOrigin(origin, request, o))
        {
            var self = SelfOrigin(request);
            if (Uri.TryCreate(origin, UriKind.Absolute, out var o1) && Uri.TryCreate(self, UriKind.Absolute, out var o2)
                && string.Equals(o1.Host, o2.Host, StringComparison.OrdinalIgnoreCase) && o1.Scheme != o2.Scheme)
            {
                // Same host, different scheme: almost always a TLS-terminating proxy without UseForwardedHeaders().
                logger.LogWarning("SlimIdentity: CSRF origin check failed – request origin {Origin} vs. API origin {Self}. " +
                    "Behind a TLS-terminating reverse proxy call app.UseForwardedHeaders() (X-Forwarded-Proto) with KnownProxies/KnownIPNetworks.",
                    origin, self);
            }
            else
            {
                logger.LogInformation("SlimIdentity: CSRF origin {Origin} rejected (API origin {Self}, not in Csrf.AllowedOrigins).", origin, self);
            }
            return SlimResults.Status("csrf_validation_failed", "Origin not allowed.", StatusCodes.Status403Forbidden);
        }

        return await next(context);
    }

    private static bool IsCookieContext(HttpRequest request, SlimIdentityOptions o)
    {
        if (request.Cookies.ContainsKey(o.Cookies.CookieName)) return true;
        if (request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return false;
        if (request.Headers.ContainsKey(SlimIdentityDefaults.ApiKeyHeaderName)) return false;

        var query = request.Query["useCookies"].ToString();
        if (bool.TryParse(query, out var useCookies)) return useCookies;
        return o.Endpoints.DefaultUseCookies;
    }

    private static bool IsAllowedOrigin(string origin, HttpRequest request, SlimIdentityOptions o)
    {
        if (string.Equals(origin.TrimEnd('/'), SelfOrigin(request), StringComparison.OrdinalIgnoreCase)) return true;
        return o.Csrf.AllowedOrigins.Any(a => string.Equals(a.TrimEnd('/'), origin.TrimEnd('/'), StringComparison.OrdinalIgnoreCase));
    }

    private static string SelfOrigin(HttpRequest request) => $"{request.Scheme}://{request.Host.Value}";
}

/// <summary>Layer 1 brute-force protection: fixed window per client IP, 429 + Retry-After.</summary>
internal sealed class SlimBruteForceRateLimiterPolicy(IOptions<SlimIdentityOptions> options)
    : SlimIpRateLimiterPolicy(() => (options.Value.RateLimit.PermitLimit, options.Value.RateLimit.Window));

/// <summary>Load guard for <c>/refresh</c>: own, more generous bucket per client IP.</summary>
internal sealed class SlimRefreshRateLimiterPolicy(IOptions<SlimIdentityOptions> options)
    : SlimIpRateLimiterPolicy(() => (options.Value.RateLimit.RefreshPermitLimit, options.Value.RateLimit.RefreshWindow));

internal abstract class SlimIpRateLimiterPolicy(Func<(int PermitLimit, TimeSpan Window)> limits) : IRateLimiterPolicy<string>
{
    public Func<OnRejectedContext, CancellationToken, ValueTask>? OnRejected { get; } = static (context, _) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
            context.HttpContext.Response.Headers.RetryAfter = ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
        return ValueTask.CompletedTask;
    };

    public RateLimitPartition<string> GetPartition(HttpContext httpContext)
    {
        var (permitLimit, window) = limits();
        var key = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitLimit,
            Window = window,
            QueueLimit = 0,
            AutoReplenishment = true,
        });
    }
}

internal static class SlimResults
{
    public static IResult Status(string status, string? message = null, int statusCode = StatusCodes.Status200OK) =>
        Results.Json(new SlimStatusResponse(status, message), statusCode: statusCode);

    public static IResult InvalidCredentials() =>
        Results.Json(new SlimLoginChallengeResponse { Status = "invalid_credentials", Message = "Invalid e-mail or password." },
            statusCode: StatusCodes.Status401Unauthorized);

    public static IResult Locked(HttpContext http, DateTimeOffset lockoutEnd, DateTimeOffset now)
    {
        var seconds = (int)Math.Max(1, Math.Ceiling((lockoutEnd - now).TotalSeconds));
        http.Response.Headers.RetryAfter = seconds.ToString(CultureInfo.InvariantCulture);
        return Results.Json(new SlimLockedResponse("locked_out", lockoutEnd), statusCode: StatusCodes.Status423Locked);
    }

    public static IResult InvalidToken(int statusCode = StatusCodes.Status400BadRequest) =>
        Status("invalid_token", "The token is invalid or has expired.", statusCode);

    public static IResult BadRequest(string status, string? message = null) =>
        Status(status, message, StatusCodes.Status400BadRequest);

    public static IResult Validation(IDictionary<string, string[]> errors) => Results.ValidationProblem(errors);
}
