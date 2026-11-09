using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using SlimIdentity.Contracts;

namespace SlimIdentity.Http;

/// <summary>
/// CSRF protection for cookie-based, state-changing requests: requires a custom header
/// (forces a CORS preflight for cross-origin callers) and checks the <c>Origin</c> header.
/// </summary>
/// <summary>
/// Endpoint metadata: authenticated by something else than a cookie (a signed token in the body), so a cookie that
/// happens to be sent along cannot be abused – no CSRF check. Used by the back-channel logout of identity providers.
/// </summary>
internal sealed class SlimNoCookieAuthentication;

internal sealed class SlimCsrfEndpointFilter(IOptions<SlimIdentityOptions> options, ILogger<SlimCsrfEndpointFilter> logger) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var o = options.Value;
        var request = context.HttpContext.Request;

        if (HttpMethods.IsGet(request.Method)
            || HttpMethods.IsHead(request.Method)
            || HttpMethods.IsOptions(request.Method)
            || context.HttpContext.GetEndpoint()?.Metadata.GetMetadata<SlimNoCookieAuthentication>() is not null
            || !IsCookieContext(request, o))
        {
            return await next(context);
        }

        return Validate(request, o, logger) ?? await next(context);
    }

    /// <summary>
    /// Header and <c>Origin</c> check. Also called by handlers that learn about cookie mode only from a signed token in
    /// the body (e.g. <c>/login/2fa</c>), which the filter cannot see. Returns <c>null</c> if the request passes.
    /// </summary>
    internal static IResult? Validate(HttpRequest request, SlimIdentityOptions o, ILogger logger)
    {
        if (!request.Headers.ContainsKey(SlimIdentityDefaults.CsrfHeaderName))
            return SlimResults.Status("csrf_validation_failed", $"Missing anti-forgery header '{SlimIdentityDefaults.CsrfHeaderName}'.", StatusCodes.Status403Forbidden);

        var origin = request.Headers.Origin.ToString();
        if (!string.IsNullOrEmpty(origin) && !IsAllowedOrigin(origin, request, o))
        {
            var self = SelfOrigin(request);
            if (Uri.TryCreate(origin, UriKind.Absolute, out var o1) && Uri.TryCreate(self, UriKind.Absolute, out var o2)
                && string.Equals(o1.Host, o2.Host, StringComparison.OrdinalIgnoreCase) && o1.Scheme != o2.Scheme)
            {
                // Same host, different scheme: almost always a TLS-terminating proxy without UseForwardedHeaders().
                Log.CsrfSchemeMismatch(logger, origin, self);
            }
            else
            {
                Log.CsrfOriginRejected(logger, origin, self);
            }
            return SlimResults.Status("csrf_validation_failed", "Origin not allowed.", StatusCodes.Status403Forbidden);
        }

        return null;
    }

    private static bool IsCookieContext(HttpRequest request, SlimIdentityOptions o)
    {
        if (request.Cookies.ContainsKey(o.Cookies.CookieName)) return true;
        if (request.Headers.Authorization.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return false;
        if (request.Headers.ContainsKey(SlimIdentityDefaults.ApiKeyHeaderName)) return false;

        var query = request.Query["useCookies"].ToString();
        if (bool.TryParse(query, out var useCookies)) return useCookies;
        return o.EffectiveDefaultUseCookies;
    }

    private static bool IsAllowedOrigin(string origin, HttpRequest request, SlimIdentityOptions o) =>
        string.Equals(origin.TrimEnd('/'), SelfOrigin(request), StringComparison.OrdinalIgnoreCase)
        || Services.SlimLinks.IsTrustedOrigin(request.HttpContext, origin);   // TrustedOrigins, or the host's per-request policy

    private static string SelfOrigin(HttpRequest request) => $"{request.Scheme}://{request.Host.Value}";
}

/// <summary>Layer 1 brute-force protection: fixed window per client, 429 + Retry-After.</summary>
internal sealed class SlimBruteForceRateLimiterPolicy(IOptions<SlimIdentityOptions> options, IServiceProvider services)
    : SlimClientRateLimiterPolicy(options, services, o => (o.PermitLimit, o.Window));

/// <summary>Load guard for <c>/refresh</c>: own, more generous bucket per client.</summary>
internal sealed class SlimRefreshRateLimiterPolicy(IOptions<SlimIdentityOptions> options, IServiceProvider services)
    : SlimClientRateLimiterPolicy(options, services, o => (o.RefreshPermitLimit, o.Window));

/// <summary>Custom partition key registered via <c>SlimIdentityBuilder.UseRateLimitPartitionKey</c>.</summary>
internal sealed class SlimRateLimitPartitioner(Func<HttpContext, string?> keySelector)
{
    public string? GetKey(HttpContext context) => keySelector(context);
}

internal abstract class SlimClientRateLimiterPolicy(
    IOptions<SlimIdentityOptions> options,
    IServiceProvider services,
    Func<SlimRateLimitOptions, (int PermitLimit, TimeSpan Window)> limits) : IRateLimiterPolicy<string>
{
    private readonly SlimRateLimitPartitioner? _custom = services.GetService<SlimRateLimitPartitioner>();
    private readonly SlimDeploymentDiagnostics? _diagnostics = services.GetService<SlimDeploymentDiagnostics>();

    /// <summary>
    /// Client key: IPv4 address, or the IPv6 network prefix (a client usually controls a whole /64 and could rotate
    /// addresses within it). Requests without a remote address (in-process test servers, Unix sockets) share one bucket.
    /// </summary>
    internal static string ClientKey(System.Net.IPAddress? address, int ipv6PrefixLength)
    {
        if (address is null) return "unknown";
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6 || ipv6PrefixLength >= 128)
            return address.ToString();

        Span<byte> bytes = stackalloc byte[16];
        address.TryWriteBytes(bytes, out _);
        for (var bit = ipv6PrefixLength; bit < 128; bit++)
            bytes[bit / 8] &= (byte)~(0x80 >> (bit % 8));
        return $"{new System.Net.IPAddress(bytes)}/{ipv6PrefixLength}";
    }

    public Func<OnRejectedContext, CancellationToken, ValueTask>? OnRejected { get; } = static (context, _) =>
    {
        var policy = context.HttpContext.GetEndpoint()?.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName ?? "unknown";
        context.HttpContext.RequestServices.GetService<SlimMetrics>()?.RateLimited(policy);
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
            context.HttpContext.Response.Headers.RetryAfter = ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
        return ValueTask.CompletedTask;
    };

    public RateLimitPartition<string> GetPartition(HttpContext httpContext)
    {
        var o = options.Value.RateLimit;
        var (permitLimit, window) = limits(o);
        var custom = _custom?.GetKey(httpContext);
        if (custom is null) _diagnostics?.InspectRequest(httpContext);   // the IP is the key – is it the client's?
        var key = custom ?? ClientKey(httpContext.Connection.RemoteIpAddress, o.IPv6PrefixLength);
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
        Results.Json(new SlimStatusResponse(status, message), SlimJsonContext.Default.SlimStatusResponse, statusCode: statusCode);

    public static IResult InvalidCredentials() =>
        Results.Json(new SlimLoginChallengeResponse { Status = "invalid_credentials", Message = "Invalid e-mail or password." },
            SlimJsonContext.Default.SlimLoginChallengeResponse, statusCode: StatusCodes.Status401Unauthorized);

    public static IResult Challenge(SlimLoginChallengeResponse challenge) =>
        Results.Json(challenge, SlimJsonContext.Default.SlimLoginChallengeResponse, statusCode: StatusCodes.Status401Unauthorized);

    public static IResult Locked(HttpContext http, DateTimeOffset lockoutEnd, DateTimeOffset now)
    {
        var seconds = (int)Math.Max(1, Math.Ceiling((lockoutEnd - now).TotalSeconds));
        http.Response.Headers.RetryAfter = seconds.ToString(CultureInfo.InvariantCulture);
        return Results.Json(new SlimLockedResponse("locked_out", lockoutEnd), SlimJsonContext.Default.SlimLockedResponse,
            statusCode: StatusCodes.Status423Locked);
    }

    public static IResult InvalidToken(int statusCode = StatusCodes.Status400BadRequest) =>
        Status("invalid_token", "The token is invalid or has expired.", statusCode);

    public static IResult BadRequest(string status, string? message = null) =>
        Status(status, message, StatusCodes.Status400BadRequest);

    public static IResult Validation(IDictionary<string, string[]> errors) => Results.ValidationProblem(errors);
}
