using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;
using SlimIdentity.Contracts;

namespace SlimIdentity.Http;

/// <summary>
/// Endpoint metadata: authenticated by something else than a cookie (a signed token in the body), so a cookie that
/// happens to be sent along cannot be abused – no CSRF check. Used by the back-channel logout of identity providers.
/// </summary>
internal sealed class SlimNoCookieAuthentication;

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
            return SlimResults.Status(SlimErrorCodes.CsrfValidationFailed, $"Missing anti-forgery header '{SlimIdentityDefaults.CsrfHeaderName}'.", StatusCodes.Status403Forbidden);

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
            return SlimResults.Status(SlimErrorCodes.CsrfValidationFailed, "Origin not allowed.", StatusCodes.Status403Forbidden);
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

/// <summary>
/// Fails closed when an endpoint protected by a SlimIdentity rate-limit policy is reached without the rate-limiting
/// middleware: without <c>app.UseRateLimiter()</c> the brute-force limit would otherwise be off without any sign.
/// </summary>
internal static class SlimRateLimitGuard
{
    internal static readonly object Applied = new();

    public static ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var metadata = http.GetEndpoint()?.Metadata;
        if (metadata?.GetMetadata<DisableRateLimitingAttribute>() is null
            && metadata?.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName is SlimIdentityDefaults.BruteForcePolicy or SlimIdentityDefaults.RefreshPolicy
            && !http.Items.ContainsKey(Applied))
            throw new InvalidOperationException(
                "SlimIdentity: the endpoint requires rate limiting, but the rate-limiting middleware did not run – the brute-force " +
                "protection would be off. Call app.UseRateLimiter() after app.UseRouting() / before the SlimIdentity endpoints are reached.");
        return next(context);
    }
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
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
            context.HttpContext.Response.Headers.RetryAfter = ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
        return new ValueTask(SlimResults.WriteProblemAsync(context.HttpContext.Response, StatusCodes.Status429TooManyRequests,
            SlimErrorCodes.RateLimited, "Too many requests."));
    };

    public RateLimitPartition<string> GetPartition(HttpContext httpContext)
    {
        httpContext.Items[SlimRateLimitGuard.Applied] = true;   // proof that app.UseRateLimiter() runs, see SlimRateLimitGuard
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
    public const string ProblemContentType = "application/problem+json";

    /// <summary>A status answer, or – from 400 on – a problem with <paramref name="status"/> as <c>code</c>.</summary>
    public static IResult Status(string status, string? message = null, int statusCode = StatusCodes.Status200OK) =>
        statusCode >= StatusCodes.Status400BadRequest
            ? Problem(statusCode, status, message)
            : Results.Json(new SlimStatusResponse(status, message), SlimJsonContext.Default.SlimStatusResponse, statusCode: statusCode);

    public static SlimProblemResponse CreateProblem(int statusCode, string code, string? detail = null) => new()
    {
        Status = statusCode,
        Code = code,
        Title = ReasonPhrases.GetReasonPhrase(statusCode),
        Detail = detail,
    };

    public static IResult Problem(int statusCode, string code, string? detail = null) =>
        Problem(CreateProblem(statusCode, code, detail));

    public static IResult Problem(SlimProblemResponse problem) =>
        Results.Json(problem, SlimJsonContext.Default.SlimProblemResponse, ProblemContentType, problem.Status);

    /// <summary>Writes a problem directly, for answers outside an endpoint (authentication events, rate limiter).</summary>
    public static Task WriteProblemAsync(HttpResponse response, int statusCode, string code, string? detail = null)
    {
        response.StatusCode = statusCode;
        response.ContentType = ProblemContentType;
        return System.Text.Json.JsonSerializer.SerializeAsync(response.Body, CreateProblem(statusCode, code, detail),
            SlimJsonContext.Default.SlimProblemResponse, response.HttpContext.RequestAborted);
    }

    public static IResult InvalidCredentials() =>
        Problem(StatusCodes.Status401Unauthorized, SlimErrorCodes.InvalidCredentials, "Invalid e-mail or password.");

    public static IResult Unauthenticated() =>
        Problem(StatusCodes.Status401Unauthorized, SlimErrorCodes.Unauthenticated, "Authentication is required.");

    public static IResult ActionRequired(SlimActionRequiredResponse response) =>
        Results.Json(response, SlimJsonContext.Default.SlimActionRequiredResponse);

    public static IResult Locked(HttpContext http, DateTimeOffset lockoutEnd, DateTimeOffset now)
    {
        var seconds = (int)Math.Max(1, Math.Ceiling((lockoutEnd - now).TotalSeconds));
        http.Response.Headers.RetryAfter = seconds.ToString(CultureInfo.InvariantCulture);
        var problem = CreateProblem(StatusCodes.Status423Locked, SlimErrorCodes.LockedOut, "The account is locked.");
        return Problem(new SlimProblemResponse
        {
            Status = problem.Status, Code = problem.Code, Title = problem.Title, Detail = problem.Detail, LockoutEndUtc = lockoutEnd,
        });
    }

    public static IResult InvalidToken(int statusCode = StatusCodes.Status400BadRequest) =>
        Status(SlimErrorCodes.InvalidToken, "The token is invalid or has expired.", statusCode);

    /// <summary>A security change of the signed-in account failed: the account changed in the meantime.</summary>
    public static IResult ConcurrentChange() =>
        Status(SlimErrorCodes.ConcurrentChange, "The account was changed at the same time; nothing was saved. Reload and try again.", StatusCodes.Status409Conflict);

    /// <summary>
    /// Answer after a change that re-issued the caller's session: the new session, or – if it could not be renewed (refresh
    /// chain at its end) – <c>401</c> with the reason; the change itself is saved, the client signs in again.
    /// </summary>
    public static IResult ReissuedSession(SlimAuthResult session) => session.Succeeded
        ? Results.Ok(session.ToResponse())
        : Status(session.Error ?? SlimErrorCodes.SessionExpired, "The change was saved, but this session could not be renewed; sign in again.", StatusCodes.Status401Unauthorized);

    public static IResult BadRequest(string status, string? message = null) =>
        Status(status, message, StatusCodes.Status400BadRequest);

    /// <summary>400 <c>validation_failed</c> with the messages per field in <c>errors</c>.</summary>
    public static IResult Validation(IDictionary<string, string[]> errors)
    {
        var problem = CreateProblem(StatusCodes.Status400BadRequest, SlimErrorCodes.ValidationFailed, "One or more fields are invalid.");
        return Problem(new SlimProblemResponse
        {
            Status = problem.Status, Code = problem.Code, Title = problem.Title, Detail = problem.Detail, Errors = errors,
        });
    }
}
