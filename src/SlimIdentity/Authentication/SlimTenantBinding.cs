namespace SlimIdentity.Authentication;

/// <summary>Tenant key registered via <c>SlimIdentityBuilder.UseTenantKey</c>.</summary>
internal sealed class SlimTenantBinding(Func<HttpContext, string?> keySelector)
{
    public string? KeyOf(HttpContext http) => keySelector(http) is { Length: > 0 } key ? key : null;

    /// <summary>True if the session was issued in the tenant of <paramref name="http"/> (no binding registered: always).</summary>
    public static bool Matches(ClaimsPrincipal? principal, HttpContext http) =>
        http.RequestServices.GetService<SlimTenantBinding>() is not { } binding
        || string.Equals(principal?.FindFirst(SlimClaimTypes.Tenant)?.Value, binding.KeyOf(http), StringComparison.Ordinal);
}
