using SlimIdentity.Abstractions;

namespace SlimIdentity.Security;

/// <summary>Claim helpers for host code.</summary>
public static class SlimClaims
{
    /// <summary>Creates a <c>sudo_until</c> claim for <see cref="ISlimAuthManager.ElevateSessionAsync"/>.</summary>
    public static Claim SudoFor(TimeSpan duration, TimeProvider? timeProvider = null)
    {
        var until = (timeProvider ?? TimeProvider.System).GetUtcNow().Add(duration).ToUnixTimeSeconds();
        return new Claim(SlimClaimTypes.SudoUntil, until.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64);
    }

    /// <summary>
    /// <c>{"sub":"&lt;impersonator id&gt;","slim_stamp":"&lt;impersonator stamp&gt;"}</c> – the stamp binds the
    /// impersonation session to the impersonator's current security state.
    /// </summary>
    internal static Dictionary<string, string> CreateActor(string impersonatorUserId, string impersonatorStamp, string? impersonatorAmr)
    {
        var actor = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [SlimClaimTypes.UserId] = impersonatorUserId,
            [SlimClaimTypes.SecurityStamp] = impersonatorStamp,
        };
        if (!string.IsNullOrEmpty(impersonatorAmr)) actor[SlimClaimTypes.AuthenticationMethod] = impersonatorAmr;
        return actor;
    }

    internal static string SerializeActor(Dictionary<string, string> actor) => JsonSerializer.Serialize(actor);

    /// <summary>Parses the <c>act</c> claim. Returns null unless it is an object with string <c>sub</c>.</summary>
    internal static SlimActor? ParseActorClaim(string? actorJson)
    {
        if (string.IsNullOrEmpty(actorJson)) return null;
        try
        {
            using var doc = JsonDocument.Parse(actorJson);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty(SlimClaimTypes.UserId, out var sub)
                || sub.ValueKind != JsonValueKind.String
                || string.IsNullOrEmpty(sub.GetString()))
                return null;

            return new SlimActor(sub.GetString()!, GetString(root, SlimClaimTypes.SecurityStamp), GetString(root, SlimClaimTypes.AuthenticationMethod));
        }
        catch (JsonException)
        {
            return null;
        }
    }

    internal static string? ParseActor(string? actorJson) => ParseActorClaim(actorJson)?.UserId;

    private static string? GetString(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

/// <summary>Impersonator carried in the <c>act</c> claim.</summary>
internal sealed record SlimActor(string UserId, string? SecurityStamp, string? AuthenticationMethod)
{
    public Dictionary<string, string> ToDictionary() =>
        SlimClaims.CreateActor(UserId, SecurityStamp ?? string.Empty, AuthenticationMethod);
}

/// <summary>Convenience accessors on <see cref="ClaimsPrincipal"/>.</summary>
public static class SlimClaimsPrincipalExtensions
{
    public static string? GetSlimUserId(this ClaimsPrincipal principal) =>
        principal.FindFirst(SlimClaimTypes.UserId)?.Value
        ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    public static string? GetSlimEmail(this ClaimsPrincipal principal) =>
        principal.FindFirst(SlimClaimTypes.Email)?.Value
        ?? principal.FindFirst(ClaimTypes.Email)?.Value;

    /// <summary>Id of the admin that impersonates the current user (<c>act</c> claim), or null.</summary>
    public static string? GetImpersonatorId(this ClaimsPrincipal principal) =>
        SlimClaims.ParseActor(principal.FindFirst(SlimClaimTypes.Actor)?.Value);

    public static bool IsImpersonating(this ClaimsPrincipal principal) => principal.GetImpersonatorId() is not null;

    public static DateTimeOffset? GetSudoUntil(this ClaimsPrincipal principal) =>
        long.TryParse(principal.FindFirst(SlimClaimTypes.SudoUntil)?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var unix)
            ? DateTimeOffset.FromUnixTimeSeconds(unix)
            : null;

    public static bool IsInSudoMode(this ClaimsPrincipal principal, TimeProvider? timeProvider = null) =>
        principal.GetSudoUntil() is { } until && until > (timeProvider ?? TimeProvider.System).GetUtcNow();

    /// <summary>True if the current principal was issued by the SlimIdentity cookie handler.</summary>
    public static bool IsSlimCookieSession(this ClaimsPrincipal principal) =>
        string.Equals(principal.Identity?.AuthenticationType, SlimIdentityDefaults.CookieScheme, StringComparison.Ordinal);
}
