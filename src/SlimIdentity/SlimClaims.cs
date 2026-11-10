
namespace SlimIdentity;

/// <summary>Claim helpers for host code.</summary>
public static class SlimClaims
{
    /// <summary>
    /// Creates a <c>sudo_until</c> claim on <paramref name="timeProvider"/> – the clock SlimIdentity checks it with
    /// (inject <see cref="TimeProvider"/>). Usually <see cref="ISlimAuthManager.ElevateToSudoAsync"/> does this for you.
    /// </summary>
    public static Claim SudoFor(TimeSpan duration, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);
        var until = timeProvider.GetUtcNow().Add(duration).ToUnixTimeSeconds();
        return new Claim(SlimClaimTypes.SudoUntil, until.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64);
    }

    /// <summary>
    /// <c>{"sub":"&lt;impersonator id&gt;","slim_stamp":"&lt;impersonator stamp&gt;","sid":"&lt;impersonator session&gt;"}</c> –
    /// the stamp binds the impersonation session to the impersonator's current security state, the session id (with
    /// <see cref="ISlimSessionStore"/>) to the administrator's session it was started from.
    /// </summary>
    internal static Dictionary<string, string> CreateActor(string impersonatorUserId, string impersonatorStamp, string? impersonatorAmr,
        DateTimeOffset? impersonatorAuthTime = null, string? impersonatorSessionId = null)
    {
        var actor = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [SlimClaimTypes.UserId] = impersonatorUserId,
            [SlimClaimTypes.SecurityStamp] = impersonatorStamp,
        };
        if (!string.IsNullOrEmpty(impersonatorAmr)) actor[SlimClaimTypes.AuthenticationMethod] = impersonatorAmr;
        // the administrator's own sign-in: restored when the impersonation ends (no fresh session chain)
        if (impersonatorAuthTime is { } t) actor[SlimClaimTypes.AuthTime] = t.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        if (!string.IsNullOrEmpty(impersonatorSessionId)) actor[SlimClaimTypes.SessionId] = impersonatorSessionId;
        return actor;
    }

    internal static string SerializeActor(Dictionary<string, string> actor) =>
        JsonSerializer.Serialize(actor, Contracts.SlimJsonContext.Default.DictionaryStringString);

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

            var authTime = long.TryParse(GetString(root, SlimClaimTypes.AuthTime), NumberStyles.Integer, CultureInfo.InvariantCulture, out var unix)
                ? DateTimeOffset.FromUnixTimeSeconds(unix) : (DateTimeOffset?)null;
            return new SlimActor(sub.GetString()!, GetString(root, SlimClaimTypes.SecurityStamp), GetString(root, SlimClaimTypes.AuthenticationMethod), authTime,
                GetString(root, SlimClaimTypes.SessionId));
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or InvalidOperationException)
        {
            // malformed JSON, invalid UTF-16 (lone surrogates) or an unreadable string escape – never a valid actor
            return null;
        }
    }

    internal static string? ParseActor(string? actorJson) => ParseActorClaim(actorJson)?.UserId;

    private static string? GetString(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

/// <summary>Impersonator carried in the <c>act</c> claim.</summary>
internal sealed record SlimActor(string UserId, string? SecurityStamp, string? AuthenticationMethod, DateTimeOffset? AuthTime = null,
    string? SessionId = null)
{
    public Dictionary<string, string> ToDictionary() =>
        SlimClaims.CreateActor(UserId, SecurityStamp ?? string.Empty, AuthenticationMethod, AuthTime, SessionId);
}

/// <summary>Convenience accessors on <see cref="ClaimsPrincipal"/>.</summary>
public static class SlimClaimsPrincipalExtensions
{
    /// <summary>User id (<c>sub</c>, falling back to <see cref="ClaimTypes.NameIdentifier"/>), or null if anonymous.</summary>
    public static string? GetSlimUserId(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return principal.FindFirst(SlimClaimTypes.UserId)?.Value ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    }

    /// <summary>E-mail address (<c>email</c>, falling back to <see cref="ClaimTypes.Email"/>).</summary>
    public static string? GetSlimEmail(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return principal.FindFirst(SlimClaimTypes.Email)?.Value ?? principal.FindFirst(ClaimTypes.Email)?.Value;
    }

    /// <summary>Id of the admin that impersonates the current user (<c>act</c> claim), or null.</summary>
    public static string? GetImpersonatorId(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return SlimClaims.ParseActor(principal.FindFirst(SlimClaimTypes.Actor)?.Value);
    }

    /// <summary>True during an impersonation session.</summary>
    public static bool IsImpersonating(this ClaimsPrincipal principal) => principal.GetImpersonatorId() is not null;

    /// <summary>End of the step-up ("sudo") mode (<c>sudo_until</c> claim), or null.</summary>
    public static DateTimeOffset? GetSudoUntil(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        // range-checked: a forged or corrupt value must not throw from FromUnixTimeSeconds
        return long.TryParse(principal.FindFirst(SlimClaimTypes.SudoUntil)?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var unix)
               && unix is >= 0 and <= 253_402_300_799   // up to 9999-12-31
            ? DateTimeOffset.FromUnixTimeSeconds(unix)
            : null;
    }

    /// <summary>True while the step-up ("sudo") mode is active – the basis of <see cref="SlimIdentityDefaults.SudoPolicy"/>.</summary>
    public static bool IsInSudoMode(this ClaimsPrincipal principal, TimeProvider? timeProvider = null) =>
        principal.GetSudoUntil() is { } until && until > (timeProvider ?? TimeProvider.System).GetUtcNow();

    /// <summary>True if the current principal was issued by the SlimIdentity cookie handler.</summary>
    public static bool IsSlimCookieSession(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return string.Equals(principal.Identity?.AuthenticationType, SlimIdentityDefaults.CookieScheme, StringComparison.Ordinal);
    }
}
