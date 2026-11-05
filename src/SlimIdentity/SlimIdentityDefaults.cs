namespace SlimIdentity;

/// <summary>Well-known names used by SlimIdentity.</summary>
public static class SlimIdentityDefaults
{
    /// <summary>Policy scheme that forwards to Bearer, API key or Cookie depending on the request.</summary>
    public const string AuthenticationScheme = "SlimIdentity";
    public const string CookieScheme = "SlimIdentity.Cookie";
    public const string BearerScheme = "SlimIdentity.Bearer";
    public const string ApiKeyScheme = "SlimIdentity.ApiKey";
    /// <summary>Temporary sign-in scheme for OAuth/OIDC handlers (set <c>SignInScheme</c> of your providers to this).</summary>
    public const string ExternalScheme = "SlimIdentity.External";

    public const string BruteForcePolicy = "SlimIdentity_BruteForce";
    /// <summary>Separate, more generous limiter for <c>/refresh</c> (refresh tokens cannot be guessed).</summary>
    public const string RefreshPolicy = "SlimIdentity_Refresh";
    public const string SudoPolicy = "SlimIdentity_Sudo";

    public const string ApiKeyHeaderName = "X-API-Key";
    public const string OpenApiTag = "SlimIdentity";

    internal static bool IsOwnScheme(string scheme) =>
        scheme.StartsWith(AuthenticationScheme, StringComparison.Ordinal);
}

/// <summary>Claim types written by SlimIdentity (short JWT-style names, identical for cookies and JWT).</summary>
public static class SlimClaimTypes
{
    public const string UserId = "sub";
    public const string Email = "email";
    public const string Role = "role";
    public const string SecurityStamp = "slim_stamp";
    /// <summary>
    /// RFC 8693 actor claim, JSON object <c>{"sub":"&lt;impersonator id&gt;","slim_stamp":"&lt;impersonator stamp&gt;"}</c>.
    /// The session is only valid while the impersonator is active and has the same security stamp.
    /// </summary>
    public const string Actor = "act";
    /// <summary>Authentication method: pwd, mfa, ext, api_key, impersonation, refresh source.</summary>
    public const string AuthenticationMethod = "amr";
    /// <summary>Unix seconds until which sudo mode is active.</summary>
    public const string SudoUntil = "sudo_until";
    /// <summary>Server-side session id (only with <c>ISlimSessionStore</c>).</summary>
    public const string SessionId = "sid";
    /// <summary>Unix seconds of the original sign-in (caps the refresh-token chain, see <c>Tokens.RefreshTokenAbsoluteLifetime</c>).</summary>
    public const string AuthTime = "auth_time";
}
