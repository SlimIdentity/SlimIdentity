namespace SlimIdentity;

/// <summary>Well-known names used by SlimIdentity.</summary>
public static class SlimIdentityDefaults
{
    /// <summary>Policy scheme that forwards to Bearer, API key or Cookie depending on the request.</summary>
    public const string AuthenticationScheme = "SlimIdentity";
    /// <summary>Cookie authentication scheme.</summary>
    public const string CookieScheme = "SlimIdentity.Cookie";
    /// <summary>JWT bearer authentication scheme.</summary>
    public const string BearerScheme = "SlimIdentity.Bearer";
    /// <summary><c>X-API-Key</c> authentication scheme (only with <see cref="ISlimApiKeyStore"/>).</summary>
    public const string ApiKeyScheme = "SlimIdentity.ApiKey";
    /// <summary>Temporary sign-in scheme for OAuth/OIDC handlers (set <c>SignInScheme</c> of your providers to this).</summary>
    public const string ExternalScheme = "SlimIdentity.External";

    /// <summary>Rate-limiter policy of the sensitive endpoints – apply it to your own login-like endpoints, too.</summary>
    public const string BruteForcePolicy = "SlimIdentity_BruteForce";
    /// <summary>Separate, more generous limiter for <c>/refresh</c> (refresh tokens cannot be guessed).</summary>
    public const string RefreshPolicy = "SlimIdentity_Refresh";
    /// <summary>Authorization policy that requires an active step-up ("sudo") session.</summary>
    public const string SudoPolicy = "SlimIdentity_Sudo";

    /// <summary>Header carrying API keys.</summary>
    public const string ApiKeyHeaderName = "X-API-Key";
    /// <summary>OpenAPI tag of all SlimIdentity endpoints.</summary>
    public const string OpenApiTag = "SlimIdentity";

    internal static bool IsOwnScheme(string scheme) =>
        scheme.StartsWith(AuthenticationScheme, StringComparison.Ordinal);
}

/// <summary>Claim types written by SlimIdentity (short JWT-style names, identical for cookies and JWT).</summary>
public static class SlimClaimTypes
{
    /// <summary>User id (<c>sub</c>).</summary>
    public const string UserId = "sub";
    /// <summary>E-mail address (<c>email</c>).</summary>
    public const string Email = "email";
    /// <summary>Role (<c>role</c>); <see cref="ClaimTypes.Role"/> from the store is normalized to this.</summary>
    public const string Role = "role";
    /// <summary>Security stamp at sign-in; compared with the store to invalidate sessions.</summary>
    public const string SecurityStamp = "slim_stamp";
    /// <summary>
    /// RFC 8693 actor claim, JSON object <c>{"sub":"&lt;impersonator id&gt;","slim_stamp":"&lt;impersonator stamp&gt;"}</c>.
    /// The session is only valid while the impersonator is active and has the same security stamp.
    /// </summary>
    public const string Actor = "act";
    /// <summary>Authentication method: <c>pwd</c>, <c>mfa</c>, <c>ext</c>, <c>api_key</c>, <c>impersonation</c>.</summary>
    public const string AuthenticationMethod = "amr";
    /// <summary>Unix seconds until which sudo mode is active.</summary>
    public const string SudoUntil = "sudo_until";
    /// <summary>Server-side session id (only with <see cref="ISlimSessionStore"/>).</summary>
    public const string SessionId = "sid";
    /// <summary>Unix seconds of the original sign-in (caps the refresh-token chain, see <see cref="SlimTokenOptions.RefreshTokenAbsoluteLifetime"/>).</summary>
    public const string AuthTime = "auth_time";
}
