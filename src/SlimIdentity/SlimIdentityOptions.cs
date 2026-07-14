namespace BFS.SlimIdentity;

public class SlimIdentityOptions
{
    public string RoutePrefix { get; set; } = "/auth";
    public EndpointOptions Endpoints { get; } = new();
    public LockoutOptions Lockout { get; } = new();
    public PasswordOptions Password { get; } = new();
    public JwtOptions Tokens { get; } = new();
    public CookieOptions Cookies { get; } = new();
}

public class EndpointOptions
{
    public bool EnableRegistration { get; set; } = true;
    public bool EnablePasswordReset { get; set; } = true;
    public bool EnableLogout { get; set; } = true;
    public bool AllowCookieAuth { get; set; } = true;
    public bool AllowJwtAuth { get; set; } = true;
}

public class LockoutOptions
{
    public int MaxFailedAttempts { get; set; } = 5;
    public TimeSpan Duration { get; set; } = TimeSpan.FromMinutes(15);
    public int MaxLoginRequestsPerMinute { get; set; } = 10;
}

public class PasswordOptions
{
    public int MinimumLength { get; set; } = 8;
    public bool RequireDigit { get; set; } = true;
    public bool RequireUppercase { get; set; } = true;
    public bool RequireNonAlphanumeric { get; set; } = false;
}

public class JwtOptions
{
    public string SecretKey { get; set; } = string.Empty;
    public string Issuer { get; set; } = "SlimIdentity";
    public string Audience { get; set; } = "SlimIdentityClient";
    public TimeSpan AccessTokenExpiration { get; set; } = TimeSpan.FromMinutes(15);
    public TimeSpan RefreshTokenExpiration { get; set; } = TimeSpan.FromDays(7);
}

public class CookieOptions
{
    public string CookieName { get; set; } = "SlimAuth";
    public TimeSpan ExpireTimeSpan { get; set; } = TimeSpan.FromHours(8);
    public bool SlidingExpiration { get; set; } = true;
}
