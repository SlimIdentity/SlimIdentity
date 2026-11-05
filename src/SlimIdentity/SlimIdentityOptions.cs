namespace SlimIdentity;

/// <summary>
/// Root options. Bindable from <c>IConfiguration</c> (section <see cref="DefaultSectionName"/>) and/or code.
/// Security-critical values are validated at startup (<c>ValidateOnStart</c>).
/// </summary>
public sealed class SlimIdentityOptions
{
    public const string DefaultSectionName = "SlimIdentity";

    /// <summary>Route prefix of all endpoints. Default <c>/auth</c>.</summary>
    public string RoutePrefix { get; set; } = "/auth";

    public SlimEndpointOptions Endpoints { get; set; } = new();
    public SlimSignInOptions SignIn { get; set; } = new();
    public SlimLockoutOptions Lockout { get; set; } = new();
    public SlimRateLimitOptions RateLimit { get; set; } = new();
    public SlimPasswordOptions Password { get; set; } = new();
    public SlimTokenOptions Tokens { get; set; } = new();
    public SlimCookieOptions Cookies { get; set; } = new();
    public SlimTwoFactorOptions TwoFactor { get; set; } = new();
    public SlimExternalLoginOptions ExternalLogin { get; set; } = new();
    public SlimLinkOptions Links { get; set; } = new();
    public SlimCsrfOptions Csrf { get; set; } = new();
    public SlimEmailOptions Email { get; set; } = new();
}

public sealed class SlimEmailOptions
{
    /// <summary>
    /// Verification, password-reset and "account exists" mails are queued and sent by a background service,
    /// so response times do not reveal whether an account exists (enumeration prevention).
    /// Set to <c>false</c> only if your <c>ISlimEmailSender</c> itself just enqueues (e.g. outbox table).
    /// Queued mails live in memory – unsent mails are lost on shutdown.
    /// </summary>
    public bool SendInBackground { get; set; } = true;

    /// <summary>Maximum number of queued mails; further mails are dropped (and logged) until the queue drains.</summary>
    public int QueueCapacity { get; set; } = 1000;
}

public sealed class SlimEndpointOptions
{
    public bool EnableRegistration { get; set; } = true;
    public bool EnableEmailVerification { get; set; } = true;
    public bool EnablePasswordReset { get; set; } = true;
    /// <summary>Disable for LDAP-only setups – the password then lives in the directory.</summary>
    public bool EnableChangePassword { get; set; } = true;
    public bool EnableLogout { get; set; } = true;
    public bool EnableMe { get; set; } = true;
    /// <summary><c>/invitation/info</c> and <c>/invitation/accept</c> (links are created by the host via <c>ISlimAuthManager.CreateInvitationAsync</c>).</summary>
    public bool EnableInvitations { get; set; } = true;

    public bool AllowCookieAuth { get; set; } = true;
    public bool AllowJwtAuth { get; set; } = true;

    /// <summary>Mode used when the request has no <c>?useCookies=</c> query parameter.</summary>
    public bool DefaultUseCookies { get; set; }

    /// <summary>
    /// Sets the SlimIdentity policy scheme as default authenticate/challenge scheme so that plain
    /// <c>[Authorize]</c> works out of the box. Disable if the host manages defaults itself.
    /// </summary>
    public bool ConfigureDefaultAuthenticationScheme { get; set; } = true;
}

public sealed class SlimSignInOptions
{
    /// <summary>Rejects logins (403 <c>email_not_confirmed</c>) until the e-mail is verified.</summary>
    public bool RequireConfirmedEmail { get; set; }

    /// <summary>
    /// <c>false</c> (default, OWASP): <c>/login</c> answers inactive and locked accounts exactly like a wrong password
    /// (401 <c>invalid_credentials</c>, same hashing time), so the response reveals neither existence nor state.
    /// <c>true</c>: inactive accounts get 403 <c>account_disabled</c>, locked accounts 423 with <c>lockoutEndUtc</c>.
    /// </summary>
    public bool RevealAccountState { get; set; }
}

/// <summary>
/// Progressive lockout (NIST SP 800-63B: throttle rather than lock hard): every <see cref="MaxFailedAttempts"/>
/// consecutive failures lock the account, starting with <see cref="Duration"/> and doubling each time up to
/// <see cref="MaxDuration"/>. The counter is only reset by a successful sign-in.
/// </summary>
public sealed class SlimLockoutOptions
{
    public bool Enabled { get; set; } = true;
    public int MaxFailedAttempts { get; set; } = 5;
    /// <summary>Duration of the first lockout.</summary>
    public TimeSpan Duration { get; set; } = TimeSpan.FromMinutes(1);
    /// <summary>Upper bound for the doubling. Set equal to <see cref="Duration"/> for a constant lockout.</summary>
    public TimeSpan MaxDuration { get; set; } = TimeSpan.FromHours(1);
}

public sealed class SlimRateLimitOptions
{
    /// <summary>Requests per IP and window on sensitive endpoints (login, 2fa, register, reset, invitation, …).</summary>
    public int PermitLimit { get; set; } = 10;
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Separate bucket for <c>/refresh</c>. Refresh tokens cannot be guessed (theft is handled by rotation + reuse
    /// detection), so this is only a load guard and deliberately generous.
    /// </summary>
    public int RefreshPermitLimit { get; set; } = 60;
    public TimeSpan RefreshWindow { get; set; } = TimeSpan.FromMinutes(1);
}

public sealed class SlimPasswordOptions
{
    public int MinimumLength { get; set; } = 8;
    /// <summary>Upper bound to prevent hashing-based DoS with huge inputs.</summary>
    public int MaximumLength { get; set; } = 256;
    public bool RequireDigit { get; set; } = true;
    public bool RequireLowercase { get; set; } = true;
    public bool RequireUppercase { get; set; } = true;
    public bool RequireNonAlphanumeric { get; set; }
}

public sealed class SlimTokenOptions
{
    /// <summary>HMAC-SHA256 signing key, at least 32 bytes (UTF-8). Required when JWT auth is allowed.</summary>
    public string JwtSecret { get; set; } = string.Empty;
    public string Issuer { get; set; } = "SlimIdentity";
    public string Audience { get; set; } = "SlimIdentityClient";
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);
    /// <summary>Sliding lifetime: every rotation issues a token valid for this long (capped by the absolute lifetime).</summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(7);
    /// <summary>Hard upper bound of a refresh-token chain, counted from the original sign-in. Then the user must sign in again.</summary>
    public TimeSpan RefreshTokenAbsoluteLifetime { get; set; } = TimeSpan.FromDays(30);
    /// <summary>
    /// RFC 9700 reuse detection: an already consumed refresh token is treated as stolen. With <c>ISlimSessionStore</c> the
    /// affected session is revoked, otherwise the security stamp is rotated (all sessions of the user end).
    /// </summary>
    public bool RevokeSessionsOnRefreshTokenReuse { get; set; } = true;
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Checks <c>slim_stamp</c> and <c>IsActive</c> against the store on every bearer request.</summary>
    public bool ValidateSecurityStampOnEachRequest { get; set; } = true;

    public TimeSpan EmailVerificationTokenLifetime { get; set; } = TimeSpan.FromHours(24);
    public TimeSpan PasswordResetTokenLifetime { get; set; } = TimeSpan.FromHours(1);
    public TimeSpan PreAuthTokenLifetime { get; set; } = TimeSpan.FromMinutes(5);
    /// <summary>Default validity of invitation / "complete your registration" links.</summary>
    public TimeSpan InvitationTokenLifetime { get; set; } = TimeSpan.FromDays(7);
}

public sealed class SlimCookieOptions
{
    public string CookieName { get; set; } = "SlimAuth";
    /// <summary>Cookie domain, e.g. <c>.domain.de</c> for cross-subdomain SPAs. Null = host only.</summary>
    public string? Domain { get; set; }
    public TimeSpan ExpireTimeSpan { get; set; } = TimeSpan.FromHours(8);
    public bool SlidingExpiration { get; set; } = true;
    /// <summary><c>Strict</c> by default; use <c>Lax</c> for <c>app.domain.de → api.domain.de</c>.</summary>
    public SameSiteMode SameSite { get; set; } = SameSiteMode.Strict;
    /// <summary>
    /// How often the cookie principal is re-checked against the store (security stamp, IsActive).
    /// <c>00:00:00</c> = on every request.
    /// </summary>
    public TimeSpan SecurityStampValidationInterval { get; set; } = TimeSpan.FromMinutes(1);
}

public sealed class SlimTwoFactorOptions
{
    /// <summary>Issuer shown in authenticator apps.</summary>
    public string AuthenticatorIssuer { get; set; } = "SlimIdentity";
    public int RecoveryCodeCount { get; set; } = 10;
    /// <summary>Accepted TOTP time steps before/after now (30 s each).</summary>
    public int TotpTimeStepTolerance { get; set; } = 1;
    public TimeSpan SetupTokenLifetime { get; set; } = TimeSpan.FromMinutes(10);
}

public sealed class SlimExternalLoginOptions
{
    /// <summary>Automatically links an external login to an existing account with the same, verified e-mail.</summary>
    public bool AutoLinkVerifiedEmails { get; set; } = true;
    /// <summary>Creates a new (password-less) user for unknown external identities.</summary>
    public bool AllowAutoRegistration { get; set; } = true;
    /// <summary>Providers whose e-mail claim is trusted as verified even without <c>email_verified=true</c> (e.g. "Google").</summary>
    public List<string> TrustedEmailProviders { get; set; } = [];
    /// <summary>Absolute origins (e.g. <c>https://app.domain.de</c>) allowed as <c>returnUrl</c>. Local paths are always allowed.</summary>
    public List<string> AllowedReturnUrls { get; set; } = [];
    public string DefaultReturnUrl { get; set; } = "/";
    /// <summary>Lifetime of the one-time code that bearer clients exchange for tokens after the redirect.</summary>
    public TimeSpan ExchangeCodeLifetime { get; set; } = TimeSpan.FromMinutes(1);
}

public sealed class SlimLinkOptions
{
    /// <summary>e.g. <c>https://app.domain.de/verify-email?token={token}</c>. Null = raw token is mailed.</summary>
    public string? EmailVerificationUrl { get; set; }
    /// <summary>e.g. <c>https://app.domain.de/reset-password?token={token}</c>. Null = raw token is mailed.</summary>
    public string? PasswordResetUrl { get; set; }
    /// <summary>e.g. <c>https://app.domain.de/accept-invitation?token={token}</c>. Null = only the raw token is returned.</summary>
    public string? InvitationUrl { get; set; }
}

public sealed class SlimCsrfOptions
{
    /// <summary>Requires <see cref="HeaderName"/> on state-changing requests in cookie mode.</summary>
    public bool Enabled { get; set; } = true;
    /// <summary>Custom header (any value) – cannot be set cross-origin without a CORS preflight.</summary>
    public string HeaderName { get; set; } = "X-CSRF";
    /// <summary>Additional allowed <c>Origin</c> values besides the API's own origin (e.g. <c>https://app.domain.de</c>).</summary>
    public List<string> AllowedOrigins { get; set; } = [];
}
