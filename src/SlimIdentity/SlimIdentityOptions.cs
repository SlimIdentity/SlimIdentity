namespace SlimIdentity;

/// <summary>
/// Root options. Bindable from <c>IConfiguration</c> (section <see cref="DefaultSectionName"/>) and/or code.
/// Security-critical values are validated at startup (<c>ValidateOnStart</c>).
/// </summary>
public sealed class SlimIdentityOptions
{
    /// <summary>Conventional configuration section name: <c>SlimIdentity</c>.</summary>
    public const string DefaultSectionName = "SlimIdentity";

    /// <summary>Route prefix of all endpoints. Default <c>/auth</c>.</summary>
    public string RoutePrefix { get; set; } = "/auth";

    /// <summary>Which endpoints are mapped and which authentication modes are allowed.</summary>
    public SlimEndpointOptions Endpoints { get; set; } = new();
    /// <summary>Sign-in requirements and answers.</summary>
    public SlimSignInOptions SignIn { get; set; } = new();
    /// <summary>Progressive account lockout.</summary>
    public SlimLockoutOptions Lockout { get; set; } = new();
    /// <summary>Per-IP rate limiting of the sensitive endpoints.</summary>
    public SlimRateLimitOptions RateLimit { get; set; } = new();
    /// <summary>Password policy for new passwords.</summary>
    public SlimPasswordOptions Password { get; set; } = new();
    /// <summary>JWT signing and lifetimes of all tokens and links.</summary>
    public SlimTokenOptions Tokens { get; set; } = new();
    /// <summary>Auth cookie settings.</summary>
    public SlimCookieOptions Cookies { get; set; } = new();
    /// <summary>Two-factor authentication.</summary>
    public SlimTwoFactorOptions TwoFactor { get; set; } = new();
    /// <summary>OAuth / OIDC logins.</summary>
    public SlimExternalLoginOptions ExternalLogin { get; set; } = new();
    /// <summary>Link templates for mails.</summary>
    public SlimLinkOptions Links { get; set; } = new();
    /// <summary>CSRF protection in cookie mode.</summary>
    public SlimCsrfOptions Csrf { get; set; } = new();
    /// <summary>Mail dispatch.</summary>
    public SlimEmailOptions Email { get; set; } = new();
}

/// <summary>Which endpoints are mapped and which authentication modes are allowed.</summary>
public sealed class SlimEndpointOptions
{
    /// <summary><c>/register</c>. Disable for invite-only applications or custom registration endpoints.</summary>
    public bool EnableRegistration { get; set; } = true;
    /// <summary><c>/verify-email</c> and <c>/resend-verification</c>; verification mail after registration.</summary>
    public bool EnableEmailVerification { get; set; } = true;
    /// <summary><c>/forgot-password</c> and <c>/reset-password</c>.</summary>
    public bool EnablePasswordReset { get; set; } = true;
    /// <summary><c>/change-password</c>. Disable for LDAP-only setups – the password then lives in the directory.</summary>
    public bool EnableChangePassword { get; set; } = true;
    /// <summary><c>/logout</c> and <c>/logout-all</c>.</summary>
    public bool EnableLogout { get; set; } = true;
    /// <summary><c>/me</c>.</summary>
    public bool EnableMe { get; set; } = true;
    /// <summary><c>/invitation/info</c> and <c>/invitation/accept</c> (links are created by the host via <c>ISlimAuthManager.CreateInvitationAsync</c>).</summary>
    public bool EnableInvitations { get; set; } = true;

    /// <summary>Allows cookie sessions (<c>?useCookies=true</c>).</summary>
    public bool AllowCookieAuth { get; set; } = true;
    /// <summary>Allows JWT access/refresh tokens. Requires <see cref="SlimTokenOptions.JwtSecret"/>.</summary>
    public bool AllowJwtAuth { get; set; } = true;

    /// <summary>Mode used when the request has no <c>?useCookies=</c> query parameter.</summary>
    public bool DefaultUseCookies { get; set; }

    /// <summary>
    /// Sets the SlimIdentity policy scheme as default authenticate/challenge scheme so that plain
    /// <c>[Authorize]</c> works out of the box. Disable if the host manages defaults itself.
    /// </summary>
    public bool ConfigureDefaultAuthenticationScheme { get; set; } = true;
}

/// <summary>Sign-in requirements and answers.</summary>
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
    /// <summary>Enables the account lockout. Default <c>true</c>.</summary>
    public bool Enabled { get; set; } = true;
    /// <summary>Failed attempts per lockout step. Default 5.</summary>
    public int MaxFailedAttempts { get; set; } = 5;
    /// <summary>Duration of the first lockout. Default 1 minute.</summary>
    public TimeSpan Duration { get; set; } = TimeSpan.FromMinutes(1);
    /// <summary>Upper bound for the doubling. Set equal to <see cref="Duration"/> for a constant lockout. Default 1 hour.</summary>
    public TimeSpan MaxDuration { get; set; } = TimeSpan.FromHours(1);
}

/// <summary>
/// Per-client rate limiting of the sensitive endpoints (layer 1 of the brute-force protection). Clients are identified
/// by IP address; IPv6 clients by their network prefix. A custom key can be set with
/// <c>SlimIdentityBuilder.UseRateLimitPartitionKey</c>.
/// </summary>
public sealed class SlimRateLimitOptions
{
    /// <summary>Requests per client and window on login, 2FA, register, reset, invitation, … Default 10.</summary>
    public int PermitLimit { get; set; } = 10;
    /// <summary>Window of <see cref="PermitLimit"/>. Default 1 minute.</summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Separate bucket for <c>/refresh</c>. Refresh tokens cannot be guessed (theft is handled by rotation + reuse
    /// detection), so this is only a load guard and deliberately generous. Default 60.
    /// </summary>
    public int RefreshPermitLimit { get; set; } = 60;
    /// <summary>Window of <see cref="RefreshPermitLimit"/>. Default 1 minute.</summary>
    public TimeSpan RefreshWindow { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// IPv6 clients are grouped by this prefix length, because a single customer usually owns a whole /64 network and
    /// could otherwise rotate addresses to bypass the limit. Default 64 (32–128 allowed, 128 = per address).
    /// </summary>
    public int IPv6PrefixLength { get; set; } = 64;
}

/// <summary>Password policy for new passwords (register, reset, change, invitation).</summary>
public sealed class SlimPasswordOptions
{
    /// <summary>Minimum length. Default 8 (at least 6).</summary>
    public int MinimumLength { get; set; } = 8;
    /// <summary>Upper bound to prevent hashing-based DoS with huge inputs. Default 256.</summary>
    public int MaximumLength { get; set; } = 256;
    /// <summary>Requires a digit. Default <c>true</c>.</summary>
    public bool RequireDigit { get; set; } = true;
    /// <summary>Requires a lowercase letter. Default <c>true</c>.</summary>
    public bool RequireLowercase { get; set; } = true;
    /// <summary>Requires an uppercase letter. Default <c>true</c>.</summary>
    public bool RequireUppercase { get; set; } = true;
    /// <summary>Requires a non-alphanumeric character. Default <c>false</c>.</summary>
    public bool RequireNonAlphanumeric { get; set; }
}

/// <summary>JWT signing and lifetimes of all tokens and links.</summary>
public sealed class SlimTokenOptions
{
    /// <summary>HMAC-SHA256 signing key, at least 32 bytes (UTF-8). Required when JWT auth is allowed. Keep it secret.</summary>
    public string JwtSecret { get; set; } = string.Empty;
    /// <summary>JWT <c>iss</c>. Default <c>SlimIdentity</c>.</summary>
    public string Issuer { get; set; } = "SlimIdentity";
    /// <summary>JWT <c>aud</c>. Default <c>SlimIdentityClient</c>.</summary>
    public string Audience { get; set; } = "SlimIdentityClient";
    /// <summary>Access token lifetime. Default 15 minutes.</summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);
    /// <summary>Sliding lifetime: every rotation issues a token valid for this long (capped by the absolute lifetime). Default 7 days.</summary>
    public TimeSpan RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(7);
    /// <summary>Hard upper bound of a refresh-token chain, counted from the original sign-in. Then the user must sign in again. Default 30 days.</summary>
    public TimeSpan RefreshTokenAbsoluteLifetime { get; set; } = TimeSpan.FromDays(30);
    /// <summary>
    /// RFC 9700 reuse detection: an already consumed refresh token is treated as stolen. With <c>ISlimSessionStore</c> the
    /// affected session is revoked, otherwise the security stamp is rotated (all sessions of the user end). Default <c>true</c>.
    /// </summary>
    public bool RevokeSessionsOnRefreshTokenReuse { get; set; } = true;
    /// <summary>Tolerated clock difference for JWT validation (0–5 minutes). Default 30 seconds.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Checks <c>slim_stamp</c>, <c>IsActive</c> and the server-side session on every bearer request. Default <c>true</c>.</summary>
    public bool ValidateSecurityStampOnEachRequest { get; set; } = true;

    /// <summary>Validity of e-mail verification links. Default 24 hours.</summary>
    public TimeSpan EmailVerificationTokenLifetime { get; set; } = TimeSpan.FromHours(24);
    /// <summary>Validity of password reset links (max. 24 hours). Default 1 hour.</summary>
    public TimeSpan PasswordResetTokenLifetime { get; set; } = TimeSpan.FromHours(1);
    /// <summary>Validity of the <c>preAuthToken</c> between password and second factor (max. 30 minutes). Default 5 minutes.</summary>
    public TimeSpan PreAuthTokenLifetime { get; set; } = TimeSpan.FromMinutes(5);
    /// <summary>Default validity of invitation / "complete your registration" links (max. 30 days). Default 7 days.</summary>
    public TimeSpan InvitationTokenLifetime { get; set; } = TimeSpan.FromDays(7);
}

/// <summary>Auth cookie settings. <c>HttpOnly</c> and <c>Secure</c> are always enforced.</summary>
public sealed class SlimCookieOptions
{
    /// <summary>Cookie name. Default <c>SlimAuth</c>.</summary>
    public string CookieName { get; set; } = "SlimAuth";
    /// <summary>Cookie domain, e.g. <c>.example.com</c> for cross-subdomain SPAs. Null = host only.</summary>
    public string? Domain { get; set; }
    /// <summary>Session lifetime. Default 8 hours.</summary>
    public TimeSpan ExpireTimeSpan { get; set; } = TimeSpan.FromHours(8);
    /// <summary>Renews the cookie while it is used. Default <c>true</c>.</summary>
    public bool SlidingExpiration { get; set; } = true;
    /// <summary><c>Strict</c> by default; use <c>Lax</c> for <c>app.example.com → api.example.com</c>.</summary>
    public SameSiteMode SameSite { get; set; } = SameSiteMode.Strict;
    /// <summary>
    /// How often the cookie principal is re-checked against the store (security stamp, IsActive, server-side session).
    /// <c>00:00:00</c> = on every request. Default 1 minute.
    /// </summary>
    public TimeSpan SecurityStampValidationInterval { get; set; } = TimeSpan.FromMinutes(1);
}

/// <summary>Two-factor authentication.</summary>
public sealed class SlimTwoFactorOptions
{
    /// <summary>Issuer shown in authenticator apps. Default <c>SlimIdentity</c> – set your product name.</summary>
    public string AuthenticatorIssuer { get; set; } = "SlimIdentity";
    /// <summary>Number of recovery codes (1–50). Default 10.</summary>
    public int RecoveryCodeCount { get; set; } = 10;
    /// <summary>Accepted TOTP time steps before/after now (30 s each, 0–3). Default 1.</summary>
    public int TotpTimeStepTolerance { get; set; } = 1;
    /// <summary>Time between <c>/2fa/setup</c> and <c>/2fa/enable</c>. Default 10 minutes.</summary>
    public TimeSpan SetupTokenLifetime { get; set; } = TimeSpan.FromMinutes(10);
}

/// <summary>OAuth / OIDC logins.</summary>
public sealed class SlimExternalLoginOptions
{
    /// <summary>Automatically links an external login to an existing account with the same, verified e-mail. Default <c>true</c>.</summary>
    public bool AutoLinkVerifiedEmails { get; set; } = true;
    /// <summary>Creates a new (password-less) user for unknown external identities. Default <c>true</c>.</summary>
    public bool AllowAutoRegistration { get; set; } = true;
    /// <summary>Providers whose e-mail claim is trusted as verified even without <c>email_verified=true</c> (e.g. "Google").</summary>
    public List<string> TrustedEmailProviders { get; set; } = [];
    /// <summary>Absolute origins (e.g. <c>https://app.example.com</c>) allowed as <c>returnUrl</c>. Local paths are always allowed.</summary>
    public List<string> AllowedReturnUrls { get; set; } = [];
    /// <summary>Redirect target when no <c>returnUrl</c> is given. Default <c>/</c>.</summary>
    public string DefaultReturnUrl { get; set; } = "/";
    /// <summary>Lifetime of the one-time code that bearer clients exchange for tokens after the redirect (max. 10 minutes). Default 1 minute.</summary>
    public TimeSpan ExchangeCodeLifetime { get; set; } = TimeSpan.FromMinutes(1);
}

/// <summary>Link templates for mails. Each must contain <c>{token}</c>. Without a template the raw token is passed to the sender.</summary>
public sealed class SlimLinkOptions
{
    /// <summary>e.g. <c>https://app.example.com/verify-email?token={token}</c>.</summary>
    public string? EmailVerificationUrl { get; set; }
    /// <summary>e.g. <c>https://app.example.com/reset-password?token={token}</c>.</summary>
    public string? PasswordResetUrl { get; set; }
    /// <summary>e.g. <c>https://app.example.com/accept-invitation?token={token}</c>.</summary>
    public string? InvitationUrl { get; set; }
}

/// <summary>CSRF protection for state-changing requests in cookie mode.</summary>
public sealed class SlimCsrfOptions
{
    /// <summary>Requires <see cref="HeaderName"/> on state-changing requests in cookie mode. Default <c>true</c>.</summary>
    public bool Enabled { get; set; } = true;
    /// <summary>Custom header (any value) – cannot be set cross-origin without a CORS preflight. Default <c>X-CSRF</c>.</summary>
    public string HeaderName { get; set; } = "X-CSRF";
    /// <summary>Additional allowed <c>Origin</c> values besides the API's own origin (e.g. <c>https://app.example.com</c>).</summary>
    public List<string> AllowedOrigins { get; set; } = [];
}

/// <summary>Mail dispatch.</summary>
public sealed class SlimEmailOptions
{
    /// <summary>
    /// Verification, password-reset, "account exists" and lockout mails are queued and sent by a background service,
    /// so response times do not reveal whether an account exists (enumeration prevention). The queue is drained on a
    /// regular shutdown. Set to <c>false</c> only if your <c>ISlimEmailSender</c> itself just enqueues (outbox). Default <c>true</c>.
    /// </summary>
    public bool SendInBackground { get; set; } = true;

    /// <summary>Maximum number of queued mails; further mails are dropped (and logged) until the queue drains. Default 1000.</summary>
    public int QueueCapacity { get; set; } = 1000;
}
