namespace SlimIdentity;

/// <summary>
/// Root options. Bindable from <c>IConfiguration</c> (section <see cref="DefaultSectionName"/>) and/or code.
/// Security-critical values are validated at startup (<c>ValidateOnStart</c>).
/// </summary>
/// <remarks>
/// Most applications set only <see cref="SlimTokenOptions.JwtSecret"/> (for bearer clients), <see cref="SlimLinkOptions.BaseUrl"/>
/// and – for a front end on another origin – <see cref="TrustedOrigins"/>. Everything else has secure defaults.
/// </remarks>
public sealed class SlimIdentityOptions
{
    /// <summary>Conventional configuration section name: <c>SlimIdentity</c>.</summary>
    public const string DefaultSectionName = "SlimIdentity";

    /// <summary>Route prefix of all endpoints. Default <c>/auth</c>.</summary>
    public string RoutePrefix { get; set; } = "/auth";

    /// <summary>
    /// Origins of your front ends (e.g. <c>https://app.example.com</c>) besides the API's own origin. Used for the CSRF
    /// <c>Origin</c> check in cookie mode and as allowed <c>returnUrl</c> targets after external login. The origin of
    /// <see cref="SlimLinkOptions.BaseUrl"/> is trusted automatically. Configure CORS for the same origins.
    /// </summary>
    public List<string> TrustedOrigins { get; set; } = [];

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
    /// <summary>JWT signing and lifetimes of tokens and links.</summary>
    public SlimTokenOptions Tokens { get; set; } = new();
    /// <summary>Auth cookie settings.</summary>
    public SlimCookieOptions Cookies { get; set; } = new();
    /// <summary>Two-factor authentication.</summary>
    public SlimTwoFactorOptions TwoFactor { get; set; } = new();
    /// <summary>OAuth / OIDC logins.</summary>
    public SlimExternalLoginOptions ExternalLogin { get; set; } = new();
    /// <summary>Links in mails.</summary>
    public SlimLinkOptions Links { get; set; } = new();
    /// <summary>Mail dispatch.</summary>
    public SlimEmailOptions Email { get; set; } = new();

    /// <summary>JWT bearer authentication is active as soon as <see cref="SlimTokenOptions.JwtSecret"/> is set.</summary>
    internal bool JwtEnabled => !string.IsNullOrEmpty(Tokens.JwtSecret);

    /// <summary>Second-factor codes by e-mail can be sent.</summary>
    internal bool EmailCodesEnabled => TwoFactor.AllowEmailCodes && Email.Enabled;

    /// <summary>Cookie mode is the default if requested, or if JWT is not configured.</summary>
    internal bool EffectiveDefaultUseCookies => Endpoints.AllowCookieAuth && (Endpoints.DefaultUseCookies || !JwtEnabled);

    /// <summary>True if <paramref name="origin"/> is one of <see cref="TrustedOrigins"/> or the origin of <see cref="SlimLinkOptions.BaseUrl"/>.</summary>
    internal bool IsTrustedOrigin(string origin)
    {
        var candidate = NormalizeOrigin(origin);
        if (candidate is null) return false;
        if (NormalizeOrigin(Links.BaseUrl) == candidate) return true;
        return TrustedOrigins.Any(t => NormalizeOrigin(t) == candidate);
    }

    internal static string? NormalizeOrigin(string? value) =>
        Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https"
            ? uri.GetLeftPart(UriPartial.Authority).ToLowerInvariant()
            : null;
}

/// <summary>Which endpoints are mapped and which authentication modes are allowed.</summary>
/// <remarks>
/// <c>/login</c>, <c>/logout</c>, <c>/me</c>, <c>/password-policy</c> and the invitation endpoints are always mapped;
/// the 2FA, session, refresh and external-login endpoints appear when the corresponding store is registered.
/// </remarks>
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
    /// <summary><c>/change-email</c> and <c>/confirm-email-change</c>. Disable if the login identifier is managed elsewhere (LDAP, SSO).</summary>
    public bool EnableChangeEmail { get; set; } = true;

    /// <summary>Allows cookie sessions (<c>?useCookies=true</c>). JWT bearer tokens are allowed when <see cref="SlimTokenOptions.JwtSecret"/> is set.</summary>
    public bool AllowCookieAuth { get; set; } = true;

    /// <summary>
    /// Mode used when the request has no <c>?useCookies=</c> query parameter. Without a <see cref="SlimTokenOptions.JwtSecret"/>
    /// cookie mode is the default anyway.
    /// </summary>
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
/// consecutive failures lock the factor, starting with <see cref="Duration"/> and doubling each time up to
/// <see cref="MaxDuration"/>. Password and second factor have separate counters with the same policy; each is reset
/// by a success of its own factor. Passkeys, external logins and <c>ISlimAuthManager.SignInAsync</c> are not affected
/// (nothing to guess) – block an account with <c>IsActive</c>.
/// </summary>
public sealed class SlimLockoutOptions
{
    /// <summary>Failed attempts per lockout step. <c>0</c> disables the lockout (not recommended). Default 5.</summary>
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
    /// <summary>Window of both limits. Default 1 minute.</summary>
    public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Separate bucket for <c>/refresh</c>. Refresh tokens cannot be guessed (theft is handled by rotation + reuse
    /// detection), so this is only a load guard and deliberately generous. Default 60.
    /// </summary>
    public int RefreshPermitLimit { get; set; } = 60;

    /// <summary>
    /// IPv6 clients are grouped by this prefix length, because a single customer usually owns a whole /64 network and
    /// could otherwise rotate addresses to bypass the limit. Default 64 (32–128 allowed, 128 = per address).
    /// </summary>
    public int IPv6PrefixLength { get; set; } = 64;
}

/// <summary>
/// Password policy for new passwords (register, reset, change, invitation). Following NIST SP 800-63B there are no
/// composition rules (digits, upper case, …) – length matters. Add checks with <c>AddPasswordRule&lt;T&gt;()</c>,
/// e.g. the breached-password sample.
/// </summary>
public sealed class SlimPasswordOptions
{
    /// <summary>Minimum length. Default 8 (at least 6); 12 or more is recommended without 2FA.</summary>
    public int MinimumLength { get; set; } = 8;
    /// <summary>Upper bound to prevent hashing-based DoS with huge inputs. Default 256.</summary>
    public int MaximumLength { get; set; } = 256;
}

/// <summary>JWT signing and lifetimes of tokens and links.</summary>
public sealed class SlimTokenOptions
{
    /// <summary>
    /// HMAC-SHA256 signing key, at least 32 bytes (UTF-8). Setting it enables JWT bearer authentication; without it only
    /// cookie sessions are available. Keep it secret.
    /// </summary>
    public string JwtSecret { get; set; } = string.Empty;
    /// <summary>
    /// Earlier signing keys that are still accepted for validation (never used to sign) – for a rotation without
    /// rejected tokens: set the new <see cref="JwtSecret"/>, move the old one here, remove it after
    /// <see cref="AccessTokenLifetime"/> once every instance runs the new configuration. Each at least 32 bytes.
    /// </summary>
    public IList<string> PreviousJwtSecrets { get; set; } = [];
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
    /// <summary>Tolerated clock difference for JWT validation (0–5 minutes). Default 30 seconds.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Checks <c>slim_stamp</c>, <c>IsActive</c> and the server-side session on every bearer request. Default <c>true</c>.</summary>
    public bool ValidateSecurityStampOnEachRequest { get; set; } = true;

    /// <summary>Validity of e-mail verification links. Default 24 hours.</summary>
    public TimeSpan EmailVerificationTokenLifetime { get; set; } = TimeSpan.FromHours(24);
    /// <summary>Validity of password reset links (max. 24 hours). Default 1 hour.</summary>
    public TimeSpan PasswordResetTokenLifetime { get; set; } = TimeSpan.FromHours(1);
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

/// <summary>Two-factor authentication (TOTP per RFC 6238 with ±1 time step, 10 recovery codes).</summary>
public sealed class SlimTwoFactorOptions
{
    /// <summary>Issuer shown in authenticator apps. Default <c>SlimIdentity</c> – set your product name.</summary>
    public string AuthenticatorIssuer { get; set; } = "SlimIdentity";

    /// <summary>
    /// "Remember this device": after a successful second factor with <c>rememberDevice: true</c>, this device skips the
    /// second factor for this long (the password is still required). <c>null</c> (default) disables the feature.
    /// Remembered devices are bound to the security stamp – password change, sign out everywhere, 2FA changes and
    /// <c>/2fa/forget-all-devices</c> invalidate all of them. Maximum 90 days.
    /// </summary>
    public TimeSpan? RememberDeviceLifetime { get; set; }

    /// <summary>
    /// Allows 6-digit codes by e-mail as second factor (<c>/2fa/enable-email</c>). E-mail is the weakest second factor
    /// (a compromised mailbox yields password reset and code alike); <c>false</c> leaves authenticator apps only.
    /// Accounts that already use e-mail codes are then asked for a recovery code. Always off with <c>WithoutEmail()</c>.
    /// Default <c>true</c>.
    /// </summary>
    public bool AllowEmailCodes { get; set; } = true;
}

/// <summary>OAuth / OIDC logins. Allowed <c>returnUrl</c> origins are the <see cref="SlimIdentityOptions.TrustedOrigins"/>.</summary>
public sealed class SlimExternalLoginOptions
{
    /// <summary>
    /// Automatically links an external login to an existing account with the same, verified e-mail – if that account has
    /// no password of its own (external-only, LDAP). An account with a password is never joined automatically: whoever
    /// set it may not be the owner of the mailbox (pre-account hijacking), so the user signs in and links the provider
    /// with the link flow (<c>/login/{provider}?link=true</c>, <c>POST /link/external</c>). Unconfirmed accounts are
    /// taken over by the verified owner instead. Default <c>true</c>.
    /// </summary>
    public bool AutoLinkVerifiedEmails { get; set; } = true;
    /// <summary>Creates a new (password-less) user for unknown external identities. Default <c>true</c>.</summary>
    public bool AllowAutoRegistration { get; set; } = true;
    /// <summary>Providers whose e-mail claim is trusted as verified even without <c>email_verified=true</c> (e.g. "Google").</summary>
    public List<string> TrustedEmailProviders { get; set; } = [];
    /// <summary>Redirect target when no <c>returnUrl</c> is given. Default <c>/</c>.</summary>
    public string DefaultReturnUrl { get; set; } = "/";
}

/// <summary>
/// Links in mails. Usually only <see cref="BaseUrl"/> is set; the individual templates override single links and must
/// contain <c>{token}</c>. Without both the raw token is passed to the sender.
/// </summary>
public sealed class SlimLinkOptions
{
    /// <summary>
    /// Base address of your front end, e.g. <c>https://app.example.com</c>. Links then point to
    /// <c>/verify-email</c>, <c>/reset-password</c>, <c>/accept-invitation</c> and <c>/confirm-email-change</c>
    /// (each with <c>?token=…</c>). Its origin is trusted like an entry in <see cref="SlimIdentityOptions.TrustedOrigins"/>.
    /// </summary>
    public string? BaseUrl { get; set; }

    /// <summary>Overrides the verification link, e.g. <c>https://app.example.com/verify?token={token}</c>.</summary>
    public string? EmailVerificationUrl { get; set; }
    /// <summary>Overrides the password reset link, e.g. <c>https://app.example.com/reset?token={token}</c>.</summary>
    public string? PasswordResetUrl { get; set; }
    /// <summary>Overrides the invitation link, e.g. <c>https://app.example.com/invite?token={token}</c>.</summary>
    public string? InvitationUrl { get; set; }
    /// <summary>Overrides the e-mail change link (sent to the new address), e.g. <c>https://app.example.com/change-email?token={token}</c>.</summary>
    public string? EmailChangeUrl { get; set; }

    internal string? EmailVerificationTemplate => EmailVerificationUrl ?? FromBase("/verify-email");
    internal string? PasswordResetTemplate => PasswordResetUrl ?? FromBase("/reset-password");
    internal string? InvitationTemplate => InvitationUrl ?? FromBase("/accept-invitation");
    internal string? EmailChangeTemplate => EmailChangeUrl ?? FromBase("/confirm-email-change");

    private string? FromBase(string path) =>
        string.IsNullOrWhiteSpace(BaseUrl) ? null : $"{BaseUrl.TrimEnd('/')}{path}?token={{token}}";
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

    /// <summary><c>false</c> after <c>WithoutEmail()</c>: SlimIdentity never sends mail and maps no mail-based endpoint.</summary>
    public bool Enabled { get; internal set; } = true;
}
