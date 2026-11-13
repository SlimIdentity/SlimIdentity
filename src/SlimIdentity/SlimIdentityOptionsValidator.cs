namespace SlimIdentity;

/// <summary>Fail-fast validation of all security-critical options (runs via <c>ValidateOnStart</c>).</summary>
internal sealed class SlimIdentityOptionsValidator : IValidateOptions<SlimIdentityOptions>
{
    // "<at least 32 random bytes …>" copied from the docs is long enough – and public
    private static bool IsPlaceholder(string secret) =>
        secret.TrimStart().StartsWith('<') && secret.TrimEnd().EndsWith('>');

    public ValidateOptionsResult Validate(string? name, SlimIdentityOptions o)
    {
        var f = new List<string>();

        if (string.IsNullOrWhiteSpace(o.RoutePrefix) || !o.RoutePrefix.StartsWith('/'))
            f.Add("RoutePrefix must start with '/'.");
        foreach (var origin in o.TrustedOrigins)
            if (SlimIdentityOptions.NormalizeOrigin(origin) is null) f.Add($"TrustedOrigins: '{origin}' is not an absolute http(s) URI.");

        // Modes: JWT is on when a secret is set
        var e = o.Endpoints;
        var t = o.Tokens;
        if (!e.AllowCookieAuth && !o.JwtEnabled)
            f.Add("Nothing to sign in with: set Tokens.JwtSecret (bearer tokens) or keep Endpoints.AllowCookieAuth = true.");
        if (e.DefaultUseCookies && !e.AllowCookieAuth)
            f.Add("Endpoints.DefaultUseCookies is true but cookie auth is disabled.");

        // Tokens
        if (o.JwtEnabled)
        {
            if (Encoding.UTF8.GetByteCount(t.JwtSecret) < 32)
                f.Add("Tokens.JwtSecret must be at least 32 bytes.");
            else if (IsPlaceholder(t.JwtSecret))
                f.Add("Tokens.JwtSecret is still the <…> placeholder of the documentation – generate a random secret (e.g. openssl rand -base64 48).");
            if (t.PreviousJwtSecrets.Any(s => Encoding.UTF8.GetByteCount(s ?? string.Empty) < 32))
                f.Add("Tokens.PreviousJwtSecrets: every secret must be at least 32 bytes.");
            if (string.IsNullOrWhiteSpace(t.Issuer)) f.Add("Tokens.Issuer is required.");
            if (string.IsNullOrWhiteSpace(t.Audience)) f.Add("Tokens.Audience is required.");
            if (t.AccessTokenLifetime <= TimeSpan.Zero) f.Add("Tokens.AccessTokenLifetime must be positive.");
            if (t.RefreshTokenLifetime <= TimeSpan.Zero) f.Add("Tokens.RefreshTokenLifetime must be positive.");
            if (t.RefreshTokenAbsoluteLifetime < t.RefreshTokenLifetime)
                f.Add("Tokens.RefreshTokenAbsoluteLifetime must be >= Tokens.RefreshTokenLifetime.");
            if (t.ClockSkew < TimeSpan.Zero || t.ClockSkew > TimeSpan.FromMinutes(5))
                f.Add("Tokens.ClockSkew must be between 0 and 5 minutes.");
        }
        if (t.EmailVerificationTokenLifetime <= TimeSpan.Zero) f.Add("Tokens.EmailVerificationTokenLifetime must be positive.");
        if (t.PasswordResetTokenLifetime <= TimeSpan.Zero || t.PasswordResetTokenLifetime > TimeSpan.FromDays(1))
            f.Add("Tokens.PasswordResetTokenLifetime must be between 0 and 24 hours.");
        if (t.InvitationTokenLifetime <= TimeSpan.Zero || t.InvitationTokenLifetime > TimeSpan.FromDays(30))
            f.Add("Tokens.InvitationTokenLifetime must be between 0 and 30 days.");

        // Lockout / rate limit
        if (o.Lockout.MaxFailedAttempts < 0) f.Add("Lockout.MaxFailedAttempts must be >= 0 (0 disables the lockout).");
        if (o.Lockout.Duration <= TimeSpan.Zero) f.Add("Lockout.Duration must be positive.");
        if (o.Lockout.MaxDuration < o.Lockout.Duration) f.Add("Lockout.MaxDuration must be >= Lockout.Duration.");
        if (o.RateLimit.PermitLimit < 1) f.Add("RateLimit.PermitLimit must be >= 1.");
        if (o.RateLimit.Window <= TimeSpan.Zero) f.Add("RateLimit.Window must be positive.");
        if (o.RateLimit.RefreshPermitLimit < 1) f.Add("RateLimit.RefreshPermitLimit must be >= 1.");
        if (o.RateLimit.IPv6PrefixLength is < 32 or > 128) f.Add("RateLimit.IPv6PrefixLength must be between 32 and 128.");

        // Password
        var p = o.Password;
        if (p.MinimumLength < 6) f.Add("Password.MinimumLength must be >= 6.");
        if (p.MaximumLength < p.MinimumLength || p.MaximumLength > 4096)
            f.Add("Password.MaximumLength must be >= MinimumLength and <= 4096.");

        // Cookies
        var c = o.Cookies;
        if (string.IsNullOrWhiteSpace(c.CookieName)) f.Add("Cookies.CookieName is required.");
        if (c.ExpireTimeSpan <= TimeSpan.Zero) f.Add("Cookies.ExpireTimeSpan must be positive.");
        if (c.SecurityStampValidationInterval < TimeSpan.Zero) f.Add("Cookies.SecurityStampValidationInterval must not be negative.");
        if (c.SameSite == SameSiteMode.Unspecified)
            f.Add("Cookies.SameSite must be Strict, Lax or None.");

        // 2FA
        if (string.IsNullOrWhiteSpace(o.TwoFactor.AuthenticatorIssuer)) f.Add("TwoFactor.AuthenticatorIssuer is required.");
        if (o.TwoFactor.RememberDeviceLifetime is { } remember && (remember <= TimeSpan.Zero || remember > TimeSpan.FromDays(90)))
            f.Add("TwoFactor.RememberDeviceLifetime must be between 0 and 90 days (or null to disable it).");

        // E-mail
        if (o.Email.QueueCapacity < 1) f.Add("Email.QueueCapacity must be >= 1.");

        // Links
        if (!string.IsNullOrWhiteSpace(o.Links.BaseUrl) && SlimIdentityOptions.NormalizeOrigin(o.Links.BaseUrl) is null)
            f.Add("Links.BaseUrl must be an absolute http(s) URI.");
        CheckTemplate(o.Links.EmailVerificationUrl, "Links.EmailVerificationUrl");
        CheckTemplate(o.Links.PasswordResetUrl, "Links.PasswordResetUrl");
        CheckTemplate(o.Links.InvitationUrl, "Links.InvitationUrl");
        CheckTemplate(o.Links.EmailChangeUrl, "Links.EmailChangeUrl");

        return f.Count > 0
            ? ValidateOptionsResult.Fail(f.Select(x => "SlimIdentity: " + x))
            : ValidateOptionsResult.Success;

        void CheckTemplate(string? template, string name)
        {
            if (template is not null && !template.Contains("{token}", StringComparison.Ordinal))
                f.Add($"{name} must contain the placeholder '{{token}}'.");
        }
    }
}
