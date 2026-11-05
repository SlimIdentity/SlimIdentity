namespace SlimIdentity;

/// <summary>Fail-fast validation of all security-critical options (runs via <c>ValidateOnStart</c>).</summary>
internal sealed class SlimIdentityOptionsValidator : IValidateOptions<SlimIdentityOptions>
{
    public ValidateOptionsResult Validate(string? name, SlimIdentityOptions o)
    {
        var f = new List<string>();

        if (string.IsNullOrWhiteSpace(o.RoutePrefix) || !o.RoutePrefix.StartsWith('/'))
            f.Add("RoutePrefix must start with '/'.");

        // Endpoints / modes
        var e = o.Endpoints;
        if (!e.AllowCookieAuth && !e.AllowJwtAuth)
            f.Add("At least one of Endpoints.AllowCookieAuth / Endpoints.AllowJwtAuth must be true.");
        if (e.DefaultUseCookies && !e.AllowCookieAuth)
            f.Add("Endpoints.DefaultUseCookies is true but cookie auth is disabled.");
        if (!e.DefaultUseCookies && !e.AllowJwtAuth)
            f.Add("Endpoints.DefaultUseCookies is false (JWT default) but JWT auth is disabled.");

        // Tokens
        var t = o.Tokens;
        if (e.AllowJwtAuth)
        {
            if (Encoding.UTF8.GetByteCount(t.JwtSecret ?? string.Empty) < 32)
                f.Add("Tokens.JwtSecret must be at least 32 bytes when JWT auth is allowed.");
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
        if (t.PreAuthTokenLifetime <= TimeSpan.Zero || t.PreAuthTokenLifetime > TimeSpan.FromMinutes(30))
            f.Add("Tokens.PreAuthTokenLifetime must be between 0 and 30 minutes.");
        if (t.InvitationTokenLifetime <= TimeSpan.Zero || t.InvitationTokenLifetime > TimeSpan.FromDays(30))
            f.Add("Tokens.InvitationTokenLifetime must be between 0 and 30 days.");

        // Lockout / rate limit
        if (o.Lockout.MaxFailedAttempts < 1) f.Add("Lockout.MaxFailedAttempts must be >= 1.");
        if (o.Lockout.Duration <= TimeSpan.Zero) f.Add("Lockout.Duration must be positive.");
        if (o.Lockout.MaxDuration < o.Lockout.Duration) f.Add("Lockout.MaxDuration must be >= Lockout.Duration.");
        if (o.RateLimit.PermitLimit < 1) f.Add("RateLimit.PermitLimit must be >= 1.");
        if (o.RateLimit.Window <= TimeSpan.Zero) f.Add("RateLimit.Window must be positive.");
        if (o.RateLimit.RefreshPermitLimit < 1) f.Add("RateLimit.RefreshPermitLimit must be >= 1.");
        if (o.RateLimit.RefreshWindow <= TimeSpan.Zero) f.Add("RateLimit.RefreshWindow must be positive.");
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
        if (c.SameSite == SameSiteMode.None && !o.Csrf.Enabled)
            f.Add("Cookies.SameSite = None requires Csrf.Enabled = true.");
        if (c.SameSite == SameSiteMode.Unspecified)
            f.Add("Cookies.SameSite must be Strict, Lax or None.");

        // CSRF
        if (o.Csrf.Enabled && string.IsNullOrWhiteSpace(o.Csrf.HeaderName)) f.Add("Csrf.HeaderName is required.");
        foreach (var origin in o.Csrf.AllowedOrigins)
            if (!Uri.TryCreate(origin, UriKind.Absolute, out _)) f.Add($"Csrf.AllowedOrigins: '{origin}' is not an absolute URI.");

        // 2FA
        if (o.TwoFactor.RecoveryCodeCount is < 1 or > 50) f.Add("TwoFactor.RecoveryCodeCount must be between 1 and 50.");
        if (o.TwoFactor.TotpTimeStepTolerance is < 0 or > 3) f.Add("TwoFactor.TotpTimeStepTolerance must be between 0 and 3.");
        if (string.IsNullOrWhiteSpace(o.TwoFactor.AuthenticatorIssuer)) f.Add("TwoFactor.AuthenticatorIssuer is required.");

        // External
        foreach (var url in o.ExternalLogin.AllowedReturnUrls)
            if (!Uri.TryCreate(url, UriKind.Absolute, out _)) f.Add($"ExternalLogin.AllowedReturnUrls: '{url}' is not an absolute URI.");
        if (o.ExternalLogin.ExchangeCodeLifetime <= TimeSpan.Zero || o.ExternalLogin.ExchangeCodeLifetime > TimeSpan.FromMinutes(10))
            f.Add("ExternalLogin.ExchangeCodeLifetime must be between 0 and 10 minutes.");

        // E-mail
        if (o.Email.QueueCapacity < 1) f.Add("Email.QueueCapacity must be >= 1.");

        // Links
        if (o.Links.EmailVerificationUrl is { } v && !v.Contains("{token}", StringComparison.Ordinal))
            f.Add("Links.EmailVerificationUrl must contain the placeholder '{token}'.");
        if (o.Links.PasswordResetUrl is { } r && !r.Contains("{token}", StringComparison.Ordinal))
            f.Add("Links.PasswordResetUrl must contain the placeholder '{token}'.");
        if (o.Links.InvitationUrl is { } i && !i.Contains("{token}", StringComparison.Ordinal))
            f.Add("Links.InvitationUrl must contain the placeholder '{token}'.");
        if (o.Links.EmailChangeUrl is { } ec && !ec.Contains("{token}", StringComparison.Ordinal))
            f.Add("Links.EmailChangeUrl must contain the placeholder '{token}'.");

        return f.Count > 0
            ? ValidateOptionsResult.Fail(f.Select(x => "SlimIdentity: " + x))
            : ValidateOptionsResult.Success;
    }
}
