namespace SlimIdentity.Contracts;

// Wire types of the /auth endpoints. Property names are serialized in camelCase.

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// <summary>Body of <c>POST /auth/login</c>.</summary>
/// <param name="Email">Login identifier (e-mail, or user name for LDAP).</param>
/// <param name="Password">The password.</param>
/// <param name="RememberMe">Cookie mode: persistent cookie that survives a browser restart.</param>
/// <param name="TwoFactorRememberToken">
/// Bearer mode: the token from a previous <c>/auth/login/2fa</c> with <c>rememberDevice</c>; skips the second factor on
/// this device. (Cookie mode uses a cookie instead.)
/// </param>
public sealed record SlimLoginRequest(string Email, string Password, bool RememberMe = false, string? TwoFactorRememberToken = null);

/// <summary>Body of <c>POST /auth/login/2fa</c>: either <see cref="Code"/> (TOTP / e-mail code) or <see cref="RecoveryCode"/>.</summary>
/// <param name="PreAuthToken">Token from the <c>requires_two_factor</c> answer of <c>/auth/login</c>.</param>
/// <param name="Code">6-digit TOTP or e-mail code.</param>
/// <param name="RecoveryCode">One of the recovery codes (single use).</param>
/// <param name="RememberDevice">
/// Skip the second factor on this device for <c>TwoFactor.RememberDeviceLifetime</c> (only if the feature is enabled).
/// </param>
public sealed record SlimTwoFactorLoginRequest(string PreAuthToken, string? Code = null, string? RecoveryCode = null, bool RememberDevice = false);

/// <summary>Body of <c>POST /auth/refresh</c>.</summary>
/// <param name="RefreshToken">The current refresh token (single use).</param>
public sealed record SlimRefreshRequest(string RefreshToken);

/// <summary>Body of <c>POST /auth/logout</c>.</summary>
/// <param name="RefreshToken">Bearer mode: the refresh token to invalidate.</param>
public sealed record SlimLogoutRequest(string? RefreshToken = null);

/// <summary>Body of <c>POST /auth/register</c>.</summary>
/// <param name="Email">E-mail address of the new account.</param>
/// <param name="Password">Password according to the password policy.</param>
public sealed record SlimRegisterRequest(string Email, string Password);

/// <summary>Body of <c>POST /auth/verify-email</c>.</summary>
/// <param name="Token">Token from the verification mail.</param>
public sealed record SlimVerifyEmailRequest(string Token);

/// <summary>Body of <c>POST /auth/forgot-password</c> and <c>POST /auth/resend-verification</c>.</summary>
/// <param name="Email">E-mail address of the account.</param>
public sealed record SlimEmailRequest(string Email);

/// <summary>Body of <c>POST /auth/reset-password</c>.</summary>
/// <param name="Token">Token from the reset mail.</param>
/// <param name="NewPassword">New password according to the password policy.</param>
public sealed record SlimResetPasswordRequest(string Token, string NewPassword);

/// <summary>Body of <c>POST /auth/login/password-change</c>: the forced change of a password set by an administrator.</summary>
/// <param name="Token"><c>passwordChangeToken</c> from the <c>password_change_required</c> answer of <c>/auth/login</c>.</param>
/// <param name="NewPassword">New password according to the password policy, different from the current one.</param>
public sealed record SlimPasswordChangeLoginRequest(string Token, string NewPassword);

/// <summary>Body of <c>POST /auth/change-password</c>.</summary>
/// <param name="CurrentPassword">The current password.</param>
/// <param name="NewPassword">New password according to the password policy.</param>
public sealed record SlimChangePasswordRequest(string CurrentPassword, string NewPassword);

/// <summary>Body of <c>POST /auth/2fa/enable</c>.</summary>
/// <param name="SetupToken">Token from <c>POST /auth/2fa/setup</c>.</param>
/// <param name="Code">First code from the authenticator app.</param>
/// <param name="Password">The current password – a stolen session alone must not install or replace the second factor.</param>
public sealed record SlimTwoFactorEnableRequest(string SetupToken, string Code, string? Password = null);

/// <summary>Body of endpoints that require the current password (<c>/auth/2fa/disable</c>, …).</summary>
/// <param name="Password">The current password.</param>
public sealed record SlimPasswordConfirmationRequest(string Password);

/// <summary>Body of <c>POST /auth/login/external/exchange</c>.</summary>
/// <param name="Code">One-time code from the external-login redirect (fragment <c>#code=</c>).</param>
/// <param name="CodeVerifier">PKCE verifier whose S256 hash was sent as <c>code_challenge</c> when the login started.</param>
/// <param name="TwoFactorRememberToken">"Remember this device" token of a bearer client – skips the second factor like at <c>/auth/login</c>.</param>
public sealed record SlimExternalExchangeRequest(string Code, string? CodeVerifier = null, string? TwoFactorRememberToken = null);

/// <summary>Body of <c>POST /auth/invitation/info</c>.</summary>
/// <param name="Token">Token from the invitation link.</param>
public sealed record SlimInvitationInfoRequest(string Token);

/// <summary>Body of <c>POST /auth/invitation/accept</c>.</summary>
/// <param name="Token">Token from the invitation link.</param>
/// <param name="Password">The password to set, according to the password policy.</param>
public sealed record SlimAcceptInvitationRequest(string Token, string Password);

/// <summary>Body of <c>POST /auth/change-email</c>.</summary>
/// <param name="NewEmail">The new e-mail address (receives the confirmation link).</param>
/// <param name="Password">The current password.</param>
public sealed record SlimChangeEmailRequest(string NewEmail, string Password);

/// <summary>Body of <c>POST /auth/confirm-email-change</c>.</summary>
/// <param name="Token">Token from the confirmation mail sent to the new address.</param>
public sealed record SlimConfirmEmailChangeRequest(string Token);

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// <summary>Generic status envelope.</summary>
/// <param name="Status">Stable snake_case machine code, e.g. <c>invalid_token</c> or <c>logged_out</c>.</param>
/// <param name="Message">Human-readable English description (not meant for display logic).</param>
public sealed record SlimStatusResponse(string Status, string? Message = null);

/// <summary>Successful sign-in. In cookie mode only <see cref="Status"/> and <see cref="Mode"/> are set.</summary>
public sealed class SlimAuthResponse
{
    /// <summary>Always <c>success</c>.</summary>
    public string Status { get; init; } = "success";
    /// <summary><c>cookie</c> or <c>bearer</c>.</summary>
    public string Mode { get; init; } = "cookie";
    /// <summary><c>Bearer</c> in bearer mode.</summary>
    public string? TokenType { get; init; }
    /// <summary>JWT access token (bearer mode).</summary>
    public string? AccessToken { get; init; }
    /// <summary>Access token lifetime in seconds.</summary>
    public int? ExpiresIn { get; init; }
    /// <summary>Expiry of the access token.</summary>
    public DateTimeOffset? AccessTokenExpiresAt { get; init; }
    /// <summary>Refresh token (bearer mode with <c>ISlimRefreshTokenStore</c>).</summary>
    public string? RefreshToken { get; init; }
    /// <summary>Expiry of the refresh token.</summary>
    public DateTimeOffset? RefreshTokenExpiresAt { get; init; }
    /// <summary>
    /// Bearer mode, after <c>/auth/login/2fa</c> with <c>rememberDevice</c>: store it securely on the device and send it
    /// as <c>twoFactorRememberToken</c> with future logins. (Cookie mode sets a cookie instead.)
    /// </summary>
    public string? TwoFactorRememberToken { get; init; }

    internal SlimAuthResponse WithTwoFactorRememberToken(string token) => new()
    {
        Status = Status, Mode = Mode, TokenType = TokenType, AccessToken = AccessToken, ExpiresIn = ExpiresIn,
        AccessTokenExpiresAt = AccessTokenExpiresAt, RefreshToken = RefreshToken, RefreshTokenExpiresAt = RefreshTokenExpiresAt,
        TwoFactorRememberToken = token,
    };
}

/// <summary>
/// 401 body of <c>/auth/login</c>: <c>invalid_credentials</c>, <c>requires_two_factor</c> (then
/// <see cref="PreAuthToken"/> and <see cref="TwoFactorMethod"/> are set) or <c>password_change_required</c> (then
/// <see cref="PasswordChangeToken"/> is set).
/// </summary>
public sealed class SlimLoginChallengeResponse
{
    /// <summary><c>invalid_credentials</c>, <c>requires_two_factor</c> or <c>password_change_required</c>.</summary>
    public string Status { get; init; } = "invalid_credentials";
    /// <summary>Human-readable English description.</summary>
    public string? Message { get; init; }
    /// <summary>Short-lived token for <c>POST /auth/login/2fa</c>.</summary>
    public string? PreAuthToken { get; init; }
    /// <summary><c>totp</c>, <c>email</c> or <c>recovery</c> (no codes can be sent – only a recovery code helps).</summary>
    public string? TwoFactorMethod { get; init; }
    /// <summary>Short-lived token for <c>POST /auth/login/password-change</c>.</summary>
    public string? PasswordChangeToken { get; init; }
    /// <summary>Lifetime of <see cref="PreAuthToken"/> or <see cref="PasswordChangeToken"/> in seconds.</summary>
    public int? ExpiresIn { get; init; }
}

/// <summary>423 body (only with <c>SignIn.RevealAccountState</c> or for already authenticated flows).</summary>
/// <param name="Status">Always <c>locked_out</c>.</param>
/// <param name="LockoutEndUtc">End of the lockout.</param>
public sealed record SlimLockedResponse(string Status, DateTimeOffset LockoutEndUtc);

/// <summary>A claim of the current principal.</summary>
/// <param name="Type">Claim type, e.g. <c>role</c>.</param>
/// <param name="Value">Claim value.</param>
public sealed record SlimClaimDto(string Type, string Value);

/// <summary>Body of <c>GET /auth/me</c> – the state an SPA needs after a reload.</summary>
/// <param name="Id">User id.</param>
/// <param name="Email">E-mail address.</param>
/// <param name="IsImpersonating">True during an impersonation session.</param>
/// <param name="ImpersonatorId">Id of the impersonating admin.</param>
/// <param name="AuthenticationMethod"><c>pwd</c>, <c>mfa</c>, <c>ext</c>, <c>impersonation</c>, …</param>
/// <param name="SudoUntil">End of the step-up ("sudo") mode, if active.</param>
/// <param name="Claims">All claims except internal ones (security stamp, actor).</param>
public sealed record SlimMeResponse(
    string Id,
    string? Email,
    bool IsImpersonating,
    string? ImpersonatorId,
    string? AuthenticationMethod,
    DateTimeOffset? SudoUntil,
    IReadOnlyList<SlimClaimDto> Claims);

/// <summary>Body of <c>GET /auth/2fa</c>.</summary>
/// <param name="Enabled">Whether 2FA is enabled.</param>
/// <param name="Method">
/// When enabled: <c>totp</c>, <c>email</c>, or <c>recovery</c> – e-mail codes are switched off (<c>WithoutEmail()</c>,
/// <c>TwoFactor.AllowEmailCodes = false</c>) and the account has no authenticator, so only a recovery code signs in;
/// suggest setting up an authenticator app.
/// </param>
/// <param name="HasAuthenticator">Whether an authenticator app is configured.</param>
public sealed record SlimTwoFactorStatusResponse(bool Enabled, string? Method, bool HasAuthenticator);

/// <summary>Body of <c>POST /auth/2fa/setup</c>.</summary>
/// <param name="SharedKey">Base32 secret, formatted for manual entry.</param>
/// <param name="AuthenticatorUri"><c>otpauth://</c> URI for a QR code.</param>
/// <param name="SetupToken">Pass to <c>POST /auth/2fa/enable</c> together with the first code.</param>
public sealed record SlimTwoFactorSetupResponse(string SharedKey, string AuthenticatorUri, string SetupToken);

/// <summary>
/// Body of <c>GET /auth/password-policy</c>: the rules for new passwords, so a front end can show them and validate
/// as the user types. The server always validates again.
/// </summary>
/// <param name="MinimumLength">Minimum number of characters.</param>
/// <param name="MaximumLength">Maximum number of characters.</param>
/// <param name="HasAdditionalRules">
/// True if the server applies further rules (e.g. a breached-password check) that can only be checked on submit.
/// </param>
public sealed record SlimPasswordPolicyResponse(
    int MinimumLength,
    int MaximumLength,
    bool HasAdditionalRules);

/// <summary>Body of <c>POST /auth/invitation/info</c>.</summary>
/// <param name="Email">The invited address (lets the "set your password" form show it).</param>
/// <param name="ExpiresAt">End of validity of the link.</param>
public sealed record SlimInvitationInfoResponse(string Email, DateTimeOffset ExpiresAt);

/// <summary>An active session / device of the signed-in user (<c>GET /auth/sessions</c>).</summary>
/// <param name="Id">Session id (for <c>DELETE /auth/sessions/{id}</c>).</param>
/// <param name="Mode"><c>cookie</c> or <c>bearer</c>.</param>
/// <param name="AuthenticationMethod"><c>pwd</c>, <c>mfa</c>, <c>ext</c>, <c>impersonation</c>, …</param>
/// <param name="IsCurrent">True for the session of the calling device.</param>
/// <param name="IsImpersonation">True for impersonation sessions started by an admin.</param>
/// <param name="CreatedUtc">Sign-in time.</param>
/// <param name="LastSeenUtc">Last validation or refresh.</param>
/// <param name="ExpiresUtc">End of the session.</param>
/// <param name="UserAgent">User agent at sign-in (if stored).</param>
/// <param name="IpAddress">Client IP at sign-in (if stored).</param>
public sealed record SlimSessionDto(
    string Id,
    string Mode,
    string AuthenticationMethod,
    bool IsCurrent,
    bool IsImpersonation,
    DateTimeOffset CreatedUtc,
    DateTimeOffset LastSeenUtc,
    DateTimeOffset ExpiresUtc,
    string? UserAgent,
    string? IpAddress);

/// <summary>Recovery codes – shown exactly once.</summary>
/// <param name="RecoveryCodes">The new codes.</param>
/// <param name="Session">Refreshed session (bearer mode: new tokens, because the security stamp rotated).</param>
public sealed record SlimRecoveryCodesResponse(IReadOnlyList<string> RecoveryCodes, SlimAuthResponse? Session);
