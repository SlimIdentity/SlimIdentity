using System.Text.Json.Serialization;

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
public sealed record SlimLoginRequest(string Email, string Password, bool RememberMe = false, string? TwoFactorRememberToken = null)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("Email = ").Append(Email);
        builder.Append(", Password = ").Append(SlimRedaction.Mask(Password));
        builder.Append(", RememberMe = ").Append(RememberMe);
        builder.Append(", TwoFactorRememberToken = ").Append(SlimRedaction.Mask(TwoFactorRememberToken));
        return true;
    }
}

/// <summary>Body of <c>POST /auth/login/2fa</c>: either <see cref="Code"/> (TOTP / e-mail code) or <see cref="RecoveryCode"/>.</summary>
/// <param name="FlowToken"><c>flowToken</c> of an <c>action_required</c> answer with <c>second_factor</c> as first step.</param>
/// <param name="Code">6-digit TOTP or e-mail code.</param>
/// <param name="RecoveryCode">One of the recovery codes (single use).</param>
/// <param name="RememberDevice">
/// Skip the second factor on this device for <c>TwoFactor.RememberDeviceLifetime</c> (only if the feature is enabled).
/// </param>
public sealed record SlimTwoFactorLoginRequest(string FlowToken, string? Code = null, string? RecoveryCode = null, bool RememberDevice = false)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("FlowToken = ").Append(SlimRedaction.Mask(FlowToken));
        builder.Append(", Code = ").Append(SlimRedaction.Mask(Code));
        builder.Append(", RecoveryCode = ").Append(SlimRedaction.Mask(RecoveryCode));
        builder.Append(", RememberDevice = ").Append(RememberDevice);
        return true;
    }
}

/// <summary>Body of <c>POST /auth/refresh</c>.</summary>
/// <param name="RefreshToken">The current refresh token (single use).</param>
public sealed record SlimRefreshRequest(string RefreshToken)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("RefreshToken = ").Append(SlimRedaction.Mask(RefreshToken));
        return true;
    }
}

/// <summary>Body of <c>POST /auth/logout</c>.</summary>
/// <param name="RefreshToken">Bearer mode: the refresh token to invalidate.</param>
public sealed record SlimLogoutRequest(string? RefreshToken = null)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("RefreshToken = ").Append(SlimRedaction.Mask(RefreshToken));
        return true;
    }
}

/// <summary>Body of <c>POST /auth/register</c>.</summary>
/// <param name="Email">
/// E-mail address of the new account. Without mail (<c>WithoutEmail(allowSelfRegistration: true)</c>) the sign-in name.
/// </param>
/// <param name="Password">
/// Without mail only: the password according to the password policy. With mail it follows at
/// <c>POST /auth/register/password</c>, once the mailbox is proven.
/// </param>
/// <param name="Profile">
/// Without mail only: business data, validated by the host's <see cref="ISlimRegistrationProfile"/>. With mail it is sent
/// with the password.
/// </param>
/// <param name="RememberMe">With mail: persistent session once the registration completes.</param>
public sealed record SlimRegisterRequest(string Email, string? Password = null, JsonElement? Profile = null, bool RememberMe = false)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("Email = ").Append(Email);
        builder.Append(", Password = ").Append(SlimRedaction.Mask(Password));
        builder.Append(", Profile = ").Append(Profile);
        builder.Append(", RememberMe = ").Append(RememberMe);
        return true;
    }
}

/// <summary>
/// Body of <c>POST /auth/register/password</c>: step <c>set_credential</c> with a password – creates the account of a
/// registration, or replaces the password after a reset link.
/// </summary>
/// <param name="FlowToken"><c>flowToken</c> at step <c>set_credential</c>.</param>
/// <param name="Password">Password according to the password policy.</param>
/// <param name="Profile">
/// Optional business data of a registration, validated by the host's <see cref="ISlimRegistrationProfile"/>. Refused for
/// an existing account.
/// </param>
public sealed record SlimRegisterPasswordRequest(string FlowToken, string Password, JsonElement? Profile = null)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("FlowToken = ").Append(SlimRedaction.Mask(FlowToken));
        builder.Append(", Password = ").Append(SlimRedaction.Mask(Password));
        builder.Append(", Profile = ").Append(Profile);
        return true;
    }
}

/// <summary>Body of <c>POST /auth/forgot-password</c>.</summary>
/// <param name="Email">E-mail address of the account.</param>
public sealed record SlimEmailRequest(string Email);

/// <summary>
/// Body of <c>POST /auth/login/verify-email</c> and <c>POST /auth/register/verify</c>: the mailed code proves the mailbox.
/// </summary>
/// <param name="FlowToken"><c>flowToken</c> of an <c>action_required</c> answer with <c>verify_email</c> as first step.</param>
/// <param name="Code">The 6-digit code from the mail sent with that answer.</param>
public sealed record SlimVerifyEmailLoginRequest(string FlowToken, string? Code)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("FlowToken = ").Append(SlimRedaction.Mask(FlowToken));
        builder.Append(", Code = ").Append(SlimRedaction.Mask(Code));
        return true;
    }
}

/// <summary>Body of <c>POST /auth/login/password-change</c>: the forced change of a password set by an administrator.</summary>
/// <param name="FlowToken"><c>flowToken</c> of an <c>action_required</c> answer with <c>change_password</c> as first step.</param>
/// <param name="NewPassword">New password according to the password policy, different from the current one.</param>
public sealed record SlimPasswordChangeLoginRequest(string FlowToken, string NewPassword)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("FlowToken = ").Append(SlimRedaction.Mask(FlowToken));
        builder.Append(", NewPassword = ").Append(SlimRedaction.Mask(NewPassword));
        return true;
    }
}

/// <summary>
/// Body of <c>POST /auth/flow</c>: reads the open steps of a flow again (<paramref name="FlowToken"/>), or redeems the
/// link of a mail into a flow (<paramref name="Token"/>).
/// </summary>
/// <param name="FlowToken"><c>flowToken</c> of an <c>action_required</c> answer.</param>
/// <param name="Token">The token of a mailed link (registration); the answer carries the flow it continues.</param>
public sealed record SlimFlowRequest(string? FlowToken = null, string? Token = null)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("FlowToken = ").Append(SlimRedaction.Mask(FlowToken));
        builder.Append(", Token = ").Append(SlimRedaction.Mask(Token));
        return true;
    }
}

/// <summary>Body of <c>POST /auth/change-password</c>.</summary>
/// <param name="CurrentPassword">The current password.</param>
/// <param name="NewPassword">New password according to the password policy.</param>
public sealed record SlimChangePasswordRequest(string CurrentPassword, string NewPassword)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("CurrentPassword = ").Append(SlimRedaction.Mask(CurrentPassword));
        builder.Append(", NewPassword = ").Append(SlimRedaction.Mask(NewPassword));
        return true;
    }
}

/// <summary>Body of <c>POST /auth/2fa/enable</c>.</summary>
/// <param name="SetupToken">Token from <c>POST /auth/2fa/setup</c>.</param>
/// <param name="Code">First code from the authenticator app.</param>
/// <param name="Password">The current password – a stolen session alone must not install or replace the second factor.</param>
public sealed record SlimTwoFactorEnableRequest(string SetupToken, string Code, string? Password = null)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("SetupToken = ").Append(SlimRedaction.Mask(SetupToken));
        builder.Append(", Code = ").Append(SlimRedaction.Mask(Code));
        builder.Append(", Password = ").Append(SlimRedaction.Mask(Password));
        return true;
    }
}

/// <summary>Body of endpoints that require the current password (<c>/auth/2fa/disable</c>, …).</summary>
/// <param name="Password">The current password.</param>
public sealed record SlimPasswordConfirmationRequest(string Password)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("Password = ").Append(SlimRedaction.Mask(Password));
        return true;
    }
}

/// <summary>Body of <c>POST /auth/login/external/exchange</c>.</summary>
/// <param name="Code">One-time code from the external-login redirect (fragment <c>#code=</c>).</param>
/// <param name="CodeVerifier">PKCE verifier whose S256 hash was sent as <c>code_challenge</c> when the login started.</param>
/// <param name="TwoFactorRememberToken">"Remember this device" token of a bearer client – skips the second factor like at <c>/auth/login</c>.</param>
public sealed record SlimExternalExchangeRequest(string Code, string? CodeVerifier = null, string? TwoFactorRememberToken = null)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("Code = ").Append(SlimRedaction.Mask(Code));
        builder.Append(", CodeVerifier = ").Append(SlimRedaction.Mask(CodeVerifier));
        builder.Append(", TwoFactorRememberToken = ").Append(SlimRedaction.Mask(TwoFactorRememberToken));
        return true;
    }
}

/// <summary>Body of <c>GET /auth/sign-in-methods</c>.</summary>
/// <param name="HasPassword">The account has a password (or the host validates passwords externally, e.g. LDAP).</param>
/// <param name="ExternalLogins">Linked external identities.</param>
/// <param name="Passkeys">Registered passkeys (empty without the <c>SlimIdentity.Passkeys</c> package).</param>
public sealed record SlimSignInMethodsResponse(bool HasPassword, IReadOnlyList<SlimExternalLogin> ExternalLogins, IReadOnlyList<SlimPasskeyInfo> Passkeys);

/// <summary>A registered passkey as listed to its owner.</summary>
/// <param name="Id">Credential id, base64url – used to rename or remove it.</param>
/// <param name="Name">Display name.</param>
/// <param name="CreatedUtc">Registration time.</param>
/// <param name="LastUsedUtc">Last sign-in with it.</param>
/// <param name="BackupEligible">May be synced to other devices (password manager, iCloud Keychain); <c>false</c> for a device-bound key.</param>
/// <param name="BackedUp">Currently synced – as of the last registration or sign-in.</param>
public sealed record SlimPasskeyInfo(string Id, string Name, DateTimeOffset CreatedUtc, DateTimeOffset? LastUsedUtc,
    bool BackupEligible = false, bool BackedUp = false);

/// <summary>Body of <c>POST /auth/sign-in-methods/external/remove</c>.</summary>
/// <param name="Provider">Provider of the link, as listed.</param>
/// <param name="ProviderKey">Subject at the provider, as listed.</param>
/// <param name="Password">The current password – required for accounts that have one.</param>
public sealed record SlimRemoveExternalLoginRequest(string Provider, string ProviderKey, string? Password = null)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("Provider = ").Append(Provider);
        builder.Append(", ProviderKey = ").Append(ProviderKey);
        builder.Append(", Password = ").Append(SlimRedaction.Mask(Password));
        return true;
    }
}

/// <summary>Body of <c>POST /auth/link/external</c>: links the external identity of a link flow to the signed-in account.</summary>
/// <param name="Code">The one-time code from the redirect's fragment (<c>#slim_link_code=…</c>).</param>
/// <param name="CodeVerifier">The PKCE verifier of the link flow – a planted code from someone else's flow fails here.</param>
/// <param name="Password">The current password (not needed for accounts without one).</param>
public sealed record SlimExternalLinkRequest(string Code, string? CodeVerifier = null, string? Password = null)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("Code = ").Append(SlimRedaction.Mask(Code));
        builder.Append(", CodeVerifier = ").Append(SlimRedaction.Mask(CodeVerifier));
        builder.Append(", Password = ").Append(SlimRedaction.Mask(Password));
        return true;
    }
}

/// <summary>Body of <c>POST /auth/change-email</c>.</summary>
/// <param name="NewEmail">The new e-mail address (receives the confirmation link).</param>
/// <param name="Password">The current password.</param>
public sealed record SlimChangeEmailRequest(string NewEmail, string Password)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("NewEmail = ").Append(NewEmail);
        builder.Append(", Password = ").Append(SlimRedaction.Mask(Password));
        return true;
    }
}

/// <summary>Body of <c>POST /auth/confirm-email-change</c>.</summary>
/// <param name="Token">Token from the confirmation mail sent to the new address.</param>
public sealed record SlimConfirmEmailChangeRequest(string Token)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("Token = ").Append(SlimRedaction.Mask(Token));
        return true;
    }
}

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
/// 200 body of a sign-in that needs further steps before its session (<c>/auth/login</c>, <c>/auth/login/2fa</c>,
/// <c>/auth/login/password-change</c>, <c>/auth/flow</c> and other sign-in entry points).
/// </summary>
public sealed class SlimActionRequiredResponse
{
    /// <summary>Always <c>action_required</c>.</summary>
    public string Status { get; init; } = SlimErrorCodes.ActionRequired;
    /// <summary>
    /// The open steps in order; the first one is taken now: <c>verify_email</c> (<c>POST /auth/login/verify-email</c>, in a
    /// registration <c>POST /auth/register/verify</c>), <c>set_credential</c> (<c>POST /auth/register/password</c>),
    /// <c>second_factor</c> (<c>POST /auth/login/2fa</c>) or <c>change_password</c> (<c>POST /auth/login/password-change</c>).
    /// Clients ignore steps they do not know.
    /// </summary>
    public required IReadOnlyList<string> Actions { get; init; }
    /// <summary>Token of the sign-in for the step endpoints and <c>POST /auth/flow</c>; every step answers with a new one.</summary>
    public required string FlowToken { get; init; }
    /// <summary>Seconds until the sign-in expires (all steps together).</summary>
    public int ExpiresIn { get; init; }
    /// <summary>Details of the first step, if it has any.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SlimActionDetails? Details { get; init; }
}

/// <summary>Details of the open step of a <see cref="SlimActionRequiredResponse"/>.</summary>
public sealed class SlimActionDetails
{
    /// <summary>Set for <c>second_factor</c>.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SlimSecondFactorDetails? SecondFactor { get; init; }

    /// <summary>Set for <c>set_credential</c>.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public SlimSetCredentialDetails? SetCredential { get; init; }
}

/// <summary>
/// The ways to sign in the step can set: the first one of a registration, or the new one after a reset link.
/// </summary>
public sealed class SlimSetCredentialDetails
{
    /// <summary>
    /// <c>password</c> (<c>POST /auth/register/password</c>) and, with the passkey package, <c>passkey</c>
    /// (<c>POST /auth/register/passkey</c>). Clients ignore kinds they do not know.
    /// </summary>
    public required IReadOnlyList<string> Kinds { get; init; }

    /// <summary>The address of the account – to show it, and as the user name for password managers.</summary>
    public required string Email { get; init; }
}

/// <summary>How the open second factor can be proven.</summary>
public sealed class SlimSecondFactorDetails
{
    /// <summary>
    /// <c>totp</c> (authenticator app), <c>email</c> (a code was sent) and <c>recovery</c> (a recovery code). Only
    /// <c>recovery</c>: no codes can be sent – a recovery code or an administrator's reset helps.
    /// </summary>
    public required IReadOnlyList<string> Methods { get; init; }
}

/// <summary>
/// Body of every error answer: RFC 9457 problem details (<c>application/problem+json</c>) with the machine-readable
/// <see cref="Code"/> (<see cref="SlimErrorCodes"/>; host guards may add their own).
/// </summary>
public sealed class SlimProblemResponse
{
    /// <summary>HTTP status code.</summary>
    public int Status { get; init; }
    /// <summary>Machine-readable error code, snake_case. Clients evaluate this field only.</summary>
    public required string Code { get; init; }
    /// <summary>Reason phrase of the HTTP status.</summary>
    public string? Title { get; init; }
    /// <summary>English description for logs and developers, not meant for display.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Detail { get; init; }
    /// <summary>423 <c>locked_out</c>: end of the lockout (also sent as <c>Retry-After</c>).</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? LockoutEndUtc { get; init; }
    /// <summary>400 <c>validation_failed</c>: messages per field.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IDictionary<string, string[]>? Errors { get; init; }
}

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
public sealed record SlimTwoFactorSetupResponse(string SharedKey, string AuthenticatorUri, string SetupToken)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("SharedKey = ").Append(SlimRedaction.Mask(SharedKey));
        builder.Append(", AuthenticatorUri = ").Append(SlimRedaction.Mask(AuthenticatorUri));
        builder.Append(", SetupToken = ").Append(SlimRedaction.Mask(SetupToken));
        return true;
    }
}

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
/// <param name="Session">
/// Refreshed session (bearer mode: new tokens, because the security stamp rotated); <c>null</c> if no session was
/// re-issued – after a 2FA change that means it could not be renewed: sign in again.
/// </param>
public sealed record SlimRecoveryCodesResponse(IReadOnlyList<string> RecoveryCodes, SlimAuthResponse? Session)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("RecoveryCodes = ").Append(SlimRedaction.Mask(RecoveryCodes));
        builder.Append(", Session = ").Append(Session);
        return true;
    }
}

/// <summary><c>ToString()</c> of the public records: secrets (passwords, tokens, codes) never reach a log.</summary>
internal static class SlimRedaction
{
    public static string Mask(object? secret) => secret is null ? "null" : "***";
}
