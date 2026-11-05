using SlimIdentity.Abstractions;

namespace SlimIdentity.Contracts;

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

public sealed record SlimLoginRequest(string Email, string Password, bool RememberMe = false);

/// <summary>Either <see cref="Code"/> (TOTP / e-mail code) or <see cref="RecoveryCode"/>.</summary>
public sealed record SlimTwoFactorLoginRequest(string PreAuthToken, string? Code = null, string? RecoveryCode = null);

public sealed record SlimRefreshRequest(string RefreshToken);

public sealed record SlimLogoutRequest(string? RefreshToken = null);

public sealed record SlimRegisterRequest(string Email, string Password);

public sealed record SlimVerifyEmailRequest(string Token);

public sealed record SlimEmailRequest(string Email);

public sealed record SlimResetPasswordRequest(string Token, string NewPassword);

public sealed record SlimChangePasswordRequest(string CurrentPassword, string NewPassword);

public sealed record SlimTwoFactorEnableRequest(string SetupToken, string Code);

public sealed record SlimPasswordConfirmationRequest(string Password);

public sealed record SlimExternalExchangeRequest(string Code);

public sealed record SlimInvitationInfoRequest(string Token);

public sealed record SlimAcceptInvitationRequest(string Token, string Password);

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// <summary>Generic status envelope. <c>status</c> is a stable snake_case machine code.</summary>
public sealed record SlimStatusResponse(string Status, string? Message = null);

/// <summary>Successful sign-in. In cookie mode only <c>status</c> and <c>mode</c> are set.</summary>
public sealed class SlimAuthResponse
{
    public string Status { get; init; } = "success";
    /// <summary><c>cookie</c> or <c>bearer</c>.</summary>
    public string Mode { get; init; } = "cookie";
    public string? TokenType { get; init; }
    public string? AccessToken { get; init; }
    /// <summary>Access token lifetime in seconds.</summary>
    public int? ExpiresIn { get; init; }
    public DateTimeOffset? AccessTokenExpiresAt { get; init; }
    public string? RefreshToken { get; init; }
    public DateTimeOffset? RefreshTokenExpiresAt { get; init; }
}

/// <summary>
/// 401 body of <c>/login</c>: either <c>invalid_credentials</c> or <c>requires_two_factor</c>
/// (then <see cref="PreAuthToken"/> and <see cref="TwoFactorMethod"/> are set).
/// </summary>
public sealed class SlimLoginChallengeResponse
{
    public string Status { get; init; } = "invalid_credentials";
    public string? Message { get; init; }
    public string? PreAuthToken { get; init; }
    /// <summary><c>totp</c> or <c>email</c>.</summary>
    public string? TwoFactorMethod { get; init; }
    public int? ExpiresIn { get; init; }
}

public sealed record SlimLockedResponse(string Status, DateTimeOffset LockoutEndUtc);

public sealed record SlimClaimDto(string Type, string Value);

public sealed record SlimMeResponse(
    string Id,
    string? Email,
    bool IsImpersonating,
    string? ImpersonatorId,
    string? AuthenticationMethod,
    DateTimeOffset? SudoUntil,
    IReadOnlyList<SlimClaimDto> Claims);

public sealed record SlimTwoFactorStatusResponse(bool Enabled, string? Method, bool HasAuthenticator);

public sealed record SlimTwoFactorSetupResponse(string SharedKey, string AuthenticatorUri, string SetupToken);

/// <summary>Who is invited (lets the "set your password" form show the address) and until when the link is valid.</summary>
public sealed record SlimInvitationInfoResponse(string Email, DateTimeOffset ExpiresAt);

/// <summary>An active session / device of the signed-in user.</summary>
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

/// <summary>Result of <see cref="ISlimAuthManager.CreateInvitationAsync"/>: send <see cref="Link"/> to the invited user.</summary>
/// <param name="Token">Raw invitation token.</param>
/// <param name="Link"><c>Links.InvitationUrl</c> with the token inserted, or the raw token if no template is configured.</param>
/// <param name="ExpiresAt">End of validity.</param>
public sealed record SlimInvitation(string Token, string Link, DateTimeOffset ExpiresAt);

/// <summary>Recovery codes are shown exactly once. <see cref="Session"/> contains refreshed tokens in bearer mode.</summary>
public sealed record SlimRecoveryCodesResponse(IReadOnlyList<string> RecoveryCodes, SlimAuthResponse? Session);

// ---------------------------------------------------------------------------
// Service result
// ---------------------------------------------------------------------------

/// <summary>Result of <see cref="ISlimAuthManager"/> operations.</summary>
public sealed record SlimAuthResult
{
    public bool Succeeded { get; init; }
    public bool UsedCookies { get; init; }
    public string? AccessToken { get; init; }
    public DateTimeOffset? AccessTokenExpiresAt { get; init; }
    public string? RefreshToken { get; init; }
    public DateTimeOffset? RefreshTokenExpiresAt { get; init; }
    public ClaimsPrincipal? Principal { get; init; }
    /// <summary>Server-side session id (only with <c>ISlimSessionStore</c>).</summary>
    public string? SessionId { get; init; }
    public string? Error { get; init; }

    internal static SlimAuthResult Failed(string error) => new() { Succeeded = false, Error = error };

    /// <summary>Maps the result to the public JSON DTO.</summary>
    public SlimAuthResponse ToResponse(DateTimeOffset utcNow) => UsedCookies
        ? new SlimAuthResponse { Status = "success", Mode = "cookie" }
        : new SlimAuthResponse
        {
            Status = "success",
            Mode = "bearer",
            TokenType = "Bearer",
            AccessToken = AccessToken,
            AccessTokenExpiresAt = AccessTokenExpiresAt,
            ExpiresIn = AccessTokenExpiresAt is { } exp ? (int)Math.Max(0, (exp - utcNow).TotalSeconds) : null,
            RefreshToken = RefreshToken,
            RefreshTokenExpiresAt = RefreshTokenExpiresAt,
        };
}
