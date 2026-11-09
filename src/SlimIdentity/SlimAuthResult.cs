using SlimIdentity.Contracts;

namespace SlimIdentity;

/// <summary>Result of <see cref="ISlimAuthManager"/> sign-in operations.</summary>
public sealed record SlimAuthResult
{
    /// <summary>Whether the operation succeeded. Otherwise see <see cref="Error"/>.</summary>
    public bool Succeeded { get; init; }
    /// <summary>True if a cookie was issued, false for a JWT pair.</summary>
    public bool UsedCookies { get; init; }
    /// <summary>JWT access token (bearer mode).</summary>
    public string? AccessToken { get; init; }
    /// <summary>Expiry of <see cref="AccessToken"/>.</summary>
    public DateTimeOffset? AccessTokenExpiresAt { get; init; }
    /// <summary>Refresh token (bearer mode with <see cref="ISlimRefreshTokenStore"/>).</summary>
    public string? RefreshToken { get; init; }
    /// <summary>Expiry of <see cref="RefreshToken"/>.</summary>
    public DateTimeOffset? RefreshTokenExpiresAt { get; init; }
    /// <summary>The issued principal.</summary>
    public ClaimsPrincipal? Principal { get; init; }
    /// <summary>Server-side session id (only with <see cref="ISlimSessionStore"/>).</summary>
    public string? SessionId { get; init; }
    /// <summary>Machine-readable error code, e.g. <c>account_inactive</c>, <c>impersonator_invalid</c> or a sign-in guard's veto.</summary>
    public string? Error { get; init; }
    /// <summary>Message of a sign-in guard's veto, else <c>null</c>.</summary>
    public string? ErrorMessage { get; init; }
    /// <summary>A <see cref="ISlimSignInGuard"/> refused the session.</summary>
    public bool Vetoed { get; init; }
    /// <summary>
    /// <see cref="ISlimAuthManager.SignInAsync"/> for an account with 2FA: the challenge to return with status 401
    /// (<see cref="Error"/> is <c>requires_two_factor</c>); the client completes it at <c>POST /auth/login/2fa</c>.
    /// </summary>
    public SlimLoginChallengeResponse? TwoFactorChallenge { get; init; }

    internal static SlimAuthResult Failed(string error) => new() { Succeeded = false, Error = error };
    internal static SlimAuthResult Veto(SlimVeto veto) => new() { Succeeded = false, Error = veto.Error, ErrorMessage = veto.Message, Vetoed = true };

    /// <summary>Maps the result to the JSON DTO returned by the built-in endpoints.</summary>
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

/// <summary>
/// Result of <see cref="ISlimAuthManager.CreatePasswordResetAsync"/>: hand <see cref="Link"/> to the user (chat, ticket,
/// in person). The user chooses the password – the administrator never sees it.
/// </summary>
/// <param name="Token">Raw reset token (for <c>POST /auth/reset-password</c>).</param>
/// <param name="Link">The reset link (<c>Links.BaseUrl</c> + <c>/reset-password</c> or <c>Links.PasswordResetUrl</c>) with the token inserted, or the raw token if neither is configured.</param>
/// <param name="ExpiresAt">End of validity.</param>
public sealed record SlimPasswordReset(string Token, string Link, DateTimeOffset ExpiresAt);

/// <summary>Result of <see cref="ISlimAuthManager.CreateInvitationAsync"/>: send <see cref="Link"/> to the invited user.</summary>
/// <param name="Token">Raw invitation token.</param>
/// <param name="Link">The invitation link (<c>Links.BaseUrl</c> + <c>/accept-invitation</c> or <c>Links.InvitationUrl</c>) with the token inserted, or the raw token if neither is configured.</param>
/// <param name="ExpiresAt">End of validity.</param>
public sealed record SlimInvitation(string Token, string Link, DateTimeOffset ExpiresAt);

/// <summary>
/// Result of <see cref="ISlimAuthManager.RegisterAsync"/>. Return <see cref="Response"/> from a public endpoint: it does
/// not reveal whether the address already had an account.
/// </summary>
public sealed class SlimRegistrationResult
{
    internal SlimRegistrationResult(SlimUser? user, IResult? failure, IResult response) => (User, Failure, Response) = (user, failure, response);

    /// <summary>
    /// The new account – <c>null</c> if <see cref="Failure"/> is set or the address already has an account (its owner
    /// got the "account exists" mail instead). Never tell the caller which of the two happened.
    /// </summary>
    public SlimUser? User { get; }

    /// <summary><c>400</c> (address, password rules) or <c>403</c> (a registration guard's veto); <c>null</c> otherwise.</summary>
    public IResult? Failure { get; }

    /// <summary>The answer of <c>POST /register</c>: <see cref="Failure"/>, or the uniform <c>registration_accepted</c>.</summary>
    public IResult Response { get; }
}
