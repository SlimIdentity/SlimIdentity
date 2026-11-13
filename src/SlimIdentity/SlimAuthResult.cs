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
    /// <summary>Machine-readable error code, e.g. <c>account_disabled</c>, <c>impersonator_invalid</c> or a sign-in guard's veto.</summary>
    public string? Error { get; init; }
    /// <summary>Message of a sign-in guard's veto, else <c>null</c>.</summary>
    public string? ErrorMessage { get; init; }
    /// <summary>A <see cref="ISlimSignInGuard"/> refused the session.</summary>
    public bool Vetoed { get; init; }
    /// <summary>
    /// Steps follow before the session (<see cref="Error"/> is <c>action_required</c>), e.g. the second factor: return it
    /// with status 200 (<c>Results.Ok(result.ActionRequired)</c>); the client continues at the step endpoints.
    /// </summary>
    public SlimActionRequiredResponse? ActionRequired { get; init; }

    /// <summary>When the tokens were issued (the registered <see cref="TimeProvider"/>) – the base of <c>expiresIn</c>.</summary>
    internal DateTimeOffset IssuedAt { get; init; }

    /// <summary>The token of a device remembered for the second factor (bearer mode), answered with the session.</summary>
    internal string? TwoFactorRememberToken { get; init; }

    internal static SlimAuthResult Failed(string error) => new() { Succeeded = false, Error = error };
    internal static SlimAuthResult Steps(SlimActionRequiredResponse response) => new() { Succeeded = false, Error = SlimErrorCodes.ActionRequired, ActionRequired = response };
    internal static SlimAuthResult Veto(SlimVeto veto) => new() { Succeeded = false, Error = veto.Error, ErrorMessage = veto.Message, Vetoed = true };

    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("Succeeded = ").Append(Succeeded);
        builder.Append(", UsedCookies = ").Append(UsedCookies);
        builder.Append(", AccessToken = ").Append(SlimRedaction.Mask(AccessToken));
        builder.Append(", AccessTokenExpiresAt = ").Append(AccessTokenExpiresAt);
        builder.Append(", RefreshToken = ").Append(SlimRedaction.Mask(RefreshToken));
        builder.Append(", RefreshTokenExpiresAt = ").Append(RefreshTokenExpiresAt);
        builder.Append(", SessionId = ").Append(SessionId);
        builder.Append(", Error = ").Append(Error);
        builder.Append(", Vetoed = ").Append(Vetoed);
        return true;
    }

    /// <summary>
    /// Maps a successful result to the JSON DTO returned by the built-in endpoints. <c>expiresIn</c> is measured from the
    /// moment the tokens were issued, on the clock SlimIdentity uses (the registered <see cref="TimeProvider"/>).
    /// </summary>
    /// <exception cref="InvalidOperationException">The result did not succeed – check <see cref="Succeeded"/> first and answer with <see cref="Error"/>.</exception>
    public SlimAuthResponse ToResponse() => !Succeeded
        ? throw new InvalidOperationException($"The sign-in did not succeed ({Error}); check Succeeded before calling ToResponse().")
        : UsedCookies
        ? new SlimAuthResponse { Status = "success", Mode = "cookie" }
        : new SlimAuthResponse
        {
            Status = "success",
            Mode = "bearer",
            TokenType = "Bearer",
            AccessToken = AccessToken,
            AccessTokenExpiresAt = AccessTokenExpiresAt,
            ExpiresIn = AccessTokenExpiresAt is { } exp ? (int)Math.Max(0, (exp - IssuedAt).TotalSeconds) : null,
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
public sealed record SlimPasswordReset(string Token, string Link, DateTimeOffset ExpiresAt)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("Token = ").Append(SlimRedaction.Mask(Token));
        builder.Append(", Link = ").Append(SlimRedaction.Mask(Link));
        builder.Append(", ExpiresAt = ").Append(ExpiresAt);
        return true;
    }
}

/// <summary>Result of <see cref="ISlimAuthManager.CreateInvitationAsync"/>: send <see cref="Link"/> to the invited user.</summary>
/// <param name="Token">Raw invitation token.</param>
/// <param name="Link">The invitation link (<c>Links.BaseUrl</c> + <c>/accept-invitation</c> or <c>Links.InvitationUrl</c>) with the token inserted, or the raw token if neither is configured.</param>
/// <param name="ExpiresAt">End of validity.</param>
public sealed record SlimInvitation(string Token, string Link, DateTimeOffset ExpiresAt)
{
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append("Token = ").Append(SlimRedaction.Mask(Token));
        builder.Append(", Link = ").Append(SlimRedaction.Mask(Link));
        builder.Append(", ExpiresAt = ").Append(ExpiresAt);
        return true;
    }
}

/// <summary>
/// Result of <see cref="ISlimAuthManager.CreateUserAsync"/>: the new account, or why there is none. It tells whether the
/// address was taken – return it to an administrator, never from a public endpoint.
/// </summary>
public sealed class SlimCreateUserResult
{
    internal SlimCreateUserResult(SlimUser? user, IResult? failure) => (User, Failure) = (user, failure);

    /// <summary>The new account; <c>null</c> if <see cref="Failure"/> is set.</summary>
    public SlimUser? User { get; }

    /// <summary>
    /// <c>400</c> (address, password rules) or <c>409 email_taken</c> – to return as-is; <c>null</c> on success.
    /// </summary>
    public IResult? Failure { get; }

    /// <summary>The account was created.</summary>
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(true, nameof(User))]
    [System.Diagnostics.CodeAnalysis.MemberNotNullWhen(false, nameof(Failure))]
    public bool Succeeded => User is not null;
}
