using SlimIdentity.Contracts;
using SlimIdentity.Security;

namespace SlimIdentity;

/// <summary>
/// Session and token management for the host's own endpoints (custom registration, admin panel, …).
/// </summary>
public interface ISlimAuthManager
{
    /// <summary>Issues a regular cookie or a JWT pair for <paramref name="user"/>.</summary>
    Task<SlimAuthResult> SignInAsync(SlimUser user, bool useCookies, bool isPersistent = false, CancellationToken ct = default);

    /// <summary>
    /// Admin impersonation: signs in as <paramref name="targetUser"/> but keeps <paramref name="impersonatorUserId"/>
    /// in the standard <c>act</c> (actor) claim. Never persistent, never issues a refresh token.
    /// The session is bound to the impersonator's security stamp: if the impersonator is deactivated or their
    /// stamp rotates, the impersonation session becomes invalid. Fails with <c>impersonator_invalid</c>,
    /// <c>already_impersonating</c> or <c>cannot_impersonate_self</c> (check <see cref="SlimAuthResult.Succeeded"/>).
    /// </summary>
    Task<SlimAuthResult> ImpersonateAsync(SlimUser targetUser, string impersonatorUserId, bool useCookies, CancellationToken ct = default);

    /// <summary>
    /// Ends the impersonation of the current request and signs the impersonator back in – only if they are still
    /// active and their security stamp is unchanged. Otherwise the session is ended and the result fails with
    /// <c>impersonator_invalid</c> (or <c>not_impersonating</c>).
    /// </summary>
    Task<SlimAuthResult> EndImpersonationAsync(CancellationToken ct = default);

    /// <summary>
    /// Step-up authentication (sudo mode): re-issues the current session with additional temporary claims,
    /// e.g. <see cref="SlimClaims.SudoFor(TimeSpan, TimeProvider?)"/>. An active impersonation is preserved.
    /// <paramref name="user"/> must be the signed-in user of the current request – anything else throws
    /// <see cref="InvalidOperationException"/> (the session would otherwise switch to another account).
    /// Confirm the password first with <see cref="ConfirmPasswordAsync"/>.
    /// </summary>
    Task<SlimAuthResult> ElevateSessionAsync(SlimUser user, IEnumerable<Claim> additionalClaims, bool useCookies, CancellationToken ct = default);

    /// <summary>
    /// Re-confirms the password of <paramref name="user"/> with the rules of the built-in endpoints: an active lockout
    /// is honoured, failures count towards it (incl. the lockout notification), parallel attempts are serialized and
    /// <see cref="ISlimCustomPasswordValidator"/> is used when registered. Returns <c>null</c> when the password is
    /// correct, otherwise the result to return as-is: <c>400 invalid_password</c> or <c>423</c> with <c>Retry-After</c>.
    /// </summary>
    /// <example><code>
    /// if (await auth.ConfirmPasswordAsync(user, request.Password, ct) is { } failure) return failure;
    /// </code></example>
    Task<IResult?> ConfirmPasswordAsync(SlimUser user, string? password, CancellationToken ct = default);

    // ---------------------------------------------------------------- administration (authorize the caller yourself!)

    /// <summary>
    /// Administrator: sets the password of <paramref name="user"/> – e.g. a start password for an account you created,
    /// on hosts without mail. With <paramref name="mustChange"/> (default) the next sign-in answers
    /// <c>password_change_required</c> and issues no session until the user has chosen an own password. All sessions
    /// and pending links of the user end; a lockout is cleared. Returns <c>null</c>, or <c>400</c> with the violated
    /// password rules. Prefer <see cref="CreatePasswordResetAsync"/> where you can: then you never know the password.
    /// </summary>
    Task<IResult?> SetPasswordAsync(SlimUser user, string password, bool mustChange = true, CancellationToken ct = default);

    /// <summary>
    /// Administrator: a single-use link with which <paramref name="user"/> chooses a new password
    /// (<c>POST /auth/reset-password</c>) – for hosts without mail, handed over by chat, ticket or in person. Valid for
    /// <paramref name="lifetime"/> (default <c>Tokens.PasswordResetTokenLifetime</c>, at most 7 days) and only until the
    /// security stamp changes. Unlike a mailed reset it is <b>no</b> proof that the user controls the mailbox: an
    /// unconfirmed account stays unconfirmed.
    /// </summary>
    Task<SlimPasswordReset> CreatePasswordResetAsync(SlimUser user, TimeSpan? lifetime = null, CancellationToken ct = default);

    /// <summary>
    /// Administrator: removes the second factor of <paramref name="user"/> (authenticator, recovery codes, remembered
    /// devices) – after the phone and the recovery codes are lost. All sessions of the user end; the next sign-in needs
    /// the password only, and the user can set up 2FA again.
    /// </summary>
    Task ResetTwoFactorAsync(SlimUser user, CancellationToken ct = default);

    /// <summary>Administrator: ends a lockout of <paramref name="user"/> and resets the failed-attempt counter.</summary>
    Task UnlockAsync(SlimUser user, CancellationToken ct = default);

    /// <summary>
    /// Ends the current session: removes the auth cookie, consumes the refresh token (if given) and – with
    /// <see cref="ISlimSessionStore"/> – revokes the server-side session so a copied cookie / token stops working too.
    /// </summary>
    Task SignOutAsync(string? refreshToken = null, CancellationToken ct = default);

    /// <summary>
    /// Ends <b>all</b> sessions of <paramref name="user"/> on all devices: rotates and persists the security stamp
    /// (invalidates every cookie, JWT and refresh token) and revokes all server-side sessions. Use it e.g. when banning
    /// a user. Does not touch the cookie of the current request.
    /// </summary>
    Task SignOutEverywhereAsync(SlimUser user, CancellationToken ct = default);

    /// <summary>
    /// Creates an invitation / "complete your registration" link for an existing user <b>without</b> password
    /// (create it first via <see cref="ISlimUserStore.CreateAsync"/> with an empty hash, plus your own business data).
    /// The link is stateless, bound to the user's security stamp and therefore single-use. Sending it is up to the host.
    /// Accepted via <c>POST /auth/invitation/accept</c>.
    /// </summary>
    Task<SlimInvitation> CreateInvitationAsync(SlimUser user, TimeSpan? lifetime = null, CancellationToken ct = default);
}
