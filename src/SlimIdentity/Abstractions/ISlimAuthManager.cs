using SlimIdentity.Contracts;
using SlimIdentity.Security;

namespace SlimIdentity.Abstractions;

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
    /// </summary>
    Task<SlimAuthResult> ElevateSessionAsync(SlimUser user, IEnumerable<Claim> additionalClaims, bool useCookies, CancellationToken ct = default);

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
