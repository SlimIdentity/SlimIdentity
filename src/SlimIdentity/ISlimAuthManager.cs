using SlimIdentity.Contracts;
using SlimIdentity.Security;

namespace SlimIdentity;

/// <summary>
/// Session and token management for the host's own endpoints (custom registration, admin panel, …).
/// </summary>
public interface ISlimAuthManager
{
    /// <summary>
    /// Signs <paramref name="user"/> in after <b>your</b> first factor – a client certificate, a magic link, your own
    /// password check – with every rule of <c>/login</c> that follows it: inactive (<c>account_inactive</c>), locked
    /// (<c>locked_out</c>), unconfirmed with <c>RequireConfirmedEmail</c> (<c>email_not_confirmed</c>) and
    /// administrator-set passwords (<c>password_change_required</c>) are refused, sign-in guards apply. If the account
    /// has 2FA, no session is issued: <see cref="SlimAuthResult.TwoFactorChallenge"/> holds the challenge – return it
    /// with status 401, the client completes it at <c>POST /auth/login/2fa</c> like after a password. Pass
    /// <paramref name="secondFactorVerified"/> only if your first factor already is multi-factor (smart card with PIN).
    /// </summary>
    /// <param name="user">The account, freshly loaded from the store.</param>
    /// <param name="useCookies">Cookie (<c>true</c>) or JWT pair.</param>
    /// <param name="isPersistent">Persistent cookie / remember me.</param>
    /// <param name="authenticationMethod">The <c>amr</c> of the session, e.g. <c>cert</c> – lowercase letters, digits, <c>_</c>.</param>
    /// <param name="secondFactorVerified">Your check already was multi-factor: no second factor is asked.</param>
    /// <param name="ct">Cancellation.</param>
    /// <example><code>
    /// var result = await auth.SignInAsync(user, useCookies: true, authenticationMethod: "cert", ct: ct);
    /// if (result.TwoFactorChallenge is { } challenge) return Results.Json(challenge, statusCode: 401);
    /// return result.Succeeded ? Results.Ok(result.ToResponse()) : Results.Json(new { status = result.Error }, statusCode: 403);
    /// </code></example>
    Task<SlimAuthResult> SignInAsync(SlimUser user, bool useCookies, bool isPersistent = false, string authenticationMethod = "pwd",
        bool secondFactorVerified = false, CancellationToken ct = default);

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
    /// Sudo mode: re-issues the current session with a step-up window of <paramref name="duration"/> (at most 1 hour) on
    /// the registered clock – endpoints with <c>SlimIdentityDefaults.SudoPolicy</c> accept it until then. Same rules as
    /// <see cref="ElevateSessionAsync"/>; confirm the password first with <see cref="ConfirmPasswordAsync"/>.
    /// </summary>
    /// <example><code>
    /// if (await auth.ConfirmPasswordAsync(user, request.Password, ct) is { } failure) return failure;
    /// return Results.Ok((await auth.ElevateToSudoAsync(user, TimeSpan.FromMinutes(5), me.IsSlimCookieSession(), ct)).ToResponse());
    /// </code></example>
    Task<SlimAuthResult> ElevateToSudoAsync(SlimUser user, TimeSpan duration, bool useCookies, CancellationToken ct = default);

    /// <summary>
    /// Step-up authentication: re-issues the current session with additional temporary claims (for the sudo window use
    /// <see cref="ElevateToSudoAsync"/>). An active impersonation is preserved.
    /// <paramref name="user"/> must be the signed-in user of the current request – anything else throws
    /// <see cref="InvalidOperationException"/> (the session would otherwise switch to another account).
    /// Confirm the password first with <see cref="ConfirmPasswordAsync"/>.
    /// </summary>
    Task<SlimAuthResult> ElevateSessionAsync(SlimUser user, IEnumerable<Claim> additionalClaims, bool useCookies, CancellationToken ct = default);

    /// <summary>
    /// Re-confirms the password of <paramref name="user"/> with the rules of the built-in endpoints: an active lockout
    /// is honoured, failures count towards it (incl. the lockout notification), parallel attempts are serialized and
    /// <see cref="ISlimCustomPasswordValidator"/> is used when registered. A correct password resets the failed-attempt
    /// counter and upgrades an outdated hash, like a sign-in; <paramref name="user"/> is updated accordingly. Returns
    /// <c>null</c> when the password is correct, otherwise the result to return as-is: <c>400 invalid_password</c> or
    /// <c>423</c> with <c>Retry-After</c>.
    /// </summary>
    /// <example><code>
    /// if (await auth.ConfirmPasswordAsync(user, request.Password, ct) is { } failure) return failure;
    /// </code></example>
    Task<IResult?> ConfirmPasswordAsync(SlimUser user, string? password, CancellationToken ct = default);

    /// <summary>
    /// Registration for your own endpoint (several steps, captcha, your own form) with every rule of
    /// <c>POST /register</c>: address and password rules, registration guards, no enumeration (an address that already
    /// has an account gets the "account exists" mail, a new one the verification mail – the answer is the same),
    /// the <c>user_created</c> event. <paramref name="profile"/> – your validated business data – reaches
    /// <see cref="ISlimUserStore.CreateAsync"/> as <see cref="SlimNewUser.Profile"/>, so account and profile are
    /// created together. Return <see cref="SlimRegistrationResult.Response"/>; <see cref="ISlimRegistrationProfile"/>
    /// is not asked (validate your own input). Works on hosts with <c>Endpoints.EnableRegistration = false</c>.
    /// </summary>
    /// <example><code>
    /// var result = await auth.RegisterAsync(form.Email, form.Password, new SignUpProfile(form.Company), ct);
    /// return result.Response;
    /// </code></example>
    Task<SlimRegistrationResult> RegisterAsync(string email, string password, object? profile = null, CancellationToken ct = default);

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

    /// <summary>
    /// The host changed what <c>GetClaimsAsync</c> returns for <paramref name="user"/> (roles, permissions, tenant):
    /// running sessions pick up the new claims at their next validation – bearer tokens on the next request, cookies
    /// within <c>Cookies.SecurityStampValidationInterval</c> – without signing anyone out. Changes only the claims part of
    /// the security stamp: links, refresh tokens and remembered devices stay valid. As long as it is not called, no
    /// session reloads its claims (they are a snapshot of the sign-in or the last refresh).
    /// </summary>
    Task RefreshClaimsAsync(SlimUser user, CancellationToken ct = default);

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
