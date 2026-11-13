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
    /// password check – with every rule of <c>/login</c> that follows it: inactive (<c>account_disabled</c>), locked
    /// (<c>locked_out</c>) are refused, sign-in guards apply. If steps follow – the mailbox of an unconfirmed address, the second factor of an account with 2FA, an own password instead of one
    /// set by an administrator – no session is issued: <see cref="SlimAuthResult.ActionRequired"/> holds them; return it
    /// with status 200, the client continues at <c>POST /auth/login/verify-email</c>, <c>/auth/login/2fa</c> and <c>/auth/login/password-change</c> like
    /// after a password. Pass <paramref name="secondFactorVerified"/> only if your first factor already is multi-factor
    /// (smart card with PIN).
    /// </summary>
    /// <param name="user">The account, freshly loaded from the store.</param>
    /// <param name="useCookies">Cookie (<c>true</c>) or JWT pair.</param>
    /// <param name="isPersistent">Persistent cookie / remember me.</param>
    /// <param name="authenticationMethod">The <c>amr</c> of the session, e.g. <c>cert</c> – lowercase letters, digits, <c>_</c>.</param>
    /// <param name="secondFactorVerified">Your check already was multi-factor: no second factor is asked.</param>
    /// <param name="ct">Cancellation.</param>
    /// <example><code>
    /// var result = await auth.SignInAsync(user, useCookies: true, authenticationMethod: "cert", ct: ct);
    /// if (result.ActionRequired is { } steps) return Results.Ok(steps);
    /// return result.Succeeded ? Results.Ok(result.ToResponse()) : Results.Json(new { status = result.Error }, statusCode: 403);
    /// </code></example>
    Task<SlimAuthResult> SignInAsync(SlimUser user, bool useCookies, bool isPersistent = false, string authenticationMethod = "pwd",
        bool secondFactorVerified = false, CancellationToken ct = default);

    /// <summary>
    /// Admin impersonation: the signed-in administrator of the current request signs in as <paramref name="targetUser"/>
    /// – in the mode of their own session (cookie or JWT) – and stays in the standard <c>act</c> (actor) claim. Never
    /// persistent, never issues a refresh token. The session is bound to the impersonator's security stamp and – with
    /// <see cref="ISlimSessionStore"/> – to the administrator's session it was started from: deactivating the
    /// impersonator, rotating their stamp or revoking that session ends it; <see cref="EndImpersonationAsync"/> resumes
    /// that session. Fails with <c>impersonator_invalid</c>, <c>already_impersonating</c> or
    /// <c>cannot_impersonate_self</c> (check <see cref="SlimAuthResult.Succeeded"/>); throws
    /// <see cref="InvalidOperationException"/> on an anonymous request. Authorize the caller yourself.
    /// </summary>
    Task<SlimAuthResult> ImpersonateAsync(SlimUser targetUser, CancellationToken ct = default);

    /// <summary>
    /// Ends the impersonation of the current request and returns to the impersonator's session – only if they are still
    /// active, their security stamp is unchanged and (with <see cref="ISlimSessionStore"/>) the session the impersonation
    /// was started from still exists. Otherwise the session is ended and the result fails with
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
    /// var result = await auth.ElevateToSudoAsync(user, TimeSpan.FromMinutes(5), ct);
    /// return result.Succeeded ? Results.Ok(result.ToResponse()) : Results.Json(new { status = result.Error }, statusCode: 403);
    /// </code></example>
    Task<SlimAuthResult> ElevateToSudoAsync(SlimUser user, TimeSpan duration, CancellationToken ct = default);

    /// <summary>
    /// Step-up authentication: re-issues the current session – in its own mode (cookie or JWT) – with additional
    /// temporary claims (for the sudo window use <see cref="ElevateToSudoAsync"/>). An active impersonation is preserved.
    /// <paramref name="user"/> must be the signed-in user of the current request – anything else throws
    /// <see cref="InvalidOperationException"/> (the session would otherwise switch to another account).
    /// Confirm the password first with <see cref="ConfirmPasswordAsync"/>.
    /// </summary>
    Task<SlimAuthResult> ElevateSessionAsync(SlimUser user, IEnumerable<Claim> additionalClaims, CancellationToken ct = default);

    /// <summary>
    /// Confirms that the owner is present before a sensitive change, with the rules of the built-in endpoints. Accounts
    /// with a password re-enter it: an active lockout is honoured, failures count towards it (incl. the lockout
    /// notification), parallel attempts are serialized and <see cref="ISlimCustomPasswordValidator"/> is used when
    /// registered; a correct password resets the failed-attempt counter and upgrades an outdated hash, like a sign-in
    /// (<paramref name="user"/> is updated accordingly). Accounts without a password (external login, passkeys) need a
    /// sign-in of at most 5 minutes ago instead (never during an impersonation – that sign-in is the administrator's).
    /// Returns <c>null</c> when confirmed, otherwise the result to return
    /// as-is: <c>400 invalid_password</c>, <c>423</c> with <c>Retry-After</c>, or <c>403 reauthentication_required</c>.
    /// </summary>
    /// <example><code>
    /// if (await auth.ConfirmPasswordAsync(user, request.Password, ct) is { } failure) return failure;
    /// </code></example>
    Task<IResult?> ConfirmPasswordAsync(SlimUser user, string? password, CancellationToken ct = default);

    /// <summary>
    /// Starts a registration from your own endpoint (captcha, your own form) exactly like <c>POST /register</c>: the
    /// address rules, the <see cref="SlimRegistrationStage.Begin"/> guards, the same answer for a free and a taken
    /// address (a code and a link, or the "account exists" mail). No account exists yet: return the result as-is – the
    /// <c>action_required</c> answer with <c>verify_email</c> – and the client continues at <c>POST /register/verify</c>
    /// (or the mailed link) and sets its first sign-in method at <c>/register/password</c> or <c>/register/passkey</c>,
    /// where the profile is validated by <see cref="ISlimRegistrationProfile"/> and the
    /// <see cref="SlimRegistrationStage.Complete"/> guards decide. Those steps are available with mail even with
    /// <c>Endpoints.EnableRegistration = false</c>. Throws <see cref="InvalidOperationException"/> without mail – there
    /// a registration is one step: create the account with <see cref="CreateUserAsync"/>.
    /// </summary>
    /// <param name="email">The address as entered.</param>
    /// <param name="useCookies">The mode of the session at the end; <c>null</c> for <c>Endpoints.DefaultUseCookies</c>.</param>
    /// <param name="rememberMe">Persistent cookie once the registration is complete.</param>
    /// <param name="ct">Cancellation.</param>
    /// <example><code>
    /// if (!await captcha.VerifyAsync(form.Captcha, ct)) return Results.BadRequest();
    /// return await auth.BeginRegistrationAsync(form.Email, ct: ct);
    /// </code></example>
    Task<IResult> BeginRegistrationAsync(string email, bool? useCookies = null, bool rememberMe = false, CancellationToken ct = default);

    // ---------------------------------------------------------------- administration (authorize the caller yourself!)

    /// <summary>
    /// Administrator: creates an account for <paramref name="email"/> with its address confirmed – you vouch for it. No
    /// registration guard is asked, no mail is sent; the <c>user_created</c> event is raised (reason
    /// <c>administrator</c>). Without <paramref name="initialPassword"/> the account has no sign-in method yet: hand
    /// out <see cref="CreateInvitationAsync"/> or <see cref="CreatePasswordResetAsync"/>, or let the user sign in with
    /// an external provider. With it, the password is a start password: checked against the password rules before
    /// anything is written, and the first sign-in answers <c>password_change_required</c>.
    /// <paramref name="profile"/> reaches <see cref="ISlimUserStore.CreateAsync"/> as <see cref="SlimNewUser.Profile"/>.
    /// Fails with <c>400</c> (address, password rules) or <c>409 email_taken</c> – which tells whether the address has an
    /// account: never return it from a public endpoint.
    /// </summary>
    /// <example><code>
    /// var created = await auth.CreateUserAsync(form.Email, profile: new Member(form.Department), ct: ct);
    /// if (!created.Succeeded) return created.Failure;
    /// var invitation = await auth.CreateInvitationAsync(created.User, ct: ct);
    /// </code></example>
    Task<SlimCreateUserResult> CreateUserAsync(string email, string? initialPassword = null, object? profile = null, CancellationToken ct = default);

    /// <summary>
    /// Whether <paramref name="user"/> can sign in at all: a password (or one your <see cref="ISlimCustomPasswordValidator"/>
    /// knows), an external login or a passkey. <c>false</c> for an account you created without a password and whose
    /// invitation is still open.
    /// </summary>
    Task<bool> HasSignInMethodAsync(SlimUser user, CancellationToken ct = default);

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
    /// (<c>POST /auth/flow</c> with the token, then step <c>set_credential</c>) – for hosts without mail, handed over by
    /// chat, ticket or in person. Valid for <paramref name="lifetime"/> (default <c>Tokens.PasswordResetTokenLifetime</c>,
    /// at most 7 days), once, and only until the security stamp changes. Unlike a mailed reset it is <b>no</b> proof that
    /// the user controls the mailbox: if confirmation is required, an unconfirmed account first passes
    /// <c>verify_email</c>, and a second factor still applies.
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
    /// (create it first via <see cref="CreateUserAsync"/> without a start password, with your business data as profile).
    /// The link is stateless, bound to the user's security stamp and therefore single-use. Sending it is up to the host.
    /// Opened with <c>POST /auth/flow</c> (the token); the flow ends in step <c>set_credential</c>, which confirms the
    /// address.
    /// </summary>
    Task<SlimInvitation> CreateInvitationAsync(SlimUser user, TimeSpan? lifetime = null, CancellationToken ct = default);
}
