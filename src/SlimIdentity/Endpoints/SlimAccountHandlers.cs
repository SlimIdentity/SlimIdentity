using SlimIdentity.Contracts;
using SlimIdentity.Http;
using SlimIdentity.Security;
using SlimIdentity.Services;

namespace SlimIdentity.Endpoints;

/// <summary>Registration, e-mail verification and change, password flows, invitations, sessions and <c>/me</c>.</summary>
internal sealed class SlimAccountHandlers(
    ISlimUserStore store,
    SlimEmailDispatcher mail,
    SlimCredentialService credentials,
    SlimPasswordPolicy passwordPolicy,
    SlimAuthManager authManager,
    SlimWorkflowTokens workflow,
    SlimHookRunner hooks,
    SlimRegistrationService registration,
    SlimLinks links,
    SlimMetrics metrics,
    IOptions<SlimIdentityOptions> options,
    TimeProvider time,
    IHttpContextAccessor httpContextAccessor,
    IServiceProvider services,
    ILogger<SlimAccountHandlers> logger)
{
    private SlimIdentityOptions O => options.Value;
    private HttpContext Http => httpContextAccessor.HttpContext!;

    // ------------------------------------------------------------------ POST /register

    public async Task<IResult> RegisterAsync(SlimRegisterRequest? request, CancellationToken ct)
    {
        var (email, invalid) = await registration.ValidateAsync(request?.Email, request?.Password, ct);
        if (invalid is not null) return invalid;

        // business data – validated from the request alone, before anything is looked up (no enumeration)
        var profile = await hooks.ValidateProfileAsync(email!, request!.Profile, ct);
        if (profile.Errors is { } errors)
            return SlimResults.Validation(errors.ToDictionary(e => e.Key.Length == 0 ? "profile" : "profile." + e.Key, e => e.Value, StringComparer.Ordinal));

        return (await registration.CreateAsync(email!, request.Password, profile.Profile, ct)).Response;
    }

    // ------------------------------------------------------------------ POST /verify-email & /resend-verification

    public async Task<IResult> VerifyEmailAsync(SlimVerifyEmailRequest? request, CancellationToken ct)
    {
        if (!workflow.TryUnprotect<SlimEmailTokenPayload>(SlimWorkflowTokens.EmailVerificationPurpose, request?.Token, out var payload))
            return SlimResults.InvalidToken();

        var user = await store.FindByIdAsync(payload.Uid, ct);
        if (user is null
            || !string.Equals(user.Email, payload.Email, StringComparison.OrdinalIgnoreCase)
            || !SlimUser.IsSameSecurityState(user.SecurityStamp, payload.Stamp))
            return SlimResults.InvalidToken();

        if (!user.EmailConfirmed)
        {
            if (!await store.TryWriteSecurityStateAsync(user, u => u.EmailConfirmed = true, ct)) return SlimResults.InvalidToken();
            await hooks.RaiseAsync(SlimEventTypes.EmailConfirmed, user.Id, ct: ct);
        }
        return SlimResults.Status("email_confirmed");
    }

    public async Task<IResult> ResendVerificationAsync(SlimEmailRequest? request, CancellationToken ct)
    {
        var email = SlimEmailAddress.Normalize(request?.Email);
        if (!string.IsNullOrEmpty(email))
        {
            var user = await store.FindByEmailAsync(email, ct);
            if (user is { IsActive: true, EmailConfirmed: false })
                await SendVerificationAsync(user, ct);
        }
        return SlimResults.Status("verification_sent", "If the account exists and is unconfirmed, an e-mail has been sent.");
    }

    internal Task SendVerificationAsync(SlimUser user, CancellationToken ct) => registration.SendVerificationAsync(user, ct);

    // ------------------------------------------------------------------ POST /forgot-password & /reset-password

    public async Task<IResult> ForgotPasswordAsync(SlimEmailRequest? request, CancellationToken ct)
    {
        var email = SlimEmailAddress.Normalize(request?.Email);
        if (!string.IsNullOrEmpty(email))
        {
            var user = await store.FindByEmailAsync(email, ct);
            // a pure SSO account gets no local password; an unconfirmed one still may (first proof of the mailbox)
            if (user is { IsActive: true } && !(user.EmailConfirmed && await SignsInOnlyExternallyAsync(user, ct)))
            {
                var token = workflow.Protect(SlimWorkflowTokens.PasswordResetPurpose,
                    new SlimResetTokenPayload(user.Id, user.SecurityStamp), O.Tokens.PasswordResetTokenLifetime);
                var address = user.Email;
                var link = links.Build(SlimLinkKind.PasswordReset, token);
                await mail.SendAsync(SlimEmailKinds.PasswordReset, address, user.Id, (s, x, c) => s.SendPasswordResetEmailAsync(x, address, link, c), ct);
                metrics.PasswordReset("requested");
            }
        }
        return SlimResults.Status("reset_requested", "If the account exists, a reset e-mail has been sent.");
    }

    public async Task<IResult> ResetPasswordAsync(SlimResetPasswordRequest? request, CancellationToken ct)
    {
        if (!workflow.TryUnprotect<SlimResetTokenPayload>(SlimWorkflowTokens.PasswordResetPurpose, request?.Token, out var payload))
            return SlimResults.InvalidToken();

        var user = await store.FindByIdAsync(payload.Uid, ct);
        if (user is null || !user.IsActive || !SlimUser.IsSameSecurityState(user.SecurityStamp, payload.Stamp))
            return SlimResults.InvalidToken();

        if (!payload.ByAdministrator && user.EmailConfirmed && await SignsInOnlyExternallyAsync(user, ct))
            return ExternalSignInOnly();
        if (await passwordPolicy.ValidateAsync(request!.NewPassword, user.Email, ct, "newPassword") is { } errors)
            return SlimResults.Validation(errors);

        var firstProof = false;
        var written = await store.TryWriteSecurityStateAsync(user, u =>
        {
            credentials.ApplyNewPassword(u, request.NewPassword); // rotates stamp → token single-use, all sessions revoked
            // a link handed over by an administrator proves no mailbox
            firstProof = !u.EmailConfirmed && !payload.ByAdministrator;
            if (firstProof) (u.TwoFactorEnabled, u.EmailConfirmed) = (false, true);
        }, ct);
        if (!written) return SlimResults.InvalidToken();
        if (firstProof)
        {
            // First proof of the mailbox: whoever registered the address before (possibly an attacker – pre-account
            // hijacking) must keep neither a second factor that locks the real owner out nor a linked external login.
            // Removed after the state is written: a link that lost against a concurrent change removes nothing.
            if (services.GetService<SlimTwoFactorService>() is { } twoFactor)
            {
                await twoFactor.RemoveSecretAsync(user, ct);
                await twoFactor.RemoveRecoveryCodesAsync(user, ct);
            }
            if (services.GetService<ISlimExternalLoginStore>() is { } externalLogins)
                await externalLogins.RemoveExternalLoginsAsync(user.Id, ct);
            if (services.GetService<ISlimPasskeySignInMethods>() is { } passkeys)
                await passkeys.RemoveAllAsync(user.Id, ct);
        }
        await credentials.ResetAttemptsAsync(user, SlimAttemptFactor.Password, ct);   // the mailbox proved the account
        await authManager.RevokeSessionsAsync(user.Id, exceptSessionId: null, ct);

        Log.PasswordReset(logger, user.Id);
        await hooks.RaiseAsync(SlimEventTypes.PasswordChanged, user.Id, reason: "reset", ct: ct);
        metrics.PasswordReset("completed");
        return SlimResults.Status("password_reset");
    }

    // ------------------------------------------------------------------ POST /change-email & /confirm-email-change

    public async Task<IResult> ChangeEmailAsync(SlimChangeEmailRequest? request, CancellationToken ct)
    {
        var (user, error) = await LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;

        var newEmail = SlimEmailAddress.Normalize(request?.NewEmail);
        if (!IsValidEmail(newEmail)) return InvalidEmail("newEmail");
        if (string.Equals(newEmail, user.Email, StringComparison.OrdinalIgnoreCase))
            return SlimResults.BadRequest(SlimErrorCodes.EmailUnchanged, "The new address equals the current one.");

        if (await credentials.ConfirmPasswordAsync(user, request!.Password, Http, ct) is { } failure)
            return failure;

        // Enumeration prevention: same answer whether or not the new address is already used. Its owner
        // gets either the confirmation link or an "account exists" notice.
        var target = newEmail!;
        var owner = await store.FindByEmailAsync(target, ct);
        if (owner is null)
        {
            var token = workflow.Protect(SlimWorkflowTokens.EmailChangePurpose,
                new SlimEmailChangePayload(user.Id, user.Email, target, user.SecurityStamp), O.Tokens.EmailVerificationTokenLifetime);
            var link = links.Build(SlimLinkKind.EmailChange, token);
            await mail.SendAsync(SlimEmailKinds.EmailChange, target, user.Id, (s, x, c) => s.SendEmailChangeConfirmationAsync(x, target, link, c), ct);
        }
        else
        {
            await mail.SendAsync(SlimEmailKinds.AccountExists, target, owner.Id, (s, x, c) => s.SendAccountExistsEmailAsync(x, target, c), ct);
        }

        Log.EmailChangeRequested(logger, user.Id);
        metrics.EmailChange("requested");
        return SlimResults.Status("email_change_requested", "If the address can be used, a confirmation link has been sent to it.");
    }

    public async Task<IResult> ConfirmEmailChangeAsync(SlimConfirmEmailChangeRequest? request, CancellationToken ct)
    {
        if (!workflow.TryUnprotect<SlimEmailChangePayload>(SlimWorkflowTokens.EmailChangePurpose, request?.Token, out var payload))
            return SlimResults.InvalidToken();

        var user = await store.FindByIdAsync(payload.Uid, ct);
        if (user is null
            || !user.IsActive
            || !string.Equals(user.Email, payload.OldEmail, StringComparison.OrdinalIgnoreCase)
            || !SlimUser.IsSameSecurityState(user.SecurityStamp, payload.Stamp))
            return SlimResults.InvalidToken();

        // address, confirmation and a new stamp in one write: link single use; sessions carry the old address → sign in again
        var newStamp = SlimUser.NewSecurityStamp();
        for (var attempt = 0; ; attempt++)
        {
            var outcome = await store.UpdateEmailAsync(user, payload.NewEmail, user.SecurityStamp ?? string.Empty, newStamp, ct);
            // the confirming person controls the new mailbox, so revealing that it is taken is fine here
            if (outcome == SlimEmailUpdateResult.EmailTaken)
                return SlimResults.BadRequest(SlimErrorCodes.EmailTaken, "The address is already used by another account.");
            if (outcome == SlimEmailUpdateResult.Updated) break;
            // only the claims part changed in between: the link still stands for the current state
            var current = await store.FindByIdAsync(payload.Uid, ct);
            if (attempt == 2 || current is null
                || !string.Equals(current.Email, payload.OldEmail, StringComparison.OrdinalIgnoreCase)
                || !SlimUser.IsSameSecurityState(current.SecurityStamp, payload.Stamp))
                return SlimResults.InvalidToken();
            user = current;
        }
        (user.Email, user.EmailConfirmed, user.SecurityStamp) = (payload.NewEmail, true, newStamp);
        await authManager.RevokeSessionsAsync(user.Id, exceptSessionId: null, ct);

        var (oldEmail, newEmail) = (payload.OldEmail, payload.NewEmail);
        await mail.SendAsync(SlimEmailKinds.EmailChanged, oldEmail, user.Id, (s, x, c) => s.SendEmailChangedNotificationAsync(x, oldEmail, newEmail, c), ct);

        Log.EmailChanged(logger, user.Id);
        await hooks.RaiseAsync(SlimEventTypes.EmailChanged, user.Id, ct: ct);
        metrics.EmailChange("completed");
        return SlimResults.Status("email_changed", "The e-mail address has been changed. Please sign in again.");
    }

    // ------------------------------------------------------------------ POST /invitation/info & /invitation/accept

    public async Task<IResult> InvitationInfoAsync(SlimInvitationInfoRequest? request, CancellationToken ct)
    {
        var (user, expiresAt) = await LoadInvitationAsync(request?.Token, ct);
        return user is null
            ? SlimResults.InvalidToken()
            : Results.Ok(new SlimInvitationInfoResponse(user.Email, expiresAt));
    }

    public async Task<IResult> AcceptInvitationAsync(SlimAcceptInvitationRequest? request, bool? useCookies, CancellationToken ct)
    {
        if (!SlimModes.TryResolve(O, useCookies, out var cookies, out var modeError)) return modeError!;

        var (user, _) = await LoadInvitationAsync(request?.Token, ct);
        if (user is null) return SlimResults.InvalidToken();

        if (services.GetService<ISlimCustomPasswordValidator>() is not null)
            return SlimResults.BadRequest(SlimErrorCodes.PasswordManagedExternally,
                "Passwords are validated externally (LDAP / custom validator); invitations cannot set one.");
        if (await passwordPolicy.ValidateAsync(request!.Password, user.Email, ct) is { } errors)
            return SlimResults.Validation(errors);

        var written = await store.TryWriteSecurityStateAsync(user, u =>
        {
            credentials.ApplyNewPassword(u, request.Password); // rotates the stamp → the link is single-use
            u.EmailConfirmed = true;                           // the invitation was delivered to this mailbox
        }, ct);
        if (!written) return SlimResults.InvalidToken();
        await authManager.RevokeSessionsAsync(user.Id, exceptSessionId: null, ct);
        Log.InvitationAccepted(logger, user.Id);
        await hooks.RaiseAsync(SlimEventTypes.PasswordChanged, user.Id, reason: "invitation", ct: ct);
        metrics.Invitation("accepted");

        // the invitation proves the mailbox and sets an own password – the second factor of an account the host set up
        // with one follows in the sign-in flow
        var result = await services.GetRequiredService<SlimSignInFlow>().StartAsync(user, cookies, rememberMe: false, SlimAuthManager.MethodPassword,
            SlimSignInProofs.None, checkRememberedDevice: false, rememberToken: null, refuseLockedSecondFactor: false, ct);
        if (result.Succeeded || result.ActionRequired is not null || result.Vetoed) return SlimLoginHandlers.ToResult(result);
        return result.Error == SlimErrorCodes.TwoFactorUnavailable
            ? services.GetRequiredService<SlimSignInFlow>().ToHttpResult(result, user)
            : SlimResults.InvalidToken();
    }

    private async Task<(SlimUser? User, DateTimeOffset ExpiresAt)> LoadInvitationAsync(string? token, CancellationToken ct)
    {
        if (!workflow.TryUnprotect<SlimInvitationPayload>(SlimWorkflowTokens.InvitationPurpose, token, out var payload, out var expiresAt))
            return (null, default);

        var user = await store.FindByIdAsync(payload.Uid, ct);
        if (user is null
            || !user.IsActive
            || !string.IsNullOrEmpty(user.PasswordHash) // already completed
            || !string.Equals(user.Email, payload.Email, StringComparison.OrdinalIgnoreCase)
            || !SlimUser.IsSameSecurityState(user.SecurityStamp, payload.Stamp))
            return (null, default);

        return (user, expiresAt);
    }

    // ------------------------------------------------------------------ GET /sessions & DELETE /sessions/{id}

    public async Task<IResult> ListSessionsAsync(CancellationToken ct)
    {
        var (user, error) = await LoadCurrentUserAsync(forbidImpersonation: false, ct);
        if (user is null) return error!;

        var sessions = services.GetRequiredService<ISlimSessionStore>();
        var current = SlimAuthManager.CurrentSessionId(Http.User);
        var now = time.GetUtcNow();
        var list = (await sessions.ListAsync(user.Id, ct))
            .Where(s => s.ExpiresUtc > now && string.Equals(s.UserId, user.Id, StringComparison.Ordinal))
            .OrderByDescending(s => s.LastSeenUtc)
            .Select(s => new SlimSessionDto(s.Id, s.Mode, s.AuthenticationMethod, s.Id == current, s.ImpersonatorId is not null,
                s.CreatedUtc, s.LastSeenUtc, s.ExpiresUtc, s.UserAgent, s.IpAddress))
            .ToList();
        return Results.Ok(list);
    }

    public async Task<IResult> RevokeSessionAsync(string sessionId, CancellationToken ct)
    {
        var (user, error) = await LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;

        var sessions = services.GetRequiredService<ISlimSessionStore>();
        var session = await sessions.FindAsync(sessionId, ct);
        if (session is null || !string.Equals(session.UserId, user.Id, StringComparison.Ordinal))
            return SlimResults.Status(SlimErrorCodes.SessionNotFound, "The session does not exist.", StatusCodes.Status404NotFound);

        await sessions.RevokeAsync(sessionId, ct);
        metrics.SignOut("session");
        if (sessionId == SlimAuthManager.CurrentSessionId(Http.User) && Http.User.IsSlimCookieSession())
            await Http.SignOutAsync(SlimIdentityDefaults.CookieScheme);

        return SlimResults.Status("session_revoked");
    }

    // ------------------------------------------------------------------ POST /change-password (authenticated)

    public async Task<IResult> ChangePasswordAsync(SlimChangePasswordRequest? request, CancellationToken ct)
    {
        var (user, error) = await LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;

        // changes an existing password only: an account without one (SSO, passkey) gets no local password this way
        if (!await credentials.HasPasswordAsync(user, ct))
            return SlimResults.Status(SlimErrorCodes.PasswordNotSet, "The account has no password to change.", StatusCodes.Status409Conflict);
        if (request is null || string.IsNullOrEmpty(request.CurrentPassword))
            return SlimResults.BadRequest(SlimErrorCodes.InvalidRequest, "currentPassword is required.");
        if (await passwordPolicy.ValidateAsync(request.NewPassword, user.Email, ct, "newPassword") is { } errors)
            return SlimResults.Validation(errors);

        if (await credentials.ConfirmPasswordAsync(user, request.CurrentPassword, Http, ct) is { } failure)
            return failure;

        // rotates stamp → other devices are signed out
        if (!await store.TryWriteSecurityStateAsync(user, u => credentials.ApplyNewPassword(u, request.NewPassword), ct))
            return SlimResults.ConcurrentChange();
        await authManager.RevokeSessionsAsync(user.Id, SlimAuthManager.CurrentSessionId(Http.User), ct);
        await hooks.RaiseAsync(SlimEventTypes.PasswordChanged, user.Id, reason: "changed", ct: ct);

        // keep the calling device signed in
        var session = await authManager.RefreshCurrentSessionAsync(user, ct);
        return SlimResults.ReissuedSession(session);
    }

    // ------------------------------------------------------------------ GET /me (authenticated)

    public IResult Me()
    {
        var principal = Http.User;
        var id = principal.GetSlimUserId();
        if (id is null) return SlimResults.Unauthenticated();

        var claims = principal.Claims
            .Where(c => c.Type is not (SlimClaimTypes.SecurityStamp or SlimClaimTypes.Actor)) // act carries the impersonator's stamp
            .Select(c => new SlimClaimDto(c.Type, c.Value))
            .ToList();

        var impersonator = principal.GetImpersonatorId();
        return Results.Ok(new SlimMeResponse(
            id,
            principal.GetSlimEmail(),
            impersonator is not null,
            impersonator,
            principal.FindFirst(SlimClaimTypes.AuthenticationMethod)?.Value,
            principal.GetSudoUntil(),
            claims));
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>No local password, but an external login: the account signs in through SSO only.</summary>
    private async Task<bool> SignsInOnlyExternallyAsync(SlimUser user, CancellationToken ct) =>
        !await credentials.HasPasswordAsync(user, ct)
        && services.GetService<ISlimExternalLoginStore>() is { } externalLogins
        && (await externalLogins.GetExternalLoginsAsync(user.Id, ct)).Count > 0;

    private static IResult ExternalSignInOnly() =>
        SlimResults.Status(SlimErrorCodes.ExternalSignInOnly,
            "The account signs in with an external provider and has no local password.", StatusCodes.Status409Conflict);

    internal async Task<(SlimUser? User, IResult? Error)> LoadCurrentUserAsync(bool forbidImpersonation, CancellationToken ct)
    {
        var principal = Http.User;
        var id = principal.GetSlimUserId();
        if (id is null) return (null, SlimResults.Unauthenticated());

        if (forbidImpersonation && principal.IsImpersonating())
            return (null, SlimResults.Status(SlimErrorCodes.NotAllowedWhileImpersonating,
                "This action is not allowed during an impersonation session.", StatusCodes.Status403Forbidden));

        // the session was validated when the request began; a security change since then (password, removed sign-in
        // method – on any instance) ends it here as well, so a change of this request is bound to the state it saw
        var user = await store.FindByIdAsync(id, ct);
        return user is { IsActive: true } && SlimUser.IsSameSecurityState(user.SecurityStamp, principal.FindFirst(SlimClaimTypes.SecurityStamp)?.Value)
            ? (user, null)
            : (null, SlimResults.Unauthenticated());
    }

    private static bool IsValidEmail(string? email) => SlimRegistrationService.IsValidEmail(email);

    private static IResult InvalidEmail(string field) => SlimRegistrationService.InvalidEmail(field);
}
