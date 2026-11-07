using System.Net.Mail;
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
    SlimMetrics metrics,
    IOptions<SlimIdentityOptions> options,
    TimeProvider time,
    IHttpContextAccessor httpContextAccessor,
    IServiceProvider services,
    ILogger<SlimAccountHandlers> logger)
{
    private const int MaxEmailLength = 256;

    private SlimIdentityOptions O => options.Value;
    private HttpContext Http => httpContextAccessor.HttpContext!;

    // ------------------------------------------------------------------ POST /register

    public async Task<IResult> RegisterAsync(SlimRegisterRequest? request, CancellationToken ct)
    {
        var email = SlimEmailAddress.Normalize(request?.Email);
        if (!IsValidEmail(email)) return InvalidEmail("email");

        if (await passwordPolicy.ValidateAsync(request!.Password, email!, ct) is { } errors)
            return SlimResults.Validation(errors);

        // the host's veto – decided from the request alone, before anything is looked up (no enumeration)
        if (await hooks.CheckRegistrationAsync(email!, null, ct) is { } veto)
            return SlimResults.Status(veto.Error, veto.Message ?? "Registration is not allowed.", StatusCodes.Status403Forbidden);

        var accepted = SlimResults.Status("registration_accepted",
            "If the address can be used, a confirmation e-mail has been sent.");

        var existing = await store.FindByEmailAsync(email!, ct);
        if (existing is not null)
        {
            // Enumeration prevention: identical response, comparable CPU time, a mail in both cases
            // (sent in the background, so the mail server's latency is not observable).
            credentials.HashPassword(new SlimUser { Email = email! }, request.Password);
            Log.RegistrationForExistingAccount(logger, existing.Id);
            return await AccountExistsAsync(existing.Email, existing.Id);
        }

        var hash = credentials.HashPassword(new SlimUser { Email = email! }, request.Password);
        var user = await store.CreateAsync(email!, hash, ct);
        if (user is null)
        {
            // a concurrent registration took the address between the lookup and the insert – same answer as above
            Log.RegistrationRaceLost(logger);
            return await AccountExistsAsync(email!, null);   // the winner of the race is not loaded
        }
        metrics.Registration("created");
        await hooks.RaiseAsync(SlimEventTypes.UserCreated, user.Id, reason: "registration", ct: ct);

        if (O.Endpoints.EnableEmailVerification && !user.EmailConfirmed)
            await SendVerificationAsync(user, ct);

        return accepted;

        async Task<IResult> AccountExistsAsync(string existingEmail, string? existingUserId)
        {
            metrics.Registration("existing_account");
            await mail.SendAsync(SlimEmailKinds.AccountExists, existingEmail, existingUserId, (s, x, c) => s.SendAccountExistsEmailAsync(x, existingEmail, c), ct);
            return accepted;
        }
    }

    // ------------------------------------------------------------------ POST /verify-email & /resend-verification

    public async Task<IResult> VerifyEmailAsync(SlimVerifyEmailRequest? request, CancellationToken ct)
    {
        if (!workflow.TryUnprotect<SlimEmailTokenPayload>(SlimWorkflowTokens.EmailVerificationPurpose, request?.Token, out var payload))
            return SlimResults.InvalidToken();

        var user = await store.FindByIdAsync(payload.Uid, ct);
        if (user is null
            || !string.Equals(user.Email, payload.Email, StringComparison.OrdinalIgnoreCase)
            || !SlimHashing.FixedTimeEquals(user.SecurityStamp, payload.Stamp))
            return SlimResults.InvalidToken();

        if (!user.EmailConfirmed)
        {
            user.EmailConfirmed = true;
            await store.UpdateSecurityStateAsync(user, ct);
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

    internal async Task SendVerificationAsync(SlimUser user, CancellationToken ct)
    {
        var token = workflow.Protect(SlimWorkflowTokens.EmailVerificationPurpose,
            new SlimEmailTokenPayload(user.Id, user.Email, user.SecurityStamp), O.Tokens.EmailVerificationTokenLifetime);
        var email = user.Email;
        var link = SlimWorkflowTokens.BuildLink(O.Links.EmailVerificationTemplate, token);
        await mail.SendAsync(SlimEmailKinds.Verification, email, user.Id, (s, x, c) => s.SendVerificationEmailAsync(x, email, link, c), ct);
    }

    // ------------------------------------------------------------------ POST /forgot-password & /reset-password

    public async Task<IResult> ForgotPasswordAsync(SlimEmailRequest? request, CancellationToken ct)
    {
        var email = SlimEmailAddress.Normalize(request?.Email);
        if (!string.IsNullOrEmpty(email))
        {
            var user = await store.FindByEmailAsync(email, ct);
            if (user is { IsActive: true })
            {
                var token = workflow.Protect(SlimWorkflowTokens.PasswordResetPurpose,
                    new SlimResetTokenPayload(user.Id, user.SecurityStamp), O.Tokens.PasswordResetTokenLifetime);
                var address = user.Email;
                var link = SlimWorkflowTokens.BuildLink(O.Links.PasswordResetTemplate, token);
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
        if (user is null || !user.IsActive || !SlimHashing.FixedTimeEquals(user.SecurityStamp, payload.Stamp))
            return SlimResults.InvalidToken();

        if (await passwordPolicy.ValidateAsync(request!.NewPassword, user.Email, ct, "newPassword") is { } errors)
            return SlimResults.Validation(errors);

        credentials.ApplyNewPassword(user, request.NewPassword); // rotates stamp → token single-use, all sessions revoked
        if (!user.EmailConfirmed && !payload.ByAdministrator)   // a link handed over by an administrator proves no mailbox
        {
            // First proof of the mailbox: whoever registered the address before (possibly an attacker – pre-account
            // hijacking) must keep neither a second factor that locks the real owner out nor a linked external login.
            user.TwoFactorEnabled = false;
            if (services.GetService<SlimTwoFactorService>() is { } twoFactor)
            {
                await twoFactor.RemoveSecretAsync(user, ct);
                await twoFactor.RemoveRecoveryCodesAsync(user, ct);
            }
            if (services.GetService<ISlimExternalLoginStore>() is { } externalLogins)
                await externalLogins.RemoveExternalLoginsAsync(user.Id, ct);
            user.EmailConfirmed = true;
        }
        await store.UpdateSecurityStateAsync(user, ct);
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
            return SlimResults.BadRequest("email_unchanged", "The new address equals the current one.");

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
            var link = SlimWorkflowTokens.BuildLink(O.Links.EmailChangeTemplate, token);
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
            || !SlimHashing.FixedTimeEquals(user.SecurityStamp, payload.Stamp))
            return SlimResults.InvalidToken();

        // the confirming person controls the new mailbox, so revealing that it is taken is fine here
        if (!await store.UpdateEmailAsync(user, payload.NewEmail, ct))
            return SlimResults.BadRequest("email_taken", "The address is already used by another account.");

        user.Email = payload.NewEmail;
        user.EmailConfirmed = true;
        user.SecurityStamp = SlimUser.NewSecurityStamp(); // link single use; sessions carry the old address → sign in again
        await store.UpdateSecurityStateAsync(user, ct);
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
            return SlimResults.BadRequest("password_managed_externally",
                "Passwords are validated externally (LDAP / custom validator); invitations cannot set one.");
        if (await passwordPolicy.ValidateAsync(request!.Password, user.Email, ct) is { } errors)
            return SlimResults.Validation(errors);

        credentials.ApplyNewPassword(user, request.Password); // rotates the stamp → the link is single-use
        user.EmailConfirmed = true;                            // the invitation was delivered to this mailbox
        await store.UpdateSecurityStateAsync(user, ct);
        await authManager.RevokeSessionsAsync(user.Id, exceptSessionId: null, ct);
        Log.InvitationAccepted(logger, user.Id);
        await hooks.RaiseAsync(SlimEventTypes.PasswordChanged, user.Id, reason: "invitation", ct: ct);
        metrics.Invitation("accepted");

        // 2FA users (pre-provisioned by the host) sign in normally to pass the second factor
        if (user.TwoFactorEnabled)
            return SlimResults.Status("invitation_accepted", "Password set. Please sign in.");

        var result = await authManager.SignInCoreAsync(user, cookies, false, SlimAuthManager.MethodPassword, null, null, true, ct);
        if (result.Vetoed) return SlimResults.Status(result.Error!, result.ErrorMessage ?? "The sign-in was refused.", StatusCodes.Status403Forbidden);
        return result.Succeeded ? Results.Ok(result.ToResponse(time.GetUtcNow())) : SlimResults.InvalidToken();
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
            || !SlimHashing.FixedTimeEquals(user.SecurityStamp, payload.Stamp))
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
            return SlimResults.Status("session_not_found", "The session does not exist.", StatusCodes.Status404NotFound);

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

        if (request is null || string.IsNullOrEmpty(request.CurrentPassword))
            return SlimResults.BadRequest("invalid_request", "currentPassword is required.");
        if (await passwordPolicy.ValidateAsync(request.NewPassword, user.Email, ct, "newPassword") is { } errors)
            return SlimResults.Validation(errors);

        if (await credentials.ConfirmPasswordAsync(user, request.CurrentPassword, Http, ct) is { } failure)
            return failure;

        credentials.ApplyNewPassword(user, request.NewPassword); // rotates stamp → other devices are signed out
        await store.UpdateSecurityStateAsync(user, ct);
        await authManager.RevokeSessionsAsync(user.Id, SlimAuthManager.CurrentSessionId(Http.User), ct);
        await hooks.RaiseAsync(SlimEventTypes.PasswordChanged, user.Id, reason: "changed", ct: ct);

        // keep the calling device signed in
        var session = await authManager.RefreshCurrentSessionAsync(user, ct);
        return Results.Ok(session.ToResponse(time.GetUtcNow()));
    }

    // ------------------------------------------------------------------ GET /me (authenticated)

    public IResult Me()
    {
        var principal = Http.User;
        var id = principal.GetSlimUserId();
        if (id is null) return Results.Unauthorized();

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

    internal async Task<(SlimUser? User, IResult? Error)> LoadCurrentUserAsync(bool forbidImpersonation, CancellationToken ct)
    {
        var principal = Http.User;
        var id = principal.GetSlimUserId();
        if (id is null) return (null, Results.Unauthorized());

        if (forbidImpersonation && principal.IsImpersonating())
            return (null, SlimResults.Status("not_allowed_while_impersonating",
                "This action is not allowed during an impersonation session.", StatusCodes.Status403Forbidden));

        var user = await store.FindByIdAsync(id, ct);
        return user is { IsActive: true } ? (user, null) : (null, Results.Unauthorized());
    }

    private static bool IsValidEmail(string? email) =>
        !string.IsNullOrEmpty(email) && email.Length <= MaxEmailLength && MailAddress.TryCreate(email, out _);

    private static IResult InvalidEmail(string field) =>
        SlimResults.Validation(new Dictionary<string, string[]> { [field] = ["A valid e-mail address is required."] });
}
