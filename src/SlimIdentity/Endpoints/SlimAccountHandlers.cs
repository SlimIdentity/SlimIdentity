using SlimIdentity.Abstractions;
using SlimIdentity.Contracts;
using SlimIdentity.Http;
using SlimIdentity.Security;
using SlimIdentity.Services;
using System.Net.Mail;

namespace SlimIdentity.Endpoints;

/// <summary>Registration, e-mail verification, password flows and <c>/me</c>.</summary>
internal sealed class SlimAccountHandlers(
    ISlimUserStore store,
    SlimEmailDispatcher mail,
    SlimCredentialService credentials,
    SlimPasswordPolicy passwordPolicy,
    SlimAuthManager authManager,
    SlimWorkflowTokens workflow,
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
        var email = request?.Email?.Trim();
        if (string.IsNullOrEmpty(email) || email.Length > 256 || !MailAddress.TryCreate(email, out _))
            return SlimResults.Validation(new Dictionary<string, string[]> { ["email"] = ["A valid e-mail address is required."] });

        if (passwordPolicy.Validate(request!.Password) is { } errors)
            return SlimResults.Validation(errors);

        var accepted = SlimResults.Status("registration_accepted",
            "If the address can be used, a confirmation e-mail has been sent.");

        var existing = await store.FindByEmailAsync(email, ct);
        if (existing is not null)
        {
            // Enumeration prevention: identical response, comparable CPU time, a mail in both cases
            // (sent in the background, so the mail server's latency is not observable).
            credentials.HashPassword(new SlimUser { Email = email }, request.Password);
            logger.LogInformation("SlimIdentity: registration attempt for existing account {UserId}.", existing.Id);
            var existingEmail = existing.Email;
            await mail.SendAsync("account-exists", (s, c) => s.SendAccountExistsEmailAsync(existingEmail, c), ct);
            return accepted;
        }

        var hash = credentials.HashPassword(new SlimUser { Email = email }, request.Password);
        var user = await store.CreateAsync(email, hash, ct);

        if (O.Endpoints.EnableEmailVerification && !user.EmailConfirmed)
            await SendVerificationAsync(user, ct);

        return accepted;
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
        }
        return SlimResults.Status("email_confirmed");
    }

    public async Task<IResult> ResendVerificationAsync(SlimEmailRequest? request, CancellationToken ct)
    {
        var email = request?.Email?.Trim();
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
        var link = BuildLink(O.Links.EmailVerificationUrl, token);
        await mail.SendAsync("verification", (s, c) => s.SendVerificationEmailAsync(email, link, c), ct);
    }

    // ------------------------------------------------------------------ POST /forgot-password & /reset-password

    public async Task<IResult> ForgotPasswordAsync(SlimEmailRequest? request, CancellationToken ct)
    {
        var email = request?.Email?.Trim();
        if (!string.IsNullOrEmpty(email))
        {
            var user = await store.FindByEmailAsync(email, ct);
            if (user is { IsActive: true })
            {
                var token = workflow.Protect(SlimWorkflowTokens.PasswordResetPurpose,
                    new SlimResetTokenPayload(user.Id, user.SecurityStamp), O.Tokens.PasswordResetTokenLifetime);
                var address = user.Email;
                var link = BuildLink(O.Links.PasswordResetUrl, token);
                await mail.SendAsync("password-reset", (s, c) => s.SendPasswordResetEmailAsync(address, link, c), ct);
            }
        }
        return SlimResults.Status("reset_requested", "If the account exists, a reset e-mail has been sent.");
    }

    public async Task<IResult> ResetPasswordAsync(SlimResetPasswordRequest? request, CancellationToken ct)
    {
        if (!workflow.TryUnprotect<SlimResetTokenPayload>(SlimWorkflowTokens.PasswordResetPurpose, request?.Token, out var payload))
            return SlimResults.InvalidToken();

        if (passwordPolicy.Validate(request!.NewPassword, "newPassword") is { } errors)
            return SlimResults.Validation(errors);

        var user = await store.FindByIdAsync(payload.Uid, ct);
        if (user is null || !user.IsActive || !SlimHashing.FixedTimeEquals(user.SecurityStamp, payload.Stamp))
            return SlimResults.InvalidToken();

        credentials.ApplyNewPassword(user, request.NewPassword); // rotates stamp → token single-use, all sessions revoked
        user.EmailConfirmed = true;                               // the mailbox has just been proven
        await store.UpdateSecurityStateAsync(user, ct);
        await authManager.RevokeSessionsAsync(user.Id, exceptSessionId: null, ct);

        logger.LogInformation("SlimIdentity: password of user {UserId} reset.", user.Id);
        return SlimResults.Status("password_reset");
    }

    // ------------------------------------------------------------------ POST /invitation/info & /invitation/accept

    public async Task<IResult> InvitationInfoAsync(SlimInvitationInfoRequest? request, CancellationToken ct)
    {
        var (user, _, expiresAt) = await LoadInvitationAsync(request?.Token, ct);
        return user is null
            ? SlimResults.InvalidToken()
            : Results.Ok(new SlimInvitationInfoResponse(user.Email, expiresAt));
    }

    public async Task<IResult> AcceptInvitationAsync(SlimAcceptInvitationRequest? request, bool? useCookies, CancellationToken ct)
    {
        if (!SlimModes.TryResolve(O, useCookies, out var cookies, out var modeError)) return modeError!;

        var (user, _, _) = await LoadInvitationAsync(request?.Token, ct);
        if (user is null) return SlimResults.InvalidToken();

        if (services.GetService<ISlimCustomPasswordValidator>() is not null)
            return SlimResults.BadRequest("password_managed_externally",
                "Passwords are validated externally (LDAP / custom validator); invitations cannot set one.");
        if (passwordPolicy.Validate(request!.Password) is { } errors)
            return SlimResults.Validation(errors);

        credentials.ApplyNewPassword(user, request.Password); // rotates the stamp → the link is single-use
        user.EmailConfirmed = true;                            // the invitation was delivered to this mailbox
        await store.UpdateSecurityStateAsync(user, ct);
        await authManager.RevokeSessionsAsync(user.Id, exceptSessionId: null, ct);
        logger.LogInformation("SlimIdentity: invitation accepted by user {UserId}.", user.Id);

        // 2FA users (pre-provisioned by the host) sign in normally to pass the second factor
        if (user.TwoFactorEnabled)
            return SlimResults.Status("invitation_accepted", "Password set. Please sign in.");

        var result = await authManager.SignInCoreAsync(user, cookies, false, SlimAuthManager.MethodPassword, null, null, true, ct);
        return result.Succeeded ? Results.Ok(result.ToResponse(time.GetUtcNow())) : SlimResults.InvalidToken();
    }

    private async Task<(SlimUser? User, SlimInvitationPayload? Payload, DateTimeOffset ExpiresAt)> LoadInvitationAsync(string? token, CancellationToken ct)
    {
        if (!workflow.TryUnprotect<SlimInvitationPayload>(SlimWorkflowTokens.InvitationPurpose, token, out var payload, out var expiresAt))
            return (null, null, default);

        var user = await store.FindByIdAsync(payload.Uid, ct);
        if (user is null
            || !user.IsActive
            || !string.IsNullOrEmpty(user.PasswordHash) // already completed
            || !string.Equals(user.Email, payload.Email, StringComparison.OrdinalIgnoreCase)
            || !SlimHashing.FixedTimeEquals(user.SecurityStamp, payload.Stamp))
            return (null, null, default);

        return (user, payload, expiresAt);
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
        if (passwordPolicy.Validate(request.NewPassword, "newPassword") is { } errors)
            return SlimResults.Validation(errors);

        var now = time.GetUtcNow();
        if (user.IsLockedOut(now)) return SlimResults.Locked(Http, user.LockoutEndUtc!.Value, now);

        if (await credentials.VerifyPasswordAsync(user, request.CurrentPassword, ct) == SlimPasswordCheck.Failed)
        {
            var locked = await credentials.RegisterFailureAsync(user, ct);
            return locked
                ? SlimResults.Locked(Http, user.LockoutEndUtc!.Value, now)
                : SlimResults.BadRequest("invalid_password", "The current password is incorrect.");
        }

        credentials.ApplyNewPassword(user, request.NewPassword); // rotates stamp → other devices are signed out
        await store.UpdateSecurityStateAsync(user, ct);
        await authManager.RevokeSessionsAsync(user.Id, SlimAuthManager.CurrentSessionId(Http.User), ct);

        // keep the calling device signed in
        var session = await authManager.RefreshCurrentSessionAsync(user, ct);
        return Results.Ok(session.ToResponse(now));
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

    private static string BuildLink(string? template, string token) => SlimWorkflowTokens.BuildLink(template, token);
}
