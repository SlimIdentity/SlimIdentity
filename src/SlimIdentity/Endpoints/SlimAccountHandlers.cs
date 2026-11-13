using SlimIdentity.Contracts;
using SlimIdentity.Http;
using SlimIdentity.Security;
using SlimIdentity.Services;

namespace SlimIdentity.Endpoints;

/// <summary>Registration, e-mail change, password flows, sessions and <c>/me</c>.</summary>
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
    SlimSharedStateAccess sharedState,
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

    public async Task<IResult> RegisterAsync(SlimRegisterRequest? request, bool? useCookies, CancellationToken ct)
    {
        // with mail the mailbox is proven before the account exists
        if (O.Email.Enabled) return await services.GetRequiredService<SlimRegistrationFlow>().BeginAsync(request, useCookies, ct);

        var (email, invalid) = await registration.ValidateAsync(request?.Email, request?.Password, ct);
        if (invalid is not null) return invalid;

        // business data – validated from the request alone, before anything is looked up (no enumeration)
        var (profile, invalidProfile) = await registration.ValidateProfileAsync(email!, request!.Profile, ct);
        if (invalidProfile is not null) return invalidProfile;

        return await registration.CreateAsync(email!, request.Password!, profile, ct);
    }

    // ------------------------------------------------------------------ POST /forgot-password

    public async Task<IResult> ForgotPasswordAsync(SlimEmailRequest? request, CancellationToken ct)
    {
        var email = SlimEmailAddress.Normalize(request?.Email);
        if (!string.IsNullOrEmpty(email))
        {
            var user = await store.FindByEmailAsync(email, ct);
            // a pure SSO account gets no local password; an unconfirmed one still may (first proof of the mailbox)
            if (user is { IsActive: true } && !(user.EmailConfirmed && await credentials.SignsInOnlyExternallyAsync(user, ct)))
            {
                var flowId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
                var token = workflow.Protect(SlimWorkflowTokens.LinkPurpose,
                    new SlimLinkPayload(SlimLinkPayload.Reset, flowId, Uid: user.Id, Stamp: user.SecurityStamp), O.Tokens.PasswordResetTokenLifetime);
                var address = user.Email;
                var link = links.Build(SlimLinkKind.PasswordReset, token);
                await mail.SendAsync(SlimEmailKinds.PasswordReset, address, user.Id, (s, x, c) => s.SendPasswordResetEmailAsync(x, address, link, c), ct);
                metrics.PasswordReset("requested");
            }
        }
        return SlimResults.Status("reset_requested", "If the account exists, a reset e-mail has been sent.");
    }

    // ------------------------------------------------------------------ POST /change-email & /change-email/confirm

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

        // Enumeration prevention: same answer whether or not the new address is already used. Its owner gets an
        // "account exists" notice instead of a code, so the confirmation fails like a wrong code.
        var target = newEmail!;
        var issuedAt = time.GetUtcNow().ToUnixTimeMilliseconds();
        string? codeHash = null;
        var owner = await store.FindByEmailAsync(target, ct);
        if (owner is null)
        {
            var code = SlimTotp.GenerateNumericCode();
            if (await mail.SendAsync(SlimEmailKinds.EmailChange, target, user.Id, (s, x, c) => s.SendEmailChangeCodeAsync(x, target, code, c), ct))
                codeHash = HashEmailChangeCode(user.Id, target, code, issuedAt);
        }
        else
        {
            await mail.SendAsync(SlimEmailKinds.AccountExists, target, owner.Id, (s, x, c) => s.SendAccountExistsEmailAsync(x, target, c), ct);
        }

        var lifetime = SlimIdentityDefaults.EmailChangeLifetime;
        var flowId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var token = workflow.Protect(SlimWorkflowTokens.EmailChangePurpose,
            new SlimEmailChangePayload(user.Id, flowId, target, user.SecurityStamp, codeHash, issuedAt), lifetime);

        Log.EmailChangeRequested(logger, user.Id);
        metrics.EmailChange("requested");
        return Results.Ok(new SlimEmailChangeResponse("email_change_requested", token, (int)lifetime.TotalSeconds));
    }

    // The code is bound to the account and its stamp, not to the session: every session of the account may enter it.
    public async Task<IResult> ConfirmEmailChangeAsync(SlimConfirmEmailChangeRequest? request, CancellationToken ct)
    {
        var (user, error) = await LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;

        if (!workflow.TryUnprotect<SlimEmailChangePayload>(SlimWorkflowTokens.EmailChangePurpose, request?.Token, out var payload)
            || !string.Equals(payload.Uid, user.Id, StringComparison.Ordinal)
            || !SlimUser.IsSameSecurityState(user.SecurityStamp, payload.Stamp))
            return SlimResults.InvalidToken();

        // counted before the check: of parallel guesses, at most the limit is checked
        if (await sharedState.CountAsync(SlimSharedStateAccess.VerificationCodeFlow, payload.FlowId, SlimIdentityDefaults.EmailChangeLifetime, ct) > SlimLoginHandlers.VerificationAttemptsPerFlow
            || await sharedState.CountAsync(SlimSharedStateAccess.VerificationCodeAddress, payload.NewEmail.Trim().ToUpperInvariant(), SlimLoginHandlers.VerificationAddressWindow, ct) > SlimLoginHandlers.VerificationAttemptsPerAddress)
        {
            metrics.EmailChange(SlimErrorCodes.TooManyAttempts);
            return SlimResults.Status(SlimErrorCodes.TooManyAttempts, "Too many attempts. Request a new code.", StatusCodes.Status429TooManyRequests);
        }

        var code = SlimTotp.NormalizeCode(request!.Code);
        if (code.Length != 6 || payload.CodeHash is null
            || !SlimHashing.FixedTimeEquals(HashEmailChangeCode(user.Id, payload.NewEmail, code, payload.IssuedAt), payload.CodeHash))
        {
            metrics.EmailChange(SlimErrorCodes.InvalidVerificationCode);
            return SlimResults.BadRequest(SlimErrorCodes.InvalidVerificationCode, "The code is invalid.");
        }

        // address, confirmation and a new stamp in one write: the code works once, other sessions end
        var oldEmail = user.Email;
        var newStamp = SlimUser.NewSecurityStamp();
        for (var attempt = 0; ; attempt++)
        {
            var outcome = await store.UpdateEmailAsync(user, payload.NewEmail, user.SecurityStamp ?? string.Empty, newStamp, ct);
            // taken since the request: the confirming person controls the new mailbox, so revealing it is fine here
            if (outcome == SlimEmailUpdateResult.EmailTaken)
                return SlimResults.BadRequest(SlimErrorCodes.EmailTaken, "The address is already used by another account.");
            if (outcome == SlimEmailUpdateResult.Updated) break;
            // only the claims part changed in between: the code still stands for the current state
            var current = await store.FindByIdAsync(user.Id, ct);
            if (attempt == 2 || current is null || !SlimUser.IsSameSecurityState(current.SecurityStamp, payload.Stamp))
                return SlimResults.ConcurrentChange();
            user = current;
        }
        (user.Email, user.EmailConfirmed, user.SecurityStamp) = (payload.NewEmail, true, newStamp);
        await authManager.RevokeSessionsAsync(user.Id, SlimAuthManager.CurrentSessionId(Http.User), ct);

        var newEmail = payload.NewEmail;
        await mail.SendAsync(SlimEmailKinds.EmailChanged, oldEmail, user.Id, (s, x, c) => s.SendEmailChangedNotificationAsync(x, oldEmail, newEmail, c), ct);

        Log.EmailChanged(logger, user.Id);
        await hooks.RaiseAsync(SlimEventTypes.EmailChanged, user.Id, ct: ct);
        metrics.EmailChange("completed");

        // keep the calling device signed in, with the new address in its claims
        return SlimResults.ReissuedSession(await authManager.RefreshCurrentSessionAsync(user, ct));
    }

    /// <summary>Bound to account and new address: the code proves this mailbox for this change only.</summary>
    private static string HashEmailChangeCode(string userId, string email, string code, long issuedAt) =>
        SlimHashing.Sha256Hex($"slimidentity.email-change-code.v1:{userId}:{email.Trim().ToUpperInvariant()}:{issuedAt}:{code}");

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
