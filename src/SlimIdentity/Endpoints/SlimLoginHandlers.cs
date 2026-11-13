using SlimIdentity.Contracts;
using SlimIdentity.Http;
using SlimIdentity.Security;
using SlimIdentity.Services;

namespace SlimIdentity.Endpoints;

/// <summary>Password sign-in and its step endpoints (<see cref="SlimSignInFlow"/>); refresh rotation; logout.</summary>
internal sealed class SlimLoginHandlers(
    ISlimUserStore store,
    SlimPasswordPolicy passwordPolicy,
    SlimHookRunner hooks,
    SlimCredentialService credentials,
    SlimAuthManager authManager,
    SlimSignInFlow flow,
    SlimSharedStateAccess sharedState,
    SlimWorkflowTokens workflow,
    SlimMetrics metrics,
    IOptions<SlimIdentityOptions> options,
    TimeProvider time,
    IHttpContextAccessor httpContextAccessor,
    IServiceProvider services,
    ILogger<SlimLoginHandlers> logger)
{
    internal const string MethodTotp = "totp";
    internal const string MethodEmail = "email";
    internal const string MethodRecovery = "recovery";

    // attempts at the code of step verify_email: per sign-in, and per address across sign-ins
    internal const int VerificationAttemptsPerFlow = 5;
    internal const int VerificationAttemptsPerAddress = 10;
    internal static readonly TimeSpan VerificationAddressWindow = TimeSpan.FromHours(24);

    private SlimIdentityOptions O => options.Value;
    private HttpContext Http => httpContextAccessor.HttpContext!;

    // ------------------------------------------------------------------ POST /login

    public async Task<IResult> LoginAsync(SlimLoginRequest? request, bool? useCookies, CancellationToken ct)
    {
        if (!SlimModes.TryResolve(O, useCookies, out var cookies, out var modeError)) return modeError!;
        var email = SlimEmailAddress.Normalize(request?.Email);
        if (request is null || email is null || string.IsNullOrEmpty(request.Password))
            return SlimResults.BadRequest(SlimErrorCodes.InvalidRequest, "E-mail and password are required.");

        // Oversized passwords are never hashed (DoS) – identical answer for known and unknown accounts.
        if (request.Password.Length > O.Password.MaximumLength) return Failed(SlimErrorCodes.InvalidPassword);

        var found = await store.FindByEmailAsync(email, ct);
        if (found is null)
        {
            credentials.BurnDummyHash(request.Password); // timing-attack mitigation
            await hooks.RaiseAsync(SlimEventTypes.SignInFailed, null, SlimAuthManager.MethodPassword, SlimErrorCodes.UnknownUser, ct: ct);
            return Failed(SlimErrorCodes.UnknownUser);
        }

        var (result, burnDummyHash) = await LoginWithPasswordAsync(found, request, cookies, ct);
        if (burnDummyHash) credentials.BurnDummyHash(request.Password);   // same hashing time as a real verification
        return result;

        IResult Failed(string reason)
        {
            metrics.Login(reason, cookies);
            return SlimResults.InvalidCredentials();
        }
    }

    /// <summary>
    /// The password step for one account. <c>BurnDummyHash</c>: the caller burns the time of a verification (inactive,
    /// locked or not reserved – the password was not checked).
    /// </summary>
    private async Task<(IResult Result, bool BurnDummyHash)> LoginWithPasswordAsync(SlimUser user, SlimLoginRequest request, bool cookies, CancellationToken ct)
    {
        // Inactive / locked accounts: by default indistinguishable from a wrong password (same answer, same hashing time).
        // Attempts during a lockout are neither verified nor counted.
        var reveal = O.SignIn.RevealAccountState;
        var now = time.GetUtcNow();
        if (!user.IsActive)
        {
            metrics.Login(SlimErrorCodes.AccountDisabled, cookies);
            await hooks.RaiseAsync(SlimEventTypes.SignInFailed, user.Id, SlimAuthManager.MethodPassword, SlimErrorCodes.AccountDisabled, ct: ct);
            return reveal
                ? (SlimResults.Status(SlimErrorCodes.AccountDisabled, "The account is disabled.", StatusCodes.Status403Forbidden), false)
                : (SlimResults.InvalidCredentials(), true);
        }

        // An account without a password cannot be guessed: counting would only let anyone lock its owner out. Answered
        // like a wrong password, with the same hashing time.
        if (!await credentials.HasPasswordAsync(user, ct))
        {
            metrics.Login(SlimErrorCodes.InvalidPassword, cookies);
            await hooks.RaiseAsync(SlimEventTypes.SignInFailed, user.Id, SlimAuthManager.MethodPassword, SlimErrorCodes.InvalidPassword, ct: ct);
            return (SlimResults.InvalidCredentials(), true);
        }

        // Reserved in the store before the check (keyed by the user id - every spelling of the address the store treats
        // as equal shares it): of parallel guesses, at most the threshold is checked, on every instance together.
        var attempt = await credentials.BeginAttemptAsync(user, SlimAttemptFactor.Password, ct);
        if (attempt.Status != SlimAttemptStatus.Reserved)
        {
            var reason = attempt.Status == SlimAttemptStatus.LockedOut ? SlimErrorCodes.LockedOut : SlimErrorCodes.AttemptNotReserved;
            metrics.Login(reason, cookies);
            await hooks.RaiseAsync(SlimEventTypes.SignInFailed, user.Id, SlimAuthManager.MethodPassword, reason, ct: ct);
            return reveal && attempt.LockoutEndUtc is { } end ? (SlimResults.Locked(Http, end, now), false) : (SlimResults.InvalidCredentials(), true);
        }

        var check = await credentials.VerifyPasswordAsync(user, request.Password, ct);
        if (check == SlimPasswordCheck.Failed)
        {
            metrics.Login(SlimErrorCodes.InvalidPassword, cookies);
            await hooks.RaiseAsync(SlimEventTypes.SignInFailed, user.Id, SlimAuthManager.MethodPassword, SlimErrorCodes.InvalidPassword, ct: ct);
            var lockedUntil = await credentials.FailAttemptAsync(user, attempt, ct);
            return (lockedUntil is { } end && reveal ? SlimResults.Locked(Http, end, now) : SlimResults.InvalidCredentials(), false);
        }

        // the second factor has its own counter: resetting the password counter opens no way to guess codes
        await credentials.SucceedAttemptAsync(user, attempt, ct);
        await credentials.RehashAsync(user, request.Password, check, ct);

        var result = await flow.StartAsync(user, cookies, request.RememberMe, SlimAuthManager.MethodPassword, SlimSignInProofs.Password,
            checkRememberedDevice: true, request.TwoFactorRememberToken, refuseLockedSecondFactor: true, ct);
        metrics.Login(SlimSignInFlow.MetricReason(result), cookies);
        return (flow.ToHttpResult(result, user), false);
    }

    // ------------------------------------------------------------------ POST /flow

    public Task<IResult> ReadFlowAsync(SlimFlowRequest? request, CancellationToken ct) => flow.ReadAsync(request, ct);

    // ------------------------------------------------------------------ POST /login/verify-email

    public async Task<IResult> VerifyEmailAsync(SlimVerifyEmailLoginRequest? request, CancellationToken ct)
    {
        if (request is null || !flow.TryRead(request.FlowToken, out var state, out _))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        // ends in a cookie sign-in without carrying a cookie – only the signed token knows (as on /login/2fa)
        if (state.UseCookies && SlimCsrfEndpointFilter.Validate(Http.Request, O, logger) is { } csrfError) return csrfError;

        // once confirmed, the step is no longer open: the token cannot confirm twice
        var user = await flow.FindUserAsync(state, ct);
        if (user is null || state.Method != SlimSignInActions.VerifyEmail || SlimSignInChain.Evaluate(user, state.Proofs, O).Next != SlimSignInActions.VerifyEmail)
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        // a lockout of the password that started after the token was issued holds
        var now = time.GetUtcNow();
        if (state.Proofs.HasFlag(SlimSignInProofs.Password) && user.IsLockedOut(now)) return SlimResults.Locked(Http, user.LockoutEndUtc!.Value, now);

        // counted before the check: of parallel guesses, at most the limit is checked
        if (await sharedState.CountAsync(SlimSharedStateAccess.VerificationCodeFlow, state.FlowId, SlimIdentityDefaults.SignInFlowLifetime, ct) > VerificationAttemptsPerFlow
            || await sharedState.CountAsync(SlimSharedStateAccess.VerificationCodeAddress, user.Email.Trim().ToUpperInvariant(), VerificationAddressWindow, ct) > VerificationAttemptsPerAddress)
        {
            metrics.Login(SlimErrorCodes.TooManyAttempts, state.UseCookies);
            return SlimResults.Status(SlimErrorCodes.TooManyAttempts,
                "Too many attempts. Confirm the address with the link of a verification mail.", StatusCodes.Status429TooManyRequests);
        }

        var code = SlimTotp.NormalizeCode(request.Code);
        if (code.Length != 6 || state.CodeHash is null
            || !SlimHashing.FixedTimeEquals(SlimSignInFlow.HashVerificationCode(user.Id, user.Email, code, state.IssuedAt), state.CodeHash))
        {
            metrics.Login(SlimErrorCodes.InvalidVerificationCode, state.UseCookies);
            await hooks.RaiseAsync(SlimEventTypes.SignInFailed, user.Id, state.Amr, SlimErrorCodes.InvalidVerificationCode, ct: ct);
            return SlimResults.Status(SlimErrorCodes.InvalidVerificationCode, "The code is invalid.", StatusCodes.Status401Unauthorized);
        }

        if (!await store.TryWriteSecurityStateAsync(user, u => u.EmailConfirmed = true, ct))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);
        await hooks.RaiseAsync(SlimEventTypes.EmailConfirmed, user.Id, ct: ct);

        var result = await flow.ContinueAsync(user, state with { Stamp = user.SecurityStamp, Method = null, CodeHash = null, IssuedAt = 0 }, ct);
        metrics.Login(SlimSignInFlow.MetricReason(result), state.UseCookies);
        return flow.ToHttpResult(result, user);
    }

    // ------------------------------------------------------------------ POST /login/password-change

    public async Task<IResult> CompletePasswordChangeAsync(SlimPasswordChangeLoginRequest? request, CancellationToken ct)
    {
        if (request is null || !flow.TryRead(request.FlowToken, out var state, out _))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        // ends in a cookie sign-in without carrying a cookie – only the signed token knows (as on /login/2fa)
        if (state.UseCookies && SlimCsrfEndpointFilter.Validate(Http.Request, O, logger) is { } csrfError) return csrfError;

        // the stamp rotates with the new password: the token works once, and a newer administrator password kills it
        var user = await flow.FindUserAsync(state, ct);
        if (user is null || SlimSignInChain.Evaluate(user, state.Proofs, O).Next != SlimSignInActions.ChangePassword)
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        // a lockout of the password that started after the token was issued holds; the new password must not lift it
        var now = time.GetUtcNow();
        if (state.Proofs.HasFlag(SlimSignInProofs.Password) && user.IsLockedOut(now)) return SlimResults.Locked(Http, user.LockoutEndUtc!.Value, now);

        if (await passwordPolicy.ValidateAsync(request.NewPassword, user.Email, ct, "newPassword") is { } errors)
            return SlimResults.Validation(errors);
        if (await credentials.VerifyPasswordAsync(user, request.NewPassword, ct) != SlimPasswordCheck.Failed)
            return SlimResults.BadRequest(SlimErrorCodes.PasswordUnchanged, "Choose a password different from the one set by the administrator.");

        if (!await store.TryWriteSecurityStateAsync(user, u => credentials.ApplyNewPassword(u, request.NewPassword), ct))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);
        await authManager.RevokeSessionsAsync(user.Id, exceptSessionId: null, ct);
        Log.ForcedPasswordChangeCompleted(logger, user.Id);
        await hooks.RaiseAsync(SlimEventTypes.PasswordChanged, user.Id, reason: "forced_change", ct: ct);

        var result = await flow.ContinueAsync(user, state with { Stamp = user.SecurityStamp }, ct);
        metrics.Login(SlimSignInFlow.MetricReason(result), state.UseCookies);
        return flow.ToHttpResult(result, user);
    }

    // ------------------------------------------------------------------ POST /login/2fa

    public async Task<IResult> LoginTwoFactorAsync(SlimTwoFactorLoginRequest? request, CancellationToken ct)
    {
        var twoFactor = services.GetRequiredService<SlimTwoFactorService>();
        if (request is null || !flow.TryRead(request.FlowToken, out var state, out _))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        // This request carries no session cookie and no useCookies flag – only the signed token knows that it ends in
        // a cookie sign-in, so the CSRF filter cannot classify it. Check here.
        if (state.UseCookies && SlimCsrfEndpointFilter.Validate(Http.Request, O, logger) is { } csrfError) return csrfError;

        var user = await flow.FindUserAsync(state, ct);
        if (user is null || state.Method is null or SlimSignInActions.VerifyEmail || SlimSignInChain.Evaluate(user, state.Proofs, O).Next != SlimSignInActions.SecondFactor)
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        // reserved in the store before the check: of parallel guesses, at most the threshold is checked
        var now = time.GetUtcNow();
        var attempt = await credentials.BeginAttemptAsync(user, SlimAttemptFactor.SecondFactor, ct);
        if (attempt.Status == SlimAttemptStatus.LockedOut) return SlimResults.Locked(Http, attempt.LockoutEndUtc!.Value, now);
        if (attempt.Status == SlimAttemptStatus.NotReserved)
        {
            metrics.TwoFactor(state.Method, SlimErrorCodes.AttemptNotReserved);
            return SlimResults.Status(SlimErrorCodes.InvalidTwoFactorCode, "The code is invalid.", StatusCodes.Status401Unauthorized);
        }

        string method;
        bool valid;
        if (!string.IsNullOrWhiteSpace(request.RecoveryCode))
        {
            method = MethodRecovery;
            valid = await twoFactor.ConsumeRecoveryCodeAsync(user, request.RecoveryCode, ct);
            if (valid) Log.RecoveryCodeUsed(logger, user.Id);
        }
        else if (state.Method == MethodTotp)
        {
            method = MethodTotp;
            var secret = await twoFactor.GetSecretAsync(user, ct);
            valid = secret.Value is not null && await twoFactor.VerifyTotpAsync(user, secret.Value, request.Code, ct);
        }
        else
        {
            method = MethodEmail;
            var code = SlimTotp.NormalizeCode(request.Code);
            valid = code.Length == 6 && state.CodeHash is not null
                && SlimHashing.FixedTimeEquals(SlimSignInFlow.HashEmailCode(user.Id, code, state.IssuedAt), state.CodeHash)
                && await twoFactor.ConsumeEmailCodeAsync(user, state.IssuedAt, ct);
        }

        if (!valid)
        {
            metrics.TwoFactor(method, "failure");
            await hooks.RaiseAsync(SlimEventTypes.SignInFailed, user.Id, method, SlimErrorCodes.InvalidTwoFactorCode, ct: ct);
            return await credentials.FailAttemptAsync(user, attempt, ct) is { } lockedUntil
                ? SlimResults.Locked(Http, lockedUntil, now)
                : SlimResults.Status(SlimErrorCodes.InvalidTwoFactorCode, "The code is invalid.", StatusCodes.Status401Unauthorized);
        }

        // the factor is proven: its counter starts over, even if the challenge was already used
        await credentials.SucceedAttemptAsync(user, attempt, ct);

        // The challenge is passed at most once. Checked after the factor, so a typo does not burn the challenge; two
        // parallel requests with different valid factors still continue the sign-in only once.
        if (!await twoFactor.ConsumeChallengeAsync(user, state.IssuedAt, ct))
        {
            metrics.TwoFactor(method, "challenge_reused");
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);
        }

        metrics.TwoFactor(method, "success");

        // "remember this device" – only after a real second factor, never after a recovery code
        var next = state with
        {
            Proofs = state.Proofs | SlimSignInProofs.SecondFactor,
            Amr = SlimAuthManager.MethodMfa,
            RememberDevice = request.RememberDevice && method != MethodRecovery,
            Method = null,
            CodeHash = null,
            IssuedAt = 0,
        };
        return flow.ToHttpResult(await flow.ContinueAsync(user, next, ct), user);
    }

    // ------------------------------------------------------------------ POST /refresh

    public async Task<IResult> RefreshAsync(SlimRefreshRequest? request, CancellationToken ct)
    {
        var refreshStore = services.GetRequiredService<ISlimRefreshTokenStore>();
        if (request is null || string.IsNullOrWhiteSpace(request.RefreshToken))
            return SlimResults.BadRequest(SlimErrorCodes.InvalidRequest, "refreshToken is required.");

        // signature + expiry of the token itself (DataProtector) – forged or expired tokens never reach the store
        if (!workflow.TryUnprotect<SlimRefreshPayload>(SlimWorkflowTokens.RefreshTokenPurpose, request.RefreshToken, out var payload, out var tokenExpiresAt))
            return RefreshFailed("invalid");

        // consume first: a token can be used at most once
        var owner = await refreshStore.ValidateAndConsumeRefreshTokenAsync(SlimHashing.Sha256Hex(request.RefreshToken), ct);
        var user = await store.FindByIdAsync(payload.Uid, ct);
        var stampValid = user is not null && SlimUser.IsSameSecurityState(user.SecurityStamp, payload.Stamp);

        if (owner is null)
        {
            // A genuine, unexpired token whose stamp is still current but that is no longer in the store has been
            // used before (or was logged out): RFC 9700 says treat it as stolen and revoke the token family.
            // Tokens at the very end of their lifetime are excluded – the store may already have expired them
            // (clock drift between app and database), which is not a replay.
            var clearlyUnexpired = tokenExpiresAt - time.GetUtcNow() > O.Tokens.ClockSkew;
            if (stampValid && clearlyUnexpired)
            {
                await HandleRefreshTokenReuseAsync(user!, payload, ct);
                return RefreshFailed("reuse_detected");
            }
            Log.UnknownRefreshToken(logger, payload.Uid);
            return RefreshFailed("invalid");
        }

        if (!string.Equals(owner, payload.Uid, StringComparison.Ordinal) || user is null || !user.IsActive || !stampValid)
            return RefreshFailed("invalid");

        // server-side session revoked (logout on that device, "sign out other devices", …)?
        if (payload.Sid is not null && services.GetService<ISlimSessionStore>() is { } sessions)
        {
            var session = await sessions.FindAsync(payload.Sid, ct);
            if (session is null || session.ExpiresUtc <= time.GetUtcNow())
                return RefreshFailed("invalid");
        }

        var result = await authManager.SignInCoreAsync(user, false, false, payload.Amr, null, null, true, ct,
            sessionId: payload.Sid, authTime: DateTimeOffset.FromUnixTimeSeconds(payload.AuthTime));
        if (!result.Succeeded && result.Error == SlimErrorCodes.SessionExpired)
        {
            metrics.Refresh(SlimErrorCodes.SessionExpired);
            return SlimResults.Status(SlimErrorCodes.SessionExpired, "The session has reached its maximum lifetime. Please sign in again.", StatusCodes.Status401Unauthorized);
        }

        metrics.Refresh(result.Succeeded ? "success" : "invalid");
        return ToResult(result);

        IResult RefreshFailed(string reason)
        {
            metrics.Refresh(reason);
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);
        }
    }

    private async Task HandleRefreshTokenReuseAsync(SlimUser user, SlimRefreshPayload payload, CancellationToken ct)
    {
        if (payload.Sid is not null && services.GetService<ISlimSessionStore>() is { } sessions)
        {
            // revoke the token family: the session and therefore every access / refresh token issued for it
            await sessions.RevokeAsync(payload.Sid, ct);
            Log.RefreshTokenReuseSession(logger, user.Id, payload.Sid);
            await hooks.RaiseAsync(SlimEventTypes.RefreshTokenReuse, user.Id, payload.Amr, ct: ct);
            return;
        }

        // stateless: the family cannot be identified, so all sessions of the user end
        await authManager.SignOutEverywhereAsync(user, ct);
        Log.RefreshTokenReuseAll(logger, user.Id);
        await hooks.RaiseAsync(SlimEventTypes.RefreshTokenReuse, user.Id, payload.Amr, ct: ct);
    }

    // ------------------------------------------------------------------ POST /logout & /logout-all

    public async Task<IResult> LogoutAsync(SlimLogoutRequest? request, CancellationToken ct)
    {
        await authManager.SignOutAsync(request?.RefreshToken, ct);
        return SlimResults.Status("logged_out");
    }

    public async Task<IResult> LogoutAllAsync(CancellationToken ct)
    {
        var userId = Http.User.GetSlimUserId();
        if (userId is null) return SlimResults.Unauthenticated();
        if (Http.User.IsImpersonating())
            return SlimResults.Status(SlimErrorCodes.NotAllowedWhileImpersonating, "This action is not allowed during an impersonation session.", StatusCodes.Status403Forbidden);

        var user = await store.FindByIdAsync(userId, ct);
        if (user is null) return SlimResults.Unauthenticated();

        await authManager.SignOutEverywhereAsync(user, ct);
        if (O.Endpoints.AllowCookieAuth) await Http.SignOutAsync(SlimIdentityDefaults.CookieScheme);
        return SlimResults.Status("logged_out_everywhere");
    }

    // ------------------------------------------------------------------ helpers

    internal static IResult ToResult(SlimAuthResult result)
    {
        if (result.ActionRequired is { } steps) return SlimResults.ActionRequired(steps);
        // a guard's veto follows a correct sign-in – its reason can be told; anything else stays uniform
        if (!result.Succeeded)
            return result.Vetoed
                ? SlimResults.Status(result.Error!, result.ErrorMessage ?? "The sign-in was refused.", StatusCodes.Status403Forbidden)
                : SlimResults.InvalidCredentials();
        var response = result.ToResponse();
        return Results.Ok(result.TwoFactorRememberToken is { } remember ? response.WithTwoFactorRememberToken(remember) : response);
    }
}

internal static class SlimModes
{
    public static bool TryResolve(SlimIdentityOptions o, bool? requested, out bool useCookies, out IResult? error)
    {
        useCookies = requested ?? o.EffectiveDefaultUseCookies;
        error = null;
        if (useCookies && !o.Endpoints.AllowCookieAuth)
            error = SlimResults.BadRequest(SlimErrorCodes.CookieAuthDisabled, "Cookie authentication is disabled.");
        else if (!useCookies && !o.JwtEnabled)
            error = SlimResults.BadRequest(SlimErrorCodes.JwtAuthDisabled, "JWT authentication is not configured (Tokens.JwtSecret).");
        return error is null;
    }
}
