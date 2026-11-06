using SlimIdentity.Contracts;
using SlimIdentity.Http;
using SlimIdentity.Security;
using SlimIdentity.Services;

namespace SlimIdentity.Endpoints;

/// <summary>Login state machine: password → (2FA) → session; refresh rotation; logout.</summary>
internal sealed class SlimLoginHandlers(
    ISlimUserStore store,
    ISlimEmailSender emailSender,
    SlimMailThrottle mailThrottle,
    SlimCredentialService credentials,
    SlimAuthManager authManager,
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

    private SlimIdentityOptions O => options.Value;
    private HttpContext Http => httpContextAccessor.HttpContext!;

    // ------------------------------------------------------------------ POST /login

    public async Task<IResult> LoginAsync(SlimLoginRequest? request, bool? useCookies, CancellationToken ct)
    {
        if (!SlimModes.TryResolve(O, useCookies, out var cookies, out var modeError)) return modeError!;
        var email = SlimEmailAddress.Normalize(request?.Email);
        if (request is null || email is null || string.IsNullOrEmpty(request.Password))
            return SlimResults.BadRequest("invalid_request", "E-mail and password are required.");

        // Oversized passwords are never hashed (DoS) – identical answer for known and unknown accounts.
        if (request.Password.Length > O.Password.MaximumLength) return Failed("invalid_password");

        // lockout check, verification and counting form one step per account – parallel guesses queue up here instead
        // of all passing the lockout check before the first failure is recorded (unknown accounts queue the same way)
        using var attempt = await credentials.EnterAttemptAsync(email, ct);
        var user = await store.FindByEmailAsync(email, ct);
        if (user is null)
        {
            credentials.BurnDummyHash(request.Password); // timing-attack mitigation
            return Failed("unknown_user");
        }

        // Inactive / locked accounts: by default indistinguishable from a wrong password (same answer, same hashing time).
        // Attempts during a lockout are neither verified nor counted.
        var reveal = O.SignIn.RevealAccountState;
        var now = time.GetUtcNow();
        if (!user.IsActive)
        {
            metrics.Login("inactive", cookies);
            if (reveal) return SlimResults.Status("account_disabled", "The account is disabled.", StatusCodes.Status403Forbidden);
            credentials.BurnDummyHash(request.Password);
            return SlimResults.InvalidCredentials();
        }
        if (user.IsLockedOut(now))
        {
            metrics.Login("locked_out", cookies);
            if (reveal) return SlimResults.Locked(Http, user.LockoutEndUtc!.Value, now);
            credentials.BurnDummyHash(request.Password);
            return SlimResults.InvalidCredentials();
        }

        var check = await credentials.VerifyPasswordAsync(user, request.Password, ct);
        if (check == SlimPasswordCheck.Failed)
        {
            metrics.Login("invalid_password", cookies);
            var locked = await credentials.RegisterFailureAsync(user, ct);
            return locked && reveal ? SlimResults.Locked(Http, user.LockoutEndUtc!.Value, now) : SlimResults.InvalidCredentials();
        }

        // With 2FA the lockout counter is only reset after the second factor – otherwise a known
        // password would allow unlimited guessing of the 6-digit code.
        await credentials.RegisterSuccessAsync(user, request.Password,
            rehash: check == SlimPasswordCheck.SuccessRehashNeeded,
            resetLockout: !user.TwoFactorEnabled, ct);

        if (O.SignIn.RequireConfirmedEmail && !user.EmailConfirmed)
        {
            metrics.Login("email_not_confirmed", cookies);
            return SlimResults.Status("email_not_confirmed", "The e-mail address has not been confirmed yet.", StatusCodes.Status403Forbidden);
        }

        // remembered device: the second factor was passed on this device before – the password was just verified
        if (user.TwoFactorEnabled && services.GetService<SlimTwoFactorService>() is { } twoFactor
            && twoFactor.IsRememberedDevice(user, Http, request.TwoFactorRememberToken))
        {
            await credentials.RegisterSuccessAsync(user, null, rehash: false, resetLockout: true, ct);
            metrics.TwoFactor("remembered_device", "success");
            var remembered = await authManager.SignInCoreAsync(user, cookies, request.RememberMe, SlimAuthManager.MethodRememberedDevice, null, null, true, ct);
            metrics.Login(remembered.Succeeded ? "success" : "rejected", cookies);
            return ToResult(remembered);
        }

        if (user.TwoFactorEnabled)
        {
            var challenge = await BeginTwoFactorAsync(user, cookies, request.RememberMe, ct);
            metrics.Login("requires_two_factor", cookies);
            return challenge is null
                ? Results.Problem(statusCode: 500, title: "Two-factor authentication is enabled for this user but ISlimTwoFactorStore is not registered.")
                : SlimResults.Challenge(challenge);
        }

        var result = await authManager.SignInCoreAsync(user, cookies, request.RememberMe, SlimAuthManager.MethodPassword, null, null, true, ct);
        metrics.Login(result.Succeeded ? "success" : "rejected", cookies);
        return ToResult(result);

        IResult Failed(string reason)
        {
            metrics.Login(reason, cookies);
            return SlimResults.InvalidCredentials();
        }
    }

    /// <summary>Creates the pre-auth token (and sends the e-mail code if no authenticator is configured).</summary>
    internal async Task<SlimLoginChallengeResponse?> BeginTwoFactorAsync(SlimUser user, bool useCookies, bool rememberMe, CancellationToken ct)
    {
        var twoFactor = services.GetService<SlimTwoFactorService>();
        if (twoFactor is null)
        {
            Log.TwoFactorStoreMissing(logger, user.Id);
            return null;
        }

        var issuedAt = time.GetUtcNow().ToUnixTimeMilliseconds();
        string method;
        string? codeHash = null;
        if ((await twoFactor.GetSecretAsync(user, ct)).Configured)
        {
            method = MethodTotp;
        }
        else
        {
            method = MethodEmail;
            var code = SlimTotp.GenerateNumericCode();
            codeHash = HashEmailCode(user.Id, code, issuedAt);
            // sent inline (the user waits for it); over the per-recipient limit the challenge is issued without a mail
            if (mailThrottle.TryAcquire(SlimMailKinds.TwoFactorCode, user.Email))
            {
                await emailSender.SendTwoFactorCodeAsync(user.Email, code, ct);
                metrics.Mail(SlimMailKinds.TwoFactorCode, "sent");
            }
            else
            {
                Log.MailThrottled(logger, SlimMailKinds.TwoFactorCode);
                metrics.Mail(SlimMailKinds.TwoFactorCode, "throttled");
            }
        }

        var lifetime = SlimIdentityDefaults.PreAuthTokenLifetime;
        var token = workflow.Protect(SlimWorkflowTokens.PreAuthPurpose,
            new SlimPreAuthPayload(user.Id, user.SecurityStamp, useCookies, rememberMe, method, codeHash, issuedAt), lifetime);

        return new SlimLoginChallengeResponse
        {
            Status = "requires_two_factor",
            Message = method == MethodTotp ? "Enter the code from your authenticator app." : "A code has been sent to your e-mail address.",
            PreAuthToken = token,
            TwoFactorMethod = method,
            ExpiresIn = (int)lifetime.TotalSeconds,
        };
    }

    // ------------------------------------------------------------------ POST /login/2fa

    public async Task<IResult> LoginTwoFactorAsync(SlimTwoFactorLoginRequest? request, CancellationToken ct)
    {
        var twoFactor = services.GetRequiredService<SlimTwoFactorService>();
        if (request is null || !workflow.TryUnprotect<SlimPreAuthPayload>(SlimWorkflowTokens.PreAuthPurpose, request.PreAuthToken, out var payload))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        // This request carries no session cookie and no useCookies flag – only the signed challenge knows that it ends in
        // a cookie sign-in, so the CSRF filter cannot classify it. Check here.
        if (payload.UseCookies && SlimCsrfEndpointFilter.Validate(Http.Request, O, logger) is { } csrfError) return csrfError;

        var user = await store.FindByIdAsync(payload.Uid, ct);
        if (user is null) return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        // one attempt per account at a time (shared with the password step); re-read inside the gate, a queued
        // predecessor may just have locked the account
        using var attempt = await credentials.EnterAttemptAsync(user.Email, ct);
        user = await store.FindByIdAsync(payload.Uid, ct);
        if (user is null || !user.IsActive || !SlimHashing.FixedTimeEquals(user.SecurityStamp, payload.Stamp))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        var now = time.GetUtcNow();
        if (user.IsLockedOut(now)) return SlimResults.Locked(Http, user.LockoutEndUtc!.Value, now);

        string method;
        bool valid;
        if (!string.IsNullOrWhiteSpace(request.RecoveryCode))
        {
            method = "recovery";
            valid = await twoFactor.ConsumeRecoveryCodeAsync(user, request.RecoveryCode, ct);
            if (valid) Log.RecoveryCodeUsed(logger, user.Id);
        }
        else if (payload.Method == MethodTotp)
        {
            method = MethodTotp;
            var secret = await twoFactor.GetSecretAsync(user, ct);
            valid = secret.Value is not null && await twoFactor.VerifyTotpAsync(user, secret.Value, request.Code, ct);
        }
        else
        {
            method = MethodEmail;
            var code = SlimTotp.NormalizeCode(request.Code);
            valid = code.Length == 6 && payload.CodeHash is not null
                && SlimHashing.FixedTimeEquals(HashEmailCode(user.Id, code, payload.IssuedAt), payload.CodeHash)
                && await twoFactor.ConsumeEmailCodeAsync(user, payload.IssuedAt, ct);
        }

        if (!valid)
        {
            metrics.TwoFactor(method, "failure");
            var locked = await credentials.RegisterFailureAsync(user, ct);
            return locked
                ? SlimResults.Locked(Http, user.LockoutEndUtc!.Value, now)
                : SlimResults.Status("invalid_two_factor_code", "The code is invalid.", StatusCodes.Status401Unauthorized);
        }

        // The challenge completes at most one sign-in. Checked after the factor, so a typo does not burn the challenge;
        // two parallel requests with different valid factors still yield only one session.
        if (!await twoFactor.ConsumeChallengeAsync(user, payload.IssuedAt, ct))
        {
            metrics.TwoFactor(method, "challenge_reused");
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);
        }

        metrics.TwoFactor(method, "success");
        await credentials.RegisterSuccessAsync(user, null, rehash: false, resetLockout: true, ct);

        if (!SlimModes.TryResolve(O, payload.UseCookies, out var cookies, out var modeError)) return modeError!;
        var result = await authManager.SignInCoreAsync(user, cookies, payload.RememberMe, SlimAuthManager.MethodMfa, null, null, true, ct);

        // "remember this device" – only after a real second factor, never after a recovery code
        var rememberToken = result.Succeeded && request.RememberDevice && method != "recovery"
            ? twoFactor.RememberDevice(user, Http, cookies)
            : null;
        return ToResult(result, rememberToken);
    }

    // ------------------------------------------------------------------ POST /refresh

    public async Task<IResult> RefreshAsync(SlimRefreshRequest? request, CancellationToken ct)
    {
        var refreshStore = services.GetRequiredService<ISlimRefreshTokenStore>();
        if (request is null || string.IsNullOrWhiteSpace(request.RefreshToken))
            return SlimResults.BadRequest("invalid_request", "refreshToken is required.");

        // signature + expiry of the token itself (DataProtector) – forged or expired tokens never reach the store
        if (!workflow.TryUnprotect<SlimRefreshPayload>(SlimWorkflowTokens.RefreshTokenPurpose, request.RefreshToken, out var payload, out var tokenExpiresAt))
            return RefreshFailed("invalid");

        // consume first: a token can be used at most once
        var owner = await refreshStore.ValidateAndConsumeRefreshTokenAsync(SlimHashing.Sha256Hex(request.RefreshToken), ct);
        var user = await store.FindByIdAsync(payload.Uid, ct);
        var stampValid = user is not null && SlimHashing.FixedTimeEquals(user.SecurityStamp, payload.Stamp);

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
        if (!result.Succeeded && result.Error == "session_expired")
        {
            metrics.Refresh("session_expired");
            return SlimResults.Status("session_expired", "The session has reached its maximum lifetime. Please sign in again.", StatusCodes.Status401Unauthorized);
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
            return;
        }

        // stateless: the family cannot be identified, so all sessions of the user end
        await authManager.SignOutEverywhereAsync(user, ct);
        Log.RefreshTokenReuseAll(logger, user.Id);
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
        if (userId is null) return Results.Unauthorized();
        if (Http.User.IsImpersonating())
            return SlimResults.Status("not_allowed_while_impersonating", "This action is not allowed during an impersonation session.", StatusCodes.Status403Forbidden);

        var user = await store.FindByIdAsync(userId, ct);
        if (user is null) return Results.Unauthorized();

        await authManager.SignOutEverywhereAsync(user, ct);
        if (O.Endpoints.AllowCookieAuth) await Http.SignOutAsync(SlimIdentityDefaults.CookieScheme);
        return SlimResults.Status("logged_out_everywhere");
    }

    // ------------------------------------------------------------------ helpers

    internal IResult ToResult(SlimAuthResult result, string? twoFactorRememberToken = null)
    {
        if (!result.Succeeded) return SlimResults.InvalidCredentials();
        var response = result.ToResponse(time.GetUtcNow());
        return Results.Ok(twoFactorRememberToken is null ? response : response.WithTwoFactorRememberToken(twoFactorRememberToken));
    }

    private static string HashEmailCode(string userId, string code, long issuedAt) =>
        SlimHashing.Sha256Hex($"slimidentity.email-code.v1:{userId}:{issuedAt}:{code}");
}

internal static class SlimModes
{
    public static bool TryResolve(SlimIdentityOptions o, bool? requested, out bool useCookies, out IResult? error)
    {
        useCookies = requested ?? o.EffectiveDefaultUseCookies;
        error = null;
        if (useCookies && !o.Endpoints.AllowCookieAuth)
            error = SlimResults.BadRequest("cookie_auth_disabled", "Cookie authentication is disabled.");
        else if (!useCookies && !o.JwtEnabled)
            error = SlimResults.BadRequest("jwt_auth_disabled", "JWT authentication is not configured (Tokens.JwtSecret).");
        return error is null;
    }
}
