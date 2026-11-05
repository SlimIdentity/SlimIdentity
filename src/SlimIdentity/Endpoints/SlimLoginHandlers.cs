using SlimIdentity.Abstractions;
using SlimIdentity.Contracts;
using SlimIdentity.Http;
using SlimIdentity.Security;
using SlimIdentity.Services;

namespace SlimIdentity.Endpoints;

/// <summary>Login state machine: password → (2FA) → session; refresh rotation; logout.</summary>
internal sealed class SlimLoginHandlers(
    ISlimUserStore store,
    ISlimEmailSender emailSender,
    SlimCredentialService credentials,
    SlimAuthManager authManager,
    SlimWorkflowTokens workflow,
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
        if (request is null || string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrEmpty(request.Password))
            return SlimResults.BadRequest("invalid_request", "E-mail and password are required.");

        // Oversized passwords are never hashed (DoS) – identical answer for known and unknown accounts.
        if (request.Password.Length > O.Password.MaximumLength) return SlimResults.InvalidCredentials();

        var user = await store.FindByEmailAsync(request.Email.Trim(), ct);
        if (user is null)
        {
            credentials.BurnDummyHash(request.Password); // timing-attack mitigation
            return SlimResults.InvalidCredentials();
        }

        // Inactive / locked accounts: by default indistinguishable from a wrong password (same answer, same hashing time).
        // Attempts during a lockout are neither verified nor counted.
        var reveal = O.SignIn.RevealAccountState;
        var now = time.GetUtcNow();
        if (!user.IsActive)
        {
            if (reveal) return SlimResults.Status("account_disabled", "The account is disabled.", StatusCodes.Status403Forbidden);
            credentials.BurnDummyHash(request.Password);
            return SlimResults.InvalidCredentials();
        }
        if (user.IsLockedOut(now))
        {
            if (reveal) return SlimResults.Locked(Http, user.LockoutEndUtc!.Value, now);
            credentials.BurnDummyHash(request.Password);
            return SlimResults.InvalidCredentials();
        }

        var check = await credentials.VerifyPasswordAsync(user, request.Password, ct);
        if (check == SlimPasswordCheck.Failed)
        {
            var locked = await credentials.RegisterFailureAsync(user, ct);
            return locked && reveal ? SlimResults.Locked(Http, user.LockoutEndUtc!.Value, now) : SlimResults.InvalidCredentials();
        }

        // With 2FA the lockout counter is only reset after the second factor – otherwise a known
        // password would allow unlimited guessing of the 6-digit code.
        await credentials.RegisterSuccessAsync(user, request.Password,
            rehash: check == SlimPasswordCheck.SuccessRehashNeeded,
            resetLockout: !user.TwoFactorEnabled, ct);

        if (O.SignIn.RequireConfirmedEmail && !user.EmailConfirmed)
            return SlimResults.Status("email_not_confirmed", "The e-mail address has not been confirmed yet.", StatusCodes.Status403Forbidden);

        if (user.TwoFactorEnabled)
        {
            var challenge = await BeginTwoFactorAsync(user, cookies, request.RememberMe, ct);
            return challenge is null
                ? Results.Problem(statusCode: 500, title: "Two-factor authentication is enabled for this user but ISlimTwoFactorStore is not registered.")
                : Results.Json(challenge, statusCode: StatusCodes.Status401Unauthorized);
        }

        var result = await authManager.SignInCoreAsync(user, cookies, request.RememberMe, SlimAuthManager.MethodPassword, null, null, true, ct);
        return ToResult(result);
    }

    /// <summary>Creates the pre-auth token (and sends the e-mail code if no authenticator is configured).</summary>
    internal async Task<SlimLoginChallengeResponse?> BeginTwoFactorAsync(SlimUser user, bool useCookies, bool rememberMe, CancellationToken ct)
    {
        var twoFactorStore = services.GetService<ISlimTwoFactorStore>();
        if (twoFactorStore is null)
        {
            logger.LogError("SlimIdentity: user {UserId} has TwoFactorEnabled but no ISlimTwoFactorStore is registered. Login denied.", user.Id);
            return null;
        }

        var secret = await twoFactorStore.GetTotpSecretAsync(user, ct);
        string method;
        string? codeHash = null;
        if (!string.IsNullOrEmpty(secret))
        {
            method = MethodTotp;
        }
        else
        {
            method = MethodEmail;
            var code = SlimTotp.GenerateNumericCode();
            codeHash = HashEmailCode(user.Id, code);
            await emailSender.SendTwoFactorCodeAsync(user.Email, code, ct);
        }

        var lifetime = O.Tokens.PreAuthTokenLifetime;
        var token = workflow.Protect(SlimWorkflowTokens.PreAuthPurpose,
            new SlimPreAuthPayload(user.Id, user.SecurityStamp, useCookies, rememberMe, method, codeHash), lifetime);

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
        var twoFactorStore = services.GetRequiredService<ISlimTwoFactorStore>();
        if (request is null || !workflow.TryUnprotect<SlimPreAuthPayload>(SlimWorkflowTokens.PreAuthPurpose, request.PreAuthToken, out var payload))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        var user = await store.FindByIdAsync(payload!.Uid, ct);
        if (user is null || !user.IsActive || !SlimHashing.FixedTimeEquals(user.SecurityStamp, payload.Stamp))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        var now = time.GetUtcNow();
        if (user.IsLockedOut(now)) return SlimResults.Locked(Http, user.LockoutEndUtc!.Value, now);

        bool valid;
        if (!string.IsNullOrWhiteSpace(request.RecoveryCode))
        {
            valid = await twoFactorStore.ValidateAndConsumeRecoveryCodeAsync(user, SlimRecoveryCodes.Hash(request.RecoveryCode), ct);
            if (valid) logger.LogInformation("SlimIdentity: user {UserId} signed in with a recovery code.", user.Id);
        }
        else if (payload.Method == MethodTotp)
        {
            var secret = await twoFactorStore.GetTotpSecretAsync(user, ct);
            valid = !string.IsNullOrEmpty(secret) && SlimTotp.Verify(secret, request.Code, now, O.TwoFactor.TotpTimeStepTolerance);
        }
        else
        {
            var code = SlimTotp.NormalizeCode(request.Code);
            valid = code.Length == 6 && payload.CodeHash is not null
                && SlimHashing.FixedTimeEquals(HashEmailCode(user.Id, code), payload.CodeHash);
        }

        if (!valid)
        {
            var locked = await credentials.RegisterFailureAsync(user, ct);
            return locked
                ? SlimResults.Locked(Http, user.LockoutEndUtc!.Value, now)
                : SlimResults.Status("invalid_two_factor_code", "The code is invalid.", StatusCodes.Status401Unauthorized);
        }

        await credentials.RegisterSuccessAsync(user, null, rehash: false, resetLockout: true, ct);

        if (!SlimModes.TryResolve(O, payload.UseCookies, out var cookies, out var modeError)) return modeError!;
        var result = await authManager.SignInCoreAsync(user, cookies, payload.RememberMe, SlimAuthManager.MethodMfa, null, null, true, ct);
        return ToResult(result);
    }

    // ------------------------------------------------------------------ POST /refresh

    public async Task<IResult> RefreshAsync(SlimRefreshRequest? request, CancellationToken ct)
    {
        var refreshStore = services.GetRequiredService<ISlimRefreshTokenStore>();
        if (request is null || string.IsNullOrWhiteSpace(request.RefreshToken))
            return SlimResults.BadRequest("invalid_request", "refreshToken is required.");

        // signature + expiry of the token itself (DataProtector) – forged or expired tokens never reach the store
        if (!workflow.TryUnprotect<SlimRefreshPayload>(SlimWorkflowTokens.RefreshTokenPurpose, request.RefreshToken, out var payload, out var tokenExpiresAt))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

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
            if (stampValid && clearlyUnexpired && O.Tokens.RevokeSessionsOnRefreshTokenReuse)
                await HandleRefreshTokenReuseAsync(user!, payload, ct);
            else
                logger.LogInformation("SlimIdentity: unknown refresh token for user {UserId}.", payload.Uid);
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);
        }

        if (!string.Equals(owner, payload.Uid, StringComparison.Ordinal) || user is null || !user.IsActive || !stampValid)
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        // server-side session revoked (logout on that device, "sign out other devices", …)?
        if (payload.Sid is not null && services.GetService<ISlimSessionStore>() is { } sessions)
        {
            var session = await sessions.FindAsync(payload.Sid, ct);
            if (session is null || session.ExpiresUtc <= time.GetUtcNow())
                return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);
        }

        var result = await authManager.SignInCoreAsync(user, false, false, payload.Amr, null, null, true, ct,
            sessionId: payload.Sid, authTime: DateTimeOffset.FromUnixTimeSeconds(payload.AuthTime));
        if (!result.Succeeded && result.Error == "session_expired")
            return SlimResults.Status("session_expired", "The session has reached its maximum lifetime. Please sign in again.", StatusCodes.Status401Unauthorized);
        return ToResult(result);
    }

    private async Task HandleRefreshTokenReuseAsync(SlimUser user, SlimRefreshPayload payload, CancellationToken ct)
    {
        if (payload.Sid is not null && services.GetService<ISlimSessionStore>() is { } sessions)
        {
            // revoke the token family: the session and therefore every access / refresh token issued for it
            await sessions.RevokeAsync(payload.Sid, ct);
            logger.LogWarning("SlimIdentity: refresh token reuse for user {UserId} – session {SessionId} revoked.", user.Id, payload.Sid);
            return;
        }

        // stateless: the family cannot be identified, so all sessions of the user end
        await authManager.SignOutEverywhereAsync(user, ct);
        logger.LogWarning("SlimIdentity: refresh token reuse for user {UserId} – security stamp rotated, all sessions revoked.", user.Id);
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

    internal IResult ToResult(SlimAuthResult result) => result.Succeeded
        ? Results.Ok(result.ToResponse(time.GetUtcNow()))
        : SlimResults.InvalidCredentials();

    private static string HashEmailCode(string userId, string code) => SlimHashing.Sha256Hex($"{userId}:{code}");
}

internal static class SlimModes
{
    public static bool TryResolve(SlimIdentityOptions o, bool? requested, out bool useCookies, out IResult? error)
    {
        useCookies = requested ?? o.Endpoints.DefaultUseCookies;
        error = null;
        if (useCookies && !o.Endpoints.AllowCookieAuth)
            error = SlimResults.BadRequest("cookie_auth_disabled", "Cookie authentication is disabled.");
        else if (!useCookies && !o.Endpoints.AllowJwtAuth)
            error = SlimResults.BadRequest("jwt_auth_disabled", "JWT authentication is disabled.");
        return error is null;
    }
}
