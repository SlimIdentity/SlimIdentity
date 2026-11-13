using Microsoft.IdentityModel.JsonWebTokens;
using SlimIdentity.Authentication;
using SlimIdentity.Contracts;
using SlimIdentity.Security;

namespace SlimIdentity.Services;

/// <summary>Default <see cref="ISlimAuthManager"/>; also used internally by all endpoints.</summary>
internal sealed class SlimAuthManager(
    IHttpContextAccessor httpContextAccessor,
    ISlimUserStore store,
    SlimJwtTokenFactory jwt,
    SlimWorkflowTokens workflow,
    SlimMetrics metrics,
    IOptions<SlimIdentityOptions> options,
    TimeProvider time,
    IServiceProvider services,
    ILogger<SlimAuthManager> logger) : ISlimAuthManager
{
    internal const string MethodPassword = "pwd";
    internal const string MethodMfa = "mfa";
    internal const string MethodExternal = "ext";
    internal const string MethodImpersonation = "impersonation";
    /// <summary>Passkey with user verification: possession and biometrics / PIN – multi-factor on its own.</summary>
    internal const string MethodPasskey = "passkey";
    /// <summary>Password + a device on which the second factor was remembered.</summary>
    internal const string MethodRememberedDevice = "mfa_remembered";

    private const int MaxUserAgentLength = 256;

    private static readonly HashSet<string> ReservedClaims = new(StringComparer.Ordinal)
    {
        SlimClaimTypes.UserId, SlimClaimTypes.Email, SlimClaimTypes.SecurityStamp, SlimClaimTypes.Actor,
        SlimClaimTypes.AuthenticationMethod, SlimClaimTypes.SessionId, SlimClaimTypes.AuthTime, SlimClaimTypes.Tenant,
        ClaimTypes.NameIdentifier, ClaimTypes.Email,
        JwtRegisteredClaimNames.Iss, JwtRegisteredClaimNames.Aud, JwtRegisteredClaimNames.Exp,
        JwtRegisteredClaimNames.Nbf, JwtRegisteredClaimNames.Iat, JwtRegisteredClaimNames.Jti,
    };

    private HttpContext Http => httpContextAccessor.HttpContext
        ?? throw new InvalidOperationException("SlimIdentity: ISlimAuthManager requires an active HttpContext.");

    private ISlimSessionStore? Sessions => services.GetService<ISlimSessionStore>();

    // ------------------------------------------------------------------ public API

    public async Task<SlimAuthResult> SignInAsync(SlimUser user, bool useCookies, bool isPersistent = false, string authenticationMethod = MethodPassword,
        bool secondFactorVerified = false, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (!IsHostMethod(authenticationMethod))
            throw new ArgumentException("SlimIdentity: the authentication method must be 1–32 lowercase letters, digits or '_' and not one " +
                "SlimIdentity issues itself for special sessions (impersonation, api_key).", nameof(authenticationMethod));

        // the rules of /login after the first factor – a host endpoint must not be a way around them. A lockout guards
        // the password and the second factor against guessing; it does not apply here (the host checks its own factor).
        var result = await services.GetRequiredService<SlimSignInFlow>().StartAsync(user, useCookies, isPersistent, authenticationMethod,
            secondFactorVerified ? SlimSignInProofs.SecondFactor : SlimSignInProofs.None,
            checkRememberedDevice: false, rememberToken: null, refuseLockedSecondFactor: false, ct);
        if (!result.Succeeded && result.ActionRequired is null && !result.Vetoed && result.Error != SlimErrorCodes.TwoFactorUnavailable)
            await Hooks.RaiseAsync(SlimEventTypes.SignInFailed, user.Id, authenticationMethod, result.Error, ct: ct);
        return result;
    }

    private static bool IsHostMethod(string? method) =>
        method is { Length: > 0 and <= 32 } && method != MethodImpersonation && method != "api_key"
        && method.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '_');

    public Task<IResult> BeginRegistrationAsync(string email, bool? useCookies = null, bool rememberMe = false, CancellationToken ct = default)
    {
        var o = options.Value;
        if (!o.Email.Enabled)
            throw new InvalidOperationException("SlimIdentity: BeginRegistrationAsync needs mail – without it, create the account with CreateUserAsync.");
        if (!SlimIdentity.Endpoints.SlimModes.TryResolve(o, useCookies, out var cookies, out var modeError)) return Task.FromResult(modeError!);
        return services.GetRequiredService<SlimRegistrationFlow>().BeginCoreAsync(email, cookies, rememberMe, ct);
    }

    public async Task<SlimCreateUserResult> CreateUserAsync(string email, string? initialPassword = null, object? profile = null, CancellationToken ct = default)
    {
        var normalized = SlimEmailAddress.Normalize(email);
        if (!services.GetRequiredService<SlimRegistrationService>().IsValidAccountName(normalized))
            return new SlimCreateUserResult(null, SlimRegistrationService.InvalidEmail("email"));
        if (initialPassword is not null
            && await services.GetRequiredService<SlimPasswordPolicy>().ValidateAsync(initialPassword, normalized, ct) is { } errors)
            return new SlimCreateUserResult(null, SlimIdentity.Http.SlimResults.Validation(errors));

        // without a hash first: the start password is written together with its change requirement – never one without the other
        var user = await store.FindByEmailAsync(normalized, ct) is null
            ? await store.CreateAsync(new SlimNewUser { Email = normalized, Profile = profile, EmailConfirmed = true }, ct)
            : null;
        if (user is null)
            return new SlimCreateUserResult(null, SlimIdentity.Http.SlimResults.Status(SlimErrorCodes.EmailTaken,
                "The address already has an account.", StatusCodes.Status409Conflict));

        if (initialPassword is not null)
        {
            var credentials = services.GetRequiredService<SlimCredentialService>();
            await store.WriteSecurityStateAsync(user, u =>
            {
                credentials.ApplyNewPassword(u, initialPassword);
                u.PasswordChangeRequired = true;
            }, ct);
        }
        Log.UserCreatedByAdministrator(logger, user.Id, initialPassword is not null);
        metrics.Registration("created");
        await Hooks.RaiseAsync(SlimEventTypes.UserCreated, user.Id, reason: "administrator", ct: ct);
        return new SlimCreateUserResult(user, null);
    }

    public async Task<bool> HasSignInMethodAsync(SlimUser user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (await services.GetRequiredService<SlimCredentialService>().HasPasswordAsync(user, ct)) return true;
        if (services.GetService<ISlimExternalLoginStore>() is { } external && (await external.GetExternalLoginsAsync(user.Id, ct)).Count > 0) return true;
        return services.GetService<ISlimPasskeySignInMethods>() is { } passkeys && (await passkeys.GetPasskeysAsync(user.Id, ct)).Count > 0;
    }

    public async Task<SlimAuthResult> ImpersonateAsync(SlimUser targetUser, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(targetUser);
        // the impersonator, the session mode and the origin session come from the administrator's own request
        var admin = Http.User;
        var impersonatorUserId = admin.Identity?.IsAuthenticated == true ? admin.GetSlimUserId() : null;
        if (string.IsNullOrEmpty(impersonatorUserId))
            throw new InvalidOperationException("SlimIdentity: ImpersonateAsync must be called by the signed-in administrator's request.");
        var useCookies = admin.IsSlimCookieSession();

        if (admin.IsImpersonating())
            return SlimAuthResult.Failed(SlimErrorCodes.AlreadyImpersonating);
        if (string.Equals(targetUser.Id, impersonatorUserId, StringComparison.Ordinal))
            return SlimAuthResult.Failed(SlimErrorCodes.CannotImpersonateSelf);

        // Bind the session to the impersonator's current security state: banning the admin or rotating
        // their stamp ends every impersonation session they started (see SlimSecurityStampValidator).
        var impersonator = await store.FindByIdAsync(impersonatorUserId, ct);
        if (impersonator is not { IsActive: true })
            return SlimAuthResult.Failed(SlimErrorCodes.ImpersonatorInvalid);

        // ... and to the administrator's session it starts from: revoking that session (a stolen device) ends it, too
        var originSessionId = Sessions is null ? null : CurrentSessionId(admin);
        var actor = SlimClaims.SerializeActor(SlimClaims.CreateActor(impersonator.Id, impersonator.SecurityStamp,
            admin.FindFirst(SlimClaimTypes.AuthenticationMethod)?.Value, CurrentAuthTime(admin), originSessionId));

        var started = await SignInCoreAsync(targetUser, useCookies, isPersistent: false, MethodImpersonation, null, actor, issueRefreshToken: false, ct);
        if (started.Succeeded)
        {
            Log.ImpersonationStarted(logger, impersonator.Id, targetUser.Id);
            metrics.Impersonation("started");
            await Hooks.RaiseAsync(SlimEventTypes.ImpersonationStarted, targetUser.Id, actorId: impersonator.Id, ct: ct);
        }
        return started;
    }

    public async Task<SlimAuthResult> EndImpersonationAsync(CancellationToken ct = default)
    {
        var current = Http.User;
        var actor = SlimClaims.ParseActorClaim(current.FindFirst(SlimClaimTypes.Actor)?.Value);
        if (actor is null) return SlimAuthResult.Failed(SlimErrorCodes.NotImpersonating);

        var useCookies = current.IsSlimCookieSession();
        if (current.FindFirst(SlimClaimTypes.SessionId)?.Value is { } sid && Sessions is { } sessions)
            await sessions.RevokeAsync(sid, ct);

        var impersonator = await store.FindByIdAsync(actor.UserId, ct);
        if (impersonator is not { IsActive: true } || !SlimUser.IsSameSecurityState(impersonator.SecurityStamp, actor.SecurityStamp)
            || !await IsLiveOriginSessionAsync(actor, ct))
        {
            // The impersonator was banned, signed out everywhere or the session the impersonation was started from was
            // revoked in the meantime: no way back, end the session.
            Log.ImpersonationReturnDenied(logger, actor.UserId);
            if (useCookies) await Http.SignOutAsync(SlimIdentityDefaults.CookieScheme);
            return SlimAuthResult.Failed(SlimErrorCodes.ImpersonatorInvalid);
        }

        Log.ImpersonationEnded(logger, impersonator.Id, current.GetSlimUserId());
        metrics.Impersonation("ended");
        await Hooks.RaiseAsync(SlimEventTypes.ImpersonationEnded, current.GetSlimUserId(), actorId: impersonator.Id, ct: ct);
        // back to the administrator's own session – its id, its sign-in time and its absolute lifetime, not a fresh chain
        return await SignInCoreAsync(impersonator, useCookies, isPersistent: false, actor.AuthenticationMethod ?? MethodPassword,
            null, null, issueRefreshToken: true, ct, sessionId: Sessions is null ? null : actor.SessionId, authTime: actor.AuthTime,
            stage: SlimSignInStage.SignIn);
    }

    /// <summary>
    /// The administrator's session an impersonation was started from still exists (always true without a session store or
    /// for impersonations started before the session id was recorded).
    /// </summary>
    internal async Task<bool> IsLiveOriginSessionAsync(SlimActor actor, CancellationToken ct) =>
        await IsLiveOriginSessionAsync(actor, Sessions, time.GetUtcNow(), ct);

    internal static async Task<bool> IsLiveOriginSessionAsync(SlimActor actor, ISlimSessionStore? sessions, DateTimeOffset now, CancellationToken ct)
    {
        if (actor.SessionId is null || sessions is null) return true;
        var origin = await sessions.FindAsync(actor.SessionId, ct);
        return origin is not null && origin.ExpiresUtc > now && string.Equals(origin.UserId, actor.UserId, StringComparison.Ordinal);
    }

    public async Task<IResult?> SetPasswordAsync(SlimUser user, string password, bool mustChange = true, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (await services.GetRequiredService<SlimPasswordPolicy>().ValidateAsync(password, user.Email, ct) is { } errors)
            return SlimIdentity.Http.SlimResults.Validation(errors);

        var credentials = services.GetRequiredService<SlimCredentialService>();
        await store.WriteSecurityStateAsync(user, u =>
        {
            credentials.ApplyNewPassword(u, password);   // new stamp
            u.PasswordChangeRequired = mustChange;
        }, ct);
        await credentials.ResetAttemptsAsync(user, SlimAttemptFactor.Password, ct);   // guesses against the old password end
        await RevokeSessionsAsync(user.Id, exceptSessionId: null, ct);
        Log.AdminPasswordSet(logger, user.Id, mustChange);
        await Hooks.RaiseAsync(SlimEventTypes.PasswordChanged, user.Id, reason: "set_by_administrator", ct: ct);
        return null;
    }

    public Task<SlimPasswordReset> CreatePasswordResetAsync(SlimUser user, TimeSpan? lifetime = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        var o = options.Value;
        var validity = lifetime ?? o.Tokens.PasswordResetTokenLifetime;
        if (validity <= TimeSpan.Zero || validity > TimeSpan.FromDays(7))
            throw new ArgumentOutOfRangeException(nameof(lifetime), "SlimIdentity: a reset link must be valid for more than 0 and at most 7 days.");

        // no proof of the mailbox: an unconfirmed account verifies its address in the flow first
        var flowId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var token = workflow.Protect(SlimWorkflowTokens.LinkPurpose,
            new SlimLinkPayload(SlimLinkPayload.AdminReset, flowId, Uid: user.Id, Stamp: user.SecurityStamp), validity);
        Log.AdminPasswordResetCreated(logger, user.Id);
        var link = services.GetRequiredService<SlimLinks>().Build(SlimLinkKind.PasswordReset, token);
        return Task.FromResult(new SlimPasswordReset(token, link, time.GetUtcNow() + validity));
    }

    public async Task ResetTwoFactorAsync(SlimUser user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        await store.WriteSecurityStateAsync(user, u =>
        {
            u.TwoFactorEnabled = false;
            u.SecurityStamp = SlimUser.NewSecurityStamp();   // remembered devices and all sessions end
        }, ct);
        if (services.GetService<SlimTwoFactorService>() is { } twoFactor)
        {
            await twoFactor.RemoveSecretAsync(user, ct);
            await twoFactor.RemoveRecoveryCodesAsync(user, ct);
        }
        await services.GetRequiredService<SlimCredentialService>().ResetAttemptsAsync(user, SlimAttemptFactor.SecondFactor, ct);
        await RevokeSessionsAsync(user.Id, exceptSessionId: null, ct);
        Log.AdminTwoFactorReset(logger, user.Id);
        await Hooks.RaiseAsync(SlimEventTypes.TwoFactorDisabled, user.Id, reason: "administrator", ct: ct);
    }

    public async Task RefreshClaimsAsync(SlimUser user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        await RotateSecurityStampAsync(user, SlimUser.WithNewClaimsPart, ct);
        Log.ClaimsRefreshed(logger, user.Id);
        await Hooks.RaiseAsync(SlimEventTypes.ClaimsChanged, user.Id, ct: ct);
    }

    /// <summary>
    /// Replaces only the security stamp (compare-and-set): a concurrent password or 2FA change is never written back over.
    /// If the stamp changed in the meantime, the user is read again and the rotation retried on the current value.
    /// </summary>
    internal async Task RotateSecurityStampAsync(SlimUser user, Func<string, string> next, CancellationToken ct)
    {
        var expected = user.SecurityStamp;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var updated = next(expected);
            if (await store.UpdateSecurityStampAsync(user, expected, updated, ct))
            {
                user.SecurityStamp = updated;
                return;
            }
            if (await store.FindByIdAsync(user.Id, ct) is not { } current) return;   // deleted – nothing left to sign out
            expected = current.SecurityStamp;
        }
        throw new InvalidOperationException($"SlimIdentity: the security stamp of user {user.Id} kept changing; it could not be rotated.");
    }

    public async Task UnlockAsync(SlimUser user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        var credentials = services.GetRequiredService<SlimCredentialService>();
        await credentials.ResetAttemptsAsync(user, SlimAttemptFactor.Password, ct);
        await credentials.ResetAttemptsAsync(user, SlimAttemptFactor.SecondFactor, ct);
        Log.AdminUnlocked(logger, user.Id);
        await Hooks.RaiseAsync(SlimEventTypes.Unlocked, user.Id, ct: ct);
    }

    public Task<IResult?> ConfirmPasswordAsync(SlimUser user, string? password, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        return services.GetRequiredService<SlimCredentialService>().ConfirmPasswordAsync(user, password, Http, ct);
    }

    public Task<SlimAuthResult> ElevateToSudoAsync(SlimUser user, TimeSpan duration, CancellationToken ct = default)
    {
        if (duration <= TimeSpan.Zero || duration > TimeSpan.FromHours(1))
            throw new ArgumentOutOfRangeException(nameof(duration), "SlimIdentity: a sudo window lasts between 0 and 1 hour.");
        return ElevateSessionAsync(user, [SlimClaims.SudoFor(duration, time)], ct);
    }

    public async Task<SlimAuthResult> ElevateSessionAsync(SlimUser user, IEnumerable<Claim> additionalClaims, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        var current = Http.User;
        // sid, act and auth_time are taken from the current session – they must not end up on another account
        if (!string.Equals(current.GetSlimUserId(), user.Id, StringComparison.Ordinal))
            throw new InvalidOperationException("SlimIdentity: ElevateSessionAsync elevates the signed-in user of the current request only.");
        var actor = SlimClaims.ParseActorClaim(current.FindFirst(SlimClaimTypes.Actor)?.Value) is { } a
            ? SlimClaims.SerializeActor(a.ToDictionary())
            : null;
        var amr = current.FindFirst(SlimClaimTypes.AuthenticationMethod)?.Value ?? MethodPassword;

        // the session is re-issued in its own mode: a cookie stays a cookie, a token pair a token pair
        var useCookies = current.IsSlimCookieSession();
        var persistent = false;
        if (useCookies)
        {
            var existing = await Http.AuthenticateAsync(SlimIdentityDefaults.CookieScheme);
            persistent = existing.Properties?.IsPersistent ?? false;
        }

        return await SignInCoreAsync(user, useCookies, persistent, amr, additionalClaims, actor, issueRefreshToken: false, ct,
            sessionId: CurrentSessionId(current), authTime: CurrentAuthTime(current));
    }

    public async Task SignOutAsync(string? refreshToken = null, CancellationToken ct = default)
    {
        var sessions = Sessions;
        var sessionIds = new HashSet<string>(StringComparer.Ordinal);

        // the caller's own session (cookie or bearer), even on an anonymous endpoint
        var principal = Http.User.Identity?.IsAuthenticated == true
            ? Http.User
            : (await Http.AuthenticateAsync(SlimIdentityDefaults.AuthenticationScheme)).Principal;
        if (principal is not null && CurrentSessionId(principal) is { } own)
        {
            sessionIds.Add(own);
            // a browser signing out of an impersonation: the administrator's session it holds for the return ends, too
            if (principal.IsSlimCookieSession()
                && SlimClaims.ParseActorClaim(principal.FindFirst(SlimClaimTypes.Actor)?.Value)?.SessionId is { } origin)
                sessionIds.Add(origin);
        }

        // A refresh token ends its session only while it is live: consumed by this call (not used before) and issued
        // under the current security stamp. An old token – rotated away, or from before a password change on the same
        // device, whose session continues with new tokens – has no effect, here as at /refresh.
        if (!string.IsNullOrWhiteSpace(refreshToken)
            && workflow.TryUnprotect<SlimRefreshPayload>(SlimWorkflowTokens.RefreshTokenPurpose, refreshToken, out var payload)
            && services.GetService<ISlimRefreshTokenStore>() is { } refreshStore)
        {
            var owner = await refreshStore.ValidateAndConsumeRefreshTokenAsync(SlimHashing.Sha256Hex(refreshToken), ct);
            if (payload.Sid is { } sid
                && string.Equals(owner, payload.Uid, StringComparison.Ordinal)
                && await store.FindByIdAsync(payload.Uid, ct) is { } owningUser
                && SlimUser.IsSameSecurityState(owningUser.SecurityStamp, payload.Stamp))
                sessionIds.Add(sid);
        }

        if (sessions is not null)
            foreach (var sid in sessionIds)
                await sessions.RevokeAsync(sid, ct);

        if (options.Value.Endpoints.AllowCookieAuth)
            await Http.SignOutAsync(SlimIdentityDefaults.CookieScheme);
        metrics.SignOut("session");
    }

    public async Task SignOutEverywhereAsync(SlimUser user, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        await RotateSecurityStampAsync(user, _ => SlimUser.NewSecurityStamp(), ct);
        await RevokeSessionsAsync(user.Id, exceptSessionId: null, ct);
        Log.AllSessionsRevoked(logger, user.Id);
        metrics.SignOut("everywhere");
        await Hooks.RaiseAsync(SlimEventTypes.SessionsRevoked, user.Id, ct: ct);
    }

    public Task<SlimInvitation> CreateInvitationAsync(SlimUser user, TimeSpan? lifetime = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        if (string.IsNullOrEmpty(user.Id) || string.IsNullOrEmpty(user.Email))
            throw new ArgumentException("SlimIdentity: the invited user must already exist (Id and Email set).", nameof(user));
        if (!string.IsNullOrEmpty(user.PasswordHash))
            throw new InvalidOperationException("SlimIdentity: the user already has a password – send a password reset instead of an invitation.");

        var o = options.Value;
        var validity = lifetime ?? o.Tokens.InvitationTokenLifetime;
        if (validity <= TimeSpan.Zero || validity > TimeSpan.FromDays(30))
            throw new ArgumentOutOfRangeException(nameof(lifetime), "SlimIdentity: invitation lifetime must be between 0 and 30 days.");

        var flowId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var token = workflow.Protect(SlimWorkflowTokens.LinkPurpose,
            new SlimLinkPayload(SlimLinkPayload.Invitation, flowId, user.Email, user.Id, user.SecurityStamp), validity);
        metrics.Invitation("created");
        var link = services.GetRequiredService<SlimLinks>().Build(SlimLinkKind.Invitation, token);
        return Task.FromResult(new SlimInvitation(token, link, time.GetUtcNow() + validity));
    }

    // ------------------------------------------------------------------ internal API

    private SlimHookRunner Hooks => services.GetRequiredService<SlimHookRunner>();

    /// <summary>
    /// Issues or renews a session – the only place sessions come from, so every path passes the host's sign-in guards
    /// (unless the current, just re-validated session is only re-issued) and reports new sessions.
    /// </summary>
    internal async Task<SlimAuthResult> SignInCoreAsync(
        SlimUser user,
        bool useCookies,
        bool isPersistent,
        string authMethod,
        IEnumerable<Claim>? additionalClaims,
        string? actorJson,
        bool issueRefreshToken,
        CancellationToken ct,
        string? sessionId = null,
        DateTimeOffset? authTime = null,
        bool checkGuards = true,
        SlimSignInStage? stage = null)
    {
        // every renewal (refresh, sudo, re-issue after a password or 2FA change) carries the original sign-in time –
        // with or without a session store; a new sign-in never does
        var signInStage = stage ?? (sessionId is null && authTime is null ? SlimSignInStage.SignIn : SlimSignInStage.Renewal);
        var impersonatorId = SlimClaims.ParseActorClaim(actorJson)?.UserId;
        // backstop: no new session while a start password set by an administrator waits to be replaced – every sign-in
        // path checks it with its own answer, this keeps a forgotten one from issuing a session (impersonation is the
        // administrator's own act)
        if (signInStage == SlimSignInStage.SignIn && user.PasswordChangeRequired && authMethod != MethodImpersonation)
            return SlimAuthResult.Failed(SlimErrorCodes.PasswordChangeRequired);
        if (user.IsActive && checkGuards && await Hooks.CheckSignInAsync(user, authMethod, signInStage, impersonatorId, ct) is { } veto)
        {
            await Hooks.RaiseAsync(SlimEventTypes.SignInFailed, user.Id, authMethod, veto.Error, impersonatorId, ct);
            return SlimAuthResult.Veto(veto);
        }

        var result = await IssueSessionAsync(user, useCookies, isPersistent, authMethod, additionalClaims, actorJson, issueRefreshToken, sessionId, authTime, ct);
        if (result.Succeeded && signInStage == SlimSignInStage.SignIn)
            await Hooks.RaiseAsync(SlimEventTypes.SignedIn, user.Id, authMethod, null, impersonatorId, ct);
        return result;
    }

    private async Task<SlimAuthResult> IssueSessionAsync(
        SlimUser user,
        bool useCookies,
        bool isPersistent,
        string authMethod,
        IEnumerable<Claim>? additionalClaims,
        string? actorJson,
        bool issueRefreshToken,
        string? sessionId,
        DateTimeOffset? authTime,
        CancellationToken ct)
    {
        if (!user.IsActive) return SlimAuthResult.Failed(SlimErrorCodes.AccountDisabled);

        // a user created outside SlimIdentity (seeding, import) may have no stamp – every session would fail its first
        // validation: give it one before anything is bound to it
        if (string.IsNullOrEmpty(user.SecurityStamp))
        {
            // a concurrent first sign-in may have set one already – either stamp serves
            await store.WriteSecurityStateAsync(user, u =>
            {
                if (string.IsNullOrEmpty(u.SecurityStamp)) u.SecurityStamp = SlimUser.NewSecurityStamp();
            }, ct);
            Log.SecurityStampMissing(logger, user.Id);
        }

        var o = options.Value;
        var now = time.GetUtcNow();
        var authStart = authTime ?? now;
        var sessions = Sessions;
        var newSession = sessions is not null && sessionId is null;
        if (newSession) sessionId = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        if (sessions is null) sessionId = null;

        var claims = await BuildClaimsAsync(user, authMethod, additionalClaims, actorJson, sessionId, authStart, ct);

        if (useCookies)
        {
            if (!o.Endpoints.AllowCookieAuth)
                throw new InvalidOperationException("SlimIdentity: cookie authentication is disabled (Endpoints.AllowCookieAuth).");

            // a new cookie replaces the one of this browser – its old server-side session is gone with it (except the
            // administrator's session an impersonation starts from: it is resumed when the impersonation ends)
            if (newSession && Http.User.IsSlimCookieSession() && CurrentSessionId(Http.User) is { } replaced
                && !string.Equals(replaced, SlimClaims.ParseActorClaim(actorJson)?.SessionId, StringComparison.Ordinal))
            {
                await sessions!.RevokeAsync(replaced, ct);
                // an impersonation cookie replaced by a new sign-in: the administrator's session kept for the return goes, too
                if (SlimClaims.ParseActorClaim(Http.User.FindFirst(SlimClaimTypes.Actor)?.Value)?.SessionId is { } origin)
                    await sessions.RevokeAsync(origin, ct);
            }

            await TrackSessionAsync(sessions, newSession, sessionId, user.Id, "cookie", authMethod, actorJson, now, now + o.Cookies.ExpireTimeSpan, ct);

            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                claims, SlimIdentityDefaults.CookieScheme, SlimClaimTypes.Email, SlimClaimTypes.Role));

            var props = new AuthenticationProperties { IsPersistent = isPersistent, AllowRefresh = true };
            props.Items[SlimSecurityStampValidator.ValidatedAtKey] = now.ToString("O", CultureInfo.InvariantCulture);

            await Http.SignInAsync(SlimIdentityDefaults.CookieScheme, principal, props);
            return new SlimAuthResult { Succeeded = true, UsedCookies = true, Principal = principal, SessionId = sessionId };
        }

        if (!o.JwtEnabled)
            throw new InvalidOperationException("SlimIdentity: JWT authentication is not configured (set Tokens.JwtSecret).");

        string? refreshToken = null;
        DateTimeOffset? refreshExpires = null;
        if (issueRefreshToken && services.GetService<ISlimRefreshTokenStore>() is { } refreshStore)
        {
            // sliding lifetime, capped by the absolute lifetime of the whole chain
            var absoluteEnd = authStart + o.Tokens.RefreshTokenAbsoluteLifetime;
            if (absoluteEnd <= now) return SlimAuthResult.Failed(SlimErrorCodes.SessionExpired);

            refreshExpires = Min(now + o.Tokens.RefreshTokenLifetime, absoluteEnd);
            refreshToken = workflow.Protect(
                SlimWorkflowTokens.RefreshTokenPurpose,
                new SlimRefreshPayload(user.Id, user.SecurityStamp, authMethod, Convert.ToHexString(RandomNumberGenerator.GetBytes(16)),
                    authStart.ToUnixTimeSeconds(), sessionId),
                refreshExpires.Value - now);
            await refreshStore.StoreRefreshTokenAsync(user.Id, SlimHashing.Sha256Hex(refreshToken), refreshExpires.Value, ct);
        }

        var (accessToken, accessExpires) = jwt.CreateAccessToken(claims);
        await TrackSessionAsync(sessions, newSession, sessionId, user.Id, "bearer", authMethod, actorJson, now, refreshExpires ?? accessExpires, ct);

        return new SlimAuthResult
        {
            Succeeded = true,
            UsedCookies = false,
            AccessToken = accessToken,
            AccessTokenExpiresAt = accessExpires,
            IssuedAt = now,
            RefreshToken = refreshToken,
            RefreshTokenExpiresAt = refreshExpires,
            SessionId = sessionId,
            Principal = new ClaimsPrincipal(new ClaimsIdentity(
                claims, SlimIdentityDefaults.BearerScheme, SlimClaimTypes.Email, SlimClaimTypes.Role)),
        };
    }

    /// <summary>
    /// Re-issues the session of the current request for <paramref name="user"/> (after stamp rotation),
    /// so the calling device stays signed in (same server-side session) while all others are logged out.
    /// </summary>
    internal async Task<SlimAuthResult> RefreshCurrentSessionAsync(SlimUser user, CancellationToken ct)
    {
        var current = Http.User;
        var amr = current.FindFirst(SlimClaimTypes.AuthenticationMethod)?.Value ?? MethodPassword;
        var sid = CurrentSessionId(current);
        var authTime = CurrentAuthTime(current);

        if (current.IsSlimCookieSession())
        {
            var existing = await Http.AuthenticateAsync(SlimIdentityDefaults.CookieScheme);
            var persistent = existing.Properties?.IsPersistent ?? false;
            return await SignInCoreAsync(user, true, persistent, amr, null, null, issueRefreshToken: false, ct, sid, authTime, checkGuards: false);
        }

        return await SignInCoreAsync(user, false, false, amr, null, null, issueRefreshToken: true, ct, sid, authTime, checkGuards: false);
    }

    /// <summary>Revokes server-side sessions after a security-stamp rotation (no-op without <see cref="ISlimSessionStore"/>).</summary>
    internal async Task RevokeSessionsAsync(string userId, string? exceptSessionId, CancellationToken ct)
    {
        if (Sessions is { } sessions) await sessions.RevokeAllAsync(userId, exceptSessionId, ct);
    }

    internal static string? CurrentSessionId(ClaimsPrincipal principal) => principal.FindFirst(SlimClaimTypes.SessionId)?.Value;

    private static DateTimeOffset? CurrentAuthTime(ClaimsPrincipal principal) =>
        long.TryParse(principal.FindFirst(SlimClaimTypes.AuthTime)?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var unix)
            ? DateTimeOffset.FromUnixTimeSeconds(unix)
            : null;

    private async Task TrackSessionAsync(ISlimSessionStore? sessions, bool isNew, string? sessionId, string userId, string mode,
        string authMethod, string? actorJson, DateTimeOffset now, DateTimeOffset expires, CancellationToken ct)
    {
        if (sessions is null || sessionId is null) return;
        if (!isNew)
        {
            await sessions.TouchAsync(sessionId, now, expires, ct);
            return;
        }

        var userAgent = Http.Request.Headers.UserAgent.ToString();
        await sessions.CreateAsync(new SlimSession
        {
            Id = sessionId,
            UserId = userId,
            Mode = mode,
            AuthenticationMethod = authMethod,
            ImpersonatorId = SlimClaims.ParseActor(actorJson),
            CreatedUtc = now,
            LastSeenUtc = now,
            ExpiresUtc = expires,
            UserAgent = userAgent.Length > MaxUserAgentLength ? userAgent[..MaxUserAgentLength] : NullIfEmpty(userAgent),
            IpAddress = Http.Connection.RemoteIpAddress?.ToString(),
        }, ct);
    }

    private async Task<List<Claim>> BuildClaimsAsync(SlimUser user, string authMethod, IEnumerable<Claim>? additionalClaims,
        string? actorJson, string? sessionId, DateTimeOffset authTime, CancellationToken ct)
    {
        var claims = new List<Claim>
        {
            new(SlimClaimTypes.UserId, user.Id),
            new(SlimClaimTypes.Email, user.Email),
            new(SlimClaimTypes.SecurityStamp, user.SecurityStamp),
            new(SlimClaimTypes.AuthenticationMethod, authMethod),
            new(SlimClaimTypes.AuthTime, authTime.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
        };
        if (sessionId is not null) claims.Add(new Claim(SlimClaimTypes.SessionId, sessionId));
        if (services.GetService<SlimTenantBinding>()?.KeyOf(Http) is { } tenant) claims.Add(new Claim(SlimClaimTypes.Tenant, tenant));

        foreach (var claim in await store.GetClaimsAsync(user, ct))
            AddNormalized(claims, claim);

        if (additionalClaims is not null)
            foreach (var claim in additionalClaims)
                AddNormalized(claims, claim);

        if (!string.IsNullOrEmpty(actorJson))
            claims.Add(new Claim(SlimClaimTypes.Actor, actorJson, JsonClaimValueTypes.Json));

        return claims;
    }

    /// <summary>
    /// A running session's principal with the host's current claims (after <c>RefreshClaimsAsync</c>): SlimIdentity's own
    /// claims (sub, amr, sid, auth_time, act, token claims) and a step-up window stay, every host claim is replaced, the
    /// stamp claim takes the current stamp. Other claims added by <c>ElevateSessionAsync</c> end here.
    /// </summary>
    internal static async Task<ClaimsPrincipal> RebuildPrincipalAsync(ClaimsPrincipal principal, SlimUser user, ISlimUserStore store, CancellationToken ct)
    {
        var claims = principal.Claims
            .Where(c => c.Type != SlimClaimTypes.SecurityStamp && (ReservedClaims.Contains(c.Type) || c.Type == SlimClaimTypes.SudoUntil))
            .Select(c => new Claim(c.Type, c.Value, c.ValueType))
            .ToList();
        claims.Add(new Claim(SlimClaimTypes.SecurityStamp, user.SecurityStamp));
        foreach (var claim in await store.GetClaimsAsync(user, ct))
            AddNormalized(claims, claim);

        var authenticationType = principal.Identity?.AuthenticationType ?? SlimIdentityDefaults.CookieScheme;
        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType, SlimClaimTypes.Email, SlimClaimTypes.Role));
    }

    private static void AddNormalized(List<Claim> target, Claim claim)
    {
        var type = claim.Type switch
        {
            ClaimTypes.Role => SlimClaimTypes.Role,
            ClaimTypes.Name => "name",
            _ => claim.Type,
        };
        if (ReservedClaims.Contains(type)) return;
        if (type == SlimClaimTypes.SudoUntil) target.RemoveAll(c => c.Type == SlimClaimTypes.SudoUntil);
        target.Add(new Claim(type, claim.Value, claim.ValueType));
    }

    private static DateTimeOffset Min(DateTimeOffset a, DateTimeOffset b) => a < b ? a : b;
    private static string? NullIfEmpty(string s) => s.Length == 0 ? null : s;
}
