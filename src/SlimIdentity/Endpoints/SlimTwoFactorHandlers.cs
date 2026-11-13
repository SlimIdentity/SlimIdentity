using SlimIdentity.Contracts;
using SlimIdentity.Http;
using SlimIdentity.Security;
using SlimIdentity.Services;

namespace SlimIdentity.Endpoints;

/// <summary>2FA management for the signed-in user (TOTP setup, e-mail codes, recovery codes).</summary>
internal sealed class SlimTwoFactorHandlers(
    ISlimUserStore store,
    SlimTwoFactorService twoFactor,
    SlimAccountHandlers account,
    SlimCredentialService credentials,
    SlimAuthManager authManager,
    SlimWorkflowTokens workflow,
    SlimHookRunner hooks,
    IOptions<SlimIdentityOptions> options,
    IHttpContextAccessor httpContextAccessor,
    ILogger<SlimTwoFactorHandlers> logger)
{
    private SlimIdentityOptions O => options.Value;
    private HttpContext Http => httpContextAccessor.HttpContext!;

    // GET /2fa
    public async Task<IResult> StatusAsync(CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: false, ct);
        if (user is null) return error!;

        var hasAuthenticator = (await twoFactor.GetSecretAsync(user, ct)).Configured;
        // the same decision as the sign-in (BeginTwoFactorAsync): without e-mail codes only a recovery code helps
        var method = !user.TwoFactorEnabled ? null
            : hasAuthenticator ? SlimLoginHandlers.MethodTotp
            : O.EmailCodesEnabled ? SlimLoginHandlers.MethodEmail
            : SlimLoginHandlers.MethodRecovery;
        return Results.Ok(new SlimTwoFactorStatusResponse(user.TwoFactorEnabled, method, hasAuthenticator));
    }

    // POST /2fa/setup – returns a secret, nothing is persisted until /2fa/enable confirms a code
    public async Task<IResult> SetupAsync(CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;
        if (UnconfirmedAddress(user) is { } unconfirmed) return unconfirmed;

        var secret = SlimTotp.GenerateSecret();
        var setupToken = workflow.Protect(SlimWorkflowTokens.TwoFactorSetupPurpose,
            new SlimTwoFactorSetupPayload(user.Id, secret, user.SecurityStamp), SlimIdentityDefaults.TwoFactorSetupTokenLifetime);

        return Results.Ok(new SlimTwoFactorSetupResponse(
            SlimTotp.FormatSharedKey(secret),
            SlimTotp.BuildAuthenticatorUri(O.TwoFactor.AuthenticatorIssuer, user.Email, secret),
            setupToken));
    }

    // POST /2fa/enable – password required like every other 2FA change: a stolen session alone must not install or
    // replace the second factor (that would lock the owner out for good)
    public async Task<IResult> EnableAuthenticatorAsync(SlimTwoFactorEnableRequest? request, CancellationToken ct)
    {
        var (user, error) = await ConfirmPasswordAsync(new SlimPasswordConfirmationRequest(request?.Password ?? string.Empty), ct, requireConfirmedAddress: true);
        if (user is null) return error!;

        // the setup token belongs to this user and dies with the security stamp (logout-all, password change, …)
        if (!workflow.TryUnprotect<SlimTwoFactorSetupPayload>(SlimWorkflowTokens.TwoFactorSetupPurpose, request?.SetupToken, out var payload)
            || !string.Equals(payload.Uid, user.Id, StringComparison.Ordinal)
            || !SlimUser.IsSameSecurityState(payload.Stamp, user.SecurityStamp))
            return SlimResults.InvalidToken();

        // the first code is consumed as well – it cannot be replayed for a sign-in afterwards
        if (!await twoFactor.VerifyTotpAsync(user, payload.Secret, request!.Code, ct, newSecret: true))
            return SlimResults.BadRequest(SlimErrorCodes.InvalidTwoFactorCode, "The code is invalid.");

        return await ActivateAsync(user, SlimLoginHandlers.MethodTotp, payload.Secret, ct);
    }

    // POST /2fa/enable-email
    public async Task<IResult> EnableEmailAsync(SlimPasswordConfirmationRequest? request, CancellationToken ct)
    {
        var (user, error) = await ConfirmPasswordAsync(request, ct, requireConfirmedAddress: true);
        if (user is null) return error!;

        return await ActivateAsync(user, SlimLoginHandlers.MethodEmail, authenticatorSecret: null, ct);
    }

    // POST /2fa/disable
    public async Task<IResult> DisableAsync(SlimPasswordConfirmationRequest? request, CancellationToken ct)
    {
        var (user, error) = await ConfirmPasswordAsync(request, ct);
        if (user is null) return error!;

        var written = await store.TryWriteSecurityStateAsync(user, u =>
        {
            u.TwoFactorEnabled = false;
            u.SecurityStamp = SlimUser.NewSecurityStamp();
        }, ct);
        if (!written) return SlimResults.ConcurrentChange();
        await twoFactor.RemoveSecretAsync(user, ct);
        await twoFactor.RemoveRecoveryCodesAsync(user, ct);
        await authManager.RevokeSessionsAsync(user.Id, SlimAuthManager.CurrentSessionId(Http.User), ct);
        Log.TwoFactorDisabled(logger, user.Id);
        await hooks.RaiseAsync(SlimEventTypes.TwoFactorDisabled, user.Id, reason: "user", ct: ct);

        var session = await authManager.RefreshCurrentSessionAsync(user, ct);
        return SlimResults.ReissuedSession(session);
    }

    // POST /2fa/recovery-codes
    public async Task<IResult> RegenerateRecoveryCodesAsync(SlimPasswordConfirmationRequest? request, CancellationToken ct)
    {
        var (user, error) = await ConfirmPasswordAsync(request, ct);
        if (user is null) return error!;
        if (!user.TwoFactorEnabled) return SlimResults.BadRequest(SlimErrorCodes.TwoFactorDisabled, "Two-factor authentication is not enabled.");

        var codes = await twoFactor.RegenerateRecoveryCodesAsync(user, ct);
        return Results.Ok(new SlimRecoveryCodesResponse(codes, null));
    }

    // POST /2fa/forget-device – this browser asks for the second factor again (bearer clients delete their token)
    public IResult ForgetDevice()
    {
        twoFactor.ForgetDevice(Http);
        return SlimResults.Status("device_forgotten");
    }

    // POST /2fa/forget-all-devices – every remembered device asks again; other sessions end, this one stays
    public async Task<IResult> ForgetAllDevicesAsync(CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;

        // remembered devices are bound to the security stamp – rotating it is the only stateless way to revoke them all
        await authManager.RotateSecurityStampAsync(user, _ => SlimUser.NewSecurityStamp(), ct);
        await authManager.RevokeSessionsAsync(user.Id, SlimAuthManager.CurrentSessionId(Http.User), ct);
        twoFactor.ForgetDevice(Http);
        Log.RememberedDevicesForgotten(logger, user.Id);

        var session = await authManager.RefreshCurrentSessionAsync(user, ct);
        return SlimResults.ReissuedSession(session);
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>
    /// A second factor only on an account whose mailbox was proven: on an unconfirmed account it may have been set up by
    /// whoever registered someone else's address – the owner's first proof of the mailbox would then have to remove it,
    /// which in turn lets a compromised mailbox strip a legitimate user's second factor. Without mail there is no such
    /// proof, and no such rule.
    /// </summary>
    private IResult? UnconfirmedAddress(SlimUser user) =>
        O.Email.Enabled && !user.EmailConfirmed
            ? SlimResults.Status(SlimErrorCodes.EmailNotConfirmed, "Confirm your e-mail address before setting up two-factor authentication.", StatusCodes.Status403Forbidden)
            : null;

    private async Task<IResult> ActivateAsync(SlimUser user, string method, string? authenticatorSecret, CancellationToken ct)
    {
        var written = await store.TryWriteSecurityStateAsync(user, u =>
        {
            u.TwoFactorEnabled = true;
            u.SecurityStamp = SlimUser.NewSecurityStamp(); // sign out all other sessions
        }, ct);
        if (!written) return SlimResults.ConcurrentChange();
        // stored only once the state is written; the e-mail method removes a secret left from an earlier setup
        if (authenticatorSecret is null) await twoFactor.RemoveSecretAsync(user, ct);
        else await twoFactor.SetSecretAsync(user, authenticatorSecret, ct);
        var codes = await twoFactor.RegenerateRecoveryCodesAsync(user, ct);
        await authManager.RevokeSessionsAsync(user.Id, SlimAuthManager.CurrentSessionId(Http.User), ct);
        Log.TwoFactorEnabled(logger, user.Id);
        await hooks.RaiseAsync(SlimEventTypes.TwoFactorEnabled, user.Id, method, ct: ct);

        var session = await authManager.RefreshCurrentSessionAsync(user, ct);
        // the codes are shown exactly once – they go out even if this session could not be renewed
        return Results.Ok(new SlimRecoveryCodesResponse(codes, session.Succeeded ? session.ToResponse() : null));
    }

    private async Task<(SlimUser? User, IResult? Error)> ConfirmPasswordAsync(
        SlimPasswordConfirmationRequest? request, CancellationToken ct, bool requireConfirmedAddress = false)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return (null, error);
        if (requireConfirmedAddress && UnconfirmedAddress(user) is { } unconfirmed) return (null, unconfirmed);   // before the password counts
        var failure = await credentials.ConfirmPasswordAsync(user, request?.Password, Http, ct);
        return failure is null ? (user, null) : (null, failure);
    }
}
