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
    IOptions<SlimIdentityOptions> options,
    TimeProvider time,
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
        var method = user.TwoFactorEnabled ? (hasAuthenticator ? SlimLoginHandlers.MethodTotp : SlimLoginHandlers.MethodEmail) : null;
        return Results.Ok(new SlimTwoFactorStatusResponse(user.TwoFactorEnabled, method, hasAuthenticator));
    }

    // POST /2fa/setup – returns a secret, nothing is persisted until /2fa/enable confirms a code
    public async Task<IResult> SetupAsync(CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;

        var secret = SlimTotp.GenerateSecret();
        var setupToken = workflow.Protect(SlimWorkflowTokens.TwoFactorSetupPurpose,
            new SlimTwoFactorSetupPayload(user.Id, secret), SlimIdentityDefaults.TwoFactorSetupTokenLifetime);

        return Results.Ok(new SlimTwoFactorSetupResponse(
            SlimTotp.FormatSharedKey(secret),
            SlimTotp.BuildAuthenticatorUri(O.TwoFactor.AuthenticatorIssuer, user.Email, secret),
            setupToken));
    }

    // POST /2fa/enable
    public async Task<IResult> EnableAuthenticatorAsync(SlimTwoFactorEnableRequest? request, CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;

        if (!workflow.TryUnprotect<SlimTwoFactorSetupPayload>(SlimWorkflowTokens.TwoFactorSetupPurpose, request?.SetupToken, out var payload)
            || !string.Equals(payload.Uid, user.Id, StringComparison.Ordinal))
            return SlimResults.InvalidToken();

        // the first code is consumed as well – it cannot be replayed for a sign-in afterwards
        if (!await twoFactor.VerifyTotpAsync(user, payload.Secret, request!.Code, ct))
            return SlimResults.BadRequest("invalid_two_factor_code", "The code is invalid.");

        await twoFactor.SetSecretAsync(user, payload.Secret, ct);
        return await ActivateAsync(user, ct);
    }

    // POST /2fa/enable-email
    public async Task<IResult> EnableEmailAsync(SlimPasswordConfirmationRequest? request, CancellationToken ct)
    {
        var (user, error) = await ConfirmPasswordAsync(request, ct);
        if (user is null) return error!;

        await twoFactor.RemoveSecretAsync(user, ct);
        return await ActivateAsync(user, ct);
    }

    // POST /2fa/disable
    public async Task<IResult> DisableAsync(SlimPasswordConfirmationRequest? request, CancellationToken ct)
    {
        var (user, error) = await ConfirmPasswordAsync(request, ct);
        if (user is null) return error!;

        await twoFactor.RemoveSecretAsync(user, ct);
        await twoFactor.RemoveRecoveryCodesAsync(user, ct);
        user.TwoFactorEnabled = false;
        user.SecurityStamp = SlimUser.NewSecurityStamp();
        await store.UpdateSecurityStateAsync(user, ct);
        await authManager.RevokeSessionsAsync(user.Id, SlimAuthManager.CurrentSessionId(Http.User), ct);
        Log.TwoFactorDisabled(logger, user.Id);

        var session = await authManager.RefreshCurrentSessionAsync(user, ct);
        return Results.Ok(session.ToResponse(time.GetUtcNow()));
    }

    // POST /2fa/recovery-codes
    public async Task<IResult> RegenerateRecoveryCodesAsync(SlimPasswordConfirmationRequest? request, CancellationToken ct)
    {
        var (user, error) = await ConfirmPasswordAsync(request, ct);
        if (user is null) return error!;
        if (!user.TwoFactorEnabled) return SlimResults.BadRequest("two_factor_disabled", "Two-factor authentication is not enabled.");

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
        user.SecurityStamp = SlimUser.NewSecurityStamp();
        await store.UpdateSecurityStateAsync(user, ct);
        await authManager.RevokeSessionsAsync(user.Id, SlimAuthManager.CurrentSessionId(Http.User), ct);
        twoFactor.ForgetDevice(Http);
        Log.RememberedDevicesForgotten(logger, user.Id);

        var session = await authManager.RefreshCurrentSessionAsync(user, ct);
        return Results.Ok(session.ToResponse(time.GetUtcNow()));
    }

    // ------------------------------------------------------------------ helpers

    private async Task<IResult> ActivateAsync(SlimUser user, CancellationToken ct)
    {
        var codes = await twoFactor.RegenerateRecoveryCodesAsync(user, ct);

        user.TwoFactorEnabled = true;
        user.SecurityStamp = SlimUser.NewSecurityStamp(); // sign out all other sessions
        await store.UpdateSecurityStateAsync(user, ct);
        await authManager.RevokeSessionsAsync(user.Id, SlimAuthManager.CurrentSessionId(Http.User), ct);
        Log.TwoFactorEnabled(logger, user.Id);

        var session = await authManager.RefreshCurrentSessionAsync(user, ct);
        return Results.Ok(new SlimRecoveryCodesResponse(codes, session.ToResponse(time.GetUtcNow())));
    }

    private async Task<(SlimUser? User, IResult? Error)> ConfirmPasswordAsync(SlimPasswordConfirmationRequest? request, CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return (null, error);
        var failure = await credentials.ConfirmPasswordAsync(user, request?.Password, Http, ct);
        return failure is null ? (user, null) : (null, failure);
    }
}
