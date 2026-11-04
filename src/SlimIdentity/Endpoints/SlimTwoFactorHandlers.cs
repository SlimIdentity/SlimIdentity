using SlimIdentity.Abstractions;
using SlimIdentity.Contracts;
using SlimIdentity.Http;
using SlimIdentity.Security;
using SlimIdentity.Services;

namespace SlimIdentity.Endpoints;

/// <summary>2FA management for the signed-in user (TOTP setup, e-mail codes, recovery codes).</summary>
internal sealed class SlimTwoFactorHandlers(
    ISlimUserStore store,
    ISlimTwoFactorStore twoFactorStore,
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

        var hasAuthenticator = !string.IsNullOrEmpty(await twoFactorStore.GetTotpSecretAsync(user, ct));
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
            new SlimTwoFactorSetupPayload(user.Id, secret), O.TwoFactor.SetupTokenLifetime);

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

        if (!SlimTotp.Verify(payload.Secret, request!.Code, time.GetUtcNow(), O.TwoFactor.TotpTimeStepTolerance))
            return SlimResults.BadRequest("invalid_two_factor_code", "The code is invalid.");

        await twoFactorStore.SetTotpSecretAsync(user, payload.Secret, ct);
        return await ActivateAsync(user, ct);
    }

    // POST /2fa/enable-email
    public async Task<IResult> EnableEmailAsync(SlimPasswordConfirmationRequest? request, CancellationToken ct)
    {
        var (user, error) = await ConfirmPasswordAsync(request, ct);
        if (user is null) return error!;

        await twoFactorStore.SetTotpSecretAsync(user, string.Empty, ct);
        return await ActivateAsync(user, ct);
    }

    // POST /2fa/disable
    public async Task<IResult> DisableAsync(SlimPasswordConfirmationRequest? request, CancellationToken ct)
    {
        var (user, error) = await ConfirmPasswordAsync(request, ct);
        if (user is null) return error!;

        await twoFactorStore.SetTotpSecretAsync(user, string.Empty, ct);
        await twoFactorStore.StoreRecoveryCodesAsync(user, Array.Empty<string>(), ct);
        user.TwoFactorEnabled = false;
        user.SecurityStamp = SlimUser.NewSecurityStamp();
        await store.UpdateSecurityStateAsync(user, ct);
        logger.LogInformation("SlimIdentity: 2FA disabled for user {UserId}.", user.Id);

        var session = await authManager.RefreshCurrentSessionAsync(user, ct);
        return Results.Ok(session.ToResponse(time.GetUtcNow()));
    }

    // POST /2fa/recovery-codes
    public async Task<IResult> RegenerateRecoveryCodesAsync(SlimPasswordConfirmationRequest? request, CancellationToken ct)
    {
        var (user, error) = await ConfirmPasswordAsync(request, ct);
        if (user is null) return error!;
        if (!user.TwoFactorEnabled) return SlimResults.BadRequest("two_factor_disabled", "Two-factor authentication is not enabled.");

        var codes = SlimRecoveryCodes.Generate(O.TwoFactor.RecoveryCodeCount);
        await twoFactorStore.StoreRecoveryCodesAsync(user, codes.Select(SlimRecoveryCodes.Hash).ToList(), ct);
        return Results.Ok(new SlimRecoveryCodesResponse(codes, null));
    }

    // ------------------------------------------------------------------ helpers

    private async Task<IResult> ActivateAsync(SlimUser user, CancellationToken ct)
    {
        var codes = SlimRecoveryCodes.Generate(O.TwoFactor.RecoveryCodeCount);
        await twoFactorStore.StoreRecoveryCodesAsync(user, codes.Select(SlimRecoveryCodes.Hash).ToList(), ct);

        user.TwoFactorEnabled = true;
        user.SecurityStamp = SlimUser.NewSecurityStamp(); // sign out all other sessions
        await store.UpdateSecurityStateAsync(user, ct);
        logger.LogInformation("SlimIdentity: 2FA enabled for user {UserId}.", user.Id);

        var session = await authManager.RefreshCurrentSessionAsync(user, ct);
        return Results.Ok(new SlimRecoveryCodesResponse(codes, session.ToResponse(time.GetUtcNow())));
    }

    private async Task<(SlimUser? User, IResult? Error)> ConfirmPasswordAsync(SlimPasswordConfirmationRequest? request, CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return (null, error);

        var now = time.GetUtcNow();
        if (user.IsLockedOut(now)) return (null, SlimResults.Locked(Http, user.LockoutEndUtc!.Value, now));

        if (await credentials.VerifyPasswordAsync(user, request?.Password, ct) == SlimPasswordCheck.Failed)
        {
            var locked = await credentials.RegisterFailureAsync(user, ct);
            return (null, locked
                ? SlimResults.Locked(Http, user.LockoutEndUtc!.Value, now)
                : SlimResults.BadRequest("invalid_password", "The password is incorrect."));
        }
        return (user, null);
    }
}
