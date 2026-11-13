using SlimIdentity.Contracts;
using SlimIdentity.Endpoints;
using SlimIdentity.Http;
using SlimIdentity.Security;

namespace SlimIdentity.Services;

/// <summary>
/// The way of every sign-in from its first factor to its session: <see cref="SlimSignInChain"/> names the open steps,
/// the signed flow token carries what is proven so far, each step endpoint adds one proof and continues here.
/// </summary>
internal sealed class SlimSignInFlow(
    SlimAuthManager authManager,
    ISlimUserStore store,
    SlimWorkflowTokens workflow,
    SlimSharedStateAccess sharedState,
    SlimMailThrottle mailThrottle,
    SlimEmailDispatcher mailDispatcher,
    SlimMetrics metrics,
    IOptions<SlimIdentityOptions> options,
    TimeProvider time,
    IHttpContextAccessor httpContextAccessor,
    IServiceProvider services,
    ILogger<SlimSignInFlow> logger)
{
    private SlimIdentityOptions O => options.Value;
    private HttpContext Http => httpContextAccessor.HttpContext!;

    /// <summary>
    /// Starts a sign-in whose first factor is proven: the session, the open steps (<see cref="SlimAuthResult.ActionRequired"/>)
    /// or a refusal – <c>account_disabled</c>, <c>two_factor_unavailable</c> or, with
    /// <paramref name="refuseLockedSecondFactor"/>, <c>locked_out</c> for a locked second factor.
    /// </summary>
    public async Task<SlimAuthResult> StartAsync(SlimUser user, bool cookies, bool rememberMe, string amr, SlimSignInProofs proofs,
        bool checkRememberedDevice, string? rememberToken, bool refuseLockedSecondFactor, CancellationToken ct)
    {
        var decision = SlimSignInChain.Evaluate(user, proofs, O);

        // checkRememberedDevice: a device on which the second factor was passed before proves it again.
        // Possession of the device: a lockout of the second factor does not apply, and its counter stays.
        if (decision.Next == SlimSignInActions.SecondFactor && checkRememberedDevice
            && services.GetService<SlimTwoFactorService>() is { } twoFactor && twoFactor.IsRememberedDevice(user, Http, cookies, rememberToken))
        {
            metrics.TwoFactor("remembered_device", "success");
            proofs |= SlimSignInProofs.SecondFactor;
            amr = SlimAuthManager.MethodRememberedDevice;
            decision = SlimSignInChain.Evaluate(user, proofs, O);
        }

        if (decision.Refusal is { } refusal) return SlimAuthResult.Failed(refusal);
        if (decision.Complete) return await authManager.SignInCoreAsync(user, cookies, rememberMe, amr, null, null, true, ct);

        // no code is sent that cannot be used
        if (decision.Next == SlimSignInActions.SecondFactor && refuseLockedSecondFactor && user.IsSecondFactorLockedOut(time.GetUtcNow()))
            return SlimAuthResult.Failed(SlimErrorCodes.LockedOut);

        var flowId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var state = new SlimFlowPayload(user.Id, user.SecurityStamp, flowId, time.GetUtcNow().ToUnixTimeMilliseconds(), proofs, amr, cookies, rememberMe);
        return await StepsAsync(user, state, decision, ct);
    }

    /// <summary>
    /// Continues after a step endpoint added its proof to <paramref name="state"/>: the next step, or the session – at most
    /// one per flow.
    /// </summary>
    public async Task<SlimAuthResult> ContinueAsync(SlimUser user, SlimFlowPayload state, CancellationToken ct)
    {
        var decision = SlimSignInChain.Evaluate(user, state.Proofs, O);
        if (decision.Refusal is { } refusal) return SlimAuthResult.Failed(refusal);
        if (!decision.Complete) return await StepsAsync(user, state, decision, ct);

        // the last step of parallel requests with one token completes the flow once
        if (!await sharedState.TryConsumeAsync(SlimSharedStateAccess.SignInFlow, state.FlowId, Deadline(state), ct))
            return SlimAuthResult.Failed(SlimErrorCodes.InvalidToken);

        var result = await authManager.SignInCoreAsync(user, state.UseCookies, state.RememberMe, state.Amr, null, null, true, ct);
        // "remember this device" – only after a real second factor, never after a recovery code
        if (result.Succeeded && state.RememberDevice && services.GetService<SlimTwoFactorService>() is { } twoFactor)
            result = result with { TwoFactorRememberToken = twoFactor.RememberDevice(user, Http, state.UseCookies) };
        return result;
    }

    /// <summary>The state of a flow token, or <c>false</c> (forged, expired).</summary>
    public bool TryRead(string? token, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out SlimFlowPayload? state, out DateTimeOffset expiresAt) =>
        workflow.TryUnprotect(SlimWorkflowTokens.SignInFlowPurpose, token, out state, out expiresAt);

    /// <summary>
    /// The account of a flow – <c>null</c> if it is gone, inactive or its security state changed since, or for a
    /// registration that has no account yet.
    /// </summary>
    public async Task<SlimUser?> FindUserAsync(SlimFlowPayload state, CancellationToken ct)
    {
        if (state.IsRegistration) return null;
        var user = await store.FindByIdAsync(state.Uid, ct);
        return user is not null && user.IsActive && SlimUser.IsSameSecurityState(user.SecurityStamp, state.Stamp) ? user : null;
    }

    /// <summary>
    /// <c>POST /flow</c>: the open steps of a flow again, with the same token – or the flow a mailed link continues.
    /// Reading changes nothing.
    /// </summary>
    public async Task<IResult> ReadAsync(SlimFlowRequest? request, bool? useCookies, CancellationToken ct)
    {
        if (request is { Token: { } link, FlowToken: null })
            return await services.GetRequiredService<SlimRegistrationFlow>().ExchangeAsync(link, useCookies, ct);
        if (request is null || !TryRead(request.FlowToken, out var state, out var expiresAt)) return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);
        if (state.IsRegistration)
            return await services.GetRequiredService<SlimRegistrationFlow>().ReadAsync(state, request.FlowToken!, expiresAt, ct);
        var user = await FindUserAsync(state, ct);
        var decision = user is null ? default : SlimSignInChain.Evaluate(user, state.Proofs, O);
        if (user is null || decision.Refusal is not null || decision.Complete) return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        return SlimResults.ActionRequired(new SlimActionRequiredResponse
        {
            Actions = decision.Pending,
            FlowToken = request.FlowToken!,
            ExpiresIn = (int)Math.Max(0, (expiresAt - time.GetUtcNow()).TotalSeconds),
            Details = Details(decision, state),
        });
    }

    /// <summary>
    /// The answer of an endpoint for a sign-in result: 200 with the session or the open steps, otherwise the error of
    /// the result's code.
    /// </summary>
    public IResult ToHttpResult(SlimAuthResult result, SlimUser user)
    {
        if (result.Succeeded || result.ActionRequired is not null || result.Vetoed) return SlimLoginHandlers.ToResult(result);
        var now = time.GetUtcNow();
        return result.Error switch
        {
            SlimErrorCodes.AccountDisabled => SlimResults.Status(SlimErrorCodes.AccountDisabled, "The account is disabled.", StatusCodes.Status403Forbidden),
            SlimErrorCodes.EmailNotConfirmed => SlimResults.Status(SlimErrorCodes.EmailNotConfirmed, "The e-mail address has not been confirmed yet.", StatusCodes.Status403Forbidden),
            SlimErrorCodes.LockedOut when user.SecondFactorLockoutEndUtc is { } end => SlimResults.Locked(Http, end, now),
            SlimErrorCodes.TwoFactorUnavailable => SlimResults.Problem(StatusCodes.Status500InternalServerError, SlimErrorCodes.TwoFactorUnavailable,
                "Two-factor authentication is enabled for this user but ISlimTwoFactorStore is not registered."),
            SlimErrorCodes.InvalidToken => SlimResults.InvalidToken(StatusCodes.Status401Unauthorized),
            _ => SlimLoginHandlers.ToResult(result),
        };
    }

    /// <summary>The reason of a sign-in result in the login metrics.</summary>
    public static string MetricReason(SlimAuthResult result) =>
        result.ActionRequired is { } steps ? SlimSignInChain.ErrorCode(steps.Actions[0])
        : result.Succeeded ? "success"
        : result.Error is SlimErrorCodes.EmailNotConfirmed or SlimErrorCodes.LockedOut or SlimErrorCodes.TwoFactorUnavailable or SlimErrorCodes.AccountDisabled ? result.Error
        : "rejected";

    internal static string HashEmailCode(string userId, string code, long issuedAt) =>
        SlimHashing.Sha256Hex($"slimidentity.email-code.v1:{userId}:{issuedAt}:{code}");

    /// <summary>Bound to the address: the code proves this mailbox only.</summary>
    internal static string HashVerificationCode(string userId, string email, string code, long issuedAt) =>
        SlimHashing.Sha256Hex($"slimidentity.verification-code.v1:{userId}:{email.Trim().ToUpperInvariant()}:{issuedAt}:{code}");

    private static DateTimeOffset Deadline(SlimFlowPayload state) =>
        DateTimeOffset.FromUnixTimeMilliseconds(state.StartedAt) + SlimIdentityDefaults.SignInFlowLifetime;

    private async Task<SlimAuthResult> StepsAsync(SlimUser user, SlimFlowPayload state, SlimSignInDecision decision, CancellationToken ct)
    {
        if (decision.Next == SlimSignInActions.VerifyEmail && state.Method is null)
        {
            var issuedAt = time.GetUtcNow().ToUnixTimeMilliseconds();
            state = state with { Method = SlimSignInActions.VerifyEmail, CodeHash = await SendVerificationCodeAsync(user, issuedAt, ct), IssuedAt = issuedAt };
        }
        else if (decision.Next == SlimSignInActions.SecondFactor && state.Method is null or SlimSignInActions.VerifyEmail)
        {
            if (await ChallengeAsync(user, ct) is not { } challenge) return SlimAuthResult.Failed(SlimErrorCodes.TwoFactorUnavailable);
            state = state with { Method = challenge.Method, CodeHash = challenge.CodeHash, IssuedAt = challenge.IssuedAt };
        }

        var lifetime = Deadline(state) - time.GetUtcNow();
        if (lifetime <= TimeSpan.Zero) return SlimAuthResult.Failed(SlimErrorCodes.InvalidToken);

        return SlimAuthResult.Steps(new SlimActionRequiredResponse
        {
            Actions = decision.Pending,
            FlowToken = workflow.Protect(SlimWorkflowTokens.SignInFlowPurpose, state, lifetime),
            ExpiresIn = (int)lifetime.TotalSeconds,
            Details = Details(decision, state),
        });
    }

    private static SlimActionDetails? Details(SlimSignInDecision decision, SlimFlowPayload state) =>
        decision.Next == SlimSignInActions.SecondFactor && state.Method is { } method and not SlimSignInActions.VerifyEmail
            ? new SlimActionDetails
            {
                SecondFactor = new SlimSecondFactorDetails
                {
                    Methods = method == SlimLoginHandlers.MethodRecovery ? [method] : [method, SlimLoginHandlers.MethodRecovery],
                },
            }
            : null;

    /// <summary>The second-factor challenge: the method, and for e-mail codes the sent code's hash.</summary>
    private async Task<(string Method, string? CodeHash, long IssuedAt)?> ChallengeAsync(SlimUser user, CancellationToken ct)
    {
        var twoFactor = services.GetService<SlimTwoFactorService>();
        if (twoFactor is null)
        {
            Log.TwoFactorStoreMissing(logger, user.Id);
            return null;
        }

        var issuedAt = time.GetUtcNow().ToUnixTimeMilliseconds();
        if ((await twoFactor.GetSecretAsync(user, ct)).Configured) return (SlimLoginHandlers.MethodTotp, null, issuedAt);

        // e-mail codes cannot be sent (WithoutEmail, AllowEmailCodes = false): only a recovery code completes the
        // sign-in – or an administrator resets the second factor
        if (!O.EmailCodesEnabled) return (SlimLoginHandlers.MethodRecovery, null, issuedAt);

        var code = SlimTotp.GenerateNumericCode();
        var sent = await SendCodeAsync(SlimEmailKinds.TwoFactorCode, user, (s, x, c) => s.SendTwoFactorCodeAsync(x, user.Email, code, c), ct);
        return (SlimLoginHandlers.MethodEmail, sent ? HashEmailCode(user.Id, code, issuedAt) : null, issuedAt);
    }

    /// <summary>The code of step <c>verify_email</c>: its hash, or <c>null</c> if no mail was sent.</summary>
    private async Task<string?> SendVerificationCodeAsync(SlimUser user, long issuedAt, CancellationToken ct)
    {
        var code = SlimTotp.GenerateNumericCode();
        return await SendCodeAsync(SlimEmailKinds.VerificationCode, user, (s, x, c) => s.SendEmailVerificationCodeAsync(x, user.Email, code, c), ct)
            ? HashVerificationCode(user.Id, user.Email, code, issuedAt)
            : null;
    }

    // Sent inline (the user waits for it). Over the per-recipient limit the step is issued without a mail and without a
    // valid code: a code that was never sent cannot be guessed either.
    private async Task<bool> SendCodeAsync(string kind, SlimUser user, Func<ISlimEmailSender, SlimEmailContext, CancellationToken, Task> send, CancellationToken ct)
    {
        if (!await mailThrottle.TryAcquireAsync(kind, user.Email, ct))
        {
            Log.MailThrottled(logger, kind);
            metrics.Mail(kind, "throttled");
            return false;
        }
        await send(services.GetRequiredService<ISlimEmailSender>(), mailDispatcher.CreateContext(kind, user.Id), ct);
        metrics.Mail(kind, "sent");
        return true;
    }
}
