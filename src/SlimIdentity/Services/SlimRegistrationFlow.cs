using SlimIdentity.Contracts;
using SlimIdentity.Endpoints;
using SlimIdentity.Http;
using SlimIdentity.Security;

namespace SlimIdentity.Services;

/// <summary>
/// The registration with mail: the mailbox is proven before the account exists (<c>verify_email</c>), then the first way
/// to sign in creates it (<c>set_credential</c>). Until then the flow token carries the address instead of an account.
/// </summary>
internal sealed class SlimRegistrationFlow(
    ISlimUserStore store,
    SlimRegistrationService registration,
    SlimSignInFlow flow,
    SlimCredentialService credentials,
    SlimPasswordPolicy passwordPolicy,
    SlimWorkflowTokens workflow,
    SlimEmailDispatcher mail,
    SlimSharedStateAccess sharedState,
    SlimHookRunner hooks,
    SlimLinks links,
    SlimMetrics metrics,
    IOptions<SlimIdentityOptions> options,
    TimeProvider time,
    IHttpContextAccessor httpContextAccessor,
    ILogger<SlimRegistrationFlow> logger)
{
    private SlimIdentityOptions O => options.Value;
    private HttpContext Http => httpContextAccessor.HttpContext!;

    /// <summary>
    /// <c>POST /register</c> with mail: one answer for a free, a taken and a throttled address – the mail decides. A free
    /// address gets a code and a link, a taken one the "account exists" mail.
    /// </summary>
    public async Task<IResult> BeginAsync(SlimRegisterRequest? request, bool? useCookies, CancellationToken ct)
    {
        if (!SlimModes.TryResolve(O, useCookies, out var cookies, out var modeError)) return modeError!;
        if (request is not null && (request.Password is not null || request.Profile is not null))
        {
            const string later = "Sent with POST /register/password, once the address is confirmed.";
            var errors = new Dictionary<string, string[]>(StringComparer.Ordinal);
            if (request.Password is not null) errors["password"] = [later];
            if (request.Profile is not null) errors["profile"] = [later];
            return SlimResults.Validation(errors);
        }

        var email = SlimEmailAddress.Normalize(request?.Email);
        if (!SlimRegistrationService.IsValidEmail(email)) return SlimRegistrationService.InvalidEmail("email");

        // the host's veto – decided from the request alone, before anything is looked up (no enumeration)
        if (await hooks.CheckRegistrationAsync(email, null, ct) is { } veto)
            return SlimResults.Status(veto.Error, veto.Message ?? "Registration is not allowed.", StatusCodes.Status403Forbidden);

        var now = time.GetUtcNow();
        var issuedAt = now.ToUnixTimeMilliseconds();
        var flowId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        string? codeHash = null;

        // the mail is sent in the background (if configured): its latency does not tell a free address from a taken one
        var existing = await store.FindByEmailAsync(email, ct);
        if (existing is null)
        {
            var code = SlimTotp.GenerateNumericCode();
            var token = workflow.Protect(SlimWorkflowTokens.LinkPurpose, new SlimLinkPayload(SlimLinkPayload.Registration, flowId, email),
                O.Tokens.EmailVerificationTokenLifetime);
            var link = links.Build(SlimLinkKind.EmailVerification, token);
            if (await mail.SendAsync(SlimEmailKinds.Verification, email, null, (s, x, c) => s.SendVerificationEmailAsync(x, email, code, link, c), ct))
                codeHash = SlimSignInFlow.HashVerificationCode("", email, code, issuedAt);
            metrics.Registration("started");
        }
        else
        {
            Log.RegistrationForExistingAccount(logger, existing.Id);
            await mail.SendAsync(SlimEmailKinds.AccountExists, existing.Email, existing.Id, (s, x, c) => s.SendAccountExistsEmailAsync(x, existing.Email, c), ct);
            metrics.Registration("existing_account");
        }

        var state = new SlimFlowPayload("", "", flowId, issuedAt, SlimSignInProofs.None, "", cookies, request!.RememberMe,
            Method: SlimSignInActions.VerifyEmail, CodeHash: codeHash, IssuedAt: issuedAt, Email: email);
        return Steps(state);
    }

    /// <summary><c>POST /register/verify</c>: the mailed code proves the mailbox; next is <c>set_credential</c>.</summary>
    public async Task<IResult> VerifyAsync(SlimVerifyEmailLoginRequest? request, CancellationToken ct)
    {
        if (request is null || !flow.TryRead(request.FlowToken, out var state, out _)
            || !state.IsRegistration || state.Method != SlimSignInActions.VerifyEmail || state.Proofs.HasFlag(SlimSignInProofs.Mailbox))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        // ends in a cookie sign-in without carrying a cookie – only the signed token knows (as on /login/2fa)
        if (state.UseCookies && SlimCsrfEndpointFilter.Validate(Http.Request, O, logger) is { } csrfError) return csrfError;

        // counted before the check: of parallel guesses, at most the limit is checked
        if (await sharedState.CountAsync(SlimSharedStateAccess.VerificationCodeFlow, state.FlowId, SlimIdentityDefaults.SignInFlowLifetime, ct) > SlimLoginHandlers.VerificationAttemptsPerFlow
            || await sharedState.CountAsync(SlimSharedStateAccess.VerificationCodeAddress, state.Email!.Trim().ToUpperInvariant(), SlimLoginHandlers.VerificationAddressWindow, ct) > SlimLoginHandlers.VerificationAttemptsPerAddress)
        {
            metrics.Registration(SlimErrorCodes.TooManyAttempts);
            return SlimResults.Status(SlimErrorCodes.TooManyAttempts,
                "Too many attempts. Open the link of the verification mail instead.", StatusCodes.Status429TooManyRequests);
        }

        var code = SlimTotp.NormalizeCode(request.Code);
        if (code.Length != 6 || state.CodeHash is null
            || !SlimHashing.FixedTimeEquals(SlimSignInFlow.HashVerificationCode("", state.Email, code, state.IssuedAt), state.CodeHash))
        {
            metrics.Registration(SlimErrorCodes.InvalidVerificationCode);
            return SlimResults.Status(SlimErrorCodes.InvalidVerificationCode, "The code is invalid.", StatusCodes.Status401Unauthorized);
        }

        if (await store.FindByEmailAsync(state.Email, ct) is not null) return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);
        return Steps(Proven(state, state.UseCookies, state.RememberMe));
    }

    /// <summary>
    /// <c>POST /flow</c> with the token of a registration link: proves the mailbox like the code and continues the flow –
    /// in the mode of this request (the link may open on another device).
    /// </summary>
    public async Task<IResult> ExchangeAsync(string token, bool? useCookies, CancellationToken ct)
    {
        if (!SlimModes.TryResolve(O, useCookies, out var cookies, out var modeError)) return modeError!;
        if (!O.Endpoints.EnableRegistration
            || !workflow.TryUnprotect<SlimLinkPayload>(SlimWorkflowTokens.LinkPurpose, token, out var link)
            || link.Kind != SlimLinkPayload.Registration || link.Email is null
            || await store.FindByEmailAsync(link.Email, ct) is not null)
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        var state = new SlimFlowPayload("", "", link.FlowId, 0, SlimSignInProofs.None, "", cookies, false, Email: link.Email);
        return Steps(Proven(state, cookies, false));
    }

    /// <summary><c>POST /flow</c> with the flow token of a registration: its open steps again. Changes nothing.</summary>
    public async Task<IResult> ReadAsync(SlimFlowPayload state, string flowToken, DateTimeOffset expiresAt, CancellationToken ct)
    {
        if (await store.FindByEmailAsync(state.Email!, ct) is not null) return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);
        var decision = SlimSignInChain.EvaluateRegistration(state.Proofs);
        return SlimResults.ActionRequired(new SlimActionRequiredResponse
        {
            Actions = decision.Pending,
            FlowToken = flowToken,
            ExpiresIn = (int)Math.Max(0, (expiresAt - time.GetUtcNow()).TotalSeconds),
            Details = Details(decision),
        });
    }

    /// <summary>
    /// <c>POST /register/password</c>: step <c>set_credential</c> with a password. Creates the account with its address
    /// confirmed and continues like a sign-in with that password – the session, once per flow.
    /// </summary>
    public async Task<IResult> CompleteWithPasswordAsync(SlimRegisterPasswordRequest? request, CancellationToken ct)
    {
        if (request is null || !flow.TryRead(request.FlowToken, out var state, out _)
            || !state.IsRegistration || !state.Proofs.HasFlag(SlimSignInProofs.Mailbox))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        if (state.UseCookies && SlimCsrfEndpointFilter.Validate(Http.Request, O, logger) is { } csrfError) return csrfError;

        var email = state.Email!;
        if (await passwordPolicy.ValidateAsync(request.Password, email, ct) is { } errors) return SlimResults.Validation(errors);
        var (profile, invalidProfile) = await registration.ValidateProfileAsync(email, request.Profile, ct);
        if (invalidProfile is not null) return invalidProfile;

        var hash = credentials.HashPassword(new SlimUser { Email = email }, request.Password);
        var user = await store.CreateAsync(new SlimNewUser { Email = email, PasswordHash = hash, Profile = profile, EmailConfirmed = true }, ct);
        if (user is null)
        {
            // a second completion of the flow, or another registration of the address – the mailbox owner knows already
            Log.RegistrationRaceLost(logger);
            return SlimResults.Status(SlimErrorCodes.EmailTaken, "The address already has an account.", StatusCodes.Status409Conflict);
        }
        metrics.Registration("created");
        await hooks.RaiseAsync(SlimEventTypes.UserCreated, user.Id, reason: "registration", ct: ct);
        await hooks.RaiseAsync(SlimEventTypes.EmailConfirmed, user.Id, ct: ct);

        var result = await flow.ContinueAsync(user, state with
        {
            Uid = user.Id, Stamp = user.SecurityStamp, Proofs = state.Proofs | SlimSignInProofs.Password, Amr = SlimAuthManager.MethodPassword,
            Email = null, Method = null, CodeHash = null, IssuedAt = 0,
        }, ct);
        metrics.Login(SlimSignInFlow.MetricReason(result), state.UseCookies);
        return flow.ToHttpResult(result, user);
    }

    /// <summary>The mailbox is proven: the rest of the flow starts now, with its own lifetime.</summary>
    private SlimFlowPayload Proven(SlimFlowPayload state, bool cookies, bool rememberMe) => state with
    {
        StartedAt = time.GetUtcNow().ToUnixTimeMilliseconds(), Proofs = state.Proofs | SlimSignInProofs.Mailbox,
        UseCookies = cookies, RememberMe = rememberMe, Method = null, CodeHash = null, IssuedAt = 0,
    };

    private IResult Steps(SlimFlowPayload state)
    {
        var decision = SlimSignInChain.EvaluateRegistration(state.Proofs);
        var lifetime = DateTimeOffset.FromUnixTimeMilliseconds(state.StartedAt) + SlimIdentityDefaults.SignInFlowLifetime - time.GetUtcNow();
        return SlimResults.ActionRequired(new SlimActionRequiredResponse
        {
            Actions = decision.Pending,
            FlowToken = workflow.Protect(SlimWorkflowTokens.SignInFlowPurpose, state, lifetime),
            ExpiresIn = (int)lifetime.TotalSeconds,
            Details = Details(decision),
        });
    }

    private static SlimActionDetails? Details(SlimSignInDecision decision) =>
        decision.Next == SlimSignInActions.SetCredential
            ? new SlimActionDetails { SetCredential = new SlimSetCredentialDetails { Kinds = ["password"] } }
            : null;
}
