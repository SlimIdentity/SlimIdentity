using System.Buffers.Text;
using SlimIdentity.Contracts;
using SlimIdentity.Diagnostics;
using SlimIdentity.Endpoints;
using SlimIdentity.Http;
using SlimIdentity.Security;
using SlimIdentity.Services;

namespace SlimIdentity.Passkeys;

/// <summary>
/// Passkeys (WebAuthn): registration for the signed-in account, sign-in without a user name (discoverable
/// credentials), renaming and removal. Every check of Web Authentication Level 2 §7.1/§7.2 that matters without
/// attestation: type, challenge, origin, RP id hash, user presence and verification, algorithm, signature, counter,
/// single use.
/// </summary>
internal sealed class SlimPasskeyHandlers(
    ISlimPasskeyStore passkeys,
    ISlimUserStore store,
    SlimAccountHandlers account,
    SlimCredentialService credentials,
    SlimAuthManager authManager,
    SlimWorkflowTokens workflow,
    SlimHookRunner hooks,
    SlimMetrics metrics,
    IOptions<SlimIdentityOptions> options,
    IOptions<SlimPasskeyOptions> passkeyOptions,
    TimeProvider time,
    IServiceProvider services,
    IHttpContextAccessor httpContextAccessor,
    ILogger<SlimPasskeyHandlers> logger)
{
    private static readonly TimeSpan CeremonyLifetime = TimeSpan.FromMinutes(5);
    private const string PublicKey = "public-key";

    private SlimIdentityOptions O => options.Value;
    private HttpContext Http => httpContextAccessor.HttpContext!;
    private string RpId => passkeyOptions.Value.EffectiveRelyingPartyId(O.Links)
        ?? throw new InvalidOperationException("SlimIdentity: set the relying party id of the passkeys (or Links.BaseUrl).");

    // ------------------------------------------------------------------ registration (signed in)

    public async Task<IResult> RegistrationOptionsAsync(SlimPasskeyRegistrationOptionsRequest? request, CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;
        // like 2FA and linking: never on an unconfirmed account (the registrant may not own the address)
        if (O.Email.Enabled && !user.EmailConfirmed)
            return SlimResults.Status(SlimErrorCodes.EmailNotConfirmed, "Confirm your e-mail address before adding a passkey.", StatusCodes.Status403Forbidden);
        // a passkey adds to a local sign-in method (a password or a passkey), never replaces SSO: an account that signs
        // in only externally gets no local method this way
        var existing = await passkeys.GetPasskeysAsync(user.Id, ct);
        if (existing.Count == 0 && !await credentials.HasPasswordAsync(user, ct))
            return SlimResults.Status(SlimErrorCodes.PasswordRequired, "The account needs a password before a passkey can be added.", StatusCodes.Status403Forbidden);
        // a new way in: a stolen session alone must not add one – the password, or without one a recent sign-in
        if (await credentials.ConfirmPasswordAsync(user, request?.Password, Http, ct) is { } failure)
            return failure;

        var challenge = SlimWebAuthn.NewChallenge();
        var userHandle = Base64Url.EncodeToString(UserHandleFor(user.Id, existing));
        var state = workflow.Protect(SlimPasskeyPurposes.Registration, new SlimPasskeyRegistrationPayload(user.Id, user.SecurityStamp, challenge, userHandle),
            CeremonyLifetime, SlimPasskeyJsonContext.Default.SlimPasskeyRegistrationPayload);

        return Results.Ok(CreationOptions(new SlimPasskeyUser(userHandle, user.Email, user.Email), challenge,
            [.. existing.Select(p => new SlimPasskeyCredentialDescriptor(PublicKey, Base64Url.EncodeToString(p.CredentialId)))], state));
    }

    public async Task<IResult> RegisterAsync(SlimPasskeyRegisterRequest? request, CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;

        if (request?.Credential is not { Type: PublicKey } credential
            || !workflow.TryUnprotect(SlimPasskeyPurposes.Registration, request.State, SlimPasskeyJsonContext.Default.SlimPasskeyRegistrationPayload, out var state)
            || !string.Equals(state.Uid, user.Id, StringComparison.Ordinal)
            || !SlimUser.IsSameSecurityState(state.Stamp, user.SecurityStamp))
            return Rejected("registration", "state");
        var (authData, reason) = VerifyCreation(credential, state.Challenge);
        if (authData is null) return Rejected("registration", reason!);

        var passkey = NewPasskey(user.Id, state.UserHandle, authData, request.Name);
        if (!await passkeys.AddPasskeyAsync(passkey, ct)) return PasskeyExists();

        Log.PasskeyAdded(logger, user.Id);
        await hooks.RaiseAsync(SlimEventTypes.PasskeyAdded, user.Id, SlimAuthManager.MethodPasskey, ct: ct);
        return Results.Ok(new SlimPasskeyInfo(Base64Url.EncodeToString(passkey.CredentialId), passkey.Name, passkey.CreatedUtc, null,
            passkey.BackupEligible, passkey.BackedUp));
    }

    // ------------------------------------------------------------------ registration of a new account (step set_credential)

    /// <summary>
    /// <c>POST /register/passkey/options</c>: the creation options for the passkey of step <c>set_credential</c> – the
    /// first of a registration whose mailbox is proven, or the new way in of an existing account. The state is bound to
    /// the flow.
    /// </summary>
    public async Task<IResult> NewAccountOptionsAsync(SlimRegisterPasskeyOptionsRequest? request, CancellationToken ct)
    {
        var (flow, account, error) = await services.GetRequiredService<SlimCredentialSetup>().ReadAsync(request?.FlowToken, ct);
        if (flow is null) return error!;

        // a reset that takes over an unconfirmed account removes its passkeys: they neither name nor exclude the new one
        IReadOnlyList<SlimPasskey> existing = account is null || SlimSignInChain.ResetsUnconfirmedAccount(account, flow)
            ? [] : await passkeys.GetPasskeysAsync(account.Id, ct);
        var challenge = SlimWebAuthn.NewChallenge();
        var userHandle = Base64Url.EncodeToString(account is null ? RandomNumberGenerator.GetBytes(32) : UserHandleFor(account.Id, existing));
        var state = workflow.Protect(SlimPasskeyPurposes.NewAccount, new SlimPasskeyNewAccountPayload(flow.FlowId, challenge, userHandle),
            CeremonyLifetime, SlimPasskeyJsonContext.Default.SlimPasskeyNewAccountPayload);
        var email = account?.Email ?? flow.Email!;
        return Results.Ok(CreationOptions(new SlimPasskeyUser(userHandle, email, email), challenge,
            [.. existing.Select(p => new SlimPasskeyCredentialDescriptor(PublicKey, Base64Url.EncodeToString(p.CredentialId)))], state));
    }

    /// <summary>
    /// <c>POST /register/passkey</c>: step <c>set_credential</c> with a passkey. Verifies the ceremony; a registration
    /// creates the account with its address confirmed and the passkey, an existing account gets the passkey instead of
    /// its password. Continues like a passkey sign-in – the session.
    /// </summary>
    public async Task<IResult> RegisterNewAccountAsync(SlimRegisterPasskeyRequest? request, CancellationToken ct)
    {
        var setup = services.GetRequiredService<SlimCredentialSetup>();
        var (flow, account, error) = await setup.ReadAsync(request?.FlowToken, ct);
        if (flow is null) return error!;

        if (request!.Credential is not { Type: PublicKey } credential
            || !workflow.TryUnprotect(SlimPasskeyPurposes.NewAccount, request.State, SlimPasskeyJsonContext.Default.SlimPasskeyNewAccountPayload, out var state)
            || !string.Equals(state.FlowId, flow.FlowId, StringComparison.Ordinal))
            return Rejected("registration", "state");
        if (account is not null) return await ReplaceCredentialAsync(setup, account, flow, credential, state, request, ct);

        var registration = services.GetRequiredService<SlimRegistrationFlow>();
        var (profile, invalidProfile) = await registration.ValidateProfileAsync(flow, request.Profile, ct);
        if (invalidProfile is not null) return invalidProfile;
        var (authData, reason) = VerifyCreation(credential, state.Challenge);
        if (authData is null) return Rejected("registration", reason!);
        // before the account exists: a known credential must not leave an account without a way in
        if (await passkeys.FindPasskeyAsync(authData.CredentialId!, ct) is not null) return PasskeyExists();

        var (user, taken) = await registration.CreateAccountAsync(flow, SlimCredentialKinds.Passkey, null, profile, ct);
        if (user is null) return taken!;
        var passkey = NewPasskey(user.Id, state.UserHandle, authData, request.Name);
        if (!await passkeys.AddPasskeyAsync(passkey, ct))
        {
            // registered in parallel: the account has no way in yet – /forgot-password gives it a password
            Log.PasskeyRejected(logger, "registration", "credential registered meanwhile");
            return PasskeyExists();
        }

        Log.PasskeyAdded(logger, user.Id);
        await hooks.RaiseAsync(SlimEventTypes.PasskeyAdded, user.Id, SlimAuthManager.MethodPasskey, ct: ct);
        return await registration.SignInAsync(user, flow, SlimSignInProofs.SecondFactor, SlimAuthManager.MethodPasskey, ct);
    }

    private async Task<IResult> ReplaceCredentialAsync(SlimCredentialSetup setup, SlimUser user, SlimFlowPayload flow,
        SlimPasskeyCredential credential, SlimPasskeyNewAccountPayload state, SlimRegisterPasskeyRequest request, CancellationToken ct)
    {
        if (request.Profile is not null) return SlimCredentialSetup.ProfileRefused();
        var (authData, reason) = VerifyCreation(credential, state.Challenge);
        if (authData is null) return Rejected("registration", reason!);
        // before the password goes: a known credential must not leave the account without a way in
        if (await passkeys.FindPasskeyAsync(authData.CredentialId!, ct) is not null) return PasskeyExists();

        return await setup.CompleteAsync(user, flow, null, async c =>
        {
            var passkey = NewPasskey(user.Id, state.UserHandle, authData, request.Name);
            if (!await passkeys.AddPasskeyAsync(passkey, c))
            {
                // registered in parallel: the account has no way in now – a new reset link gives it one
                Log.PasskeyRejected(logger, "registration", "credential registered meanwhile");
                return PasskeyExists();
            }
            Log.PasskeyAdded(logger, user.Id);
            await hooks.RaiseAsync(SlimEventTypes.PasskeyAdded, user.Id, SlimAuthManager.MethodPasskey, ct: c);
            return null;
        }, ct);
    }

    // ------------------------------------------------------------------ sign-in (anonymous, discoverable credentials)

    public IResult LoginOptions()
    {
        var challenge = SlimWebAuthn.NewChallenge();
        var state = workflow.Protect(SlimPasskeyPurposes.Login, new SlimPasskeyLoginPayload(challenge, time.GetUtcNow().ToUnixTimeMilliseconds()),
            CeremonyLifetime, SlimPasskeyJsonContext.Default.SlimPasskeyLoginPayload);
        return Results.Ok(new SlimPasskeyRequestOptionsResponse(
            new SlimPasskeyRequestOptions(challenge, RpId, (int)CeremonyLifetime.TotalMilliseconds, "required", []), state));
    }

    public async Task<IResult> LoginAsync(SlimPasskeyLoginRequest? request, bool? useCookies, CancellationToken ct)
    {
        if (!SlimModes.TryResolve(O, useCookies, out var cookies, out var modeError)) return modeError!;
        if (request?.Credential is not { Type: PublicKey, Response: { } response } credential
            || !workflow.TryUnprotect(SlimPasskeyPurposes.Login, request.State, SlimPasskeyJsonContext.Default.SlimPasskeyLoginPayload, out var state))
            return Failed("state");

        // §7.2 steps 10–15: client data
        var clientDataJson = SlimWebAuthn.FromBase64Url(response.ClientDataJson);
        if (clientDataJson is null || SlimWebAuthn.ParseClientData(clientDataJson) is not { } clientData) return Failed("client data");
        if (clientData.Type != "webauthn.get") return Failed("type");
        if (!SlimHashing.FixedTimeEquals(clientData.Challenge, state.Challenge)) return Failed("challenge");
        if (!OriginAllowed(clientData)) return Failed("origin");

        // §7.2 steps 16–18: authenticator data
        var authDataBytes = SlimWebAuthn.FromBase64Url(response.AuthenticatorData);
        if (authDataBytes is null || SlimWebAuthn.ParseAuthenticatorData(authDataBytes) is not { } authData) return Failed("authenticator data");
        if (!SlimWebAuthn.IsForRelyingParty(authData, RpId)) return Failed("rp id");
        if (!authData.UserPresent || !authData.UserVerified) return Failed("user verification");
        if (!authData.BackupFlagsValid) return Failed("backup flags");

        // §7.2 steps 5–6: the credential and its owner
        if (SlimWebAuthn.FromBase64Url(credential.RawId) is not { } credentialId
            || await passkeys.FindPasskeyAsync(credentialId, ct) is not { } passkey)
            return Failed("unknown credential");
        if (response.UserHandle is { Length: > 0 } handle
            && !string.Equals(handle, Base64Url.EncodeToString(passkey.UserHandle is { Length: > 0 } stored ? stored : Encoding.UTF8.GetBytes(passkey.UserId)), StringComparison.Ordinal))
            return Failed("user handle");

        // §7.2 step 20: the signature
        var signature = SlimWebAuthn.FromBase64Url(response.Signature);
        if (signature is null || !SlimWebAuthn.VerifySignature(passkey.PublicKey, authDataBytes, clientDataJson, signature))
            return Failed("signature");

        // backup eligibility is a fixed property of the credential: a change means it is not the authenticator registered
        if (authData.BackupEligible != passkey.BackupEligible) return Failed("backup eligibility");

        // §7.2 step 21: a counter that does not increase hints at a cloned authenticator (most synced passkeys send 0)
        if ((authData.SignCount != 0 || passkey.SignCount != 0) && authData.SignCount <= passkey.SignCount)
        {
            Log.PasskeyCounterRegression(logger, passkey.UserId);
            return Failed("counter");
        }

        // the account before anything is recorded: an inactive or locked account leaves no trace on its passkey.
        // Possession and user verification are multi-factor on their own – no second factor follows; an unconfirmed
        // address still has to be proven in the flow that follows.
        var user = await store.FindByIdAsync(passkey.UserId, ct);
        if (user is null) return Failed("account");
        var flow = services.GetRequiredService<SlimSignInFlow>();
        var decision = SlimSignInChain.Evaluate(user, SlimSignInProofs.SecondFactor, O);
        if (decision.Refusal is not null)
        {
            var refused = SlimAuthResult.Failed(decision.Refusal);
            metrics.Login(SlimSignInFlow.MetricReason(refused), cookies);
            return flow.ToHttpResult(refused, user);
        }

        // single use, atomically: this challenge must be newer than the last one used with this passkey
        if (!await passkeys.TryRecordUseAsync(credentialId, passkey.SignCount, authData.SignCount, state.IssuedAt, time.GetUtcNow(), authData.BackedUp, ct))
            return Failed("replay");

        // a start password set by an administrator is replaced in the flow that follows
        var result = await flow.StartAsync(user, cookies, request.RememberMe, SlimAuthManager.MethodPasskey, SlimSignInProofs.SecondFactor,
            checkRememberedDevice: false, rememberToken: null, refuseLockedSecondFactor: false, ct);
        metrics.Login(SlimSignInFlow.MetricReason(result), cookies);
        return flow.ToHttpResult(result, user);

        IResult Failed(string reason)
        {
            metrics.Login("passkey_rejected", cookies);
            Log.PasskeyRejected(logger, "sign-in", reason);
            return SlimResults.Status(SlimErrorCodes.InvalidPasskey, "The passkey could not be verified.", StatusCodes.Status401Unauthorized);
        }
    }

    // ------------------------------------------------------------------ sign-in methods: rename, remove

    public async Task<IResult> RenameAsync(SlimPasskeyRenameRequest? request, CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;
        if (CleanName(request?.Name) is not { } name)
            return SlimResults.BadRequest(SlimErrorCodes.InvalidName, "The name must have 1–64 characters.");
        return SlimWebAuthn.FromBase64Url(request?.Id) is { } id && await passkeys.RenamePasskeyAsync(user.Id, id, name, ct)
            ? SlimResults.Status("passkey_renamed")
            : NotFound();
    }

    public async Task<IResult> RemoveAsync(SlimRemovePasskeyRequest? request, CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;
        if (SlimWebAuthn.FromBase64Url(request?.Id) is not { } id) return NotFound();
        if (!(await passkeys.GetPasskeysAsync(user.Id, ct)).Any(p => p.CredentialId.AsSpan().SequenceEqual(id))) return NotFound();

        // the password – or, without one, a fresh sign-in – keeps a stolen session from cutting the owner's methods
        if (await credentials.ConfirmPasswordAsync(user, request?.Password, Http, ct) is { } failure) return failure;
        if (!await credentials.HasPasswordAsync(user, ct))
        {
            // no password: passkeys and external logins are the only ways in
            var external = services.GetService<ISlimExternalLoginStore>() is { } externalStore
                ? (await externalStore.GetExternalLoginsAsync(user.Id, ct)).Count : 0;
            if ((await passkeys.GetPasskeysAsync(user.Id, ct)).Count + external <= 1) return SlimSignInMethodHandlers.LastMethod();
        }

        // a new stamp bound to the state this request saw: of two parallel removals – on any instance – only one passes
        if (!await store.TryWriteSecurityStateAsync(user, u => u.SecurityStamp = SlimUser.NewSecurityStamp(), ct))
            return SlimResults.ConcurrentChange();
        await passkeys.RemovePasskeyAsync(user.Id, id, ct);

        Log.PasskeyRemoved(logger, user.Id);
        await hooks.RaiseAsync(SlimEventTypes.PasskeyRemoved, user.Id, SlimAuthManager.MethodPasskey, ct: ct);
        await authManager.RevokeSessionsAsync(user.Id, SlimAuthManager.CurrentSessionId(Http.User), ct);
        return SlimResults.ReissuedSession(await authManager.RefreshCurrentSessionAsync(user, ct));
    }

    // ------------------------------------------------------------------ helpers

    private SlimPasskeyCreationOptionsResponse CreationOptions(SlimPasskeyUser user, string challenge,
        SlimPasskeyCredentialDescriptor[] exclude, string state) =>
        new(new SlimPasskeyCreationOptions(
            new SlimPasskeyRelyingParty(RpId, passkeyOptions.Value.RelyingPartyName ?? O.TwoFactor.AuthenticatorIssuer),
            user,
            challenge,
            [new(PublicKey, SlimWebAuthn.Es256), new(PublicKey, SlimWebAuthn.Rs256)],
            (int)CeremonyLifetime.TotalMilliseconds,
            "none",
            new SlimPasskeyAuthenticatorSelection("required", true, "required"),
            exclude),
            state);

    /// <summary>
    /// Web Authentication §7.1 for a new credential: client data and authenticator data, the attestation statement not
    /// evaluated (attestation "none"). The authenticator data with credential id and public key, or the reason of the
    /// rejection.
    /// </summary>
    private (SlimWebAuthn.AuthenticatorData? Data, string? Rejection) VerifyCreation(SlimPasskeyCredential credential, string challenge)
    {
        // §7.1 steps 5–14: client data
        var clientDataJson = SlimWebAuthn.FromBase64Url(credential.Response?.ClientDataJson);
        if (clientDataJson is null || SlimWebAuthn.ParseClientData(clientDataJson) is not { } clientData) return Reject("client data");
        if (clientData.Type != "webauthn.create") return Reject("type");
        if (!SlimHashing.FixedTimeEquals(clientData.Challenge, challenge)) return Reject("challenge");
        if (!OriginAllowed(clientData)) return Reject("origin");

        // §7.1 steps 15–21: authenticator data
        var attestation = SlimWebAuthn.FromBase64Url(credential.Response!.AttestationObject);
        if (attestation is null || SlimWebAuthn.AuthenticatorDataOfAttestation(attestation) is not { } authDataBytes
            || SlimWebAuthn.ParseAuthenticatorData(authDataBytes) is not { CredentialId: { } credentialId, CredentialPublicKey: { } publicKey } authData)
            return Reject("authenticator data");
        if (!SlimWebAuthn.IsForRelyingParty(authData, RpId)) return Reject("rp id");
        if (!authData.UserPresent || !authData.UserVerified) return Reject("user verification");
        if (!authData.BackupFlagsValid) return Reject("backup flags");
        if (SlimWebAuthn.AlgorithmOf(publicKey) is null) return Reject("algorithm");
        if (SlimWebAuthn.FromBase64Url(credential.RawId) is not { } rawId || !rawId.AsSpan().SequenceEqual(credentialId))
            return Reject("credential id");
        return (authData, null);

        static (SlimWebAuthn.AuthenticatorData?, string?) Reject(string reason) => (null, reason);
    }

    private SlimPasskey NewPasskey(string userId, string userHandle, SlimWebAuthn.AuthenticatorData authData, string? name) => new()
    {
        UserId = userId,
        UserHandle = Base64Url.DecodeFromChars(userHandle),
        CredentialId = authData.CredentialId!,
        PublicKey = authData.CredentialPublicKey!,
        SignCount = authData.SignCount,
        BackupEligible = authData.BackupEligible,
        BackedUp = authData.BackedUp,
        Name = CleanName(name) ?? "Passkey",
        CreatedUtc = time.GetUtcNow(),
    };

    private static IResult PasskeyExists() =>
        SlimResults.Status(SlimErrorCodes.PasskeyExists, "This passkey is already registered.", StatusCodes.Status409Conflict);

    /// <summary>
    /// The handle of the account's passkeys, so an authenticator keeps one entry per account; random for the first
    /// one – the user id (an e-mail address or a sequential number) never goes to the authenticator.
    /// </summary>
    private static byte[] UserHandleFor(string userId, IReadOnlyList<SlimPasskey> existing) =>
        existing.FirstOrDefault(p => p.UserHandle is { Length: > 0 })?.UserHandle
        ?? (existing.Count > 0 ? Encoding.UTF8.GetBytes(userId) : RandomNumberGenerator.GetBytes(32));

    /// <summary>The page that ran the ceremony: trusted (origin policy, or the API's own origin) and within the RP id.</summary>
    private bool OriginAllowed(SlimWebAuthn.ClientData clientData)
    {
        if (clientData.CrossOrigin || !SlimWebAuthn.OriginMatchesRelyingParty(clientData.Origin, RpId)) return false;
        var self = $"{Http.Request.Scheme}://{Http.Request.Host.Value}";
        return string.Equals(clientData.Origin.TrimEnd('/'), self, StringComparison.OrdinalIgnoreCase)
            || SlimLinks.IsTrustedOrigin(Http, clientData.Origin);
    }

    private static string? CleanName(string? name)
    {
        var trimmed = name?.Trim();
        return string.IsNullOrEmpty(trimmed) || trimmed.Length > 64 || trimmed.Any(char.IsControl) ? null : trimmed;
    }

    private static IResult NotFound() =>
        SlimResults.Status(SlimErrorCodes.PasskeyNotFound, "This passkey is not registered for your account.", StatusCodes.Status404NotFound);

    private IResult Rejected(string ceremony, string reason)
    {
        Log.PasskeyRejected(logger, ceremony, reason);
        return SlimResults.BadRequest(SlimErrorCodes.InvalidPasskey, "The passkey could not be verified.");
    }
}
