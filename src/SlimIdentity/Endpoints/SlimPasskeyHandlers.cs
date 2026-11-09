using System.Buffers.Text;
using SlimIdentity.Contracts;
using SlimIdentity.Http;
using SlimIdentity.Security;
using SlimIdentity.Services;

namespace SlimIdentity.Endpoints;

/// <summary>
/// Passkeys (WebAuthn): registration for the signed-in account, sign-in without a user name (discoverable
/// credentials), renaming. Every check of Web Authentication Level 2 §7.1/§7.2 that matters without attestation:
/// type, challenge, origin, RP id hash, user presence and verification, algorithm, signature, counter, single use.
/// </summary>
internal sealed class SlimPasskeyHandlers(
    ISlimPasskeyStore passkeys,
    ISlimUserStore store,
    SlimAccountHandlers account,
    SlimCredentialService credentials,
    SlimLoginHandlers login,
    SlimAuthManager authManager,
    SlimWorkflowTokens workflow,
    SlimHookRunner hooks,
    SlimMetrics metrics,
    IOptions<SlimIdentityOptions> options,
    TimeProvider time,
    IServiceProvider services,
    IHttpContextAccessor httpContextAccessor,
    ILogger<SlimPasskeyHandlers> logger)
{
    private static readonly TimeSpan CeremonyLifetime = TimeSpan.FromMinutes(5);
    private const string PublicKey = "public-key";

    private SlimIdentityOptions O => options.Value;
    private HttpContext Http => httpContextAccessor.HttpContext!;
    private string RpId => O.Passkeys.EffectiveRelyingPartyId(O.Links)
        ?? throw new InvalidOperationException("SlimIdentity: set Passkeys.RelyingPartyId (or Links.BaseUrl).");

    // ------------------------------------------------------------------ registration (signed in)

    public async Task<IResult> RegistrationOptionsAsync(SlimPasskeyRegistrationOptionsRequest? request, CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;
        // like 2FA and linking: never on an unconfirmed account (the registrant may not own the address)
        if (O.Email.Enabled && !user.EmailConfirmed)
            return SlimResults.Status("email_not_confirmed", "Confirm your e-mail address before adding a passkey.", StatusCodes.Status403Forbidden);
        // a new way in: a stolen session alone must not add one
        if (HasPassword(user) && await credentials.ConfirmPasswordAsync(user, request?.Password, Http, ct) is { } failure)
            return failure;

        var challenge = SlimWebAuthn.NewChallenge();
        var existing = await passkeys.GetPasskeysAsync(user.Id, ct);
        var state = workflow.Protect(SlimWorkflowTokens.PasskeyRegistrationPurpose,
            new SlimPasskeyRegistrationPayload(user.Id, user.SecurityStamp, challenge), CeremonyLifetime);

        return Results.Ok(new SlimPasskeyCreationOptionsResponse(new SlimPasskeyCreationOptions(
            new SlimPasskeyRelyingParty(RpId, O.Passkeys.RelyingPartyName ?? O.TwoFactor.AuthenticatorIssuer),
            new SlimPasskeyUser(Base64Url.EncodeToString(Encoding.UTF8.GetBytes(user.Id)), user.Email, user.Email),
            challenge,
            [new(PublicKey, SlimWebAuthn.Es256), new(PublicKey, SlimWebAuthn.Rs256)],
            (int)CeremonyLifetime.TotalMilliseconds,
            "none",
            new SlimPasskeyAuthenticatorSelection("required", true, "required"),
            [.. existing.Select(p => new SlimPasskeyCredentialDescriptor(PublicKey, Base64Url.EncodeToString(p.CredentialId)))]),
            state));
    }

    public async Task<IResult> RegisterAsync(SlimPasskeyRegisterRequest? request, CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;

        if (request?.Credential is not { Type: PublicKey } credential
            || !workflow.TryUnprotect<SlimPasskeyRegistrationPayload>(SlimWorkflowTokens.PasskeyRegistrationPurpose, request.State, out var state)
            || !string.Equals(state.Uid, user.Id, StringComparison.Ordinal)
            || !SlimUser.IsSameSecurityState(state.Stamp, user.SecurityStamp))
            return Rejected("registration", "state");

        // §7.1 steps 5–14: client data
        var clientDataJson = SlimWebAuthn.FromBase64Url(credential.Response.ClientDataJson);
        if (clientDataJson is null || SlimWebAuthn.ParseClientData(clientDataJson) is not { } clientData) return Rejected("registration", "client data");
        if (clientData.Type != "webauthn.create") return Rejected("registration", "type");
        if (!SlimHashing.FixedTimeEquals(clientData.Challenge, state.Challenge)) return Rejected("registration", "challenge");
        if (!OriginAllowed(clientData)) return Rejected("registration", "origin");

        // §7.1 steps 15–21: authenticator data (attestation statement not evaluated: attestation "none")
        var attestation = SlimWebAuthn.FromBase64Url(credential.Response.AttestationObject);
        if (attestation is null || SlimWebAuthn.AuthenticatorDataOfAttestation(attestation) is not { } authDataBytes
            || SlimWebAuthn.ParseAuthenticatorData(authDataBytes) is not { CredentialId: { } credentialId, CredentialPublicKey: { } publicKey } authData)
            return Rejected("registration", "authenticator data");
        if (!SlimWebAuthn.IsForRelyingParty(authData, RpId)) return Rejected("registration", "rp id");
        if (!authData.UserPresent || !authData.UserVerified) return Rejected("registration", "user verification");
        if (SlimWebAuthn.AlgorithmOf(publicKey) is null) return Rejected("registration", "algorithm");
        if (SlimWebAuthn.FromBase64Url(credential.RawId) is not { } rawId || !rawId.AsSpan().SequenceEqual(credentialId))
            return Rejected("registration", "credential id");

        var passkey = new SlimPasskey
        {
            UserId = user.Id,
            CredentialId = credentialId,
            PublicKey = publicKey,
            SignCount = authData.SignCount,
            Name = CleanName(request.Name) ?? "Passkey",
            CreatedUtc = time.GetUtcNow(),
        };
        if (!await passkeys.AddPasskeyAsync(passkey, ct))
            return SlimResults.Status("passkey_exists", "This passkey is already registered.", StatusCodes.Status409Conflict);

        Log.PasskeyAdded(logger, user.Id);
        await hooks.RaiseAsync(SlimEventTypes.PasskeyAdded, user.Id, SlimAuthManager.MethodPasskey, ct: ct);
        return Results.Ok(new SlimPasskeyInfo(Base64Url.EncodeToString(credentialId), passkey.Name, passkey.CreatedUtc, null));
    }

    // ------------------------------------------------------------------ sign-in (anonymous, discoverable credentials)

    public IResult LoginOptions()
    {
        var challenge = SlimWebAuthn.NewChallenge();
        var state = workflow.Protect(SlimWorkflowTokens.PasskeyLoginPurpose,
            new SlimPasskeyLoginPayload(challenge, time.GetUtcNow().ToUnixTimeMilliseconds()), CeremonyLifetime);
        return Results.Ok(new SlimPasskeyRequestOptionsResponse(
            new SlimPasskeyRequestOptions(challenge, RpId, (int)CeremonyLifetime.TotalMilliseconds, "required", []), state));
    }

    public async Task<IResult> LoginAsync(SlimPasskeyLoginRequest? request, bool? useCookies, CancellationToken ct)
    {
        if (!SlimModes.TryResolve(O, useCookies, out var cookies, out var modeError)) return modeError!;
        if (request?.Credential is not { Type: PublicKey } credential
            || !workflow.TryUnprotect<SlimPasskeyLoginPayload>(SlimWorkflowTokens.PasskeyLoginPurpose, request.State, out var state))
            return Failed("state");

        // §7.2 steps 10–15: client data
        var clientDataJson = SlimWebAuthn.FromBase64Url(credential.Response.ClientDataJson);
        if (clientDataJson is null || SlimWebAuthn.ParseClientData(clientDataJson) is not { } clientData) return Failed("client data");
        if (clientData.Type != "webauthn.get") return Failed("type");
        if (!SlimHashing.FixedTimeEquals(clientData.Challenge, state.Challenge)) return Failed("challenge");
        if (!OriginAllowed(clientData)) return Failed("origin");

        // §7.2 steps 16–18: authenticator data
        var authDataBytes = SlimWebAuthn.FromBase64Url(credential.Response.AuthenticatorData);
        if (authDataBytes is null || SlimWebAuthn.ParseAuthenticatorData(authDataBytes) is not { } authData) return Failed("authenticator data");
        if (!SlimWebAuthn.IsForRelyingParty(authData, RpId)) return Failed("rp id");
        if (!authData.UserPresent || !authData.UserVerified) return Failed("user verification");

        // §7.2 steps 5–6: the credential and its owner
        if (SlimWebAuthn.FromBase64Url(credential.RawId) is not { } credentialId
            || await passkeys.FindPasskeyAsync(credentialId, ct) is not { } passkey)
            return Failed("unknown credential");
        if (credential.Response.UserHandle is { Length: > 0 } handle
            && !string.Equals(handle, Base64Url.EncodeToString(Encoding.UTF8.GetBytes(passkey.UserId)), StringComparison.Ordinal))
            return Failed("user handle");

        // §7.2 step 20: the signature
        var signature = SlimWebAuthn.FromBase64Url(credential.Response.Signature);
        if (signature is null || !SlimWebAuthn.VerifySignature(passkey.PublicKey, authDataBytes, clientDataJson, signature))
            return Failed("signature");

        // §7.2 step 21: a counter that does not increase hints at a cloned authenticator (most synced passkeys send 0)
        if ((authData.SignCount != 0 || passkey.SignCount != 0) && authData.SignCount <= passkey.SignCount)
        {
            Log.PasskeyCounterRegression(logger, passkey.UserId);
            return Failed("counter");
        }

        // single use, atomically: this challenge must be newer than the last one used with this passkey
        if (!await passkeys.TryRecordUseAsync(credentialId, passkey.SignCount, authData.SignCount, state.IssuedAt, time.GetUtcNow(), ct))
            return Failed("replay");

        var user = await store.FindByIdAsync(passkey.UserId, ct);
        if (user is not { IsActive: true }) return Failed("account");
        if (O.SignIn.RequireConfirmedEmail && !user.EmailConfirmed)
            return SlimResults.Status("email_not_confirmed", "The e-mail address has not been confirmed yet.", StatusCodes.Status403Forbidden);

        // possession + user verification: multi-factor on its own – no second factor follows
        var result = await authManager.SignInCoreAsync(user, cookies, request.RememberMe, SlimAuthManager.MethodPasskey, null, null, true, ct);
        metrics.Login(result.Succeeded ? "success" : "rejected", cookies);
        return login.ToResult(result);

        IResult Failed(string reason)
        {
            metrics.Login("passkey_rejected", cookies);
            Log.PasskeyRejected(logger, "sign-in", reason);
            return SlimResults.Status("invalid_passkey", "The passkey could not be verified.", StatusCodes.Status401Unauthorized);
        }
    }

    // ------------------------------------------------------------------ rename

    public async Task<IResult> RenameAsync(SlimPasskeyRenameRequest? request, CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;
        if (CleanName(request?.Name) is not { } name)
            return SlimResults.BadRequest("invalid_name", "The name must have 1–64 characters.");
        return SlimWebAuthn.FromBase64Url(request!.Id) is { } id && await passkeys.RenamePasskeyAsync(user.Id, id, name, ct)
            ? SlimResults.Status("passkey_renamed")
            : SlimResults.Status("passkey_not_found", "This passkey is not registered for your account.", StatusCodes.Status404NotFound);
    }

    // ------------------------------------------------------------------ helpers

    private bool HasPassword(SlimUser user) =>
        !string.IsNullOrEmpty(user.PasswordHash) || services.GetService<ISlimCustomPasswordValidator>() is not null;

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

    private IResult Rejected(string ceremony, string reason)
    {
        Log.PasskeyRejected(logger, ceremony, reason);
        return SlimResults.BadRequest("invalid_passkey", "The passkey could not be verified.");
    }
}
