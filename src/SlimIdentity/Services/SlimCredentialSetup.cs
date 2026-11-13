using SlimIdentity.Http;
using SlimIdentity.Security;

namespace SlimIdentity.Services;

/// <summary>
/// Step <c>set_credential</c>: the flow token at the step, and its completion for an existing account. The account of a
/// registration is created by <see cref="SlimRegistrationFlow"/>.
/// </summary>
internal sealed class SlimCredentialSetup(
    ISlimUserStore store,
    SlimSignInFlow flow,
    SlimCredentialService credentials,
    SlimPasswordPolicy passwordPolicy,
    SlimAuthManager authManager,
    SlimHookRunner hooks,
    SlimMetrics metrics,
    IOptions<SlimIdentityOptions> options,
    IHttpContextAccessor httpContextAccessor,
    IServiceProvider services,
    ILogger<SlimCredentialSetup> logger)
{
    private SlimIdentityOptions O => options.Value;

    /// <summary>
    /// The flow token at step <c>set_credential</c> – the start of every endpoint of the step, with the CSRF check of
    /// cookie mode. <c>User</c> is the account, <c>null</c> for a registration (its mailbox is proven).
    /// </summary>
    public async Task<(SlimFlowPayload? State, SlimUser? User, IResult? Error)> ReadAsync(string? flowToken, CancellationToken ct)
    {
        if (!flow.TryRead(flowToken, out var state, out _)) return (null, null, SlimResults.InvalidToken(StatusCodes.Status401Unauthorized));

        SlimUser? user = null;
        if (state.IsRegistration)
        {
            if (!state.Proofs.HasFlag(SlimSignInProofs.Mailbox)) return (null, null, SlimResults.InvalidToken(StatusCodes.Status401Unauthorized));
        }
        else
        {
            // the stamp rotates with the new way to sign in: the token sets it once
            user = await flow.FindUserAsync(state, ct);
            if (user is null || state.Link is null || SlimSignInChain.Evaluate(user, state, O).Next != SlimSignInActions.SetCredential)
                return (null, null, SlimResults.InvalidToken(StatusCodes.Status401Unauthorized));
        }

        // ends in a cookie sign-in without carrying a cookie – only the signed token knows (as on /login/2fa)
        if (state.UseCookies && SlimCsrfEndpointFilter.Validate(httpContextAccessor.HttpContext!.Request, O, logger) is { } csrfError)
            return (null, null, csrfError);
        return (state, user, null);
    }

    /// <summary>Business data belongs to a registration: refused for an existing account.</summary>
    public static IResult ProfileRefused() =>
        SlimResults.Validation(new Dictionary<string, string[]>(StringComparer.Ordinal)
        {
            ["profile"] = ["Only a registration carries a profile."],
        });

    /// <summary>
    /// Completes the step for an existing account with <paramref name="newPassword"/>, or – <c>null</c> – with the passkey
    /// <paramref name="addPasskey"/> adds (it answers <c>null</c> on success). The new way replaces the password and ends
    /// every session; a link that proves the mailbox confirms the address – a reset of an unconfirmed account also
    /// removes every other way in, an invitation does not (the administrator set the account up). Then the flow continues like a sign-in with the new way – the session.
    /// </summary>
    public async Task<IResult> CompleteAsync(SlimUser user, SlimFlowPayload state, string? newPassword,
        Func<CancellationToken, Task<IResult?>>? addPasskey, CancellationToken ct)
    {
        if (newPassword is not null)
        {
            if (services.GetService<ISlimCustomPasswordValidator>() is not null)
                return SlimResults.BadRequest(SlimErrorCodes.PasswordManagedExternally,
                    "Passwords are validated externally (LDAP / custom validator) and cannot be set here.");
            if (await passwordPolicy.ValidateAsync(newPassword, user.Email, ct) is { } errors) return SlimResults.Validation(errors);
        }

        var takeover = false;
        var confirms = false;
        var written = await store.TryWriteSecurityStateAsync(user, u =>
        {
            // rotates the stamp: the flow and its link are single-use, every session ends
            if (newPassword is not null) credentials.ApplyNewPassword(u, newPassword);
            else SlimCredentialService.RemovePassword(u);
            takeover = SlimSignInChain.ResetsUnconfirmedAccount(u, state);
            confirms = !u.EmailConfirmed && state.Proofs.HasFlag(SlimSignInProofs.Mailbox);
            if (takeover) u.TwoFactorEnabled = false;
            if (confirms) u.EmailConfirmed = true;
        }, ct);
        if (!written) return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        if (takeover)
        {
            // First proof of the mailbox: whoever registered the address before (possibly an attacker – pre-account
            // hijacking) must keep neither a second factor that locks the real owner out nor a linked external login or
            // passkey. Removed after the state is written: a link that lost against a concurrent change removes nothing.
            if (services.GetService<SlimTwoFactorService>() is { } twoFactor)
            {
                await twoFactor.RemoveSecretAsync(user, ct);
                await twoFactor.RemoveRecoveryCodesAsync(user, ct);
            }
            if (services.GetService<ISlimExternalLoginStore>() is { } externalLogins)
                await externalLogins.RemoveExternalLoginsAsync(user.Id, ct);
            if (services.GetService<ISlimPasskeySignInMethods>() is { } passkeys)
                await passkeys.RemoveAllAsync(user.Id, ct);
        }
        if (confirms) await hooks.RaiseAsync(SlimEventTypes.EmailConfirmed, user.Id, ct: ct);
        if (addPasskey is not null && await addPasskey(ct) is { } refused) return refused;

        await credentials.ResetAttemptsAsync(user, SlimAttemptFactor.Password, ct);   // the link proved the account
        await authManager.RevokeSessionsAsync(user.Id, exceptSessionId: null, ct);
        var invitation = state.Link == SlimLinkPayload.Invitation;
        if (invitation) Log.InvitationAccepted(logger, user.Id);
        else Log.PasswordReset(logger, user.Id);
        if (newPassword is not null) await hooks.RaiseAsync(SlimEventTypes.PasswordChanged, user.Id, reason: invitation ? "invitation" : "reset", ct: ct);
        if (invitation) metrics.Invitation("accepted");
        else metrics.PasswordReset("completed");

        var passkey = newPassword is null;
        var result = await flow.ContinueAsync(user, state with
        {
            Stamp = user.SecurityStamp,
            Proofs = state.Proofs | (passkey ? SlimSignInProofs.SecondFactor : SlimSignInProofs.Password),
            Amr = passkey ? SlimAuthManager.MethodPasskey
                : state.Proofs.HasFlag(SlimSignInProofs.SecondFactor) ? state.Amr : SlimAuthManager.MethodPassword,
            Link = null, Method = null, CodeHash = null, IssuedAt = 0,
        }, ct);
        metrics.Login(SlimSignInFlow.MetricReason(result), state.UseCookies);
        return flow.ToHttpResult(result, user);
    }
}
