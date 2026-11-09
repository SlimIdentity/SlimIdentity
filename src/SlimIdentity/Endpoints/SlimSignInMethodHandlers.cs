using System.Buffers.Text;
using SlimIdentity.Contracts;
using SlimIdentity.Http;
using SlimIdentity.Security;
using SlimIdentity.Services;

namespace SlimIdentity.Endpoints;

/// <summary>The sign-in methods of the signed-in account: list them, remove one – never the last.</summary>
internal sealed class SlimSignInMethodHandlers(
    SlimAccountHandlers account,
    SlimCredentialService credentials,
    SlimHookRunner hooks,
    SlimMetrics metrics,
    IServiceProvider services,
    IHttpContextAccessor httpContextAccessor,
    ILogger<SlimSignInMethodHandlers> logger)
{
    private HttpContext Http => httpContextAccessor.HttpContext!;
    private ISlimExternalLoginStore? ExternalStore => services.GetService<ISlimExternalLoginStore>();
    private ISlimPasskeyStore? PasskeyStore => services.GetService<ISlimPasskeyStore>();

    // GET /sign-in-methods
    public async Task<IResult> ListAsync(CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: false, ct);
        if (user is null) return error!;

        var external = ExternalStore is { } store ? await store.GetExternalLoginsAsync(user.Id, ct) : [];
        var passkeys = PasskeyStore is { } keys ? await keys.GetPasskeysAsync(user.Id, ct) : [];
        return Results.Ok(new SlimSignInMethodsResponse(HasPassword(user), external,
            [.. passkeys.Select(p => new SlimPasskeyInfo(Base64Url.EncodeToString(p.CredentialId), p.Name, p.CreatedUtc, p.LastUsedUtc))]));
    }

    // POST /sign-in-methods/external/remove
    public async Task<IResult> RemoveExternalAsync(SlimRemoveExternalLoginRequest? request, CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;
        if (request is null || ExternalStore is not { } store) return NotFound();

        var target = new SlimExternalLogin(request.Provider, request.ProviderKey);
        if (!(await store.GetExternalLoginsAsync(user.Id, ct)).Contains(target)) return NotFound();

        if (HasPassword(user))
        {
            // the password stays a way in – confirming it is what keeps a stolen session from cutting the owner's methods
            if (await credentials.ConfirmPasswordAsync(user, request.Password, Http, ct) is { } failure) return failure;
            if (!await store.RemoveExternalLoginAsync(user.Id, target.Provider, target.ProviderKey, ct)) return NotFound();
        }
        else
        {
            // no password: the remaining links are the only way in – check and remove as one step per account, so two
            // parallel requests cannot remove the last two
            using var attempt = await credentials.TryEnterAttemptAsync(user.Id, ct);
            if (attempt is null) return LastMethod();
            var links = await store.GetExternalLoginsAsync(user.Id, ct);
            if (!links.Contains(target)) return NotFound();
            if (links.Count + await PasskeyCountAsync(user.Id, ct) <= 1) return LastMethod();
            if (!await store.RemoveExternalLoginAsync(user.Id, target.Provider, target.ProviderKey, ct)) return NotFound();
        }

        Log.ExternalLoginRemoved(logger, target.Provider, user.Id);
        metrics.ExternalLogin(target.Provider, "removed");
        await hooks.RaiseAsync(SlimEventTypes.ExternalLoginRemoved, user.Id, target.Provider, ct: ct);
        return SlimResults.Status("external_login_removed");
    }

    // POST /sign-in-methods/passkeys/remove
    public async Task<IResult> RemovePasskeyAsync(SlimRemovePasskeyRequest? request, CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;
        if (PasskeyStore is not { } keys || SlimWebAuthn.FromBase64Url(request?.Id) is not { } id) return PasskeyNotFound();
        if (!(await keys.GetPasskeysAsync(user.Id, ct)).Any(p => p.CredentialId.AsSpan().SequenceEqual(id))) return PasskeyNotFound();

        if (HasPassword(user))
        {
            if (await credentials.ConfirmPasswordAsync(user, request!.Password, Http, ct) is { } failure) return failure;
            if (!await keys.RemovePasskeyAsync(user.Id, id, ct)) return PasskeyNotFound();
        }
        else
        {
            using var attempt = await credentials.TryEnterAttemptAsync(user.Id, ct);
            if (attempt is null) return LastMethod();
            var remaining = await keys.GetPasskeysAsync(user.Id, ct);
            if (!remaining.Any(p => p.CredentialId.AsSpan().SequenceEqual(id))) return PasskeyNotFound();
            var external = ExternalStore is { } store ? (await store.GetExternalLoginsAsync(user.Id, ct)).Count : 0;
            if (remaining.Count + external <= 1) return LastMethod();
            if (!await keys.RemovePasskeyAsync(user.Id, id, ct)) return PasskeyNotFound();
        }

        Log.PasskeyRemoved(logger, user.Id);
        await hooks.RaiseAsync(SlimEventTypes.PasskeyRemoved, user.Id, SlimAuthManager.MethodPasskey, ct: ct);
        return SlimResults.Status("passkey_removed");
    }

    private async Task<int> PasskeyCountAsync(string userId, CancellationToken ct) =>
        PasskeyStore is { } keys ? (await keys.GetPasskeysAsync(userId, ct)).Count : 0;

    private static IResult PasskeyNotFound() =>
        SlimResults.Status("passkey_not_found", "This passkey is not registered for your account.", StatusCodes.Status404NotFound);

    private bool HasPassword(SlimUser user) =>
        !string.IsNullOrEmpty(user.PasswordHash) || services.GetService<ISlimCustomPasswordValidator>() is not null;

    private static IResult NotFound() =>
        SlimResults.Status("external_login_not_found", "This external login is not linked to your account.", StatusCodes.Status404NotFound);

    private static IResult LastMethod() =>
        SlimResults.Status("last_sign_in_method", "This is the last way to sign in to the account – add another one first.", StatusCodes.Status409Conflict);
}
