using SlimIdentity.Contracts;
using SlimIdentity.Http;
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
    private ISlimPasskeySignInMethods? Passkeys => services.GetService<ISlimPasskeySignInMethods>();

    // GET /sign-in-methods
    public async Task<IResult> ListAsync(CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: false, ct);
        if (user is null) return error!;

        var external = ExternalStore is { } store ? await store.GetExternalLoginsAsync(user.Id, ct) : [];
        var passkeys = Passkeys is { } keys ? await keys.GetPasskeysAsync(user.Id, ct) : [];
        return Results.Ok(new SlimSignInMethodsResponse(await credentials.HasPasswordAsync(user, ct), external, passkeys));
    }

    // POST /sign-in-methods/external/remove
    public async Task<IResult> RemoveExternalAsync(SlimRemoveExternalLoginRequest? request, CancellationToken ct)
    {
        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;
        if (request is null || ExternalStore is not { } store) return NotFound();

        var target = new SlimExternalLogin(request.Provider, request.ProviderKey);
        if (!(await store.GetExternalLoginsAsync(user.Id, ct)).Contains(target)) return NotFound();

        // the password – or, without one, a fresh sign-in – keeps a stolen session from cutting the owner's methods
        if (await credentials.ConfirmPasswordAsync(user, request.Password, Http, ct) is { } failure) return failure;
        if (await credentials.HasPasswordAsync(user, ct))
        {
            // the password stays a way in
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

    private async Task<int> PasskeyCountAsync(string userId, CancellationToken ct) =>
        Passkeys is { } keys ? (await keys.GetPasskeysAsync(userId, ct)).Count : 0;

    private static IResult NotFound() =>
        SlimResults.Status("external_login_not_found", "This external login is not linked to your account.", StatusCodes.Status404NotFound);

    internal static IResult LastMethod() =>
        SlimResults.Status("last_sign_in_method", "This is the last way to sign in to the account – add another one first.", StatusCodes.Status409Conflict);
}
