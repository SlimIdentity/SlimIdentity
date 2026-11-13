using SlimIdentity.Contracts;
using SlimIdentity.Http;
using SlimIdentity.Services;

namespace SlimIdentity.Endpoints;

/// <summary>The sign-in methods of the signed-in account: list them, remove one – never the last.</summary>
internal sealed class SlimSignInMethodHandlers(
    SlimAccountHandlers account,
    SlimCredentialService credentials,
    SlimAuthManager authManager,
    ISlimUserStore userStore,
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
        if (!await credentials.HasPasswordAsync(user, ct)
            && (await store.GetExternalLoginsAsync(user.Id, ct)).Count + await PasskeyCountAsync(user.Id, ct) <= 1)
            return LastMethod();

        if (await BeginRemovalAsync(user, ct) is { } conflict) return conflict;
        await store.RemoveExternalLoginAsync(user.Id, target.Provider, target.ProviderKey, ct);

        Log.ExternalLoginRemoved(logger, target.Provider, user.Id);
        metrics.ExternalLogin(target.Provider, "removed");
        await hooks.RaiseAsync(SlimEventTypes.ExternalLoginRemoved, user.Id, target.Provider, ct: ct);
        return await EndRemovalAsync(user, ct);
    }

    /// <summary>
    /// Before a sign-in method is removed: a new security stamp, bound to the state this request saw. Of two parallel
    /// removals – on any instance – only one passes, so the methods counted before stay counted; other sessions end.
    /// </summary>
    private async Task<IResult?> BeginRemovalAsync(SlimUser user, CancellationToken ct) =>
        await userStore.TryWriteSecurityStateAsync(user, u => u.SecurityStamp = SlimUser.NewSecurityStamp(), ct)
            ? null
            : SlimResults.ConcurrentChange();

    /// <summary>After the removal: other sessions end, this one is issued again with the new stamp.</summary>
    private async Task<IResult> EndRemovalAsync(SlimUser user, CancellationToken ct)
    {
        await authManager.RevokeSessionsAsync(user.Id, SlimAuthManager.CurrentSessionId(Http.User), ct);
        return SlimResults.ReissuedSession(await authManager.RefreshCurrentSessionAsync(user, ct));
    }

    private async Task<int> PasskeyCountAsync(string userId, CancellationToken ct) =>
        Passkeys is { } keys ? (await keys.GetPasskeysAsync(userId, ct)).Count : 0;

    private static IResult NotFound() =>
        SlimResults.Status(SlimErrorCodes.ExternalLoginNotFound, "This external login is not linked to your account.", StatusCodes.Status404NotFound);

    internal static IResult LastMethod() =>
        SlimResults.Status(SlimErrorCodes.LastSignInMethod, "This is the last way to sign in to the account – add another one first.", StatusCodes.Status409Conflict);
}
