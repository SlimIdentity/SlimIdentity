using System.Buffers.Text;
using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using SlimIdentity.Contracts;

namespace SlimIdentity.Passkeys;

/// <summary>The package reaches into the core's flows, so both must come from the same release.</summary>
internal static class SlimPasskeyVersion
{
    public static void EnsureSameAsCore()
    {
        var core = VersionOf(typeof(SlimIdentityBuilder).Assembly);
        var own = VersionOf(typeof(SlimPasskeyVersion).Assembly);
        if (!string.Equals(core, own, StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"SlimIdentity.Passkeys {own} needs SlimIdentity {own}, found {core}. Reference both packages with the same version.");
    }

    private static string? VersionOf(Assembly assembly) =>
        assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0];
}

/// <summary>Passkeys as sign-in methods of the core: listed, counted for the last way in, cleared on a mailbox proof.</summary>
internal sealed class SlimPasskeySignInMethods(ISlimPasskeyStore passkeys) : ISlimPasskeySignInMethods
{
    public async Task<IReadOnlyList<SlimPasskeyInfo>> GetPasskeysAsync(string userId, CancellationToken ct) =>
        [.. (await passkeys.GetPasskeysAsync(userId, ct)).Select(p =>
            new SlimPasskeyInfo(Base64Url.EncodeToString(p.CredentialId), p.Name, p.CreatedUtc, p.LastUsedUtc, p.BackupEligible, p.BackedUp))];

    public Task RemoveAllAsync(string userId, CancellationToken ct) => passkeys.RemovePasskeysAsync(userId, ct);
}

/// <summary>The passkey endpoints, mapped by <c>MapSlimIdentityApi</c>.</summary>
internal sealed class SlimPasskeyEndpoints : ISlimEndpointModule
{
    public void Map(RouteGroupBuilder auth, RouteGroupBuilder signInMethods, IServiceProvider services)
    {
        if (services.GetService<IServiceProviderIsService>() is { } isService && !isService.IsService(typeof(ISlimPasskeyStore)))
            throw new InvalidOperationException("SlimIdentity: AddPasskeys() without a passkey store. Call .AddPasskeyStore<T>() " +
                "(EF Core package: AddEntityFrameworkStores<…>(o => o.Passkeys = true)).");
        var o = services.GetRequiredService<IOptions<SlimIdentityOptions>>().Value;
        if (services.GetRequiredService<IOptions<SlimPasskeyOptions>>().Value.EffectiveRelyingPartyId(o.Links) is null)
            throw new InvalidOperationException("SlimIdentity: passkeys need a relying party id – AddPasskeys(o => o.RelyingPartyId = …) " +
                "or Links.BaseUrl: the domain they are bound to. Choose it once, changing it later makes every registered passkey unusable.");

        var group = auth.MapGroup("/passkeys");

        group.MapPost("/register/options", static ([FromBody] SlimPasskeyRegistrationOptionsRequest request,
                [FromServices] SlimPasskeyHandlers h, CancellationToken ct) => h.RegistrationOptionsAsync(request, ct))
            .WithName("SlimIdentity_PasskeyRegistrationOptions")
            .WithSummary("Start adding a passkey (password required if the account has one): options for navigator.credentials.create and a state.")
            .Produces<SlimPasskeyCreationOptionsResponse>()
            .ProducesSlimProblem(StatusCodes.Status400BadRequest)
            .ProducesSlimProblem(StatusCodes.Status403Forbidden)
            .RequireAuthorization(SlimIdentityEndpointExtensions.SlimAuthorize)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);

        group.MapPost("/register", static ([FromBody] SlimPasskeyRegisterRequest request,
                [FromServices] SlimPasskeyHandlers h, CancellationToken ct) => h.RegisterAsync(request, ct))
            .WithName("SlimIdentity_PasskeyRegister")
            .WithSummary("Finish adding a passkey with the result of navigator.credentials.create.")
            .Produces<SlimPasskeyInfo>()
            .ProducesSlimProblem(StatusCodes.Status400BadRequest)
            .ProducesSlimProblem(StatusCodes.Status409Conflict)
            .RequireAuthorization(SlimIdentityEndpointExtensions.SlimAuthorize)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);

        group.MapPost("/login/options", static ([FromServices] SlimPasskeyHandlers h) => h.LoginOptions())
            .WithName("SlimIdentity_PasskeyLoginOptions")
            .WithSummary("Start a passkey sign-in: options for navigator.credentials.get (no user name needed) and a state.")
            .Produces<SlimPasskeyRequestOptionsResponse>()
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
            .AllowAnonymous();

        group.MapPost("/login", static ([FromBody] SlimPasskeyLoginRequest request, [FromQuery] bool? useCookies,
                [FromServices] SlimPasskeyHandlers h, CancellationToken ct) => h.LoginAsync(request, useCookies, ct))
            .WithName("SlimIdentity_PasskeyLogin")
            .WithSummary("Sign in with the result of navigator.credentials.get.             A passkey is multi-factor: no second factor follows (action_required only for change_password).")
            .Produces<SlimAuthResponse>()
                        .Produces<SlimActionRequiredResponse>()
            .ProducesSlimProblem(StatusCodes.Status401Unauthorized)
            .ProducesSlimProblem(StatusCodes.Status403Forbidden)
            .ProducesSlimProblem(StatusCodes.Status429TooManyRequests)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
            .AllowAnonymous();

        signInMethods.MapPost("/passkeys/rename", static ([FromBody] SlimPasskeyRenameRequest request,
                [FromServices] SlimPasskeyHandlers h, CancellationToken ct) => h.RenameAsync(request, ct))
            .WithName("SlimIdentity_RenamePasskey")
            .WithSummary("Rename a passkey of the account.")
            .Produces<SlimStatusResponse>()
            .ProducesSlimProblem(StatusCodes.Status400BadRequest)
            .ProducesSlimProblem(StatusCodes.Status404NotFound);

        signInMethods.MapPost("/passkeys/remove", static ([FromBody] SlimRemovePasskeyRequest request,
                [FromServices] SlimPasskeyHandlers h, CancellationToken ct) => h.RemoveAsync(request, ct))
            .WithName("SlimIdentity_RemovePasskey")
            .WithSummary("Remove a passkey (password required if the account has one) – never the last sign-in method.")
            .Produces<SlimStatusResponse>()
            .ProducesSlimProblem(StatusCodes.Status400BadRequest)
            .ProducesSlimProblem(StatusCodes.Status404NotFound)
            .ProducesSlimProblem(StatusCodes.Status409Conflict)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);
    }
}
