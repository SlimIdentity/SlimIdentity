namespace SlimIdentity.Services;

/// <summary>
/// Runs the host's hooks: guards are resolved from the request's services (they may be scoped), a guard that throws
/// fails closed (no session), an event handler that throws is logged and ignored.
/// </summary>
internal sealed class SlimHookRunner(IHttpContextAccessor httpContextAccessor, IServiceProvider rootServices, TimeProvider time, ILogger<SlimHookRunner> logger)
{
    public async ValueTask<SlimVeto?> CheckSignInAsync(SlimUser user, string method, SlimSignInStage stage, string? impersonatorId, CancellationToken ct)
    {
        if (httpContextAccessor.HttpContext is not { } http) return null;
        SlimSignInContext? context = null;
        foreach (var guard in http.RequestServices.GetServices<ISlimSignInGuard>())
        {
            context ??= new SlimSignInContext
            {
                User = user, AuthenticationMethod = method, Stage = stage, ImpersonatorId = impersonatorId, HttpContext = http,
            };
            if (await guard.CheckAsync(context, ct) is { } veto)
            {
                Log.SignInVetoed(logger, user.Id, veto.Error, stage.ToString());
                return veto;
            }
        }
        return null;
    }

    public async ValueTask<SlimVeto?> CheckRegistrationAsync(string email, string? provider, CancellationToken ct)
    {
        if (httpContextAccessor.HttpContext is not { } http) return null;
        SlimRegistrationContext? context = null;
        foreach (var guard in http.RequestServices.GetServices<ISlimRegistrationGuard>())
        {
            context ??= new SlimRegistrationContext { Email = email, Provider = provider, HttpContext = http };
            if (await guard.CheckAsync(context, ct) is { } veto)
            {
                Log.RegistrationVetoed(logger, veto.Error);
                return veto;
            }
        }
        return null;
    }

    public async ValueTask RaiseAsync(string type, string? userId, string? method = null, string? reason = null, string? actorId = null, CancellationToken ct = default)
    {
        var http = httpContextAccessor.HttpContext;
        SlimEvent? e = null;
        foreach (var handler in (http?.RequestServices ?? rootServices).GetServices<ISlimEventObserver>())
        {
            e ??= new SlimEvent
            {
                Type = type, UserId = userId, Method = method, Reason = reason, ActorId = actorId,
                Timestamp = time.GetUtcNow(), HttpContext = http,
            };
            try
            {
                await handler.HandleAsync(e, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log.EventHandlerFailed(logger, ex, type);   // observers never change the outcome
            }
        }
    }
}
