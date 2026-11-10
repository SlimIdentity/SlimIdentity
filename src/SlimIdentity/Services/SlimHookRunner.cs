namespace SlimIdentity.Services;

/// <summary>
/// Runs the host's hooks: guards are resolved from the request's services (they may be scoped) – or, without a request
/// (a background job calling <see cref="ISlimAuthManager"/>), from a scope of their own, so they always run. A guard that
/// throws fails closed (no session), an event handler that throws is logged and ignored.
/// </summary>
internal sealed class SlimHookRunner(IHttpContextAccessor httpContextAccessor, IServiceProvider rootServices, TimeProvider time, ILogger<SlimHookRunner> logger)
{
    public async ValueTask<SlimVeto?> CheckSignInAsync(SlimUser user, string method, SlimSignInStage stage, string? impersonatorId, CancellationToken ct)
    {
        var http = httpContextAccessor.HttpContext;
        var scope = http is null ? rootServices.CreateAsyncScope() : (AsyncServiceScope?)null;
        try
        {
            SlimSignInContext? context = null;
            foreach (var guard in (http?.RequestServices ?? scope!.Value.ServiceProvider).GetServices<ISlimSignInGuard>())
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
        finally
        {
            if (scope is { } s) await s.DisposeAsync();
        }
    }

    public async ValueTask<SlimVeto?> CheckRegistrationAsync(string email, string? provider, CancellationToken ct)
    {
        var http = httpContextAccessor.HttpContext;
        var scope = http is null ? rootServices.CreateAsyncScope() : (AsyncServiceScope?)null;
        try
        {
            SlimRegistrationContext? context = null;
            foreach (var guard in (http?.RequestServices ?? scope!.Value.ServiceProvider).GetServices<ISlimRegistrationGuard>())
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
        finally
        {
            if (scope is { } s) await s.DisposeAsync();
        }
    }

    /// <summary>
    /// The host's <see cref="ISlimRegistrationProfile"/>. Without one, a sent profile is refused – nothing unvalidated
    /// ever reaches the store.
    /// </summary>
    public async ValueTask<SlimProfileValidation> ValidateProfileAsync(string email, JsonElement? profile, CancellationToken ct)
    {
        if (profile is { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined }) profile = null;
        var http = httpContextAccessor.HttpContext;
        if (http?.RequestServices.GetService<ISlimRegistrationProfile>() is not { } validator)
            return profile is null
                ? SlimProfileValidation.Valid(null)
                : SlimProfileValidation.Invalid("", "No profile is accepted.");
        return await validator.ValidateAsync(new SlimRegistrationProfileContext { Email = email, Profile = profile, HttpContext = http }, ct);
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
