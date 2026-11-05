using Microsoft.AspNetCore.WebUtilities;
using SlimIdentity.Contracts;
using SlimIdentity.Http;
using SlimIdentity.Security;
using SlimIdentity.Services;

namespace SlimIdentity.Endpoints;

/// <summary>
/// OAuth / OIDC flow on top of the host's remote authentication handlers (Google, Apple, Entra ID, Keycloak, …).
/// Errors are reported by redirecting to the return URL with <c>slim_error=&lt;code&gt;</c>
/// (<c>account_conflict</c> corresponds to the 409 split-account case).
/// </summary>
internal sealed class SlimExternalLoginHandlers(
    ISlimUserStore store,
    ISlimExternalLoginStore externalStore,
    IAuthenticationSchemeProvider schemes,
    SlimLoginHandlers login,
    SlimAuthManager authManager,
    SlimWorkflowTokens workflow,
    SlimMetrics metrics,
    SlimLocalNonceRegistry nonces,
    IServiceProvider services,
    IOptions<SlimIdentityOptions> options,
    TimeProvider time,
    IHttpContextAccessor httpContextAccessor,
    ILogger<SlimExternalLoginHandlers> logger)
{
    private const string ItemProvider = "slim.provider";
    private const string ItemReturnUrl = "slim.returnUrl";
    private const string ItemUseCookies = "slim.useCookies";

    private SlimIdentityOptions O => options.Value;
    private HttpContext Http => httpContextAccessor.HttpContext!;

    // ------------------------------------------------------------------ GET /login/{provider}

    public async Task<IResult> ChallengeAsync(string provider, string? returnUrl, bool? useCookies)
    {
        var scheme = await FindRemoteSchemeAsync(provider);
        if (scheme is null) return SlimResults.Status("unknown_provider", $"Provider '{provider}' is not configured.", StatusCodes.Status404NotFound);
        if (!SlimModes.TryResolve(O, useCookies, out var cookies, out var modeError)) return modeError!;

        var target = ValidateReturnUrl(returnUrl);
        if (target is null) return SlimResults.BadRequest("invalid_return_url", "The returnUrl is not allowed.");

        var properties = new AuthenticationProperties
        {
            RedirectUri = $"{Http.Request.PathBase}{O.RoutePrefix.TrimEnd('/')}/login/{Uri.EscapeDataString(scheme.Name)}/callback",
        };
        properties.Items[ItemProvider] = scheme.Name;
        properties.Items[ItemReturnUrl] = target;
        properties.Items[ItemUseCookies] = cookies ? "true" : "false";

        return Results.Challenge(properties, [scheme.Name]);
    }

    // ------------------------------------------------------------------ GET /login/{provider}/callback

    public async Task<IResult> CallbackAsync(string provider, CancellationToken ct)
    {
        var external = await Http.AuthenticateAsync(SlimIdentityDefaults.ExternalScheme);
        await Http.SignOutAsync(SlimIdentityDefaults.ExternalScheme); // the temporary cookie is never reused

        if (!external.Succeeded || external.Principal is null || external.Properties is null)
            return SlimResults.Status("external_login_failed", "External authentication failed.", StatusCodes.Status401Unauthorized);

        var items = external.Properties.Items;
        var returnUrl = items.TryGetValue(ItemReturnUrl, out var r) && r is not null ? r : O.ExternalLogin.DefaultReturnUrl;
        if (!items.TryGetValue(ItemProvider, out var storedProvider) || !string.Equals(storedProvider, provider, StringComparison.Ordinal))
            return Redirect(returnUrl, "slim_error", "provider_mismatch");
        var cookies = items.TryGetValue(ItemUseCookies, out var c) && c == "true";

        var principal = external.Principal;
        var providerKey = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? principal.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(providerKey)) return Redirect(returnUrl, "slim_error", "missing_provider_key");

        var email = principal.FindFirst(ClaimTypes.Email)?.Value
                    ?? principal.FindFirst("email")?.Value
                    ?? principal.FindFirst("preferred_username")?.Value
                    ?? principal.FindFirst(ClaimTypes.Upn)?.Value;
        var emailVerified = IsEmailVerified(principal, provider);

        var user = await externalStore.FindByExternalLoginAsync(provider, providerKey, ct);
        if (user is null)
        {
            if (string.IsNullOrWhiteSpace(email)) return Redirect(returnUrl, "slim_error", "email_required");

            var existing = await store.FindByEmailAsync(email, ct);
            if (existing is not null)
            {
                if (!(O.ExternalLogin.AutoLinkVerifiedEmails && emailVerified))
                {
                    Log.ExternalLoginConflict(logger, provider, existing.Id);
                    metrics.ExternalLogin(provider, "conflict");
                    return Redirect(returnUrl, "slim_error", "account_conflict"); // 409 semantics
                }
                await externalStore.LinkExternalLoginAsync(existing.Id, provider, providerKey, ct);
                if (!existing.EmailConfirmed)
                {
                    existing.EmailConfirmed = true;
                    await store.UpdateSecurityStateAsync(existing, ct);
                }
                Log.ExternalLoginLinked(logger, provider, existing.Id);
                metrics.ExternalLogin(provider, "linked");
                user = existing;
            }
            else
            {
                if (!O.ExternalLogin.AllowAutoRegistration) return Redirect(returnUrl, "slim_error", "registration_disabled");

                user = await store.CreateAsync(email.Trim(), string.Empty, ct);
                if (emailVerified && !user.EmailConfirmed)
                {
                    user.EmailConfirmed = true;
                    await store.UpdateSecurityStateAsync(user, ct);
                }
                await externalStore.LinkExternalLoginAsync(user.Id, provider, providerKey, ct);
                Log.ExternalUserCreated(logger, user.Id, provider);
                metrics.ExternalLogin(provider, "created");
            }
        }

        var now = time.GetUtcNow();
        var rejection = !user.IsActive ? "account_disabled"
            : user.IsLockedOut(now) ? "account_locked"
            : O.SignIn.RequireConfirmedEmail && !user.EmailConfirmed ? "email_not_confirmed"
            : null;
        if (rejection is not null)
        {
            metrics.ExternalLogin(provider, "rejected");
            return Redirect(returnUrl, "slim_error", rejection);
        }
        metrics.ExternalLogin(provider, "success");

        if (user.TwoFactorEnabled)
        {
            var challenge = await login.BeginTwoFactorAsync(user, cookies, false, ct);
            if (challenge is null) return Redirect(returnUrl, "slim_error", "two_factor_unavailable");
            return Results.Redirect(QueryHelpers.AddQueryString(returnUrl, new Dictionary<string, string?>
            {
                ["slim_status"] = "requires_two_factor",
                ["preAuthToken"] = challenge.PreAuthToken,
                ["method"] = challenge.TwoFactorMethod,
            }));
        }

        if (cookies)
        {
            await authManager.SignInCoreAsync(user, true, false, SlimAuthManager.MethodExternal, null, null, false, ct);
            return Results.Redirect(returnUrl);
        }

        // Bearer clients: never put tokens into URLs – hand out a short-lived one-time code instead.
        var code = workflow.Protect(SlimWorkflowTokens.ExternalExchangePurpose,
            new SlimExchangePayload(user.Id, user.SecurityStamp, provider, Convert.ToHexString(RandomNumberGenerator.GetBytes(16))),
            O.ExternalLogin.ExchangeCodeLifetime);

        // Single use: with a refresh-token store the code is registered there and consumed atomically (works across
        // instances); otherwise the nonce is tracked in memory on exchange.
        if (services.GetService<ISlimRefreshTokenStore>() is { } refreshStore)
            await refreshStore.StoreRefreshTokenAsync(user.Id, ExchangeCodeHash(code), time.GetUtcNow() + O.ExternalLogin.ExchangeCodeLifetime, ct);

        return Redirect(returnUrl, "code", code);
    }

    // ------------------------------------------------------------------ POST /login/external/exchange

    public async Task<IResult> ExchangeAsync(SlimExternalExchangeRequest? request, CancellationToken ct)
    {
        if (!workflow.TryUnprotect<SlimExchangePayload>(SlimWorkflowTokens.ExternalExchangePurpose, request?.Code, out var payload, out var expiresAt))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        // consume first – a code that was already exchanged (leaked via history, logs or a referrer) is rejected
        var consumed = services.GetService<ISlimRefreshTokenStore>() is { } refreshStore
            ? string.Equals(await refreshStore.ValidateAndConsumeRefreshTokenAsync(ExchangeCodeHash(request!.Code), ct), payload.Uid, StringComparison.Ordinal)
            : nonces.TryConsume(payload.Nonce, expiresAt);
        if (!consumed)
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        var user = await store.FindByIdAsync(payload.Uid, ct);
        if (user is null || !user.IsActive || !SlimHashing.FixedTimeEquals(user.SecurityStamp, payload.Stamp))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        if (!SlimModes.TryResolve(O, false, out _, out var modeError)) return modeError!;
        var result = await authManager.SignInCoreAsync(user, false, false, SlimAuthManager.MethodExternal, null, null, true, ct);
        return login.ToResult(result);
    }

    // ------------------------------------------------------------------ helpers

    // domain-separated, so an exchange code can never be confused with a refresh token in the shared store
    private static string ExchangeCodeHash(string code) => SlimHashing.Sha256Hex($"slimidentity.exchange-code.v1:{code}");

    private async Task<AuthenticationScheme?> FindRemoteSchemeAsync(string provider)
    {
        if (string.IsNullOrWhiteSpace(provider) || SlimIdentityDefaults.IsOwnScheme(provider)) return null;
        var scheme = await schemes.GetSchemeAsync(provider);
        // only remote handlers (OAuth / OIDC / WS-Fed / SAML) qualify
        return scheme is not null && typeof(IAuthenticationRequestHandler).IsAssignableFrom(scheme.HandlerType) ? scheme : null;
    }

    private bool IsEmailVerified(ClaimsPrincipal principal, string provider)
    {
        var claim = principal.FindFirst("email_verified")?.Value;
        if (string.Equals(claim, "true", StringComparison.OrdinalIgnoreCase)) return true;
        return O.ExternalLogin.TrustedEmailProviders.Contains(provider, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Open-redirect protection: local paths or explicitly allowed origins only.</summary>
    private string? ValidateReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl)) return O.ExternalLogin.DefaultReturnUrl;

        if (returnUrl.StartsWith('/') && !returnUrl.StartsWith("//", StringComparison.Ordinal) && !returnUrl.StartsWith("/\\", StringComparison.Ordinal))
            return returnUrl;

        if (!Uri.TryCreate(returnUrl, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
            return null;

        foreach (var allowed in O.ExternalLogin.AllowedReturnUrls)
        {
            if (Uri.TryCreate(allowed, UriKind.Absolute, out var a)
                && string.Equals(a.Scheme, uri.Scheme, StringComparison.OrdinalIgnoreCase)
                && string.Equals(a.Host, uri.Host, StringComparison.OrdinalIgnoreCase)
                && a.Port == uri.Port)
                return returnUrl;
        }
        return null;
    }

    private static IResult Redirect(string returnUrl, string key, string value) =>
        Results.Redirect(QueryHelpers.AddQueryString(returnUrl, key, value));
}
