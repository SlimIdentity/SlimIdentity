using Microsoft.IdentityModel.JsonWebTokens;
using SlimIdentity.Abstractions;
using SlimIdentity.Authentication;
using SlimIdentity.Contracts;
using SlimIdentity.Security;

namespace SlimIdentity.Services;

/// <summary>Default <see cref="ISlimAuthManager"/>; also used internally by all endpoints.</summary>
internal sealed class SlimAuthManager(
    IHttpContextAccessor httpContextAccessor,
    ISlimUserStore store,
    SlimJwtTokenFactory jwt,
    SlimWorkflowTokens workflow,
    IOptions<SlimIdentityOptions> options,
    TimeProvider time,
    IServiceProvider services,
    ILogger<SlimAuthManager> logger) : ISlimAuthManager
{
    internal const string MethodPassword = "pwd";
    internal const string MethodMfa = "mfa";
    internal const string MethodExternal = "ext";
    internal const string MethodImpersonation = "impersonation";

    private static readonly HashSet<string> ReservedClaims = new(StringComparer.Ordinal)
    {
        SlimClaimTypes.UserId, SlimClaimTypes.Email, SlimClaimTypes.SecurityStamp, SlimClaimTypes.Actor,
        SlimClaimTypes.AuthenticationMethod, ClaimTypes.NameIdentifier, ClaimTypes.Email,
        JwtRegisteredClaimNames.Iss, JwtRegisteredClaimNames.Aud, JwtRegisteredClaimNames.Exp,
        JwtRegisteredClaimNames.Nbf, JwtRegisteredClaimNames.Iat, JwtRegisteredClaimNames.Jti,
    };

    private HttpContext Http => httpContextAccessor.HttpContext
        ?? throw new InvalidOperationException("SlimIdentity: ISlimAuthManager requires an active HttpContext.");

    // ------------------------------------------------------------------ public API

    public Task<SlimAuthResult> SignInAsync(SlimUser user, bool useCookies, bool isPersistent = false, CancellationToken ct = default) =>
        SignInCoreAsync(user, useCookies, isPersistent, MethodPassword, null, null, issueRefreshToken: true, ct);

    public async Task<SlimAuthResult> ImpersonateAsync(SlimUser targetUser, string impersonatorUserId, bool useCookies, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(targetUser);
        ArgumentException.ThrowIfNullOrWhiteSpace(impersonatorUserId);

        if (httpContextAccessor.HttpContext?.User.IsImpersonating() == true)
            return SlimAuthResult.Failed("already_impersonating");
        if (string.Equals(targetUser.Id, impersonatorUserId, StringComparison.Ordinal))
            return SlimAuthResult.Failed("cannot_impersonate_self");

        // Bind the session to the impersonator's current security state: banning the admin or rotating
        // their stamp ends every impersonation session they started (see SlimSecurityStampValidator).
        var impersonator = await store.FindByIdAsync(impersonatorUserId, ct);
        if (impersonator is not { IsActive: true })
            return SlimAuthResult.Failed("impersonator_invalid");

        var currentAmr = httpContextAccessor.HttpContext?.User.FindFirst(SlimClaimTypes.AuthenticationMethod)?.Value;
        var actor = SlimClaims.SerializeActor(SlimClaims.CreateActor(impersonator.Id, impersonator.SecurityStamp, currentAmr));

        logger.LogWarning("SlimIdentity: user {Impersonator} impersonates {Target}.", impersonator.Id, targetUser.Id);
        return await SignInCoreAsync(targetUser, useCookies, isPersistent: false, MethodImpersonation, null, actor, issueRefreshToken: false, ct);
    }

    public async Task<SlimAuthResult> EndImpersonationAsync(CancellationToken ct = default)
    {
        var current = Http.User;
        var actor = SlimClaims.ParseActorClaim(current.FindFirst(SlimClaimTypes.Actor)?.Value);
        if (actor is null) return SlimAuthResult.Failed("not_impersonating");

        var useCookies = current.IsSlimCookieSession();
        var impersonator = await store.FindByIdAsync(actor.UserId, ct);
        if (impersonator is not { IsActive: true } || !SlimHashing.FixedTimeEquals(impersonator.SecurityStamp, actor.SecurityStamp))
        {
            // The impersonator was banned or signed out everywhere in the meantime: no way back, end the session.
            logger.LogWarning("SlimIdentity: return to impersonator {Impersonator} denied (inactive or security stamp changed).", actor.UserId);
            if (useCookies) await Http.SignOutAsync(SlimIdentityDefaults.CookieScheme);
            return SlimAuthResult.Failed("impersonator_invalid");
        }

        logger.LogWarning("SlimIdentity: user {Impersonator} ended the impersonation of {Target}.", impersonator.Id, current.GetSlimUserId());
        return await SignInCoreAsync(impersonator, useCookies, isPersistent: false, actor.AuthenticationMethod ?? MethodPassword,
            null, null, issueRefreshToken: true, ct);
    }

    public async Task<SlimAuthResult> ElevateSessionAsync(SlimUser user, IEnumerable<Claim> additionalClaims, bool useCookies, CancellationToken ct = default)
    {
        var current = Http.User;
        var impersonator = SlimClaims.ParseActorClaim(current.FindFirst(SlimClaimTypes.Actor)?.Value) is { } a
            ? SlimClaims.SerializeActor(a.ToDictionary())
            : null;
        var amr = current.FindFirst(SlimClaimTypes.AuthenticationMethod)?.Value ?? MethodPassword;

        var persistent = false;
        if (useCookies)
        {
            var existing = await Http.AuthenticateAsync(SlimIdentityDefaults.CookieScheme);
            persistent = existing.Properties?.IsPersistent ?? false;
        }

        return await SignInCoreAsync(user, useCookies, persistent, amr, additionalClaims, impersonator, issueRefreshToken: false, ct);
    }

    public async Task SignOutAsync(string? refreshToken = null, CancellationToken ct = default)
    {
        if (!string.IsNullOrWhiteSpace(refreshToken) && services.GetService<ISlimRefreshTokenStore>() is { } refreshStore)
            await refreshStore.ValidateAndConsumeRefreshTokenAsync(SlimHashing.Sha256Hex(refreshToken), ct);

        if (options.Value.Endpoints.AllowCookieAuth)
            await Http.SignOutAsync(SlimIdentityDefaults.CookieScheme);
    }

    // ------------------------------------------------------------------ internal API

    internal async Task<SlimAuthResult> SignInCoreAsync(
        SlimUser user,
        bool useCookies,
        bool isPersistent,
        string authMethod,
        IEnumerable<Claim>? additionalClaims,
        string? actorJson,
        bool issueRefreshToken,
        CancellationToken ct)
    {
        if (!user.IsActive) return SlimAuthResult.Failed("account_inactive");

        var o = options.Value;
        var now = time.GetUtcNow();
        var claims = await BuildClaimsAsync(user, authMethod, additionalClaims, actorJson, ct);

        if (useCookies)
        {
            if (!o.Endpoints.AllowCookieAuth)
                throw new InvalidOperationException("SlimIdentity: cookie authentication is disabled (Endpoints.AllowCookieAuth).");

            var principal = new ClaimsPrincipal(new ClaimsIdentity(
                claims, SlimIdentityDefaults.CookieScheme, SlimClaimTypes.Email, SlimClaimTypes.Role));

            var props = new AuthenticationProperties { IsPersistent = isPersistent, AllowRefresh = true };
            props.Items[SlimSecurityStampValidator.ValidatedAtKey] = now.ToString("O", CultureInfo.InvariantCulture);

            await Http.SignInAsync(SlimIdentityDefaults.CookieScheme, principal, props);
            return new SlimAuthResult { Succeeded = true, UsedCookies = true, Principal = principal };
        }

        if (!o.Endpoints.AllowJwtAuth)
            throw new InvalidOperationException("SlimIdentity: JWT authentication is disabled (Endpoints.AllowJwtAuth).");

        var (accessToken, accessExpires) = jwt.CreateAccessToken(claims);

        string? refreshToken = null;
        DateTimeOffset? refreshExpires = null;
        if (issueRefreshToken && services.GetService<ISlimRefreshTokenStore>() is { } refreshStore)
        {
            refreshExpires = now + o.Tokens.RefreshTokenLifetime;
            refreshToken = workflow.Protect(
                SlimWorkflowTokens.RefreshTokenPurpose,
                new SlimRefreshPayload(user.Id, user.SecurityStamp, authMethod, Convert.ToHexString(RandomNumberGenerator.GetBytes(16))),
                o.Tokens.RefreshTokenLifetime);
            await refreshStore.StoreRefreshTokenAsync(user.Id, SlimHashing.Sha256Hex(refreshToken), refreshExpires.Value, ct);
        }

        return new SlimAuthResult
        {
            Succeeded = true,
            UsedCookies = false,
            AccessToken = accessToken,
            AccessTokenExpiresAt = accessExpires,
            RefreshToken = refreshToken,
            RefreshTokenExpiresAt = refreshExpires,
            Principal = new ClaimsPrincipal(new ClaimsIdentity(
                claims, SlimIdentityDefaults.BearerScheme, SlimClaimTypes.Email, SlimClaimTypes.Role)),
        };
    }

    /// <summary>
    /// Re-issues the session of the current request for <paramref name="user"/> (after stamp rotation),
    /// so the calling device stays signed in while all others are logged out.
    /// </summary>
    internal async Task<SlimAuthResult> RefreshCurrentSessionAsync(SlimUser user, CancellationToken ct)
    {
        var current = Http.User;
        var amr = current.FindFirst(SlimClaimTypes.AuthenticationMethod)?.Value ?? MethodPassword;

        if (current.IsSlimCookieSession())
        {
            var existing = await Http.AuthenticateAsync(SlimIdentityDefaults.CookieScheme);
            var persistent = existing.Properties?.IsPersistent ?? false;
            return await SignInCoreAsync(user, true, persistent, amr, null, null, issueRefreshToken: false, ct);
        }

        return await SignInCoreAsync(user, false, false, amr, null, null, issueRefreshToken: true, ct);
    }

    private async Task<List<Claim>> BuildClaimsAsync(
        SlimUser user, string authMethod, IEnumerable<Claim>? additionalClaims, string? actorJson, CancellationToken ct)
    {
        var claims = new List<Claim>
        {
            new(SlimClaimTypes.UserId, user.Id),
            new(SlimClaimTypes.Email, user.Email),
            new(SlimClaimTypes.SecurityStamp, user.SecurityStamp),
            new(SlimClaimTypes.AuthenticationMethod, authMethod),
        };

        foreach (var claim in await store.GetClaimsAsync(user, ct))
            AddNormalized(claims, claim);

        if (additionalClaims is not null)
            foreach (var claim in additionalClaims)
                AddNormalized(claims, claim);

        if (!string.IsNullOrEmpty(actorJson))
            claims.Add(new Claim(SlimClaimTypes.Actor, actorJson, JsonClaimValueTypes.Json));

        return claims;
    }

    private static void AddNormalized(List<Claim> target, Claim claim)
    {
        var type = claim.Type switch
        {
            ClaimTypes.Role => SlimClaimTypes.Role,
            ClaimTypes.Name => "name",
            _ => claim.Type,
        };
        if (ReservedClaims.Contains(type)) return;
        if (type == SlimClaimTypes.SudoUntil) target.RemoveAll(c => c.Type == SlimClaimTypes.SudoUntil);
        target.Add(new Claim(type, claim.Value, claim.ValueType));
    }
}
