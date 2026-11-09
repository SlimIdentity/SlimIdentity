using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using SlimIdentity.Security;

namespace SlimIdentity.Authentication;

/// <summary>
/// Re-validates cookie and bearer principals against the store: a rotated security stamp or
/// <c>IsActive = false</c> invalidates every existing session.
/// </summary>
internal static class SlimSecurityStampValidator
{
    public const string ValidatedAtKey = ".slim.validated";

    public static async Task ValidateCookieAsync(CookieValidatePrincipalContext context)
    {
        var http = context.HttpContext;
        var options = http.RequestServices.GetRequiredService<IOptions<SlimIdentityOptions>>().Value;
        var now = http.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow();
        var interval = options.Cookies.SecurityStampValidationInterval;

        if (interval > TimeSpan.Zero
            && context.Properties.Items.TryGetValue(ValidatedAtKey, out var raw)
            && DateTimeOffset.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var last)
            && now - last < interval)
        {
            return;
        }

        var user = await ValidPrincipalUserAsync(context.Principal, http);
        if (user is null)
        {
            context.RejectPrincipal();
            await http.SignOutAsync(SlimIdentityDefaults.CookieScheme);
            return;
        }

        // RefreshClaimsAsync changed the claims part of the stamp: re-issue the cookie with fresh claims – no sign-out
        if (await RefreshedPrincipalAsync(context.Principal!, user, http) is { } refreshed)
        {
            context.ReplacePrincipal(refreshed);
            context.ShouldRenew = true;
        }

        if (interval > TimeSpan.Zero)
        {
            context.Properties.Items[ValidatedAtKey] = now.ToString("O", CultureInfo.InvariantCulture);
            context.ShouldRenew = true;

            // keep "last seen" of the server-side session current (at most once per interval)
            if (context.Principal?.FindFirst(SlimClaimTypes.SessionId)?.Value is { } sid
                && http.RequestServices.GetService<ISlimSessionStore>() is { } sessions)
            {
                var expires = options.Cookies.SlidingExpiration ? now + options.Cookies.ExpireTimeSpan : context.Properties.ExpiresUtc ?? now + options.Cookies.ExpireTimeSpan;
                await sessions.TouchAsync(sid, now, expires, http.RequestAborted);
            }
        }
    }

    public static async Task ValidateBearerAsync(TokenValidatedContext context)
    {
        var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<SlimIdentityOptions>>().Value;
        if (!options.Tokens.ValidateSecurityStampOnEachRequest) return;

        var user = await ValidPrincipalUserAsync(context.Principal, context.HttpContext);
        if (user is null)
        {
            context.Fail("SlimIdentity: security stamp is no longer valid.");
            return;
        }

        // new claims for this request; the token itself is replaced at the next refresh
        if (await RefreshedPrincipalAsync(context.Principal!, user, context.HttpContext) is { } refreshed)
            context.Principal = refreshed;
    }

    /// <summary>
    /// The principal again, with the host's current claims – only if its stamp has an outdated claims part
    /// (same security state). Otherwise <c>null</c>: as long as nothing changed, no claims are loaded.
    /// </summary>
    private static async Task<ClaimsPrincipal?> RefreshedPrincipalAsync(ClaimsPrincipal principal, SlimUser user, HttpContext http)
    {
        var stamp = principal.FindFirst(SlimClaimTypes.SecurityStamp)?.Value;
        if (string.Equals(stamp, user.SecurityStamp, StringComparison.Ordinal)) return null;
        return await Services.SlimAuthManager.RebuildPrincipalAsync(principal, user,
            http.RequestServices.GetRequiredService<ISlimUserStore>(), http.RequestAborted);
    }

    /// <summary>The account behind <paramref name="principal"/> if the session is still valid, else <c>null</c>.</summary>
    private static async Task<SlimUser?> ValidPrincipalUserAsync(ClaimsPrincipal? principal, HttpContext http)
    {
        var userId = principal?.FindFirst(SlimClaimTypes.UserId)?.Value;
        var stamp = principal?.FindFirst(SlimClaimTypes.SecurityStamp)?.Value;
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(stamp)) return null;

        var store = http.RequestServices.GetRequiredService<ISlimUserStore>();
        var user = await store.FindByIdAsync(userId, http.RequestAborted);
        // only the security part counts here – a changed claims part means "reload claims", not "signed out"
        if (user is not { IsActive: true } || !SlimUser.IsSameSecurityState(user.SecurityStamp, stamp)) return null;

        // Server-side session: must exist (not revoked) and not be expired.
        if (principal!.FindFirst(SlimClaimTypes.SessionId)?.Value is { } sid
            && http.RequestServices.GetService<ISlimSessionStore>() is { } sessions)
        {
            var session = await sessions.FindAsync(sid, http.RequestAborted);
            var now = http.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow();
            if (session is null || session.ExpiresUtc <= now || !string.Equals(session.UserId, userId, StringComparison.Ordinal))
                return null;
        }

        // the host's sign-in guards decide about running sessions, too (suspended tenant, IP allow-list, …)
        var amr = principal.FindFirst(SlimClaimTypes.AuthenticationMethod)?.Value ?? "pwd";
        var actorId = SlimClaims.ParseActorClaim(principal.FindFirst(SlimClaimTypes.Actor)?.Value)?.UserId;
        if (await http.RequestServices.GetRequiredService<Services.SlimHookRunner>()
                .CheckSignInAsync(user, amr, SlimSignInStage.Revalidation, actorId, http.RequestAborted) is not null)
            return null;

        // Impersonation: the impersonator must still be active with an unchanged stamp.
        var actorClaim = principal.FindFirst(SlimClaimTypes.Actor)?.Value;
        if (actorClaim is null) return user;

        var actor = SlimClaims.ParseActorClaim(actorClaim);
        if (actor?.SecurityStamp is null) return null;
        var impersonator = await store.FindByIdAsync(actor.UserId, http.RequestAborted);
        return impersonator is { IsActive: true } && SlimUser.IsSameSecurityState(impersonator.SecurityStamp, actor.SecurityStamp) ? user : null;
    }
}
