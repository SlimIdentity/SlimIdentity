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

        if (!await IsPrincipalValidAsync(context.Principal, http))
        {
            context.RejectPrincipal();
            await http.SignOutAsync(SlimIdentityDefaults.CookieScheme);
            return;
        }

        if (interval > TimeSpan.Zero)
        {
            context.Properties.Items[ValidatedAtKey] = now.ToString("O", CultureInfo.InvariantCulture);
            context.ShouldRenew = true;
        }
    }

    public static async Task ValidateBearerAsync(TokenValidatedContext context)
    {
        var options = context.HttpContext.RequestServices.GetRequiredService<IOptions<SlimIdentityOptions>>().Value;
        if (!options.Tokens.ValidateSecurityStampOnEachRequest) return;

        if (!await IsPrincipalValidAsync(context.Principal, context.HttpContext))
            context.Fail("SlimIdentity: security stamp is no longer valid.");
    }

    private static async Task<bool> IsPrincipalValidAsync(ClaimsPrincipal? principal, HttpContext http)
    {
        var userId = principal?.FindFirst(SlimClaimTypes.UserId)?.Value;
        var stamp = principal?.FindFirst(SlimClaimTypes.SecurityStamp)?.Value;
        if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(stamp)) return false;

        var store = http.RequestServices.GetRequiredService<ISlimUserStore>();
        var user = await store.FindByIdAsync(userId, http.RequestAborted);
        if (user is not { IsActive: true } || !SlimHashing.FixedTimeEquals(user.SecurityStamp, stamp)) return false;

        // Impersonation: the impersonator must still be active with an unchanged stamp.
        var actorClaim = principal!.FindFirst(SlimClaimTypes.Actor)?.Value;
        if (actorClaim is null) return true;

        var actor = SlimClaims.ParseActorClaim(actorClaim);
        if (actor?.SecurityStamp is null) return false;
        var impersonator = await store.FindByIdAsync(actor.UserId, http.RequestAborted);
        return impersonator is { IsActive: true } && SlimHashing.FixedTimeEquals(impersonator.SecurityStamp, actor.SecurityStamp);
    }
}
