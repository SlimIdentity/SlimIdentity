// SlimIdentity sample – admin endpoints built on ISlimAuthManager:
// impersonation (user masking with 'act' claim), sudo mode, custom registration and API-key issuing.
//
//   app.MapAdminEndpoints();

using System.Security.Claims;
using SlimIdentity;
using SlimIdentity.Abstractions;
using SlimIdentity.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;

namespace MyApp.Enterprise;

public static class AdminEndpoints
{
    public sealed record SudoRequest(string Password);
    public sealed record InviteRegistrationRequest(string InviteCode, string Email, string Password, string DisplayName);

    public static IEndpointRouteBuilder MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var admin = app.MapGroup("/api/admin")
            .RequireAuthorization(p => p.RequireRole("Admin"))
            .RequireSlimCsrf()
            .WithTags("Admin");

        // Impersonate – requires a fresh sudo session
        admin.MapPost("/impersonate/{userId}", async (
                string userId, [FromQuery] bool? useCookies, ClaimsPrincipal me,
                ISlimUserStore store, ISlimAuthManager auth, ILoggerFactory lf, CancellationToken ct) =>
            {
                if (!me.IsInSudoMode()) return Results.Json(new { status = "sudo_required" }, statusCode: 403);
                if (me.IsImpersonating()) return Results.BadRequest(new { status = "already_impersonating" });

                var target = await store.FindByIdAsync(userId, ct);
                if (target is null) return Results.NotFound();

                lf.CreateLogger("Audit").LogWarning("AUDIT impersonation {Admin} -> {Target}", me.GetSlimUserId(), target.Id);
                var result = await auth.ImpersonateAsync(target, me.GetSlimUserId()!, useCookies ?? me.IsSlimCookieSession(), ct);
                return result.Succeeded
                    ? Results.Ok(result.ToResponse(DateTimeOffset.UtcNow))
                    : Results.BadRequest(new { status = result.Error });
            });

        // Return from impersonation (only the impersonated session can call it, so not under the Admin role).
        // EndImpersonationAsync re-checks that the admin is still active and their security stamp is unchanged.
        app.MapPost("/api/impersonation/stop", async (ISlimAuthManager auth, CancellationToken ct) =>
            {
                var result = await auth.EndImpersonationAsync(ct);
                return result.Succeeded
                    ? Results.Ok(result.ToResponse(DateTimeOffset.UtcNow))
                    : Results.Json(new { status = result.Error }, statusCode: result.Error == "not_impersonating" ? 400 : 401);
            })
            .RequireAuthorization()
            .RequireSlimCsrf();

        // Sudo: re-confirm password → 10 min elevated session
        app.MapPost("/api/sudo", async (SudoRequest req, ClaimsPrincipal me, ISlimUserStore store,
                IPasswordHasher<SlimUser> hasher, ISlimAuthManager auth, CancellationToken ct) =>
            {
                var user = await store.FindByIdAsync(me.GetSlimUserId()!, ct);
                if (user is null || hasher.VerifyHashedPassword(user, user.PasswordHash, req.Password) == PasswordVerificationResult.Failed)
                    return Results.BadRequest(new { status = "invalid_password" });

                var result = await auth.ElevateSessionAsync(user, [SlimClaims.SudoFor(TimeSpan.FromMinutes(10))], me.IsSlimCookieSession(), ct);
                return Results.Ok(result.ToResponse(DateTimeOffset.UtcNow));
            })
            .RequireAuthorization()
            .RequireSlimCsrf()
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);

        // Issue an API key (key shown once, only the hash is stored)
        admin.MapPost("/api-keys/{clientId}", (string clientId) =>
            {
                var (key, hash) = SlimApiKeys.Generate();
                // TODO: persist (clientId, hash) in your ApiKeys table
                return Results.Ok(new { clientId, apiKey = key, storedHash = hash });
            })
            .RequireAuthorization(SlimIdentityDefaults.SudoPolicy);

        // Custom registration with business fields (built-in /register disabled via Endpoints.EnableRegistration = false)
        app.MapPost("/api/register-with-invite", async (InviteRegistrationRequest req,
                ISlimUserStore store, IPasswordHasher<SlimUser> hasher, ISlimAuthManager auth, CancellationToken ct) =>
            {
                // TODO: validate invite code, password policy, create business profile (DisplayName, tenant …)
                var hash = hasher.HashPassword(new SlimUser { Email = req.Email }, req.Password);
                var user = await store.CreateAsync(req.Email, hash, ct);
                var result = await auth.SignInAsync(user, useCookies: false, ct: ct);
                return Results.Ok(result.ToResponse(DateTimeOffset.UtcNow));
            })
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);

        return app;
    }
}
