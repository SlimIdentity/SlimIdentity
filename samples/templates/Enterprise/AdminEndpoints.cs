// SlimIdentity sample – admin endpoints built on ISlimAuthManager:
// impersonation (user masking with 'act' claim), sudo mode, custom registration and API-key issuing.
//
//   app.MapAdminEndpoints();

using System.Security.Claims;
using SlimIdentity;
using SlimIdentity.Security;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MyApp.Enterprise;

public static class AdminEndpoints
{
    public sealed record SudoRequest(string Password);
    public sealed record InviteRequest(string Email, string DisplayName);
    public sealed record CreateUserRequest(string Email, string? StartPassword);
    public sealed record SetPasswordRequest(string Password, bool MustChange = true);

    /// <summary>Your own invitation mail (inviter name, company branding, …) – not part of ISlimEmailSender.</summary>
    public interface IInvitationMailer
    {
        Task SendInvitationAsync(string email, string displayName, string? invitedBy, string link, DateTimeOffset expiresAt, CancellationToken ct);
    }

    public static IEndpointRouteBuilder MapAdminEndpoints(this IEndpointRouteBuilder app)
    {
        var admin = app.MapGroup("/api/admin")
            .RequireAuthorization(p => p.RequireRole("Admin"))
            .RequireSlimCsrf()
            .WithTags("Admin");

        // Impersonate – requires a fresh sudo session
        admin.MapPost("/impersonate/{userId}", async (
                string userId, ClaimsPrincipal me,
                ISlimUserStore store, ISlimAuthManager auth, ILoggerFactory lf, CancellationToken ct) =>
            {
                if (!me.IsInSudoMode()) return Results.Json(new { status = "sudo_required" }, statusCode: 403);
                if (me.IsImpersonating()) return Results.BadRequest(new { status = "already_impersonating" });

                var target = await store.FindByIdAsync(userId, ct);
                if (target is null) return Results.NotFound();

                lf.CreateLogger("Audit").LogWarning("AUDIT impersonation {Admin} -> {Target}",
                    EscapeLogLineBreaks(me.GetSlimUserId() ?? ""), EscapeLogLineBreaks(target.Id));
                // the impersonation session takes the mode of the admin's session (cookie or JWT)
                var result = await auth.ImpersonateAsync(target, ct);
                return result.Succeeded
                    ? Results.Ok(result.ToResponse())
                    : Results.BadRequest(new { status = result.Error });
            });

        // Return from impersonation (only the impersonated session can call it, so not under the Admin role).
        // EndImpersonationAsync re-checks that the admin is still active and their security stamp is unchanged.
        app.MapPost("/api/impersonation/stop", async (ISlimAuthManager auth, CancellationToken ct) =>
            {
                var result = await auth.EndImpersonationAsync(ct);
                return result.Succeeded
                    ? Results.Ok(result.ToResponse())
                    : Results.Json(new { status = result.Error }, statusCode: result.Error == "not_impersonating" ? 400 : 401);
            })
            .RequireAuthorization()
            .RequireSlimCsrf();

        // Sudo: re-confirm password → 10 min elevated session
        app.MapPost("/api/sudo", async (SudoRequest req, ClaimsPrincipal me, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
            {
                var user = await store.FindByIdAsync(me.GetSlimUserId()!, ct);
                if (user is null) return Results.Unauthorized();
                // lockout, notification mail and ISlimCustomPasswordValidator – exactly like the built-in endpoints
                if (await auth.ConfirmPasswordAsync(user, req.Password, ct) is { } failure) return failure;

                var result = await auth.ElevateToSudoAsync(user, TimeSpan.FromMinutes(10), ct);
                return result.Succeeded
                    ? Results.Ok(result.ToResponse())
                    : Results.Json(new { status = result.Error }, statusCode: 403);   // e.g. vetoed by a sign-in guard
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

        // Invite-only B2B (built-in /register disabled via Endpoints.EnableRegistration = false):
        // the admin creates the account with business data but WITHOUT password and mails the link.
        // The invitee opens it in the SPA, which calls POST /auth/invitation/info (shows the e-mail)
        // and POST /auth/invitation/accept { token, password } (sets the password, confirms the mail, signs in).
        admin.MapPost("/invitations", async (InviteRequest req, ClaimsPrincipal me,
                ISlimUserStore store, ISlimAuthManager auth, IInvitationMailer mailer, CancellationToken ct) =>
            {
                if (SlimEmailAddress.Normalize(req.Email) is not { } email) return InvalidEmail();
                // CreateAsync returns null if the address is taken (unique index) – no check-then-act race
                // the profile is written by the store together with the account (EF Core package: ISlimUserFactory)
                if (await store.CreateAsync(new SlimNewUser { Email = email, Profile = req }, ct) is not { } user)
                    return Results.Conflict(new { status = "already_exists" });
                var invitation = await auth.CreateInvitationAsync(user, TimeSpan.FromDays(14), ct); // link from Links.BaseUrl (or Links.InvitationUrl)
                await mailer.SendInvitationAsync(email, req.DisplayName, me.GetSlimEmail(), invitation.Link, invitation.ExpiresAt, ct);
                return Results.Ok(new { status = "invited", user.Id, invitation.ExpiresAt });
            });

        // ---- account administration (essential with .WithoutEmail(); all behind a fresh sudo session)
        var accounts = admin.MapGroup("/users").RequireAuthorization(SlimIdentityDefaults.SudoPolicy);

        // Create an account without mail: the admin vouches for the address and hands over a reset link
        accounts.MapPost("/", async (CreateUserRequest req, ISlimUserStore store, ISlimAuthManager auth,
                IOptions<SlimIdentityOptions> options, IEnumerable<ISlimPasswordRule> rules, CancellationToken ct) =>
            {
                // the same canonical form as the built-in endpoints – otherwise look-alike duplicates slip past the unique index
                if (SlimEmailAddress.Normalize(req.Email) is not { } email) return InvalidEmail();
                // the start password is checked BEFORE the account exists: a rejected one must not leave an orphan
                // account behind that answers the corrected retry with 409
                if (req.StartPassword is { } candidate && await CheckPasswordAsync(candidate, email, options.Value, rules, ct) is { } rejected)
                    return rejected;

                // business data (DisplayName, roles …) as Profile – never the request itself, it holds the start password
                if (await store.CreateAsync(new SlimNewUser { Email = email }, ct) is not { } user)
                    return Results.Conflict(new { status = "already_exists" });
                user.EmailConfirmed = true;   // the administrator vouches for the address
                await store.UpdateSecurityStateAsync(user, ct);
                // read out on the phone – the user must choose an own password at the first sign-in
                if (req.StartPassword is { } start && await auth.SetPasswordAsync(user, start, mustChange: true, ct) is null)
                    return Results.Ok(new { status = "created", user.Id });
                // no start password – or a rule changed its mind since the check (e.g. a breach lookup): never an
                // account nobody can sign in to, the user sets the first password with the link
                var reset = await auth.CreatePasswordResetAsync(user, TimeSpan.FromDays(3), ct);
                return Results.Ok(new { status = "created", user.Id, resetLink = reset.Link, reset.ExpiresAt });
            });

        // Forgotten password: a link the user sets the password with – the admin never knows it
        accounts.MapPost("/{userId}/reset-link", async (string userId, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
            await store.FindByIdAsync(userId, ct) is { } user
                ? Results.Ok(await auth.CreatePasswordResetAsync(user, ct: ct))
                : Results.NotFound());

        // Start password (forced change at the next sign-in unless mustChange is false)
        accounts.MapPost("/{userId}/password", async (string userId, SetPasswordRequest req, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
            await store.FindByIdAsync(userId, ct) is { } user
                ? await auth.SetPasswordAsync(user, req.Password, req.MustChange, ct) ?? Results.Ok(new { status = "password_set" })
                : Results.NotFound());

        // Phone and recovery codes lost
        accounts.MapPost("/{userId}/reset-2fa", async (string userId, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
            {
                if (await store.FindByIdAsync(userId, ct) is not { } user) return Results.NotFound();
                await auth.ResetTwoFactorAsync(user, ct);
                return Results.Ok(new { status = "two_factor_reset" });
            });

        accounts.MapPost("/{userId}/unlock", async (string userId, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
            {
                if (await store.FindByIdAsync(userId, ct) is not { } user) return Results.NotFound();
                await auth.UnlockAsync(user, ct);
                return Results.Ok(new { status = "unlocked" });
            });

        // Ban: end every session on every device, then block the account in your own store
        admin.MapPost("/users/{userId}/ban", async (string userId, ISlimUserStore store, ISlimAuthManager auth, CancellationToken ct) =>
            {
                var user = await store.FindByIdAsync(userId, ct);
                if (user is null) return Results.NotFound();
                await auth.SignOutEverywhereAsync(user, ct);
                // TODO: set IsActive = false in your users table (not part of UpdateSecurityStateAsync)
                return Results.Ok(new { status = "banned" });
            });

        return app;
    }

    private static IResult InvalidEmail() =>
        Results.ValidationProblem(new Dictionary<string, string[]> { ["email"] = ["A valid e-mail address is required."] },
            extensions: new Dictionary<string, object?> { ["code"] = "validation_failed" });

    // the rules SetPasswordAsync applies (length limits + every ISlimPasswordRule), in the same validation format
    private static async Task<IResult?> CheckPasswordAsync(string password, string email, SlimIdentityOptions options,
        IEnumerable<ISlimPasswordRule> rules, CancellationToken ct)
    {
        var p = options.Password;
        var errors = new List<string>();
        if (password.Length < p.MinimumLength) errors.Add($"Password must be at least {p.MinimumLength} characters long.");
        if (password.Length > p.MaximumLength) errors.Add($"Password must be at most {p.MaximumLength} characters long.");
        if (errors.Count == 0)
            foreach (var rule in rules)
                errors.AddRange(await rule.ValidateAsync(password, email, ct));
        return errors.Count == 0
            ? null
            : Results.ValidationProblem(new Dictionary<string, string[]> { ["password"] = [.. errors] },
                extensions: new Dictionary<string, object?> { ["code"] = "validation_failed" });
    }

    private static string EscapeLogLineBreaks(string value) =>
        value.Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);
}
