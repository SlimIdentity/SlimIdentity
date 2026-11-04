using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SlimIdentity.Abstractions;
using SlimIdentity.Contracts;
using SlimIdentity.Endpoints;
using SlimIdentity.Http;

namespace SlimIdentity;

public static class SlimIdentityEndpointExtensions
{
    private static readonly IAuthorizeData[] SlimAuthorize =
        [new AuthorizeAttribute { AuthenticationSchemes = SlimIdentityDefaults.AuthenticationScheme }];

    /// <summary>
    /// Maps the hardened SlimIdentity JSON endpoints (default prefix <c>/auth</c>) incl. OpenAPI metadata.
    /// Capability routes are only mapped when the corresponding store is registered.
    /// </summary>
    public static RouteGroupBuilder MapSlimIdentityApi(this IEndpointRouteBuilder endpoints)
    {
        var sp = endpoints.ServiceProvider;
        var o = sp.GetRequiredService<IOptions<SlimIdentityOptions>>().Value; // triggers validation
        var isService = sp.GetRequiredService<IServiceProviderIsService>();
        bool Has<T>() => isService.IsService(typeof(T));

        if (!Has<ISlimUserStore>())
            throw new InvalidOperationException("SlimIdentity: no ISlimUserStore registered. Call .AddUserStore<T>() after AddSlimIdentity().");
        if (!Has<ISlimEmailSender>())
            throw new InvalidOperationException("SlimIdentity: no ISlimEmailSender registered. Call .AddEmailSender<T>() or .AddNullEmailSender().");

        var group = endpoints.MapGroup(o.RoutePrefix)
            .WithTags(SlimIdentityDefaults.OpenApiTag)
            .AddEndpointFilter<RouteGroupBuilder, SlimCsrfEndpointFilter>();

        MapLogin(group, o, Has<ISlimTwoFactorStore>(), Has<ISlimRefreshTokenStore>());
        MapAccount(group, o);
        if (Has<ISlimTwoFactorStore>()) MapTwoFactor(group);
        if (Has<ISlimExternalLoginStore>()) MapExternal(group, o);

        return group;
    }

    /// <summary>Applies the SlimIdentity CSRF check (custom header + Origin) to a host endpoint.</summary>
    public static TBuilder RequireSlimCsrf<TBuilder>(this TBuilder builder) where TBuilder : IEndpointConventionBuilder =>
        builder.AddEndpointFilter<TBuilder, SlimCsrfEndpointFilter>();

    // ------------------------------------------------------------------ login / session

    private static void MapLogin(RouteGroupBuilder group, SlimIdentityOptions o, bool twoFactor, bool refresh)
    {
        group.MapPost("/login", static ([FromBody] SlimLoginRequest request, [FromQuery] bool? useCookies,
                [FromServices] SlimLoginHandlers h, CancellationToken ct) => h.LoginAsync(request, useCookies, ct))
            .WithName("SlimIdentity_Login")
            .WithSummary("Sign in with e-mail and password (cookie or JWT, see ?useCookies).")
            .Produces<SlimAuthResponse>()
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .Produces<SlimLoginChallengeResponse>(StatusCodes.Status401Unauthorized)
            .Produces<SlimStatusResponse>(StatusCodes.Status403Forbidden)
            .Produces<SlimLockedResponse>(StatusCodes.Status423Locked)
            .Produces(StatusCodes.Status429TooManyRequests)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
            .AllowAnonymous();

        if (twoFactor)
        {
            group.MapPost("/login/2fa", static ([FromBody] SlimTwoFactorLoginRequest request,
                    [FromServices] SlimLoginHandlers h, CancellationToken ct) => h.LoginTwoFactorAsync(request, ct))
                .WithName("SlimIdentity_LoginTwoFactor")
                .WithSummary("Exchange preAuthToken + TOTP / e-mail / recovery code for the final session.")
                .Produces<SlimAuthResponse>()
                .Produces<SlimStatusResponse>(StatusCodes.Status401Unauthorized)
                .Produces<SlimLockedResponse>(StatusCodes.Status423Locked)
                .Produces(StatusCodes.Status429TooManyRequests)
                .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
                .AllowAnonymous();
        }

        if (refresh && o.Endpoints.AllowJwtAuth)
        {
            group.MapPost("/refresh", static ([FromBody] SlimRefreshRequest request,
                    [FromServices] SlimLoginHandlers h, CancellationToken ct) => h.RefreshAsync(request, ct))
                .WithName("SlimIdentity_Refresh")
                .WithSummary("Rotate a refresh token into a new JWT pair.")
                .Produces<SlimAuthResponse>()
                .Produces<SlimStatusResponse>(StatusCodes.Status401Unauthorized)
                .Produces(StatusCodes.Status429TooManyRequests)
                .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
                .AllowAnonymous();
        }

        if (o.Endpoints.EnableLogout)
        {
            group.MapPost("/logout", static ([FromBody] SlimLogoutRequest? request,
                    [FromServices] SlimLoginHandlers h, CancellationToken ct) => h.LogoutAsync(request, ct))
                .WithName("SlimIdentity_Logout")
                .WithSummary("Delete the auth cookie and/or consume the given refresh token.")
                .Produces<SlimStatusResponse>()
                .AllowAnonymous();
        }
    }

    // ------------------------------------------------------------------ account

    private static void MapAccount(RouteGroupBuilder group, SlimIdentityOptions o)
    {
        var e = o.Endpoints;

        if (e.EnableRegistration)
        {
            group.MapPost("/register", static ([FromBody] SlimRegisterRequest request,
                    [FromServices] SlimAccountHandlers h, CancellationToken ct) => h.RegisterAsync(request, ct))
                .WithName("SlimIdentity_Register")
                .WithSummary("Register with e-mail and password only. Always 200 (enumeration prevention).")
                .Produces<SlimStatusResponse>()
                .ProducesValidationProblem()
                .Produces(StatusCodes.Status429TooManyRequests)
                .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
                .AllowAnonymous();
        }

        if (e.EnableEmailVerification)
        {
            group.MapPost("/verify-email", static ([FromBody] SlimVerifyEmailRequest request,
                    [FromServices] SlimAccountHandlers h, CancellationToken ct) => h.VerifyEmailAsync(request, ct))
                .WithName("SlimIdentity_VerifyEmail")
                .WithSummary("Confirm the e-mail address with the token from the verification mail.")
                .Produces<SlimStatusResponse>()
                .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
                .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
                .AllowAnonymous();

            group.MapPost("/resend-verification", static ([FromBody] SlimEmailRequest request,
                    [FromServices] SlimAccountHandlers h, CancellationToken ct) => h.ResendVerificationAsync(request, ct))
                .WithName("SlimIdentity_ResendVerification")
                .WithSummary("Send the verification mail again. Always 200.")
                .Produces<SlimStatusResponse>()
                .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
                .AllowAnonymous();
        }

        if (e.EnablePasswordReset)
        {
            group.MapPost("/forgot-password", static ([FromBody] SlimEmailRequest request,
                    [FromServices] SlimAccountHandlers h, CancellationToken ct) => h.ForgotPasswordAsync(request, ct))
                .WithName("SlimIdentity_ForgotPassword")
                .WithSummary("Send a password reset mail. Always 200 (enumeration prevention).")
                .Produces<SlimStatusResponse>()
                .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
                .AllowAnonymous();

            group.MapPost("/reset-password", static ([FromBody] SlimResetPasswordRequest request,
                    [FromServices] SlimAccountHandlers h, CancellationToken ct) => h.ResetPasswordAsync(request, ct))
                .WithName("SlimIdentity_ResetPassword")
                .WithSummary("Set a new password with the reset token. Rotates the security stamp.")
                .Produces<SlimStatusResponse>()
                .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
                .ProducesValidationProblem()
                .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
                .AllowAnonymous();
        }

        if (e.EnableChangePassword)
        {
            group.MapPost("/change-password", static ([FromBody] SlimChangePasswordRequest request,
                    [FromServices] SlimAccountHandlers h, CancellationToken ct) => h.ChangePasswordAsync(request, ct))
                .WithName("SlimIdentity_ChangePassword")
                .WithSummary("Change the password of the signed-in user; signs out all other devices.")
                .Produces<SlimAuthResponse>()
                .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
                .ProducesValidationProblem()
                .Produces(StatusCodes.Status401Unauthorized)
                .Produces<SlimLockedResponse>(StatusCodes.Status423Locked)
                .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
                .RequireAuthorization(SlimAuthorize);
        }

        if (e.EnableMe)
        {
            group.MapGet("/me", static ([FromServices] SlimAccountHandlers h) => h.Me())
                .WithName("SlimIdentity_Me")
                .WithSummary("Current user, impersonation info and claims (for SPA state after reload).")
                .Produces<SlimMeResponse>()
                .Produces(StatusCodes.Status401Unauthorized)
                .RequireAuthorization(SlimAuthorize);
        }
    }

    // ------------------------------------------------------------------ 2FA management

    private static void MapTwoFactor(RouteGroupBuilder root)
    {
        var group = root.MapGroup("/2fa").RequireAuthorization(SlimAuthorize);

        group.MapGet("/", static ([FromServices] SlimTwoFactorHandlers h, CancellationToken ct) => h.StatusAsync(ct))
            .WithName("SlimIdentity_TwoFactorStatus")
            .WithSummary("2FA status of the signed-in user.")
            .Produces<SlimTwoFactorStatusResponse>();

        group.MapPost("/setup", static ([FromServices] SlimTwoFactorHandlers h, CancellationToken ct) => h.SetupAsync(ct))
            .WithName("SlimIdentity_TwoFactorSetup")
            .WithSummary("Create a TOTP secret (otpauth URI for QR code). Persisted only after /2fa/enable.")
            .Produces<SlimTwoFactorSetupResponse>();

        group.MapPost("/enable", static ([FromBody] SlimTwoFactorEnableRequest request,
                [FromServices] SlimTwoFactorHandlers h, CancellationToken ct) => h.EnableAuthenticatorAsync(request, ct))
            .WithName("SlimIdentity_TwoFactorEnable")
            .WithSummary("Confirm the first TOTP code; enables 2FA and returns recovery codes.")
            .Produces<SlimRecoveryCodesResponse>()
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);

        group.MapPost("/enable-email", static ([FromBody] SlimPasswordConfirmationRequest request,
                [FromServices] SlimTwoFactorHandlers h, CancellationToken ct) => h.EnableEmailAsync(request, ct))
            .WithName("SlimIdentity_TwoFactorEnableEmail")
            .WithSummary("Enable 2FA with e-mail codes (password confirmation required).")
            .Produces<SlimRecoveryCodesResponse>()
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);

        group.MapPost("/disable", static ([FromBody] SlimPasswordConfirmationRequest request,
                [FromServices] SlimTwoFactorHandlers h, CancellationToken ct) => h.DisableAsync(request, ct))
            .WithName("SlimIdentity_TwoFactorDisable")
            .WithSummary("Disable 2FA (password confirmation required).")
            .Produces<SlimAuthResponse>()
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);

        group.MapPost("/recovery-codes", static ([FromBody] SlimPasswordConfirmationRequest request,
                [FromServices] SlimTwoFactorHandlers h, CancellationToken ct) => h.RegenerateRecoveryCodesAsync(request, ct))
            .WithName("SlimIdentity_TwoFactorRecoveryCodes")
            .WithSummary("Replace all recovery codes (password confirmation required).")
            .Produces<SlimRecoveryCodesResponse>()
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);
    }

    // ------------------------------------------------------------------ external login

    private static void MapExternal(RouteGroupBuilder group, SlimIdentityOptions o)
    {
        // literal route first so it never collides with /login/{provider}
        if (o.Endpoints.AllowJwtAuth)
        {
            group.MapPost("/login/external/exchange", static ([FromBody] SlimExternalExchangeRequest request,
                    [FromServices] SlimExternalLoginHandlers h, CancellationToken ct) => h.ExchangeAsync(request, ct))
                .WithName("SlimIdentity_ExternalExchange")
                .WithSummary("Exchange the one-time code from the external-login redirect for a JWT pair.")
                .Produces<SlimAuthResponse>()
                .Produces<SlimStatusResponse>(StatusCodes.Status401Unauthorized)
                .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
                .AllowAnonymous();
        }

        group.MapGet("/login/{provider}", static (string provider, [FromQuery] string? returnUrl, [FromQuery] bool? useCookies,
                [FromServices] SlimExternalLoginHandlers h) => h.ChallengeAsync(provider, returnUrl, useCookies))
            .WithName("SlimIdentity_ExternalChallenge")
            .WithSummary("Start an OAuth / OIDC login (Google, Apple, Entra ID, Keycloak, …). Browser navigation, not fetch.")
            .Produces(StatusCodes.Status302Found)
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .Produces<SlimStatusResponse>(StatusCodes.Status404NotFound)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
            .AllowAnonymous();

        group.MapGet("/login/{provider}/callback", static (string provider,
                [FromServices] SlimExternalLoginHandlers h, CancellationToken ct) => h.CallbackAsync(provider, ct))
            .WithName("SlimIdentity_ExternalCallback")
            .ExcludeFromDescription()
            .AllowAnonymous();
    }
}
