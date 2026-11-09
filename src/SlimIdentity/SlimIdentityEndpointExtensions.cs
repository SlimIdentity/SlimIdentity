using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Mvc;
using SlimIdentity.Contracts;
using SlimIdentity.Endpoints;
using SlimIdentity.Http;

namespace SlimIdentity;

/// <summary>Endpoint mapping: <c>app.MapSlimIdentityApi()</c> and <c>.RequireSlimCsrf()</c>.</summary>
public static class SlimIdentityEndpointExtensions
{
    /// <summary>
    /// Answers carry tokens, recovery codes, TOTP secrets or account state – no browser, proxy or CDN may store them
    /// (RFC 6749 §5.1, OAuth 2.1). Set before the endpoint runs, so it covers error and CSRF answers too.
    /// </summary>
    private static ValueTask<object?> NoStore(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var headers = context.HttpContext.Response.Headers;
        headers.CacheControl = "no-store";
        headers.Pragma = "no-cache";
        return next(context);
    }

    private static readonly IAuthorizeData[] SlimAuthorize =
        [new AuthorizeAttribute { AuthenticationSchemes = SlimIdentityDefaults.UserScheme }];   // never API keys

    /// <summary>
    /// Maps the hardened SlimIdentity JSON endpoints (default prefix <c>/auth</c>) incl. OpenAPI metadata.
    /// Capability routes are only mapped when the corresponding store is registered.
    /// </summary>
    public static RouteGroupBuilder MapSlimIdentityApi(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var sp = endpoints.ServiceProvider;
        var o = sp.GetRequiredService<IOptions<SlimIdentityOptions>>().Value; // triggers validation
        var isService = sp.GetRequiredService<IServiceProviderIsService>();
        bool Has<T>() => isService.IsService(typeof(T));

        if (!Has<ISlimUserStore>())
            throw new InvalidOperationException("SlimIdentity: no ISlimUserStore registered. Call .AddUserStore<T>() after AddSlimIdentity().");
        if (o.Email.Enabled && !Has<ISlimEmailSender>())
            throw new InvalidOperationException(
                "SlimIdentity: no ISlimEmailSender registered. Call .AddEmailSender<T>() or .AddNullEmailSender() – or .WithoutEmail() for a host without mail.");
        if (!o.Email.Enabled && Has<ISlimEmailSender>())
            throw new InvalidOperationException(
                "SlimIdentity: WithoutEmail() and a mail sender are both registered. Remove one of them.");
        if (sp.GetService<SlimIdentityBuilder.SlimNullEmailSenderGuard>() is { AllowInProduction: false }
            && sp.GetService<Microsoft.Extensions.Hosting.IHostEnvironment>() is { } environment
            && Microsoft.Extensions.Hosting.HostEnvironmentEnvExtensions.IsProduction(environment))
            throw new InvalidOperationException(
                "SlimIdentity: AddNullEmailSender() in the Production environment – it would write live password-reset links and " +
                "2FA codes to the log. Register a real sender with .AddEmailSender<T>(), or pass allowInProduction: true deliberately.");

        sp.GetService<SlimDeploymentDiagnostics>()?.InspectStartup(sp);

        var group = endpoints.MapGroup(o.RoutePrefix)
            .WithTags(SlimIdentityDefaults.OpenApiTag)
            .AddEndpointFilter(NoStore)
            .AddEndpointFilter<RouteGroupBuilder, SlimCsrfEndpointFilter>();

        // OpenAPI: every state-changing endpoint can answer 403 csrf_validation_failed in cookie mode
        ((IEndpointConventionBuilder)group).Finally(AddCsrfResponseMetadata);

        MapLogin(group, o, Has<ISlimTwoFactorStore>(), Has<ISlimRefreshTokenStore>());
        MapAccount(group, o);
        if (Has<ISlimSessionStore>()) MapSessions(group);
        if (Has<ISlimTwoFactorStore>()) MapTwoFactor(group, o);
        if (Has<ISlimExternalLoginStore>()) MapExternal(group, o);
        MapSignInMethods(group, Has<ISlimExternalLoginStore>(), Has<ISlimPasskeyStore>());
        if (Has<ISlimPasskeyStore>())
        {
            if (o.Passkeys.EffectiveRelyingPartyId(o.Links) is null)
                throw new InvalidOperationException("SlimIdentity: passkeys need Passkeys.RelyingPartyId (or Links.BaseUrl) – the domain " +
                    "they are bound to – choose it once, changing it later makes every registered passkey unusable.");
            MapPasskeys(group);
        }
        if (Has<ISlimExternalLoginStore>() && Has<SlimBackChannelProviders>()) MapBackChannelLogout(group);

        return group;
    }

    private static void AddCsrfResponseMetadata(EndpointBuilder endpoint)
    {
        var stateChanging = endpoint.Metadata.OfType<IHttpMethodMetadata>()
            .Any(m => m.HttpMethods.Any(x => x is not ("GET" or "HEAD" or "OPTIONS")));
        var has403 = endpoint.Metadata.OfType<IProducesResponseTypeMetadata>().Any(m => m.StatusCode == StatusCodes.Status403Forbidden);
        if (stateChanging && !has403)
            endpoint.Metadata.Add(new ProducesResponseTypeMetadata(StatusCodes.Status403Forbidden, typeof(SlimStatusResponse), ["application/json"]));
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

        group.MapPost("/login/password-change", static ([FromBody] SlimPasswordChangeLoginRequest request,
                [FromServices] SlimLoginHandlers h, CancellationToken ct) => h.CompletePasswordChangeAsync(request, ct))
            .WithName("SlimIdentity_LoginPasswordChange")
            .WithSummary("Replace a password set by an administrator (passwordChangeToken from /login); then 2FA or the session.")
            .Produces<SlimAuthResponse>()
            .Produces<SlimLoginChallengeResponse>(StatusCodes.Status401Unauthorized)
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .ProducesValidationProblem()
            .Produces(StatusCodes.Status429TooManyRequests)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
            .AllowAnonymous();

        if (refresh && o.JwtEnabled)
        {
            group.MapPost("/refresh", static ([FromBody] SlimRefreshRequest request,
                    [FromServices] SlimLoginHandlers h, CancellationToken ct) => h.RefreshAsync(request, ct))
                .WithName("SlimIdentity_Refresh")
                .WithSummary("Rotate a refresh token into a new JWT pair (single use; reuse revokes the session).")
                .Produces<SlimAuthResponse>()
                .Produces<SlimStatusResponse>(StatusCodes.Status401Unauthorized)
                .Produces(StatusCodes.Status429TooManyRequests)
                .RequireRateLimiting(SlimIdentityDefaults.RefreshPolicy)
                .AllowAnonymous();
        }

        group.MapPost("/logout", static ([FromBody] SlimLogoutRequest? request,
                [FromServices] SlimLoginHandlers h, CancellationToken ct) => h.LogoutAsync(request, ct))
            .WithName("SlimIdentity_Logout")
            .WithSummary("End the current session: delete the cookie, consume the refresh token, revoke the server-side session.")
            .Produces<SlimStatusResponse>()
            .AllowAnonymous();

        group.MapPost("/logout-all", static ([FromServices] SlimLoginHandlers h, CancellationToken ct) => h.LogoutAllAsync(ct))
            .WithName("SlimIdentity_LogoutAll")
            .WithSummary("Sign out on all devices (rotates the security stamp, revokes all sessions).")
            .Produces<SlimStatusResponse>()
            .Produces(StatusCodes.Status401Unauthorized)
            .RequireAuthorization(SlimAuthorize);
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

        if (e.EnablePasswordReset && o.Email.Enabled)
        {
            group.MapPost("/forgot-password", static ([FromBody] SlimEmailRequest request,
                    [FromServices] SlimAccountHandlers h, CancellationToken ct) => h.ForgotPasswordAsync(request, ct))
                .WithName("SlimIdentity_ForgotPassword")
                .WithSummary("Send a password reset mail. Always 200 (enumeration prevention).")
                .Produces<SlimStatusResponse>()
                .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
                .AllowAnonymous();
        }

        // also without mail: administrators hand out reset links (ISlimAuthManager.CreatePasswordResetAsync)
        if (e.EnablePasswordReset)
        {
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

        // invitations: harmless without links – only the host can create them (ISlimAuthManager.CreateInvitationAsync)
        group.MapPost("/invitation/info", static ([FromBody] SlimInvitationInfoRequest request,
                [FromServices] SlimAccountHandlers h, CancellationToken ct) => h.InvitationInfoAsync(request, ct))
            .WithName("SlimIdentity_InvitationInfo")
            .WithSummary("Check an invitation link and return the invited e-mail address (for the \"set your password\" form).")
            .Produces<SlimInvitationInfoResponse>()
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
            .AllowAnonymous();

        group.MapPost("/invitation/accept", static ([FromBody] SlimAcceptInvitationRequest request, [FromQuery] bool? useCookies,
                [FromServices] SlimAccountHandlers h, CancellationToken ct) => h.AcceptInvitationAsync(request, useCookies, ct))
            .WithName("SlimIdentity_AcceptInvitation")
            .WithSummary("Accept an invitation: set the password, confirm the e-mail and sign in (cookie or JWT, see ?useCookies).")
            .Produces<SlimAuthResponse>()
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .ProducesValidationProblem()
            .Produces(StatusCodes.Status429TooManyRequests)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
            .AllowAnonymous();

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

        if (e.EnableChangeEmail)
        {
            group.MapPost("/change-email", static ([FromBody] SlimChangeEmailRequest request,
                    [FromServices] SlimAccountHandlers h, CancellationToken ct) => h.ChangeEmailAsync(request, ct))
                .WithName("SlimIdentity_ChangeEmail")
                .WithSummary("Request an e-mail change (password required). A confirmation link is sent to the new address. Always 200.")
                .Produces<SlimStatusResponse>()
                .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
                .ProducesValidationProblem()
                .Produces(StatusCodes.Status401Unauthorized)
                .Produces<SlimLockedResponse>(StatusCodes.Status423Locked)
                .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
                .RequireAuthorization(SlimAuthorize);

            group.MapPost("/confirm-email-change", static ([FromBody] SlimConfirmEmailChangeRequest request,
                    [FromServices] SlimAccountHandlers h, CancellationToken ct) => h.ConfirmEmailChangeAsync(request, ct))
                .WithName("SlimIdentity_ConfirmEmailChange")
                .WithSummary("Confirm the e-mail change with the token from the mail; all sessions end.")
                .Produces<SlimStatusResponse>()
                .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
                .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
                .AllowAnonymous();
        }

        group.MapGet("/password-policy", static ([FromServices] IOptions<SlimIdentityOptions> options,
                [FromServices] IEnumerable<ISlimPasswordRule> rules) =>
            {
                var p = options.Value.Password;
                return Results.Ok(new SlimPasswordPolicyResponse(p.MinimumLength, p.MaximumLength, rules.Any()));
            })
            .WithName("SlimIdentity_PasswordPolicy")
            .WithSummary("Rules for new passwords – for hints and live validation in the front end.")
            .Produces<SlimPasswordPolicyResponse>()
            .AllowAnonymous();

        group.MapGet("/me", static ([FromServices] SlimAccountHandlers h) => h.Me())
            .WithName("SlimIdentity_Me")
            .WithSummary("Current user, impersonation info and claims (for SPA state after reload).")
            .Produces<SlimMeResponse>()
            .Produces(StatusCodes.Status401Unauthorized)
            .RequireAuthorization(SlimAuthorize);
    }

    // ------------------------------------------------------------------ sessions (ISlimSessionStore)

    private static void MapSessions(RouteGroupBuilder root)
    {
        var group = root.MapGroup("/sessions").RequireAuthorization(SlimAuthorize);

        group.MapGet("/", static ([FromServices] SlimAccountHandlers h, CancellationToken ct) => h.ListSessionsAsync(ct))
            .WithName("SlimIdentity_Sessions")
            .WithSummary("Active sessions (devices) of the signed-in user.")
            .Produces<List<SlimSessionDto>>()
            .Produces(StatusCodes.Status401Unauthorized);

        group.MapDelete("/{sessionId}", static (string sessionId, [FromServices] SlimAccountHandlers h, CancellationToken ct) =>
                h.RevokeSessionAsync(sessionId, ct))
            .WithName("SlimIdentity_RevokeSession")
            .WithSummary("Sign out one device. Revoking the current session also deletes the cookie.")
            .Produces<SlimStatusResponse>()
            .Produces<SlimStatusResponse>(StatusCodes.Status404NotFound)
            .Produces(StatusCodes.Status401Unauthorized);
    }

    // ------------------------------------------------------------------ 2FA management

    private static void MapTwoFactor(RouteGroupBuilder root, SlimIdentityOptions o)
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

        if (o.EmailCodesEnabled)
        {
            group.MapPost("/enable-email", static ([FromBody] SlimPasswordConfirmationRequest request,
                    [FromServices] SlimTwoFactorHandlers h, CancellationToken ct) => h.EnableEmailAsync(request, ct))
                .WithName("SlimIdentity_TwoFactorEnableEmail")
                .WithSummary("Enable 2FA with e-mail codes (password confirmation required).")
                .Produces<SlimRecoveryCodesResponse>()
                .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
                .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);
        }

        group.MapPost("/disable", static ([FromBody] SlimPasswordConfirmationRequest request,
                [FromServices] SlimTwoFactorHandlers h, CancellationToken ct) => h.DisableAsync(request, ct))
            .WithName("SlimIdentity_TwoFactorDisable")
            .WithSummary("Disable 2FA (password confirmation required).")
            .Produces<SlimAuthResponse>()
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);

        group.MapPost("/forget-device", static ([FromServices] SlimTwoFactorHandlers h) => h.ForgetDevice())
            .WithName("SlimIdentity_TwoFactorForgetDevice")
            .WithSummary("This browser asks for the second factor again (deletes the remember-device cookie).")
            .Produces<SlimStatusResponse>()
            .AllowAnonymous();

        group.MapPost("/forget-all-devices", static ([FromServices] SlimTwoFactorHandlers h, CancellationToken ct) =>
                h.ForgetAllDevicesAsync(ct))
            .WithName("SlimIdentity_TwoFactorForgetAllDevices")
            .WithSummary("All remembered devices ask for the second factor again; other sessions end, this one is renewed.")
            .Produces<SlimAuthResponse>()
            .Produces(StatusCodes.Status401Unauthorized);

        group.MapPost("/recovery-codes", static ([FromBody] SlimPasswordConfirmationRequest request,
                [FromServices] SlimTwoFactorHandlers h, CancellationToken ct) => h.RegenerateRecoveryCodesAsync(request, ct))
            .WithName("SlimIdentity_TwoFactorRecoveryCodes")
            .WithSummary("Replace all recovery codes (password confirmation required).")
            .Produces<SlimRecoveryCodesResponse>()
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);
    }

    // ------------------------------------------------------------------ external login

    private static void MapPasskeys(RouteGroupBuilder root)
    {
        var group = root.MapGroup("/passkeys");

        group.MapPost("/register/options", static ([FromBody] SlimPasskeyRegistrationOptionsRequest request,
                [FromServices] SlimPasskeyHandlers h, CancellationToken ct) => h.RegistrationOptionsAsync(request, ct))
            .WithName("SlimIdentity_PasskeyRegistrationOptions")
            .WithSummary("Start adding a passkey (password required if the account has one): options for navigator.credentials.create and a state.")
            .Produces<SlimPasskeyCreationOptionsResponse>()
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .Produces<SlimStatusResponse>(StatusCodes.Status403Forbidden)
            .RequireAuthorization(SlimAuthorize)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);

        group.MapPost("/register", static ([FromBody] SlimPasskeyRegisterRequest request,
                [FromServices] SlimPasskeyHandlers h, CancellationToken ct) => h.RegisterAsync(request, ct))
            .WithName("SlimIdentity_PasskeyRegister")
            .WithSummary("Finish adding a passkey with the result of navigator.credentials.create.")
            .Produces<SlimPasskeyInfo>()
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .Produces<SlimStatusResponse>(StatusCodes.Status409Conflict)
            .RequireAuthorization(SlimAuthorize)
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
            .WithSummary("Sign in with the result of navigator.credentials.get. A passkey is multi-factor: no second factor follows.")
            .Produces<SlimAuthResponse>()
            .Produces<SlimStatusResponse>(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status429TooManyRequests)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
            .AllowAnonymous();
    }

    private static void MapSignInMethods(RouteGroupBuilder root, bool externalLogins, bool passkeys)
    {
        var group = root.MapGroup("/sign-in-methods").RequireAuthorization(SlimAuthorize);

        group.MapGet("", static ([FromServices] SlimSignInMethodHandlers h, CancellationToken ct) => h.ListAsync(ct))
            .WithName("SlimIdentity_SignInMethods")
            .WithSummary("The sign-in methods of the account: password, linked external logins.")
            .Produces<SlimSignInMethodsResponse>();

        if (passkeys)
        {
            group.MapPost("/passkeys/rename", static ([FromBody] SlimPasskeyRenameRequest request,
                    [FromServices] SlimPasskeyHandlers h, CancellationToken ct) => h.RenameAsync(request, ct))
                .WithName("SlimIdentity_RenamePasskey")
                .WithSummary("Rename a passkey of the account.")
                .Produces<SlimStatusResponse>()
                .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
                .Produces<SlimStatusResponse>(StatusCodes.Status404NotFound);

            group.MapPost("/passkeys/remove", static ([FromBody] SlimRemovePasskeyRequest request,
                    [FromServices] SlimSignInMethodHandlers h, CancellationToken ct) => h.RemovePasskeyAsync(request, ct))
                .WithName("SlimIdentity_RemovePasskey")
                .WithSummary("Remove a passkey (password required if the account has one) – never the last sign-in method.")
                .Produces<SlimStatusResponse>()
                .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
                .Produces<SlimStatusResponse>(StatusCodes.Status404NotFound)
                .Produces<SlimStatusResponse>(StatusCodes.Status409Conflict)
                .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);
        }

        if (!externalLogins) return;
        group.MapPost("/external/remove", static ([FromBody] SlimRemoveExternalLoginRequest request,
                [FromServices] SlimSignInMethodHandlers h, CancellationToken ct) => h.RemoveExternalAsync(request, ct))
            .WithName("SlimIdentity_RemoveExternalLogin")
            .WithSummary("Remove a linked external login (password required if the account has one) – never the last sign-in method.")
            .Produces<SlimStatusResponse>()
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .Produces<SlimStatusResponse>(StatusCodes.Status404NotFound)
            .Produces<SlimStatusResponse>(StatusCodes.Status409Conflict)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);
    }

    private static void MapBackChannelLogout(RouteGroupBuilder group)
    {
        group.MapPost("/backchannel-logout/{provider}", static (string provider,
                [FromServices] SlimBackChannelLogoutHandler h, CancellationToken ct) => h.LogoutAsync(provider, ct))
            .WithName("SlimIdentity_BackChannelLogout")
            .WithSummary("OpenID Connect Back-Channel Logout: the identity provider posts a signed logout_token (form); the user's sessions end.")
            .Accepts<IFormCollection>("application/x-www-form-urlencoded")
            .Produces(StatusCodes.Status200OK)
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .Produces<SlimStatusResponse>(StatusCodes.Status404NotFound)
            .WithMetadata(new SlimNoCookieAuthentication())
            .AllowAnonymous();
    }

    private static void MapExternal(RouteGroupBuilder group, SlimIdentityOptions o)
    {
        // literal route first so it never collides with /login/{provider}
        if (o.JwtEnabled)
        {
            group.MapPost("/login/external/exchange", static ([FromBody] SlimExternalExchangeRequest request,
                    [FromServices] SlimExternalLoginHandlers h, CancellationToken ct) => h.ExchangeAsync(request, ct))
                .WithName("SlimIdentity_ExternalExchange")
                .WithSummary("Exchange the one-time code from the external-login redirect (#code=…) and the PKCE verifier for a JWT pair – or a 2FA challenge.")
                .Produces<SlimAuthResponse>()
                .Produces<SlimStatusResponse>(StatusCodes.Status401Unauthorized)
                .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
                .AllowAnonymous();
        }

        group.MapGet("/login/{provider}", static (string provider, [FromQuery] string? returnUrl, [FromQuery] bool? useCookies,
                [FromQuery(Name = "code_challenge")] string? codeChallenge, [FromQuery(Name = "code_challenge_method")] string? codeChallengeMethod,
                [FromQuery] bool? link, [FromServices] SlimExternalLoginHandlers h) =>
                h.ChallengeAsync(provider, returnUrl, useCookies, codeChallenge, codeChallengeMethod, link == true))
            .WithName("SlimIdentity_ExternalChallenge")
            .WithSummary("Start an OAuth / OIDC login (Google, Apple, Entra ID, Keycloak, …). Browser navigation, not fetch.")
            .Produces(StatusCodes.Status302Found)
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .Produces<SlimStatusResponse>(StatusCodes.Status404NotFound)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy)
            .AllowAnonymous();

        group.MapPost("/link/external", static ([FromBody] SlimExternalLinkRequest request,
                [FromServices] SlimExternalLoginHandlers h, CancellationToken ct) => h.LinkAsync(request, ct))
            .WithName("SlimIdentity_ExternalLink")
            .WithSummary("Link the external identity of a link flow (#slim_link_code=…, PKCE verifier, password) to the signed-in account.")
            .Produces<SlimStatusResponse>()
            .Produces<SlimStatusResponse>(StatusCodes.Status400BadRequest)
            .Produces<SlimStatusResponse>(StatusCodes.Status401Unauthorized)
            .Produces<SlimStatusResponse>(StatusCodes.Status403Forbidden)
            .Produces<SlimStatusResponse>(StatusCodes.Status409Conflict)
            .RequireAuthorization(SlimAuthorize)
            .RequireRateLimiting(SlimIdentityDefaults.BruteForcePolicy);

        group.MapGet("/login/{provider}/callback", static (string provider,
                [FromServices] SlimExternalLoginHandlers h, CancellationToken ct) => h.CallbackAsync(provider, ct))
            .WithName("SlimIdentity_ExternalCallback")
            .ExcludeFromDescription()
            .AllowAnonymous();
    }
}
