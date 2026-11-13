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
    SlimSignInFlow flow,
    SlimAccountHandlers account,
    SlimCredentialService credentials,
    SlimAuthManager authManager,
    SlimWorkflowTokens workflow,
    SlimHookRunner hooks,
    SlimMetrics metrics,
    SlimSharedStateAccess sharedState,
    IServiceProvider services,
    IOptions<SlimIdentityOptions> options,
    IHttpContextAccessor httpContextAccessor,
    ILogger<SlimExternalLoginHandlers> logger)
{
    private const string ItemProvider = "slim.provider";
    private const string ItemReturnUrl = "slim.returnUrl";
    private const string ItemUseCookies = "slim.useCookies";
    private const string ItemCodeChallenge = "slim.codeChallenge";
    private const string ItemLink = "slim.link";

    private SlimIdentityOptions O => options.Value;
    private HttpContext Http => httpContextAccessor.HttpContext!;

    // ------------------------------------------------------------------ GET /login/{provider}

    public async Task<IResult> ChallengeAsync(string provider, string? returnUrl, bool? useCookies, string? codeChallenge, string? codeChallengeMethod, bool link = false)
    {
        var scheme = await FindRemoteSchemeAsync(provider);
        if (scheme is null) return SlimResults.Status(SlimErrorCodes.UnknownProvider, $"Provider '{provider}' is not configured.", StatusCodes.Status404NotFound);
        // the link flow signs nobody in – it hands a link code to the client that started it (PKCE), whatever its mode
        var cookies = false;
        if (!link && !SlimModes.TryResolve(O, useCookies, out cookies, out var modeError)) return modeError!;

        var target = ValidateReturnUrl(returnUrl);
        if (target is null) return SlimResults.BadRequest(SlimErrorCodes.InvalidReturnUrl, "The returnUrl is not allowed.");

        // Bearer clients receive a one-time code in the redirect – an app that intercepts the redirect (custom URI
        // scheme, history, logs) must not be able to redeem it. PKCE (RFC 7636, S256) binds it to this client.
        if (!cookies || link)
        {
            if (string.IsNullOrEmpty(codeChallenge))
                return SlimResults.BadRequest(SlimErrorCodes.CodeChallengeRequired, "Bearer clients must send a PKCE code_challenge (S256).");
            if (!string.Equals(codeChallengeMethod ?? "S256", "S256", StringComparison.Ordinal) || !IsS256Challenge(codeChallenge))
                return SlimResults.BadRequest(SlimErrorCodes.InvalidCodeChallenge, "code_challenge must be BASE64URL(SHA256(code_verifier)) with code_challenge_method=S256.");
        }

        var properties = new AuthenticationProperties
        {
            RedirectUri = $"{Http.Request.PathBase}{O.RoutePrefix.TrimEnd('/')}/login/{Uri.EscapeDataString(scheme.Name)}/callback",
        };
        properties.Items[ItemProvider] = scheme.Name;
        properties.Items[ItemReturnUrl] = target;
        properties.Items[ItemUseCookies] = cookies ? "true" : "false";
        if (!cookies || link) properties.Items[ItemCodeChallenge] = codeChallenge;
        if (link) properties.Items[ItemLink] = "true";

        return Results.Challenge(properties, [scheme.Name]);
    }

    // ------------------------------------------------------------------ GET /login/{provider}/callback

    public async Task<IResult> CallbackAsync(string provider, CancellationToken ct)
    {
        var external = await Http.AuthenticateAsync(SlimIdentityDefaults.ExternalScheme);
        await Http.SignOutAsync(SlimIdentityDefaults.ExternalScheme); // the temporary cookie is never reused

        if (!external.Succeeded || external.Principal is null || external.Properties is null)
            return SlimResults.Status(SlimErrorCodes.ExternalLoginFailed, "External authentication failed.", StatusCodes.Status401Unauthorized);

        var items = external.Properties.Items;
        var returnUrl = items.TryGetValue(ItemReturnUrl, out var r) && r is not null ? r : O.ExternalLogin.DefaultReturnUrl;
        if (!items.TryGetValue(ItemProvider, out var storedProvider) || !string.Equals(storedProvider, provider, StringComparison.Ordinal))
            return Redirect(returnUrl, "slim_error", SlimErrorCodes.ProviderMismatch);
        var cookies = items.TryGetValue(ItemUseCookies, out var c) && c == "true";
        var codeChallenge = items.TryGetValue(ItemCodeChallenge, out var cc) ? cc : null;
        if (!cookies && string.IsNullOrEmpty(codeChallenge)) return Redirect(returnUrl, "slim_error", SlimErrorCodes.CodeChallengeRequired);

        var principal = external.Principal;
        var providerKey = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? principal.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(providerKey)) return Redirect(returnUrl, "slim_error", SlimErrorCodes.MissingProviderKey);

        // link flow: nobody is signed in here – the client that started the flow redeems the code with its verifier,
        // its session and its password (POST /link/external)
        if (items.TryGetValue(ItemLink, out var linkFlag) && linkFlag == "true")
        {
            if (string.IsNullOrEmpty(codeChallenge)) return Redirect(returnUrl, "slim_error", SlimErrorCodes.CodeChallengeRequired);
            var linkCode = workflow.Protect(SlimWorkflowTokens.ExternalLinkPurpose,
                new SlimExternalLinkPayload(provider, providerKey, Convert.ToHexString(RandomNumberGenerator.GetBytes(16)), codeChallenge),
                SlimIdentityDefaults.ExternalExchangeCodeLifetime);
            return RedirectWithFragment(returnUrl, new() { ["slim_link_code"] = linkCode });
        }

        var emailClaim = principal.FindFirst(ClaimTypes.Email)?.Value ?? principal.FindFirst("email")?.Value;
        var email = SlimEmailAddress.Normalize(
            emailClaim
            ?? principal.FindFirst("preferred_username")?.Value
            ?? principal.FindFirst(ClaimTypes.Upn)?.Value);
        // email_verified speaks about the email claim only – never about a user name or UPN that merely looks like an address
        var emailVerified = IsEmailVerified(principal, provider, fromEmailClaim: !string.IsNullOrEmpty(emailClaim));

        var user = await externalStore.FindByExternalLoginAsync(provider, providerKey, ct);
        if (user is null)
        {
            if (!SlimRegistrationService.IsValidEmail(email)) return Redirect(returnUrl, "slim_error", SlimErrorCodes.EmailRequired);

            var existing = await store.FindByEmailAsync(email, ct);
            if (existing is not null)
            {
                // Never join an account that has an own password automatically: whoever set it may not own the mailbox
                // – a click on the verification link proves the mailbox, not who registered (pre-account hijacking).
                // The user signs in and links the provider instead. Unconfirmed accounts are taken over below.
                var joinsForeignPassword = existing.EmailConfirmed && !string.IsNullOrEmpty(existing.PasswordHash);
                if (!(O.ExternalLogin.AutoLinkVerifiedEmails && emailVerified) || joinsForeignPassword)
                {
                    Log.ExternalLoginConflict(logger, provider, existing.Id);
                    metrics.ExternalLogin(provider, "conflict");
                    return Redirect(returnUrl, "slim_error", SlimErrorCodes.AccountConflict); // 409 semantics
                }
                if (!existing.EmailConfirmed)
                {
                    // Pre-account hijacking: nobody has proven ownership of this address yet – whoever registered it
                    // (possibly an attacker, with an own password or an own external login) must not share the account
                    // with the verified owner. Remove the password, every linked identity and every session; the owner
                    // can set a password later via reset.
                    var claimed = await store.TryWriteSecurityStateAsync(existing, u =>
                    {
                        u.EmailConfirmed = true;
                        u.PasswordHash = string.Empty;
                        u.PasswordChangeRequired = false;   // the start password is gone – nothing left to change
                        u.SecurityStamp = SlimUser.NewSecurityStamp();
                        u.TwoFactorEnabled = false;   // a 2FA set up by the registrant must not lock out the owner
                    }, ct);
                    if (!claimed)
                    {
                        // the account changed meanwhile (confirmed, password reset …): the next attempt follows the rules above
                        metrics.ExternalLogin(provider, "conflict");
                        return Redirect(returnUrl, "slim_error", SlimErrorCodes.AccountConflict);
                    }
                    await externalStore.RemoveExternalLoginsAsync(existing.Id, ct);
                    if (services.GetService<ISlimPasskeySignInMethods>() is { } passkeys)
                        await passkeys.RemoveAllAsync(existing.Id, ct);
                    // guesses against the removed password must not lock the owner out of a password set later
                    await services.GetRequiredService<SlimCredentialService>().ResetAttemptsAsync(existing, SlimAttemptFactor.Password, ct);
                    await authManager.RevokeSessionsAsync(existing.Id, null, ct);
                    if (services.GetService<ISlimTwoFactorStore>() is { } twoFactorStore)
                    {
                        await twoFactorStore.SetTotpSecretAsync(existing, string.Empty, ct);
                        await twoFactorStore.StoreRecoveryCodesAsync(existing, [], ct);
                    }
                    Log.UnverifiedAccountClaimed(logger, provider, existing.Id);
                }
                await externalStore.LinkExternalLoginAsync(existing.Id, provider, providerKey, ct);
                Log.ExternalLoginLinked(logger, provider, existing.Id);
                await hooks.RaiseAsync(SlimEventTypes.ExternalLoginLinked, existing.Id, provider, ct: ct);
                metrics.ExternalLogin(provider, "linked");
                user = existing;
            }
            else
            {
                if (!O.ExternalLogin.AllowAutoRegistration) return Redirect(returnUrl, "slim_error", SlimErrorCodes.RegistrationDisabled);

                // An account is only created for an address the provider has verified: otherwise anyone whose provider
                // account merely *claims* an address would own an account for it (pre-account hijacking).
                if (!emailVerified)
                {
                    metrics.ExternalLogin(provider, "rejected");
                    return Redirect(returnUrl, "slim_error", SlimErrorCodes.EmailNotVerified);
                }

                if (await hooks.CheckRegistrationAsync(email, provider, ct) is { } veto)
                {
                    metrics.ExternalLogin(provider, "rejected");
                    return Redirect(returnUrl, "slim_error", veto.Error);
                }

                user = await store.CreateAsync(new SlimNewUser { Email = email, Provider = provider }, ct);
                if (user is null)
                {
                    // the address was registered concurrently – never link silently; the next attempt follows the rules above
                    metrics.ExternalLogin(provider, "conflict");
                    return Redirect(returnUrl, "slim_error", SlimErrorCodes.AccountConflict);
                }
                if (!user.EmailConfirmed)
                    await store.WriteSecurityStateAsync(user, u => u.EmailConfirmed = true, ct);
                await externalStore.LinkExternalLoginAsync(user.Id, provider, providerKey, ct);
                Log.ExternalUserCreated(logger, user.Id, provider);
                await hooks.RaiseAsync(SlimEventTypes.UserCreated, user.Id, provider, "external", ct: ct);
                metrics.ExternalLogin(provider, "created");
            }
        }

        // the provider proved the account – a lockout of the password or the second factor does not apply. The steps
        // that follow (second factor, own password) are taken in the sign-in flow; bearer clients start it at the exchange.
        var decision = SlimSignInChain.Evaluate(user, SlimSignInProofs.None, O);
        var rejection = decision.Refusal ?? (decision.Next == SlimSignInActions.VerifyEmail ? SlimErrorCodes.EmailNotConfirmed : null);
        if (rejection is not null)
        {
            metrics.ExternalLogin(provider, "rejected");
            return Redirect(returnUrl, "slim_error", rejection);
        }
        metrics.ExternalLogin(provider, "success");

        if (!cookies)
        {
            // Bearer clients: never tokens in URLs. A short-lived, single-use, PKCE-bound code in the fragment (never
            // sent to servers, logs or referrers); the steps of the sign-in, if any, follow the exchange.
            var code = workflow.Protect(SlimWorkflowTokens.ExternalExchangePurpose,
                new SlimExchangePayload(user.Id, user.SecurityStamp, provider, Convert.ToHexString(RandomNumberGenerator.GetBytes(16)), codeChallenge!),
                SlimIdentityDefaults.ExternalExchangeCodeLifetime);

            return RedirectWithFragment(returnUrl, new() { ["code"] = code });
        }

        // the browser may carry a "remember this device" cookie from an earlier second factor
        var result = await flow.StartAsync(user, cookies: true, rememberMe: false, SlimAuthManager.MethodExternal, SlimSignInProofs.None,
            checkRememberedDevice: true, rememberToken: null, refuseLockedSecondFactor: false, ct);
        // the flow token stands for the passed first factor – fragment only, like the exchange code
        if (result.ActionRequired is { } steps)
            return RedirectWithFragment(returnUrl, new()
            {
                ["slim_status"] = SlimErrorCodes.ActionRequired,
                ["flowToken"] = steps.FlowToken,
            });
        return result.Succeeded ? Results.Redirect(returnUrl) : Redirect(returnUrl, "slim_error", result.Error ?? SlimErrorCodes.SignInFailed);
    }

    // ------------------------------------------------------------------ POST /login/external/exchange

    public async Task<IResult> ExchangeAsync(SlimExternalExchangeRequest? request, CancellationToken ct)
    {
        if (!workflow.TryUnprotect<SlimExchangePayload>(SlimWorkflowTokens.ExternalExchangePurpose, request?.Code, out var payload, out var expiresAt))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        // PKCE first: whoever intercepted the code but lacks the verifier must not even burn it for the real client
        if (!VerifiesChallenge(request!.CodeVerifier, payload.CodeChallenge))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        // consume – a code that was already exchanged is rejected
        if (!await sharedState.TryConsumeAsync(SlimSharedStateAccess.ExchangeCode, payload.Nonce, expiresAt, ct))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        var user = await store.FindByIdAsync(payload.Uid, ct);
        if (user is null || !SlimUser.IsSameSecurityState(user.SecurityStamp, payload.Stamp))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        if (!SlimModes.TryResolve(O, false, out _, out var modeError)) return modeError!;

        // the steps that follow exactly as at /auth/login: a remembered device (token in the body) passes the second factor
        var result = await flow.StartAsync(user, cookies: false, rememberMe: false, SlimAuthManager.MethodExternal, SlimSignInProofs.None,
            checkRememberedDevice: true, request.TwoFactorRememberToken, refuseLockedSecondFactor: false, ct);
        return flow.ToHttpResult(result, user);
    }

    // ------------------------------------------------------------------ POST /link/external

    public async Task<IResult> LinkAsync(SlimExternalLinkRequest? request, CancellationToken ct)
    {
        if (!workflow.TryUnprotect<SlimExternalLinkPayload>(SlimWorkflowTokens.ExternalLinkPurpose, request?.Code, out var payload, out var expiresAt)
            || !VerifiesChallenge(request!.CodeVerifier, payload.CodeChallenge))
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        var (user, error) = await account.LoadCurrentUserAsync(forbidImpersonation: true, ct);
        if (user is null) return error!;

        // like a second factor: only on an account whose mailbox was proven (a registrant must not plant an identity)
        if (O.Email.Enabled && !user.EmailConfirmed)
            return SlimResults.Status(SlimErrorCodes.EmailNotConfirmed, "Confirm your e-mail address before linking an external login.", StatusCodes.Status403Forbidden);

        // a stolen session alone must not add a permanent way in: the password, or without one a fresh sign-in
        if (await credentials.ConfirmPasswordAsync(user, request.Password, Http, ct) is { } failure)
            return failure;

        if (!await sharedState.TryConsumeAsync(SlimSharedStateAccess.LinkCode, payload.Nonce, expiresAt, ct))   // after the password: a typo does not burn the code
            return SlimResults.InvalidToken(StatusCodes.Status401Unauthorized);

        var owner = await externalStore.FindByExternalLoginAsync(payload.Provider, payload.ProviderKey, ct);
        if (owner is not null)
        {
            return string.Equals(owner.Id, user.Id, StringComparison.Ordinal)
                ? SlimResults.Status("external_login_linked")
                : SlimResults.Status(SlimErrorCodes.ExternalLoginTaken, "This external account is linked to another account.", StatusCodes.Status409Conflict);
        }

        await externalStore.LinkExternalLoginAsync(user.Id, payload.Provider, payload.ProviderKey, ct);
        Log.ExternalLoginLinked(logger, payload.Provider, user.Id);
        await hooks.RaiseAsync(SlimEventTypes.ExternalLoginLinked, user.Id, payload.Provider, "link_flow", ct: ct);
        metrics.ExternalLogin(payload.Provider, "linked");
        return SlimResults.Status("external_login_linked");
    }

    // ------------------------------------------------------------------ helpers

    private async Task<AuthenticationScheme?> FindRemoteSchemeAsync(string provider)
    {
        if (string.IsNullOrWhiteSpace(provider) || SlimIdentityDefaults.IsOwnScheme(provider)) return null;
        var scheme = await schemes.GetSchemeAsync(provider);
        // only remote handlers (OAuth / OIDC / WS-Fed / SAML) qualify
        return scheme is not null && typeof(IAuthenticationRequestHandler).IsAssignableFrom(scheme.HandlerType) ? scheme : null;
    }

    private bool IsEmailVerified(ClaimsPrincipal principal, string provider, bool fromEmailClaim)
    {
        var claim = principal.FindFirst("email_verified")?.Value;
        if (fromEmailClaim && string.Equals(claim, "true", StringComparison.OrdinalIgnoreCase)) return true;
        return O.ExternalLogin.TrustedEmailProviders.Contains(provider, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Open-redirect protection: local paths or trusted origins only.</summary>
    /// <summary>
    /// A failed provider round trip (see <see cref="SlimRemoteAuthenticationExtensions.UseSlimErrorRedirects{TOptions}"/>):
    /// back to the returnUrl of the sign-in – it travels in the handler's protected state and is validated again – or,
    /// when no sign-in can be recognized, to <c>ExternalLogin.DefaultReturnUrl</c>.
    /// </summary>
    internal static Task RedirectRemoteFailureAsync(HttpContext http, AuthenticationProperties? properties, string provider, string error) =>
        http.RequestServices.GetRequiredService<SlimExternalLoginHandlers>().RedirectRemoteFailureAsync(properties, provider, error);

    private async Task RedirectRemoteFailureAsync(AuthenticationProperties? properties, string provider, string error)
    {
        var started = properties?.Items.TryGetValue(ItemReturnUrl, out var url) == true ? url : null;
        var target = ValidateReturnUrl(started) ?? ValidateReturnUrl(null) ?? "/";
        Log.ExternalLoginRemoteFailure(logger, provider, error);
        metrics.ExternalLogin(provider, error == SlimErrorCodes.AccessDenied ? "cancelled" : "failed");
        await Redirect(target, "slim_error", error).ExecuteAsync(Http);
    }

    private string? ValidateReturnUrl(string? returnUrl) =>
        SlimReturnUrl.Validate(returnUrl, O, origin => SlimLinks.IsTrustedOrigin(Http, origin));

    // errors are no secrets – query, readable by server-rendered pages too
    private static IResult Redirect(string returnUrl, string key, string value) =>
        Results.Redirect(QueryHelpers.AddQueryString(returnUrl, key, value));

    /// <summary>Secrets go into the fragment: browsers never send it to a server, so it is not in logs or referrers.</summary>
    private static IResult RedirectWithFragment(string returnUrl, Dictionary<string, string> values)
    {
        var withoutFragment = returnUrl.Split('#', 2)[0];
        var fragment = string.Join('&', values.Select(v => $"{Uri.EscapeDataString(v.Key)}={Uri.EscapeDataString(v.Value)}"));
        return Results.Redirect($"{withoutFragment}#{fragment}");
    }

    /// <summary>A well-formed S256 challenge: 43 base64url characters (a SHA-256 hash).</summary>
    private static bool IsS256Challenge(string challenge) =>
        challenge.Length == 43 && challenge.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_');

    private static bool VerifiesChallenge(string? verifier, string challenge)
    {
        // RFC 7636: 43–128 characters of [A-Z a-z 0-9 - . _ ~]
        if (verifier is null || verifier.Length is < 43 or > 128 || !verifier.All(ch => char.IsAsciiLetterOrDigit(ch) || ch is '-' or '.' or '_' or '~'))
            return false;
        var computed = System.Buffers.Text.Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return SlimHashing.FixedTimeEquals(computed, challenge);
    }
}
