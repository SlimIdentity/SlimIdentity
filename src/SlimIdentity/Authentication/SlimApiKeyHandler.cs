using SlimIdentity;
using SlimIdentity.Security;
using System.Text.Encodings.Web;

namespace SlimIdentity.Authentication;

/// <summary>Authentication handler for <c>X-API-Key</c> machine-to-machine access.</summary>
internal sealed class SlimApiKeyHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory loggerFactory,
    UrlEncoder encoder,
    ISlimApiKeyStore store)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(SlimIdentityDefaults.ApiKeyHeaderName, out var values))
            return AuthenticateResult.NoResult();

        var key = values.ToString().Trim();
        if (key.Length is 0 or > 512)
            return AuthenticateResult.Fail("Invalid API key.");

        var claims = await store.ValidateApiKeyAsync(SlimApiKeys.Hash(key), Context.RequestAborted);
        if (claims is null)
            return AuthenticateResult.Fail("Invalid API key.");

        var identity = new ClaimsIdentity(claims, Scheme.Name, SlimClaimTypes.UserId, SlimClaimTypes.Role);
        if (!identity.HasClaim(c => c.Type == SlimClaimTypes.AuthenticationMethod))
            identity.AddClaim(new Claim(SlimClaimTypes.AuthenticationMethod, "api_key"));

        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = "ApiKey";
        return Task.CompletedTask;
    }
}

/// <summary>Marker singleton: signals the policy scheme that an API-key store is registered.</summary>
internal sealed class SlimApiKeyMarker { }
