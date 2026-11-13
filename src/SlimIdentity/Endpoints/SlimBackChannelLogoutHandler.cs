using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using SlimIdentity.Http;
using SlimIdentity.Services;

namespace SlimIdentity.Endpoints;

/// <summary>The providers registered with <c>AddBackChannelLogout</c> (mapping decision).</summary>
internal sealed class SlimBackChannelProviders
{
    public HashSet<string> Names { get; } = new(StringComparer.Ordinal);
}

/// <summary>
/// <c>POST /backchannel-logout/{provider}</c> – OpenID Connect Back-Channel Logout 1.0. The provider posts a signed
/// logout token; every session of the user linked to its <c>sub</c> ends. Not authenticated by a cookie (no CSRF), but
/// by the token: signature, issuer, audience, the back-channel event, no <c>nonce</c>, fresh <c>iat</c>, single use.
/// </summary>
internal sealed class SlimBackChannelLogoutHandler(
    IOptionsMonitor<SlimBackChannelLogoutOptions> providerOptions,
    SlimBackChannelProviders providers,
    SlimBackChannelConfigurations configurations,
    SlimSharedStateAccess sharedState,
    IServiceProvider services,
    SlimAuthManager authManager,
    IOptions<SlimIdentityOptions> options,
    TimeProvider time,
    IHttpContextAccessor httpContextAccessor,
    ILogger<SlimBackChannelLogoutHandler> logger)
{
    private const string LogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    /// <summary>How old a logout token may be: the provider sends it right after the logout.</summary>
    internal static readonly TimeSpan MaxTokenAge = TimeSpan.FromMinutes(5);

    public async Task<IResult> LogoutAsync(string provider, CancellationToken ct)
    {
        if (!providers.Names.Contains(provider))
            return SlimResults.Status(SlimErrorCodes.UnknownProvider, $"Provider '{provider}' has no back-channel logout.", StatusCodes.Status404NotFound);

        var request = httpContextAccessor.HttpContext!.Request;
        if (!request.HasFormContentType) return Invalid(provider, "expected application/x-www-form-urlencoded");
        var form = await request.ReadFormAsync(ct);
        var token = form["logout_token"].ToString();
        if (token.Length is 0 or > 16 * 1024) return Invalid(provider, "logout_token missing");

        var o = providerOptions.Get(provider);
        OpenIdConnectConfiguration configuration;
        try
        {
            configuration = await configurations.GetAsync(provider, o, ct);
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or HttpRequestException)
        {
            Log.BackChannelMetadataFailed(logger, ex, provider);
            return SlimResults.Problem(StatusCodes.Status503ServiceUnavailable, SlimErrorCodes.ServiceUnavailable,
                "The provider metadata could not be loaded.");   // retried by the provider
        }

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = configuration.Issuer,
            ValidAudience = o.ClientId,
            IssuerSigningKeys = configuration.SigningKeys,
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            RequireExpirationTime = false,     // exp is optional in the specification – iat is checked below
            ClockSkew = options.Value.Tokens.ClockSkew,
        });
        if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt) return Invalid(provider, "invalid signature, issuer or audience");

        // a logout token, not an ID token: the back-channel event, never a nonce (OIDC Back-Channel Logout 1.0, 2.6)
        if (!HasLogoutEvent(jwt) || jwt.TryGetPayloadValue<object>("nonce", out _)) return Invalid(provider, "not a logout token");

        // fresh only – a replayed token would end sessions started after the logout
        var now = time.GetUtcNow();
        var skew = options.Value.Tokens.ClockSkew;
        if (!jwt.TryGetPayloadValue<long>("iat", out var iat)) return Invalid(provider, "iat missing");
        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(iat);
        if (issuedAt > now + skew || now - issuedAt > MaxTokenAge + skew) return Invalid(provider, "iat outside the accepted window");
        // jti is required (OIDC Back-Channel Logout §2.4) – without it the token could be replayed within its lifetime
        if (!jwt.TryGetPayloadValue<string>("jti", out var jti) || string.IsNullOrEmpty(jti)) return Invalid(provider, "jti missing");
        if (!await sharedState.TryConsumeAsync(SlimSharedStateAccess.BackChannelToken, $"{provider}:{jti}", issuedAt + MaxTokenAge + skew, ct)) return Invalid(provider, "replayed");

        // sid-only tokens would need the provider's session id per local session – not tracked; providers send sub
        if (!jwt.TryGetPayloadValue<string>("sub", out var sub) || string.IsNullOrEmpty(sub)) return Invalid(provider, "sub missing");

        var user = await services.GetRequiredService<ISlimExternalLoginStore>().FindByExternalLoginAsync(provider, sub, ct);
        if (user is not null)
        {
            await authManager.SignOutEverywhereAsync(user, ct);
            Log.BackChannelLogout(logger, provider, user.Id);
        }
        return Results.Ok();   // also for an unknown sub: nothing to do here (specification: success)
    }

    private static bool HasLogoutEvent(JsonWebToken jwt)
    {
        if (!jwt.TryGetPayloadValue<JsonElement>("events", out var events) || events.ValueKind != JsonValueKind.Object) return false;
        return events.TryGetProperty(LogoutEvent, out var value) && value.ValueKind == JsonValueKind.Object;
    }

    private IResult Invalid(string provider, string reason)
    {
        Log.BackChannelTokenRejected(logger, provider, reason);
        return SlimResults.BadRequest(SlimErrorCodes.InvalidRequest, "The logout token was rejected.");
    }
}

/// <summary>Issuer and signing keys per provider: fixed, or from the discovery document (cached and refreshed).</summary>
internal sealed class SlimBackChannelConfigurations
{
    private readonly ConcurrentDictionary<string, ConfigurationManager<OpenIdConnectConfiguration>> _managers = new(StringComparer.Ordinal);

    public Task<OpenIdConnectConfiguration> GetAsync(string provider, SlimBackChannelLogoutOptions o, CancellationToken ct)
    {
        if (o.Configuration is { } fixedConfiguration) return Task.FromResult(fixedConfiguration);
        var manager = _managers.GetOrAdd(provider, _ => new ConfigurationManager<OpenIdConnectConfiguration>(
            o.MetadataAddress!, new OpenIdConnectConfigurationRetriever(), new HttpDocumentRetriever { RequireHttps = o.RequireHttpsMetadata }));
        return manager.GetConfigurationAsync(ct);
    }
}
