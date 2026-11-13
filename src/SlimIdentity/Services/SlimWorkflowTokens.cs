using System.Text.Json.Serialization.Metadata;
using Microsoft.AspNetCore.DataProtection;
using SlimIdentity.Contracts;

namespace SlimIdentity.Services;

/// <summary>
/// Stateless, signed + encrypted workflow tokens via <see cref="IDataProtector"/> (no token table).
/// Each token carries an expiry and is bound to the user's security stamp where relevant. The expiry is part of the
/// protected payload and checked against the injected <see cref="TimeProvider"/> – not the system clock the
/// time-limited protector would use – so every expiry follows the same clock (and is testable).
/// </summary>
internal sealed class SlimWorkflowTokens(
    IDataProtectionProvider provider,
    TimeProvider time,
    IHttpContextAccessor httpContextAccessor,
    IServiceProvider services,
    ILogger<SlimWorkflowTokens> logger)
{
    /// <summary>Format version of the protected plaintext: <c>v2.{expires unix ms}.{json}</c>.</summary>
    private const string FormatPrefix = "v2.";

    public const string LinkPurpose = "SlimIdentity.Link.v1";
    public const string SignInFlowPurpose = "SlimIdentity.SignInFlow.v1";
    public const string TwoFactorSetupPurpose = "SlimIdentity.TwoFactorSetup.v1";
    public const string ExternalExchangePurpose = "SlimIdentity.ExternalExchange.v1";
    public const string ExternalLinkPurpose = "SlimIdentity.ExternalLink.v1";
    public const string RefreshTokenPurpose = "SlimIdentity.RefreshToken.v1";
    public const string EmailChangePurpose = "SlimIdentity.EmailChange.v1";
    public const string RememberDevicePurpose = "SlimIdentity.TwoFactorRememberDevice.v1";

    // AOT-safe: metadata comes from the source-generated context, never from reflection
    private static JsonTypeInfo<T> TypeInfo<T>() =>
        (JsonTypeInfo<T>?)SlimJsonContext.Default.GetTypeInfo(typeof(T))
        ?? throw new InvalidOperationException($"SlimIdentity: {typeof(T).Name} is missing in SlimJsonContext.");

    /// <summary>
    /// With <c>UseTenantKey</c>, the tenant of the request is part of the purpose: a token issued in one tenant does not
    /// decrypt in another, whatever its payload. Outside a request or a tenant the plain purpose applies.
    /// </summary>
    private IDataProtector Protector(string purpose) =>
        services.GetService<Authentication.SlimTenantBinding>() is { } binding
        && httpContextAccessor.HttpContext is { } http
        && binding.KeyOf(http) is { } tenant
            ? provider.CreateProtector(purpose, "SlimIdentity.Tenant:" + tenant)
            : provider.CreateProtector(purpose);

    /// <summary>Replaces <c>{token}</c> in the template, or returns the raw token if no template is configured.</summary>
    public static string BuildLink(string? template, string token) =>
        template is null ? token : template.Replace("{token}", Uri.EscapeDataString(token), StringComparison.Ordinal);

    public string Protect<T>(string purpose, T payload, TimeSpan lifetime) => Protect(purpose, payload, lifetime, TypeInfo<T>());

    /// <summary>For payloads of other SlimIdentity packages (their own source-generated context).</summary>
    public string Protect<T>(string purpose, T payload, TimeSpan lifetime, JsonTypeInfo<T> typeInfo)
    {
        var expires = (time.GetUtcNow() + lifetime).ToUnixTimeMilliseconds();
        return Protector(purpose).Protect(
            string.Concat(FormatPrefix, expires.ToString(CultureInfo.InvariantCulture), ".", JsonSerializer.Serialize(payload, typeInfo)));
    }

    public bool TryUnprotect<T>(string purpose, string? token, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out T? payload) where T : class =>
        TryUnprotect(purpose, token, TypeInfo<T>(), out payload, out _);

    public bool TryUnprotect<T>(string purpose, string? token, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out T? payload, out DateTimeOffset expiresAt) where T : class =>
        TryUnprotect(purpose, token, TypeInfo<T>(), out payload, out expiresAt);

    public bool TryUnprotect<T>(string purpose, string? token, JsonTypeInfo<T> typeInfo, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out T? payload) where T : class =>
        TryUnprotect(purpose, token, typeInfo, out payload, out _);

    private bool TryUnprotect<T>(string purpose, string? token, JsonTypeInfo<T> typeInfo, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out T? payload, out DateTimeOffset expiresAt) where T : class
    {
        payload = null;
        expiresAt = default;
        if (string.IsNullOrWhiteSpace(token) || token.Length > 8192) return false;
        try
        {
            var plaintext = Protector(purpose).Unprotect(token);
            var separator = plaintext.IndexOf('.', FormatPrefix.Length);
            if (!plaintext.StartsWith(FormatPrefix, StringComparison.Ordinal) || separator < 0
                || !long.TryParse(plaintext.AsSpan(FormatPrefix.Length, separator - FormatPrefix.Length), NumberStyles.None, CultureInfo.InvariantCulture, out var expires))
                throw new FormatException("Unknown workflow token format.");

            expiresAt = DateTimeOffset.FromUnixTimeMilliseconds(expires);
            if (time.GetUtcNow() >= expiresAt)
            {
                Log.TokenExpired(logger, purpose);
                expiresAt = default;
                return false;
            }

            payload = JsonSerializer.Deserialize(plaintext.AsSpan(separator + 1), typeInfo);
            return payload is not null;
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or FormatException)
        {
            Log.TokenRejected(logger, ex, purpose);
            return false;
        }
    }
}


/// <summary>
/// A sign-in between its first factor and the session. <c>Proofs</c> and <c>Amr</c> (method of the session) say what is
/// proven so far; <c>FlowId</c> completes at most one session; <c>StartedAt</c> (unix milliseconds) bounds the whole flow.
/// The open second-factor challenge: <c>Method</c>, <c>CodeHash</c> of an e-mail code and <c>IssuedAt</c> (unix
/// milliseconds, single use via <c>ISlimTwoFactorStore.TryMarkChallengeUsedAsync</c> and <c>TryMarkCodeUsedAsync</c>).
/// A registration before its account has no <c>Uid</c> and <c>Stamp</c>, but the <c>Email</c> it registers.
/// <c>Link</c>: the kind of link (<see cref="SlimLinkPayload"/>) that started a flow ending in <c>set_credential</c> for an
/// existing account.
/// </summary>
internal sealed record SlimFlowPayload(string Uid, string Stamp, string FlowId, long StartedAt, SlimSignInProofs Proofs, string Amr,
    bool UseCookies, bool RememberMe, bool RememberDevice = false, string? Method = null, string? CodeHash = null, long IssuedAt = 0,
    string? Email = null, string? Link = null)
{
    /// <summary>A registration whose account does not exist yet.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsRegistration => Email is not null;
}
/// <summary>
/// The link of a mail or of an administrator: starts or continues a flow (<c>FlowId</c>). A <see cref="Registration"/>
/// carries the address, the links of an existing account (<see cref="Reset"/>, <see cref="AdminReset"/>,
/// <see cref="Invitation"/>) its <c>Uid</c> and <c>Stamp</c> – the next security change ends them. An invitation also
/// carries the invited <c>Email</c>.
/// </summary>
internal sealed record SlimLinkPayload(string Kind, string FlowId, string? Email = null, string? Uid = null, string? Stamp = null)
{
    /// <summary>A registration: proves the mailbox like the code of the same mail.</summary>
    public const string Registration = "registration";
    /// <summary>A reset the owner requested: the mail proves the mailbox.</summary>
    public const string Reset = "reset";
    /// <summary>A reset an administrator handed over: proves no mailbox.</summary>
    public const string AdminReset = "admin_reset";
    /// <summary>An invitation to an account without a way to sign in yet: delivered to its mailbox, proves it.</summary>
    public const string Invitation = "invitation";
}
/// <summary>"Remember this device" for 2FA; <c>ExpiresAt</c> (unix seconds) is checked against the injected clock.</summary>
internal sealed record SlimRememberDevicePayload(string Uid, string Stamp, long ExpiresAt);
internal sealed record SlimEmailChangePayload(string Uid, string OldEmail, string NewEmail, string Stamp);
internal sealed record SlimTwoFactorSetupPayload(string Uid, string Secret, string Stamp);
/// <summary>An external identity to be linked to the signed-in account; PKCE-bound like the exchange code.</summary>
internal sealed record SlimExternalLinkPayload(string Provider, string ProviderKey, string Nonce, string CodeChallenge);
/// <summary><c>CodeChallenge</c>: PKCE S256 challenge – the code is redeemable only with the matching verifier.</summary>
internal sealed record SlimExchangePayload(string Uid, string Stamp, string Provider, string Nonce, string CodeChallenge);
/// <summary><c>AuthTime</c> = unix seconds of the original sign-in (absolute lifetime), <c>Sid</c> = server-side session (optional).</summary>
internal sealed record SlimRefreshPayload(string Uid, string Stamp, string Amr, string Nonce, long AuthTime, string? Sid);
