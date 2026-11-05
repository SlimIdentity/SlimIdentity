using System.Text.Json.Serialization.Metadata;
using Microsoft.AspNetCore.DataProtection;
using SlimIdentity.Contracts;

namespace SlimIdentity.Services;

/// <summary>
/// Stateless, signed + encrypted workflow tokens via <see cref="IDataProtector"/> (no token table).
/// Each token carries an expiry and is bound to the user's security stamp where relevant.
/// </summary>
internal sealed class SlimWorkflowTokens(IDataProtectionProvider provider, ILogger<SlimWorkflowTokens> logger)
{
    public const string EmailVerificationPurpose = "SlimIdentity.EmailVerification.v1";
    public const string PasswordResetPurpose = "SlimIdentity.PasswordReset.v1";
    public const string PreAuthPurpose = "SlimIdentity.PreAuth.v1";
    public const string TwoFactorSetupPurpose = "SlimIdentity.TwoFactorSetup.v1";
    public const string ExternalExchangePurpose = "SlimIdentity.ExternalExchange.v1";
    public const string RefreshTokenPurpose = "SlimIdentity.RefreshToken.v1";
    public const string InvitationPurpose = "SlimIdentity.Invitation.v1";

    // AOT-safe: metadata comes from the source-generated context, never from reflection
    private static JsonTypeInfo<T> TypeInfo<T>() =>
        (JsonTypeInfo<T>?)SlimJsonContext.Default.GetTypeInfo(typeof(T))
        ?? throw new InvalidOperationException($"SlimIdentity: {typeof(T).Name} is missing in SlimJsonContext.");

    /// <summary>Replaces <c>{token}</c> in the template, or returns the raw token if no template is configured.</summary>
    public static string BuildLink(string? template, string token) =>
        template is null ? token : template.Replace("{token}", Uri.EscapeDataString(token), StringComparison.Ordinal);

    public string Protect<T>(string purpose, T payload, TimeSpan lifetime)
    {
        var protector = provider.CreateProtector(purpose).ToTimeLimitedDataProtector();
        return protector.Protect(JsonSerializer.Serialize(payload, TypeInfo<T>()), lifetime);
    }

    public bool TryUnprotect<T>(string purpose, string? token, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out T? payload) where T : class =>
        TryUnprotect(purpose, token, out payload, out _);

    public bool TryUnprotect<T>(string purpose, string? token, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out T? payload, out DateTimeOffset expiresAt) where T : class
    {
        payload = null;
        expiresAt = default;
        if (string.IsNullOrWhiteSpace(token) || token.Length > 8192) return false;
        try
        {
            var protector = provider.CreateProtector(purpose).ToTimeLimitedDataProtector();
            var json = protector.Unprotect(token, out expiresAt);
            payload = JsonSerializer.Deserialize(json, TypeInfo<T>());
            return payload is not null;
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException or FormatException)
        {
            logger.LogDebug(ex, "SlimIdentity: rejected {Purpose} token.", purpose);
            return false;
        }
    }
}

internal sealed record SlimEmailTokenPayload(string Uid, string Email, string Stamp);
internal sealed record SlimResetTokenPayload(string Uid, string Stamp);
internal sealed record SlimPreAuthPayload(string Uid, string Stamp, bool UseCookies, bool RememberMe, string Method, string? CodeHash);
internal sealed record SlimTwoFactorSetupPayload(string Uid, string Secret);
internal sealed record SlimExchangePayload(string Uid, string Stamp, string Provider, string Nonce);
/// <summary><c>AuthTime</c> = unix seconds of the original sign-in (absolute lifetime), <c>Sid</c> = server-side session (optional).</summary>
internal sealed record SlimRefreshPayload(string Uid, string Stamp, string Amr, string Nonce, long AuthTime, string? Sid);
internal sealed record SlimInvitationPayload(string Uid, string Email, string Stamp);
