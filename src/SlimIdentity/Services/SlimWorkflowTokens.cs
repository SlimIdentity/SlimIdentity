using Microsoft.AspNetCore.DataProtection;

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

    public string Protect<T>(string purpose, T payload, TimeSpan lifetime)
    {
        var protector = provider.CreateProtector(purpose).ToTimeLimitedDataProtector();
        return protector.Protect(JsonSerializer.Serialize(payload), lifetime);
    }

    public bool TryUnprotect<T>(string purpose, string? token, [System.Diagnostics.CodeAnalysis.NotNullWhen(true)] out T? payload) where T : class
    {
        payload = null;
        if (string.IsNullOrWhiteSpace(token) || token.Length > 8192) return false;
        try
        {
            var protector = provider.CreateProtector(purpose).ToTimeLimitedDataProtector();
            var json = protector.Unprotect(token, out _);
            payload = JsonSerializer.Deserialize<T>(json);
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
internal sealed record SlimRefreshPayload(string Uid, string Stamp, string Amr, string Nonce);
