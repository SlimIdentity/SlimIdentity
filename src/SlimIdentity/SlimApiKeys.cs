using System.Buffers.Text;
using SlimIdentity.Security;

namespace SlimIdentity;

/// <summary>Helpers for hosts that issue API keys for the <c>X-API-Key</c> handler.</summary>
public static class SlimApiKeys
{
    /// <summary>
    /// Creates a new random key (256 bit). Show <c>Key</c> to the client exactly once and persist only <c>Hash</c>.
    /// </summary>
    /// <param name="prefix">Readable prefix that helps to identify leaked keys, e.g. in secret scanners.</param>
    public static (string Key, string Hash) Generate(string prefix = "sk")
    {
        var key = $"{prefix}_{Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32))}";
        return (key, Hash(key));
    }

    /// <summary>SHA-256 hex hash, exactly what <see cref="ISlimApiKeyStore.ValidateApiKeyAsync"/> receives.</summary>
    public static string Hash(string key) => SlimHashing.Sha256Hex(key);
}
