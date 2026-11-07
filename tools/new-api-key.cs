// Creates an API key for SlimIdentity's X-API-Key handler: the key (give it to the client, once) and its SHA-256 hash
// (the only thing you store – in configuration for AddConfigurationApiKeys, or in your own key table).
//
//   dotnet run tools/new-api-key.cs              → prefix "sk"
//   dotnet run tools/new-api-key.cs -- reports   → prefix "reports"
//
// Same format as SlimApiKeys.Generate(prefix): "{prefix}_{base64url(32 random bytes)}", hash = lowercase SHA-256 hex.

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

var prefix = args.Length > 0 ? args[0] : "sk";
if (prefix.Length is 0 or > 16 || !prefix.All(char.IsAsciiLetterOrDigit))
{
    Console.Error.WriteLine("The prefix must be 1–16 ASCII letters or digits.");
    return 1;
}

var key = $"{prefix}_{Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32))}";
var hash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(key)));

Console.WriteLine($"Key  (give to the client, shown only now): {key}");
Console.WriteLine($"Hash (store this):                         {hash}");
return 0;
