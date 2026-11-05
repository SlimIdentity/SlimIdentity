// SlimIdentity sample – reject passwords that appear in known data breaches (NIST SP 800-63B).
// Uses the Have I Been Pwned "range" API with k-anonymity: only the first 5 hex characters of the password's SHA-1
// hash leave the server, never the password or the full hash.
//
//   builder.Services.AddHttpClient(PwnedPasswordRule.HttpClientName, c => c.Timeout = TimeSpan.FromSeconds(3));
//   builder.Services.AddSlimIdentity(...)
//       .AddPasswordRule<PwnedPasswordRule>();
//
// No package needed. Fails open: if the service is unreachable, the password is accepted (and a warning logged),
// so an outage of a third-party API never blocks registrations.

using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using SlimIdentity;

namespace MyApp.Security;

public sealed class PwnedPasswordRule(IHttpClientFactory httpClientFactory, ILogger<PwnedPasswordRule> logger) : ISlimPasswordRule
{
    public const string HttpClientName = "pwned-passwords";

    public async Task<IReadOnlyList<string>> ValidateAsync(string password, string email, CancellationToken ct)
    {
        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));   // SHA-1 is what the API uses
        var (prefix, suffix) = (hash[..5], hash[5..]);

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"https://api.pwnedpasswords.com/range/{prefix}");
            request.Headers.Add("Add-Padding", "true");   // hides the real response size
            using var response = await httpClientFactory.CreateClient(HttpClientName).SendAsync(request, ct);
            response.EnsureSuccessStatusCode();

            var body = await response.Content.ReadAsStringAsync(ct);
            foreach (var line in body.Split('\n'))
            {
                var parts = line.Trim().Split(':');
                if (parts.Length == 2 && parts[0].Equals(suffix, StringComparison.OrdinalIgnoreCase) && parts[1] != "0")
                    return ["This password has appeared in a data breach. Please choose a different one."];
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            logger.LogWarning(ex, "Pwned Passwords check unavailable – password accepted without breach check.");
        }

        return [];
    }
}
