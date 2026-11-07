using SlimIdentity.Security;

namespace SlimIdentity;

/// <summary>
/// One machine client of <see cref="SlimIdentityBuilder.AddConfigurationApiKeys"/>. Only the hash of the key is
/// configured – create key and hash with <see cref="SlimApiKeys.Generate"/> (or <c>dotnet run tools/new-api-key.cs</c>).
/// </summary>
public sealed class SlimConfiguredApiKey
{
    /// <summary>Name of the client; the principal's <c>sub</c> becomes <c>client:{ClientId}</c>.</summary>
    public string ClientId { get; set; } = string.Empty;
    /// <summary>SHA-256 hex hash of the key (64 characters, case-insensitive) – never the key itself.</summary>
    public string Hash { get; set; } = string.Empty;
    /// <summary>Granted scopes, issued as <c>scope</c> claims.</summary>
    public IList<string> Scopes { get; set; } = [];
    /// <summary>Granted roles, issued as <c>role</c> claims.</summary>
    public IList<string> Roles { get; set; } = [];
    /// <summary>Optional end of validity (UTC); afterwards the key is rejected.</summary>
    public DateTimeOffset? ExpiresUtc { get; set; }
}

/// <summary>The configured machine clients (bound from the section given to <c>AddConfigurationApiKeys</c>).</summary>
public sealed class SlimConfiguredApiKeyOptions
{
    /// <summary>All configured keys.</summary>
    public IList<SlimConfiguredApiKey> Keys { get; set; } = [];
}

/// <summary><see cref="ISlimApiKeyStore"/> over configuration – follows reloads, so a key is revoked by removing it.</summary>
internal sealed class SlimConfigurationApiKeyStore(IOptionsMonitor<SlimConfiguredApiKeyOptions> options, TimeProvider time) : ISlimApiKeyStore
{
    public Task<IReadOnlyCollection<Claim>?> ValidateApiKeyAsync(string keyHash, CancellationToken ct)
    {
        var now = time.GetUtcNow();
        SlimConfiguredApiKey? match = null;
        foreach (var key in options.CurrentValue.Keys)   // a handful of keys: compare all, in constant time
            if (SlimHashing.FixedTimeEquals(key.Hash.ToLowerInvariant(), keyHash)) match = key;

        if (match is null || match.ExpiresUtc <= now) return Task.FromResult<IReadOnlyCollection<Claim>?>(null);

        List<Claim> claims = [new(SlimClaimTypes.UserId, "client:" + match.ClientId)];
        claims.AddRange(match.Scopes.Select(s => new Claim("scope", s)));
        claims.AddRange(match.Roles.Select(r => new Claim(SlimClaimTypes.Role, r)));
        return Task.FromResult<IReadOnlyCollection<Claim>?>(claims);
    }
}

internal sealed class SlimConfiguredApiKeyValidator : IValidateOptions<SlimConfiguredApiKeyOptions>
{
    public ValidateOptionsResult Validate(string? name, SlimConfiguredApiKeyOptions options)
    {
        List<string> failures = [];
        for (var i = 0; i < options.Keys.Count; i++)
        {
            var key = options.Keys[i];
            if (string.IsNullOrWhiteSpace(key.ClientId)) failures.Add($"ApiKeys[{i}].ClientId is required.");
            if (key.Hash is not { Length: 64 } || !key.Hash.All(char.IsAsciiHexDigit))
                failures.Add($"ApiKeys[{i}].Hash must be the 64-character SHA-256 hex hash of the key – never the key itself.");
        }
        var duplicates = options.Keys.GroupBy(k => k.Hash.ToLowerInvariant()).Where(g => g.Count() > 1).Select(g => g.First().ClientId);
        failures.AddRange(duplicates.Select(c => $"ApiKeys: the hash of client '{c}' is configured more than once."));
        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
