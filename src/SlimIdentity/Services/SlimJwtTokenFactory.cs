using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SlimIdentity.Security;

namespace SlimIdentity.Services;

/// <summary>Creates HS256 access tokens with <see cref="JsonWebTokenHandler"/>.</summary>
internal sealed class SlimJwtTokenFactory(IOptions<SlimIdentityOptions> options, TimeProvider time)
{
    private readonly JsonWebTokenHandler _handler = new();

    public (string Token, DateTimeOffset ExpiresAt) CreateAccessToken(IEnumerable<Claim> claims)
    {
        var t = options.Value.Tokens;
        var now = time.GetUtcNow();
        var expires = now + t.AccessTokenLifetime;

        var subject = new List<Claim>();
        var extra = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString("N"),
        };

        foreach (var claim in claims)
        {
            if (claim.Type == SlimClaimTypes.Actor)
            {
                // RFC 8693: "act" is a JSON object, not a string
                if (SlimClaims.ParseActorClaim(claim.Value) is { } actor)
                    extra[SlimClaimTypes.Actor] = actor.ToDictionary().ToDictionary(kv => kv.Key, kv => (object)kv.Value, StringComparer.Ordinal);
                continue;
            }
            subject.Add(claim);
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(subject),
            Claims = extra,
            Issuer = t.Issuer,
            Audience = t.Audience,
            IssuedAt = now.UtcDateTime,
            NotBefore = now.UtcDateTime,
            Expires = expires.UtcDateTime,
            SigningCredentials = new SigningCredentials(CreateSigningKey(t.JwtSecret), SecurityAlgorithms.HmacSha256),
        };

        return (_handler.CreateToken(descriptor), expires);
    }

    internal static SymmetricSecurityKey CreateSigningKey(string secret) =>
        new(Encoding.UTF8.GetBytes(secret)) { KeyId = "slim-hs256" };
}
