using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Forged and manipulated access tokens are rejected.</summary>
public sealed class TokenTests
{
    private const string JwtSecret = "test-secret-0123456789-abcdefghijklmnopqrstuvwxyz";   // TestApp's key

    private static (JsonObject Header, JsonObject Payload) Decode(string jwt)
    {
        var parts = jwt.Split('.');
        return (JsonNode.Parse(Base64Url.DecodeFromChars(parts[0]))!.AsObject(), JsonNode.Parse(Base64Url.DecodeFromChars(parts[1]))!.AsObject());
    }

    private static string Encode(JsonObject header, JsonObject payload, string? key, Func<byte[], byte[], byte[]>? mac = null)
    {
        var unsigned = $"{Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString()))}.{Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payload.ToJsonString()))}";
        if (key is null) return unsigned + ".";
        var signature = (mac ?? HMACSHA256.HashData)(Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(unsigned));
        return $"{unsigned}.{Base64Url.EncodeToString(signature)}";
    }

    private static JsonObject Set(JsonObject o, string name, JsonNode? value) { var copy = o.DeepClone().AsObject(); copy[name] = value; return copy; }
    private static JsonObject Remove(JsonObject o, string name) { var copy = o.DeepClone().AsObject(); copy.Remove(name); return copy; }

    private static async Task<HttpStatusCode> CallWith(TestApp app, string token)
    {
        var client = app.CreateClient();
        client.BearerToken = token;
        return (await client.GetAsync("/api/hello")).StatusCode;
    }

    public static TheoryData<string> Manipulations => ["control", "alg-none", "wrong-key", "hs512-same-key", "expired", "no-exp", "wrong-issuer", "wrong-audience", "future-nbf", "stamp-swapped"];

    [Theory]
    [MemberData(nameof(Manipulations))]
    public async Task Manipulated_jwts_are_rejected(string manipulation)
    {
        await using var app = await TestApp.StartAsync();
        var real = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken!;
        var (header, payload) = Decode(real);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();   // JWT validation uses the system clock

        var token = manipulation switch
        {
            "control" => Encode(header, payload, JwtSecret),   // re-signed unchanged: proves the forging helper is correct
            "alg-none" => Encode(Set(header, "alg", "none"), payload, key: null),
            "wrong-key" => Encode(header, payload, "another-secret-0123456789-abcdefghijklmnop"),
            "hs512-same-key" => Encode(Set(header, "alg", "HS512"), payload, JwtSecret, HMACSHA512.HashData),
            "expired" => Encode(header, Set(Set(payload, "exp", now - 3600), "nbf", now - 7200), JwtSecret),
            "no-exp" => Encode(header, Remove(payload, "exp"), JwtSecret),
            "wrong-issuer" => Encode(header, Set(payload, "iss", "evil"), JwtSecret),
            "wrong-audience" => Encode(header, Set(payload, "aud", "evil"), JwtSecret),
            "future-nbf" => Encode(header, Set(payload, "nbf", now + 3600), JwtSecret),
            "stamp-swapped" => Encode(header, Set(payload, SlimClaimTypes.SecurityStamp, SlimUser.NewSecurityStamp()), JwtSecret),
            _ => throw new ArgumentOutOfRangeException(nameof(manipulation)),
        };

        var expected = manipulation == "control" ? HttpStatusCode.OK : HttpStatusCode.Unauthorized;
        Assert.Equal(expected, await CallWith(app, token));
    }

    [Fact]
    public async Task A_token_bound_to_another_users_session_is_rejected()
    {
        // even with the signing key: the session id must belong to the token's user
        await using var app = await TestApp.StartAsync();
        var user = Decode((await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken!).Payload;
        var (header, admin) = Decode((await app.LoginBearerAsync(TestApp.AdminEmail, TestApp.AdminPassword)).AccessToken!);

        var forged = Encode(header, Set(admin, SlimClaimTypes.SessionId, user[SlimClaimTypes.SessionId]!.GetValue<string>()), JwtSecret);
        Assert.Equal(HttpStatusCode.Unauthorized, await CallWith(app, forged));
    }
}
