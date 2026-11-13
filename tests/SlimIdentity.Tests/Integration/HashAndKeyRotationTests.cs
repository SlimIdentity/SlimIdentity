using System.Buffers.Binary;
using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Integration;

/// <summary>Password hash strength and rotation of the JWT signing secret.</summary>
public sealed class HashAndKeyRotationTests
{
    /// <summary>PBKDF2 iteration count stored in an Identity V3 hash (format byte, PRF, iterations big-endian, …).</summary>
    private static int Iterations(string hash) => BinaryPrimitives.ReadInt32BigEndian(Convert.FromBase64String(hash).AsSpan(5, 4));

    [Fact]
    public async Task Passwords_are_hashed_with_the_owasp_iteration_count_by_default()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { FastHashing = false });
        Assert.Equal(210_000, app.App.Services.GetRequiredService<IOptions<PasswordHasherOptions>>().Value.IterationCount);
    }

    [Fact]
    public async Task The_hosts_iteration_count_wins()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions
        {
            Builder = b => b.Services.Configure<PasswordHasherOptions>(o => o.IterationCount = 300_000),
        });
        Assert.Equal(300_000, app.App.Services.GetRequiredService<IOptions<PasswordHasherOptions>>().Value.IterationCount);
    }

    [Fact]
    public async Task Weaker_hashes_are_upgraded_at_the_next_sign_in()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { FastHashing = false });
        var user = app.Users.Get(TestApp.UserEmail);
        var weak = new PasswordHasher<SlimUser>(Options.Create(new PasswordHasherOptions { IterationCount = 100_000 }))
            .HashPassword(user, TestApp.UserPassword);
        await app.Users.UpdatePasswordHashAsync(user, user.PasswordHash!, weak, default);
        Assert.Equal(100_000, Iterations(app.Users.Get(TestApp.UserEmail).PasswordHash!));

        await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword);

        Assert.Equal(210_000, Iterations(app.Users.Get(TestApp.UserEmail).PasswordHash!));
    }

    private const string OldSecret = "old-secret-0123456789-abcdefghijklmnopqrstuvwxyz";

    /// <summary>The same token (claims, stamp, lifetime), signed with another key – as an instance with the old secret issued it.</summary>
    private static string ResignWith(string token, SecurityKey key)
    {
        var payload = JsonSerializer.Deserialize<Dictionary<string, object>>(
            Base64UrlEncoder.Decode(token.Split('.')[1]))!;
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(
            JsonSerializer.Serialize(payload),
            new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
    }

    private static SymmetricSecurityKey KeyWithId(string secret, string? keyId) =>
        new(System.Text.Encoding.UTF8.GetBytes(secret)) { KeyId = keyId };

    [Fact]
    public async Task Tokens_of_the_previous_secret_stay_valid_during_a_rotation()
    {
        await using var app = await TestApp.StartAsync(new TestAppOptions { Configure = o => o.Tokens.PreviousJwtSecrets = [OldSecret] });
        var current = (await app.LoginBearerAsync(TestApp.UserEmail, TestApp.UserPassword)).AccessToken;

        var client = app.CreateClient();
        // exactly as the old instance signed it – including its key id
        client.BearerToken = ResignWith(current!, SlimIdentity.Services.SlimJwtTokenFactory.CreateSigningKey(OldSecret));
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/me")).StatusCode);

        // tokens of 0.9.0-rc.1 carry the shared legacy id, tokens without an id exist too
        client.BearerToken = ResignWith(current!, KeyWithId(OldSecret, "slim-hs256"));
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/me")).StatusCode);
        client.BearerToken = ResignWith(current!, KeyWithId(OldSecret, null));
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/auth/me")).StatusCode);

        client.BearerToken = ResignWith(current!, KeyWithId("unknown-secret-0123456789-abcdefghijklmnopqrstuvw", "slim-hs256"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/auth/me")).StatusCode);
    }

    [Fact]
    public void Every_secret_gets_its_own_key_id()
    {
        var a = SlimIdentity.Services.SlimJwtTokenFactory.CreateSigningKey(OldSecret);
        var b = SlimIdentity.Services.SlimJwtTokenFactory.CreateSigningKey(OldSecret + "x");
        Assert.NotEqual(a.KeyId, b.KeyId);
        Assert.Equal(a.KeyId, SlimIdentity.Services.SlimJwtTokenFactory.CreateSigningKey(OldSecret).KeyId);
    }

    [Fact]
    public async Task Previous_secrets_are_validated_like_the_current_one()
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(() => TestApp.StartAsync(new TestAppOptions
        {
            Configure = o => o.Tokens.PreviousJwtSecrets = ["too-short"],
        }));
        Assert.Contains("PreviousJwtSecrets", error.ToString());
    }
}
