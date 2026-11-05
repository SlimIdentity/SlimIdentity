using System.Text;
using SlimIdentity.Security;
using SlimIdentity.Services;

namespace SlimIdentity.Tests.Unit;

public sealed class TotpTests
{
    // RFC 6238 Appendix B (SHA-1 seed "12345678901234567890"); 6-digit codes are the last 6 digits of the 8-digit vectors.
    [Theory]
    [InlineData(59L, "287082")]
    [InlineData(1111111109L, "081804")]
    [InlineData(1234567890L, "005924")]
    [InlineData(2000000000L, "279037")]
    public void Compute_matches_RFC_6238_test_vectors(long unixTime, string expected) =>
        Assert.Equal(expected, SlimTotp.Compute(Encoding.ASCII.GetBytes("12345678901234567890"), unixTime / 30));

    [Fact]
    public void Verify_accepts_neighbouring_steps_within_the_tolerance_only()
    {
        var secret = SlimTotp.GenerateSecret();
        var key = SlimBase32.Decode(secret);
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_010);
        var previous = SlimTotp.Compute(key, now.ToUnixTimeSeconds() / 30 - 1);
        var older = SlimTotp.Compute(key, now.ToUnixTimeSeconds() / 30 - 2);

        Assert.True(SlimTotp.Verify(secret, previous, now, tolerance: 1));
        Assert.False(SlimTotp.Verify(secret, older, now, tolerance: 1));
        Assert.False(SlimTotp.Verify(secret, "12345", now, tolerance: 1));
        Assert.False(SlimTotp.Verify(secret, "abcdef", now, tolerance: 1));
    }

    [Fact]
    public void Base32_round_trips_and_ignores_formatting()
    {
        var bytes = Enumerable.Range(0, 20).Select(i => (byte)(i * 13)).ToArray();
        var encoded = SlimBase32.Encode(bytes);

        Assert.Equal(bytes, SlimBase32.Decode(encoded));
        Assert.Equal(bytes, SlimBase32.Decode(SlimTotp.FormatSharedKey(encoded)));
        Assert.Throws<FormatException>(() => SlimBase32.Decode("not-base32!"));
    }

    [Fact]
    public void Recovery_codes_are_unique_and_hash_independent_of_formatting()
    {
        var codes = SlimRecoveryCodes.Generate(10);
        Assert.Equal(10, codes.Distinct().Count());
        Assert.Equal(SlimRecoveryCodes.Hash(codes[0]), SlimRecoveryCodes.Hash(" " + codes[0].ToUpperInvariant().Replace("-", "") + " "));
    }
}

public sealed class LockoutDurationTests
{
    [Theory]
    [InlineData(1, 1)]
    [InlineData(2, 2)]
    [InlineData(3, 4)]
    [InlineData(6, 32)]
    [InlineData(7, 60)]          // capped
    [InlineData(int.MaxValue, 60)]
    public void Duration_doubles_per_lockout_up_to_the_cap(int lockoutNumber, int expectedMinutes)
    {
        var options = new SlimLockoutOptions { Duration = TimeSpan.FromMinutes(1), MaxDuration = TimeSpan.FromHours(1) };
        Assert.Equal(TimeSpan.FromMinutes(expectedMinutes), SlimCredentialService.LockoutDuration(options, lockoutNumber));
    }
}

public sealed class RateLimitKeyTests
{
    [Theory]
    [InlineData("203.0.113.7", 64, "203.0.113.7")]
    [InlineData("::ffff:203.0.113.7", 64, "203.0.113.7")]                         // IPv4-mapped
    [InlineData("2001:db8:aaaa:bbbb:1:2:3:4", 64, "2001:db8:aaaa:bbbb::/64")]     // whole /64 = one client
    [InlineData("2001:db8:aaaa:bbbb:ffff::1", 64, "2001:db8:aaaa:bbbb::/64")]
    [InlineData("2001:db8:aaaa:bbbb:1:2:3:4", 48, "2001:db8:aaaa::/48")]
    [InlineData("2001:db8::1", 128, "2001:db8::1")]
    public void Client_key_groups_ipv6_by_prefix(string address, int prefix, string expected) =>
        Assert.Equal(expected, SlimIdentity.Http.SlimClientRateLimiterPolicy.ClientKey(System.Net.IPAddress.Parse(address), prefix));

    [Fact]
    public void Missing_address_shares_one_bucket() =>
        Assert.Equal("unknown", SlimIdentity.Http.SlimClientRateLimiterPolicy.ClientKey(null, 64));
}

public sealed class ActorClaimTests
{
    [Fact]
    public void Actor_round_trips_id_stamp_and_amr()
    {
        var json = SlimClaims.SerializeActor(SlimClaims.CreateActor("admin-1", "STAMP", "mfa"));
        var actor = SlimClaims.ParseActorClaim(json);

        Assert.Equal(new SlimActor("admin-1", "STAMP", "mfa"), actor);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("\"admin-1\"")]
    [InlineData("{\"sub\":42}")]
    [InlineData("{\"sub\":\"\"}")]
    public void Malformed_actor_claims_are_ignored(string? json) => Assert.Null(SlimClaims.ParseActorClaim(json));
}

public sealed class OptionsValidatorTests
{
    private static IReadOnlyList<string> Validate(Action<SlimIdentityOptions> configure)
    {
        var options = new SlimIdentityOptions { Tokens = { JwtSecret = new string('x', 32) } };
        configure(options);
        var result = new SlimIdentityOptionsValidator().Validate(null, options);
        return result.Failed ? result.Failures.ToList() : [];
    }

    [Fact]
    public void Defaults_with_a_jwt_secret_are_valid() => Assert.Empty(Validate(_ => { }));

    [Theory]
    [InlineData("short-secret")]
    [InlineData("")]
    public void Jwt_secret_must_have_32_bytes(string secret) =>
        Assert.Contains(Validate(o => o.Tokens.JwtSecret = secret), f => f.Contains("JwtSecret"));

    [Fact]
    public void Jwt_secret_is_not_required_for_cookie_only_setups() =>
        Assert.Empty(Validate(o => { o.Tokens.JwtSecret = ""; o.Endpoints.AllowJwtAuth = false; o.Endpoints.DefaultUseCookies = true; }));

    [Fact]
    public void SameSite_none_requires_csrf_protection() =>
        Assert.Contains(Validate(o => { o.Cookies.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.None; o.Csrf.Enabled = false; }),
            f => f.Contains("SameSite"));

    [Fact]
    public void Lockout_cap_must_not_be_below_the_first_duration() =>
        Assert.Contains(Validate(o => { o.Lockout.Duration = TimeSpan.FromHours(2); }), f => f.Contains("MaxDuration"));

    [Fact]
    public void Absolute_refresh_lifetime_must_cover_the_sliding_lifetime() =>
        Assert.Contains(Validate(o => o.Tokens.RefreshTokenAbsoluteLifetime = TimeSpan.FromDays(1)), f => f.Contains("RefreshTokenAbsoluteLifetime"));

    [Fact]
    public void Link_templates_need_the_token_placeholder() =>
        Assert.Contains(Validate(o => o.Links.InvitationUrl = "https://app/accept"), f => f.Contains("InvitationUrl"));
}
