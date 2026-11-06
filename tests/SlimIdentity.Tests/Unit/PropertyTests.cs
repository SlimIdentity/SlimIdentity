using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using FsCheck;
using FsCheck.Fluent;
using FsCheck.Xunit;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using SlimIdentity.Http;
using SlimIdentity.Security;
using SlimIdentity.Services;

namespace SlimIdentity.Tests.Unit;

/// <summary>
/// Property-based tests (FsCheck) for everything that parses input from outside: generated, often hostile strings
/// must never crash the parser and never get past the security rule it enforces.
/// </summary>
public sealed class PropertyTests
{
    private const int Many = 3000;

    // ------------------------------------------------------------------ generators

    /// <summary>Characters that matter to URL parsers: separators, escapes, whitespace, controls, look-alikes.</summary>
    private static readonly char[] UrlChars =
        "/\\:@.?#%&=+-_~ \t\n\r\0\u0085\u00a0\u2028\u3000\uff0f\uff3c;,'\"<>[]{}|^`!$()*0123456789abcdefghiklmnopstuvwxyzAEHPST".ToCharArray();

    private static readonly string[] UrlPrefixes =
    [
        "", "/", "//", "/\\", "\\\\", "https://", "http://", "https:", "javascript:", "data:", "file://", " ",
        "https://app.example.com", "https://app.example.com:443", "https://app.example.com.evil.example",
        "https://app.example.com@evil.example", "https://evil.example", "https://evil.example\\@app.example.com",
        "HTTPS://APP.EXAMPLE.COM", "https://admin.example.com", "http://app.example.com",
    ];

    private static Arbitrary<string> UrlLike() =>
        Gen.Elements(UrlPrefixes)
            .SelectMany(prefix => Gen.Elements(UrlChars).ArrayOf().Select(cs => prefix + new string(cs)))
            .ToArbitrary();

    private static Arbitrary<string> AnyString() =>
        Gen.Elements(UrlChars.Concat("{}\"\\u0000\ud800\udc00".ToCharArray()).ToArray())
            .ArrayOf().Select(cs => new string(cs))
            .ToArbitrary();

    private static SlimIdentityOptions Options() => new()
    {
        TrustedOrigins = { "https://admin.example.com" },
        Links = { BaseUrl = "https://app.example.com" },
    };

    // ------------------------------------------------------------------ open redirect

    [Property(MaxTest = Many)]
    public Property Return_url_never_leaves_the_trusted_origins() =>
        Prop.ForAll(UrlLike(), input =>
        {
            var result = SlimReturnUrl.Validate(input, Options());
            return result is null || result == "/" || IsSafeLocalPath(result) || IsTrustedAbsolute(result);
        });

    [Theory]
    [InlineData("/\t/evil.example")]            // browsers strip tabs: "//evil.example"
    [InlineData("/\n/evil.example")]
    [InlineData("/\r\n/evil.example")]
    [InlineData("//evil.example")]
    [InlineData("/\\evil.example")]
    [InlineData(" //evil.example")]
    [InlineData("\\\\evil.example")]
    [InlineData("https://evil.example")]
    [InlineData("https://app.example.com@evil.example")]
    [InlineData("https://app.example.com.evil.example")]
    [InlineData("https://evil.example\\@app.example.com")]
    [InlineData("https:evil.example")]
    [InlineData("javascript:alert(1)")]
    [InlineData("http://app.example.com/")]     // scheme counts
    [InlineData("https://app.example.com:8443/")] // port counts
    public void Known_open_redirect_tricks_are_rejected(string input) =>
        Assert.Null(SlimReturnUrl.Validate(input, Options()));

    [Theory]
    [InlineData("/dashboard?tab=1", "/dashboard?tab=1")]
    [InlineData("https://app.example.com/after-login", "https://app.example.com/after-login")]
    [InlineData("HTTPS://APP.EXAMPLE.COM/x", "https://app.example.com/x")]
    [InlineData("https://admin.example.com/", "https://admin.example.com/")]
    [InlineData("", "/")]
    public void Local_paths_and_trusted_origins_are_allowed(string input, string expected) =>
        Assert.Equal(expected, SlimReturnUrl.Validate(input, Options()));

    private static bool IsSafeLocalPath(string url) =>
        url[0] == '/' && (url.Length == 1 || (url[1] != '/' && url[1] != '\\')) && !url.Any(char.IsControl) && !char.IsWhiteSpace(url[^1]);

    private static bool IsTrustedAbsolute(string url) =>
        Uri.TryCreate(url, UriKind.Absolute, out var uri)
        && string.IsNullOrEmpty(uri.UserInfo)
        && uri.GetLeftPart(UriPartial.Authority).ToLowerInvariant() is "https://app.example.com" or "https://admin.example.com"
        && !url.Any(char.IsControl);

    // ------------------------------------------------------------------ CSRF origin check

    [Property(MaxTest = Many)]
    public Property Only_exact_trusted_origins_are_trusted() =>
        Prop.ForAll(UrlLike(), input =>
        {
            var trusted = Options().IsTrustedOrigin(input);   // must never throw
            return !trusted || SlimIdentityOptions.NormalizeOrigin(input) is "https://app.example.com" or "https://admin.example.com";
        });

    // ------------------------------------------------------------------ workflow tokens

    private static readonly SlimWorkflowTokens Tokens =
        new(new EphemeralDataProtectionProvider(), NullLogger<SlimWorkflowTokens>.Instance);

    [Property(MaxTest = Many)]
    public Property Arbitrary_strings_are_never_accepted_as_tokens() =>
        Prop.ForAll(AnyString(), input =>
            !Tokens.TryUnprotect<SlimResetTokenPayload>(SlimWorkflowTokens.PasswordResetPurpose, input, out _));

    [Property(MaxTest = 500)]
    public Property Tampered_tokens_are_rejected(PositiveInt position, char replacement)
    {
        var token = Tokens.Protect(SlimWorkflowTokens.PasswordResetPurpose, new SlimResetTokenPayload("user-1", "stamp"), TimeSpan.FromHours(1));
        var index = position.Get % token.Length;
        var tampered = token[..index] + replacement + token[(index + 1)..];
        return (tampered == token
                || !Tokens.TryUnprotect<SlimResetTokenPayload>(SlimWorkflowTokens.PasswordResetPurpose, tampered, out var payload)
                || payload.Uid == "user-1")   // base64url padding bits may decode identically – then the payload is intact
            .ToProperty();
    }

    [Fact]
    public void A_token_is_bound_to_its_purpose()
    {
        var token = Tokens.Protect(SlimWorkflowTokens.PasswordResetPurpose, new SlimResetTokenPayload("user-1", "stamp"), TimeSpan.FromHours(1));
        Assert.True(Tokens.TryUnprotect<SlimResetTokenPayload>(SlimWorkflowTokens.PasswordResetPurpose, token, out _));
        Assert.False(Tokens.TryUnprotect<SlimResetTokenPayload>(SlimWorkflowTokens.InvitationPurpose, token, out _));
    }

    // ------------------------------------------------------------------ claims

    [Property(MaxTest = Many)]
    public Property Actor_claim_parsing_never_throws() =>
        Prop.ForAll(AnyString(), input =>
        {
            var actor = SlimClaims.ParseActorClaim(input);
            return actor is null || !string.IsNullOrEmpty(actor.UserId);
        });

    [Property(MaxTest = Many)]
    public Property Actor_claim_parsing_never_throws_for_json_shaped_input(string? id, string? stamp)
    {
        var json = $"{{\"sub\":\"{id}\",\"slim_stamp\":\"{stamp}\"}}";
        var actor = SlimClaims.ParseActorClaim(json);
        return (actor is null || !string.IsNullOrEmpty(actor.UserId)).ToProperty();
    }

    [Property(MaxTest = Many)]
    public bool Sudo_claim_parsing_never_throws(string? value)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(SlimClaimTypes.SudoUntil, value ?? string.Empty)]));
        _ = principal.GetSudoUntil();
        _ = principal.IsInSudoMode();
        return true;
    }

    // ------------------------------------------------------------------ Base32 / TOTP

    [Property(MaxTest = Many)]
    public bool Base32_round_trips(byte[] data) =>
        SlimBase32.Decode(SlimBase32.Encode(data)).SequenceEqual(data);

    [Property(MaxTest = Many)]
    public Property Base32_decoding_fails_only_with_FormatException() =>
        Prop.ForAll(AnyString(), input =>
        {
            try { SlimBase32.Decode(input); }
            catch (FormatException) { }
            return true;
        });

    [Property(MaxTest = 1000)]
    public bool Totp_accepts_exactly_the_tolerance_window(PositiveInt stepSeed, int offset)
    {
        var key = SHA1Key(stepSeed.Get);
        var secret = SlimBase32.Encode(key);
        var step = 50_000_000L + stepSeed.Get;            // around the year 2017+, far from overflow
        var distance = Math.Abs(offset % 4);              // 0..3 steps away
        var codeStep = step + (offset < 0 ? -distance : distance);
        var code = SlimTotp.Compute(key, codeStep);
        var now = DateTimeOffset.FromUnixTimeSeconds(step * 30 + 15);

        var matchesCodeStep = SlimTotp.TryVerify(secret, code, now, tolerance: 1, out var matched) && matched == codeStep;
        // within ±1 step it must be accepted for exactly that step; further away never for that step
        return distance <= 1 ? matchesCodeStep : !matchesCodeStep;
    }

    [Property(MaxTest = Many)]
    public Property Totp_verification_never_throws_for_any_code() =>
        Prop.ForAll(AnyString(), code =>
        {
            SlimTotp.TryVerify("JBSWY3DPEHPK3PXP", code, DateTimeOffset.UtcNow, 1, out _);
            SlimTotp.TryVerify(code, "123456", DateTimeOffset.UtcNow, 1, out _);   // corrupt secret, too
            return true;
        });

    private static byte[] SHA1Key(int seed) => SHA256.HashData(BitConverter.GetBytes(seed))[..20];

    // ------------------------------------------------------------------ rate-limit client key

    [Property(MaxTest = Many)]
    public bool All_addresses_of_one_ipv6_network_share_a_rate_limit_key(byte[] seed, byte[] hostBits, PositiveInt prefixSeed)
    {
        var prefix = 32 + prefixSeed.Get % 97;   // 32..128
        var a = new byte[16];
        seed.AsSpan(0, Math.Min(16, seed.Length)).CopyTo(a);
        var b = (byte[])a.Clone();
        for (var bit = prefix; bit < 128; bit++)   // vary only host bits
            if (hostBits.Length > 0 && (hostBits[bit % hostBits.Length] & (1 << (bit % 8))) != 0)
                b[bit / 8] ^= (byte)(0x80 >> (bit % 8));

        var keyA = SlimClientRateLimiterPolicy.ClientKey(new IPAddress(a), prefix);
        var keyB = SlimClientRateLimiterPolicy.ClientKey(new IPAddress(b), prefix);
        // IPv4-mapped addresses (::ffff:a.b.c.d) are keyed by their IPv4 address – a different client by design
        return keyA == keyB || new IPAddress(a).IsIPv4MappedToIPv6 || new IPAddress(b).IsIPv4MappedToIPv6;
    }
}
