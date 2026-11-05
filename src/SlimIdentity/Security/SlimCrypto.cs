using System.Buffers.Binary;
using System.Buffers.Text;

namespace SlimIdentity.Security;

internal static class SlimHashing
{
    public static string Sha256Hex(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    /// <summary>Constant-time comparison of two strings.</summary>
    public static bool FixedTimeEquals(string? a, string? b)
    {
        if (a is null || b is null) return false;
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
    }
}

/// <summary>RFC 4648 Base32 (no padding) – used for TOTP secrets.</summary>
internal static class SlimBase32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                sb.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
            buffer &= (1 << bits) - 1;
        }
        if (bits > 0) sb.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    public static byte[] Decode(string input)
    {
        var clean = input.Trim().TrimEnd('=').Replace(" ", "", StringComparison.Ordinal).Replace("-", "", StringComparison.Ordinal).ToUpperInvariant();
        var output = new List<byte>(clean.Length * 5 / 8);
        int buffer = 0, bits = 0;
        foreach (var ch in clean)
        {
            var v = Alphabet.IndexOf(ch);
            if (v < 0) throw new FormatException("Invalid Base32 character.");
            buffer = (buffer << 5) | v;
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
                buffer &= (1 << bits) - 1;
            }
        }
        return output.ToArray();
    }
}

/// <summary>RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s) – compatible with all common authenticator apps.</summary>
internal static class SlimTotp
{
    private const int StepSeconds = 30;

    public static string GenerateSecret() => SlimBase32.Encode(RandomNumberGenerator.GetBytes(20));

    public static string GenerateNumericCode() =>
        RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6", CultureInfo.InvariantCulture);

    public static string NormalizeCode(string? code) =>
        (code ?? string.Empty).Replace(" ", "", StringComparison.Ordinal).Replace("-", "", StringComparison.Ordinal).Trim();

    public static bool Verify(string base32Secret, string? code, DateTimeOffset utcNow, int tolerance) =>
        TryVerify(base32Secret, code, utcNow, tolerance, out _);

    /// <summary>Verifies the code and returns the matching time step (for replay protection).</summary>
    public static bool TryVerify(string base32Secret, string? code, DateTimeOffset utcNow, int tolerance, out long matchedStep)
    {
        matchedStep = 0;
        var normalized = NormalizeCode(code);
        if (normalized.Length != 6 || !normalized.All(char.IsAsciiDigit)) return false;

        byte[] key;
        try { key = SlimBase32.Decode(base32Secret); }
        catch (FormatException) { return false; }
        if (key.Length == 0) return false;

        var provided = Encoding.ASCII.GetBytes(normalized);
        var step = utcNow.ToUnixTimeSeconds() / StepSeconds;
        var match = false;
        for (var i = -tolerance; i <= tolerance; i++)
        {
            // no early exit – constant work regardless of which window matches
            if (CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Compute(key, step + i)), provided))
            {
                match = true;
                matchedStep = step + i;
            }
        }
        return match;
    }

    /// <summary>Start of a time step in unix milliseconds (the unit of <c>ISlimTwoFactorStore.TryMarkCodeUsedAsync</c>).</summary>
    public static long StepStart(long step) => step * StepSeconds * 1000;

    internal static string Compute(byte[] key, long counter)
    {
        Span<byte> counterBytes = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counterBytes, counter);
        Span<byte> hash = stackalloc byte[20];
        HMACSHA1.HashData(key, counterBytes, hash);
        var offset = hash[19] & 0x0F;
        var binary = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        return (binary % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
    }

    public static string FormatSharedKey(string secret)
    {
        var sb = new StringBuilder();
        for (var i = 0; i < secret.Length; i++)
        {
            if (i > 0 && i % 4 == 0) sb.Append(' ');
            sb.Append(char.ToLowerInvariant(secret[i]));
        }
        return sb.ToString();
    }

    public static string BuildAuthenticatorUri(string issuer, string account, string secret)
    {
        var i = Uri.EscapeDataString(issuer);
        return $"otpauth://totp/{i}:{Uri.EscapeDataString(account)}?secret={secret}&issuer={i}&algorithm=SHA1&digits=6&period={StepSeconds}";
    }
}

/// <summary>
/// Recovery codes: 80 bit of entropy (16 Base32 characters, <c>xxxx-xxxx-xxxx-xxxx</c>). Stored as SHA-256 over a
/// versioned domain prefix, the user id and the code – salted per user, so identical codes never share a hash and
/// precomputed tables are useless. With 2^80 candidates per code an offline search is infeasible.
/// </summary>
internal static class SlimRecoveryCodes
{
    public static IReadOnlyList<string> Generate(int count)
    {
        var codes = new List<string>(count);
        for (var i = 0; i < count; i++)
        {
            var raw = SlimBase32.Encode(RandomNumberGenerator.GetBytes(10)).ToLowerInvariant(); // 80 bit = 16 chars
            codes.Add($"{raw[..4]}-{raw[4..8]}-{raw[8..12]}-{raw[12..16]}");
        }
        return codes;
    }

    public static string Hash(string userId, string code) =>
        SlimHashing.Sha256Hex($"slimidentity.recovery.v1:{userId}:{Normalize(code)}");

    private static string Normalize(string code) =>
        code.Replace("-", "", StringComparison.Ordinal).Replace(" ", "", StringComparison.Ordinal).Trim().ToLowerInvariant();
}
