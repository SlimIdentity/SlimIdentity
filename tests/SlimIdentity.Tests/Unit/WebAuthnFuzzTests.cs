using System.Buffers.Text;
using System.Text.Json;
using SlimIdentity.Passkeys;
using SlimIdentity.Tests.Infrastructure;

namespace SlimIdentity.Tests.Unit;

/// <summary>
/// Mutation fuzzing of the WebAuthn parsers: valid attestations, authenticator data, COSE keys and signatures from a
/// software authenticator are flipped, cut, extended and overwritten thousands of times. Whatever arrives, the parsers
/// answer "invalid" (null / false) – an exception would be a 500 or worse, a crash path an attacker controls.
/// Deterministic seeds: a failure is reproducible.
/// </summary>
public sealed class WebAuthnFuzzTests
{
    // CI: a few thousand rounds per parser; before a release longer: SLIMIDENTITY_FUZZ_ROUNDS=200000 (and a SEED)
    private static readonly int Rounds = int.TryParse(Environment.GetEnvironmentVariable("SLIMIDENTITY_FUZZ_ROUNDS"), out var n) ? n : 4_000;
    private static readonly int Seed = int.TryParse(Environment.GetEnvironmentVariable("SLIMIDENTITY_FUZZ_SEED"), out var s) ? s : 1_026;

    private static readonly JsonElement CreateOptions = JsonDocument.Parse("""
        { "rp": { "id": "test.local" }, "user": { "id": "dXNlci0x" }, "challenge": "Y2hhbGxlbmdl" }
        """).RootElement;

    private static readonly JsonElement GetOptions = JsonDocument.Parse("""{ "rpId": "test.local", "challenge": "Y2hhbGxlbmdl" }""").RootElement;

    /// <summary>A real registration and sign-in of the software authenticator, as raw bytes.</summary>
    private static (byte[] ClientData, byte[] Attestation, byte[] AuthData, byte[] CoseKey, byte[] AssertionData, byte[] Signature) Material(bool rsa)
    {
        using var key = new SoftwarePasskey(rsa);
        var created = JsonSerializer.SerializeToElement(key.Create(CreateOptions, "https://app.test.local"));
        var asserted = JsonSerializer.SerializeToElement(key.Get(GetOptions, "https://app.test.local"));
        static byte[] Bytes(JsonElement e, string name) => Base64Url.DecodeFromChars(e.GetProperty("response").GetProperty(name).GetString());

        var attestation = Bytes(created, "attestationObject");
        var authData = SlimWebAuthn.AuthenticatorDataOfAttestation(attestation)!;
        var cose = SlimWebAuthn.ParseAuthenticatorData(authData)!.CredentialPublicKey!;
        return (Bytes(asserted, "clientDataJSON"), attestation, authData, cose, Bytes(asserted, "authenticatorData"), Bytes(asserted, "signature"));
    }

    /// <summary>One of several kinds of damage, chosen by the seeded random source.</summary>
    private static byte[] Mutate(byte[] input, Random random)
    {
        var bytes = input.ToList();
        switch (random.Next(7))
        {
            case 0:   // flip a few bytes
                for (var i = random.Next(1, 9); i > 0 && bytes.Count > 0; i--) bytes[random.Next(bytes.Count)] = (byte)random.Next(256);
                break;
            case 1:   // cut
                bytes = bytes.Take(random.Next(bytes.Count + 1)).ToList();
                break;
            case 2:   // trailing garbage
                bytes.AddRange(Enumerable.Range(0, random.Next(1, 64)).Select(_ => (byte)random.Next(256)));
                break;
            case 3:   // insert bytes in the middle
                bytes.InsertRange(random.Next(bytes.Count + 1), Enumerable.Range(0, random.Next(1, 16)).Select(_ => (byte)random.Next(256)));
                break;
            case 4:   // CBOR "length" bytes that claim huge sizes or indefinite lengths
                if (bytes.Count > 0) bytes[random.Next(bytes.Count)] = new byte[] { 0x1b, 0x1a, 0x5f, 0x7f, 0x9f, 0xbf, 0xff, 0x3b }[random.Next(8)];
                break;
            case 5:   // remove a slice
                if (bytes.Count > 1) { var at = random.Next(bytes.Count - 1); bytes.RemoveRange(at, random.Next(1, bytes.Count - at)); }
                break;
            default:  // pure noise
                return Enumerable.Range(0, random.Next(0, 300)).Select(_ => (byte)random.Next(256)).ToArray();
        }
        return [.. bytes];
    }

    private static void Survives(string what, byte[] input, Action<byte[]> parse)
    {
        try { parse(input); }
        catch (Exception ex)
        {
            Assert.Fail($"{what} threw {ex.GetType().Name} ({ex.Message}) for input {Convert.ToHexString(input)}");
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void The_parsers_never_throw_whatever_arrives(bool rsa)
    {
        var m = Material(rsa);
        var random = new Random(rsa ? Seed + 1_000 : Seed);

        for (var i = 0; i < Rounds; i++)
        {
            Survives("ParseClientData", Mutate(m.ClientData, random), b => SlimWebAuthn.ParseClientData(b));
            Survives("AuthenticatorDataOfAttestation", Mutate(m.Attestation, random), b =>
            {
                if (SlimWebAuthn.AuthenticatorDataOfAttestation(b) is { } data) SlimWebAuthn.ParseAuthenticatorData(data);
            });
            Survives("ParseAuthenticatorData", Mutate(m.AuthData, random), b => SlimWebAuthn.ParseAuthenticatorData(b));
            Survives("ParseAuthenticatorData (assertion)", Mutate(m.AssertionData, random), b => SlimWebAuthn.ParseAuthenticatorData(b));
            Survives("AlgorithmOf", Mutate(m.CoseKey, random), b => SlimWebAuthn.AlgorithmOf(b));
            Survives("VerifySignature (key)", Mutate(m.CoseKey, random), b => SlimWebAuthn.VerifySignature(b, m.AssertionData, m.ClientData, m.Signature));
            Survives("VerifySignature (signature)", Mutate(m.Signature, random), b =>
                Assert.False(SlimWebAuthn.VerifySignature(m.CoseKey, m.AssertionData, m.ClientData, b) && !b.AsSpan().SequenceEqual(m.Signature)));
        }

        // and the untouched material still verifies – the fuzzing worked on real input
        Assert.True(SlimWebAuthn.VerifySignature(m.CoseKey, m.AssertionData, m.ClientData, m.Signature));
    }
}
