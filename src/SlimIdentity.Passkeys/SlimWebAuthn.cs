using System.Buffers.Binary;
using System.Buffers.Text;
using System.Formats.Cbor;
using System.Numerics;

namespace SlimIdentity.Passkeys;

/// <summary>
/// The WebAuthn checks SlimIdentity.Passkeys needs (Web Authentication Level 2, §7.1 registration, §7.2 authentication):
/// client data, authenticator data, COSE public keys (ES256, RS256) and assertion signatures. Attestation statements
/// are not evaluated – SlimIdentity requests <c>attestation: "none"</c> and does not trust authenticator models.
/// </summary>
internal static class SlimWebAuthn
{
    public const int Es256 = -7;
    public const int Rs256 = -257;

    private const byte FlagUserPresent = 0x01;
    private const byte FlagUserVerified = 0x04;
    private const byte FlagBackupEligible = 0x08;
    private const byte FlagBackedUp = 0x10;
    private const byte FlagAttestedCredentialData = 0x40;

    public sealed record ClientData(string Type, string Challenge, string Origin, bool CrossOrigin);

    public sealed record AuthenticatorData(byte[] RpIdHash, byte Flags, uint SignCount, byte[]? CredentialId, byte[]? CredentialPublicKey)
    {
        public bool UserPresent => (Flags & FlagUserPresent) != 0;
        public bool UserVerified => (Flags & FlagUserVerified) != 0;
        public bool BackupEligible => (Flags & FlagBackupEligible) != 0;
        public bool BackedUp => (Flags & FlagBackedUp) != 0;
        /// <summary>§6.1: a credential that may not be backed up cannot be backed up.</summary>
        public bool BackupFlagsValid => BackupEligible || !BackedUp;
    }

    /// <summary>Parses <c>clientDataJSON</c>; <c>null</c> if it is not a JSON object with type, challenge and origin.</summary>
    public static ClientData? ParseClientData(byte[] json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("type", out var type) || type.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("challenge", out var challenge) || challenge.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("origin", out var origin) || origin.ValueKind != JsonValueKind.String)
                return null;
            var crossOrigin = root.TryGetProperty("crossOrigin", out var co) && co.ValueKind == JsonValueKind.True;
            return new ClientData(type.GetString()!, challenge.GetString()!, origin.GetString()!, crossOrigin);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>The <c>authData</c> of an attestation object (CBOR map with fmt, attStmt, authData).</summary>
    public static byte[]? AuthenticatorDataOfAttestation(byte[] attestationObject)
    {
        try
        {
            var reader = new CborReader(attestationObject, CborConformanceMode.Lax);
            var entries = reader.ReadStartMap();
            byte[]? authData = null;
            for (var i = 0; entries is null || i < entries; i++)
            {
                if (entries is null && reader.PeekState() == CborReaderState.EndMap) break;
                var key = reader.ReadTextString();
                if (key == "authData") authData = reader.ReadByteString();
                else reader.SkipValue();
            }
            return authData;
        }
        catch (CborContentException) { return null; }
        catch (InvalidOperationException) { return null; }
    }

    /// <summary>Parses authenticator data (§6.1); with attested credential data when the AT flag is set.</summary>
    public static AuthenticatorData? ParseAuthenticatorData(byte[] data)
    {
        if (data.Length < 37) return null;
        var rpIdHash = data[..32];
        var flags = data[32];
        var signCount = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(33, 4));
        if ((flags & FlagAttestedCredentialData) == 0) return new AuthenticatorData(rpIdHash, flags, signCount, null, null);

        // aaguid (16) | credentialIdLength (2) | credentialId | credentialPublicKey (COSE, CBOR) | extensions (ignored)
        const int offset = 37 + 16;
        if (data.Length < offset + 2) return null;
        var idLength = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(offset, 2));
        if (idLength is 0 or > 1023 || data.Length < offset + 2 + idLength + 1) return null;
        var credentialId = data.AsSpan(offset + 2, idLength).ToArray();
        var keyStart = offset + 2 + idLength;
        try
        {
            var reader = new CborReader(data.AsMemory(keyStart), CborConformanceMode.Lax, allowMultipleRootLevelValues: true);
            reader.SkipValue();
            var keyLength = data.Length - keyStart - reader.BytesRemaining;
            return new AuthenticatorData(rpIdHash, flags, signCount, credentialId, data.AsSpan(keyStart, keyLength).ToArray());
        }
        catch (CborContentException) { return null; }
        catch (InvalidOperationException) { return null; }
    }

    /// <summary>The COSE algorithm of a supported public key (ES256 on P-256, RS256 with ≥ 2048 bits), else <c>null</c>.</summary>
    public static int? AlgorithmOf(byte[] coseKey)
    {
        try
        {
            using var key = Load(coseKey, out var alg);
            return key is null ? null : alg;
        }
        catch (CborContentException) { return null; }
        catch (InvalidOperationException) { return null; }
        catch (CryptographicException) { return null; }
    }

    /// <summary>Verifies an assertion signature over <c>authenticatorData || SHA-256(clientDataJSON)</c> (§7.2 step 20).</summary>
    public static bool VerifySignature(byte[] coseKey, byte[] authenticatorData, byte[] clientDataJson, byte[] signature)
    {
        try
        {
            var signed = new byte[authenticatorData.Length + 32];
            authenticatorData.CopyTo(signed, 0);
            SHA256.HashData(clientDataJson, signed.AsSpan(authenticatorData.Length));

            using var key = Load(coseKey, out var alg);
            return key switch
            {
                ECDsa ec when alg == Es256 => ec.VerifyData(signed, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence),
                RSA rsa when alg == Rs256 => rsa.VerifyData(signed, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                _ => false,
            };
        }
        catch (CborContentException) { return false; }
        catch (InvalidOperationException) { return false; }
        catch (CryptographicException) { return false; }
    }

    /// <summary>A COSE_Key (RFC 9052/9053) as .NET key: EC2 / P-256 / ES256 or RSA / RS256.</summary>
    private static AsymmetricAlgorithm? Load(byte[] coseKey, out int alg)
    {
        alg = 0;
        var reader = new CborReader(coseKey, CborConformanceMode.Lax);
        var entries = reader.ReadStartMap();
        // labels -1/-2/-3 mean different things per key type (EC2: crv, x, y – RSA: n, e): collect, then interpret
        int? kty = null, crv = null;
        byte[]? minus1 = null, minus2 = null, minus3 = null;
        for (var i = 0; entries is null || i < entries; i++)
        {
            if (entries is null && reader.PeekState() == CborReaderState.EndMap) break;
            if (reader.PeekState() is not (CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger)) { reader.SkipValue(); reader.SkipValue(); continue; }
            switch (reader.ReadInt32())
            {
                case 1: kty = reader.ReadInt32(); break;
                case 3: alg = reader.ReadInt32(); break;
                case -1 when reader.PeekState() is CborReaderState.UnsignedInteger or CborReaderState.NegativeInteger: crv = reader.ReadInt32(); break;
                case -1: minus1 = reader.ReadByteString(); break;
                case -2: minus2 = reader.ReadByteString(); break;
                case -3: minus3 = reader.ReadByteString(); break;
                default: reader.SkipValue(); break;
            }
        }
        reader.ReadEndMap();

        if (kty == 2 && alg == Es256 && crv == 1 && minus2 is { Length: 32 } && minus3 is { Length: 32 })
            return ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = minus2, Y = minus3 } });
        // the bit length of the modulus counts, not its encoded length: zero bytes in front would pass a weak key off
        // as 2048 bit (RSA.KeySize only counts the bytes)
        if (kty == 3 && alg == Rs256 && minus1 is not null && minus2 is { Length: > 0 }
            && new BigInteger(minus1, isUnsigned: true, isBigEndian: true).GetBitLength() >= 2048)
        {
            var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Modulus = minus1, Exponent = minus2 });
            return rsa;
        }
        return null;
    }

    /// <summary>True if the authenticator data was produced for <paramref name="rpId"/>.</summary>
    public static bool IsForRelyingParty(AuthenticatorData data, string rpId) =>
        CryptographicOperations.FixedTimeEquals(data.RpIdHash, SHA256.HashData(Encoding.UTF8.GetBytes(rpId)));

    /// <summary>The origin's host is the relying party id or a subdomain of it (§13.4.9).</summary>
    public static bool OriginMatchesRelyingParty(string origin, string rpId) =>
        Uri.TryCreate(origin, UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttps || (uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback))
        && (string.Equals(uri.Host, rpId, StringComparison.OrdinalIgnoreCase)
            || uri.Host.EndsWith("." + rpId, StringComparison.OrdinalIgnoreCase));

    public static string NewChallenge() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

    public static byte[]? FromBase64Url(string? value)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 8192) return null;
        try { return Base64Url.DecodeFromChars(value); }
        catch (FormatException) { return null; }
    }
}
