using System.Buffers.Binary;
using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SlimIdentity.Tests.Infrastructure;

/// <summary>
/// A software authenticator that produces WebAuthn responses exactly like a browser + authenticator would – with knobs
/// to produce every kind of broken or malicious response.
/// </summary>
public sealed class SoftwarePasskey : IDisposable
{
    private readonly ECDsa? _ec;
    private readonly RSA? _rsa;

    public SoftwarePasskey(bool rsa = false, int rsaBits = 2048)
    {
        if (rsa) _rsa = RSA.Create(rsaBits); else _ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CredentialId = RandomNumberGenerator.GetBytes(16);
    }

    public byte[] CredentialId { get; init; }
    public string IdBase64Url => Base64Url.EncodeToString(CredentialId);
    /// <summary>Signature counter; 0 like most synced passkeys, or counting.</summary>
    public uint Counter { get; set; }
    public bool CountUp { get; set; }
    /// <summary>The user handle (base64url of the user id) remembered from the registration – sent on sign-in.</summary>
    public string? UserHandle { get; set; }

    public sealed record Tamper(string? Origin = null, string? RpId = null, string? Type = null, string? Challenge = null,
        bool UserVerified = true, bool CrossOrigin = false, SoftwarePasskey? SignWith = null, uint? Counter = null,
        string? UserHandle = null);

    /// <summary>navigator.credentials.create: the JSON the client posts (credential).</summary>
    public object Create(JsonElement options, string origin, Tamper? t = null)
    {
        t ??= new Tamper();
        UserHandle = options.GetProperty("user").GetProperty("id").GetString();
        var rpId = t.RpId ?? options.GetProperty("rp").GetProperty("id").GetString()!;
        var clientData = ClientData(t.Type ?? "webauthn.create", t.Challenge ?? options.GetProperty("challenge").GetString()!, t.Origin ?? origin, t.CrossOrigin);

        var authData = AuthData(rpId, t.UserVerified, Counter, attested: true);
        var attestation = new CborWriter();
        attestation.WriteStartMap(3);
        attestation.WriteTextString("fmt"); attestation.WriteTextString("none");
        attestation.WriteTextString("attStmt"); attestation.WriteStartMap(0); attestation.WriteEndMap();
        attestation.WriteTextString("authData"); attestation.WriteByteString(authData);
        attestation.WriteEndMap();

        return new
        {
            id = IdBase64Url,
            rawId = IdBase64Url,
            type = "public-key",
            response = new { clientDataJSON = Base64Url.EncodeToString(clientData), attestationObject = Base64Url.EncodeToString(attestation.Encode()) },
        };
    }

    /// <summary>navigator.credentials.get: the JSON the client posts (credential).</summary>
    public object Get(JsonElement options, string origin, Tamper? t = null)
    {
        t ??= new Tamper();
        if (CountUp) Counter++;
        var rpId = t.RpId ?? options.GetProperty("rpId").GetString()!;
        var clientData = ClientData(t.Type ?? "webauthn.get", t.Challenge ?? options.GetProperty("challenge").GetString()!, t.Origin ?? origin, t.CrossOrigin);
        var authData = AuthData(rpId, t.UserVerified, t.Counter ?? Counter, attested: false);

        var signed = authData.Concat(SHA256.HashData(clientData)).ToArray();
        var signer = t.SignWith ?? this;
        var signature = signer._ec is not null
            ? signer._ec.SignData(signed, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence)
            : signer._rsa!.SignData(signed, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return new
        {
            id = IdBase64Url,
            rawId = IdBase64Url,
            type = "public-key",
            response = new
            {
                clientDataJSON = Base64Url.EncodeToString(clientData),
                authenticatorData = Base64Url.EncodeToString(authData),
                signature = Base64Url.EncodeToString(signature),
                userHandle = t.UserHandle ?? UserHandle,
            },
        };
    }

    private static byte[] ClientData(string type, string challenge, string origin, bool crossOrigin) =>
        JsonSerializer.SerializeToUtf8Bytes(new { type, challenge, origin, crossOrigin });

    private byte[] AuthData(string rpId, bool userVerified, uint counter, bool attested)
    {
        var data = new List<byte>(SHA256.HashData(Encoding.UTF8.GetBytes(rpId)));
        data.Add((byte)(0x01 | (userVerified ? 0x04 : 0) | (attested ? 0x40 : 0)));
        var count = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(count, counter);
        data.AddRange(count);
        if (!attested) return [.. data];

        data.AddRange(new byte[16]);   // aaguid
        var length = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(length, (ushort)CredentialId.Length);
        data.AddRange(length);
        data.AddRange(CredentialId);
        data.AddRange(CoseKey());
        return [.. data];
    }

    private byte[] CoseKey()
    {
        var w = new CborWriter(CborConformanceMode.Ctap2Canonical);
        if (_ec is not null)
        {
            var p = _ec.ExportParameters(false);
            w.WriteStartMap(5);
            w.WriteInt32(1); w.WriteInt32(2);        // kty: EC2
            w.WriteInt32(3); w.WriteInt32(-7);       // alg: ES256
            w.WriteInt32(-1); w.WriteInt32(1);       // crv: P-256
            w.WriteInt32(-2); w.WriteByteString(p.Q.X!);
            w.WriteInt32(-3); w.WriteByteString(p.Q.Y!);
        }
        else
        {
            var p = _rsa!.ExportParameters(false);
            w.WriteStartMap(4);
            w.WriteInt32(1); w.WriteInt32(3);        // kty: RSA
            w.WriteInt32(3); w.WriteInt32(-257);     // alg: RS256
            // a modulus shorter than 256 bytes is sent zero-padded – a weak key that looks like 2048 bit
            w.WriteInt32(-1); w.WriteByteString(p.Modulus!.Length >= 256 ? p.Modulus : [.. new byte[256 - p.Modulus.Length], .. p.Modulus]);
            w.WriteInt32(-2); w.WriteByteString(p.Exponent!);
        }
        w.WriteEndMap();
        return w.Encode();
    }

    public void Dispose()
    {
        _ec?.Dispose();
        _rsa?.Dispose();
    }
}

/// <summary>In-memory <see cref="ISlimPasskeyStore"/> with the required atomicity.</summary>
public sealed class TestPasskeyStore : ISlimPasskeyStore
{
    private readonly ConcurrentDictionary<string, SlimPasskey> _keys = new(StringComparer.Ordinal);
    private static string Key(byte[] id) => Convert.ToHexString(id);

    public Task<IReadOnlyList<SlimPasskey>> GetPasskeysAsync(string userId, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<SlimPasskey>>(_keys.Values.Where(p => p.UserId == userId).OrderBy(p => p.CreatedUtc).Select(Clone).ToList());

    public Task<SlimPasskey?> FindPasskeyAsync(byte[] credentialId, CancellationToken ct) =>
        Task.FromResult(_keys.TryGetValue(Key(credentialId), out var p) ? Clone(p) : null);

    public Task<bool> AddPasskeyAsync(SlimPasskey passkey, CancellationToken ct) => Task.FromResult(_keys.TryAdd(Key(passkey.CredentialId), Clone(passkey)));

    public Task<bool> TryRecordUseAsync(byte[] credentialId, uint expectedSignCount, uint signCount, long challengeIssuedAt, DateTimeOffset usedUtc, CancellationToken ct)
    {
        if (!_keys.TryGetValue(Key(credentialId), out var p)) return Task.FromResult(false);
        lock (p)
        {
            if (p.SignCount != expectedSignCount || (p.LastChallengeAt is { } last && last >= challengeIssuedAt)) return Task.FromResult(false);
            p.SignCount = signCount;
            p.LastChallengeAt = challengeIssuedAt;
            p.LastUsedUtc = usedUtc;
            return Task.FromResult(true);
        }
    }

    public Task<bool> RenamePasskeyAsync(string userId, byte[] credentialId, string name, CancellationToken ct)
    {
        if (!_keys.TryGetValue(Key(credentialId), out var p) || p.UserId != userId) return Task.FromResult(false);
        p.Name = name;
        return Task.FromResult(true);
    }

    public Task RemovePasskeysAsync(string userId, CancellationToken ct)
    {
        foreach (var (id, p) in _keys)
            if (p.UserId == userId) _keys.TryRemove(id, out _);
        return Task.CompletedTask;
    }

    public Task<bool> RemovePasskeyAsync(string userId, byte[] credentialId, CancellationToken ct) =>
        Task.FromResult(_keys.TryGetValue(Key(credentialId), out var p) && p.UserId == userId
            && ((ICollection<KeyValuePair<string, SlimPasskey>>)_keys).Remove(new KeyValuePair<string, SlimPasskey>(Key(credentialId), p)));

    private static SlimPasskey Clone(SlimPasskey p) => new()
    {
        UserId = p.UserId, CredentialId = p.CredentialId, PublicKey = p.PublicKey, SignCount = p.SignCount,
        LastChallengeAt = p.LastChallengeAt, Name = p.Name, CreatedUtc = p.CreatedUtc, LastUsedUtc = p.LastUsedUtc,
    };
}
