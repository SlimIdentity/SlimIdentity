namespace SlimIdentity;

/// <summary>
/// Optional capability: passkeys (WebAuthn) – sign-in without a password, phishing-resistant, counted as multi-factor.
/// Registering it maps <c>/passkeys/*</c>. Credential ids are unique across all users.
/// </summary>
public interface ISlimPasskeyStore
{
    /// <summary>The passkeys of a user (sign-in methods list, exclude list at registration).</summary>
    Task<IReadOnlyList<SlimPasskey>> GetPasskeysAsync(string userId, CancellationToken ct);

    /// <summary>The passkey with this credential id (any user), or <c>null</c>.</summary>
    Task<SlimPasskey?> FindPasskeyAsync(byte[] credentialId, CancellationToken ct);

    /// <summary>Stores a new passkey. Returns <c>false</c> if the credential id already exists (unique index).</summary>
    Task<bool> AddPasskeyAsync(SlimPasskey passkey, CancellationToken ct);

    /// <summary>
    /// Records a sign-in <b>atomically</b> – one statement, e.g. <c>UPDATE passkeys SET sign_count = @signCount,
    /// last_challenge_at = @challengeIssuedAt, last_used_utc = @usedUtc WHERE credential_id = @id AND sign_count =
    /// @expectedSignCount AND (last_challenge_at IS NULL OR last_challenge_at &lt; @challengeIssuedAt)</c>. Returns
    /// <c>false</c> if no row matched: a replayed sign-in or a parallel one with the same counter.
    /// </summary>
    Task<bool> TryRecordUseAsync(byte[] credentialId, uint expectedSignCount, uint signCount, long challengeIssuedAt, DateTimeOffset usedUtc, CancellationToken ct);

    /// <summary>Renames a passkey of <b>this</b> user. Returns <c>false</c> if it does not belong to the user.</summary>
    Task<bool> RenamePasskeyAsync(string userId, byte[] credentialId, string name, CancellationToken ct);

    /// <summary>Removes a passkey of <b>this</b> user. Returns <c>false</c> if it does not belong to the user.</summary>
    Task<bool> RemovePasskeyAsync(string userId, byte[] credentialId, CancellationToken ct);
}

/// <summary>A registered passkey. SlimIdentity stores only the public key – the private key never leaves the device.</summary>
public sealed class SlimPasskey
{
    /// <summary>Owner.</summary>
    public required string UserId { get; set; }
    /// <summary>Credential id chosen by the authenticator (unique, at most 1023 bytes).</summary>
    public required byte[] CredentialId { get; set; }
    /// <summary>The credential's public key, COSE-encoded as received.</summary>
    public required byte[] PublicKey { get; set; }
    /// <summary>Signature counter of the authenticator (0 for most synced passkeys).</summary>
    public uint SignCount { get; set; }
    /// <summary>Unix milliseconds of the challenge of the last sign-in – each challenge counts once.</summary>
    public long? LastChallengeAt { get; set; }
    /// <summary>Display name chosen by the user ("MacBook", "Phone").</summary>
    public string Name { get; set; } = "Passkey";
    /// <summary>Registration time.</summary>
    public DateTimeOffset CreatedUtc { get; set; }
    /// <summary>Last sign-in.</summary>
    public DateTimeOffset? LastUsedUtc { get; set; }
}
