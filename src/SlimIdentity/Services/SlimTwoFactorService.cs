using Microsoft.AspNetCore.DataProtection;
using SlimIdentity.Security;

namespace SlimIdentity.Services;

/// <summary>
/// 2FA building blocks shared by login and management endpoints:
/// TOTP secrets encrypted at rest, user-bound recovery-code hashes and replay protection.
/// </summary>
internal sealed class SlimTwoFactorService(
    ISlimTwoFactorStore store,
    IDataProtectionProvider dataProtection,
    IOptions<SlimIdentityOptions> options,
    TimeProvider time,
    ILogger<SlimTwoFactorService> logger)
{
    private readonly IDataProtector _secretProtector = dataProtection.CreateProtector(SlimIdentityDefaults.TotpSecretProtectionPurpose);

    /// <summary>Result of reading the authenticator secret.</summary>
    internal readonly record struct TotpSecret(bool Configured, string? Value);

    /// <summary>
    /// Reads and decrypts the TOTP secret. <see cref="TotpSecret.Configured"/> is true even if decryption fails
    /// (lost key ring) – the user then has to use a recovery code, and is never silently downgraded to e-mail codes.
    /// </summary>
    public async Task<TotpSecret> GetSecretAsync(SlimUser user, CancellationToken ct)
    {
        var stored = await store.GetTotpSecretAsync(user, ct);
        if (string.IsNullOrEmpty(stored)) return new TotpSecret(false, null);
        try
        {
            return new TotpSecret(true, _secretProtector.Unprotect(stored));
        }
        catch (CryptographicException ex)
        {
            Log.TotpSecretUndecryptable(logger, ex, user.Id);
            return new TotpSecret(true, null);
        }
    }

    public Task SetSecretAsync(SlimUser user, string base32Secret, CancellationToken ct) =>
        store.SetTotpSecretAsync(user, _secretProtector.Protect(base32Secret), ct);

    public Task RemoveSecretAsync(SlimUser user, CancellationToken ct) => store.SetTotpSecretAsync(user, string.Empty, ct);

    /// <summary>Verifies a TOTP code and consumes its time step (a code is accepted only once).</summary>
    public async Task<bool> VerifyTotpAsync(SlimUser user, string secret, string? code, CancellationToken ct)
    {
        if (!SlimTotp.TryVerify(secret, code, time.GetUtcNow(), options.Value.TwoFactor.TotpTimeStepTolerance, out var step))
            return false;
        if (await store.TryMarkCodeUsedAsync(user, SlimTotp.StepStart(step), ct)) return true;

        Log.TwoFactorCodeReplayed(logger, user.Id);
        return false;
    }

    /// <summary>Consumes an e-mail code by its issue time (unix seconds) – the same code cannot be used twice.</summary>
    public async Task<bool> ConsumeEmailCodeAsync(SlimUser user, long issuedAt, CancellationToken ct)
    {
        if (await store.TryMarkCodeUsedAsync(user, issuedAt, ct)) return true;
        Log.TwoFactorCodeReplayed(logger, user.Id);
        return false;
    }

    /// <summary>Generates new recovery codes, replaces the stored hashes and returns the codes (shown once).</summary>
    public async Task<IReadOnlyList<string>> RegenerateRecoveryCodesAsync(SlimUser user, CancellationToken ct)
    {
        var codes = SlimRecoveryCodes.Generate(options.Value.TwoFactor.RecoveryCodeCount);
        await store.StoreRecoveryCodesAsync(user, codes.Select(c => SlimRecoveryCodes.Hash(user.Id, c)).ToList(), ct);
        return codes;
    }

    public Task RemoveRecoveryCodesAsync(SlimUser user, CancellationToken ct) =>
        store.StoreRecoveryCodesAsync(user, Array.Empty<string>(), ct);

    public Task<bool> ConsumeRecoveryCodeAsync(SlimUser user, string code, CancellationToken ct) =>
        store.ValidateAndConsumeRecoveryCodeAsync(user, SlimRecoveryCodes.Hash(user.Id, code), ct);
}
