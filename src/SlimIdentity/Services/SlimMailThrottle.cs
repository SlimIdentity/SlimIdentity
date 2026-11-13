namespace SlimIdentity.Services;

/// <summary>
/// Limits mails per recipient and kind (attack scenario "mail bombing": the per-IP rate limit does not stop a
/// distributed attacker from flooding one inbox with reset or verification mails). Requests over the limit get the
/// same answer as always – the mail is just not sent. Counted in <see cref="ISlimSharedState"/>: with a shared
/// implementation the limit holds across instances, with the in-memory default per instance.
/// </summary>
internal sealed class SlimMailThrottle(SlimSharedStateAccess state)
{
    internal static readonly TimeSpan Window = TimeSpan.FromMinutes(15);
    internal const int PerKindAndRecipient = 3;
    internal const int CodesPerRecipient = 5;   // sign-in codes: users legitimately retry a sign-in more often

    /// <summary>True if a mail of <paramref name="kind"/> may be sent to <paramref name="recipient"/> now (and counts it).</summary>
    public async Task<bool> TryAcquireAsync(string kind, string recipient, CancellationToken ct)
    {
        var limit = kind is SlimEmailKinds.TwoFactorCode or SlimEmailKinds.VerificationCode ? CodesPerRecipient : PerKindAndRecipient;
        var count = await state.CountAsync(SlimSharedStateAccess.Mail, $"{kind}\n{recipient.Trim().ToUpperInvariant()}", Window, ct);
        return count <= limit;
    }
}