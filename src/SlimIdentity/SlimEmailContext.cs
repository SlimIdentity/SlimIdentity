using System.Collections.ObjectModel;

namespace SlimIdentity;

/// <summary>
/// What every <see cref="ISlimEmailSender"/> call receives besides recipient and link: which mail it is, whom it is
/// about, the culture of the request that caused it and host data captured at that moment. Most mails are sent from a
/// background queue – everything a template needs (language, tenant, branding) must come from here, not from the
/// current <c>HttpContext</c> or thread culture.
/// </summary>
public sealed class SlimEmailContext
{
    private static readonly IReadOnlyDictionary<string, string> NoItems = ReadOnlyDictionary<string, string>.Empty;

    /// <summary>Kind of mail, one of <see cref="SlimEmailKinds"/>.</summary>
    public required string Kind { get; init; }

    /// <summary>
    /// Id of the account the mail is about (for <c>account-exists</c> on an e-mail change: the account that owns the
    /// address). <c>null</c> only when no account is involved.
    /// </summary>
    public string? UserId { get; init; }

    /// <summary>UI culture of the request (from <c>UseRequestLocalization</c>, else the server's culture).</summary>
    public required CultureInfo Culture { get; init; }

    /// <summary>Host data added by <see cref="ISlimEmailContextEnricher"/> while the request existed, e.g. a tenant.</summary>
    public IReadOnlyDictionary<string, string> Items { get; init; } = NoItems;
}

/// <summary>The kinds of mail SlimIdentity sends (<see cref="SlimEmailContext.Kind"/>, metrics tag <c>kind</c>).</summary>
public static class SlimEmailKinds
{
    /// <summary><see cref="ISlimEmailSender.SendVerificationEmailAsync"/>.</summary>
    public const string Verification = "verification";
    /// <summary><see cref="ISlimEmailSender.SendPasswordResetEmailAsync"/>.</summary>
    public const string PasswordReset = "password-reset";
    /// <summary><see cref="ISlimEmailSender.SendAccountExistsEmailAsync"/>.</summary>
    public const string AccountExists = "account-exists";
    /// <summary><see cref="ISlimEmailSender.SendEmailChangeCodeAsync"/>.</summary>
    public const string EmailChange = "email-change";
    /// <summary><see cref="ISlimEmailSender.SendEmailChangedNotificationAsync"/>.</summary>
    public const string EmailChanged = "email-changed";
    /// <summary><see cref="ISlimEmailSender.SendLockoutNotificationEmailAsync"/>.</summary>
    public const string LockoutNotification = "lockout-notification";
    /// <summary><see cref="ISlimEmailSender.SendTwoFactorCodeAsync"/>.</summary>
    public const string TwoFactorCode = "two-factor-code";
    /// <summary><see cref="ISlimEmailSender.SendEmailVerificationCodeAsync"/>.</summary>
    public const string VerificationCode = "verification-code";
}

/// <summary>
/// Optional: adds host data to <see cref="SlimEmailContext.Items"/> while the request still exists – e.g. the tenant
/// from the host name, a brand or the front-end origin. Register with <c>AddEmailContextEnricher&lt;T&gt;()</c>.
/// Never add secrets: the context may be logged by your sender.
/// </summary>
public interface ISlimEmailContextEnricher
{
    /// <summary>Called for every mail, in the request that causes it.</summary>
    void Enrich(HttpContext httpContext, string kind, string? userId, IDictionary<string, string> items);
}
