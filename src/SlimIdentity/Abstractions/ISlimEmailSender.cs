using SlimIdentity;

namespace SlimIdentity.Abstractions;

/// <summary>
/// Mandatory communication bridge (no SMTP dependency in the core).
/// When <see cref="SlimLinkOptions"/> contain a URL template the second argument is a ready-to-use link,
/// otherwise it is the raw token.
/// </summary>
public interface ISlimEmailSender
{
    Task SendVerificationEmailAsync(string email, string verificationTokenOrLink, CancellationToken ct);
    Task SendPasswordResetEmailAsync(string email, string resetTokenOrLink, CancellationToken ct);
    Task SendTwoFactorCodeAsync(string email, string code, CancellationToken ct);

    /// <summary>
    /// Optional: sent when someone tries to <c>/register</c> with an address that already has an account
    /// ("you already have an account – forgot your password?"). The caller always gets the same answer;
    /// only the real owner of the mailbox learns about the attempt. Default: no mail.
    /// </summary>
    Task SendAccountExistsEmailAsync(string email, CancellationToken ct) => Task.CompletedTask;

    /// <summary>
    /// Optional: the account was locked after repeated failed sign-ins ("someone tried to sign in to your account").
    /// Sent once per series (first lockout since the last successful sign-in). Default: no mail.
    /// </summary>
    Task SendLockoutNotificationEmailAsync(string email, DateTimeOffset lockoutEndUtc, CancellationToken ct) => Task.CompletedTask;
}
