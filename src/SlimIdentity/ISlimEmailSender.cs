namespace SlimIdentity;

/// <summary>
/// Mandatory communication bridge (no SMTP dependency in the core).
/// When <see cref="SlimLinkOptions"/> contain a URL template the second argument is a ready-to-use link,
/// otherwise it is the raw token. Most mails are sent from a background queue (see <see cref="SlimEmailOptions"/>),
/// so implementations must not depend on the current <c>HttpContext</c>.
/// </summary>
public interface ISlimEmailSender
{
    /// <summary>E-mail verification after registration or on <c>/resend-verification</c>.</summary>
    Task SendVerificationEmailAsync(string email, string verificationTokenOrLink, CancellationToken ct);

    /// <summary>Password reset link (<c>/forgot-password</c>).</summary>
    Task SendPasswordResetEmailAsync(string email, string resetTokenOrLink, CancellationToken ct);

    /// <summary>6-digit sign-in code for users with e-mail based 2FA. Sent directly (the user is waiting for it).</summary>
    Task SendTwoFactorCodeAsync(string email, string code, CancellationToken ct);

    /// <summary>
    /// Confirmation link for a requested e-mail change, sent to the <b>new</b> address
    /// (<c>/change-email</c>, link template <c>Links.EmailChangeUrl</c>). The address changes only when the link is confirmed.
    /// </summary>
    Task SendEmailChangeConfirmationAsync(string newEmail, string confirmationTokenOrLink, CancellationToken ct);

    /// <summary>
    /// Optional: informs the <b>old</b> address after the e-mail change was confirmed ("your address was changed –
    /// not you? contact support"). Default: no mail.
    /// </summary>
    Task SendEmailChangedNotificationAsync(string oldEmail, string newEmail, CancellationToken ct) => Task.CompletedTask;

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
