namespace SlimIdentity;

/// <summary>
/// Communication bridge (no SMTP dependency in the core).
/// When <see cref="SlimLinkOptions"/> contain a URL template the link argument is a ready-to-use link, otherwise it is
/// the raw token. Most mails are sent from a background queue (see <see cref="SlimEmailOptions"/>), so implementations
/// must not depend on the current <c>HttpContext</c> or thread culture – <see cref="SlimEmailContext"/> carries the
/// account, the request's culture and host data captured at request time.
/// </summary>
public interface ISlimEmailSender
{
    /// <summary>E-mail verification after registration or on <c>/resend-verification</c>.</summary>
    Task SendVerificationEmailAsync(SlimEmailContext context, string email, string verificationTokenOrLink, CancellationToken ct);

    /// <summary>Password reset link (<c>/forgot-password</c>).</summary>
    Task SendPasswordResetEmailAsync(SlimEmailContext context, string email, string resetTokenOrLink, CancellationToken ct);

    /// <summary>6-digit sign-in code for users with e-mail based 2FA. Sent directly (the user is waiting for it).</summary>
    Task SendTwoFactorCodeAsync(SlimEmailContext context, string email, string code, CancellationToken ct);

    /// <summary>
    /// 6-digit code that confirms the address during a sign-in (step <c>verify_email</c>, <c>POST /auth/login/verify-email</c>).
    /// Sent directly (the user is waiting for it).
    /// </summary>
    Task SendEmailVerificationCodeAsync(SlimEmailContext context, string email, string code, CancellationToken ct);

    /// <summary>
    /// Confirmation link for a requested e-mail change, sent to the <b>new</b> address
    /// (<c>/change-email</c>, link from <c>Links.BaseUrl</c> or <c>Links.EmailChangeUrl</c>). The address changes only when the link is confirmed.
    /// </summary>
    Task SendEmailChangeConfirmationAsync(SlimEmailContext context, string newEmail, string confirmationTokenOrLink, CancellationToken ct);

    /// <summary>
    /// Optional: informs the <b>old</b> address after the e-mail change was confirmed ("your address was changed –
    /// not you? contact support"). Default: no mail.
    /// </summary>
    Task SendEmailChangedNotificationAsync(SlimEmailContext context, string oldEmail, string newEmail, CancellationToken ct) => Task.CompletedTask;

    /// <summary>
    /// Optional: sent when someone tries to <c>/register</c> with an address that already has an account
    /// ("you already have an account – forgot your password?"). The caller always gets the same answer;
    /// only the real owner of the mailbox learns about the attempt. Default: no mail.
    /// </summary>
    Task SendAccountExistsEmailAsync(SlimEmailContext context, string email, CancellationToken ct) => Task.CompletedTask;

    /// <summary>
    /// Optional: the account was locked after repeated failed sign-ins ("someone tried to sign in to your account").
    /// Sent once per series (first lockout since the last successful sign-in). Default: no mail.
    /// </summary>
    Task SendLockoutNotificationEmailAsync(SlimEmailContext context, string email, DateTimeOffset lockoutEndUtc, CancellationToken ct) => Task.CompletedTask;
}
