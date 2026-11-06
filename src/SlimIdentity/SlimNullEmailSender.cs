namespace SlimIdentity;

/// <summary>
/// Development-only sender that writes tokens / codes to the log instead of sending mail.
/// Never use in production – the log then contains live credentials.
/// </summary>
public sealed class SlimNullEmailSender(ILogger<SlimNullEmailSender> logger) : ISlimEmailSender
{
    /// <inheritdoc />
    public Task SendVerificationEmailAsync(string email, string verificationTokenOrLink, CancellationToken ct)
    {
        Log.NullMailVerification(logger, email, verificationTokenOrLink);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task SendPasswordResetEmailAsync(string email, string resetTokenOrLink, CancellationToken ct)
    {
        Log.NullMailPasswordReset(logger, email, resetTokenOrLink);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task SendTwoFactorCodeAsync(string email, string code, CancellationToken ct)
    {
        Log.NullMailTwoFactorCode(logger, email, code);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task SendEmailChangeConfirmationAsync(string newEmail, string confirmationTokenOrLink, CancellationToken ct)
    {
        Log.NullMailEmailChange(logger, newEmail, confirmationTokenOrLink);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task SendEmailChangedNotificationAsync(string oldEmail, string newEmail, CancellationToken ct)
    {
        Log.NullMailEmailChanged(logger, oldEmail, newEmail);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task SendAccountExistsEmailAsync(string email, CancellationToken ct)
    {
        Log.NullMailAccountExists(logger, email);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task SendLockoutNotificationEmailAsync(string email, DateTimeOffset lockoutEndUtc, CancellationToken ct)
    {
        Log.NullMailLockout(logger, email, lockoutEndUtc);
        return Task.CompletedTask;
    }
}
