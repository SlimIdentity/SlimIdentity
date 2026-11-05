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
        logger.LogWarning("[SlimIdentity:NullEmailSender] Verification for {Email}: {Link}", email, verificationTokenOrLink);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task SendPasswordResetEmailAsync(string email, string resetTokenOrLink, CancellationToken ct)
    {
        logger.LogWarning("[SlimIdentity:NullEmailSender] Password reset for {Email}: {Link}", email, resetTokenOrLink);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task SendTwoFactorCodeAsync(string email, string code, CancellationToken ct)
    {
        logger.LogWarning("[SlimIdentity:NullEmailSender] 2FA code for {Email}: {Code}", email, code);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task SendAccountExistsEmailAsync(string email, CancellationToken ct)
    {
        logger.LogWarning("[SlimIdentity:NullEmailSender] Registration attempt for existing account {Email}", email);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task SendLockoutNotificationEmailAsync(string email, DateTimeOffset lockoutEndUtc, CancellationToken ct)
    {
        logger.LogWarning("[SlimIdentity:NullEmailSender] Account {Email} locked until {LockoutEnd}", email, lockoutEndUtc);
        return Task.CompletedTask;
    }
}
