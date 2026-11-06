namespace SlimIdentity.Diagnostics;

/// <summary>
/// All log messages of SlimIdentity (source-generated, allocation-free). Event ids are stable and can be used for
/// alerting: 1xxx sign-in, 2xxx two-factor, 3xxx tokens and sessions, 4xxx account, 5xxx external login,
/// 6xxx impersonation, 7xxx mail, 8xxx configuration / infrastructure.
/// </summary>
internal static partial class Log
{
    // ---------------------------------------------------------------- 1xxx sign-in
    [LoggerMessage(1001, LogLevel.Warning, "SlimIdentity: user {UserId} locked out until {LockoutEnd} (lockout #{Number}).")]
    public static partial void LockedOut(ILogger logger, string userId, DateTimeOffset? lockoutEnd, int number);

    [LoggerMessage(1002, LogLevel.Information, "SlimIdentity: password hash of user {UserId} upgraded.")]
    public static partial void PasswordRehashed(ILogger logger, string userId);

    [LoggerMessage(1003, LogLevel.Warning, "SlimIdentity: stored password hash of user {UserId} is malformed.")]
    public static partial void MalformedPasswordHash(ILogger logger, Exception exception, string userId);

    [LoggerMessage(1004, LogLevel.Warning, "SlimIdentity: CSRF origin check failed – request origin {Origin} vs. API origin {Self}. Behind a TLS-terminating reverse proxy call app.UseForwardedHeaders() (X-Forwarded-Proto) with KnownProxies/KnownIPNetworks.")]
    public static partial void CsrfSchemeMismatch(ILogger logger, string origin, string self);

    [LoggerMessage(1005, LogLevel.Information, "SlimIdentity: CSRF origin {Origin} rejected (API origin {Self}, not in TrustedOrigins).")]
    public static partial void CsrfOriginRejected(ILogger logger, string origin, string self);

    // ---------------------------------------------------------------- 2xxx two-factor
    [LoggerMessage(2001, LogLevel.Error, "SlimIdentity: user {UserId} has TwoFactorEnabled but no ISlimTwoFactorStore is registered. Login denied.")]
    public static partial void TwoFactorStoreMissing(ILogger logger, string userId);

    [LoggerMessage(2002, LogLevel.Information, "SlimIdentity: user {UserId} signed in with a recovery code.")]
    public static partial void RecoveryCodeUsed(ILogger logger, string userId);

    [LoggerMessage(2003, LogLevel.Information, "SlimIdentity: 2FA enabled for user {UserId}.")]
    public static partial void TwoFactorEnabled(ILogger logger, string userId);

    [LoggerMessage(2004, LogLevel.Information, "SlimIdentity: 2FA disabled for user {UserId}.")]
    public static partial void TwoFactorDisabled(ILogger logger, string userId);

    [LoggerMessage(2005, LogLevel.Warning, "SlimIdentity: replayed two-factor code for user {UserId} rejected.")]
    public static partial void TwoFactorCodeReplayed(ILogger logger, string userId);

    [LoggerMessage(2007, LogLevel.Information, "SlimIdentity: all remembered 2FA devices of user {UserId} forgotten (security stamp rotated).")]
    public static partial void RememberedDevicesForgotten(ILogger logger, string userId);

    [LoggerMessage(2006, LogLevel.Error, "SlimIdentity: the TOTP secret of user {UserId} cannot be decrypted (Data Protection key ring lost or changed?). The user has to sign in with a recovery code.")]
    public static partial void TotpSecretUndecryptable(ILogger logger, Exception exception, string userId);

    [LoggerMessage(2008, LogLevel.Warning, "SlimIdentity: reused or superseded sign-in challenge for user {UserId} rejected.")]
    public static partial void TwoFactorChallengeReplayed(ILogger logger, string userId);

    // ---------------------------------------------------------------- 3xxx tokens and sessions
    [LoggerMessage(3001, LogLevel.Information, "SlimIdentity: unknown refresh token for user {UserId}.")]
    public static partial void UnknownRefreshToken(ILogger logger, string userId);

    [LoggerMessage(3002, LogLevel.Warning, "SlimIdentity: refresh token reuse for user {UserId} – session {SessionId} revoked.")]
    public static partial void RefreshTokenReuseSession(ILogger logger, string userId, string sessionId);

    [LoggerMessage(3003, LogLevel.Warning, "SlimIdentity: refresh token reuse for user {UserId} – security stamp rotated, all sessions revoked.")]
    public static partial void RefreshTokenReuseAll(ILogger logger, string userId);

    [LoggerMessage(3004, LogLevel.Information, "SlimIdentity: all sessions of user {UserId} revoked.")]
    public static partial void AllSessionsRevoked(ILogger logger, string userId);

    [LoggerMessage(3005, LogLevel.Debug, "SlimIdentity: rejected {Purpose} token.")]
    public static partial void TokenRejected(ILogger logger, Exception exception, string purpose);

    // ---------------------------------------------------------------- 4xxx account
    [LoggerMessage(4001, LogLevel.Information, "SlimIdentity: registration attempt for existing account {UserId}.")]
    public static partial void RegistrationForExistingAccount(ILogger logger, string userId);

    [LoggerMessage(4006, LogLevel.Information, "SlimIdentity: concurrent registration for an address that was taken in the meantime.")]
    public static partial void RegistrationRaceLost(ILogger logger);

    [LoggerMessage(4002, LogLevel.Information, "SlimIdentity: password of user {UserId} reset.")]
    public static partial void PasswordReset(ILogger logger, string userId);

    [LoggerMessage(4003, LogLevel.Information, "SlimIdentity: invitation accepted by user {UserId}.")]
    public static partial void InvitationAccepted(ILogger logger, string userId);

    [LoggerMessage(4004, LogLevel.Information, "SlimIdentity: e-mail change requested by user {UserId}.")]
    public static partial void EmailChangeRequested(ILogger logger, string userId);

    [LoggerMessage(4005, LogLevel.Information, "SlimIdentity: e-mail address of user {UserId} changed.")]
    public static partial void EmailChanged(ILogger logger, string userId);

    // ---------------------------------------------------------------- 5xxx external login
    [LoggerMessage(5001, LogLevel.Warning, "SlimIdentity: {Provider} login for existing account {UserId} not linked (unverified e-mail or auto-link disabled).")]
    public static partial void ExternalLoginConflict(ILogger logger, string provider, string userId);

    [LoggerMessage(5002, LogLevel.Information, "SlimIdentity: linked {Provider} login to user {UserId}.")]
    public static partial void ExternalLoginLinked(ILogger logger, string provider, string userId);

    [LoggerMessage(5003, LogLevel.Information, "SlimIdentity: created user {UserId} from {Provider} login.")]
    public static partial void ExternalUserCreated(ILogger logger, string userId, string provider);

    // ---------------------------------------------------------------- 6xxx impersonation
    [LoggerMessage(6001, LogLevel.Warning, "SlimIdentity: user {Impersonator} impersonates {Target}.")]
    public static partial void ImpersonationStarted(ILogger logger, string impersonator, string target);

    [LoggerMessage(6002, LogLevel.Warning, "SlimIdentity: user {Impersonator} ended the impersonation of {Target}.")]
    public static partial void ImpersonationEnded(ILogger logger, string impersonator, string? target);

    [LoggerMessage(6003, LogLevel.Warning, "SlimIdentity: return to impersonator {Impersonator} denied (inactive or security stamp changed).")]
    public static partial void ImpersonationReturnDenied(ILogger logger, string impersonator);

    // ---------------------------------------------------------------- 7xxx mail
    [LoggerMessage(7001, LogLevel.Error, "SlimIdentity: mail queue is full – {Kind} mail dropped.")]
    public static partial void MailDropped(ILogger logger, string kind);

    [LoggerMessage(7002, LogLevel.Error, "SlimIdentity: sending {Kind} mail failed.")]
    public static partial void MailFailed(ILogger logger, Exception exception, string kind);

    [LoggerMessage(7003, LogLevel.Information, "SlimIdentity: sent {Count} queued mail(s) during shutdown.")]
    public static partial void MailDrained(ILogger logger, int count);

    [LoggerMessage(7004, LogLevel.Warning, "SlimIdentity: shutdown timeout reached with {Count} unsent mail(s) in the queue.")]
    public static partial void MailLost(ILogger logger, int count);

    // SlimNullEmailSender (development only – these log live links and codes)
    [LoggerMessage(7101, LogLevel.Warning, "[SlimIdentity:NullEmailSender] Verification for {Email}: {Link}")]
    public static partial void NullMailVerification(ILogger logger, string email, string link);

    [LoggerMessage(7102, LogLevel.Warning, "[SlimIdentity:NullEmailSender] Password reset for {Email}: {Link}")]
    public static partial void NullMailPasswordReset(ILogger logger, string email, string link);

    [LoggerMessage(7103, LogLevel.Warning, "[SlimIdentity:NullEmailSender] 2FA code for {Email}: {Code}")]
    public static partial void NullMailTwoFactorCode(ILogger logger, string email, string code);

    [LoggerMessage(7104, LogLevel.Warning, "[SlimIdentity:NullEmailSender] E-mail change confirmation for {Email}: {Link}")]
    public static partial void NullMailEmailChange(ILogger logger, string email, string link);

    [LoggerMessage(7105, LogLevel.Warning, "[SlimIdentity:NullEmailSender] Address {OldEmail} was changed to {NewEmail}")]
    public static partial void NullMailEmailChanged(ILogger logger, string oldEmail, string newEmail);

    [LoggerMessage(7106, LogLevel.Warning, "[SlimIdentity:NullEmailSender] Registration attempt for existing account {Email}")]
    public static partial void NullMailAccountExists(ILogger logger, string email);

    [LoggerMessage(7107, LogLevel.Warning, "[SlimIdentity:NullEmailSender] Account {Email} locked until {LockoutEnd}")]
    public static partial void NullMailLockout(ILogger logger, string email, DateTimeOffset lockoutEnd);
}
