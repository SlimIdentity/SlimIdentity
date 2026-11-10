namespace SlimIdentity.Passkeys;

/// <summary>Log events 9xxx (passkeys) – stable ids, no personal data.</summary>
internal static partial class Log
{
    [LoggerMessage(9001, LogLevel.Information, "SlimIdentity: passkey registered for user {UserId}.")]
    public static partial void PasskeyAdded(ILogger logger, string userId);

    [LoggerMessage(9002, LogLevel.Information, "SlimIdentity: passkey removed from user {UserId}.")]
    public static partial void PasskeyRemoved(ILogger logger, string userId);

    [LoggerMessage(9003, LogLevel.Information, "SlimIdentity: passkey {Ceremony} rejected ({Reason}).")]
    public static partial void PasskeyRejected(ILogger logger, string ceremony, string reason);

    [LoggerMessage(9004, LogLevel.Warning, "SlimIdentity: passkey of user {UserId} reported a signature counter that did not increase – possibly a cloned authenticator; sign-in refused.")]
    public static partial void PasskeyCounterRegression(ILogger logger, string userId);
}
