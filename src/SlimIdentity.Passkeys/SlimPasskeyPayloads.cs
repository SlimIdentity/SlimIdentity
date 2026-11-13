namespace SlimIdentity.Passkeys;

internal static class SlimPasskeyPurposes
{
    // unchanged since passkeys were part of the core – states issued before an update stay valid
    public const string Registration = "SlimIdentity.PasskeyRegistration.v1";
    public const string Login = "SlimIdentity.PasskeyLogin.v1";
    public const string NewAccount = "SlimIdentity.PasskeyRegistration.NewAccount.v1";
}

/// <summary>A pending passkey registration: the challenge, bound to the account and its security stamp.</summary>
internal sealed record SlimPasskeyRegistrationPayload(string Uid, string Stamp, string Challenge, string UserHandle);
/// <summary>A pending passkey of a registration: the challenge, bound to the registration flow before its account exists.</summary>
internal sealed record SlimPasskeyNewAccountPayload(string FlowId, string Challenge, string UserHandle);
/// <summary>A pending passkey sign-in: the challenge and when it was issued (unix ms – each counts once per passkey).</summary>
internal sealed record SlimPasskeyLoginPayload(string Challenge, long IssuedAt);
