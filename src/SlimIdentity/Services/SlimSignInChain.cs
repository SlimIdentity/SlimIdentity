namespace SlimIdentity.Services;

/// <summary>The steps a sign-in may still need once its first factor is proven, in the order they are taken.</summary>
internal static class SlimSignInActions
{
    /// <summary>
    /// The mailbox is proven first, by a code sent within the sign-in: every unconfirmed account, as long as SlimIdentity
    /// sends mail.
    /// </summary>
    public const string VerifyEmail = "verify_email";
    /// <summary>The second factor of an account with two-factor authentication.</summary>
    public const string SecondFactor = "second_factor";
    /// <summary>A start password set by an administrator is replaced by an own one.</summary>
    public const string ChangePassword = "change_password";
    /// <summary>
    /// A way to sign in is set: the first one of a registration whose mailbox is proven, or a new one after a reset link.
    /// </summary>
    public const string SetCredential = "set_credential";
    /// <summary>
    /// A second factor that is more than a mail code is set up (<c>/login/2fa/setup</c>, <c>/login/2fa/enable</c>):
    /// <see cref="ISlimSecondFactorPolicy"/> requires one and the sign-in has not proven one.
    /// </summary>
    public const string SetupSecondFactor = "setup_second_factor";
    /// <summary>The recovery codes of the second factor set up in this sign-in are shown once and confirmed as saved.</summary>
    public const string ConfirmRecoveryCodes = "confirm_recovery_codes";
}

/// <summary>What the current sign-in has proven.</summary>
[Flags]
internal enum SlimSignInProofs
{
    None = 0,
    /// <summary>
    /// The second factor: a code at <c>/login/2fa</c>, a remembered device, a passkey (possession and user verification)
    /// or a host check that is multi-factor on its own.
    /// </summary>
    SecondFactor = 1,
    /// <summary>The first factor was the password: its lockout holds for the rest of the sign-in.</summary>
    Password = 2,
    /// <summary>The mailbox: a mailed code or the link of the same mail.</summary>
    Mailbox = 4,
    /// <summary>
    /// The second factor was more than a mail code: an authenticator app, a recovery code, a passkey, a remembered device
    /// of an account with an authenticator app, or a host check. Only together with <see cref="SecondFactor"/>.
    /// </summary>
    Authenticator = 8,
    /// <summary>A second factor that fulfils <see cref="ISlimSecondFactorPolicy"/>.</summary>
    StrongSecondFactor = SecondFactor | Authenticator,
}

/// <summary>The outcome of <see cref="SlimSignInChain.Evaluate(SlimUser, SlimFlowPayload, SlimIdentityOptions)"/>.</summary>
/// <param name="Refusal">The account cannot sign in at all (<see cref="SlimErrorCodes.AccountDisabled"/>).</param>
/// <param name="Pending">The open steps in order; empty when a session may be issued.</param>
internal readonly record struct SlimSignInDecision(string? Refusal, IReadOnlyList<string> Pending)
{
    /// <summary>The step to take now, or <c>null</c>.</summary>
    public string? Next => Pending.Count > 0 ? Pending[0] : null;

    /// <summary>A session may be issued.</summary>
    public bool Complete => Refusal is null && Pending.Count == 0;
}

/// <summary>
/// The rules every sign-in follows after its first factor, in one place: each check contributes at most one step, the
/// entry points translate the first open step into their answer. A lockout is not part of the chain – it guards the
/// guessable factors and is checked where they are.
/// </summary>
internal static class SlimSignInChain
{
    private readonly record struct Facts(SlimSignInProofs Proofs, bool SecondFactorRequired, bool RecoveryCodesPending);

    private sealed record Check(string Action, Func<SlimUser, Facts, SlimIdentityOptions, bool> IsPending);

    private static readonly Check[] Checks =
    [
        new(SlimSignInActions.VerifyEmail, static (user, _, o) => o.Email.Enabled && !user.EmailConfirmed),
        // the second factor before the own password: whoever chooses it has proven the account completely
        new(SlimSignInActions.SecondFactor, static (user, f, _) => user.TwoFactorEnabled && !f.Proofs.HasFlag(SlimSignInProofs.SecondFactor)),
        new(SlimSignInActions.ChangePassword, static (user, _, _) => user.PasswordChangeRequired),
        // an account with a second factor passes it first – it may well be the one the policy asks for
        new(SlimSignInActions.SetupSecondFactor, static (user, f, _) => f.SecondFactorRequired
            && !f.Proofs.HasFlag(SlimSignInProofs.StrongSecondFactor) && (!user.TwoFactorEnabled || f.Proofs.HasFlag(SlimSignInProofs.SecondFactor))),
        new(SlimSignInActions.ConfirmRecoveryCodes, static (_, f, _) => f.RecoveryCodesPending),
    ];

    /// <param name="user">The account.</param>
    /// <param name="proofs">What the sign-in has proven.</param>
    /// <param name="options">The options.</param>
    /// <param name="secondFactorRequired"><see cref="ISlimSecondFactorPolicy"/> requires a second factor.</param>
    /// <param name="recoveryCodesPending">Recovery codes of this sign-in are not confirmed yet.</param>
    public static SlimSignInDecision Evaluate(SlimUser user, SlimSignInProofs proofs, SlimIdentityOptions options,
        bool secondFactorRequired = false, bool recoveryCodesPending = false)
    {
        if (!user.IsActive) return new(SlimErrorCodes.AccountDisabled, []);
        var facts = new Facts(proofs, secondFactorRequired, recoveryCodesPending);
        List<string>? pending = null;
        foreach (var check in Checks)
            if (check.IsPending(user, facts, options)) (pending ??= []).Add(check.Action);
        return new(null, pending ?? (IReadOnlyList<string>)[]);
    }

    /// <summary>The steps of a flow: those of its link (<see cref="SlimFlowPayload.Link"/>), otherwise those of a sign-in.</summary>
    public static SlimSignInDecision Evaluate(SlimUser user, SlimFlowPayload state, SlimIdentityOptions options) =>
        state.Link is null
            ? Evaluate(user, state.Proofs, options, state.SecondFactorRequired == true, state.RecoveryCodesPending)
            : EvaluateLink(user, state, options);

    /// <summary>
    /// The steps of a link that sets a new way to sign in (<see cref="SlimSignInActions.SetCredential"/>, always last).
    /// The mailbox first, unless the link proved it. The second factor before it – except at the first proof of the
    /// mailbox by a reset: setting the new way removes the second factor with everything else whoever registered the
    /// address may have added.
    /// </summary>
    private static SlimSignInDecision EvaluateLink(SlimUser user, SlimFlowPayload state, SlimIdentityOptions options)
    {
        if (!user.IsActive) return new(SlimErrorCodes.AccountDisabled, []);
        var pending = new List<string>(3);
        if (options.Email.Enabled && !user.EmailConfirmed && !state.Proofs.HasFlag(SlimSignInProofs.Mailbox))
            pending.Add(SlimSignInActions.VerifyEmail);
        if (user.TwoFactorEnabled && !state.Proofs.HasFlag(SlimSignInProofs.SecondFactor) && !ResetsUnconfirmedAccount(user, state))
            pending.Add(SlimSignInActions.SecondFactor);
        pending.Add(SlimSignInActions.SetCredential);
        return new(null, pending);
    }

    /// <summary>
    /// A reset that proves the mailbox of an unconfirmed account for the first time: the new way to sign in replaces
    /// every other one – the second factor, external logins and passkeys go.
    /// </summary>
    public static bool ResetsUnconfirmedAccount(SlimUser user, SlimFlowPayload state) =>
        state.Link == SlimLinkPayload.Reset && state.Proofs.HasFlag(SlimSignInProofs.Mailbox) && !user.EmailConfirmed;

    /// <summary>
    /// The steps of a registration before its account exists: the mailbox first, then the way to sign in. The account is
    /// created with the last step and continues with <see cref="Evaluate(SlimUser, SlimFlowPayload, SlimIdentityOptions)"/>.
    /// </summary>
    public static SlimSignInDecision EvaluateRegistration(SlimSignInProofs proofs) =>
        new(null, proofs.HasFlag(SlimSignInProofs.Mailbox)
            ? [SlimSignInActions.SetCredential]
            : [SlimSignInActions.VerifyEmail, SlimSignInActions.SetCredential]);

    /// <summary>
    /// The code of a step's rule – the reason in metrics and events, and the answer of an entry point that cannot continue it.
    /// </summary>
    public static string ErrorCode(string action) => action switch
    {
        SlimSignInActions.VerifyEmail => SlimErrorCodes.EmailNotConfirmed,
        SlimSignInActions.ChangePassword => SlimErrorCodes.PasswordChangeRequired,
        SlimSignInActions.SecondFactor => SlimErrorCodes.RequiresTwoFactor,
        SlimSignInActions.SetCredential => SlimErrorCodes.PasswordNotSet,
        SlimSignInActions.SetupSecondFactor => SlimErrorCodes.TwoFactorSetupRequired,
        SlimSignInActions.ConfirmRecoveryCodes => SlimErrorCodes.TwoFactorSetupRequired,
        _ => throw new ArgumentOutOfRangeException(nameof(action), action, null),
    };
}
