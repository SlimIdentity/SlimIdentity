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
}

/// <summary>The outcome of <see cref="SlimSignInChain.Evaluate"/>.</summary>
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
    private sealed record Check(string Action, Func<SlimUser, SlimSignInProofs, SlimIdentityOptions, bool> IsPending);

    private static readonly Check[] Checks =
    [
        new(SlimSignInActions.VerifyEmail, static (user, _, o) => o.Email.Enabled && !user.EmailConfirmed),
        // the second factor before the own password: whoever chooses it has proven the account completely
        new(SlimSignInActions.SecondFactor, static (user, proofs, _) => user.TwoFactorEnabled && !proofs.HasFlag(SlimSignInProofs.SecondFactor)),
        new(SlimSignInActions.ChangePassword, static (user, _, _) => user.PasswordChangeRequired),
    ];

    public static SlimSignInDecision Evaluate(SlimUser user, SlimSignInProofs proofs, SlimIdentityOptions options)
    {
        if (!user.IsActive) return new(SlimErrorCodes.AccountDisabled, []);
        List<string>? pending = null;
        foreach (var check in Checks)
            if (check.IsPending(user, proofs, options)) (pending ??= []).Add(check.Action);
        return new(null, pending ?? (IReadOnlyList<string>)[]);
    }

    /// <summary>
    /// The code of a step's rule – the reason in metrics and events, and the answer of an entry point that cannot continue it.
    /// </summary>
    public static string ErrorCode(string action) => action switch
    {
        SlimSignInActions.VerifyEmail => SlimErrorCodes.EmailNotConfirmed,
        SlimSignInActions.ChangePassword => SlimErrorCodes.PasswordChangeRequired,
        SlimSignInActions.SecondFactor => SlimErrorCodes.RequiresTwoFactor,
        _ => throw new ArgumentOutOfRangeException(nameof(action), action, null),
    };
}
