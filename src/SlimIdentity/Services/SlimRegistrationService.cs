using System.Net.Mail;
using SlimIdentity.Http;
using SlimIdentity.Security;

namespace SlimIdentity.Services;

/// <summary>
/// Creates accounts with the rules of <c>/register</c> – used by the endpoint and by
/// <see cref="ISlimAuthManager.RegisterAsync"/>, so a host's own registration endpoint cannot skip one of them.
/// </summary>
internal sealed class SlimRegistrationService(
    ISlimUserStore store,
    SlimEmailDispatcher mail,
    SlimCredentialService credentials,
    SlimPasswordPolicy passwordPolicy,
    SlimHookRunner hooks,
    SlimMetrics metrics,
    IOptions<SlimIdentityOptions> options,
    ILogger<SlimRegistrationService> logger)
{
    internal const int MaxEmailLength = 256;

    /// <summary>The uniform answer – identical whether the address was free or already had an account.</summary>
    internal static IResult Accepted => SlimResults.Status("registration_accepted",
        "If the address can be used, the account has been created.");

    /// <summary>
    /// A plain address only: <see cref="MailAddress"/> also accepts <c>Name &lt;addr&gt;</c> and <c>addr (comment)</c>, and a mail
    /// transport delivers those to the address inside – one inbox behind endless "different" addresses (mail limit,
    /// look-alike accounts). The parsed address must be the whole input.
    /// </summary>
    internal static bool IsValidEmail([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] string? email) =>
        !string.IsNullOrEmpty(email) && email.Length <= MaxEmailLength
        && MailAddress.TryCreate(email, out var parsed)
        && string.IsNullOrEmpty(parsed.DisplayName)
        && string.Equals(parsed.Address, email, StringComparison.Ordinal);

    internal static IResult InvalidEmail(string field) =>
        SlimResults.Validation(new Dictionary<string, string[]> { [field] = ["A valid e-mail address is required."] });

    /// <summary>
    /// Without mail the field carries a sign-in name (with LDAP the user name): not empty, at most
    /// <see cref="MaxEmailLength"/> characters, no control characters.
    /// </summary>
    internal static bool IsValidIdentifier([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] string? identifier) =>
        !string.IsNullOrEmpty(identifier) && identifier.Length <= MaxEmailLength && !identifier.Any(char.IsControl);

    /// <summary>The address (with mail) or sign-in name (without) of a new account, from the request alone.</summary>
    internal bool IsValidAccountName([System.Diagnostics.CodeAnalysis.NotNullWhen(true)] string? name) =>
        options.Value.Email.Enabled ? IsValidEmail(name) : IsValidIdentifier(name);

    /// <summary>The profile through the host's <see cref="ISlimRegistrationProfile"/>; errors as a <c>400</c> under <c>profile</c>.</summary>
    public async Task<(object? Profile, IResult? Failure)> ValidateProfileAsync(string email, JsonElement? profile, CancellationToken ct)
    {
        var result = await hooks.ValidateProfileAsync(email, profile, ct);
        return result.Errors is { } errors
            ? (null, SlimResults.Validation(errors.ToDictionary(e => e.Key.Length == 0 ? "profile" : "profile." + e.Key, e => e.Value, StringComparer.Ordinal)))
            : (result.Profile, null);
    }

    /// <summary>
    /// Step 1, from the request alone: address and password rules. Returns the normalized address, or the <c>400</c>.
    /// </summary>
    public async Task<(string? Email, IResult? Failure)> ValidateAsync(string? email, string? password, CancellationToken ct)
    {
        var normalized = SlimEmailAddress.Normalize(email);
        if (!IsValidAccountName(normalized)) return (null, InvalidEmail("email"));
        if (await passwordPolicy.ValidateAsync(password, normalized!, ct) is { } errors)
            return (null, SlimResults.Validation(errors));
        return (normalized, null);
    }

    /// <summary>
    /// Step 2: the host's veto, then the account – or, if the address is taken, the "account exists" mail and the same
    /// answer. <paramref name="email"/> and <paramref name="password"/> passed <see cref="ValidateAsync"/>.
    /// </summary>
    public async Task<SlimRegistrationResult> CreateAsync(string email, string password, object? profile, CancellationToken ct)
    {
        // the host's veto – decided from the request alone, before anything is looked up (no enumeration)
        if (await hooks.CheckRegistrationAsync(email, null, ct) is { } veto)
        {
            var refused = SlimResults.Status(veto.Error, veto.Message ?? "Registration is not allowed.", StatusCodes.Status403Forbidden);
            return new SlimRegistrationResult(null, refused, refused);
        }

        var existing = await store.FindByEmailAsync(email, ct);
        if (existing is not null)
        {
            // Enumeration prevention: identical response, comparable CPU time, a mail in both cases
            // (sent in the background, so the mail server's latency is not observable).
            credentials.HashPassword(new SlimUser { Email = email }, password);
            Log.RegistrationForExistingAccount(logger, existing.Id);
            return await AccountExistsAsync(existing.Email, existing.Id);
        }

        var hash = credentials.HashPassword(new SlimUser { Email = email }, password);
        var user = await store.CreateAsync(new SlimNewUser { Email = email, PasswordHash = hash, Profile = profile }, ct);
        if (user is null)
        {
            // a concurrent registration took the address between the lookup and the insert – same answer as above
            Log.RegistrationRaceLost(logger);
            return await AccountExistsAsync(email, null);   // the winner of the race is not loaded
        }
        metrics.Registration("created");
        await hooks.RaiseAsync(SlimEventTypes.UserCreated, user.Id, reason: "registration", ct: ct);

        // with mail the address is confirmed at the first sign-in (step verify_email)
        return new SlimRegistrationResult(user, null, Accepted);

        async Task<SlimRegistrationResult> AccountExistsAsync(string existingEmail, string? existingUserId)
        {
            metrics.Registration("existing_account");
            await mail.SendAsync(SlimEmailKinds.AccountExists, existingEmail, existingUserId, (s, x, c) => s.SendAccountExistsEmailAsync(x, existingEmail, c), ct);
            return new SlimRegistrationResult(null, null, Accepted);
        }
    }
}
