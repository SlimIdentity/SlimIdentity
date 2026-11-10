namespace SlimIdentity.Security;

/// <summary>Validates new passwords against <see cref="SlimPasswordOptions"/> and all registered <see cref="ISlimPasswordRule"/>s.</summary>
internal sealed class SlimPasswordPolicy(IOptions<SlimIdentityOptions> options, IEnumerable<ISlimPasswordRule> rules)
{
    /// <summary>Returns validation errors keyed by <paramref name="field"/>, or null if valid.</summary>
    public async Task<Dictionary<string, string[]>?> ValidateAsync(string? password, string email, CancellationToken ct, string field = "password")
    {
        var p = options.Value.Password;
        var errors = new List<string>();
        password ??= string.Empty;

        if (password.Length < p.MinimumLength) errors.Add($"Password must be at least {p.MinimumLength} characters long.");
        if (password.Length > p.MaximumLength) errors.Add($"Password must be at most {p.MaximumLength} characters long.");
        // no composition rules (NIST SP 800-63B) – they make passwords harder to remember, not harder to guess

        // custom rules (breached-password checks, blocklists, …) only for otherwise valid, reasonably sized input
        if (errors.Count == 0)
            foreach (var rule in rules)
                errors.AddRange(await rule.ValidateAsync(password, email, ct));

        return errors.Count == 0 ? null : new Dictionary<string, string[]> { [field] = errors.ToArray() };
    }
}
