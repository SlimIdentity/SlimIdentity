namespace SlimIdentity.Security;

/// <summary>Validates new passwords against <see cref="SlimPasswordOptions"/>.</summary>
internal sealed class SlimPasswordPolicy(IOptions<SlimIdentityOptions> options)
{
    /// <summary>Returns validation errors keyed by <paramref name="field"/>, or null if valid.</summary>
    public Dictionary<string, string[]>? Validate(string? password, string field = "password")
    {
        var p = options.Value.Password;
        var errors = new List<string>();
        password ??= string.Empty;

        if (password.Length < p.MinimumLength) errors.Add($"Password must be at least {p.MinimumLength} characters long.");
        if (password.Length > p.MaximumLength) errors.Add($"Password must be at most {p.MaximumLength} characters long.");
        if (p.RequireDigit && !password.Any(char.IsDigit)) errors.Add("Password must contain a digit.");
        if (p.RequireLowercase && !password.Any(char.IsLower)) errors.Add("Password must contain a lowercase letter.");
        if (p.RequireUppercase && !password.Any(char.IsUpper)) errors.Add("Password must contain an uppercase letter.");
        if (p.RequireNonAlphanumeric && password.All(char.IsLetterOrDigit)) errors.Add("Password must contain a non-alphanumeric character.");

        return errors.Count == 0 ? null : new Dictionary<string, string[]> { [field] = errors.ToArray() };
    }
}
