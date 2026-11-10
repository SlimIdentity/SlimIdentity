namespace SlimIdentity.Security;

/// <summary>
/// Canonical form of an incoming address before it reaches the store: trimmed and Unicode-normalized (NFC), so
/// "josé" typed precomposed or decomposed is one account, not two look-alikes. Case is left to the store
/// (case-insensitive lookup). Sub-addresses (<c>+tag</c>) and homoglyphs stay different addresses by design.
/// Hosts that create accounts themselves (administration, imports) pass addresses through <see cref="Normalize"/>
/// before <see cref="ISlimUserStore.CreateAsync"/>, exactly as the SlimIdentity endpoints do.
/// </summary>
public static class SlimEmailAddress
{
    /// <summary>The normalized address, or <c>null</c> for empty input or invalid UTF-16 (e.g. lone surrogates).</summary>
    public static string? Normalize(string? value)
    {
        var trimmed = value?.Trim();
        if (string.IsNullOrEmpty(trimmed)) return null;
        try
        {
            return trimmed.Normalize(NormalizationForm.FormC);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}
