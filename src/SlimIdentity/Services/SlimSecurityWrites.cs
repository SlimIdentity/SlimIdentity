namespace SlimIdentity.Services;

/// <summary>
/// Writes of the security state through the compare-and-set of <see cref="ISlimUserStore.UpdateSecurityStateAsync"/>.
/// Every write changes the stamp (at least its claims part), so a copy of the user read before a concurrent write can
/// never be written back over it.
/// </summary>
internal static class SlimSecurityWrites
{
    private const int MaxRetries = 3;

    /// <summary>
    /// A change that is only valid for the security state the caller checked (a link, a flow token, a password just
    /// confirmed): retried on a fresh copy while only the claims part changed in between; <c>false</c> once the security
    /// part changed or the user is gone – <paramref name="user"/> then holds the current state, if any.
    /// </summary>
    public static Task<bool> TryWriteSecurityStateAsync(this ISlimUserStore store, SlimUser user, Action<SlimUser> change, CancellationToken ct) =>
        WriteAsync(store, user, change, bound: true, ct);

    /// <summary>
    /// A change that applies to any state (administrator, sign-out everywhere): applied again on a fresh copy after a
    /// concurrent write. <c>false</c> only if the user is gone; throws if the stamp keeps changing.
    /// </summary>
    public static Task<bool> WriteSecurityStateAsync(this ISlimUserStore store, SlimUser user, Action<SlimUser> change, CancellationToken ct) =>
        WriteAsync(store, user, change, bound: false, ct);

    private static async Task<bool> WriteAsync(ISlimUserStore store, SlimUser user, Action<SlimUser> change, bool bound, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(user);
        var checkedStamp = user.SecurityStamp;
        for (var attempt = 0; attempt < MaxRetries; attempt++)
        {
            var expected = user.SecurityStamp ?? string.Empty;
            change(user);
            if (string.Equals(user.SecurityStamp, expected, StringComparison.Ordinal))
                user.SecurityStamp = expected.Length == 0 ? SlimUser.NewSecurityStamp() : SlimUser.WithNewClaimsPart(expected);
            if (await store.UpdateSecurityStateAsync(user, expected, ct)) return true;

            if (await store.FindByIdAsync(user.Id, ct) is not { } current) return false;
            user.CopyFrom(current);
            if (bound && !SlimUser.IsSameSecurityState(current.SecurityStamp, checkedStamp)) return false;
        }
        if (bound) return false;
        throw new InvalidOperationException($"SlimIdentity: the security state of user {user.Id} kept changing; it could not be written.");
    }
}
