namespace BFS.SlimIdentity;

public class SlimUser
{
    public string Id { get; set; } = string.Empty;

    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;

    public int FailedLoginAttempts { get; set; }
    public DateTimeOffset? LockoutEndUtc { get; set; }

    public string SecurityStamp { get; set; } = Guid.NewGuid().ToString();
}
