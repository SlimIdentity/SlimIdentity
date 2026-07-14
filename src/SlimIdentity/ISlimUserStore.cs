namespace BFS.SlimIdentity;

public interface ISlimUserStore
{
    // 1. Wird beim Login aufgerufen, um den Hash und den Lockout-Status zu prüfen
    Task<SlimUser?> FindByEmailAsync(string email, CancellationToken cancellationToken);

    // 2. Wird aufgerufen, wenn der Login fehlschlägt (Zähler hochsetzen) 
    // oder wenn der User nach einem Lockout wieder freigegeben wird
    Task UpdateSecurityStateAsync(SlimUser user, CancellationToken cancellationToken);

    // 3. Wird vom /register Endpoint aufgerufen
    Task<SlimUser> CreateAsync(string email, string passwordHash, CancellationToken cancellationToken);
}
