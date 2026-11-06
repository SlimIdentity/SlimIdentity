# Invitations

For invite-only applications (typical B2B) or accounts created by an admin or an import: the user receives a link and
sets the password themselves.

```csharp
builder.Services.AddSlimIdentity(o =>
{
    o.Endpoints.EnableRegistration = false;                                    // no self-registration
    o.Links.BaseUrl = "https://app.example.com";   // link: /accept-invitation?token=… (or set Links.InvitationUrl)
    o.Tokens.InvitationTokenLifetime = TimeSpan.FromDays(14);
});
```

## Creating an invitation (host endpoint)

```csharp
app.MapPost("/api/admin/invitations", async (InviteRequest req, ISlimUserStore store, ISlimAuthManager auth,
        IMyMailer mailer, CancellationToken ct) =>
    {
        // no password yet; null = the address is already taken
        if (await store.CreateAsync(req.Email, passwordHash: string.Empty, ct) is not { } user)
            return Results.Conflict();
        // … create your business data for user.Id (tenant, roles, display name)
        var invitation = await auth.CreateInvitationAsync(user, ct: ct);
        await mailer.SendInvitationAsync(req.Email, invitation.Link, invitation.ExpiresAt, ct);
        return Results.Ok();
    })
    .RequireAuthorization(p => p.RequireRole("Admin"))
    .RequireSlimCsrf();
```

The invitation mail is yours (sender, wording, inviter's name, branding) – it is not part of `ISlimEmailSender`.

## Accepting (front end)

1. The page behind the link (`/accept-invitation`) calls `POST /auth/invitation/info { token }` → `{ email, expiresAt }` to show the
   address (or `400 invalid_token` → "link expired or already used").
2. The user chooses a password; `POST /auth/invitation/accept?useCookies=true { token, password }` sets it (password
   policy applies), confirms the e-mail and signs the user in.

## Properties

- **Stateless:** the token is a Data Protection payload bound to the user's security stamp – no table, survives
  restarts and deployments (as long as the key ring is persisted).
- **Single use:** accepting rotates the stamp; a user who already has a password cannot use the link.
- Any stamp rotation (e.g. an admin signs the user out everywhere) invalidates outstanding invitations – create a new one.
- With `ISlimCustomPasswordValidator` (LDAP) there is no local password; `accept` answers `400 password_managed_externally`.
