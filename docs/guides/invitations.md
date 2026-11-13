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
app.MapPost("/api/admin/invitations", async (InviteRequest req, ISlimAuthManager auth, IMyMailer mailer,
        CancellationToken ct) =>
    {
        // no password yet; business data (tenant, roles, display name) goes in as profile – written with the account
        var created = await auth.CreateUserAsync(req.Email, profile: req, ct: ct);
        if (!created.Succeeded) return created.Failure;   // 400 invalid address, 409 address taken
        var invitation = await auth.CreateInvitationAsync(created.User, ct: ct);
        await mailer.SendInvitationAsync(req.Email, invitation.Link, invitation.ExpiresAt, ct);
        return Results.Ok();
    })
    .RequireAuthorization(p => p.RequireRole("Admin"))
    .RequireSlimCsrf();
```

The invitation mail is yours (sender, wording, inviter's name, branding) – it is not part of `ISlimEmailSender`.

## Accepting (front end)

1. The page behind the link (`/accept-invitation`) calls `POST /auth/flow?useCookies=true { token }` →
   `action_required` `["set_credential"]` with `details.setCredential.email` to show the address (or
   `401 invalid_token` → "link expired or already used"). Accounts with 2FA (enabled by the host beforehand) pass
   `second_factor` first; a mailed code is accepted.
2. The user chooses a password: `POST /auth/register/password { flowToken, password }` sets it (password policy
   applies), confirms the e-mail and signs the user in. With the passkey package, `/auth/register/passkey` sets a
   passkey instead.

## Properties

- **Stateless:** the token is a Data Protection payload bound to the user's security stamp – no table, survives
  restarts and deployments (as long as the key ring is persisted).
- **Single use:** accepting rotates the stamp; a user who already has a password or whose address changed cannot use
  the link.
- Any stamp rotation (e.g. an admin signs the user out everywhere) invalidates outstanding invitations – create a new one.
- With `ISlimCustomPasswordValidator` (LDAP) and no passkeys there is no local credential to set; `/flow` answers
  `400 password_managed_externally`.
