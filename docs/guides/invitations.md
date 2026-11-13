# Invitations

For invite-only applications or accounts created by an administrator or an import: the user receives a link and sets
the first credential. The flow itself (`POST /auth/flow` → `set_credential`) is described in the
[endpoint reference](../endpoints.md#invitations).

```csharp
builder.Services.AddSlimIdentity(o =>
{
    o.Endpoints.EnableRegistration = false;                     // no self-registration
    o.Links.BaseUrl = "https://app.example.com";                // link: /accept-invitation?token=… (or Links.InvitationUrl)
    o.Tokens.InvitationTokenLifetime = TimeSpan.FromDays(14);   // default 7 days, at most 30
});
```

## Creating an invitation (host endpoint)

```csharp
app.MapPost("/api/admin/invitations", async (InviteRequest req, ISlimAuthManager auth, IMyMailer mailer,
        CancellationToken ct) =>
    {
        var created = await auth.CreateUserAsync(req.Email, profile: req, ct: ct);   // no password; profile = your data
        if (!created.Succeeded) return created.Failure;                             // 400 invalid address, 409 taken
        var invitation = await auth.CreateInvitationAsync(created.User!, ct: ct);
        await mailer.SendInvitationAsync(req.Email, invitation.Link, invitation.ExpiresAt, ct);
        return Results.Ok();
    })
    .RequireAuthorization(p => p.RequireRole("Admin"))
    .RequireSlimCsrf();
```

The invitation mail is yours (sender, wording, branding); it is not sent through `ISlimEmailSender`.

## Accepting (front end)

The page behind the link posts the `token` to `POST /auth/flow?useCookies=true` and continues with `set_credential`
(`details.setCredential.email` names the account) as in the [endpoint reference](../endpoints.md#invitations);
`401 invalid_token` means "link expired or already used". The token is a Data Protection payload bound to the
security stamp – no table. Accepting rotates the stamp; any other rotation (e.g. sign out everywhere) also
invalidates outstanding invitations.
