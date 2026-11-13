# Registration with business data

A company, a name, accepted terms: SlimIdentity takes this data with the registration and hands it to your store, so
**account and profile are created together – or not at all**. The profile comes with the credential in the last step
of the [registration](../endpoints.md#registration), once the mailbox is proven:

```http
POST /auth/register/password
{ "flowToken": "…", "password": "…", "profile": { "company": "ACME", "name": "Ada" } }
```

`/register/passkey` takes it the same way; without mail (`WithoutEmail(allowSelfRegistration: true)`) it comes with
`/register` itself.

## 1. Validate the profile

```csharp
public sealed record SignUpProfile(string Company, string Name);

public sealed class SignUpProfileValidator : ISlimRegistrationProfile
{
    public ValueTask<SlimProfileValidation> ValidateAsync(SlimRegistrationProfileContext context, CancellationToken ct)
    {
        if (context.Profile is not { ValueKind: JsonValueKind.Object } json
            || json.Deserialize(AppJsonContext.Default.SignUpForm) is not { } form)   // your own (source-generated) type
            return ValueTask.FromResult(SlimProfileValidation.Invalid("", "The profile is required."));

        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(form.Company) || form.Company.Length > 100) errors["company"] = ["The company is required."];
        if (string.IsNullOrWhiteSpace(form.Name) || form.Name.Length > 100) errors["name"] = ["The name is required."];
        return ValueTask.FromResult(errors.Count > 0
            ? SlimProfileValidation.Invalid(errors)
            : SlimProfileValidation.Valid(new SignUpProfile(form.Company.Trim(), form.Name.Trim())));
    }
}

builder.Services.AddSlimIdentity(…).AddRegistrationProfile<SignUpProfileValidator>();
```

- Errors answer `400` with prefixed keys: `profile.company`, `profile.name` (`""` → `profile`).
- Asked after the password rules, before the account is written – also when no profile was sent (`context.Profile` is
  `null`), so you decide whether one is required.
- Decide from the request; without mail the address is not proven – never check it against your users.
- Only the returned object reaches the store, never the raw JSON (no mass assignment).
- Without this hook a `profile` is refused (`400 profile`).
- If the address already has an account, nothing is written: with mail the owner gets the "account exists" mail and
  the flow never gets here; without mail the caller gets the usual `registration_accepted` and the profile is dropped.

## 2. Write it with the account

The validated profile reaches `ISlimUserStore.CreateAsync` as `SlimNewUser.Profile`.

**EF Core package:** an `ISlimUserFactory<TUser>` copies it into the entity; related entities set as navigation
properties are inserted in the same `SaveChanges`. A profile without a factory throws instead of being dropped.

```csharp
public sealed class AppUsers : ISlimUserFactory<AppUser>
{
    public AppUser Create(SlimNewUser user) => user.Profile is SignUpProfile p
        ? new AppUser { DisplayName = p.Name, Company = new Company { Name = p.Company } }
        : new AppUser();   // external login, invitation: no profile
}

builder.Services.AddSingleton<ISlimUserFactory<AppUser>, AppUsers>();
```

**Own store:** write account and profile in one transaction (e.g. `INSERT … ON CONFLICT (normalized_email) DO NOTHING
RETURNING …`, then the profile row); return `null` with nothing written when the address is taken.

## Your own first step

For a captcha or an own form, turn off `/register` and call `ISlimAuthManager.BeginRegistrationAsync`. It applies the
address rules, registration guards and the uniform `action_required` answer; `/register/verify`,
`/register/password` and `/register/passkey` stay mapped while mail is on.

```csharp
builder.Services.AddSlimIdentity(o => o.Endpoints.EnableRegistration = false);

app.MapPost("/api/sign-up", async (SignUpForm form, ISlimAuthManager auth, CancellationToken ct) =>
{
    if (!await captcha.VerifyAsync(form.Captcha, ct)) return Results.BadRequest();
    return await auth.BeginRegistrationAsync(form.Email, ct: ct);   // 400 / 403, or the uniform action_required
});
```

Accounts created by administrators or imports use `CreateUserAsync(email, startPassword?, profile)` – no guards, no
mail ([without e-mail](without-email.md#the-administrators-tools)). Without a start password, follow up with an
invitation or reset link (`HasSignInMethodAsync` tells whether an account can sign in).
