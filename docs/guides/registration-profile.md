# Registration with business data

Many applications need more than an address and a password to create an account: a company, a name, accepted terms,
a customer number. SlimIdentity takes this data with the registration and hands it to your store, so **the account and
its profile are created together – or not at all**. No account without a profile, no half-finished sign-up.

The profile comes with the last step of the [registration](../endpoints.md#registration), together with the password,
once the mailbox is proven:

```http
POST /auth/register/password
{ "flowToken": "…", "password": "…", "profile": { "company": "ACME", "name": "Ada" } }
```

Without mail (`WithoutEmail(allowSelfRegistration: true)`) it comes with `/register` itself.

## 1. Validate the profile

`ISlimRegistrationProfile` turns the free-form `profile` object into your typed, validated profile – or refuses it:

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

builder.Services.AddSlimIdentity(…)
    .AddRegistrationProfile<SignUpProfileValidator>();
```

- **Errors answer `400`** with the keys prefixed: `profile.company`, `profile.name` (`""` → `profile`).
- **Asked before the account is written** – after the password rules. Decide from the request (a customer number, an
  invitation code); the address is proven by then, but without mail it is not – never check it against your users,
  otherwise the answer reveals which addresses are registered.
- **Also asked without a profile** (`context.Profile` is `null`): you decide whether one is required.
- **Only what you return reaches the store** – never the raw JSON. Copy field by field into your own type; a client
  that sends `"isAdmin": true` changes nothing (no mass assignment).
- **Without this hook a `profile` is refused** (`400 profile`), so nothing unvalidated is ever passed on.
- If the address already has an account, nothing is written and the existing account is not touched: with mail the
  owner gets the "account exists" mail at `/register` and the flow never reaches this step; without mail the caller
  gets the same `registration_accepted` as everyone else and the profile is discarded.

## 2. Write it with the account

The validated profile reaches `ISlimUserStore.CreateAsync` as `SlimNewUser.Profile`.

**EF Core package** – your `ISlimUserFactory<TUser>` copies it into the new entity. Related entities set as
navigation properties are inserted in the same `SaveChanges`:

```csharp
public sealed class AppUsers : ISlimUserFactory<AppUser>
{
    public AppUser Create(SlimNewUser user) => user.Profile is SignUpProfile p
        ? new AppUser { DisplayName = p.Name, Company = new Company { Name = p.Company } }
        : new AppUser();   // external login, invitation: no profile
}

builder.Services.AddSingleton<ISlimUserFactory<AppUser>, AppUsers>();
```

If the address was taken by a concurrent registration, nothing is written – neither the account nor the company. A
profile without a factory is refused with an exception instead of being lost silently.

**Your own store** – write account and profile in one transaction:

```csharp
public async Task<SlimUser?> CreateAsync(SlimNewUser newUser, CancellationToken ct)
{
    await using var tx = await connection.BeginTransactionAsync(ct);
    var user = /* INSERT … ON CONFLICT (normalized_email) DO NOTHING RETURNING … */;
    if (user is null) return null;                        // taken: roll back, nothing written
    if (newUser.Profile is SignUpProfile p) /* INSERT INTO profiles (user_id, company, name) … */;
    await tx.CommitAsync(ct);
    return user;
}
```

## Your own first step

A captcha, an invitation check, a form of your own before the address is entered? Turn off `/register` and call
`ISlimAuthManager.BeginRegistrationAsync` – it applies every rule of the built-in endpoint: address normalization and
validation, registration guards, the uniform `action_required` answer with the verification or "account exists" mail.
The client continues with the built-in steps (`/register/verify`, `/register/password` or a passkey), which stay
mapped while mail is on; the profile comes with the credential there and `ISlimRegistrationProfile` validates it as
usual:

```csharp
builder.Services.AddSlimIdentity(o => o.Endpoints.EnableRegistration = false);

app.MapPost("/api/sign-up", async (SignUpForm form, ISlimAuthManager auth, CancellationToken ct) =>
{
    if (!await captcha.VerifyAsync(form.Captcha, ct)) return Results.BadRequest();
    return await auth.BeginRegistrationAsync(form.Email, ct: ct);   // 400 / 403, or the uniform action_required
});
```

## Accounts you create yourself

Administrators and imports call `ISlimAuthManager.CreateUserAsync` – a confirmed account without guards and without
mail, optionally with a start password that must be changed at the first sign-in, and with your profile:

```csharp
var result = await auth.CreateUserAsync(request.Email, profile: new SignUpProfile(…), ct: ct);
if (!result.Succeeded) return result.Failure;   // 400 invalid address or password, 409 address taken
```

Without a start password the account has no sign-in method yet: send an invitation or a password reset link next
(`HasSignInMethodAsync` tells whether an account can sign in).
