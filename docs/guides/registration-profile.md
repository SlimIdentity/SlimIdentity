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

## Your own registration endpoint

Several steps, a captcha, a form of your own? Turn off `/register` and call `ISlimAuthManager.RegisterAsync` – it
applies every rule of the built-in endpoint: address normalization and validation, password rules, registration
guards, the uniform answer with the "account exists" and verification mails, the `user_created` event. You validate the
profile yourself (`ISlimRegistrationProfile` is not asked) and pass your typed object:

```csharp
builder.Services.AddSlimIdentity(o => o.Endpoints.EnableRegistration = false);

app.MapPost("/api/sign-up", async (SignUpForm form, ISlimAuthManager auth, CancellationToken ct) =>
{
    if (Validate(form) is { } errors) return Results.ValidationProblem(errors);   // before anything is looked up
    var result = await auth.RegisterAsync(form.Email, form.Password, new SignUpProfile(form.Company, form.Name), ct);
    return result.Response;   // 400 / 403, or the uniform registration_accepted
});
```

`result.User` is the new account (e.g. to start an onboarding job). It is `null` both when the address already had an
account and when `result.Failure` is set – never tell the caller which, or the endpoint reveals registered addresses.

## Accounts you create yourself

Administrators and invitations call the store directly and can pass a profile the same way:

```csharp
var user = await store.CreateAsync(new SlimNewUser { Email = request.Email, Profile = new SignUpProfile(…) }, ct);
```
