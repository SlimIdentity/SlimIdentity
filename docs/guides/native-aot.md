# Native AOT

SlimIdentity is trimming- and Native-AOT-compatible (`IsAotCompatible`): all JSON serialization uses source
generation, the endpoints use the minimal-API request delegate generator, and options binding uses the configuration
binding generator. CI publishes the demo as Native AOT on every build, so regressions fail the build.

## What your application needs

```xml
<PropertyGroup>
  <PublishAot>true</PublishAot>
</PropertyGroup>
```

SlimIdentity registers its own `JsonSerializerContext` for its request/response types. Your own endpoint DTOs need one
as well – anonymous types (`new { … }`) do not work under AOT:

```csharp
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.TypeInfoResolverChain.Add(AppJsonContext.Default));

app.MapGet("/api/hello", (ClaimsPrincipal user) => new HelloResponse($"Hello {user.GetSlimEmail()}"));

internal sealed record HelloResponse(string Message);

[JsonSerializable(typeof(HelloResponse))]
internal sealed partial class AppJsonContext : JsonSerializerContext;
```

The demo ([`samples/SlimIdentity.Demo`](../../samples/SlimIdentity.Demo)) is a complete AOT example including
OpenAPI.

## Store implementations

- **EF Core:** Native AOT support is still limited (precompiled queries); check the EF Core documentation for your version.
- **Dapper:** uses reflection; use [Dapper.AOT](https://aot.dapperlib.dev/) or hand-written ADO.NET mapping.
- In-memory, REST or hand-written ADO.NET stores work without restrictions.

## Checking your app

```bash
dotnet publish -c Release -r linux-x64
```

Trimming/AOT warnings (IL2xxx, IL3xxx) during publish point to code that may break at runtime. SlimIdentity itself
produces none.
