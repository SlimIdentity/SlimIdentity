# Native AOT

SlimIdentity is trimming- and Native-AOT-compatible: source-generated JSON, the minimal-API request delegate generator
and the configuration binding generator. The demo ([`samples/SlimIdentity.Demo`](../../samples/SlimIdentity.Demo))
is a complete AOT example including OpenAPI.

Set `<PublishAot>true</PublishAot>`. SlimIdentity registers its own `JsonSerializerContext`; your DTOs need one too
(anonymous types do not work under AOT):

```csharp
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.TypeInfoResolverChain.Add(AppJsonContext.Default));

app.MapGet("/api/hello", (ClaimsPrincipal user) => new HelloResponse($"Hello {user.GetSlimEmail()}"));

internal sealed record HelloResponse(string Message);

[JsonSerializable(typeof(HelloResponse))]
internal sealed partial class AppJsonContext : JsonSerializerContext;
```

Stores: EF Core's AOT support is limited (precompiled queries – check your version); Dapper needs
[Dapper.AOT](https://aot.dapperlib.dev/); hand-written ADO.NET, REST or in-memory stores work. Check with
`dotnet publish -c Release -r linux-x64`: IL2xxx/IL3xxx warnings point to code that may break at runtime.
