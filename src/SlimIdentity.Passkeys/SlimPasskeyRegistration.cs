using System.Diagnostics.CodeAnalysis;
using SlimIdentity.Contracts;
using SlimIdentity.Passkeys;

namespace SlimIdentity;

/// <summary>Registration of the passkey package: <c>.AddPasskeyStore&lt;T&gt;()</c> after <c>AddSlimIdentity()</c>.</summary>
public static class SlimPasskeyBuilderExtensions
{
    /// <summary>
    /// Activates passkeys (WebAuthn): <c>/passkeys/*</c>, and passkeys in <c>/sign-in-methods</c>. Needs a relying
    /// party id (<see cref="AddPasskeys"/>, or <c>Links.BaseUrl</c>) and the front end's origin among the trusted origins.
    /// </summary>
    public static SlimIdentityBuilder AddPasskeyStore<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TStore>(
        this SlimIdentityBuilder builder, ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TStore : class, ISlimPasskeyStore
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.Replace(new ServiceDescriptor(typeof(ISlimPasskeyStore), typeof(TStore), lifetime));
        return builder.AddPasskeys();
    }

    /// <summary>
    /// Configures passkeys – e.g. <c>o.RelyingPartyId = "example.com"</c>. Can be called before or after
    /// <see cref="AddPasskeyStore{TStore}"/> and several times; a store is required (the EF Core package registers one
    /// with <c>o.Passkeys = true</c>).
    /// </summary>
    public static SlimIdentityBuilder AddPasskeys(this SlimIdentityBuilder builder, Action<SlimPasskeyOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        SlimPasskeyVersion.EnsureSameAsCore();
        var services = builder.Services;
        services.AddOptions<SlimPasskeyOptions>();
        if (configure is not null) services.Configure(configure);
        if (services.Any(d => d.ServiceType == typeof(SlimPasskeyHandlers))) return builder;

        services.TryAddScoped<SlimPasskeyHandlers>();
        services.TryAddScoped<ISlimPasskeySignInMethods, SlimPasskeySignInMethods>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ISlimEndpointModule, SlimPasskeyEndpoints>());
        services.ConfigureHttpJsonOptions(o => o.SerializerOptions.TypeInfoResolverChain.Insert(0, SlimPasskeyJsonContext.Default));
        return builder;
    }
}
