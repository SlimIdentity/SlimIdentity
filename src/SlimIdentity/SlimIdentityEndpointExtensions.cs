namespace BFS.SlimIdentity
{
    public static class SlimIdentityEndpointExtensions
    {
        public static IEndpointRouteBuilder MapSlimIdentity(this IEndpointRouteBuilder endpoints)
        {
            // Optionen aus dem DI-Container holen, um den Route-Prefix zu kennen
            var options = endpoints.ServiceProvider.GetRequiredService<SlimIdentityOptions>();

            // 1. Eine Route-Group erstellen (Standard: "/auth") und den Rate-Limiter als Metadaten anheften
            var group = endpoints.MapGroup(options.RoutePrefix)
                                 .RequireRateLimiting("SlimIdentity_BruteForce");

            // 2. Endpoints mappen (Feature-Toggled)
            if (options.Endpoints.EnableRegistration)
            {
                group.MapPost("/register", async (HttpContext context) =>
                {
                    // TODO: Registration Logic
                    return Results.Ok(new { status = "success" });
                });
            }

            group.MapPost("/login", async (HttpContext context) =>
            {
                // TODO: Login State-Machine Logic
                return Results.Ok(new { status = "success" });
            });

            if (options.Endpoints.EnableLogout)
            {
                group.MapPost("/logout", async (HttpContext context) =>
                {
                    // TODO: Logout Logic
                    return Results.Ok(new { status = "success" });
                });
            }

            return endpoints;
        }
    }
}
