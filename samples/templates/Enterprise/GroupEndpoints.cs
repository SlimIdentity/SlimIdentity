// SlimIdentity sample – groups and permissions on top of claims (no permission model in SlimIdentity itself).
//
//   Your data:  Group ── GroupMember ── AppUser,  Group ── GroupPermission ("reports.read", …)   (EfCore/EfCoreModel.cs)
//   Claims:     EfCoreUserStore.GetClaimsAsync resolves them to "permission" claims                (EfCore/EfCoreStores.cs)
//   Policies:   builder.Services.AddAuthorizationBuilder()
//                   .AddPolicy("reports.read", p => p.RequireClaim("permission", "reports.read"));
//               app.MapGet("/api/reports", …).RequireAuthorization("reports.read");
//   Changes:    after every change, RefreshClaimsAsync for each affected user – running sessions pick up the new
//               claims at their next validation, nobody is signed out (see docs/guides/roles-and-permissions.md).
//
//   app.MapGroupEndpoints();

using SlimIdentity;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using MyApp.Data;

namespace MyApp.Enterprise;

public static class GroupEndpoints
{
    public sealed record PermissionsRequest(string[] Permissions);

    public static IEndpointRouteBuilder MapGroupEndpoints(this IEndpointRouteBuilder app)
    {
        // managing permissions is itself a permission – and a sensitive one: behind a fresh sudo session
        var groups = app.MapGroup("/api/admin/groups")
            .RequireAuthorization(p => p.RequireClaim("permission", "groups.manage"))
            .RequireAuthorization(SlimIdentityDefaults.SudoPolicy)
            .RequireSlimCsrf();

        groups.MapPut("/{groupId:guid}/members/{userId:guid}", async (Guid groupId, Guid userId, AppDbContext db, ISlimUserStore users, ISlimAuthManager auth, CancellationToken ct) =>
        {
            if (!await db.GroupMembers.AnyAsync(m => m.GroupId == groupId && m.UserId == userId, ct))
            {
                db.GroupMembers.Add(new GroupMember { GroupId = groupId, UserId = userId });
                await db.SaveChangesAsync(ct);
            }
            await RefreshAsync([userId], users, auth, ct);
            return Results.Ok(new { status = "member_added" });
        });

        groups.MapDelete("/{groupId:guid}/members/{userId:guid}", async (Guid groupId, Guid userId, AppDbContext db, ISlimUserStore users, ISlimAuthManager auth, CancellationToken ct) =>
        {
            await db.GroupMembers.Where(m => m.GroupId == groupId && m.UserId == userId).ExecuteDeleteAsync(ct);
            await RefreshAsync([userId], users, auth, ct);   // the removed member loses the permissions within a minute
            return Results.Ok(new { status = "member_removed" });
        });

        groups.MapPut("/{groupId:guid}/permissions", async (Guid groupId, PermissionsRequest req, AppDbContext db, ISlimUserStore users, ISlimAuthManager auth, CancellationToken ct) =>
        {
            await db.GroupPermissions.Where(p => p.GroupId == groupId).ExecuteDeleteAsync(ct);
            db.GroupPermissions.AddRange(req.Permissions.Distinct().Select(p => new GroupPermission { GroupId = groupId, Permission = p }));
            await db.SaveChangesAsync(ct);

            // a group change affects every member (large groups: do this in a background job)
            var members = await db.GroupMembers.Where(m => m.GroupId == groupId).Select(m => m.UserId).ToListAsync(ct);
            await RefreshAsync(members, users, auth, ct);
            return Results.Ok(new { status = "permissions_set", refreshed = members.Count });
        });

        return app;
    }

    private static async Task RefreshAsync(IEnumerable<Guid> userIds, ISlimUserStore users, ISlimAuthManager auth, CancellationToken ct)
    {
        foreach (var id in userIds)
            if (await users.FindByIdAsync(id.ToString(), ct) is { } user)
                await auth.RefreshClaimsAsync(user, ct);
    }
}
