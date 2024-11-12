using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.HttpLogging;

var builder = WebApplication.CreateBuilder(args);

// Existing service configurations

builder.Services.AddDbContext<IdentityDbContext>(options =>
    options.UseInMemoryDatabase("AuthDemoDB"));

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<IdentityDbContext>();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Events.OnRedirectToLogin = context =>
    {
        if (context.Request.Path.StartsWithSegments("/api") && context.Response.StatusCode == StatusCodes.Status200OK)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        }
        context.Response.Redirect(context.RedirectUri);
        return Task.CompletedTask;
    };
});

builder.Services.AddCors();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
    options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
    options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
});

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("admin_Access", policy => policy.RequireRole("Admin"));

builder.Services.AddAuthorizationBuilder()
    .AddPolicy("ITDepartment", policy => policy.RequireClaim("Department", "IT"));

builder.Services.AddHttpLogging(logging =>
{
    logging.LoggingFields = HttpLoggingFields.All;
    logging.RequestBodyLogLimit = 4096;
    logging.ResponseBodyLogLimit = 4096;
});

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

var app = builder.Build();

app.UseCors();
app.UseHttpLogging();
app.UseAuthentication();
app.UseAuthorization();

// Define basic routes
app.MapGet("/", () => "Minimal API with Roles and Claims Example");


// RequireAuthorization
app.MapGet("/api/admin-only", () => "Admin access only").RequireAuthorization("admin_Access");
app.MapGet("/api/user-claim-check", () => "Access granted to IT department").RequireAuthorization("ITDepartment");

var roles = new[] { "Admin", "User" };

app.MapPost("/api/create-role", async (RoleManager<IdentityRole> roleManager) =>
{
    foreach (var role in roles)
    {
        if (!await roleManager.RoleExistsAsync(role))
        {
            await roleManager.CreateAsync(new IdentityRole(role));
        }
    }
    return Results.Ok("Roles created successfully");
});

app.MapPost("/api/login", async (SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager) =>
{
    var user = await userManager.FindByEmailAsync("testuser@example.com");
    if (user == null)
    {
        return Results.NotFound("User not found");
    }

    await signInManager.SignInAsync(user, isPersistent: false);
    return Results.Ok("User signed in");
});

app.MapPost("/api/assign-role", async (UserManager<IdentityUser> userManager) =>
{
    var user = new IdentityUser { UserName = "testuser@example.com", Email = "testuser@example.com" };
    await userManager.CreateAsync(user, "Test@1234");
    await userManager.AddToRoleAsync(user, "Admin");

    // Check if the user is in the Admin role
    var isInRole = await userManager.IsInRoleAsync(user, "Admin");



    return isInRole
        ? Results.Ok("User created and successfully assigned to Admin role")
        : Results.BadRequest("User created but failed to assign Admin role");
});

app.MapPost("/api/add-claim", async (UserManager<IdentityUser> userManager) =>
{
    var user = await userManager.FindByEmailAsync("testuser@example.com");
    if (user == null) return Results.NotFound("User not found");

    await userManager.AddClaimAsync(user, new Claim("Department", "IT"));

    // Retrieve and return claims for debugging
    var claims = await userManager.GetClaimsAsync(user);
    var hasITClaim = claims.Any(c => c.Type == "Department" && c.Value == "IT");

    return hasITClaim
        ? Results.Ok("Claim added and verified on user")
        : Results.BadRequest("Claim addition failed");
});

app.Run();
