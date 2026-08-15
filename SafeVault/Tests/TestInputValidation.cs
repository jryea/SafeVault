using System.Security.Claims;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;
using static BCrypt.Net.BCrypt;

[TestFixture]
public class TestInputValidation
{
    [Test]
    public async Task TestForSQLInjection()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"safevault-security-{Guid.NewGuid():N}.db");

        await using (var connection = new SqliteConnection($"Data Source={databasePath}"))
        {
            await connection.OpenAsync();
            const string setupSql = @"
                CREATE TABLE Users (
                    UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                    Username TEXT NOT NULL,
                    Email TEXT NOT NULL
                );
                INSERT INTO Users (Username, Email) VALUES ('alice', 'alice@example.com');";

            await using var setupCommand = connection.CreateCommand();
            setupCommand.CommandText = setupSql;
            await setupCommand.ExecuteNonQueryAsync();
        }

        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:DefaultConnection"] = $"Data Source={databasePath}"
                })
                .Build();

            var service = new UserQueryService(configuration);
            var maliciousInput = "alice' OR 1=1 --";

            var result = await service.GetUserByUsernameAsync(maliciousInput);

            Assert.That(result, Is.Null, "Parameterized query should treat SQL injection payload as literal text.");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath))
            {
                File.Delete(databasePath);
            }
        }
    }

    [Test]
    public async Task SearchUsers_SQLInjectionPayload_DoesNotBypassFilter()
    {
        var databasePath = Path.Combine(Path.GetTempPath(), $"safevault-search-security-{Guid.NewGuid():N}.db");

        await using (var connection = new SqliteConnection($"Data Source={databasePath}"))
        {
            await connection.OpenAsync();
            const string setupSql = @"
                CREATE TABLE Users (
                    UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                    Username TEXT NOT NULL,
                    Email TEXT NOT NULL
                );
                INSERT INTO Users (Username, Email) VALUES ('alice', 'alice@example.com');
                INSERT INTO Users (Username, Email) VALUES ('bob', 'bob@example.com');";

            await using var setupCommand = connection.CreateCommand();
            setupCommand.CommandText = setupSql;
            await setupCommand.ExecuteNonQueryAsync();
        }

        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["ConnectionStrings:DefaultConnection"] = $"Data Source={databasePath}"
                })
                .Build();

            var service = new UserQueryService(configuration);
            var maliciousSearch = "%' OR 1=1 --";

            var results = await service.SearchUsersByUsernameAsync(maliciousSearch);

            Assert.That(results, Is.Empty, "Escaped LIKE pattern and parameters should prevent wildcard/SQL payload bypass.");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(databasePath))
            {
                File.Delete(databasePath);
            }
        }
    }

    [Test]
    public void TestForXSS()
    {
        var usernameInput = "<script>alert('xss')</script>john";
        var emailInput = "<script>alert('xss')</script>";

        var usernameIsValid = InputSanitizer.TrySanitizeUsername(usernameInput, out var sanitizedUsername);
        var emailIsValid = InputSanitizer.TrySanitizeEmail(emailInput, out _);

        Assert.That(usernameIsValid, Is.False, "Username with script payload should be rejected, not transformed.");
        Assert.That(sanitizedUsername, Is.EqualTo(string.Empty));
        Assert.That(emailIsValid, Is.False, "Invalid script-based email payload should be rejected.");
    }

    [Test]
    public async Task RegisterUser_XssPayloadInFormFields_IsRejected()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        await using var dbContext = CreateDbContext(connection);
        await dbContext.Database.EnsureCreatedAsync();

        var service = new UserAuthenticationService(dbContext);

        var created = await service.RegisterUserAsync("<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "Password123!");

        Assert.That(created, Is.False, "Registration must fail when form fields contain malicious scripts.");
        Assert.That(await dbContext.Users.CountAsync(), Is.EqualTo(0));
    }

    [Test]
    public async Task AuthenticateAsync_InvalidPassword_ReturnsNull()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        var dbContext = CreateDbContext(connection);
        await dbContext.Database.EnsureCreatedAsync();
        dbContext.Users.Add(new User
        {
            Username = "admin",
            Email = "admin@example.com",
            PasswordHash = HashPassword("CorrectPassword1!"),
            Role = AppRoles.Admin
        });
        await dbContext.SaveChangesAsync();

        var service = new UserAuthenticationService(dbContext);
        var result = await service.AuthenticateAsync("admin", "WrongPassword1!");

        Assert.That(result, Is.Null, "Invalid login attempts must not authenticate the user.");
    }

    [Test]
    public async Task RegisterUserAsync_AssignsAdminToFirstUser_AndUserToSecond()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();

        var dbContext = CreateDbContext(connection);
        await dbContext.Database.EnsureCreatedAsync();

        var service = new UserAuthenticationService(dbContext);

        var firstCreated = await service.RegisterUserAsync("firstadmin", "first@example.com", "Password123!");
        var secondCreated = await service.RegisterUserAsync("seconduser", "second@example.com", "Password123!");

        var users = await dbContext.Users.OrderBy(u => u.UserID).ToListAsync();

        Assert.Multiple(() =>
        {
            Assert.That(firstCreated, Is.True);
            Assert.That(secondCreated, Is.True);
            Assert.That(users.Count, Is.EqualTo(2));
            Assert.That(users[0].Role, Is.EqualTo(AppRoles.Admin));
            Assert.That(users[1].Role, Is.EqualTo(AppRoles.User));
        });
    }

    [Test]
    public void AccessControl_RequiresAdminRole()
    {
        var unauthenticatedPrincipal = new ClaimsPrincipal(new ClaimsIdentity());
        var userPrincipal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, "basicuser"), new Claim(ClaimTypes.Role, AppRoles.User)],
            "Cookies"));
        var adminPrincipal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.Name, "admin"), new Claim(ClaimTypes.Role, AppRoles.Admin)],
            "Cookies"));

        Assert.Multiple(() =>
        {
            Assert.That(unauthenticatedPrincipal.Identity?.IsAuthenticated ?? false, Is.False);
            Assert.That(unauthenticatedPrincipal.IsInRole(AppRoles.Admin), Is.False, "Unauthenticated users are unauthorized for admin features.");
            Assert.That(userPrincipal.IsInRole(AppRoles.Admin), Is.False, "Non-admin role should be denied admin access.");
            Assert.That(adminPrincipal.IsInRole(AppRoles.Admin), Is.True, "Admin role should be authorized for admin access.");
        });
    }

    private static AppDbContext CreateDbContext(SqliteConnection connection)
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseSqlite(connection)
            .Options;

        return new AppDbContext(options);
    }
}
