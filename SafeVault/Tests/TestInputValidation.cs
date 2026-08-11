using NUnit.Framework;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using SafeVault.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

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
            var setupSql = @"
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
        // Placeholder for SQL Injection test
    }
    [Test]
    public void TestForXSS()
    {
        var usernameInput = "<script>alert('xss')</script>john";
        var emailInput = "<script>alert('xss')</script>";

        var usernameIsValid = InputSanitizer.TrySanitizeUsername(usernameInput, out var sanitizedUsername);
        var emailIsValid = InputSanitizer.TrySanitizeEmail(emailInput, out _);

        Assert.That(usernameIsValid, Is.True);
        Assert.That(sanitizedUsername, Does.Not.Contain("<"));
        Assert.That(sanitizedUsername, Does.Not.Contain(">"));
        Assert.That(sanitizedUsername, Is.EqualTo("scriptalertxssscriptjohn"));
        Assert.That(emailIsValid, Is.False, "Invalid script-based email payload should be rejected.");
        // Placeholder for XSS test
    }
}