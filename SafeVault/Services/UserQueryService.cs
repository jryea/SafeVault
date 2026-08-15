using Microsoft.Data.Sqlite;
using System.Data;
using SafeVault.Models;

namespace SafeVault.Services;

public class UserQueryService(IConfiguration configuration)
{
    private readonly string _connectionString = configuration.GetConnectionString("DefaultConnection")
        ?? throw new InvalidOperationException("Connection string 'DefaultConnection' was not found.");

    public async Task<User?> GetUserByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        if (!InputSanitizer.TrySanitizeUsername(username, out var sanitizedUsername))
        {
            return null;
        }

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, Email FROM Users WHERE Username = @username LIMIT 1;";
        var usernameParameter = command.CreateParameter();
        usernameParameter.ParameterName = "@username";
        usernameParameter.DbType = DbType.String;
        usernameParameter.Value = sanitizedUsername;
        command.Parameters.Add(usernameParameter);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
        {
            return null;
        }

        return new User
        {
            UserID = reader.GetInt32(0),
            Username = reader.GetString(1),
            Email = reader.GetString(2)
        };
    }

    public async Task<IReadOnlyList<User>> SearchUsersByUsernameAsync(string searchInput, CancellationToken cancellationToken = default)
    {
        var users = new List<User>();
        var normalizedInput = (searchInput ?? string.Empty).Trim();
        if (normalizedInput.Length > 64)
        {
            normalizedInput = normalizedInput[..64];
        }

        var escapedLikeInput = EscapeLikePattern(normalizedInput);

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, Email FROM Users WHERE Username LIKE @searchPattern ESCAPE '\\' ORDER BY Username LIMIT 25;";

        var searchParameter = command.CreateParameter();
        searchParameter.ParameterName = "@searchPattern";
        searchParameter.DbType = DbType.String;
        searchParameter.Value = $"%{escapedLikeInput}%";
        command.Parameters.Add(searchParameter);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            users.Add(new User
            {
                UserID = reader.GetInt32(0),
                Username = reader.GetString(1),
                Email = reader.GetString(2)
            });
        }

        return users;
    }

    private static string EscapeLikePattern(string input)
    {
        return input
            .Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("%", "\\%", StringComparison.Ordinal)
            .Replace("_", "\\_", StringComparison.Ordinal);
    }
}