using Microsoft.Data.Sqlite;
using SafeVault.Models;

namespace SafeVault.Services;

public class UserQueryService(IConfiguration configuration)
{
    private readonly string _connectionString = configuration.GetConnectionString("DefaultConnection")
        ?? throw new InvalidOperationException("Connection string 'DefaultConnection' was not found.");

    public async Task<User?> GetUserByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, Email FROM Users WHERE Username = @username LIMIT 1;";
        command.Parameters.AddWithValue("@username", username);

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

        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT UserID, Username, Email FROM Users WHERE Username LIKE @searchPattern ORDER BY Username LIMIT 25;";
        command.Parameters.AddWithValue("@searchPattern", $"%{searchInput}%");

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
}