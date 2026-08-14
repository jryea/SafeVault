using Microsoft.EntityFrameworkCore;
using SafeVault.Data;
using SafeVault.Models;
using static BCrypt.Net.BCrypt;

namespace SafeVault.Services;

public class UserAuthenticationService(AppDbContext dbContext)
{
    public async Task<bool> RegisterUserAsync(string username, string email, string password, CancellationToken cancellationToken = default)
    {
        if (!InputSanitizer.TrySanitizeUsername(username, out var sanitizedUsername))
        {
            return false;
        }

        if (!InputSanitizer.TrySanitizeEmail(email, out var sanitizedEmail))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
        {
            return false;
        }

        var exists = await dbContext.Users.AnyAsync(u => u.Username == sanitizedUsername, cancellationToken);
        if (exists)
        {
            return false;
        }

        var passwordHash = HashPassword(password);
        dbContext.Users.Add(new User
        {
            Username = sanitizedUsername,
            Email = sanitizedEmail,
            PasswordHash = passwordHash
        });

        await dbContext.SaveChangesAsync(cancellationToken);
        return true;
    }

    public async Task<User?> AuthenticateAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        if (!InputSanitizer.TrySanitizeUsername(username, out var sanitizedUsername) || string.IsNullOrWhiteSpace(password))
        {
            return null;
        }

        var user = await dbContext.Users.AsNoTracking()
            .SingleOrDefaultAsync(u => u.Username == sanitizedUsername, cancellationToken);

        if (user is null)
        {
            return null;
        }

        return Verify(password, user.PasswordHash) ? user : null;
    }
}