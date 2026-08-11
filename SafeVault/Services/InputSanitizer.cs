using System.Net.Mail;
using System.Text.RegularExpressions;

namespace SafeVault.Services;

public static partial class InputSanitizer
{
    [GeneratedRegex("[^a-zA-Z0-9._-]")]
    private static partial Regex UsernameUnsafeCharacters();

    [GeneratedRegex("[^a-z0-9@._+\\-]")]
    private static partial Regex EmailUnsafeCharacters();

    public static bool TrySanitizeUsername(string? input, out string sanitized)
    {
        sanitized = UsernameUnsafeCharacters().Replace((input ?? string.Empty).Trim(), string.Empty);
        return sanitized.Length is >= 3 and <= 32;
    }

    public static bool TrySanitizeEmail(string? input, out string sanitized)
    {
        var normalized = EmailUnsafeCharacters().Replace((input ?? string.Empty).Trim().ToLowerInvariant(), string.Empty);

        try
        {
            var parsed = new MailAddress(normalized);
            sanitized = parsed.Address;
            return sanitized == normalized;
        }
        catch
        {
            sanitized = string.Empty;
            return false;
        }
    }
}