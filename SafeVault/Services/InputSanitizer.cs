using System.Net.Mail;
using System.Text.RegularExpressions;

namespace SafeVault.Services;

public static partial class InputSanitizer
{
    [GeneratedRegex("^[a-zA-Z0-9._-]{3,32}$")]
    private static partial Regex UsernameAllowedPattern();

    public static bool TrySanitizeUsername(string? input, out string sanitized)
    {
        sanitized = (input ?? string.Empty).Trim();
        if (!UsernameAllowedPattern().IsMatch(sanitized))
        {
            sanitized = string.Empty;
            return false;
        }

        return true;
    }

    public static bool TrySanitizeEmail(string? input, out string sanitized)
    {
        var normalized = (input ?? string.Empty).Trim().ToLowerInvariant();
        if (normalized.Length is 0 or > 254)
        {
            sanitized = string.Empty;
            return false;
        }

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