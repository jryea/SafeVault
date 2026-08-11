using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SafeVault.Services;
using System.ComponentModel.DataAnnotations;

namespace SafeVault.Pages
{
    public class IndexModel : PageModel
    {
        [BindProperty]
        public InputModel Input { get; set; } = new();

        public string? SanitizedUsername { get; private set; }
        public string? SanitizedEmail { get; private set; }

        public void OnGet()
        {

        }

        public IActionResult OnPost()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            if (!InputSanitizer.TrySanitizeUsername(Input.Username, out var username))
            {
                ModelState.AddModelError("Input.Username", "Username can only contain letters, numbers, ., _, - and must be 3-32 characters.");
                return Page();
            }

            if (!InputSanitizer.TrySanitizeEmail(Input.Email, out var email))
            {
                ModelState.AddModelError("Input.Email", "Email format is invalid.");
                return Page();
            }

            SanitizedUsername = username;
            SanitizedEmail = email;
            return Page();
        }

        public class InputModel
        {
            [Required]
            public string Username { get; set; } = string.Empty;

            [Required]
            [EmailAddress]
            public string Email { get; set; } = string.Empty;
        }
    }
}
