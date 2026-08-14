using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SafeVault.Services;
using System.ComponentModel.DataAnnotations;

namespace SafeVault.Pages;

public class LoginModel(UserAuthenticationService authenticationService) : PageModel
{
    [BindProperty]
    public LoginInput Input { get; set; } = new();

    [BindProperty]
    public RegisterInput Register { get; set; } = new();

    public string? Message { get; private set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostLoginAsync(CancellationToken cancellationToken)
    {
        if (!TryValidateModel(Input, nameof(Input)))
        {
            return Page();
        }

        var user = await authenticationService.AuthenticateAsync(Input.Username, Input.Password, cancellationToken);
        Register = new RegisterInput();
        if (user is null)
        {
            ModelState.AddModelError(string.Empty, "Invalid username or password.");
            return Page();
        }

        Message = $"Authenticated: {user.Username}";
        return Page();
    }

    public async Task<IActionResult> OnPostRegisterAsync(CancellationToken cancellationToken)
    {
        if (!TryValidateModel(Register, nameof(Register)))
        {
            return Page();
        }

        var registered = await authenticationService.RegisterUserAsync(Register.Username, Register.Email, Register.Password, cancellationToken);
        Input = new LoginInput();
        if (!registered)
        {
            ModelState.AddModelError(string.Empty, "Registration failed. Use a unique username, valid email, and password of at least 8 characters.");
            return Page();
        }

        Message = "Registration successful. You can now sign in.";
        return Page();
    }

    public class LoginInput
    {
        [Required]
        public string Username { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;
    }

    public class RegisterInput
    {
        [Required]
        public string Username { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [MinLength(8)]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;
    }
}
