using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SafeVault.Services;

namespace SafeVault.Pages.Admin;

[Authorize(Roles = AppRoles.Admin)]
public class DashboardModel : PageModel
{
    public void OnGet()
    {
    }
}
