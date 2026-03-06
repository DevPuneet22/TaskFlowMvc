using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using TaskFlowMvc.Data;
using TaskFlowMvc.Models;
using TaskFlowMvc.Services;

namespace TaskFlowMvc.Areas.Identity.Pages.Account;

public class LoginModel(
    SignInManager<ApplicationUser> signInManager,
    UserManager<ApplicationUser> userManager,
    IEmailSender emailSender,
    IConfiguration configuration,
    ISecurityService securityService,
    ILogger<LoginModel> logger) : PageModel
{
    [BindProperty]
    public InputModel Input { get; set; } = new();

    public IList<AuthenticationScheme> ExternalLogins { get; set; } = new List<AuthenticationScheme>();
    public string? ReturnUrl { get; set; }

    [TempData]
    public string? ErrorMessage { get; set; }

    public class InputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }

    public async Task OnGetAsync(string? returnUrl = null)
    {
        if (!string.IsNullOrEmpty(ErrorMessage))
        {
            ModelState.AddModelError(string.Empty, ErrorMessage);
        }

        returnUrl ??= Url.Content("~/");
        await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        ExternalLogins = (await signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
        ReturnUrl = returnUrl;
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");
        ExternalLogins = (await signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

        if (!ModelState.IsValid)
        {
            return Page();
        }

        var normalizedEmail = Input.Email.Trim();
        var user = await userManager.Users.FirstOrDefaultAsync(u => u.NormalizedEmail == normalizedEmail.ToUpperInvariant());
        if (user is null)
        {
            await securityService.RecordLoginActivityAsync(null, normalizedEmail, LoginActivityType.LoginFailed, HttpContext, "Unknown email.");
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return Page();
        }

        if (user.IsDisabled)
        {
            if (string.Equals(user.DisabledReason, AuthFlowConstants.PendingRegistrationOtpReason, StringComparison.Ordinal))
            {
                await securityService.RecordLoginActivityAsync(user.Id, normalizedEmail, LoginActivityType.LoginFailed, HttpContext, "Pending registration OTP verification.");
                TempData["Info"] = "Complete OTP verification to activate your account.";
                return RedirectToPage("./RegisterOtp", new { userId = user.Id, email = user.Email, returnUrl });
            }

            await securityService.RecordLoginActivityAsync(user.Id, normalizedEmail, LoginActivityType.LoginFailed, HttpContext, "User disabled.");
            ModelState.AddModelError(string.Empty, "Your account is disabled. Contact an administrator.");
            return Page();
        }

        var enableEmailOtp = configuration.GetValue<bool>("Authentication:EnableEmailOtp2fa");
        if (enableEmailOtp && !user.TwoFactorEnabled)
        {
            user.TwoFactorEnabled = true;
            await userManager.UpdateAsync(user);
        }

        var result = await signInManager.PasswordSignInAsync(user.UserName!, Input.Password, Input.RememberMe, lockoutOnFailure: true);

        if (result.Succeeded)
        {
            await securityService.RecordLoginActivityAsync(user.Id, normalizedEmail, LoginActivityType.LoginSucceeded, HttpContext);
            logger.LogInformation("User logged in.");
            return LocalRedirect(returnUrl);
        }

        if (result.RequiresTwoFactor)
        {
            var token = await userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
            await emailSender.SendEmailAsync(user.Email!, "Your TaskFlow OTP", $"Your one-time verification code is <strong>{token}</strong>.");
            await securityService.RecordLoginActivityAsync(user.Id, normalizedEmail, LoginActivityType.TwoFactorChallengeSent, HttpContext, "Email OTP sent.");
            return RedirectToPage("./LoginWithOtp", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe, Email = user.Email });
        }

        if (result.IsLockedOut)
        {
            await securityService.RecordLoginActivityAsync(user.Id, normalizedEmail, LoginActivityType.LoginFailed, HttpContext, "User locked out.");
            logger.LogWarning("User account locked out.");
            return RedirectToPage("./Lockout");
        }

        await securityService.RecordLoginActivityAsync(user.Id, normalizedEmail, LoginActivityType.LoginFailed, HttpContext, "Invalid password.");
        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
        return Page();
    }
}
