using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TaskFlowMvc.Data;
using TaskFlowMvc.Models;

namespace TaskFlowMvc.Areas.Identity.Pages.Account;

public class RegisterModel(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    IEmailSender emailSender,
    IConfiguration configuration,
    ILogger<RegisterModel> logger) : PageModel
{
    [BindProperty]
    public InputModel Input { get; set; } = new();

    public string? ReturnUrl { get; set; }
    public IList<AuthenticationScheme> ExternalLogins { get; set; } = new List<AuthenticationScheme>();

    public class InputModel
    {
        [Required]
        [StringLength(80)]
        [Display(Name = "First name")]
        public string FirstName { get; set; } = string.Empty;

        [Required]
        [StringLength(80)]
        [Display(Name = "Last name")]
        public string LastName { get; set; } = string.Empty;

        [Phone]
        [StringLength(30)]
        [Display(Name = "Phone number")]
        public string? PhoneNumber { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 8)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;

        [DataType(DataType.Password)]
        [Display(Name = "Confirm password")]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public async Task OnGetAsync(string? returnUrl = null)
    {
        ReturnUrl = returnUrl;
        ExternalLogins = (await signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
    }

    public async Task<IActionResult> OnPostAsync(string? returnUrl = null)
    {
        returnUrl ??= Url.Content("~/");
        ReturnUrl = returnUrl;
        ExternalLogins = (await signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

        if (!ModelState.IsValid)
        {
            return Page();
        }

        if (!IsSmtpConfigured())
        {
            ModelState.AddModelError(string.Empty, "Email service is not configured. Registration OTP cannot be sent.");
            return Page();
        }

        var email = (Input.Email ?? string.Empty).Trim();
        var firstName = NormalizeName(Input.FirstName);
        var lastName = NormalizeName(Input.LastName);
        var phone = string.IsNullOrWhiteSpace(Input.PhoneNumber) ? null : Input.PhoneNumber.Trim();

        var existing = await userManager.FindByEmailAsync(email);
        if (existing is not null)
        {
            if (!IsPendingRegistration(existing))
            {
                ModelState.AddModelError(string.Empty, "An account with this email already exists. Please log in.");
                return Page();
            }

            var deleteResult = await userManager.DeleteAsync(existing);
            if (!deleteResult.Succeeded)
            {
                foreach (var error in deleteResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }

                return Page();
            }
        }

        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            FirstName = firstName,
            LastName = lastName,
            PhoneNumber = phone,
            EmailConfirmed = false,
            IsDisabled = true,
            DisabledReason = AuthFlowConstants.PendingRegistrationOtpReason,
            DisabledAtUtc = DateTime.UtcNow,
            CreatedAtUtc = DateTime.UtcNow
        };

        var createResult = await userManager.CreateAsync(user, Input.Password);
        if (!createResult.Succeeded)
        {
            foreach (var error in createResult.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return Page();
        }

        // New self-registered users default to Viewer role.
        await userManager.AddToRoleAsync(user, AppRoles.Viewer);
        logger.LogInformation("A new user account was created and marked pending OTP verification.");

        try
        {
            await SendAccountCreatedEmailAsync(user);
            await SendRegistrationOtpAsync(user);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Failed sending registration emails for user {UserId}", user.Id);
            await userManager.DeleteAsync(user);
            ModelState.AddModelError(string.Empty, "Unable to send verification email right now. Please try again.");
            return Page();
        }

        TempData["Info"] = $"A verification OTP was sent to {email}.";
        return RedirectToPage("./RegisterOtp", new { userId = user.Id, email, returnUrl });
    }

    private static string NormalizeName(string value)
    {
        return (value ?? string.Empty).Trim();
    }

    private static bool IsPendingRegistration(ApplicationUser user)
    {
        return user.IsDisabled &&
               string.Equals(user.DisabledReason, AuthFlowConstants.PendingRegistrationOtpReason, StringComparison.Ordinal);
    }

    private bool IsSmtpConfigured()
    {
        var host = configuration["Email:Smtp:Host"];
        var username = configuration["Email:Smtp:Username"];
        var password = configuration["Email:Smtp:Password"];
        var fromEmail = configuration["Email:Smtp:FromEmail"];

        return !string.IsNullOrWhiteSpace(host) &&
               !string.IsNullOrWhiteSpace(username) &&
               !string.IsNullOrWhiteSpace(password) &&
               !string.IsNullOrWhiteSpace(fromEmail);
    }

    private async Task SendAccountCreatedEmailAsync(ApplicationUser user)
    {
        await emailSender.SendEmailAsync(
            user.Email!,
            "TaskFlow account created",
            $"Hi {System.Text.Encodings.Web.HtmlEncoder.Default.Encode(user.DisplayName)},<br/>" +
            "Your TaskFlow account has been created successfully.<br/>" +
            "Complete OTP verification to activate your account.");
    }

    private async Task SendRegistrationOtpAsync(ApplicationUser user)
    {
        var otp = await userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
        await emailSender.SendEmailAsync(
            user.Email!,
            "TaskFlow registration OTP",
            $"Your registration OTP is <strong>{System.Text.Encodings.Web.HtmlEncoder.Default.Encode(otp)}</strong>.<br/>" +
            "This code is required to verify your email and activate your account.");
    }
}
