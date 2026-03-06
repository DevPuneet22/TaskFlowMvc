using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using TaskFlowMvc.Data;
using TaskFlowMvc.Models;

namespace TaskFlowMvc.Areas.Identity.Pages.Account;

public class RegisterOtpModel(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    IEmailSender emailSender,
    IConfiguration configuration,
    ILogger<RegisterOtpModel> logger) : PageModel
{
    [BindProperty]
    public InputModel Input { get; set; } = new();

    public class InputModel
    {
        [Required]
        public string UserId { get; set; } = string.Empty;

        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [StringLength(12, MinimumLength = 4)]
        [Display(Name = "OTP code")]
        public string Code { get; set; } = string.Empty;

        public string ReturnUrl { get; set; } = "/";
    }

    public async Task<IActionResult> OnGetAsync(string? userId = null, string? email = null, string? returnUrl = null)
    {
        if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(email))
        {
            return RedirectToPage("./Register");
        }

        var user = await userManager.FindByIdAsync(userId);
        if (user is null || !IsPendingRegistration(user) || !IsEmailMatch(user, email))
        {
            TempData["Error"] = "Registration verification session is invalid or expired.";
            return RedirectToPage("./Register");
        }

        Input = new InputModel
        {
            UserId = userId,
            Email = email,
            ReturnUrl = returnUrl ?? Url.Content("~/")
        };

        return Page();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var user = await userManager.FindByIdAsync(Input.UserId);
        if (user is null || !IsEmailMatch(user, Input.Email))
        {
            ModelState.AddModelError(string.Empty, "Unable to validate this registration request.");
            return Page();
        }

        if (!IsPendingRegistration(user))
        {
            ModelState.AddModelError(string.Empty, "This account is no longer pending OTP verification.");
            return Page();
        }

        var code = (Input.Code ?? string.Empty).Replace(" ", string.Empty).Replace("-", string.Empty);
        var valid = await userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider, code);
        if (!valid)
        {
            ModelState.AddModelError(string.Empty, "Invalid OTP code.");
            return Page();
        }

        user.EmailConfirmed = true;
        user.IsDisabled = false;
        user.DisabledAtUtc = null;
        user.DisabledReason = string.Empty;
        await userManager.UpdateAsync(user);

        await signInManager.SignInAsync(user, isPersistent: false);
        await SendVerificationSuccessEmailAsync(user);
        TempData["Success"] = "Email verified and account activated.";
        return LocalRedirect(string.IsNullOrWhiteSpace(Input.ReturnUrl) ? Url.Content("~/") : Input.ReturnUrl);
    }

    public async Task<IActionResult> OnPostResendAsync()
    {
        if (string.IsNullOrWhiteSpace(Input.UserId) || string.IsNullOrWhiteSpace(Input.Email))
        {
            return RedirectToPage("./Register");
        }

        var user = await userManager.FindByIdAsync(Input.UserId);
        if (user is null || !IsPendingRegistration(user) || !IsEmailMatch(user, Input.Email))
        {
            TempData["Error"] = "Unable to resend OTP for this request.";
            return RedirectToPage("./Register");
        }

        if (!IsSmtpConfigured())
        {
            TempData["Error"] = "Email service is not configured. Unable to resend OTP.";
            return RedirectToPage("./RegisterOtp", new { userId = Input.UserId, email = Input.Email, returnUrl = Input.ReturnUrl });
        }

        await SendRegistrationOtpAsync(user);
        TempData["Info"] = "A new OTP has been sent to your email.";
        return RedirectToPage("./RegisterOtp", new { userId = Input.UserId, email = Input.Email, returnUrl = Input.ReturnUrl });
    }

    private static bool IsPendingRegistration(ApplicationUser user)
    {
        return user.IsDisabled &&
               string.Equals(user.DisabledReason, AuthFlowConstants.PendingRegistrationOtpReason, StringComparison.Ordinal);
    }

    private static bool IsEmailMatch(ApplicationUser user, string email)
    {
        return !string.IsNullOrWhiteSpace(user.Email) &&
               string.Equals(user.Email.Trim(), (email ?? string.Empty).Trim(), StringComparison.OrdinalIgnoreCase);
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

    private async Task SendRegistrationOtpAsync(ApplicationUser user)
    {
        var otp = await userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultEmailProvider);
        await emailSender.SendEmailAsync(
            user.Email!,
            "TaskFlow registration OTP",
            $"Your registration OTP is <strong>{System.Text.Encodings.Web.HtmlEncoder.Default.Encode(otp)}</strong>.<br/>" +
            "Enter this code on the verification page to activate your account.");
    }

    private async Task SendVerificationSuccessEmailAsync(ApplicationUser user)
    {
        if (!IsSmtpConfigured() || string.IsNullOrWhiteSpace(user.Email))
        {
            return;
        }

        try
        {
            await emailSender.SendEmailAsync(
                user.Email,
                "TaskFlow account verified",
                $"Hi {System.Text.Encodings.Web.HtmlEncoder.Default.Encode(user.DisplayName)},<br/>" +
                "Your email has been verified and your account is now active.");
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Unable to send verification success email for user {UserId}", user.Id);
        }
    }
}
