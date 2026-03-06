using System.ComponentModel.DataAnnotations;
using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using TaskFlowMvc.Models;

namespace TaskFlowMvc.Data;

public class ApplicationUser : IdentityUser
{
    private static readonly Regex DisplayNameSeparatorRegex = new(@"[._\-]+", RegexOptions.Compiled);

    public string DisplayName => BuildDisplayName(FirstName, LastName, UserName, Email);

    [StringLength(80)]
    public string FirstName { get; set; } = string.Empty;

    [StringLength(80)]
    public string LastName { get; set; } = string.Empty;

    public bool IsDisabled { get; set; }
    public DateTime? DisabledAtUtc { get; set; }
    public string DisabledReason { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAtUtc { get; set; }

    public List<Project> OwnedProjects { get; set; } = new();
    public List<TaskItem> AssignedTasks { get; set; } = new();
    public List<Team> OwnedTeams { get; set; } = new();
    public List<TeamMember> TeamMemberships { get; set; } = new();
    public List<TeamInvitation> SentTeamInvitations { get; set; } = new();
    public List<LoginActivity> LoginActivities { get; set; } = new();
    public List<DeviceSession> DeviceSessions { get; set; } = new();
    public List<NotificationItem> Notifications { get; set; } = new();
    public List<UserInvitation> SentUserInvitations { get; set; } = new();
    public List<TeamActivityLog> TeamActivities { get; set; } = new();
    public List<TaskComment> TaskComments { get; set; } = new();
    public List<FileAttachment> UploadedFiles { get; set; } = new();
    public List<TimeEntry> TimeEntries { get; set; } = new();

    public static string BuildDisplayName(string? firstName, string? lastName, string? userName, string? email)
    {
        var fullName = string.Join(" ", new[] { firstName, lastName }
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .Select(s => s!.Trim()));

        if (!string.IsNullOrWhiteSpace(fullName))
        {
            return NormalizeWords(fullName);
        }

        return BuildDisplayName(userName, email);
    }

    public static string BuildDisplayName(string? userName, string? email)
    {
        var raw = !string.IsNullOrWhiteSpace(userName)
            ? userName
            : (!string.IsNullOrWhiteSpace(email) ? email : "User");

        var localPart = raw!;
        var atIndex = localPart.IndexOf('@');
        if (atIndex >= 0)
        {
            localPart = localPart[..atIndex];
        }

        var cleaned = DisplayNameSeparatorRegex.Replace(localPart, " ").Trim();
        return NormalizeWords(cleaned);
    }

    private static string NormalizeWords(string value)
    {
        var cleaned = (value ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(cleaned))
        {
            return "User";
        }

        return CultureInfo.InvariantCulture.TextInfo.ToTitleCase(cleaned.ToLowerInvariant());
    }
}
