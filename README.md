# TaskFlow MVC

TaskFlow MVC is an ASP.NET Core MVC app for collaborative team, project, and task management.

## Current implementation status

### Authentication and identity
- ASP.NET Core Identity login/register/logout.
- Custom registration form that captures first name, last name, phone number, email, and password.
- Enhanced login and OTP screens with improved UI.
- Password policy and account lockout policy.
- Optional social logins: Google, GitHub, LinkedIn (enabled only when keys are configured).
- Email OTP login flow using Identity 2FA email tokens (`Login` -> `LoginWithOtp`).
- Registration OTP verification flow (`Register` -> `RegisterOtp`) with account activation after OTP validation.
- Registration emails include account-created notice and OTP code delivery.
- Optional `RequireConfirmedAccount` behavior from config.
- Automatic verification email reminder filter for signed-in, unconfirmed users (once per session).

### Security and session control
- Configurable session timeout (`Authentication:SessionTimeoutMinutes`, clamped to 5-720 minutes).
- Device session tracking via secure cookie claims + DB records.
- Login activity history (success/failure, 2FA challenge/result, logout).
- Security dashboard for revoking one device session or logging out all other devices.
- Disabled users are rejected during cookie validation.

### Roles and admin
- Roles: `Admin`, `TeamLeader`, `TeamMember`, `Viewer`.
- Roles are auto-created on startup.
- If no admins exist, the first registered user is auto-promoted to `Admin`.
- Admin user management UI for creating users, inviting users by email, changing roles, and disabling/enabling accounts.

### Team management
- Create teams.
- Invite members by email with invite role and expiring token.
- Accept/revoke invites.
- Change member roles.
- Remove members.
- Transfer leadership.
- Team workload view (open tasks by assignee).
- Team activity log.

### Project and task management
- Project CRUD for owners.
- Project archive action.
- Optional project-to-team assignment.
- Project milestones (add + mark complete).
- Project timeline view (tasks + milestones by date).
- Global timeline view (all accessible tasks grouped by due date).
- Task CRUD.
- Task filtering by status, priority, assignee, and label.
- Task assignment and status updates.
- Bulk status update and bulk assignee update.
- Subtasks.
- Kanban drag-and-drop status updates (SortableJS + POST to `UpdateTaskStatus`).
- Task template save action.
- Recurrence fields can be stored/edited on tasks.

### Collaboration, comments, and files
- Task comments (add/edit/delete with soft delete).
- Mentions in comments (`@email`, `@username`, `@userId`) with mention notifications.
- Emoji reactions on comments.
- Multi-file attachments on comments.
- Attachment preview/download endpoints with project access checks: `/Attachments/Preview/{id}` and `/Attachments/Download/{id}`.
- Attachment versioning for same `task + comment + filename`.
- Local file storage in `wwwroot/uploads/comments` with path traversal protections.

### Notifications
- In-app notifications persisted in DB.
- Optional email notifications through SMTP.
- SignalR hub at `/hubs/notifications`.
- Real-time unread badge + toast notifications in layout.
- Background service checks every 30 minutes for overdue tasks and sends one overdue notification per task/user/day.

### Time tracking and reporting
- Start/stop timer per task.
- Only one active timer per user at a time (starting a new one ends the previous).
- Manual time log entry.
- Tracked minutes shown per task in project details.
- Reports dashboard with date-range filtering and CSV export.

## Partially wired / known gaps
- `CreateTaskFromTemplate` endpoint exists, but there is no UI flow to select and create from saved templates.
- Task dependency service/actions exist (`AddDependency`, `RemoveDependency`), but current views do not expose dependency management forms.
- Recurrence metadata is stored on tasks, but there is no scheduler/background job that automatically spawns future recurring tasks.
- No dedicated automated test project is currently included.

## Tech stack
- .NET 10 (`net10.0`)
- ASP.NET Core MVC + Identity
- Entity Framework Core 10 (SQL Server provider)
- SignalR
- Bootstrap 5, Chart.js, SortableJS

## Prerequisites
1. .NET 10 SDK
2. SQL Server LocalDB (or another SQL Server instance)
3. `dotnet-ef` tool

Install `dotnet-ef` if needed:

```powershell
dotnet tool install --global dotnet-ef
```

## Configuration

Main settings are in `appsettings.json` / `appsettings.Development.json`:

- `ConnectionStrings:DefaultConnection`
- `Authentication:RequireConfirmedAccount`
- `Authentication:SessionTimeoutMinutes`
- `Authentication:EnableEmailOtp2fa`
- `Authentication:Google:ClientId`
- `Authentication:Google:ClientSecret`
- `Authentication:GitHub:ClientId`
- `Authentication:GitHub:ClientSecret`
- `Authentication:LinkedIn:ClientId`
- `Authentication:LinkedIn:ClientSecret`
- `Email:Smtp:*` (for OTP/notification/invite emails)

Use user-secrets for sensitive values:

```powershell
dotnet user-secrets init
dotnet user-secrets set "Authentication:Google:ClientId" "your-client-id"
dotnet user-secrets set "Authentication:Google:ClientSecret" "your-client-secret"
dotnet user-secrets set "Authentication:GitHub:ClientId" "your-github-client-id"
dotnet user-secrets set "Authentication:GitHub:ClientSecret" "your-github-client-secret"
dotnet user-secrets set "Authentication:LinkedIn:ClientId" "your-linkedin-client-id"
dotnet user-secrets set "Authentication:LinkedIn:ClientSecret" "your-linkedin-client-secret"
dotnet user-secrets set "Email:Smtp:Host" "smtp.gmail.com"
dotnet user-secrets set "Email:Smtp:Port" "587"
dotnet user-secrets set "Email:Smtp:Username" "your-email"
dotnet user-secrets set "Email:Smtp:Password" "your-app-password"
dotnet user-secrets set "Email:Smtp:FromEmail" "your-email"
dotnet user-secrets set "Email:Smtp:FromName" "TaskFlow MVC"
dotnet user-secrets set "Email:Smtp:EnableSsl" "true"
```

OAuth callback URLs used by this app:
- Google: `https://localhost:5001/signin-google`
- GitHub: `https://localhost:5001/signin-github`
- LinkedIn: `https://localhost:5001/signin-linkedin`

## Run locally

```powershell
cd C:\Users\PuneetGupta\Desktop\TaskFlowMvc
dotnet restore
dotnet ef database update --project .\TaskFlowMvc.csproj
dotnet build .\TaskFlowMvc.csproj
dotnet run --launch-profile https
```

Launch profile uses fixed local URLs: `https://localhost:5001` and `http://localhost:5000`.

## Useful commands

```powershell
dotnet build .\TaskFlowMvc.csproj
dotnet ef migrations list --project .\TaskFlowMvc.csproj
dotnet run --launch-profile https
```

If you get "Failed to bind to address ... address already in use", use:

```powershell
.\restart-dev.ps1
```
