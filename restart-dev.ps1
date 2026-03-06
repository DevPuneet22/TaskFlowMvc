param(
    [switch]$NoBuild
)

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ports = @(5000, 5001)
$targetPids = New-Object System.Collections.Generic.HashSet[int]

foreach ($port in $ports) {
    $listeners = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue
    foreach ($listener in $listeners) {
        if ($listener.OwningProcess -gt 0 -and $listener.OwningProcess -ne $PID) {
            [void]$targetPids.Add($listener.OwningProcess)
        }
    }
}

foreach ($pidToStop in $targetPids) {
    try {
        $proc = Get-Process -Id $pidToStop -ErrorAction Stop
        if ($proc.ProcessName -eq "TaskFlowMvc" -or $proc.ProcessName -eq "dotnet") {
            Write-Host "Stopping process $($proc.ProcessName) (PID $pidToStop) using port 5000/5001..."
            Stop-Process -Id $pidToStop -Force
        }
    }
    catch {
        # Ignore processes that exit between query and stop.
    }
}

Set-Location $projectRoot
$args = @("run", "--launch-profile", "https")
if ($NoBuild) {
    $args += "--no-build"
}

Write-Host "Starting TaskFlowMvc on https://localhost:5001 ..."
& dotnet @args
