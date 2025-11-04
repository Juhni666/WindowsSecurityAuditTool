# This script demonstrates how to schedule the full_system_audit.ps1 script to run at specified intervals using Windows Task Scheduler.
# Run this script as Administrator to create the scheduled task.

# Auto-detect the script location relative to this example file
$exampleDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$scriptRoot = Split-Path -Parent $exampleDir
$scriptPath = Join-Path $scriptRoot "scripts\full_system_audit.ps1"
$workingDir = Join-Path $scriptRoot "scripts"

# Verify the script exists
if (-not (Test-Path $scriptPath)) {
    Write-Error "Script not found at: $scriptPath"
    Write-Error "Please update the `$scriptPath variable to point to your full_system_audit.ps1 location"
    exit 1
}

$taskName = "Windows Security Audit"
$taskDescription = "Runs the full system audit script to check the security status of the Windows system."

# Create trigger for daily execution at 3:00 AM
$trigger = New-ScheduledTaskTrigger -Daily -At "3:00AM"

# Create action with proper working directory and arguments
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`"" `
    -WorkingDirectory $workingDir

# Run as SYSTEM account with highest privileges
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Configure settings for the task
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable:$false `
    -DontStopOnIdleEnd

# Register the scheduled task
try {
    Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Description $taskDescription -TaskName $taskName -Force
    
    Write-Output "✓ Scheduled task '$taskName' created successfully"
    Write-Output "  Script: $scriptPath"
    Write-Output "  Working Directory: $workingDir"
    Write-Output "  Schedule: Daily at 3:00 AM"
    Write-Output "  Running as: SYSTEM account"
    Write-Output ""
    Write-Output "To test the task immediately, run:"
    Write-Output "  Start-ScheduledTask -TaskName '$taskName'"
} catch {
    Write-Error "Failed to create scheduled task: $_"
    exit 1
}