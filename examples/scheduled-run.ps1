# This script demonstrates how to schedule the full_system_audit.ps1 script to run at specified intervals using Windows Task Scheduler.

$scriptPath = "C:\path\to\your\scripts\full_system_audit.ps1"
$taskName = "Windows Security Audit"
$taskDescription = "Runs the full system audit script to check the security status of the Windows system."
$trigger = New-ScheduledTaskTrigger -Daily -At "2:00AM"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

# Register the scheduled task
Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription -TaskName $taskName -Force

Write-Output "Scheduled task '$taskName' created to run daily at 2:00 AM."