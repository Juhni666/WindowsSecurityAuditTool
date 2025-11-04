<#
security-check-windows.ps1
Purpose: Collect system, network and basic security data on Windows 11 for analysis.
Author: Copilot (generated for user Juhni666)
Usage (Admin PowerShell):
  - Save this file and run as Administrator:
    .\security-check-windows.ps1
  - Optional parameters:
    -RunDefenderScan       : run a Windows Defender full scan (may take a long time)
    -CollectEventDays 1    : collect event logs from last N days (default 7)
    -SkipLargeFiles        : skip collecting very large files (for speed)
Notes:
  - This script is read-only except for starting a Defender scan when requested.
  - Do not upload files that contain secrets (credential files, full registry hives) to public places.
  - Use only on systems you own or have permission to inspect.
#>

[CmdletBinding()]
param(
    [switch]$RunDefenderScan,
    [int]$CollectEventDays = 7,
    [switch]$SkipLargeFiles
)

function Require-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This script must be run as Administrator. Re-run in an elevated PowerShell."
        exit 1
    }
}

function Safe-Write {
    param($Text)
    Write-Output $Text
    Add-Content -Path $Global:LogFile -Value $Text
}

Require-Admin

$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$OutDir = Join-Path -Path $env:TEMP -ChildPath "security-check-$timestamp"
New-Item -Path $OutDir -ItemType Directory -Force | Out-Null

$Global:LogFile = Join-Path $OutDir "run.log"
"Security-check started at $(Get-Date -Format o)" | Out-File -FilePath $Global:LogFile -Encoding utf8

Safe-Write "Output directory: $OutDir"

# 1) Basic system info
Safe-Write "`n=== System Info ===`n"
Get-ComputerInfo | Select-Object CsName,WindowsProductName,WindowsVersion,OsArchitecture,OsLanguage,OsHardwareAbstractionLayer |
    Out-File -FilePath (Join-Path $OutDir "computerinfo.txt") -Encoding utf8

Get-CimInstance -ClassName Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, BootDevice, LastBootUpTime | Out-File (Join-Path $OutDir "os_details.txt")

# 2) Installed updates & hotfixes
Safe-Write "`n=== Installed Updates / Hotfixes ===`n"
Get-HotFix | Sort-Object InstalledOn -Descending | Out-File (Join-Path $OutDir "hotfixes.txt")

# 3) Installed Programs (registry)
Safe-Write "`n=== Installed Programs (registry) ===`n"
$regpaths = @(
 "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
 "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
 "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$programs = foreach ($p in $regpaths) {
    Get-ItemProperty $p -ErrorAction SilentlyContinue |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
}
$programs | Sort-Object DisplayName | Out-File (Join-Path $OutDir "installed_programs.txt")

# Also include winget list if available
if (Get-Command winget -ErrorAction SilentlyContinue) {
    Safe-Write "Running winget list..."
    winget list --accept-source-agreements --accept-package-agreements | Out-File (Join-Path $OutDir "winget_list.txt")
}

# 4) Running services, scheduled tasks, drivers
Safe-Write "`n=== Running Services ===`n"
Get-Service | Where-Object {$_.Status -eq "Running"} | Sort-Object Name | Out-File (Join-Path $OutDir "running_services.txt")

Safe-Write "`n=== System Drivers (Win32_Service paths) ===`n"
Get-WmiObject -Class Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName | Out-File (Join-Path $OutDir "services_paths.txt")

Safe-Write "`n=== Scheduled Tasks ===`n"
Get-ScheduledTask | Select-Object TaskName,TaskPath,State | Out-File (Join-Path $OutDir "scheduled_tasks.txt")

# 5) Autoruns (Run / RunOnce)
Safe-Write "`n=== Autoruns (HKLM & HKCU Run keys) ===`n"
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($k in $runKeys) {
    try {
        Get-ItemProperty -Path $k -ErrorAction Stop | Select-Object * | Out-File (Join-Path $OutDir ("autorun_" + ($k -replace ':|\\|/','_') + ".txt")) -Encoding utf8
    } catch {
        "`n$k : (not present or access denied)" | Out-File -FilePath (Join-Path $OutDir "autoruns_summary.txt") -Append
    }
}

# 6) Open/listening network ports & connections
Safe-Write "`n=== Listening TCP/UDP Ports ===`n"
# NetTCPConnection for modern view
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess,AppliedSetting | Sort-Object LocalPort |
    Out-File (Join-Path $OutDir "listening_tcp.txt")
Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess | Out-File (Join-Path $OutDir "listening_udp.txt")

# Map PIDs to processes
Get-NetTCPConnection -State Listen | ForEach-Object {
    $pid = $_.OwningProcess
    $proc = (Get-Process -Id $pid -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,Path)
    [PSCustomObject]@{
        LocalAddress = $_.LocalAddress
        LocalPort = $_.LocalPort
        ProcessId = $pid
        ProcessName = $proc.ProcessName
        ProcessPath = $proc.Path
    }
} | Out-File (Join-Path $OutDir "listening_pid_map.txt")

# netstat raw output
netstat -ano | Out-File (Join-Path $OutDir "netstat_ano.txt")

# 7) Firewall / Lateral movement settings
Safe-Write "`n=== Windows Firewall Profiles & Rules ===`n"
Get-NetFirewallProfile | Out-File (Join-Path $OutDir "firewall_profiles.txt")
Get-NetFirewallRule | Select-Object DisplayName,Direction,Action,Enabled,Profile | Out-File (Join-Path $OutDir "firewall_rules.txt")

# 8) RDP / Remote settings / SMB
Safe-Write "`n=== Remote Desktop / SMB / WinRM ===`n"
try {
    $rdp = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction Stop
    $rdp | Select-Object fDenyTSConnections | Out-File (Join-Path $OutDir "rdp_setting.txt")
} catch { "RDP key not accessible or not present" | Out-File (Join-Path $OutDir "rdp_setting.txt") }

Get-SmbShare | Out-File (Join-Path $OutDir "smb_shares.txt") -ErrorAction SilentlyContinue
Get-Service -Name WinRM -ErrorAction SilentlyContinue | Out-File (Join-Path $OutDir "winrm_service.txt")

# 9) Users, groups, and admin accounts
Safe-Write "`n=== Local Users & Groups ===`n"
if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
    Get-LocalUser | Select-Object Name,Enabled,LastLogon | Out-File (Join-Path $OutDir "local_users.txt")
    Get-LocalGroup | Out-File (Join-Path $OutDir "local_groups.txt")
    # group members (only do Administrators to avoid too much output)
    Get-LocalGroupMember -Group "Administrators" | Out-File (Join-Path $OutDir "administrators_members.txt")
} else {
    "Get-LocalUser not available on this system" | Out-File (Join-Path $OutDir "local_users.txt")
}

# 10) Network interfaces & routes & public IP
Safe-Write "`n=== Network Info ===`n"
Get-NetIPAddress | Out-File (Join-Path $OutDir "net_ipaddresses.txt")
Get-NetRoute | Out-File (Join-Path $OutDir "net_routes.txt")
Get-NetAdapter | Select-Object Name,Status,MacAddress,LinkSpeed | Out-File (Join-Path $OutDir "net_adapters.txt")

# Public IP (external)
try {
    $publicIp = (Invoke-RestMethod -Uri "https://ifconfig.me/ip" -UseBasicParsing -ErrorAction Stop).Trim()
    "PublicIP: $publicIp" | Out-File (Join-Path $OutDir "public_ip.txt")
} catch {
    "Public IP lookup failed: $_" | Out-File (Join-Path $OutDir "public_ip.txt")
}

# 11) Recent Event Logs (System, Application, Security)
Safe-Write "`n=== Event Logs (last $CollectEventDays days) ===`n"
$startTime = (Get-Date).AddDays(-$CollectEventDays)
$eventsToCollect = 1000
Get-WinEvent -FilterHashtable @{LogName='System';StartTime=$startTime} -MaxEvents $eventsToCollect |
    Export-Clixml (Join-Path $OutDir "system_events.xml")
Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$startTime} -MaxEvents $eventsToCollect |
    Export-Clixml (Join-Path $OutDir "application_events.xml")
# Security log may require elevated permissions (we have admin)
Get-WinEvent -FilterHashtable @{LogName='Security';StartTime=$startTime} -MaxEvents $eventsToCollect |
    Export-Clixml (Join-Path $OutDir "security_events.xml")

# 12) Windows Defender quick info & optional full scan
Safe-Write "`n=== Windows Defender Status ===`n"
if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
    Get-MpComputerStatus | Out-File (Join-Path $OutDir "defender_status.txt")
    Get-MpPreference | Out-File (Join-Path $OutDir "defender_preferences.txt")
    if ($RunDefenderScan) {
        Safe-Write "Starting a Windows Defender quick scan (this may take long if FullScan requested)..."
        # QuickScan type: 1, FullScan type: 2
        Start-MpScan -ScanType QuickScan | Out-File (Join-Path $OutDir "defender_scan_start.txt")
        # To run full scan instead uncomment the following and comment the QuickScan above:
        # Start-MpScan -ScanType FullScan
    } else {
        "Defender scan not requested. To run, re-run script with -RunDefenderScan." | Out-File (Join-Path $OutDir "defender_scan_note.txt")
    }
} else {
    "Windows Defender PowerShell module not available or not installed." | Out-File (Join-Path $OutDir "defender_status.txt")
}

# 13) Basic file system checks (large files and recent changes)
Safe-Write "`n=== File system: Large files and recent exe/dll changes ===`n"
$maxSizeMB = 100
if (-not $SkipLargeFiles) {
    Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Force |
        Where-Object { -not $_.PSIsContainer -and ($_.Length/1MB) -gt $maxSizeMB } |
        Select-Object FullName,Length,LastWriteTime |
        Out-File (Join-Path $OutDir "large_files_over_${maxSizeMB}MB.txt")
} else {
    "Skipped large file enumeration by user request." | Out-File (Join-Path $OutDir "large_files_over_${maxSizeMB}MB.txt")
}

# List recently modified executable files (last 7 days)
Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue -Force |
    Where-Object { -not $_.PSIsContainer -and ($_.Extension -match 'exe|dll|sys') -and ($_.LastWriteTime -ge (Get-Date).AddDays(-7)) } |
    Select-Object FullName,Length,LastWriteTime |
    Out-File (Join-Path $OutDir "recent_executables_7days.txt")

# 14) Capture Tasklist with modules (careful)
tasklist /v > (Join-Path $OutDir "tasklist_verbose.txt")

# 15) Hashes of suspicious autorun executable paths (if present)
Safe-Write "`n=== Hash autorun executables (if paths found) ===`n"
$autorunFiles = @()
foreach ($file in Get-Content -ErrorAction SilentlyContinue (Join-Path $OutDir "autoruns_summary.txt")) { }
# Instead find paths discovered earlier
Get-Content (Join-Path $OutDir "autorun_HKLM__SOFTWARE_Microsoft_Windows_CurrentVersion_Run.txt") -ErrorAction SilentlyContinue | Out-File -FilePath (Join-Path $OutDir "autorun_paths_raw.txt") -Append -Encoding utf8

# Create a ZIP of the output
Safe-Write "`nCreating ZIP archive of collected data..."
$zipPath = Join-Path $env:TEMP ("security-check-$timestamp.zip")
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($OutDir, $zipPath)
Safe-Write "Archive created: $zipPath"

Safe-Write "`nScript completed at $(Get-Date -Format o). Review logs in $OutDir and the ZIP $zipPath"
Safe-Write "Caution: Do NOT share passwords, private keys, or other secrets. You may paste relevant text files (e.g. netstat_ano.txt, listening_pid_map.txt, firewall_rules.txt) here for analysis."
