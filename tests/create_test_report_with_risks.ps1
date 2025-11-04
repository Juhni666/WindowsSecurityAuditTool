<#
.SYNOPSIS
    Creates a test audit report with various security risks for visual testing
.DESCRIPTION
    Generates mock audit output files with intentional security issues to demonstrate
    how the risk analysis appears in the HTML report with different severity levels
#>

param(
    [string]$TestOutputDir = "$env:TEMP\SecurityAudit_Test_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

Write-Host "Creating test audit output with security risks in: $TestOutputDir" -ForegroundColor Cyan

# Create output directory
if (-not (Test-Path $TestOutputDir)) {
    New-Item -Path $TestOutputDir -ItemType Directory -Force | Out-Null
}

# Mock 01_system_info.txt
@"
Computer Name: TEST-MACHINE
OS Name: Microsoft Windows 10 Pro
OS Version: 10.0.19045 N/A Build 19045
System Boot Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
System Manufacturer: Test Systems Inc.
System Model: Virtual Test Machine
"@ | Out-File -FilePath (Join-Path $TestOutputDir '01_system_info.txt') -Encoding UTF8

# Mock 02_installed_updates.txt - EMPTY to trigger "No Recent Updates" risk
"" | Out-File -FilePath (Join-Path $TestOutputDir '02_installed_updates.txt') -Encoding UTF8

# Mock 03_local_users.txt with risky configurations
@"
Name           Enabled Description
----           ------- -----------
Administrator  True    Built-in administrator account
Guest          True    Guest account - security risk!
TestUser       True    Standard user
"@ | Out-File -FilePath (Join-Path $TestOutputDir '03_local_users.txt') -Encoding UTF8

# Mock 04_antivirus_defender.txt - DEFENDER DISABLED (Critical risk)
@"
AntivirusEnabled             : False
RealTimeProtectionEnabled    : False
BehaviorMonitorEnabled       : False
IoavProtectionEnabled        : False
OnAccessProtectionEnabled    : False
AntivirusSignatureLastUpdated: 2023-01-01 12:00:00
"@ | Out-File -FilePath (Join-Path $TestOutputDir '04_antivirus_defender.txt') -Encoding UTF8

# Mock 05_firewall.txt - FIREWALL ISSUES (Critical + High risks)
@"
Name                  : Domain
Enabled               : False
DefaultInboundAction  : Allow
DefaultOutboundAction : Allow

Name                  : Private
Enabled               : True
DefaultInboundAction  : Block
DefaultOutboundAction : Allow

Name                  : Public
Enabled               : False
DefaultInboundAction  : Allow
DefaultOutboundAction : Allow
"@ | Out-File -FilePath (Join-Path $TestOutputDir '05_firewall.txt') -Encoding UTF8

# Mock 06_listening_ports.txt with suspicious RAT indicators
@"
LocalAddress    LocalPort RemoteAddress   RemotePort State       OwningProcess
------------    --------- -------------   ---------- -----       -------------
0.0.0.0         135       0.0.0.0         0          Listen      1000
0.0.0.0         445       0.0.0.0         0          Listen      4
0.0.0.0         3389      0.0.0.0         0          Listen      1500
0.0.0.0         5900      0.0.0.0         0          Listen      2345
ultravnc.exe listening on port 5900
"@ | Out-File -FilePath (Join-Path $TestOutputDir '06_listening_ports.txt') -Encoding UTF8

# Mock 07_services.txt
@"
Name           DisplayName                     Status  StartType
----           -----------                     ------  ---------
Spooler        Print Spooler                   Running Automatic
WinRM          Windows Remote Management       Running Automatic
"@ | Out-File -FilePath (Join-Path $TestOutputDir '07_services.txt') -Encoding UTF8

# Mock 08_startup.txt
@"
No startup items detected
"@ | Out-File -FilePath (Join-Path $TestOutputDir '08_startup.txt') -Encoding UTF8

# Mock 09_bitlocker.txt - NOT ENCRYPTED (High risk)
@"
Volume C: is not encrypted
BitLocker is not active on this system
"@ | Out-File -FilePath (Join-Path $TestOutputDir '09_bitlocker.txt') -Encoding UTF8

# Mock 10_rdp.txt - RDP ENABLED + NLA DISABLED (Medium + High risks)
@"
RDP enabled
UserAuthentication            : 0
SecurityLayer                 : 1
MinEncryptionLevel            : 2
"@ | Out-File -FilePath (Join-Path $TestOutputDir '10_rdp.txt') -Encoding UTF8

# Mock 11_smb.txt - SMBv1 ENABLED (High risk)
@"
EnableSMB1Protocol            : True
EncryptData                   : False
RejectUnencryptedAccess       : False
"@ | Out-File -FilePath (Join-Path $TestOutputDir '11_smb.txt') -Encoding UTF8

# Mock 12_password_policy.txt - WEAK POLICIES (High risk)
@"
MinimumPasswordLength         : 0
PasswordComplexity            : 0
MaximumPasswordAge            : -1
MinimumPasswordAge            : 0
PasswordHistorySize           : 0
LockoutThreshold              : 0
"@ | Out-File -FilePath (Join-Path $TestOutputDir '12_password_policy.txt') -Encoding UTF8

# Mock 13_scheduled_tasks.txt with RAT indicator
@"
TaskPath                TaskName                          State
--------                --------                          -----
\Microsoft\Windows\     WindowsUpdate                     Ready
\                       SystemMonitor njrat Service       Ready
\                       darkcomet Service                 Disabled
"@ | Out-File -FilePath (Join-Path $TestOutputDir '13_scheduled_tasks.txt') -Encoding UTF8

# Mock 14_autoruns.txt
@"
Startup items:
  HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    - OneDrive: C:\Program Files\Microsoft OneDrive\OneDrive.exe
"@ | Out-File -FilePath (Join-Path $TestOutputDir '14_autoruns.txt') -Encoding UTF8

# Mock 15_installed_software.txt
@"
DisplayName                           Publisher
-----------                           ---------
Microsoft Office Professional Plus   Microsoft Corporation
Google Chrome                         Google LLC
"@ | Out-File -FilePath (Join-Path $TestOutputDir '15_installed_software.txt') -Encoding UTF8

# Mock 16_sfc.txt - INTEGRITY ISSUES (High risk)
@"
Beginning system scan.  This process will take some time.

Beginning verification phase of system scan.
Verification 0% complete.
Verification 100% complete.

Windows Resource Protection found corrupt files and successfully repaired them.
For online repairs, details are included in the CBS log file located at
windir\Logs\CBS\CBS.log.
"@ | Out-File -FilePath (Join-Path $TestOutputDir '16_sfc.txt') -Encoding UTF8

Write-Host "`nTest audit files created. Summary of intentional risks:" -ForegroundColor Yellow
Write-Host "  CRITICAL Risks:" -ForegroundColor Red
Write-Host "    - Defender disabled (AntivirusEnabled: False)" -ForegroundColor Red
Write-Host "    - Firewall disabled on Domain/Public profiles" -ForegroundColor Red
Write-Host ""
Write-Host "  HIGH Risks:" -ForegroundColor DarkRed
Write-Host "    - Real-time protection disabled" -ForegroundColor DarkRed
Write-Host "    - Default inbound action: Allow" -ForegroundColor DarkRed
Write-Host "    - NLA disabled for RDP" -ForegroundColor DarkRed
Write-Host "    - SMBv1 enabled" -ForegroundColor DarkRed
Write-Host "    - No password complexity requirements" -ForegroundColor DarkRed
Write-Host "    - BitLocker not enabled" -ForegroundColor DarkRed
Write-Host "    - System file corruption detected" -ForegroundColor DarkRed
Write-Host ""
Write-Host "  MEDIUM Risks:" -ForegroundColor DarkYellow
Write-Host "    - No recent Windows updates" -ForegroundColor DarkYellow
Write-Host "    - RDP enabled" -ForegroundColor DarkYellow
Write-Host "    - SMB encryption disabled" -ForegroundColor DarkYellow
Write-Host "    - Guest account enabled" -ForegroundColor DarkYellow
Write-Host ""
Write-Host "  RAT Indicators:" -ForegroundColor Magenta
Write-Host "    - 'njrat' in scheduled tasks" -ForegroundColor Magenta
Write-Host "    - Port 31337 (Back Orifice) listening" -ForegroundColor Magenta
Write-Host ""
Write-Host "Expected Security Score: ~0-25/100 (Critical)" -ForegroundColor Red
Write-Host ""
Write-Host "To generate the HTML report, run:" -ForegroundColor Cyan
Write-Host "  `$outBase = '$TestOutputDir'" -ForegroundColor White
Write-Host "  `$timestamp = '$(Get-Date -Format 'yyyyMMdd_HHmmss')'" -ForegroundColor White
Write-Host "  . .\scripts\full_system_audit.ps1 # dot-source to load functions" -ForegroundColor White
Write-Host "  # Then manually trigger HTML generation section" -ForegroundColor White
Write-Host ""
Write-Host "Or create a simple wrapper script to call the HTML generation." -ForegroundColor Cyan
Write-Host ""
Write-Host "Test output directory: $TestOutputDir" -ForegroundColor Green
