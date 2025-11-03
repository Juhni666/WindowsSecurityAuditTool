<#
Simple installer for WindowsSecurityAudit.
- Copies repository files to Program Files\WindowsSecurityAudit\<timestamp>
- Creates Desktop and Start Menu shortcuts that launch the GUI launcher script: scripts\run_gui.ps1

Run elevated. If not elevated the script will prompt to elevate.

Usage (elevated):
    powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
#>

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsElevated)) {
    Write-Host "This installer requires elevation. Restarting elevated..."
    Start-Process -FilePath powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File \"$PSCommandPath\"" -Verb RunAs
    exit
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot = (Resolve-Path "$scriptDir\.." | Select-Object -ExpandProperty Path)
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$installBase = Join-Path ${env:ProgramFiles} "WindowsSecurityAudit"
$target = Join-Path $installBase $timestamp

Write-Host "Installing to: $target"
New-Item -Path $target -ItemType Directory -Force | Out-Null

# Copy files (preserve structure)
Write-Host "Copying files..."
robocopy $repoRoot $target /MIR /NFL /NDL /NJH /NJS | Out-Null

# Create shortcuts
$wsh = New-Object -ComObject WScript.Shell
$desktop = [Environment]::GetFolderPath('Desktop')
$startMenu = [Environment]::GetFolderPath('Programs')

$launcherPath = Join-Path $target 'scripts\run_gui.ps1'
$psExe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'

# Desktop shortcut
$deskLnk = Join-Path $desktop 'Windows Security Audit.lnk'
$sc = $wsh.CreateShortcut($deskLnk)
$sc.TargetPath = $psExe
$sc.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$launcherPath`""
$sc.WorkingDirectory = $target
$sc.IconLocation = "$psExe,0"
$sc.Save()

# Start Menu shortcut
$startLnkFolder = Join-Path $startMenu 'Windows Security Audit'
if (-not (Test-Path $startLnkFolder)) { New-Item -Path $startLnkFolder -ItemType Directory | Out-Null }
$startLnk = Join-Path $startLnkFolder 'Windows Security Audit.lnk'
$sc2 = $wsh.CreateShortcut($startLnk)
$sc2.TargetPath = $psExe
$sc2.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$launcherPath`""
$sc2.WorkingDirectory = $target
$sc2.IconLocation = "$psExe,0"
$sc2.Save()

# Persist an install record
$instRecord = [PSCustomObject]@{
    installed = (Get-Date).ToString('u')
    path = $target
    desktopShortcut = $deskLnk
    startMenuShortcut = $startLnk
}
$recordPath = Join-Path $installBase 'install_records.json'
if (Test-Path $recordPath) {
    $existing = Get-Content $recordPath -Raw | ConvertFrom-Json
    $arr = @($existing) + $instRecord
    $arr | ConvertTo-Json -Depth 4 | Out-File -FilePath $recordPath -Encoding UTF8
} else {
    @($instRecord) | ConvertTo-Json -Depth 4 | Out-File -FilePath $recordPath -Encoding UTF8
}

Write-Host "Installed to: $target"
Write-Host "Shortcuts created: `n - $deskLnk`n - $startLnk"
Write-Host "Installation complete. To uninstall, run scripts\uninstall.ps1 from the installed folder or the repo."