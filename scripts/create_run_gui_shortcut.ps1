# Creates a Desktop shortcut that launches the GUI script elevated.
# This helper writes a small wrapper CMD file that calls PowerShell to Start-Process the GUI with -Verb RunAs
# (which triggers UAC). Then it creates a .lnk on the current user's Desktop that runs that CMD.

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$guiScript = Join-Path $scriptDir 'run_gui.ps1'
$desktop = [Environment]::GetFolderPath('Desktop')

# Paths for the helper files on Desktop
$wrapperName = 'Run-WindowsSecurityAudit-GUI.cmd'
$wrapperPath = Join-Path $desktop $wrapperName
$lnkName = 'Windows Security Audit.lnk'
$lnkPath = Join-Path $desktop $lnkName

# Create CMD wrapper that invokes PowerShell Start-Process with -Verb RunAs to elevate and run the GUI script
try {
    # Build a CMD wrapper that launches an elevated PowerShell process which runs the GUI script.
    # Use a here-string with a format placeholder and then substitute the real script path to avoid complex escaping.
    $wrapperContent = @"
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""{0}""' -Verb RunAs -WindowStyle Hidden"
"@ -f $guiScript

    Set-Content -Path $wrapperPath -Value $wrapperContent -Encoding ASCII -Force
    Write-Output "Wrote wrapper CMD: $wrapperPath"
} catch {
    Write-Error "Failed to write wrapper CMD: $_"
}

# Create a .lnk that points to the wrapper CMD
try {
    $wsh = New-Object -ComObject WScript.Shell
    $shortcut = $wsh.CreateShortcut($lnkPath)
    $shortcut.TargetPath = $wrapperPath
    $shortcut.WorkingDirectory = $scriptDir
    # Use PowerShell icon if available for nicer appearance
    $psExe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path $psExe) { $shortcut.IconLocation = $psExe }
    $shortcut.Description = 'Launch Windows Security Audit (elevated)'
    $shortcut.Save()
    Write-Output "Created Desktop shortcut: $lnkPath"
} catch {
    Write-Error "Failed to create shortcut: $_"
}

Write-Output "Done. Use the desktop shortcut to launch the GUI (UAC prompt will appear)."