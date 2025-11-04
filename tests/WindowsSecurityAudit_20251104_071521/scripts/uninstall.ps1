<#
Uninstall helper: removes an installed copy created by `install.ps1`.
- If run from a repository copy it will remove an installed folder selected interactively.
- If run from an installed folder it can remove that installation and associated shortcuts.

Run elevated.
#>

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsElevated)) {
    Write-Host "This uninstall helper requires elevation. Restarting elevated..."
    Start-Process -FilePath powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File \"$PSCommandPath\"" -Verb RunAs
    exit
}

$installBase = Join-Path ${env:ProgramFiles} 'WindowsSecurityAudit'
if (-not (Test-Path $installBase)) { Write-Host "No installation found under $installBase"; exit }

# Load records if present
$recordPath = Join-Path $installBase 'install_records.json'
$choices = @()
if (Test-Path $recordPath) {
    try { $records = Get-Content -Path $recordPath -Raw | ConvertFrom-Json } catch { $records = @() }
    foreach ($r in $records) { $choices += [PSCustomObject]@{ Name = "$($r.installed) - $($r.path)"; Path = $r.path; Desktop = $r.desktopShortcut; Start = $r.startMenuShortcut } }
}

if ($choices.Count -eq 0) {
    # fallback: list subfolders
    $subs = Get-ChildItem -Path $installBase -Directory | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Path = $_.FullName } }
    if ($subs.Count -eq 0) { Write-Host "No installed versions found."; exit }
    $i = 0
    foreach ($s in $subs) { Write-Host "$i) $($s.Path)"; $i++ }
    $sel = Read-Host "Enter index to uninstall (or 'all')"
    if ($sel -eq 'all') {
        foreach ($s in $subs) { Remove-Item -Path $s.Path -Recurse -Force -ErrorAction SilentlyContinue }
        Write-Host "All installs removed from $installBase"
        exit
    } else {
        $idx = [int]$sel
        $target = $subs[$idx].Path
        Remove-Item -Path $target -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Removed: $target"
        exit
    }
} else {
    $i = 0
    foreach ($c in $choices) { Write-Host "$i) $($c.Name)"; $i++ }
    $sel = Read-Host "Enter index to uninstall (or 'all')"
    if ($sel -eq 'all') {
        foreach ($c in $choices) {
            if (Test-Path $c.Path) { Remove-Item -Path $c.Path -Recurse -Force -ErrorAction SilentlyContinue }
            if ($c.Desktop -and (Test-Path $c.Desktop)) { Remove-Item -Path $c.Desktop -Force -ErrorAction SilentlyContinue }
            if ($c.Start -and (Test-Path $c.Start)) { Remove-Item -Path $c.Start -Force -ErrorAction SilentlyContinue }
        }
        Remove-Item -Path $recordPath -Force -ErrorAction SilentlyContinue
        Write-Host "Removed all recorded installs and shortcuts."
        exit
    } else {
        $idx = [int]$sel
        $c = $choices[$idx]
        if (Test-Path $c.Path) { Remove-Item -Path $c.Path -Recurse -Force -ErrorAction SilentlyContinue }
        if ($c.Desktop -and (Test-Path $c.Desktop)) { Remove-Item -Path $c.Desktop -Force -ErrorAction SilentlyContinue }
        if ($c.Start -and (Test-Path $c.Start)) { Remove-Item -Path $c.Start -Force -ErrorAction SilentlyContinue }
        Write-Host "Removed: $($c.Path)"
        exit
    }
}
