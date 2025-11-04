<#
Package the repository into a distributable ZIP under the `release/` folder.
- Creates release/<timestamp>-WindowsSecurityAudit.zip
- Includes scripts/, modules/, docs/, examples/, README.md, LICENSE
- Produces a small manifest.json alongside the zip

Designed for PowerShell 5.1+. Run from repository root:
    powershell -ExecutionPolicy Bypass -File .\scripts\package_release.ps1
#>

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot = (Resolve-Path "$repoRoot\.." | Select-Object -ExpandProperty Path)
$releaseDir = Join-Path $repoRoot 'release'
if (-not (Test-Path $releaseDir)) { New-Item -Path $releaseDir -ItemType Directory | Out-Null }

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$version = "0.2.0-$timestamp"
$zipName = "WindowsSecurityAudit_$timestamp.zip"
$zipPath = Join-Path $releaseDir $zipName

# Create temp staging area for the package
$stagingDir = Join-Path $env:TEMP "WindowsSecurityAudit_$timestamp"
if (Test-Path $stagingDir) { Remove-Item -Path $stagingDir -Recurse -Force }
New-Item -Path $stagingDir -ItemType Directory | Out-Null

# Files and folders to include
$include = @(
    'scripts',
    'modules',
    'docs',
    'examples',
    'README.md',
    'LICENSE'
)

# Copy files to staging, preserving structure
foreach ($item in $include) {
    $source = Join-Path $repoRoot $item
    $dest = Join-Path $stagingDir $item
    if (Test-Path $source) {
        if (Test-Path $source -PathType Container) {
            Copy-Item -Path $source -Destination $dest -Recurse
        } else {
            Copy-Item -Path $source -Destination $dest
        }
    }
}

# Create a quick-start README in the package root
$quickstartContent = @"
Windows Security Audit Tool
=========================

Quick Start:
1. Right-click on 'install.ps1' and select "Run with PowerShell"
2. Click "Yes" when asked for administrator permissions
3. The tool will install and create a desktop shortcut
4. Use the shortcut to run security audits

For full documentation, see docs/usage.md

Note: All scripts are signed and require administrator privileges to run.
"@
$quickstartContent | Out-File -FilePath (Join-Path $stagingDir 'QUICK_START.txt') -Encoding UTF8

Write-Host "Packaging: $zipPath"

# Remove existing zip if present
if (Test-Path $zipPath) { Remove-Item -Path $zipPath -Force }

try {
    # Create the release ZIP from staging
    Compress-Archive -Path (Join-Path $stagingDir '*') -DestinationPath $zipPath -Force
    Write-Host "Created: $zipPath"
    
    # Clean up staging directory
    Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue

    # Create a simple manifest
    $manifest = [PSCustomObject]@{
        name = 'WindowsSecurityAudit'
        version = $version
        built = (Get-Date).ToString('u')
        author = 'See LICENSE'
        files = (Get-ChildItem -Path $zipPath | Select-Object -ExpandProperty Name)
    }
    $manifestPath = Join-Path $releaseDir "manifest_$timestamp.json"
    $manifest | ConvertTo-Json -Depth 4 | Out-File -FilePath $manifestPath -Encoding UTF8
    Write-Host "Manifest: $manifestPath"

} catch {
    Write-Error "Packaging failed: $_"
    exit 1
}

Write-Host "Done. Deliverable: $zipPath"
