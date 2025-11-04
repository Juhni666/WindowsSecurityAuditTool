<#
.SYNOPSIS
    Generates HTML report from test audit data
.DESCRIPTION
    Takes test audit output and runs the risk analysis + HTML generation
    to visualize how security findings appear in the report
#>

param(
    [string]$TestDataDir,
    [switch]$OpenInBrowser
)

if (-not $TestDataDir) {
    Write-Host "ERROR: Please provide -TestDataDir parameter" -ForegroundColor Red
    Write-Host "Usage: .\generate_test_html_report.ps1 -TestDataDir 'C:\Path\To\Test\Output'" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To create test data first, run:" -ForegroundColor Cyan
    Write-Host "  .\tests\create_test_report_with_risks.ps1" -ForegroundColor White
    exit 1
}

if (-not (Test-Path $TestDataDir)) {
    Write-Host "ERROR: Directory not found: $TestDataDir" -ForegroundColor Red
    exit 1
}

Write-Host "Generating HTML report from test data: $TestDataDir" -ForegroundColor Cyan

# Load configuration files
$scriptDir = Split-Path -Parent $PSCommandPath
$projectRoot = Split-Path -Parent $scriptDir

$indicatorPath = Join-Path $projectRoot 'scripts\indicators.json'
$riskRulesPath = Join-Path $projectRoot 'scripts\risk_rules.json'
$auditConfigPath = Join-Path $projectRoot 'scripts\audit_config.json'

if (-not (Test-Path $indicatorPath)) {
    Write-Host "ERROR: indicators.json not found at $indicatorPath" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $riskRulesPath)) {
    Write-Host "ERROR: risk_rules.json not found at $riskRulesPath" -ForegroundColor Red
    exit 1
}

$indicatorCfg = Get-Content $indicatorPath -Raw | ConvertFrom-Json
$riskCfg = Get-Content $riskRulesPath -Raw | ConvertFrom-Json
$auditCfg = if (Test-Path $auditConfigPath) { Get-Content $auditConfigPath -Raw | ConvertFrom-Json } else { $null }

# Helper function to read report files
function Read-ReportFile {
    param([string]$fileName)
    $fullPath = Join-Path $TestDataDir $fileName
    if (Test-Path $fullPath) {
        return Get-Content $fullPath -Encoding UTF8
    }
    return @()
}

# Initialize risk analysis
$riskFindings = @()
$baseScore = 100

Write-Host "Running risk analysis..." -ForegroundColor Yellow

# Perform risk analysis
if ($riskCfg -and $riskCfg.riskRules) {
    foreach ($rule in $riskCfg.riskRules) {
        $fileContent = Read-ReportFile $rule.file
        if ($fileContent.Count -eq 0) { continue }
        
        $fileText = $fileContent -join "`n"
        foreach ($check in $rule.checks) {
            if ($fileText -match $check.pattern) {
                Write-Host "  Found: $($check.name) in $($rule.file)" -ForegroundColor DarkYellow
                $riskFindings += [PSCustomObject]@{
                    Category = $rule.category
                    Name = $check.name
                    Severity = $check.severity
                    Points = $check.points
                    Description = $check.description
                }
                $baseScore += $check.points  # Points are negative
            }
        }
    }
}

Write-Host "Running RAT/malware detection..." -ForegroundColor Yellow

# RAT detection
$searchFiles = @('06_listening_ports.txt','14_autoruns.txt','07_services.txt','13_scheduled_tasks.txt','15_installed_software.txt')
$hits = @()
foreach ($f in $searchFiles) {
    $lines = Read-ReportFile $f
    if ($lines.Count -eq 0) { continue }
    foreach ($ind in $indicatorCfg.indicators) {
        $pattern = '\b' + [regex]::Escape($ind) + '\b'
        $regex = [regex]::new($pattern,'IgnoreCase')
        $matched = $lines | Select-String -Pattern $regex -AllMatches
        foreach ($m in $matched) {
            $lineText = $m.Line.Trim()
            $allowlisted = $false
            foreach ($al in $indicatorCfg.allowlist) { 
                $alPat = '\b' + [regex]::Escape($al) + '\b'
                if ($lineText -match $alPat) { $allowlisted = $true; break }
            }
            $severity = 'Medium'
            if ($indicatorCfg.highSeverity -contains $ind) { $severity = 'High' }
            
            Write-Host "  Found RAT indicator: $ind in $f" -ForegroundColor Magenta
            
            $hits += [PSCustomObject]@{ 
                Indicator = $ind
                File = $f
                Line = $lineText
                Allowlisted = $allowlisted
                Severity = $severity 
            }
        }
    }
}

# Compute RAT score deductions
foreach ($h in $hits) {
    switch ($h.Severity) {
        'High' { $baseScore -= 10 }
        'Medium' { $baseScore -= 4 }
        default { $baseScore -= 2 }
    }
    if ($h.Allowlisted) { $baseScore -= 1 }
}

# Ensure score doesn't go below 0
if ($baseScore -lt 0) { $baseScore = 0 }

Write-Host "`nRisk Analysis Summary:" -ForegroundColor Cyan
Write-Host "  Configuration Risks: $($riskFindings.Count)" -ForegroundColor Yellow
Write-Host "  RAT/Malware Indicators: $($hits.Count)" -ForegroundColor Magenta
Write-Host "  Security Score: $baseScore/100" -ForegroundColor $(if ($baseScore -lt 40) { 'Red' } elseif ($baseScore -lt 60) { 'DarkYellow' } elseif ($baseScore -lt 75) { 'Yellow' } else { 'Green' })

# Determine category and color
$category = 'Excellent'
$bannerColor = '#d4edda'
if ($baseScore -lt 90) { $category = 'Good'; $bannerColor = '#d1ecf1' }
if ($baseScore -lt 75) { $category = 'Fair'; $bannerColor = '#fff3cd' }
if ($baseScore -lt 60) { $category = 'Poor'; $bannerColor = '#f8d7da' }
if ($baseScore -lt 40) { $category = 'Critical'; $bannerColor = '#f5c6cb' }

# Build risk findings HTML
$riskHtml = ''
if ($riskFindings.Count -gt 0) {
    $riskHtml = "<h3>Configuration Risks ($($riskFindings.Count) findings)</h3>"
    $riskHtml += "<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse;width:100%'><tr style='background:#e9ecef'><th>Severity</th><th>Category</th><th>Issue</th><th>Impact</th></tr>"
    foreach ($r in $riskFindings | Sort-Object -Property @{Expression={
        switch ($_.Severity) {
            'Critical' {4}
            'High' {3}
            'Medium' {2}
            default {1}
        }
    }} -Descending) {
        $color = switch ($r.Severity) {
            'Critical' { '#f5c6cb' }
            'High' { '#fdd' }
            'Medium' { '#fff4e5' }
            default { '#efe' }
        }
        $riskHtml += "<tr style='background:$color'><td><strong>$($r.Severity)</strong></td><td>$($r.Category)</td><td>$($r.Name)</td><td>$($r.Description) <em>($($r.Points) points)</em></td></tr>"
    }
    $riskHtml += "</table>"
} else {
    $riskHtml = "<p style=""color:#28a745;font-weight:bold"">&#10003; No configuration risks detected</p>"
}

# Build RAT/malware findings HTML
$hitsHtml = ''
if ($hits.Count -gt 0) {
    $hitsHtml = "<h3>Malware / RAT Indicators ($($hits.Count) findings)</h3>"
    $hitsHtml += "<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse;width:100%'><tr style='background:#e9ecef'><th>Severity</th><th>Indicator</th><th>File</th><th>Line (excerpt)</th><th>Allowlisted</th></tr>"
    foreach ($h in $hits | Sort-Object Severity -Descending) {
        $color = if ($h.Severity -eq 'High') { '#fdd' } elseif ($h.Severity -eq 'Medium') { '#fff4e5' } else { '#efe' }
        $allow = if ($h.Allowlisted) { 'Yes' } else { 'No' }
        $hitsHtml += "<tr style='background:$color'><td><strong>$($h.Severity)</strong></td><td>$($h.Indicator)</td><td>$($h.File)</td><td style='font-family:monospace;font-size:0.9em'>$($h.Line)</td><td>$allow</td></tr>"
    }
    $hitsHtml += "</table>"
} else {
    $hitsHtml = "<p style=""color:#28a745;font-weight:bold"">&#10003; No malware indicators detected</p>"
}

# Build file list
$filesList = Get-ChildItem -Path $TestDataDir -Filter '*.txt' -File | Sort-Object Name | ForEach-Object { 
    "<li><a href='$($_.Name)'>$($_.Name)</a></li>" 
} | Out-String

# Gather system information
$computerName = $env:COMPUTERNAME
$userName = $env:USERNAME
$domain = $env:USERDOMAIN
$osInfo = Get-CimInstance Win32_OperatingSystem
$computerInfo = Get-CimInstance Win32_ComputerSystem
$cpuInfo = Get-CimInstance Win32_Processor | Select-Object -First 1
$totalRAM = [math]::Round($computerInfo.TotalPhysicalMemory / 1GB, 2)
$freeRAM = [math]::Round($osInfo.FreePhysicalMemory / 1MB, 2)
$osVersion = $osInfo.Caption
$osBuild = $osInfo.BuildNumber
$lastBoot = $osInfo.LastBootUpTime
$manufacturer = $computerInfo.Manufacturer
$model = $computerInfo.Model
$reportTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

# Compact system info in grid format
$systemInfoHtml = @"
<div style='display:grid;grid-template-columns: repeat(2, 1fr);gap:10px;font-size:0.9em'>
  <div><strong>OS:</strong> $osVersion (Build $osBuild)</div>
  <div><strong>User:</strong> $userName @ $domain</div>
  <div><strong>CPU:</strong> $($cpuInfo.Name -replace '\s+', ' ')</div>
  <div><strong>RAM:</strong> $totalRAM GB total, $freeRAM MB free</div>
  <div><strong>Last Boot:</strong> $($lastBoot.ToString('yyyy-MM-dd HH:mm:ss'))</div>
  <div><strong>Cores:</strong> $($cpuInfo.NumberOfCores) cores, $($cpuInfo.NumberOfLogicalProcessors) threads</div>
</div>
"@

# Header with system name, identifier, timestamp and score
$headerHtml = @"
<div style='display:flex;justify-content:space-between;align-items:center;padding:20px;background:$bannerColor;border-radius:8px;margin-bottom:20px;border:2px solid #666'>
  <div style='flex:1'>
    <h1 style='margin:0;border:none;padding:0;font-size:1.8em'>$computerName</h1>
    <p style='margin:5px 0 0 0;color:#666;font-size:0.85em'>$manufacturer $model | $domain</p>
  </div>
  <div style='text-align:center;padding:0 20px'>
    <div style='color:#666;font-size:0.85em'>Report Generated</div>
    <div style='font-size:0.95em;font-weight:500;margin-top:2px'>$reportTime</div>
  </div>
  <div style='text-align:right'>
    <div style='font-size:2.5em;font-weight:bold;line-height:1'>$baseScore<span style='font-size:0.5em;color:#666'>/100</span></div>
    <div style='font-size:1.1em;margin-top:5px'>$category</div>
  </div>
</div>
"@

# Generate HTML report
$timestamp = (Get-Item $TestDataDir).Name -replace 'SecurityAudit_Test_',''
$htmlPath = Join-Path $TestDataDir "test_report.html"

$html = @"
<!DOCTYPE html>
<html>
<head>
  <meta charset='UTF-8'>
  <title>TEST Security Audit Report - $timestamp</title>
  <style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #e8e8e8; }
    .panel { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
    h2 { color: #0056b3; margin-top: 0; }
    h3 { color: #495057; margin-top: 20px; }
    pre { background: #f8f9fa; padding: 12px; border-left: 4px solid #007bff; overflow-x: auto; font-size: 0.9em; }
    table { width: 100%; border-collapse: collapse; margin: 15px 0; }
    th { background: #e9ecef; font-weight: bold; padding: 10px; text-align: left; }
    td { padding: 10px; border-bottom: 1px solid #dee2e6; }
    a { color: #007bff; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .timestamp { color: #6c757d; font-size: 0.9em; }
  </style>
</head>
<body>
  $headerHtml

  <div class='panel'>
    <p class='timestamp'>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Test Data Mode</p>
    <p style='background:#fff3cd;padding:12px;border-left:4px solid #ffc107;margin-top:15px;margin-bottom:15px'>
      <strong>WARNING:</strong> This is a TEST report generated from mock data with intentional security issues for demonstration purposes.
    </p>
    <h3 style='margin-top:0;color:#0056b3;border-bottom:2px solid #dee2e6;padding-bottom:8px'>System Information</h3>
    $systemInfoHtml
  </div>

  <div class='panel'>
    <h2>Security Risk Analysis</h2>
    $riskHtml
    <hr style='margin:20px 0'>
    $hitsHtml
  </div>

  <div class='panel'>
    <h2>Test Data Files</h2>
    <p>The following mock audit files were analyzed:</p>
    <ul>$filesList</ul>
  </div>

</body>
</html>
"@

$html | Out-File -FilePath $htmlPath -Encoding UTF8

Write-Host "`nHTML report generated: $htmlPath" -ForegroundColor Green

if ($OpenInBrowser) {
    Write-Host "Opening in browser..." -ForegroundColor Cyan
    Start-Process $htmlPath
} else {
    Write-Host "`nTo open the report, run:" -ForegroundColor Yellow
    Write-Host "  Start-Process '$htmlPath'" -ForegroundColor White
}

Write-Host "`nReport breakdown:" -ForegroundColor Cyan
Write-Host "  - Color-coded severity levels" -ForegroundColor White
Write-Host "    • Critical (dark pink): #f5c6cb" -ForegroundColor White
Write-Host "    • High (light pink): #fdd" -ForegroundColor White
Write-Host "    • Medium (light orange): #fff4e5" -ForegroundColor White
Write-Host "  - Risk findings table with category, issue, and impact" -ForegroundColor White
Write-Host "  - RAT/malware indicators with file locations" -ForegroundColor White
Write-Host "  - Overall security score with visual banner" -ForegroundColor White
