# ...existing code...
<#
Windows Full Security Audit v0.2.2
- Run in an elevated PowerShell session (Run as Administrator).
- Usage:
    powershell -ExecutionPolicy Bypass -File "C:\security-check\full_system_audit.ps1"
- Output: folder on Desktop named SecurityAudit_YYYYMMDD_HHmmss and a zip file.
#>

$script:AuditVersion = "0.2.2"

# Check elevation
if (-not ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) {
    Write-Error "This script must be run as Administrator. Right-click PowerShell -> Run as Administrator."
    exit 1
}

$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$outBase = Join-Path $env:USERPROFILE ("Desktop\SecurityAudit_$timestamp")
New-Item -Path $outBase -ItemType Directory -Force | Out-Null

function Safe-Run {
    param($ScriptBlock, $File)
    try {
        # Progress integration: if script self can compute total steps, increment and show progress
        if (-not (Get-Variable -Name StepIndex -Scope Global -ErrorAction SilentlyContinue)) { Set-Variable -Name StepIndex -Value 0 -Scope Global }
        if (-not (Get-Variable -Name TotalSteps -Scope Global -ErrorAction SilentlyContinue)) {
            try {
                $me = $MyInvocation.MyCommand.Definition
                $count = (Get-Content -Path $me -ErrorAction SilentlyContinue | Select-String -Pattern 'Safe-Run\s*{' | Measure-Object).Count
                if ($count -gt 0) { Set-Variable -Name TotalSteps -Value $count -Scope Global } else { Set-Variable -Name TotalSteps -Value 30 -Scope Global }
            } catch { Set-Variable -Name TotalSteps -Value 30 -Scope Global }
        }
        $global:StepIndex = $global:StepIndex + 1
        $percent = [int](($global:StepIndex / $global:TotalSteps) * 100)
        $label = Split-Path -Path $File -Leaf
        Write-Progress -Activity 'Windows Security Audit' -Status "Running: $label ($global:StepIndex of $global:TotalSteps)" -PercentComplete $percent
        & $ScriptBlock 2>&1 | Out-File -FilePath $File -Encoding UTF8
    } catch {
        "$_" | Out-File -FilePath $File -Encoding UTF8
    }
}

Write-Output "Starting security audit v$script:AuditVersion: $timestamp"
"Output folder: $outBase" | Out-File (Join-Path $outBase "summary.txt") -Encoding UTF8

# 1) Basic system info
Safe-Run {
    @{
        Time = (Get-Date).ToString();
        ComputerName = $env:COMPUTERNAME;
        User = $env:USERNAME;
        OS = (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber);
        Uptime = (Get-CimInstance Win32_OperatingSystem | ForEach-Object {
            try {
                $boot = $_.LastBootUpTime
                if ($boot) {
                    (Get-Date) - ([Management.ManagementDateTimeConverter]::ToDateTime($boot))
                } else {
                    'Unknown'
                }
            } catch {
                "Unknown (LastBootUpTime: $($_.LastBootUpTime))"
            }
        });
        Architecture = (Get-CimInstance Win32_Processor | Select-Object -First 1 AddressWidth);
        LogicalProcessors = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors;
    } | Format-List | Out-String
} (Join-Path $outBase "01_system_info.txt")

# 2) Installed updates
Safe-Run { Get-HotFix | Sort-Object InstalledOn -Descending | Out-String } (Join-Path $outBase "02_installed_updates.txt")

# 3) Windows Update status (best-effort)
Safe-Run {
    try { Get-WindowsUpdateLog | Out-String } catch { "Get-WindowsUpdateLog not available or failed: $_" }
} (Join-Path $outBase "03_windows_update_log.txt")

# 4) Antivirus and Defender status
Safe-Run {
    "SecurityCenter2 Antivirus discovery:"
    try { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName,productState,pathToSignedProductExe | Format-List } catch { "SecurityCenter2 query failed: $_" }
    ""
    "Windows Defender (if present):"
    try { Get-MpComputerStatus | Select-Object AMServiceEnabled,AMServiceVersion,AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled,SignatureLastUpdated | Format-List } catch { "Get-MpComputerStatus unavailable: $_" }
} (Join-Path $outBase "04_antivirus_defender.txt")

# 5) Firewall profiles & rules summary
Safe-Run {
    "Firewall profiles:"
    Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowLocalFirewallRules | Format-List
    ""
    "Active inbound rules permitting RemoteAccess or Any:"
    Get-NetFirewallRule -Direction Inbound -Enabled True | Where-Object { $_.Action -eq 'Allow' } | Select-Object Name,DisplayName,Profile,Enabled,Direction,Action | Format-Table -AutoSize
} (Join-Path $outBase "05_firewall.txt")

# 6) Open/listening TCP ports and owning processes
Safe-Run {
    "Listening TCP endpoints (LocalAddress:Port -> ProcessName (PID))"
    Get-NetTCPConnection -State Listen | ForEach-Object {
        $proc = $null
        try { $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } catch {}
        if (-not $proc) { $proc = 'Unknown' }
        "{0}:{1} -> {2} ({3})" -f $_.LocalAddress,$_.LocalPort, $proc, $_.OwningProcess
    }
} (Join-Path $outBase "06_listening_ports.txt")

# 7) Services: automatic but stopped + suspicious ones
Safe-Run {
    "Automatic services not running:"
    Get-Service | Where-Object { $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' } | Select-Object Name,DisplayName,Status,StartType | Format-Table -AutoSize
    ""
    "Services running with unusual accounts (LocalSystem is common, check others):"
    Get-WmiObject -Class Win32_Service | Where-Object { $_.StartName -notmatch 'LocalSystem|LocalService|NetworkService|LocalService$' } | Select-Object Name,DisplayName,StartName,State | Format-Table -AutoSize
} (Join-Path $outBase "07_services.txt")

# 8) Local users and admin group membership
Safe-Run {
    "Local users (locked/disabled/password never expires):"
    if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        Get-LocalUser | Select-Object Name,Enabled,LockedOut,PasswordExpires | Format-Table -AutoSize
    } else {
        "Get-LocalUser not available; falling back to 'net user' output:" 
        net user
    }
    ""
    "Local Administrators group members:"
    if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
        Get-LocalGroupMember -Group Administrators | Select-Object Name,ObjectClass | Format-Table -AutoSize
    } else {
        "Get-LocalGroupMember not available; attempting to locate Administrators group by well-known SID (S-1-5-32-544) and list members via CIM..."
        try {
            $adminGroup = Get-CimInstance -ClassName Win32_Group -Filter "SID='S-1-5-32-544'" -ErrorAction SilentlyContinue
            if ($adminGroup) {
                $members = Get-CimAssociatedInstance -InputObject $adminGroup -Association Win32_GroupUser -ResultClassName Win32_UserAccount -ErrorAction SilentlyContinue
                if ($members) {
                    $members | Select-Object Name,Domain | Format-Table -AutoSize
                } else {
                    "No members found via CIM associators. Falling back to 'net localgroup' using discovered group name if present."
                    if ($adminGroup.Name) {
                        try { net localgroup "$($adminGroup.Name)" } catch { "net localgroup failed: $_" }
                    } else {
                        "Could not determine Administrators group name; skipping members listing."
                    }
                }
            } else {
                "Administrators group (SID S-1-5-32-544) not found via CIM; attempting 'net localgroup Administrators' fallback"
                try { net localgroup Administrators } catch { "net localgroup failed: $_" }
            }
        } catch {
            "Failed to enumerate Administrators group members via CIM: $_"
        }
    }
} (Join-Path $outBase "08_users_admins.txt")

# 9) Password & account policy
Safe-Run { net accounts 2>&1 } (Join-Path $outBase "09_password_policy.txt")

# 10) RDP & Remote access settings
Safe-Run {
    "RDP enabled?"
    try {
        $deny = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections
        if ($deny -eq 0) { "RDP enabled (fDenyTSConnections=0)" } else { "RDP disabled (fDenyTSConnections=1)" }
    } catch { "Could not read RDP registry: $_" }
    ""
    "RDP NLA required?"
    try { Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction Stop | Format-List } catch { "NLA read failed: $_" }
} (Join-Path $outBase "10_rdp.txt")

# 11) SMB / File share settings (SMBv1 check if possible)
Safe-Run {
    "SMB Server configuration (if available):"
    try { Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EncryptData,RejectUnencryptedAccess | Format-List } catch { "Get-SmbServerConfiguration not available or requires admin module: $_" }
    ""
    "SMB shares:"
    try { Get-SmbShare | Select-Object Name,Path,Description,ScopeName,RestrictNullSessAccess | Format-Table -AutoSize } catch { "Get-SmbShare failed or not available: $_" }
    ""
    "OptionalFeature SMB1 (best effort):"
    try { Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Format-List } catch { "Get-WindowsOptionalFeature not available: $_" }
} (Join-Path $outBase "11_smb.txt")

# 12) BitLocker / disk encryption status
Safe-Run {
    "BitLocker volumes (if BitLocker module present):"
    try { Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,EncryptionPercentage,KeyProtector | Format-List } catch { "Get-BitLockerVolume unavailable: $_" }
} (Join-Path $outBase "12_bitlocker.txt")

# 13) Scheduled tasks running as highest privilege / unknown authors
Safe-Run {
    "Scheduled tasks (showing TaskName, State, Author, Principal):"
    Get-ScheduledTask | ForEach-Object {
        $s = $_
        $st = (Get-ScheduledTaskInfo -TaskName $s.TaskName -TaskPath $s.TaskPath -ErrorAction SilentlyContinue).State
        [PSCustomObject]@{
            TaskName = ($s.TaskPath + $s.TaskName)
            State    = $st
            Author   = $s.Author
            RunLevel = $s.Principal.RunLevel
            Principal = $s.Principal.UserId
        }
    } | Format-Table -AutoSize
} (Join-Path $outBase "13_scheduled_tasks.txt")

# 14) Startup / autoruns (registry Run keys + startup folder)
Safe-Run {
    "HKCU Run and HKLM Run entries:"
    Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Format-List
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Format-List
    Get-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Format-List
    ""
    "Startup folder contents:"
    Get-ChildItem -Path "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -ErrorAction SilentlyContinue | Select-Object Name,FullName | Format-Table -AutoSize
    Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Select-Object Name,FullName | Format-Table -AutoSize
} (Join-Path $outBase "14_autoruns.txt")

# 15) Installed software list (registry)
Safe-Run {
    "Installed (x64) from registry:"
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Where-Object { $_.DisplayName } | Sort-Object DisplayName | Format-Table -AutoSize
    ""
    "Installed (x86) from registry:"
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Select-Object DisplayName,DisplayVersion,Publisher,InstallDate | Where-Object { $_.DisplayName } | Sort-Object DisplayName | Format-Table -AutoSize
} (Join-Path $outBase "15_installed_software.txt")

# 16) TLS / Schannel protocols & ciphers (registry inspection)
Safe-Run {
    "Schannel Protocols settings (HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols)"
    $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    try {
        Get-ChildItem -Path $base -Recurse | ForEach-Object {
            $p = $_.PSPath
            $vals = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
            "{0} -> {1}" -f $_.PSPath, ($vals | Select-Object -Property * -ExcludeProperty PS*,PSComputerName | Out-String)
        }
    } catch { "Schannel read failed: $_" }
} (Join-Path $outBase "16_schannel_tls.txt")

# 17) Recent suspicious Security events (failed logons, elevation, new service install)
Safe-Run {
    "Failed logon events (4625) last 7 days:"
    $failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 200 -ErrorAction SilentlyContinue
    if ($failedLogons) { $failedLogons | Select-Object TimeCreated,Id,Message | Format-List } else { "No failed logon events found in the last 7 days." }
    ""
    "New service creation or start events (4688/4697) last 7 days (best-effort):"
    $svcEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 200 -ErrorAction SilentlyContinue
    if ($svcEvents) { $svcEvents | Select-Object TimeCreated,Id,Message | Format-List } else { "No service creation/start events found in the last 7 days." }
} (Join-Path $outBase "17_security_events.txt")

# 18) Quick credential & account checks
Safe-Run {
    "Recent local group changes (Security ID 4732/4733/4734 etc) last 30 days (best-effort):"
    $groupEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=(Get-Date).AddDays(-30); Id=@(4728,4729,4732,4733,4734)} -MaxEvents 200 -ErrorAction SilentlyContinue
    if ($groupEvents) { $groupEvents | Select-Object TimeCreated,Id,Message | Format-List } else { "No local group change events found in the last 30 days." }
} (Join-Path $outBase "18_account_events.txt")

# 19) Basic network configuration / DNS / ARP
Safe-Run {
    "IP configuration:"
    ipconfig /all
    ""
    "Routing table:"
    route print
    ""
    "ARP table:"
    arp -a
} (Join-Path $outBase "19_network.txt")

# 20) Quick integrity checks: system file checker (SFC scan summary) - only the scan start, may take long
Write-Host ""
Write-Host ">>> PHASE 20/30: System File Checker (SFC) <<<" -ForegroundColor Cyan -BackgroundColor Blue
Write-Host "This may take a couple of minutes. Please wait..." -ForegroundColor White
Write-Host ""

# Simple animated spinner while SFC runs
function Show-AnimatedSfcMessage {
    $spinChars = @('|', '/', '-', '\')
    for ($i = 0; $i -lt 20; $i++) {
        $char = $spinChars[$i % $spinChars.Length]
        Write-Host -NoNewline "`r[$char] Running System File Checker... " -ForegroundColor Yellow
        Start-Sleep -Milliseconds 200
    }
    Write-Host "`r[✓] SFC started - this will continue in the background..." -ForegroundColor Green
}

Safe-Run {
    Show-AnimatedSfcMessage
    
    "SFC check (summary only). Running 'sfc /verifyonly' which checks integrity but does not attempt repairs (safer/faster):"

    # Ensure TrustedInstaller (Windows Modules Installer) is running - SFC depends on it
    function Ensure-TrustedInstallerRunning {
        try {
            $svc = Get-Service -Name TrustedInstaller -ErrorAction SilentlyContinue
            if ($null -eq $svc) {
                "TrustedInstaller service not found on this host. SFC may fail."
                return $false
            }

            if ($svc.Status -eq 'Running') {
                "TrustedInstaller is running."
                return $true
            }

            # If the service is Disabled, try to set it to Manual so we can start it
            try {
                $wmi = Get-CimInstance -ClassName Win32_Service -Filter "Name='TrustedInstaller'" -ErrorAction SilentlyContinue
                if ($wmi -and $wmi.StartMode -eq 'Disabled') {
                    "TrustedInstaller StartMode is Disabled - attempting to set to Manual"
                    try { Set-Service -Name TrustedInstaller -StartupType Manual -ErrorAction Stop; "Set StartupType to Manual." } catch { "Failed to change StartupType: $_" }
                }
            } catch {
                "Could not query/modify TrustedInstaller StartMode: $_"
            }

            # Try starting the service with a few retries
            $attempt = 0
            while ($attempt -lt 3) {
                $attempt++
                "Attempting to start TrustedInstaller (attempt $attempt of 3)..."
                try {
                    Start-Service -Name TrustedInstaller -ErrorAction Stop
                } catch {
                    "Start-Service failed: $_"
                }
                Start-Sleep -Seconds 3
                $svc.Refresh()
                if ($svc.Status -eq 'Running') {
                    "TrustedInstaller started."
                    return $true
                }
            }

            "TrustedInstaller could not be started after retries."
            return $false
        } catch {
            "Error while checking/starting TrustedInstaller: $_"
            return $false
        }
    }

    $tiRunning = Ensure-TrustedInstallerRunning


    # Helper to run SFC and return output text and exit code
    function Invoke-SfcVerifyOnly {
        $out = & sfc /verifyonly 2>&1
        $exit = $LASTEXITCODE
        
        # Filter progress messages to only show significant changes (0%, 25%, 50%, 75%, 100%)
        $filtered = $out | Where-Object {
            if ($_ -match '^Verification\s+(\d+)%\s+complete\.?$') {
                $percent = [int]$matches[1]
                return $percent % 25 -eq 0  # Only keep 0%, 25%, 50%, 75%, 100%
            }
            return $true  # Keep non-progress messages
        }
        
        return @{Text = ($filtered -join "`n"); ExitCode = $exit; Raw = $filtered}
    }

    $first = Invoke-SfcVerifyOnly
    $first.Raw | ForEach-Object { $_ }

    # If SFC exited non-zero, or reported repair-service failure, or TrustedInstaller isn't running,
    # treat it as needing remediation: run DISM, ensure service, then retry SFC and (if needed) run sfc /scannow.
    if ($first.ExitCode -ne 0 -or $first.Text -match "could not start the repair service" -or -not $tiRunning) {
        "SFC verify-only finished with exit code $($first.ExitCode). Will attempt remediation: DISM /RestoreHealth, then retry service start and SFC."

        # Run DISM restore to try to repair component store (may take long)
        try {
            "Running: DISM /Online /Cleanup-Image /RestoreHealth (this may take several minutes)"
            & DISM /Online /Cleanup-Image /RestoreHealth 2>&1 | ForEach-Object { $_ }
            "DISM completed."
        } catch {
            "DISM failed to run or returned an error: $_"
        }

        # After DISM, attempt to start TrustedInstaller again
        $tiRunning = Ensure-TrustedInstallerRunning

        if ($tiRunning) {
            "TrustedInstaller is running after remediation; re-attempting sfc /verifyonly..."
            $second = Invoke-SfcVerifyOnly
            $second.Raw | ForEach-Object { $_ }

                if ($second.ExitCode -ne 0) {
                    "SFC retry finished with exit code $($second.ExitCode). As a last-resort attempt, running 'sfc /scannow' to perform repairs."
                    ""
                    try {
                        & sfc /scannow 2>&1
                        "sfc /scannow scan completed."
                    } catch {
                        "sfc /scannow failed to run or returned an error: $_"
                    }
                } else {
                    "SFC retry completed successfully (exit code 0)."
                }

        } else {
            "TrustedInstaller is still not running after DISM. SFC cannot perform repairs. Inspect C:\Windows\Logs\CBS\CBS.log and DISM output for details."
        }

    } else {
        # No repair-service text; report exit code if non-zero
        if ($first.ExitCode -ne 0) {
            "SFC finished with exit code $($first.ExitCode). If you want repairs, run 'sfc /scannow' or run DISM /RestoreHealth."
        } else {
            "SFC completed successfully (exit code 0)."
        }
    }

} (Join-Path $outBase "20_sfc_scannow.txt")

# --- 00) Quick aggregated report (summarize important findings, RAT indicators) ---
Safe-Run {
    $reportPath = Join-Path $outBase "00_quick_report.txt"
    "Quick security summary" | Out-File -FilePath $reportPath -Encoding UTF8
    "Generated: $(Get-Date)" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    "" | Out-File -FilePath $reportPath -Append -Encoding UTF8

    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
    $indFile = Join-Path $scriptRoot 'indicators.json'
    $cfgFile = Join-Path $scriptRoot 'audit_config.json'
    $riskFile = Join-Path $scriptRoot 'risk_rules.json'

    # Load indicator config (fallback to inline defaults)
    $indicatorCfg = @{ indicators = @('njrat','darkcomet','remcos','radmin','quasar','cobalt','metasploit','psexec','rat','remoteadmin','anydesk','teamviewer'); allowlist = @('TeamViewer','AnyDesk'); highSeverity = @('njrat','darkcomet','remcos') }
    if (Test-Path $indFile) {
        try { $indicatorCfg = Get-Content -Path $indFile -Raw | ConvertFrom-Json } catch { "Failed to read indicators.json: $_" | Out-File -FilePath $reportPath -Append -Encoding UTF8 }
    }

    # Load other audit config
    $auditCfg = @{ AutoRemediate = $true; RunScannowIfVerifyFails = $true; OpenHtmlReport = $true }
    if (Test-Path $cfgFile) {
        try { $auditCfg = Get-Content -Path $cfgFile -Raw | ConvertFrom-Json } catch { "Failed to read audit_config.json: $_" | Out-File -FilePath $reportPath -Append -Encoding UTF8 }
    }

    # Load risk analysis rules
    $riskCfg = $null
    if (Test-Path $riskFile) {
        try { $riskCfg = Get-Content -Path $riskFile -Raw | ConvertFrom-Json } catch { "Failed to read risk_rules.json: $_" | Out-File -FilePath $reportPath -Append -Encoding UTF8 }
    }

    function Read-ReportFile($name) { $p = Join-Path $outBase $name; if (Test-Path $p) { Get-Content -Path $p -ErrorAction SilentlyContinue } else { @() } }

    # Basic structured highlights
    "Highlights:" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    $sys = Read-ReportFile '01_system_info.txt'
    if ($sys) {
        $osLine = $sys | Where-Object { $_ -match 'Caption' -or $_ -match 'OS' -or $_ -match 'Uptime' -or $_ -match 'User' } | Select-Object -First 10
        $osLine | Out-File -FilePath $reportPath -Append -Encoding UTF8
    }

    "" | Out-File -FilePath $reportPath -Append -Encoding UTF8

    # Defender status
    $def = Read-ReportFile '04_antivirus_defender.txt'
    if ($def -and ($def -join "`n") -match 'AntivirusEnabled\s*:\s*True') {
        "Windows Defender: Enabled" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    } else {
        "Windows Defender: Not fully enabled or not present (see 04_antivirus_defender.txt)" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    }

    "" | Out-File -FilePath $reportPath -Append -Encoding UTF8

    # === COMPREHENSIVE RISK ANALYSIS ===
    "=== SECURITY RISK ANALYSIS ===" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    "" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    
    $riskFindings = @()
    $baseScore = 100
    
    # Perform risk analysis if risk rules are loaded
    if ($riskCfg -and $riskCfg.riskRules) {
        foreach ($rule in $riskCfg.riskRules) {
            $fileContent = Read-ReportFile $rule.file
            if ($fileContent.Count -eq 0) { continue }
            
            $fileText = $fileContent -join "`n"
            foreach ($check in $rule.checks) {
                if ($fileText -match $check.pattern) {
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

    # RAT detection - structured
    "Malware / RAT Indicators:" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    $searchFiles = @('06_listening_ports.txt','14_autoruns.txt','07_services.txt','13_scheduled_tasks.txt','15_installed_software.txt')
    $hits = @()
    foreach ($f in $searchFiles) {
        $lines = Read-ReportFile $f
        if ($lines.Count -eq 0) { continue }
        foreach ($ind in $indicatorCfg.indicators) {
            # match whole words to avoid hitting substrings (e.g. 'rat' inside 'Corporation')
            $pattern = '\b' + [regex]::Escape($ind) + '\b'
            $regex = [regex]::new($pattern,'IgnoreCase')
            $matched = $lines | Select-String -Pattern $regex -AllMatches
            foreach ($m in $matched) {
                $lineText = $m.Line.Trim()
                # allowlist check: if any allowlist token appears in the line, mark as allowlisted
                $allowlisted = $false
                foreach ($al in $indicatorCfg.allowlist) { 
                    $alPat = '\b' + [regex]::Escape($al) + '\b'
                    if ($lineText -match $alPat) { $allowlisted = $true; break }
                }
                $severity = 'Medium'
                if ($indicatorCfg.highSeverity -contains $ind) { $severity = 'High' }
                $hits += [PSCustomObject]@{ Indicator = $ind; File = $f; Line = $lineText; Allowlisted = $allowlisted; Severity = $severity }
            }
        }
    }

    if ($hits.Count -gt 0) {
        # Compute RAT score deductions
        foreach ($h in $hits) {
            switch ($h.Severity) {
                'High' { $baseScore -= 10 }
                'Medium' { $baseScore -= 4 }
                default { $baseScore -= 2 }
            }
            if ($h.Allowlisted) { $baseScore -= 1 }
        }
        
        $hits | Sort-Object -Property @{Expression={if ($_.Severity -eq 'High') {3} elseif ($_.Severity -eq 'Medium') {2} else {1}}},Indicator -Descending | ForEach-Object {
            $msg = "  [RAT-$($_.Severity)] $($_.Indicator) in $($_.File): $($_.Line)"
            if ($_.Allowlisted) { $msg = "$msg (allowlisted)" }
            $msg | Out-File -FilePath $reportPath -Append -Encoding UTF8
        }
    } else {
        "  No malware indicators detected" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    }
    
    "" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    
    # Display risk findings
    if ($riskFindings.Count -gt 0) {
        "Security Risk Findings:" | Out-File -FilePath $reportPath -Append -Encoding UTF8
        $riskFindings | Sort-Object -Property @{Expression={
            switch ($_.Severity) {
                'Critical' {4}
                'High' {3}
                'Medium' {2}
                default {1}
            }
        }} -Descending | ForEach-Object {
            $pts = $_.Points
            "  [{0}] {1} - {2} ({3} pts)" -f $_.Severity, $_.Category, $_.Description, $pts | Out-File -FilePath $reportPath -Append -Encoding UTF8
        }
    } else {
        "Security Risk Findings:" | Out-File -FilePath $reportPath -Append -Encoding UTF8
        "  No configuration risks detected" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    }
    
    "" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    
    # Final score calculation
    if ($baseScore -lt 0) { $baseScore = 0 }
    "Overall Security Score: $baseScore / 100" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    
    # Determine category
    $category = 'Unknown'
    $categoryColor = '#ccc'
    if ($riskCfg -and $riskCfg.scoreCategories) {
        foreach ($cat in $riskCfg.scoreCategories.PSObject.Properties) {
            $range = $cat.Value
            if ($baseScore -ge $range.min -and $baseScore -le $range.max) {
                $category = $range.label
                $categoryColor = $range.color
                break
            }
        }
    } else {
        # Fallback categories
        $category = if ($baseScore -ge 90) { 'Excellent' } 
                    elseif ($baseScore -ge 75) { 'Good' }
                    elseif ($baseScore -ge 60) { 'Fair' } 
                    elseif ($baseScore -ge 40) { 'Poor' }
                    else { 'Critical' }
    }
    
    "Security Rating: $category" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    "" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    
    "Risk Breakdown:" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    "  Base Score: 100" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    if ($riskFindings.Count -gt 0) {
        $totalRiskPoints = ($riskFindings | Measure-Object -Property Points -Sum).Sum
        $riskCount = $riskFindings.Count
        "  Configuration Risks: {0} pts ({1} findings)" -f $totalRiskPoints, $riskCount | Out-File -FilePath $reportPath -Append -Encoding UTF8
    }
    if ($hits.Count -gt 0) {
        $ratPoints = 100 - $baseScore - $(if ($riskFindings.Count -gt 0) { ($riskFindings | Measure-Object -Property Points -Sum).Sum } else { 0 })
        $hitsCount = $hits.Count
        "  Malware Indicators: -{0} pts ({1} findings)" -f $ratPoints, $hitsCount | Out-File -FilePath $reportPath -Append -Encoding UTF8
    }

    "" | Out-File -FilePath $reportPath -Append -Encoding UTF8

    # SFC/DISM quick status
    $sfc = Read-ReportFile '20_sfc_scannow.txt'
    if ($sfc -and ($sfc -join "`n") -match 'completed successfully') {
        "SFC: OK (verify/completed)" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    } elseif ($sfc -and ($sfc -join "`n") -match 'DISM') {
        "SFC/DISM: see 20_sfc_scannow.txt for DISM/SFC remediation output" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    } else {
        "SFC: Issues detected or no output (see 20_sfc_scannow.txt)" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    }

    "" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    "Full output files (for details):" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    Get-ChildItem -Path $outBase -Filter '*.txt' | Sort-Object Name | ForEach-Object { $_.Name } | Out-File -FilePath $reportPath -Append -Encoding UTF8

    "" | Out-File -FilePath $reportPath -Append -Encoding UTF8
    "End of quick report" | Out-File -FilePath $reportPath -Append -Encoding UTF8

} (Join-Path $outBase "00_quick_report.txt")

# Enhanced HTML report with sections, severity coloring, and links
try {
    $txtPath = Join-Path $outBase '00_quick_report.txt'
    $htmlPath = Join-Path $outBase '00_quick_report.html'
    if (Test-Path $txtPath) {
        $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
        $indFile = Join-Path $scriptRoot 'indicators.json'
        $cfgFile = Join-Path $scriptRoot 'audit_config.json'
        $indicatorCfg = $null; $auditCfg = $null
        try { if (Test-Path $indFile) { $indicatorCfg = Get-Content -Path $indFile -Raw | ConvertFrom-Json } }
        catch { $indicatorCfg = $null }
        try { if (Test-Path $cfgFile) { $auditCfg = Get-Content -Path $cfgFile -Raw | ConvertFrom-Json } }
        catch { $auditCfg = $null }
        if (-not $auditCfg) { $auditCfg = @{ OpenHtmlReport = $true } }

        # Helper: read a text file and try to detect common encodings (UTF-8 BOM, UTF-16LE/BE), fallback to system default
        function Read-TextFileDetectEncoding($path) {
            try {
                if (-not (Test-Path $path)) { return '' }
                $bytes = [System.IO.File]::ReadAllBytes($path)
                if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
                    $enc = [System.Text.Encoding]::UTF8
                } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
                    $enc = [System.Text.Encoding]::Unicode # UTF-16 LE
                } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
                    $enc = [System.Text.Encoding]::BigEndianUnicode
                } else {
                    # No BOM: assume default system code page (OEM) which is usually correct for cmd.exe redirects
                    $enc = [System.Text.Encoding]::Default
                }
                return $enc.GetString($bytes)
            } catch {
                # fallback to Get-Content
                return (Get-Content -Path $path -ErrorAction SilentlyContinue) -join "`n"
            }
        }

        # Read files for structured sections (use encoding-aware reader to avoid embedded NULs / doubled characters)
        $system = Read-TextFileDetectEncoding((Join-Path $outBase '01_system_info.txt'))
        $defender = Read-TextFileDetectEncoding((Join-Path $outBase '04_antivirus_defender.txt'))
        
        # Special handling for SFC output which may contain Unicode with NUL bytes
        function Read-SfcOutput($path) {
            try {
                # Try reading as UTF-16 first (handles the NUL byte case)
                $content = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::Unicode)
                # If content looks like UTF-16 (has NUL bytes), clean it up
                if ($content -match '\0') {
                    $content = $content -replace '\0', ''
                }
                return $content
            }
            catch {
                # Fallback to default encoding if UTF-16 fails
                return (Get-Content -Path $path -Raw -ErrorAction SilentlyContinue)
            }
        }
        
        $sfctext = Read-SfcOutput((Join-Path $outBase '20_sfc_scannow.txt'))
        
        # Process SFC output to remove progress spam and collapse duplicate lines
        function Process-SfcOutput([string]$text) {
            if (-not $text) { return "" }
            
            # Split into lines and normalize all whitespace
            $lines = $text -split '\r?\n' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            $out = @()
            $lastPercent = -1
            $inProgress = $false
            
            foreach ($line in $lines) {
                # Clean up any remaining weird characters
                $line = $line -replace '[^\x20-\x7E\r\n]', ''
                
                # Skip visual progress bars like: [==     3.8%     ]
                if ($line -match '^\[=*\s+\d+\.?\d*%\s+\]') {
                    continue
                }
                
                if ($line -match 'Verification\s*(\d+)%\s*complete') {
                    $percent = [int]$matches[1]
                    $inProgress = $true
                    # Only keep 0%, 25%, 50%, 75%, 100%
                    if ($percent % 25 -eq 0 -and $percent -ne $lastPercent) {
                        $out += "Verification $percent% complete"
                        $lastPercent = $percent
                    }
                }
                elseif ($line -and -not ($inProgress -and $line -match 'Verification')) {
                    # Keep non-progress lines that aren't empty
                    # and aren't part of the verification spam
                    $out += $line
                    if ($line -match 'Windows Resource Protection') {
                        $inProgress = $false
                    }
                }
            }
            
            # Return as a single string with newlines
            return ($out -join "`n")
        }

        # Process the SFC output to clean up progress spam and fix character spacing
        $sfctext = Process-SfcOutput($sfctext)

        # Load risk rules for HTML report
        $riskCfg = $null
        $riskFile = Join-Path $scriptRoot 'risk_rules.json'
        if (Test-Path $riskFile) {
            try { $riskCfg = Get-Content -Path $riskFile -Raw | ConvertFrom-Json } catch { }
        }

        # Perform comprehensive risk analysis
        $riskFindings = @()
        $baseScore = 100
        
        if ($riskCfg -and $riskCfg.riskRules) {
            foreach ($rule in $riskCfg.riskRules) {
                $p = Join-Path $outBase $rule.file
                if (-not (Test-Path $p)) { continue }
                $fileContent = Get-Content -Path $p -ErrorAction SilentlyContinue
                if ($fileContent.Count -eq 0) { continue }
                
                $fileText = $fileContent -join "`n"
                foreach ($check in $rule.checks) {
                    if ($fileText -match $check.pattern) {
                        $riskFindings += [PSCustomObject]@{
                            Category = $rule.category
                            Name = $check.name
                            Severity = $check.severity
                            Points = $check.points
                            Description = $check.description
                        }
                        $baseScore += $check.points
                    }
                }
            }
        }
        
        # Perform RAT scan again to include structured hits in HTML
        $hits = @()
        if ($indicatorCfg) {
            $searchFiles = @('06_listening_ports.txt','14_autoruns.txt','07_services.txt','13_scheduled_tasks.txt','15_installed_software.txt')
            foreach ($f in $searchFiles) {
                $p = Join-Path $outBase $f
                if (-not (Test-Path $p)) { continue }
                $lines = Get-Content -Path $p -ErrorAction SilentlyContinue
                foreach ($ind in $indicatorCfg.indicators) {
                    # use whole-word matching to reduce substring false-positives
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
                        $hits += [PSCustomObject]@{ Indicator = $ind; File = $f; Line = $lineText; Allowlisted = $allowlisted; Severity = $severity }
                    }
                }
            }
        }

        # HTML encode helper
        function HtmlEncode([string]$s) { if ($null -eq $s) { return '' } ; return ($s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'","&#39;") }

        # Compute score for HTML - combines risk findings and RAT findings
        foreach ($h in $hits) {
            if ($h.Severity -eq 'High') { $baseScore -= 10 } elseif ($h.Severity -eq 'Medium') { $baseScore -= 4 } else { $baseScore -= 2 }
            if ($h.Allowlisted) { $baseScore -= 1 }
        }
        if ($baseScore -lt 0) { $baseScore = 0 }
        
        # Determine category and color
        $category = 'Unknown'
        $bannerColor = '#ccc'
        if ($riskCfg -and $riskCfg.scoreCategories) {
            foreach ($cat in $riskCfg.scoreCategories.PSObject.Properties) {
                $range = $cat.Value
                if ($baseScore -ge $range.min -and $baseScore -le $range.max) {
                    $category = $range.label
                    $bannerColor = $range.color
                    break
                }
            }
        } else {
            # Fallback categories
            $category = if ($baseScore -ge 90) { 'Excellent' } 
                        elseif ($baseScore -ge 75) { 'Good' }
                        elseif ($baseScore -ge 60) { 'Fair' } 
                        elseif ($baseScore -ge 40) { 'Poor' }
                        else { 'Critical' }
            $bannerColor = if ($baseScore -ge 90) { '#d4edda' } 
                          elseif ($baseScore -ge 75) { '#d1ecf1' }
                          elseif ($baseScore -ge 60) { '#fff3cd' } 
                          elseif ($baseScore -ge 40) { '#f8d7da' }
                          else { '#f5c6cb' }
        }
        
    $bannerHtml = "<div style='padding:12px;border-radius:6px;background:$bannerColor;margin-bottom:12px'><strong>Security Score: $baseScore/100</strong> - <em>$category</em></div>"

        # Build risk findings HTML
        $riskHtml = ''
        if ($riskFindings.Count -gt 0) {
            $riskHtml = "<h3>Configuration Risks ($($riskFindings.Count) findings)</h3>"
            $riskHtml += "<table border='1' cellpadding='6' cellspacing='0'><tr><th>Severity</th><th>Category</th><th>Issue</th><th>Impact</th></tr>"
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
                $riskHtml += "<tr style='background:$color'><td>$([System.Web.HttpUtility]::HtmlEncode($r.Severity))</td><td>$([System.Web.HttpUtility]::HtmlEncode($r.Category))</td><td>$([System.Web.HttpUtility]::HtmlEncode($r.Name))</td><td>$([System.Web.HttpUtility]::HtmlEncode($r.Description)) ($($r.Points) points)</td></tr>"
            }
            $riskHtml += "</table>"
        } else {
            $riskHtml = "<p style=""color:#28a745"">&#10003; No configuration risks detected</p>"
        }
        
        # Build RAT/malware findings HTML
        $hitsHtml = ''

        if ($hits.Count -gt 0) {
            $hitsHtml = "<h3>Malware / RAT Indicators ($($hits.Count) findings)</h3>"
            $hitsHtml += "<table border='1' cellpadding='6' cellspacing='0'><tr><th>Severity</th><th>Indicator</th><th>File</th><th>Line (excerpt)</th><th>Allowlisted</th></tr>"
            foreach ($h in $hits | Sort-Object Severity -Descending) {
                $color = if ($h.Severity -eq 'High') { '#fdd' } elseif ($h.Severity -eq 'Medium') { '#fff4e5' } else { '#efe' }
                $allow = if ($h.Allowlisted) { 'Yes' } else { 'No' }
                $hitsHtml += "<tr style='background:$color'><td>$([System.Web.HttpUtility]::HtmlEncode($h.Severity))</td><td>$([System.Web.HttpUtility]::HtmlEncode($h.Indicator))</td><td>$([System.Web.HttpUtility]::HtmlEncode($h.File))</td><td>$([System.Web.HttpUtility]::HtmlEncode($h.Line))</td><td>$allow</td></tr>"
            }
            $hitsHtml += "</table>"
        } else {
            $hitsHtml = "<p style=""color:#28a745"">&#10003; No malware indicators detected</p>"
        }

        $filesList = Get-ChildItem -Path $outBase -Filter '*.txt' -File | Sort-Object Name | ForEach-Object { "<li><a href='$($_.Name)'>$($_.Name)</a></li>" } | Out-String

        $html = @"
<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <title>Security Audit - Quick Report</title>
  <style>
    body{font-family:Segoe UI,Arial,Helvetica,sans-serif;margin:18px;color:#222}
    .panel{background:#fff;padding:12px;border-radius:6px;margin-bottom:12px;border:1px solid #e1e4e8}
    pre{background:#f6f8fa;padding:12px;border-radius:6px;white-space:pre-wrap;word-wrap:break-word}
    h1,h2{color:#111}
    table{border-collapse:collapse;width:100%}
    th{background:#f0f3f6;text-align:left}
    td,th{padding:8px;border:1px solid #ddd}
    a{color:#0366d6}
  </style>
</head>
<body>
    <h1>Windows Security Audit Report</h1>
    <p><strong>Version:</strong> $script:AuditVersion | <strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

    $bannerHtml

    <div class='panel'><h2>System info</h2><pre>$([System.Web.HttpUtility]::HtmlEncode($system))</pre></div>

  <div class='panel'><h2>Windows Defender / Antivirus</h2><pre>$([System.Web.HttpUtility]::HtmlEncode($defender))</pre></div>

  <div class='panel'><h2>SFC / DISM status</h2><pre>$([System.Web.HttpUtility]::HtmlEncode($sfctext))</pre></div>

  <div class='panel'><h2>Security Risk Analysis</h2>
    $riskHtml
    <hr style='margin:20px 0'>
    $hitsHtml
  </div>

  <div class='panel'><h2>All output files</h2><ul>$filesList</ul></div>

</body>
</html>
"@

        $html | Out-File -FilePath $htmlPath -Encoding UTF8

        # Optionally auto-open the HTML report in the default browser
        if ($auditCfg.OpenHtmlReport -eq $true) {
            try {
                $fullHtmlPath = Resolve-Path $htmlPath -ErrorAction Stop
                if (Test-Path $fullHtmlPath) {
                    Start-Process $fullHtmlPath
                } else {
                    "HTML report not found at: $fullHtmlPath" | Out-File -FilePath (Join-Path $outBase '00_quick_report_html_error.txt') -Encoding UTF8
                }
            } catch { 
                "Failed to open HTML report: $_" | Out-File -FilePath (Join-Path $outBase '00_quick_report_html_error.txt') -Encoding UTF8 
            }
        }
    }
} catch {
    "Failed to create HTML quick report: $_" | Out-File -FilePath (Join-Path $outBase '00_quick_report_html_error.txt') -Encoding UTF8
}

# Compress results
$zipPath = Join-Path $env:USERPROFILE ("Desktop\SecurityAudit_$timestamp.zip")
try {
    Compress-Archive -Path (Join-Path $outBase '*') -DestinationPath $zipPath -Force
    "Created archive: $zipPath" | Out-File (Join-Path $outBase "summary.txt") -Append -Encoding UTF8
} catch {
    "Compression failed: $_" | Out-File (Join-Path $outBase "summary.txt") -Append -Encoding UTF8
}

"Audit completed at: $(Get-Date)" | Out-File (Join-Path $outBase "summary.txt") -Append -Encoding UTF8
Write-Output "Audit completed. Results: $outBase"
Write-Output "Zip archive (if created): $zipPath"
