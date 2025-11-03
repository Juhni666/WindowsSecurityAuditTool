function Get-SystemInfo {
    # Retrieves basic system information
    return @{
        Time = (Get-Date).ToString();
        ComputerName = $env:COMPUTERNAME;
        User = $env:USERNAME;
        OS = (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber);
        Uptime = (Get-CimInstance Win32_OperatingSystem | ForEach-Object {
            (Get-Date) - ([Management.ManagementDateTimeConverter]::ToDateTime($_.LastBootUpTime))
        });
        Architecture = (Get-CimInstance Win32_Processor | Select-Object -First 1 AddressWidth);
        LogicalProcessors = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors;
    }
}

function Get-InstalledUpdates {
    # Retrieves a list of installed updates
    return Get-HotFix | Sort-Object InstalledOn -Descending
}

function Get-AntivirusStatus {
    # Retrieves antivirus and Windows Defender status
    $status = @{}
    $status['Antivirus'] = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName, productState, pathToSignedProductExe
    $status['Defender'] = Get-MpComputerStatus | Select-Object AMServiceEnabled, AMServiceVersion, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled, SignatureLastUpdated
    return $status
}

function Get-FirewallStatus {
    # Retrieves firewall profiles and rules
    $profiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowLocalFirewallRules
    $rules = Get-NetFirewallRule -Direction Inbound -Enabled True | Where-Object { $_.Action -eq 'Allow' } | Select-Object Name, DisplayName, Profile, Enabled, Direction, Action
    return @{ Profiles = $profiles; Rules = $rules }
}

function Get-ListeningPorts {
    # Retrieves open/listening TCP ports and owning processes
    return Get-NetTCPConnection -State Listen | ForEach-Object {
        $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort = $_.LocalPort
            ProcessName = $proc -or "Unknown"
            OwningProcess = $_.OwningProcess
        }
    }
}

function Get-LocalUsers {
    # Retrieves local user accounts and admin group membership
    $users = Get-LocalUser | Select-Object Name, Enabled, LockedOut, PasswordExpires
    $admins = Get-LocalGroupMember -Group Administrators | Select-Object Name, ObjectClass
    return @{ Users = $users; Admins = $admins }
}

function Get-PasswordPolicy {
    # Retrieves password and account policy
    return net accounts
}

function Get-RDPSettings {
    # Retrieves RDP and remote access settings
    $rdpSettings = @{
        RDPEnabled = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections -eq 0
        NLARequired = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication
    }
    return $rdpSettings
}

function Get-SMBSettings {
    # Retrieves SMB and file share settings
    $smbConfig = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EncryptData, RejectUnencryptedAccess
    $shares = Get-SmbShare | Select-Object Name, Path, Description, ScopeName, RestrictNullSessAccess
    return @{ SMBConfig = $smbConfig; Shares = $shares }
}

function Get-BitLockerStatus {
    # Retrieves BitLocker disk encryption status
    return Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, EncryptionPercentage, KeyProtector
}

function Get-ScheduledTasks {
    # Retrieves scheduled tasks
    return Get-ScheduledTask | ForEach-Object {
        $s = $_
        $st = (Get-ScheduledTaskInfo -TaskName $s.TaskName -TaskPath $s.TaskPath -ErrorAction SilentlyContinue).State
        [PSCustomObject]@{
            TaskName = ($s.TaskPath + $s.TaskName)
            State = $st
            Author = $s.Author
            RunLevel = $s.Principal.RunLevel
            Principal = $s.Principal.UserId
        }
    }
}

function Get-InstalledSoftware {
    # Retrieves installed software from the registry
    $x64Software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object { $_.DisplayName }
    $x86Software = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object { $_.DisplayName }
    return @{ x64 = $x64Software; x86 = $x86Software }
}

function Get-NetworkConfiguration {
    # Retrieves basic network configuration
    return @{
        IPConfig = ipconfig /all
        RoutingTable = route print
        ARPTable = arp -a
    }
}