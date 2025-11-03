# This file contains unit tests for the full_system_audit.ps1 script, ensuring that the audit functions work as expected.

Describe "Full System Audit Tests" {
    # Load the main audit script
    . (Join-Path $PSScriptRoot "..\scripts\full_system_audit.ps1")

    It "Should return system information" {
        $result = Get-SystemInfo
        $result | Should -Not -BeNullOrEmpty
        $result.ComputerName | Should -Be $env:COMPUTERNAME
    }

    It "Should list installed updates" {
        $result = Get-InstalledUpdates
        $result | Should -Not -BeNullOrEmpty
    }

    It "Should check antivirus status" {
        $result = Get-AntivirusStatus
        $result | Should -Not -BeNullOrEmpty
        $result | Should -Contain "AntivirusEnabled"
    }

    It "Should return firewall profiles" {
        $result = Get-FirewallProfiles
        $result | Should -Not -BeNullOrEmpty
    }

    It "Should list open TCP ports" {
        $result = Get-OpenTcpPorts
        $result | Should -Not -BeNullOrEmpty
    }

    It "Should return services status" {
        $result = Get-ServicesStatus
        $result | Should -Not -BeNullOrEmpty
    }

    It "Should list local users" {
        $result = Get-LocalUsers
        $result | Should -Not -BeNullOrEmpty
    }

    It "Should return password policy" {
        $result = Get-PasswordPolicy
        $result | Should -Not -BeNullOrEmpty
    }

    It "Should check RDP settings" {
        $result = Get-RdpSettings
        $result | Should -Not -BeNullOrEmpty
    }

    It "Should return SMB configuration" {
        $result = Get-SmbConfiguration
        $result | Should -Not -BeNullOrEmpty
    }

    It "Should check BitLocker status" {
        $result = Get-BitLockerStatus
        $result | Should -Not -BeNullOrEmpty
    }

    It "Should list scheduled tasks" {
        $result = Get-ScheduledTasks
        $result | Should -Not -BeNullOrEmpty
    }

    It "Should list autoruns" {
        $result = Get-Autoruns
        $result | Should -Not -BeNullOrEmpty
    }

    It "Should list installed software" {
        $result = Get-InstalledSoftware
        $result | Should -Not -BeNullOrEmpty
    }

    It "Should check TLS settings" {
        $result = Get-TlsSettings
        $result | Should -Not -BeNullOrEmpty
    }

    It "Should return recent security events" {
        $result = Get-SecurityEvents
        $result | Should -Not -BeNullOrEmpty
    }

    It "Should return network configuration" {
        $result = Get-NetworkConfiguration
        $result | Should -Not -BeNullOrEmpty
    }

    It "Should perform SFC scan" {
        $result = Start-SfcScan
        $result | Should -Not -BeNullOrEmpty
    }
}