# Windows Security Audit

This project provides a comprehensive security audit solution for Windows systems. The main script, `full_system_audit.ps1`, performs a thorough examination of various system settings and configurations to ensure security best practices are followed.

## Features

- **System Information**: Gathers essential details about the operating system, architecture, and uptime.
- **Installed Updates**: Lists all installed Windows updates.
- **Antivirus Status**: Checks the status of installed antivirus software and Windows Defender.
- **Firewall Settings**: Reviews firewall profiles and active rules.
- **Open Ports**: Identifies listening TCP ports and their associated processes.
- **Service Status**: Reports on automatic services that are not running and those running under unusual accounts.
- **User Accounts**: Lists local users and their account statuses, including admin group memberships.
- **Password Policies**: Displays current password and account policies.
- **Remote Desktop Settings**: Checks RDP settings and configurations.
- **SMB Configurations**: Reviews SMB settings and shares.
- **Disk Encryption**: Reports on BitLocker status for volumes.
- **Scheduled Tasks**: Lists scheduled tasks, focusing on those running with elevated privileges.
- **Startup Programs**: Inspects autoruns from registry and startup folders.
- **Installed Software**: Provides a list of installed software from the registry.
- **TLS Settings**: Inspects Schannel protocols and cipher settings.
- **Security Events**: Reviews recent security events related to logons and service installations.
- **Network Configuration**: Displays IP configuration, routing table, and ARP table.
- **Integrity Checks**: Performs a system file checker (SFC) scan summary.

## Getting Started

1. **Prerequisites**: Ensure you have PowerShell running with administrative privileges.
2. **Execution Policy**: Set the execution policy to allow script execution:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process
   ```
3. **Run the Audit**: Execute the main audit script:
   ```powershell
   powershell -ExecutionPolicy Bypass -File "C:\path\to\full_system_audit.ps1"
   ```

## Documentation

For detailed usage instructions, refer to the [usage documentation](docs/usage.md).

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.