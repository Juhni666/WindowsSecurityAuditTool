# CHANGELOG

## [Unreleased]
### Added
- Initial creation of the Windows Security Audit project.
- Comprehensive security audit script (`full_system_audit.ps1`) to check system information, installed updates, antivirus status, firewall settings, open ports, services, user accounts, password policies, RDP settings, SMB configurations, BitLocker status, scheduled tasks, autoruns, installed software, TLS settings, security events, network configuration, and integrity checks.
- Helper functions in `helpers.ps1` for error handling and script execution.
- Compression script (`archive-results.ps1`) for zipping audit results.
- PowerShell module (`AuditHelpers`) with additional utilities for auditing.
- Unit tests for the main audit script in `full_system_audit.Tests.ps1`.
- Documentation for usage in `usage.md`.
- Example script for scheduling audits in `scheduled-run.ps1`.

### Changed
- None

### Fixed
- None

## [1.0.0] - YYYY-MM-DD
### Added
- First stable release of the Windows Security Audit project.