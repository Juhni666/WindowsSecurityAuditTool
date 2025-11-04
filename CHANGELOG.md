# CHANGELOG

## [0.1.1] - 2025-11-04
### Fixed
- SFC output formatting in HTML reports (removed verbose progress spam)
- PowerShell window visibility in desktop shortcuts
- Unicode/UTF-16 character handling in SFC output files

### Changed
- Improved README with clearer installation instructions
- Updated release packaging to include QUICK_START.txt

## [0.1.0] - 2025-11-04
### Added
- Initial release of the Windows Security Audit project
- Comprehensive security audit script (`full_system_audit.ps1`) to check system information, installed updates, antivirus status, firewall settings, open ports, services, user accounts, password policies, RDP settings, SMB configurations, BitLocker status, scheduled tasks, autoruns, installed software, TLS settings, security events, network configuration, and integrity checks
- Helper functions in `helpers.ps1` for error handling and script execution
- Compression script (`archive-results.ps1`) for zipping audit results
- PowerShell module (`AuditHelpers`) with additional utilities for auditing
- Unit tests for the main audit script in `full_system_audit.Tests.ps1`
- Documentation for usage in `usage.md`
- Example script for scheduling audits in `scheduled-run.ps1`
- GUI interface (`run_gui.ps1`) for easy operation
- Installation and uninstallation scripts
- HTML report generation with RAT detection scoring