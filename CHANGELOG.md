# CHANGELOG

## [0.2.2] - 2025-11-04
### Added
- Version number display in script header and HTML report title
- Live SFC /scannow progress output to console using Write-Host

### Changed
- SFC /scannow now displays real-time progress to user while also capturing output

### Fixed
- SFC /scannow appearing stuck with no visible progress indicator
- RDP false positive detection (pattern now requires fDenyTSConnections=0)
- Visual progress bars filtered from SFC output files
- Emoji encoding issues in HTML reports (changed to HTML entities)

## [0.2.0] - 2025-11-04
### Added
- Comprehensive test suite for visual validation of risk analysis
  - `create_test_report_with_risks.ps1` generates mock audit data with security issues
  - `generate_test_html_report.ps1` creates test HTML reports
  - `TEST_SCRIPTS_README.md` with usage instructions
- Enhanced HTML report header with system identification
  - Computer name, manufacturer/model, domain display
  - Report generation timestamp
  - Compact 2-column grid layout for system information
- System info display: OS, User, CPU, RAM, Last Boot, Cores

### Changed
- **BREAKING**: Rebalanced security scoring system for more realistic assessments
  - Critical issues: -7 to -10 points (previously -20 to -30)
  - High issues: -5 to -8 points (previously -12 to -20)
  - Medium issues: -2 to -5 points (previously -5 to -10)
  - RAT indicators: High -10, Medium -4, Low -2 (previously -30, -10, -5)
  - Systems with severe issues now score 20-40 instead of bottoming at 0
- Updated risk_rules.json with balanced point values across all 10 categories
- Improved HTML report background (slightly darker #e8e8e8 for better contrast)

### Fixed
- Removed emoji characters causing encoding issues in HTML reports
- Better visual differentiation between security score categories

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