# Test Scripts for Risk Analysis Visualization

This directory contains test scripts to demonstrate how the security risk analysis appears visually in the HTML report.

## Quick Start

### 1. Create Test Data with Security Risks
```powershell
.\tests\create_test_report_with_risks.ps1
```

This creates mock audit files with intentional security issues including:
- **Critical**: Disabled antivirus, firewall off
- **High**: No password policies, SMBv1 enabled, NLA disabled
- **Medium**: No updates, RDP enabled, unencrypted SMB
- **RAT Indicators**: njrat, Back Orifice port

### 2. Generate HTML Report from Test Data
```powershell
# Use the path from step 1 output
$testDir = "C:\Users\...\AppData\Local\Temp\SecurityAudit_Test_20251104_XXXXXX"
.\tests\generate_test_html_report.ps1 -TestDataDir $testDir -OpenInBrowser
```

Or in one command:
```powershell
$testDir = (.\tests\create_test_report_with_risks.ps1 | Select-String 'Test output directory:').Line.Split(':')[1].Trim()
.\tests\generate_test_html_report.ps1 -TestDataDir $testDir -OpenInBrowser
```

## What You'll See

### Visual Elements in HTML Report

1. **Security Score Banner**
   - Score: 0-100 with color coding
   - Assessment: Critical (red), Poor (pink), Fair (yellow), Good (blue), Excellent (green)
   - Large, prominent display at top of Risk Analysis section

2. **Configuration Risks Table**
   - Color-coded rows by severity:
     - Critical: Dark pink (#f5c6cb)
     - High: Light pink (#fdd)
     - Medium: Light orange (#fff4e5)
   - Columns: Severity, Category, Issue, Impact (with points deducted)
   - Sorted by severity (Critical → High → Medium → Low)

3. **RAT/Malware Indicators Table**
   - Same color coding as configuration risks
   - Columns: Severity, Indicator, File, Line excerpt, Allowlisted
   - Shows exactly where suspicious patterns were found

### Example Network Risk Appearance

When the test report runs, you'll see network-related risks like:

**Configuration Risks:**
| Severity | Category | Issue | Impact |
|----------|----------|-------|--------|
| **High** (pink row) | SMB | SMBv1 Enabled | Insecure SMBv1 protocol is enabled (-15 points) |
| **Medium** (orange row) | SMB | Unencrypted SMB | SMB encryption is not enabled (-8 points) |
| **Medium** (orange row) | Remote Desktop | RDP Enabled | Remote Desktop is enabled (potential attack vector) (-8 points) |

**RAT Indicators:**
| Severity | Indicator | File | Line | Allowlisted |
|----------|-----------|------|------|-------------|
| **High** (pink row) | njrat | 13_scheduled_tasks.txt | `\ njrat_persistence Ready` | No |

## Customizing Test Data

Edit `create_test_report_with_risks.ps1` to add/remove specific risks:

- **Add a risk**: Modify mock file content to match patterns in `scripts/risk_rules.json`
- **Remove a risk**: Change mock file to avoid matching patterns
- **Test specific scenarios**: Create targeted mock files for edge cases

## Files

- `create_test_report_with_risks.ps1` - Generates mock audit output with security issues
- `generate_test_html_report.ps1` - Processes mock data through risk analysis and creates HTML
- `full_system_audit.Tests.ps1` - Pester unit tests for the main audit script

## Expected Output

With all default test risks, you should see:
- **Security Score**: ~0-25/100
- **Assessment**: Critical (red banner)
- **Configuration Risks**: 12-15 findings
- **RAT Indicators**: 2 findings

Total point deductions around 200-300 points (capped at 0).
