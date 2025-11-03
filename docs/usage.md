# Usage Instructions for Windows Security Audit

## Prerequisites
- Ensure you have PowerShell installed on your Windows system.
- The script must be run in an elevated PowerShell session (Run as Administrator).
- Set the execution policy to allow script execution by running the following command:
  ```powershell
  Set-ExecutionPolicy Bypass -Scope Process
  ```

## Running the Audit
To execute the full security audit, use the following command in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File "C:\path\to\your\windows-security-audit\scripts\full_system_audit.ps1"
```

Replace `C:\path\to\your` with the actual path where the `windows-security-audit` project is located.

### GUI launcher (optional)

A simple Windows Forms launcher with a Start button is provided at `scripts/run_gui.ps1`.

- Run the launcher to show a small dialog with a "Start Audit" button. Clicking it launches the audit in a new PowerShell process. If the audit requires elevation, you'll be prompted by UAC.
- The launcher does not capture or display the audit output — results are written to the user's Desktop in a timestamped folder as usual.

```powershell
# Run the GUI launcher
powershell -ExecutionPolicy Bypass -File ".\scripts\run_gui.ps1"
```

## Output
- The audit results will be saved in a folder on your Desktop named `SecurityAudit_YYYYMMDD_HHmmss`.
- A zip file containing the audit results will also be created in the same location.

## Scheduling the Audit
To schedule the audit to run at specified intervals, you can use the example script provided in the `examples` directory. Modify the `scheduled-run.ps1` script as needed to fit your scheduling requirements.