Windows Security Audit — Release packaging

This folder contains a small release packaging and install helper for the project.

Files provided by the release tooling

- `scripts\package_release.ps1` — creates a distributable ZIP under `release/` containing the main scripts, module, docs and license.
- `scripts\install.ps1` — simple elevated installer: copies files to `Program Files\WindowsSecurityAudit\<timestamp>` and creates Desktop/Start Menu shortcuts.
- `scripts\uninstall.ps1` — interactive uninstall helper that removes installed folder(s) and shortcuts.
- `manifest_*.json` — metadata created by `package_release.ps1` describing the build.

Prerequisites & notes

- PowerShell 5.1 (Windows PowerShell) is the target runtime. The scripts avoid PowerShell Core-only features.
- The installer requires elevation (the script will re-launch elevated if needed).
- The installed copy is a portable snapshot (files are copied as-is). The installer does not modify scheduled tasks or registry keys.
- You should sign the package and scripts before publishing (recommended for public distribution).

How to build a release ZIP

Open an elevated or normal PowerShell prompt in the repository root and run:

```powershell
Set-ExecutionPolicy Bypass -Scope Process
powershell -ExecutionPolicy Bypass -File .\scripts\package_release.ps1
```

The produced ZIP will land in `release/`.

How to install the packaged release

- Unzip the produced package on the target machine. From an elevated PowerShell prompt run:

```powershell
Set-ExecutionPolicy Bypass -Scope Process
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

This creates a timestamped installation under `C:\Program Files\WindowsSecurityAudit` and places shortcuts.

How to uninstall

Run the included `scripts\uninstall.ps1` elevated and follow the prompts. You can run the uninstall helper from the installed folder or from the repo.

Security & publishing checklist

- Code-sign the PowerShell scripts and the package
- Review `indicators.json` and `audit_config.json` for any environment-specific defaults you want to change
- Add a changelog entry and update `manifest_*.json` before publishing

