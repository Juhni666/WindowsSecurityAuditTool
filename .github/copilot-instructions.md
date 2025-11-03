## Quick orientation — what this repo is

This is a PowerShell-based Windows security audit toolkit. The single-entry script is `scripts/full_system_audit.ps1`. Helpers live in `scripts/helpers.ps1` and a reusable module is in `modules/AuditHelpers/` (manifest: `AuditHelpers.psd1`, implementation: `AuditHelpers.psm1`). Tests are in `tests/` and examples (scheduling) are in `examples/`.

## Big picture architecture

- Main runner: `scripts/full_system_audit.ps1` — orchestrates a sequence of checks, writes numbered text files (e.g. `01_system_info.txt`, `02_installed_updates.txt`) into an output folder `$outBase` and then compresses results to a zip on the Desktop.
- Helpers/module: `scripts/helpers.ps1` and `modules/AuditHelpers` — provide `Safe-Run`, timestamp helpers, and small utilities. Prefer adding reusable logic to the module and exporting via `AuditHelpers.psd1`.
- Tests: `tests/full_system_audit.Tests.ps1` — Pester-based unit tests that dot-source the main script and assert on function outputs. Keep function names stable (e.g. `Get-SystemInfo`, `Get-InstalledSoftware`) or update tests accordingly.

Why this structure: the runner is intentionally script-first (single-file runnable) while functionality is extracted into helpers/module for reuse and testability.

## Critical developer workflows

- Run the audit locally (must be elevated):

```powershell
Set-ExecutionPolicy Bypass -Scope Process
powershell -ExecutionPolicy Bypass -File ".\scripts\full_system_audit.ps1"
```

- Run tests (Pester required; install if needed):

```powershell
Install-Module -Name Pester -Scope CurrentUser -Force
Import-Module Pester
Invoke-Pester .\tests\full_system_audit.Tests.ps1
```

- Schedule using `examples/scheduled-run.ps1` as a template — it demonstrates how the project expects scheduled execution and how outputs are stored.

## Project-specific conventions and patterns

- Output naming: audit output files are explicitly numbered and named (e.g. `01_system_info.txt`, `06_listening_ports.txt`). When adding checks, follow the same numeric prefix pattern and append the text file to `$outBase` via `Safe-Run`.
- Safe-Run wrapper: use `Safe-Run { <scriptblock> } (Join-Path $outBase "NN_description.txt")` to capture output and errors. This is the canonical pattern for side-effecting checks and logging.
- Idempotence & best-effort: many checks wrap feature-specific cmdlets (BitLocker, SMB, Defender) in try/catch and continue on failure. Prefer the same defensive approach when adding new checks.
- PowerShell version: module manifest targets PowerShell 5.1 (see `AuditHelpers.psd1`). Keep compatibility with PS 5.1 where feasible.
- Timestamp format: the project uses `yyyyMMdd_HHmmss` for output folder names (see `$timestamp` usage in `full_system_audit.ps1`). Reuse this format when creating artifacts.

## Integration points & external dependencies

- Platform: Windows desktop with administrative privileges. Many cmdlets require admin or optional modules.
- Optional Windows modules/cmdlets used (may not exist on all hosts): `Get-BitLockerVolume`, `Get-SmbServerConfiguration`, `Get-MpComputerStatus`, `Get-ScheduledTask`, `Get-NetTCPConnection`. Code uses try/catch; follow that pattern.
- Compression: `Compress-Archive` is used to build the ZIP result.

## Editing & extending the codebase — practical notes

- To add a new audit check:
  1. Implement the function in `scripts/helpers.ps1` or `modules/AuditHelpers/AuditHelpers.psm1`.
  2. Export it from `AuditHelpers.psd1` if reusable.
  3. Call it from `full_system_audit.ps1` inside `Safe-Run` and write to a new `NN_description.txt` file.
  4. Add a focused unit test in `tests/full_system_audit.Tests.ps1` that dot-sources the main script and validates the function output.

Examples from repo:
- `Safe-Run { Get-NetTCPConnection -State Listen | ForEach-Object { ... } } (Join-Path $outBase "06_listening_ports.txt")`
- Timestamp & output folder: see `$timestamp` and `$outBase` in `scripts/full_system_audit.ps1`.

## Things an AI agent should watch for

- Admin-only behavior: always note that many checks require elevation; do not propose running them non-elevated without guard clauses.
- Avoid assuming presence of optional modules; use try/catch and graceful fallbacks like existing code does.
- Keep function names referenced by tests stable; renames must be accompanied by test updates.

## Where to look first (quick navigation)

- `scripts/full_system_audit.ps1` — main runner and canonical usage of `Safe-Run` and output layout.
- `scripts/helpers.ps1` — helper functions used by the runner.
- `modules/AuditHelpers/AuditHelpers.psm1` and `.psd1` — module code and manifest (PowerShell compatibility and exported functions).
- `tests/full_system_audit.Tests.ps1` — examples of unit tests (Pester) and expected function names/behaviour.

If any of these sections are unclear or you need expanded examples (e.g., a patch adding a new check and test), tell me which part to expand and I'll update this file.
