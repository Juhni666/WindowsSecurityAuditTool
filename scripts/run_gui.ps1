# Windows Security Audit — simple GUI launcher
#
# Usage:
# - Double-click or run this script from PowerShell. The Start button will launch
#   `scripts/full_system_audit.ps1`. If the audit requires elevation, the audit
#   will be launched elevated (UAC prompt) using Start-Process -Verb RunAs.
# - This script only starts the audit in a new PowerShell process; it does not
#   embed the audit run or capture its output.

[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
[void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$auditScript = Join-Path $scriptDir 'full_system_audit.ps1'

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Windows Security Audit'
$form.Size = New-Object System.Drawing.Size(420,160)
$form.StartPosition = 'CenterScreen'

$lbl = New-Object System.Windows.Forms.Label
$lbl.Text = "Click Start to run the security audit.`nOutput is written to the current user's Desktop (SecurityAudit_YYYYMMDD_HHmmss)."
$lbl.AutoSize = $true
$lbl.MaximumSize = New-Object System.Drawing.Size(380,0)
$lbl.Location = New-Object System.Drawing.Point(12,12)
$form.Controls.Add($lbl)

$status = New-Object System.Windows.Forms.Label
$status.Text = "Ready"
$status.AutoSize = $true
$status.Location = New-Object System.Drawing.Point(12,70)
$form.Controls.Add($status)

$btn = New-Object System.Windows.Forms.Button
$btn.Text = 'Start Audit'
$btn.Size = New-Object System.Drawing.Size(120,36)
$btn.Location = New-Object System.Drawing.Point(270,12)
$btn.Add_Click({
    $btn.Enabled = $false
    $status.Text = 'Starting...'
    try {
        if (Test-IsAdmin) {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = 'powershell.exe'
            $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$auditScript`""
            $psi.UseShellExecute = $true
            [System.Diagnostics.Process]::Start($psi) | Out-Null
            [System.Windows.Forms.MessageBox]::Show('Audit started (running in a new PowerShell process).','Started',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        } else {
            $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$auditScript`""
            Start-Process -FilePath 'powershell.exe' -ArgumentList $arg -Verb RunAs
            [System.Windows.Forms.MessageBox]::Show('Audit launched elevated. You may be prompted by UAC.','Launched',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        }
        $status.Text = 'Launched'
    } catch {
        $status.Text = "Error: $($_.Exception.Message)"
        [System.Windows.Forms.MessageBox]::Show("Failed to start audit:`n$($_.Exception.Message)",'Error',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        $btn.Enabled = $true
    }
})
$form.Controls.Add($btn)

$closeBtn = New-Object System.Windows.Forms.Button
$closeBtn.Text = 'Close'
$closeBtn.Size = New-Object System.Drawing.Size(80,28)
$closeBtn.Location = New-Object System.Drawing.Point(270,56)
$closeBtn.Add_Click({ $form.Close() })
$form.Controls.Add($closeBtn)

[System.Windows.Forms.Application]::EnableVisualStyles()
[System.Windows.Forms.Application]::Run($form)
