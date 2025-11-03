function Safe-Run {
    param(
        [scriptblock]$ScriptBlock,
        [string]$File
    )
    try {
        & $ScriptBlock 2>&1 | Out-File -FilePath $File -Encoding UTF8
    } catch {
        "$_" | Out-File -FilePath $File -Encoding UTF8
    }
}

function Get-CurrentTimestamp {
    return (Get-Date).ToString("yyyyMMdd_HHmmss")
}

function Create-OutputDirectory {
    param(
        [string]$BasePath
    )
    $timestamp = Get-CurrentTimestamp
    $outDir = Join-Path $BasePath ("SecurityAudit_$timestamp")
    New-Item -Path $outDir -ItemType Directory -Force | Out-Null
    return $outDir
}

function Compress-Results {
    param(
        [string]$SourcePath,
        [string]$DestinationPath
    )
    try {
        Compress-Archive -Path (Join-Path $SourcePath '*') -DestinationPath $DestinationPath -Force
    } catch {
        "Compression failed: $_" | Out-File -FilePath (Join-Path $SourcePath "summary.txt") -Append -Encoding UTF8
    }
}