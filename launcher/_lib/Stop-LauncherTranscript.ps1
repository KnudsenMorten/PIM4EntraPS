#Requires -Version 5.1
<#
.SYNOPSIS
    Stop the active transcript and prune logs older than the retention window.

.PARAMETER RetentionDays
    Override the global retention window (default: $global:PIM_LogRetentionDays
    set by shared-defaults, 30 days).

.PARAMETER SkipPrune
    Skip the prune step (e.g. for ad-hoc runs where you want to keep every log).

.NOTES
    Honours `$global:PIM_DisableTranscript = $true` (no-op if set).
    Mirrors SecurityInsight's Stop-LauncherTranscript pattern.
#>
[CmdletBinding()]
param(
    [Parameter()]
    [int]$RetentionDays,

    [Parameter()]
    [switch]$SkipPrune
)

if ($global:PIM_DisableTranscript) {
    Write-Verbose 'Stop-LauncherTranscript: transcript was disabled -- nothing to stop.'
    return
}

try {
    Stop-Transcript | Out-Null
} catch {
    Write-Verbose ("Stop-LauncherTranscript: no active transcript to stop ({0})" -f $_.Exception.Message)
}

if ($SkipPrune) { return }

if (-not $RetentionDays) { $RetentionDays = $global:PIM_LogRetentionDays }
if (-not $RetentionDays -or $RetentionDays -le 0) {
    Write-Verbose 'Stop-LauncherTranscript: retention disabled (RetentionDays <= 0).'
    return
}

$logsDir = Join-Path $global:PIM_SolutionRoot 'logs'
if (-not (Test-Path $logsDir)) { return }

$cutoff = (Get-Date).AddDays(-1 * $RetentionDays)
Get-ChildItem -Path $logsDir -Filter '*.log' -File -ErrorAction SilentlyContinue | Where-Object {
    $_.LastWriteTime -lt $cutoff
} | ForEach-Object {
    Write-Verbose ("Stop-LauncherTranscript: pruning {0} (older than {1} days)" -f $_.Name, $RetentionDays)
    Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
}
