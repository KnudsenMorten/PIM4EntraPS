#Requires -Version 5.1
<#
.SYNOPSIS
    Start a PowerShell transcript for a launcher run. Log file is created
    under <solution>/logs/<engine>_<flavour>_<yyyyMMddTHHmmssZ>.log.

.PARAMETER Flavour
    One of 'internal-vm', 'internal-azure', 'community-vm', 'community-azure'.
    Used in the log file name so multiple flavours don't collide.

.PARAMETER EngineName
    Override the auto-detected engine name (default: $global:PIM_EngineName
    set by Initialize-LauncherConfig).

.PARAMETER LogPath
    Override the log file path (default: derived from engine + flavour + UTC stamp).

.NOTES
    Honours `$global:PIM_DisableTranscript = $true` (no-op if set).
    Mirrors SecurityInsight's Start-LauncherTranscript pattern.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('internal-vm','internal-azure','community-vm','community-azure')]
    [string]$Flavour,

    [Parameter()]
    [string]$EngineName,

    [Parameter()]
    [string]$LogPath
)

if ($global:PIM_DisableTranscript) {
    Write-Verbose 'Start-LauncherTranscript: $global:PIM_DisableTranscript = $true -- skipping.'
    return
}

if (-not $EngineName) { $EngineName = $global:PIM_EngineName }
if (-not $EngineName) {
    throw 'Start-LauncherTranscript: EngineName not provided and $global:PIM_EngineName not set. Call Initialize-LauncherConfig first.'
}

if (-not $LogPath) {
    $logsDir = Join-Path $global:PIM_SolutionRoot 'logs'
    if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir -Force | Out-Null }
    $stamp   = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $LogPath = Join-Path $logsDir ("{0}_{1}_{2}.log" -f $EngineName, $Flavour, $stamp)
}

Start-Transcript -Path $LogPath -Append | Out-Null
$global:PIM_TranscriptPath = $LogPath
Write-Host ("[transcript] log = {0}" -f $LogPath)
