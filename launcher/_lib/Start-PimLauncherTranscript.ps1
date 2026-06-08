#Requires -Version 5.1
<#
.SYNOPSIS
    Default transcript logging for every PIM4EntraPS launcher (internal-vm,
    internal-azure, community-vm, community-azure) across all engines.

.DESCRIPTION
    Mirrors the SecurityInsight pattern (launcher/_lib/Start-LauncherTranscript.ps1)
    so every PIM4EntraPS run leaves a copy on disk for forensics + customer
    support even when the operator didn't redirect stdout.

    Log path : <repoRoot>/SOLUTIONS/PIM4EntraPS/logs/<engine>_<flavour>_<utcStamp>.log
                - one folder per repo (easier to grep / archive)
                - utcStamp = yyyyMMddTHHmmssZ (sortable)
                - <flavour> = 'internal-vm' | 'internal-azure' | 'community-vm' | 'community-azure' | 'container'
                - <engine>  = parent folder name (PIM-Baseline-Management-CSV,
                              PIM-Assignment-Exporter, etc.)

    Retention: prune log files older than $RetentionDays (default 30).
    Customers override via $global:PIM_LogRetentionDays in config or by
    passing -RetentionDays from the launcher.

    Honours $global:PIM_DisableTranscript = $true (lab/CI override).

.NOTES
    Designed by  : Morten Knudsen, 2linkIT
    Introduced   : PIM4EntraPS v2.4.71 (parity with SI logging)
#>

function Start-PimLauncherTranscript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][string]$Flavour,
        [Parameter()][string]$RepoRoot,
        [Parameter()][int]$RetentionDays = $(if ($global:PIM_LogRetentionDays) { [int]$global:PIM_LogRetentionDays } else { 30 })
    )

    if ($global:PIM_DisableTranscript) { return $null }

    # Resolve repo root: caller's $InstallPath > walk up from $PSScriptRoot.
    if (-not $RepoRoot) {
        $cur = $PSScriptRoot
        while ($cur -and `
               -not (Test-Path (Join-Path $cur 'SOLUTIONS\PIM4EntraPS\VERSION')) -and `
               -not (Test-Path (Join-Path $cur 'VERSION'))) {
            $parent = Split-Path -Parent $cur
            if (-not $parent -or $parent -eq $cur) { break }
            $cur = $parent
        }
        $RepoRoot = $cur
    }

    # Layout-aware logs dir: monorepo layout writes to
    # SOLUTIONS/PIM4EntraPS/logs; flat (community) publish writes to <root>/logs.
    $logsDir = if ($RepoRoot -and (Test-Path -LiteralPath (Join-Path $RepoRoot 'SOLUTIONS\PIM4EntraPS\VERSION'))) {
        Join-Path $RepoRoot 'SOLUTIONS/PIM4EntraPS/logs'
    } elseif ($RepoRoot) {
        Join-Path $RepoRoot 'logs'
    } else {
        Join-Path $PSScriptRoot '..\..\logs'
    }
    if (-not (Test-Path -LiteralPath $logsDir)) {
        try {
            New-Item -ItemType Directory -Path $logsDir -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Warning ("Could not create transcript folder {0}: {1}. Continuing without transcript." -f $logsDir, $_.Exception.Message)
            return $null
        }
    }

    # Retention prune (best-effort -- never throws)
    if ($RetentionDays -gt 0) {
        $cutoff = (Get-Date).AddDays(-$RetentionDays)
        try {
            Get-ChildItem -LiteralPath $logsDir -Filter '*.log' -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $cutoff } |
                Remove-Item -Force -ErrorAction SilentlyContinue
        } catch { }
    }

    $stamp   = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $engSafe = [regex]::Replace($Engine,  '[^A-Za-z0-9_-]', '')
    $flvSafe = [regex]::Replace($Flavour, '[^A-Za-z0-9_-]', '')
    $logPath = Join-Path $logsDir ("{0}_{1}_{2}.log" -f $engSafe, $flvSafe, $stamp)

    # Defensive: stop any prior transcript silently.
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }

    try {
        Start-Transcript -Path $logPath -Force -ErrorAction Stop | Out-Null
        $global:PIM_TranscriptPath = $logPath
        return $logPath
    } catch {
        Write-Warning ("Start-Transcript failed ({0}); continuing without transcript." -f $_.Exception.Message)
        return $null
    }
}

function Stop-PimLauncherTranscript {
    [CmdletBinding()]
    param()
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    Remove-Variable -Name PIM_TranscriptPath -Scope Global -ErrorAction SilentlyContinue
}
