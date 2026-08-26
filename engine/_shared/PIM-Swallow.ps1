# ---------------------------------------------------------------------------
# IMP-03 -- ONE visible way to swallow a non-fatal error.
#
# Shipped source has 218 empty `catch {}` blocks. Most are deliberate best-effort
# paths and are CORRECT not to rethrow: an audit-write failure must not mask the
# abort it was recording, and a Dispose() failure must not change a verdict. The
# defect is not the swallowing -- it is that the swallowed error leaves NO TRACE,
# so a decision silently taken on fallback data is indistinguishable from the
# same decision taken on real data.
#
# §32.6c records this exact class biting in the Activator: a refactor left an
# undefined local, it threw at runtime, a catch ate it, and Show Roles silently
# returned nothing. Nothing was broken loudly enough to notice.
#
# This helper is deliberately NOT a rethrow and NOT a logger with state. It is a
# single line on the host + the warning stream, so the operator and the container
# log see it, plus an in-memory ring the tests assert against.
#
# RULES:
#   1. NEVER throws. A reporting failure must not become the failure. (Everything
#      here is inside its own guard -- including the ring buffer.)
#   2. Does not change control flow. The caller's fallback still runs, unchanged.
#      This is an observability fix, not a behaviour fix.
#   3. Use it where a swallowed error can CHANGE A DECISION -- auth, gating,
#      store reads, audit writes. Do NOT sweep it through all 218 sites; a
#      warning on every best-effort nicety is how real warnings get ignored.
# ---------------------------------------------------------------------------

# In-memory ring of what has been swallowed this process. Bounded, so a hot loop
# on a broken store cannot grow it without limit.
if ($null -eq $global:PIM_SwallowedErrors) { $global:PIM_SwallowedErrors = New-Object System.Collections.ArrayList }
$script:PimSwallowMax = 200

function Write-PimSwallowed {
    <#
    .SYNOPSIS
        Report a non-fatal error that is being swallowed on purpose. Never throws.
    .PARAMETER Scope
        Where it happened, in caller terms -- 'feature-gate-read', 'approval-store-write'.
        This is what an operator greps for, so name the DECISION, not the function.
    .PARAMETER Consequence
        What the caller does now instead. The whole point: "fell back to defaults"
        is the difference between a log line and a useful log line.
    .PARAMETER ErrorRecord
        The caught $_ . Optional -- some callers only know that a value was absent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Scope,
        [string]$Consequence = '',
        [AllowNull()][object]$ErrorRecord = $null
    )

    $msg = ''
    try {
        if ($ErrorRecord -and $ErrorRecord.Exception) { $msg = "$($ErrorRecord.Exception.Message)" }
        elseif ($ErrorRecord)                         { $msg = "$ErrorRecord" }
    } catch { $msg = '' }
    if (-not "$msg".Trim()) { $msg = '(no error detail)' }

    $line = "[engine] non-fatal in {0}: {1}" -f $Scope, $msg
    if ("$Consequence".Trim()) { $line += " -- $Consequence" }

    # Host first: in the container/scheduler log this is the trace that survives.
    try { Write-Host $line -ForegroundColor DarkYellow } catch { }
    try { Write-Warning $line } catch { }
    try {
        if ($global:PIM_SwallowedErrors -is [System.Collections.IList]) {
            if ($global:PIM_SwallowedErrors.Count -ge $script:PimSwallowMax) { [void]$global:PIM_SwallowedErrors.RemoveAt(0) }
            [void]$global:PIM_SwallowedErrors.Add([pscustomobject]@{
                utc         = [datetime]::UtcNow.ToString('o')
                scope       = $Scope
                consequence = $Consequence
                message     = $msg
            })
        }
    } catch { }
}

function Get-PimSwallowedErrors {
    # Everything swallowed this process, oldest first. Optional -Scope filter.
    [CmdletBinding()] param([string]$Scope)
    $all = @()
    try { if ($global:PIM_SwallowedErrors) { $all = @($global:PIM_SwallowedErrors) } } catch { $all = @() }
    if ("$Scope".Trim()) { $all = @($all | Where-Object { "$($_.scope)" -eq "$Scope" }) }
    return @($all)
}

function Clear-PimSwallowedErrors {
    # Test/diagnostic helper. Never throws.
    [CmdletBinding()] param()
    try { $global:PIM_SwallowedErrors = New-Object System.Collections.ArrayList } catch { }
}
