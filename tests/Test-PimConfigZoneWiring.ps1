#Requires -Version 5.1
<#
.SYNOPSIS
  IMP-20 SAFETY NET -- the four CONFIGURATION blocks must still be WIRED after being moved to
  the Settings page.

.DESCRIPTION
  Those blocks are RENDERED by renderGovernance() and WIRED in its tail ~130 lines later. Moving
  them means carrying the wiring with them, and the failure mode is a control that still LOOKS
  right and silently does nothing.

  🔑 NO STATIC CHECK CAN SEE THAT. The markup still exists, a getElementById() for it still
  exists, and the endpoints are untouched -- so a grep passes, and the dead-controls harness
  (which asserts endpoints resolve to handlers) passes too. Only the live DOM knows whether a
  handler is actually attached.

  So the node harness renders the page in jsdom, visits the tabs, and asserts each control is
  PRESENT and has a HANDLER ATTACHED. Written and made to pass against the PRE-MOVE layout
  first: a test authored after a refactor only proves the refactor is self-consistent, while one
  that passed before and still passes proves the behaviour survived.

  Self-skips (exit 0) when node or jsdom is unavailable -- absence is not failure, mirroring the
  project's Live-test rule.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$js   = Join-Path $here 'gui-headless\config-zone-wiring.js'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

Write-Host "`n=== IMP-20: configuration-zone control wiring (headless DOM) ===" -ForegroundColor Cyan
$node = (Get-Command node -ErrorAction SilentlyContinue)
if (-not $node) { Write-Host '  SKIP node not available -- absence is not a failure.' -ForegroundColor DarkGray; exit 0 }
if (-not (Test-Path -LiteralPath $js)) { Write-Host "  FAIL harness missing: $js" -ForegroundColor Red; exit 1 }

$raw = & node $js 2>&1 | Out-String
$obj = $null
try { $obj = $raw | ConvertFrom-Json } catch { }
if (-not $obj) { Write-Host "  FAIL harness produced no JSON:`n$raw" -ForegroundColor Red; exit 1 }
if ($obj.PSObject.Properties['harnessError']) {
    if ("$($obj.harnessError)" -match 'jsdom not installed') {
        Write-Host "  SKIP $($obj.harnessError) -- absence is not a failure." -ForegroundColor DarkGray; exit 0
    }
    Write-Host "  FAIL harness error: $($obj.harnessError)" -ForegroundColor Red; exit 1
}

foreach ($f in @($obj.findings)) {
    if ($f.conditional -and -not $f.present) {
        Write-Host ("  n/a  {0} -- section had no data in this seed (conditional control)" -f $f.id) -ForegroundColor DarkGray
        continue
    }
    T ("{0} is rendered ({1})" -f $f.id, $f.what) ([bool]$f.present)
    if ($f.present) { T ("{0} has a handler ATTACHED (survived the move)" -f $f.id) ([bool]$f.wired) }
}
T 'no control is present-but-dead' ([bool]$obj.ok)

Write-Host ""
if ($fail) { Write-Host " RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
Write-Host " RESULT: $pass pass, 0 fail" -ForegroundColor Green
exit 0
