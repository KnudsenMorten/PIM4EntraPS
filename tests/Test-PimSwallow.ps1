#Requires -Version 5.1
<#
.SYNOPSIS
    IMP-03 -- the one VISIBLE way to swallow a non-fatal error (PIM-Swallow.ps1),
    plus proof that the decision paths it was introduced for actually report:
    feature/edition store reads, the approval store, and the disable-abort alert.

    Shipped source has 218 empty `catch {}`. Most are correct not to rethrow -- an
    audit-write failure must not undo the approval it was recording. The defect is
    that they leave NO TRACE, so a decision taken on fallback data is
    indistinguishable from the same decision taken on real data. §32.6c records this
    class biting in the Activator: an undefined local threw, a catch ate it, and
    Show Roles silently returned nothing.

    These tests assert the OBSERVABILITY, and equally that the fallback BEHAVIOUR
    did not change -- this was not allowed to alter a single decision.

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot = Split-Path -Parent $PSScriptRoot
$shared  = Join-Path $solRoot 'engine\_shared'
. (Join-Path $shared 'PIM-DateSafe.ps1')
. (Join-Path $shared 'PIM-Swallow.ps1')

Write-Host "=== PIM-Swallow (IMP-03 visible swallowed errors) ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. The helper itself: it must never throw, and never change control flow.
# ---------------------------------------------------------------------------
Clear-PimSwallowedErrors
$threw = $false
try { Write-PimSwallowed -Scope 'unit' -Consequence 'nothing' -ErrorRecord $null -WarningAction SilentlyContinue } catch { $threw = $true }
Assert "reports with a `$null ErrorRecord without throwing" (-not $threw)
Assert "records the entry"                                  (@(Get-PimSwallowedErrors -Scope 'unit').Count -eq 1)
Assert "no error detail degrades to a placeholder"          (@(Get-PimSwallowedErrors -Scope 'unit')[0].message -eq '(no error detail)')

Clear-PimSwallowedErrors
try { throw 'boom-in-a-decision' } catch { Write-PimSwallowed -Scope 'unit' -Consequence 'fell back to defaults' -ErrorRecord $_ -WarningAction SilentlyContinue }
$e = @(Get-PimSwallowedErrors -Scope 'unit')
Assert "captures the exception message"     ($e.Count -eq 1 -and "$($e[0].message)" -like '*boom-in-a-decision*')
Assert "captures the CONSEQUENCE, not just the error" ("$($e[0].consequence)" -eq 'fell back to defaults')
Assert "stamps UTC in round-trip format"    ((Get-PimUtcStamp $e[0].utc) -is [datetime] -or ([datetime]::Parse($e[0].utc, [Globalization.CultureInfo]::InvariantCulture)) -is [datetime])

# a garbage "ErrorRecord" must not become the failure
$threw = $false
try { Write-PimSwallowed -Scope 'unit' -ErrorRecord ([pscustomobject]@{ nope = 1 }) -WarningAction SilentlyContinue } catch { $threw = $true }
Assert "a non-ErrorRecord object does not throw" (-not $threw)

# the ring is bounded -- a hot loop on a broken store must not grow memory forever
Clear-PimSwallowedErrors
for ($i = 0; $i -lt 260; $i++) { Write-PimSwallowed -Scope 'flood' -Consequence "i=$i" -WarningAction SilentlyContinue }
$flood = @(Get-PimSwallowedErrors -Scope 'flood')
Assert "the ring is bounded (<= 200 entries after 260 reports)" ($flood.Count -le 200)
Assert "the ring keeps the NEWEST entries"                      ("$($flood[-1].consequence)" -eq 'i=259')

# filtering
Clear-PimSwallowedErrors
Write-PimSwallowed -Scope 'a' -WarningAction SilentlyContinue
Write-PimSwallowed -Scope 'b' -WarningAction SilentlyContinue
Assert "-Scope filters"           (@(Get-PimSwallowedErrors -Scope 'a').Count -eq 1)
Assert "no -Scope returns all"    (@(Get-PimSwallowedErrors).Count -eq 2)

# ---------------------------------------------------------------------------
# 2. Feature-gate + edition store reads (PIM-FeatureCatalog.ps1).
#    A store read that fails silently means the ENGINE runs on defaults while the
#    GUI shows the operator's saved toggles -- state that no longer equals
#    behaviour, with nothing anywhere saying why.
# ---------------------------------------------------------------------------
. (Join-Path $shared 'PIM-FeatureCatalog.ps1')

# A working bridge must stay SILENT -- a warning on every healthy read is how real
# warnings get ignored.
Clear-PimSwallowedErrors
$global:PIM_NamingConventions = $null
function Get-PimSetting { param([string]$Name) return $null }
$null = Get-PimFeatureGateState
Assert "a healthy (empty) read reports nothing" (@(Get-PimSwallowedErrors).Count -eq 0)

# Now make the bridge THROW.
Clear-PimSwallowedErrors
function Get-PimSetting { param([string]$Name) throw 'SQL unreachable' }
$state = Get-PimFeatureGateState 3>$null
$rep   = @(Get-PimSwallowedErrors)
Assert "a throwing store read IS reported"        ($rep.Count -ge 1)
Assert "  ...naming the setting that could not be read" (@($rep | Where-Object { "$($_.consequence)" -like '*FeatureGates*' -or "$($_.consequence)" -like "*could not read setting*" }).Count -ge 1)
Assert "  ...and saying defaults are now in force"     (@($rep | Where-Object { "$($_.consequence)" -like '*defaults*' }).Count -ge 1)
# BEHAVIOUR UNCHANGED: it still resolves to the default gate map, and does not throw.
Assert "the gate map still resolves (fallback intact)" ($null -ne $state)

Clear-PimSwallowedErrors
$ed = Get-PimActiveEdition 3>$null
Assert "a throwing edition read IS reported"  (@(Get-PimSwallowedErrors).Count -ge 1)
Assert "edition still falls back to Core"     ("$ed" -eq 'Core')

Remove-Item Function:\Get-PimSetting -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 3. The approval store (PIM-ApprovalGate.ps1).
#    An unreadable approval store reads as "never approved" -- every gate fails
#    CLOSED on it, which is right, but must not be indistinguishable from a
#    genuine absence of approval.
# ---------------------------------------------------------------------------
. (Join-Path $shared 'PIM-ApprovalGate.ps1')

Clear-PimSwallowedErrors
function Get-PimSetting { param([string]$Name) throw 'store down' }
$env:PIM_APPROVAL_STORE_DIR = $null
$reqs = @(Get-PimApprovalRequests 3>$null)
$rep  = @(Get-PimSwallowedErrors -Scope 'approval-store-read')
Assert "an unreadable approval store IS reported"     ($rep.Count -ge 1)
Assert "  ...and says the gate now fails CLOSED"      ("$($rep[0].consequence)" -like '*CLOSED*')
Assert "the list still degrades to empty, no throw"   ($reqs.Count -eq 0)

# A write that lands nowhere is the worst case: the approval exists only in memory.
Clear-PimSwallowedErrors
function Set-PimSetting { param([string]$Name, [object]$Value) throw 'store down' }
# A path whose PARENT cannot be created, so both the SQL write and the file write fail.
# (Built as a plain string -- Join-Path itself refuses a non-existent PSDrive.)
function Get-PimApprovalStorePath { return 'Z:\no-such-drive-for-pim-tests\pim-approval-requests.json' }
Save-PimApprovalRequests -Requests @([pscustomobject]@{ id = 'x1'; status = 'Approved' }) 3>$null 2>$null
$rep = @(Get-PimSwallowedErrors -Scope 'approval-store-write')
Assert "an approval write that lands NOWHERE is reported" ($rep.Count -ge 1)
Assert "  ...and says the state is in memory only"        ("$($rep[0].consequence)" -like '*IN MEMORY ONLY*')

Remove-Item Function:\Get-PimSetting, Function:\Set-PimSetting, Function:\Get-PimApprovalStorePath -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# 4. The disable-abort alert (PIM-DisableGuard.ps1) -- BUG-01's signal.
#    A trip that nobody is told about is the incident all over again.
# ---------------------------------------------------------------------------
. (Join-Path $shared 'PIM-DisableGuard.ps1')

Clear-PimSwallowedErrors
function Write-PimAuditEvent { param($Action, $Target, $After) throw 'audit sink down' }
function Send-PimNotifyMail  { param($Type, $Tokens, $Recipient) throw 'smtp down' }
$global:PIM_AlertRecipient = 'ops@example.invalid'
$decision = [pscustomobject]@{ allowed=$false; abort=$true; tripped='G2'; reason='cap exceeded'; toDisable=53; scanned=100 }
$threw = $false
try { Write-PimDisableAbortAlert -Scope 'unit-sweep' -Decision $decision 3>$null 6>$null | Out-Null } catch { $threw = $true }
Assert "the alert helper still NEVER throws"          (-not $threw)
Assert "a failed audit write is reported"             (@(Get-PimSwallowedErrors -Scope 'disable-abort-audit').Count -ge 1)
Assert "a failed alert MAIL is reported"              (@(Get-PimSwallowedErrors -Scope 'disable-abort-alert-mail').Count -ge 1)
Assert "  ...and says nobody is being paged"          ("$(@(Get-PimSwallowedErrors -Scope 'disable-abort-alert-mail')[0].consequence)" -like '*nobody is being paged*')

Remove-Item Function:\Write-PimAuditEvent, Function:\Send-PimNotifyMail -ErrorAction SilentlyContinue
$global:PIM_AlertRecipient = $null

# ---------------------------------------------------------------------------
# 5. Anti-regression: the sites IMP-03 fixed must not quietly go back to `catch {}`.
#    Deliberately narrow -- this asserts the DECISION paths only, never all 218.
# ---------------------------------------------------------------------------
$guarded = @(
    @{ file = 'engine\_shared\PIM-FeatureCatalog.ps1'; scopes = @('feature-store-read','feature-gate-read','edition-read') }
    @{ file = 'engine\_shared\PIM-ApprovalGate.ps1';   scopes = @('approval-store-read','approval-store-write','approval-audit-write') }
    @{ file = 'engine\_shared\PIM-DisableGuard.ps1';   scopes = @('disable-abort-audit','disable-abort-alert-mail') }
    @{ file = 'tools\pim-manager\Open-PimManager.ps1'; scopes = @('portal-scope-rows-read') }
)
foreach ($g in $guarded) {
    $p = Join-Path $solRoot $g.file
    $txt = if (Test-Path -LiteralPath $p) { Get-Content -LiteralPath $p -Raw } else { '' }
    foreach ($s in $g.scopes) {
        Assert ("{0} still reports '{1}'" -f (Split-Path -Leaf $g.file), $s) ($txt -like "*'$s'*")
    }
}

# Every consumer must be able to load the helper on its own -- five suites went red
# during IMP-02 for exactly this reason (a test dot-sources one _shared file alone).
foreach ($f in 'PIM-FeatureCatalog.ps1','PIM-ApprovalGate.ps1','PIM-DisableGuard.ps1') {
    $txt = Get-Content -LiteralPath (Join-Path $shared $f) -Raw
    Assert "$f loads PIM-Swallow.ps1 defensively" ($txt -like '*PIM-Swallow.ps1*')
}
$mgr = Get-Content -LiteralPath (Join-Path $solRoot 'tools\pim-manager\Open-PimManager.ps1') -Raw
Assert "Open-PimManager.ps1 loads PIM-Swallow.ps1" ($mgr -like '*PIM-Swallow.ps1*')
$psm = Get-Content -LiteralPath (Join-Path $shared 'PIM-Functions.psm1') -Raw
Assert "PIM-Functions.psm1 dot-sources PIM-Swallow.ps1" ($psm -like '*PIM-Swallow.ps1*')

Write-Host ""
Write-Host ("PIM-Swallow (IMP-03): {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
