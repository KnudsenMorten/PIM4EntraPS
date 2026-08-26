#Requires -Version 5.1
<#
.SYNOPSIS
    MSP Downlink Manager surface (control #1/#2, framework MSP-2) -- static + pure
    offline checks that the tab, its endpoints and its safety gates are REALLY wired.

    Why static assertions matter here specifically: this surface writes privilege into
    a tenant the operator does not own. The failure that costs most is not a crash but
    a control that LOOKS wired and is not -- a tab with no render, an endpoint with no
    caller, or a write path missing its SuperAdmin gate. Each of those is asserted.

    All OFFLINE: no HTTP, no SQL, no tenant. The Manager script and HTML are read as
    text; the pure helpers are dot-sourced and exercised over fixtures.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root = Split-Path -Parent $PSScriptRoot
$html = Get-Content -LiteralPath (Join-Path $root 'tools\pim-manager\pim-manager.html') -Raw
$srv  = Get-Content -LiteralPath (Join-Path $root 'tools\pim-manager\Open-PimManager.ps1') -Raw
$lib  = Join-Path $root 'engine\_shared\PIM-DownlinkManager.ps1'

# ===========================================================================
Write-Host "`n== 1. THE TAB IS REACHABLE (a view nobody can open is not a feature) ==" -ForegroundColor Cyan
# ===========================================================================
T 'the flat strip declares data-tab="downlink"' ($html -match 'data-tab="downlink"')
T '  ...and it carries an unresolved badge' ($html -match 'id="downlinkUnresBadge"')
T 'the tab is placed in a NAV_GROUP (or the grouped nav drops it)' ($html -match "items: \[.*'downlink'.*\]")
T 'a panel host exists for it' ($html -match 'id="downlinkTab"' -and $html -match 'id="downlinkBody"')
T 'switchTab dispatches to renderDownlink' ($html -match "name === 'downlink'\) renderDownlink\(\)")
T 'renderDownlink is actually defined' ($html -match 'async function renderDownlink\(\)')
T 'the feature catalog registers the tab id' ((Get-Content -LiteralPath (Join-Path $root 'engine\_shared\PIM-FeatureFlags.ps1') -Raw) -match "id = 'downlink'")

# ===========================================================================
Write-Host "`n== 2. THE ENDPOINTS EXIST AND THE GUI CALLS THEM ==" -ForegroundColor Cyan
# ===========================================================================
T 'GET /api/downlink is served' ($srv -match "\`$path -eq '/api/downlink' -and \`$method -eq 'GET'")
T 'PUT /api/downlink/policy is served' ($srv -match "\`$path -eq '/api/downlink/policy' -and \`$method -eq 'PUT'")
T 'POST /api/downlink/run is served' ($srv -match "\`$path -eq '/api/downlink/run' -and \`$method -eq 'POST'")
T 'the GUI GETs /api/downlink' ($html -match "api\('GET', '/api/downlink'\)")
T 'the GUI PUTs the policy' ($html -match "api\('PUT', '/api/downlink/policy'")
T 'the GUI POSTs a run' ($html -match "api\('POST', '/api/downlink/run'")
T 'the Manager dot-sources the downlink library' ($srv -match 'PIM-DownlinkManager\.ps1')

# ===========================================================================
Write-Host "`n== 3. THE SAFETY GATES (this writes privilege into someone else's tenant) ==" -ForegroundColor Cyan
# ===========================================================================
# Slice each handler so a gate present in a NEIGHBOURING handler cannot satisfy the
# assertion -- that is exactly how a missing gate hides in a 9k-line dispatcher.
function Get-Handler([string]$text, [string]$marker) {
    $i = $text.IndexOf($marker); if ($i -lt 0) { return '' }
    $j = $text.IndexOf("`n        if (`$path -eq", $i + 10)
    if ($j -lt 0) { $j = [Math]::Min($text.Length, $i + 4000) }
    return $text.Substring($i, $j - $i)
}
$hPolicy = Get-Handler $srv "'/api/downlink/policy' -and `$method -eq 'PUT'"
$hRun    = Get-Handler $srv "'/api/downlink/run' -and `$method -eq 'POST'"
T 'the policy WRITE requires SuperAdmin' ($hPolicy -match "Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin'")
T '  ...and is audited' ($hPolicy -match "Write-PimManagerAuditEvent -Action 'downlink\.policy\.save'")
T '  ...and REFUSES an unknown Mode rather than coercing it' ($hPolicy -match "invalid Mode" -and $hPolicy -match "return 400")
T 'a real RUN requires SuperAdmin' ($hRun -match "Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin'")
T '  ...but a DRY RUN does not (it changes nothing)' ($hRun -match '-not \$whatIf -and -not \(Test-PimManagerRoleAtLeast')
T '  ...defaulting to whatIf when the caller omits it' ($hRun -match '\$whatIf = \$true')

# ---------------------------------------------------------------------------
# MSP-3: THE MASTER MUST NOT WRITE INTO A MANAGED TENANT.
# An earlier build of this surface did exactly that -- breaking s22 ("MSP never
# writes to a customer tenant") and the pull-not-push tenet, and authenticating as
# the wrong tenant into the bargain. These assertions exist so it cannot come back.
# ---------------------------------------------------------------------------
$dlm = Get-Content -LiteralPath $lib -Raw
T 'MSP-3: an APPLY is REFUSED, not silently downgraded to a preview' ($dlm -match 'REFUSED: the master does not write into a managed tenant')
T '  ...and the refusal explains the pull model instead of just failing' ($dlm -match 'PULLS the signed baseline')
T '  ...so the GUI offers NO apply button at all' (-not ($html -match "class=`"dl-apply`""))
T '  ...and no client handler for one' (-not ($html -match "\.dl-apply"))
T 'MSP-3: the master never reaches into a managed store to WRITE' (-not ($dlm -match 'Invoke-PimDownlinkAdminApply|Invoke-PimDownlinkDefinitionApply|Invoke-PimDownlinkAssignmentApply'))
# Match the CALL, not the word: the file explains at length why it does not pass
# -SlaveGroupTags, and a bare word-match would be satisfied by that explanation.
T '  ...nor to READ (customer data never leaves their tenant)' (-not ($dlm -match "\`$planArgs\['SlaveGroupTags'\]" -or $dlm -match '-SlaveGroupTags '))
T '  ...and it no longer SELECTs a customer store coordinate' (-not ($dlm -match 'SELECT[^;]*StoreServer'))

# The projection policy is DELETE-then-INSERT, and "no rows" means ALLOW ALL -- so a
# half-applied write would silently WIDEN privilege. It must be one transaction.
T 'the policy write is transactional (a failure must not leave allow-all)' ($dlm -match 'BeginTransaction' -and $dlm -match 'Rollback')
T '  ...and validates BEFORE writing anything' ($dlm -match 'nothing was written')
T 'the baseline banner reports a REAL verification, not a hardcoded true' ($dlm -match 'Test-PimDownlinkBaseline -Doc \$bl\.doc')

# ===========================================================================
Write-Host "`n== 4. THE GUI RENDERS THE PLAN -- it must not form a second opinion ==" -ForegroundColor Cyan
# ===========================================================================
# The projection is decided server-side from the SIGNED bundle. If the browser
# re-derived it, the preview and the apply could disagree about who holds privilege.
T 'the view states the no-recompute rule' ($html -match 'NEVER RECOMPUTES')
T 'no client-side ring filtering' (-not ($html -match 'renderDownlink[\s\S]{0,6000}?Ring\s*<=' ))
T 'no client-side allow/deny evaluation' (-not ($html -match "renderDownlink[\s\S]{0,6000}?Mode === 'deny' \?\?"))
T 'excluded and unresolved are shown SEPARATELY (they mean different things)' ($html -match 'Held back' -and $html -match 'the role cannot be granted here')

# ===========================================================================
Write-Host "`n== 5. THE PURE HELPERS ==" -ForegroundColor Cyan
# ===========================================================================
T 'the downlink-manager library exists' (Test-Path -LiteralPath $lib)
$e = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($lib, [ref]$null, [ref]$e)
T '  ...and parses clean under this PowerShell' (@($e).Count -eq 0)
. $lib
foreach ($fn in @('Get-PimManagerDownlinkTenants','Get-PimManagerDownlinkPolicy','Set-PimManagerDownlinkPolicy','Get-PimManagerBaselineDoc','Get-PimManagerDownlinkOverview','Invoke-PimManagerDownlinkRun')) {
    T "  ...defines $fn" ([bool](Get-Command $fn -ErrorAction SilentlyContinue))
}

# A missing baseline must be REPORTED, never silently treated as "nothing projects" --
# those two states look identical in the GUI and mean opposite things.
$blMissing = Get-PimManagerBaselineDoc -Path (Join-Path $env:TEMP ('no-such-baseline-' + [guid]::NewGuid().ToString('N') + '.json'))
T 'a MISSING baseline is reported, not treated as an empty projection' ($null -eq $blMissing.doc -and "$($blMissing.error)" -match 'not found')
$blBad = Join-Path $env:TEMP ('bad-baseline-' + [guid]::NewGuid().ToString('N') + '.json')
Set-Content -LiteralPath $blBad -Value 'not json at all' -Encoding ascii
try {
    $r = Get-PimManagerBaselineDoc -Path $blBad
    T 'a CORRUPT baseline is reported, not swallowed' ($null -eq $r.doc -and "$($r.error)" -match 'not valid JSON')
} finally { Remove-Item -LiteralPath $blBad -Force -ErrorAction SilentlyContinue }

# The preview is honest about being a preview -- it must not read as a completed sync.
T 'the preview says plainly that nothing was written' ($dlm -match 'nothing was written')
T '  ...and reports what would be OFFERED, not what was applied' ($dlm -match 'admins offered' -and $dlm -match 'roles offered')

Write-Host ""
Write-Host ("==== Downlink GUI test: {0} passed, {1} failed ====" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 } else { exit 0 }
