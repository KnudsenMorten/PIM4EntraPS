#Requires -Version 5.1
<#
.SYNOPSIS
    Governance PREVIEW gate -- "show the surface, safely OFF" for the two security-
    sensitive governance surfaces (s27 approval-gated offboarding/revoke; s28 [L2]
    active-exemptions register on Template Rollout). Proves: both default OFF; the
    surface stays VISIBLE but renders a disabled/preview banner; the mutating
    endpoints short-circuit (409) while off; the underlying safety gates are never
    touched; a persisted override flips a preview on; GUI state == endpoint behaviour.

.DESCRIPTION
    Two layers, both OFFLINE (no live tenant, no server boot, no SQL):

      1. PURE catalog + resolver over the REAL shared lib
         (engine/_shared/PIM-GovernancePreview.ps1): both previews default OFF; a
         persisted override flips one on; an unknown key is ignored (+ warned); the
         minimal-override reduction (a default install stores {} and stays OFF);
         JSON-string + PSCustomObject + hashtable store shapes; anyEnabled;
         Test-PimGovernancePreviewEnabled (known on/off + unknown id fail-safe).

      2. STATIC GUI / SERVER wiring (no dead view, GUI == behaviour): the html bakes
         __PIM_GOVPREVIEW__ at boot + reads it; renderApprovals + renderConformance
         short-circuit to the preview banner while disabled; the Settings tab renders
         a Governance-preview card with a save; the server dot-sources the lib, routes
         GET/PUT /api/settings/governance-preview (SuperAdmin write), the request-time
         guard (Test-PimGovernancePreviewBlocked) exists, is wired into BOTH the
         approvals mutating endpoints AND the conformance mutating endpoints, and BOTH
         html injection sites bake the boot value.

    Run standalone (exits 0 green / 1 red) or via Run-AllPimTests.ps1 / PIM.Tests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
$root  = Split-Path -Parent $here
$lib   = Join-Path $root 'engine\_shared\PIM-GovernancePreview.ps1'
$mgr   = Join-Path $root 'tools\pim-manager\Open-PimManager.ps1'
$html  = Join-Path $root 'tools\pim-manager\pim-manager.html'

Write-Host "=== PIM-GovernancePreview (show the surface, safely OFF) ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. PURE resolver
# ---------------------------------------------------------------------------
T "lib exists" (Test-Path -LiteralPath $lib)
. $lib

# defaults: both previews OFF on an empty/null store
$d = Resolve-PimGovernancePreview -Raw $null
T "default approvalsPreview OFF"   ($d.flags['approvalsPreview'] -eq $false)
T "default conformancePreview OFF" ($d.flags['conformancePreview'] -eq $false)
T "default anyEnabled false"       ($d.anyEnabled -eq $false)
T "catalog has both surfaces"      (@($d.catalog).Count -eq 2)
T "catalog defaults are OFF"       (-not (@($d.catalog) | Where-Object { $_.default }))
T "no warnings on empty store"     (@($d.warnings).Count -eq 0)

# a persisted override flips ONE preview on (hashtable shape)
$o = Resolve-PimGovernancePreview -Raw @{ flags = @{ approvalsPreview = $true } }
T "override flips approvals on"    ($o.flags['approvalsPreview'] -eq $true)
T "untouched stays off"           ($o.flags['conformancePreview'] -eq $false)
T "anyEnabled true with one on"   ($o.anyEnabled -eq $true)

# JSON-string store shape (the SQL/file round-trip), flat map accepted too
$j = Resolve-PimGovernancePreview -Raw '{"flags":{"conformancePreview":true}}'
T "JSON-string conformance on"    ($j.flags['conformancePreview'] -eq $true)
$flat = Resolve-PimGovernancePreview -Raw @{ approvalsPreview = 'on' }
T "flat map + string truthy"      ($flat.flags['approvalsPreview'] -eq $true)

# PSCustomObject store shape (the JSON-parsed round-trip)
$psobj = [pscustomobject]@{ flags = [pscustomobject]@{ approvalsPreview = $true } }
$pp = Resolve-PimGovernancePreview -Raw $psobj
T "PSCustomObject shape read"     ($pp.flags['approvalsPreview'] -eq $true)

# garbage JSON falls back to defaults + warns (never throws)
$g = Resolve-PimGovernancePreview -Raw '{not json'
T "garbage JSON -> defaults OFF"  ($g.flags['approvalsPreview'] -eq $false -and $g.flags['conformancePreview'] -eq $false)
T "garbage JSON warns"            (@($g.warnings).Count -ge 1)

# unknown key ignored (+ warned), known key alongside still applies
$u = Resolve-PimGovernancePreview -Raw @{ flags = @{ approvalsPreview = $true; bogusFlag = $true } }
T "unknown key not added"         (-not $u.flags.Contains('bogusFlag'))
T "unknown key warns"             (@($u.warnings | Where-Object { $_ -match 'bogusFlag' }).Count -ge 1)
T "known key still applied"       ($u.flags['approvalsPreview'] -eq $true)

# minimal-override reduction: default install stores {} (stays OFF)
$min0 = ConvertTo-PimGovernancePreviewOverrides -Raw @{ flags = @{ approvalsPreview = $false; conformancePreview = $false } }
T "all-default reduces to empty"  ($min0.Count -eq 0)
$min1 = ConvertTo-PimGovernancePreviewOverrides -Raw @{ flags = @{ approvalsPreview = $true; conformancePreview = $false } }
T "only non-default persisted"    ($min1.Count -eq 1 -and $min1['approvalsPreview'] -eq $true)

# Test-PimGovernancePreviewEnabled: known on/off + unknown fail-safe
T "enabled predicate: on"         (Test-PimGovernancePreviewEnabled -Resolved $o -Id 'approvalsPreview')
T "enabled predicate: off"        (-not (Test-PimGovernancePreviewEnabled -Resolved $d -Id 'approvalsPreview'))
T "enabled predicate: unknown=off" (-not (Test-PimGovernancePreviewEnabled -Resolved $d -Id 'noSuchPreview'))

# ---------------------------------------------------------------------------
# 2. STATIC GUI / SERVER wiring
# ---------------------------------------------------------------------------
T "Manager script exists" (Test-Path -LiteralPath $mgr)
T "html exists"           (Test-Path -LiteralPath $html)
$m = Get-Content -LiteralPath $mgr -Raw
$h = Get-Content -LiteralPath $html -Raw

# server dot-sources the lib + has the wrappers + the request-time guard
T "server dot-sources the lib"        ($m -match 'PIM-GovernancePreview\.ps1')
T "Get-PimGovernancePreview wrapper"  ($m -match 'function Get-PimGovernancePreview')
T "Set-PimGovernancePreview wrapper"  ($m -match 'function Set-PimGovernancePreview')
T "request-time guard defined"        ($m -match 'function Test-PimGovernancePreviewBlocked')
T "guard returns 409 preview marker"  ($m -match 'previewDisabled\s*=\s*\$true')

# settings endpoint routed GET + PUT (PUT SuperAdmin-gated)
T "settings GET routed"   ($m -match "path -eq '/api/settings/governance-preview' -and \`$method -eq 'GET'")
T "settings PUT routed"   ($m -match "path -eq '/api/settings/governance-preview' -and \`$method -eq 'PUT'")
$putBlock = ''
$pi = $m.IndexOf("/api/settings/governance-preview' -and `$method -eq 'PUT'")
if ($pi -ge 0) { $putBlock = $m.Substring($pi, [Math]::Min(400, $m.Length - $pi)) }
T "PUT is SuperAdmin-gated" ($putBlock -match "Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin'")
T "PUT audited"            ($m -match "settings\.governance-preview\.save")

# guard wired into the approvals mutating endpoints (POST/decide/execute)
$apprGuards = ([regex]::Matches($m, "Test-PimGovernancePreviewBlocked -Response \`$resp -FlagId 'approvalsPreview'")).Count
T "approvals endpoints guarded (>=3)" ($apprGuards -ge 3)
# guard wired into the conformance mutating endpoints (grant/revoke/approve/deploy)
$confGuards = ([regex]::Matches($m, "Test-PimGovernancePreviewBlocked -Response \`$resp -FlagId 'conformancePreview'")).Count
T "conformance endpoints guarded (>=4)" ($confGuards -ge 4)

# BOTH html injection sites bake the boot value
$injects = ([regex]::Matches($m, "__PIM_GOVPREVIEW__")).Count
T "boot value injected at both sites (>=2)" ($injects -ge 2)

# html: boot read + banner helpers + preview short-circuit in both render fns
T "html boot placeholder present"  ($h -match 'window\.PIM_GOVPREVIEW_BOOT = __PIM_GOVPREVIEW__')
T "html reads the boot map"        ($h -match 'PIM_GOVPREVIEW_BOOT')
T "isGovernancePreviewDisabled fn" ($h -match 'function isGovernancePreviewDisabled')
T "governancePreviewBanner fn"     ($h -match 'function governancePreviewBanner')
T "banner marks preview disabled"  ($h -match 'data-preview="disabled"')
T "banner has the disabled text"   ($h -match 'Preview &mdash; disabled in Settings')

# renderApprovals short-circuits to the banner while disabled
$ra = ''
$rai = $h.IndexOf('async function renderApprovals()')
if ($rai -ge 0) { $ra = $h.Substring($rai, [Math]::Min(1000, $h.Length - $rai)) }
T "renderApprovals checks preview"  ($ra -match "isGovernancePreviewDisabled\('approvals'\)")
T "renderApprovals shows banner"    ($ra -match 'governancePreviewBanner')

# renderConformance short-circuits to the banner while disabled
$rc = ''
$rci = $h.IndexOf('async function renderConformance()')
if ($rci -ge 0) { $rc = $h.Substring($rci, [Math]::Min(700, $h.Length - $rci)) }
T "renderConformance checks preview" ($rc -match "isGovernancePreviewDisabled\('conformance'\)")
T "renderConformance shows banner"   ($rc -match 'governancePreviewBanner')

# Settings tab renders the Governance-preview card + render fn + save wiring
T "Settings card host present"   ($h -match 'setGovPreviewBody')
T "renderGovPreviewCard fn"      ($h -match 'function renderGovPreviewCard')
T "card invoked in renderSettings" ($h -match 'renderGovPreviewCard\(canEdit\)')
T "card GETs the endpoint"       ($h -match "api\('GET', '/api/settings/governance-preview'\)")
T "card PUTs the endpoint"       ($h -match "api\('PUT', '/api/settings/governance-preview'")

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 } else { exit 0 }
