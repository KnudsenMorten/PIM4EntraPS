<#
  Offline tests for the Conformance ACTIVE-EXEMPTIONS REGISTER + revoke
  (engine/_shared/PIM-Conformance.ps1 -- REQUIREMENTS §28 [L2] / §17).

  Background: exemptions were write-only (POST /api/conformance/exemptions, raw
  prompt() in the GUI) -- no way to see what waivers exist, when they lapse, or
  end one early, so they accumulated invisibly. This proves the new reviewable
  register + revoke:

    * Get-PimExemptionList classifies every stored waiver Active / Expiring (in
      the warn window) / Expired / Invalid, with days-left + a stable RevokeKey;
    * the list is tenant/template scoped and soonest-to-lapse first (Invalid last);
    * Get-PimExemptionSummary counts each state (Expiring counts as Active too);
    * Get-PimExemptionRevokeKey is stable + distinguishes re-issued (new-expiry) rows;
    * Remove-PimExemptionEntry removes exactly the keyed row, is idempotent on an
      unknown key, never mutates the input, and refuses an empty key (can't wipe).

  PURE -- no network, clock injected (NowUtc), in-memory exemption objects.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
. "$here\..\engine\_shared\PIM-Conformance.ps1"

$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }

$now = ([datetime]'2026-06-16T12:00:00Z').ToUniversalTime()
Write-Host "=== PIM-ExemptionRegister tests ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Seed a register with one of each state for the SAME instance ('local'):
#   active   -> expires +120d            -> Active
#   soon     -> expires +10d (<=30 warn) -> Expiring
#   gone     -> expired -5d              -> Expired
#   bad      -> no expiry                -> Invalid
# Plus a row for a DIFFERENT instance (must be filtered out by TenantId), and a
# row for a different template (filtered by TemplateId).
# ---------------------------------------------------------------------------
$store = @(
    [pscustomobject]@{ tenantId='local'; templateId='defender-xdr-roles'; itemKey='role:Active';   reason='r-active'; approvedBy='ops'; approvedUtc='2026-06-01T00:00:00Z'; expiresUtc=$now.AddDays(120).ToString('o') }
    [pscustomobject]@{ tenantId='local'; templateId='defender-xdr-roles'; itemKey='role:Soon';     reason='r-soon';   approvedBy='ops'; approvedUtc='2026-06-01T00:00:00Z'; expiresUtc=$now.AddDays(10).ToString('o') }
    [pscustomobject]@{ tenantId='local'; templateId='defender-xdr-roles'; itemKey='role:Gone';     reason='r-gone';   approvedBy='ops'; approvedUtc='2026-05-01T00:00:00Z'; expiresUtc=$now.AddDays(-5).ToString('o') }
    [pscustomobject]@{ tenantId='local'; templateId='defender-xdr-roles'; itemKey='role:Bad';      reason='r-bad';    approvedBy='ops'; approvedUtc='2026-06-01T00:00:00Z'; expiresUtc='' }
    [pscustomobject]@{ tenantId='other'; templateId='defender-xdr-roles'; itemKey='role:Other';    reason='r-other';  approvedBy='ops'; approvedUtc='2026-06-01T00:00:00Z'; expiresUtc=$now.AddDays(50).ToString('o') }
    [pscustomobject]@{ tenantId='local'; templateId='intune-roles';       itemKey='role:OtherTpl'; reason='r-otpl';   approvedBy='ops'; approvedUtc='2026-06-01T00:00:00Z'; expiresUtc=$now.AddDays(50).ToString('o') }
)

# --- Get-PimExemptionList: scope + state classification --------------------
$list = @(Get-PimExemptionList -Exemptions $store -TenantId 'local' -TemplateId 'defender-xdr-roles' -NowUtc $now -WarningAction SilentlyContinue)
Assert "list is tenant+template scoped (4 rows, others excluded)" ($list.Count -eq 4)
Assert "no 'other' instance row leaked"  (-not ($list | Where-Object { $_.ItemKey -eq 'role:Other' }))
Assert "no other-template row leaked"    (-not ($list | Where-Object { $_.ItemKey -eq 'role:OtherTpl' }))

$byKey = @{}; foreach ($r in $list) { $byKey[$r.ItemKey] = $r }
Assert "Active row classified Active"        ($byKey['role:Active'].State -eq 'Active')
Assert "Active row Active flag true"         ($byKey['role:Active'].Active -eq $true)
Assert "Active row days-left ~120"           ($byKey['role:Active'].DaysLeft -ge 119 -and $byKey['role:Active'].DaysLeft -le 120)
Assert "Soon row classified Expiring"        ($byKey['role:Soon'].State -eq 'Expiring')
Assert "Expiring still counts as Active"     ($byKey['role:Soon'].Active -eq $true)
Assert "Soon row days-left ~10"              ($byKey['role:Soon'].DaysLeft -ge 9 -and $byKey['role:Soon'].DaysLeft -le 10)
Assert "Gone row classified Expired"         ($byKey['role:Gone'].State -eq 'Expired')
Assert "Expired row Active flag false"       ($byKey['role:Gone'].Active -eq $false)
Assert "Expired row days-left negative"      ($byKey['role:Gone'].DaysLeft -lt 0)
Assert "Bad row classified Invalid"          ($byKey['role:Bad'].State -eq 'Invalid')
Assert "Invalid row days-left is null"       ($null -eq $byKey['role:Bad'].DaysLeft)
Assert "every row carries a RevokeKey"       (-not ($list | Where-Object { -not $_.RevokeKey }))

# --- sort order: soonest-to-lapse first, Invalid last ----------------------
Assert "first row is the most-expired (Gone)" ($list[0].ItemKey -eq 'role:Gone')
Assert "second row is Expiring soon (Soon)"   ($list[1].ItemKey -eq 'role:Soon')
Assert "Active before Invalid"                ($list[2].ItemKey -eq 'role:Active')
Assert "Invalid row sorts last"               ($list[3].ItemKey -eq 'role:Bad')

# --- configurable warn window ----------------------------------------------
$tight = @(Get-PimExemptionList -Exemptions $store -TenantId 'local' -TemplateId 'defender-xdr-roles' -NowUtc $now -ExpiringWithinDays 5 -WarningAction SilentlyContinue)
$soonT = $tight | Where-Object { $_.ItemKey -eq 'role:Soon' }
Assert "Soon (+10d) is Active when warn window is 5d" ($soonT.State -eq 'Active')

# --- unscoped list (all instances/templates) -------------------------------
$all = @(Get-PimExemptionList -Exemptions $store -NowUtc $now -WarningAction SilentlyContinue)
Assert "unscoped list returns every row (6)" ($all.Count -eq 6)

# --- Get-PimExemptionSummary ------------------------------------------------
$sum = Get-PimExemptionSummary -List $list
Assert "summary Total = 4"     ($sum.Total -eq 4)
Assert "summary Active = 2"    ($sum.Active -eq 2)     # Active + Expiring
Assert "summary Expiring = 1"  ($sum.Expiring -eq 1)
Assert "summary Expired = 1"   ($sum.Expired -eq 1)
Assert "summary Invalid = 1"   ($sum.Invalid -eq 1)
$emptySum = Get-PimExemptionSummary -List @()
Assert "empty summary Total = 0" ($emptySum.Total -eq 0)

# --- Get-PimExemptionRevokeKey: stable + distinguishes re-issued ------------
$k1 = Get-PimExemptionRevokeKey -Exemption $store[0]
$k1b = Get-PimExemptionRevokeKey -Exemption $store[0]
Assert "revoke key is deterministic" ($k1 -eq $k1b)
$reissued = [pscustomobject]@{ tenantId='local'; templateId='defender-xdr-roles'; itemKey='role:Active'; expiresUtc=$now.AddDays(200).ToString('o') }
Assert "re-issued (new expiry) gets a different revoke key" ((Get-PimExemptionRevokeKey -Exemption $reissued) -ne $k1)

# --- Remove-PimExemptionEntry: precise, idempotent, non-mutating, guarded ----
$soonKey = $byKey['role:Soon'].RevokeKey
$before = $store.Count
$res = Remove-PimExemptionEntry -Exemptions $store -RevokeKey $soonKey
Assert "revoke removed exactly 1"               ($res.Removed -eq 1)
Assert "kept set has one fewer row"             ($res.Kept.Count -eq ($before - 1))
Assert "the revoked item is gone from kept"     (-not ($res.Kept | Where-Object { $_.itemKey -eq 'role:Soon' }))
Assert "an untouched row survives"              ([bool]($res.Kept | Where-Object { $_.itemKey -eq 'role:Active' }))
Assert "input array NOT mutated"                ($store.Count -eq $before)

$noop = Remove-PimExemptionEntry -Exemptions $store -RevokeKey 'local|defender-xdr-roles|role:DoesNotExist|x'
Assert "unknown key is an idempotent no-op (0 removed)" ($noop.Removed -eq 0)
Assert "unknown key keeps the full set"                 ($noop.Kept.Count -eq $before)

$threw = $false
try { Remove-PimExemptionEntry -Exemptions $store -RevokeKey '   ' } catch { $threw = $true }
Assert "blank revoke key is refused (can't wipe the set)" $threw

# --- empty register is a clean empty list/summary, not an error ------------
$none = @(Get-PimExemptionList -Exemptions @() -TenantId 'local' -NowUtc $now)
Assert "empty store -> empty list" ($none.Count -eq 0)

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 } else { exit 0 }
