#Requires -Version 5.1
<#
.SYNOPSIS
  SEC-14 -- find TEST-HARNESS objects left behind in a tenant. READ-ONLY. Deletes nothing.

.DESCRIPTION
  On 2026-06-14 a live marker harness ran against the PRODUCTION tenant and left
  332 groups + 16 administrative units holding 240 Entra directory-role assignments --
  Global Administrator among them -- for 77 DAYS. Nothing detected it. The operator found it
  by not recognising a group name in his own tenant.

  🔑 WHY NO EXISTING CHECK COULD HAVE FOUND IT, and the rule this tool is built on:
  the marker is a PREFIX, so `PIMCOREENGINE-PIM-...` never matches the operator's own
  `PIM-*` filters. That invisibility is exactly what made the harness SAFE while it ran --
  real PIM- groups were never touched -- and exactly what HID the debris afterwards. Drift
  could not see the objects, the display-name resolver could not resolve them, the delegation
  map did not list them.
  ⇒ A sweep for them MUST look OUTSIDE the configured filters. Anything filter-based is
    structurally incapable of finding this, which is why it is a separate tool and not another
    rule inside the engine's reconcile.

  Reports groups, administrative units, and -- because that is where the actual risk lives --
  the DIRECTORY ROLES those objects hold, plus their members and owners:
    * members  = who holds the privilege RIGHT NOW (active exposure)
    * owners   = who can GRANT it to themselves without passing through PIM (latent exposure;
                 this was the real finding in SEC-14, where the role-holding groups were empty
                 but every one of them had an owner)

.PARAMETER Marker
  Object-name prefix to hunt for. Defaults to every marker this repo's harnesses use.

.PARAMETER FailIfFound
  Exit 3 when anything is found, so a scheduled run surfaces as a failure instead of a log
  nobody reads. Default is exit 0 (report-only), so the tool is safe to run anywhere.

.EXAMPLE
  .\Find-PimStrayTestObjects.ps1
  .\Find-PimStrayTestObjects.ps1 -FailIfFound       # for the scheduled/CI run

.NOTES
  READ-ONLY BY CONSTRUCTION -- it issues GETs only. Cleanup is a separate, deliberate act:
  tests\live\Manage-PimCoreEngineTest.ps1 -Cleanup. Detection and deletion are kept apart on
  purpose: a sweep that could delete would eventually be run by someone who meant only to look.
#>
[CmdletBinding()]
param(
    [string[]]$Marker = @('PIMCOREENGINE-', 'PIMTEST-'),
    [switch]$FailIfFound
)
$ErrorActionPreference = 'Stop'
$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)   # tools\setup -> tools -> <solution root>
. (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1')

function Line($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }

Line "=== SEC-14 stray test-object sweep (READ-ONLY) ===" 'Cyan'
Line ("  markers: {0}" -f ($Marker -join ', ')) 'DarkGray'
Line ("  tenant : {0}" -f "$($global:PIM_TenantId)") 'DarkGray'
if (-not "$($global:PIM_TenantId)".Trim()) {
    Line '  no tenant context ($global:PIM_TenantId) -- connect first. Nothing scanned.' 'Yellow'
    exit 0
}

$groups = New-Object System.Collections.Generic.List[object]
$aus    = New-Object System.Collections.Generic.List[object]
foreach ($m in $Marker) {
    $f = [uri]::EscapeDataString("startswith(displayName,'$m')")
    try {
        foreach ($g in @(Invoke-PimGraph -Path "/groups?`$filter=$f&`$select=id,displayName,createdDateTime,isAssignableToRole&`$top=999" -All)) { $groups.Add($g) }
    } catch { Line "  ! group query failed for '$m': $($_.Exception.Message)" 'Red' }
    try {
        foreach ($a in @(Invoke-PimGraph -Path "/directory/administrativeUnits?`$select=id,displayName&`$top=999" -All | Where-Object { "$($_.displayName)" -like "$m*" })) { $aus.Add($a) }
    } catch { Line "  ! AU query failed for '$m': $($_.Exception.Message)" 'Red' }
}

if ($groups.Count -eq 0 -and $aus.Count -eq 0) {
    Line "`n  CLEAN -- no marker-prefixed groups or administrative units in this tenant." 'Green'
    exit 0
}

Line ("`n  FOUND: {0} group(s), {1} administrative unit(s)" -f $groups.Count, $aus.Count) 'Red'
$roleAssignable = @($groups | Where-Object { $_.isAssignableToRole })
Line ("  of those groups, {0} are ROLE-ASSIGNABLE" -f $roleAssignable.Count) $(if ($roleAssignable.Count) { 'Red' } else { 'DarkGray' })
$groups | Group-Object { ("$($_.createdDateTime)" -split 'T')[0] } | Sort-Object Name |
    ForEach-Object { Line ("    created {0}: {1} group(s)" -f $_.Name, $_.Count) 'DarkGray' }

# ---- the privilege these objects actually hold ------------------------------------------
$byId = @{}; foreach ($g in $groups) { $byId["$($g.id)"] = "$($g.displayName)" }
$held = @()
try {
    $ra = @(Invoke-PimGraph -Path "/roleManagement/directory/roleAssignments?`$expand=roleDefinition(`$select=displayName)&`$top=999" -All)
    $held = @($ra | Where-Object { $byId.ContainsKey("$($_.principalId)") })
} catch { Line "  ! role-assignment query failed: $($_.Exception.Message)" 'Red' }
Line ("`n  DIRECTORY ROLES held by these objects: {0} assignment(s)" -f $held.Count) $(if ($held.Count) { 'Red' } else { 'Green' })
$held | Group-Object { "$($_.roleDefinition.displayName)" } | Sort-Object Count -Descending |
    Select-Object -First 15 | ForEach-Object { Line ("    {0,4}x  {1}" -f $_.Count, $_.Name) 'Yellow' }

# ---- who can USE that privilege, now or by helping themselves to it ----------------------
$withMembers = 0; $withOwners = 0; $memberEdges = 0; $ownerEdges = 0
foreach ($g in $groups) {
    $mm = @(); $oo = @()
    try { $mm = @(Invoke-PimGraph -Path "/groups/$($g.id)/members?`$select=id,userPrincipalName,displayName&`$top=999" -All) } catch {}
    try { $oo = @(Invoke-PimGraph -Path "/groups/$($g.id)/owners?`$select=id,userPrincipalName,displayName&`$top=999" -All) } catch {}
    $memberEdges += $mm.Count; $ownerEdges += $oo.Count
    if ($mm.Count) { $withMembers++ }
    if ($oo.Count) { $withOwners++ }
}
Line ("`n  EXPOSURE") 'Cyan'
Line ("    groups with MEMBERS : {0} of {1}  ({2} edge(s))  <- privilege held RIGHT NOW" -f $withMembers, $groups.Count, $memberEdges) $(if ($withMembers) { 'Red' } else { 'Green' })
Line ("    groups with OWNERS  : {0} of {1}  ({2} edge(s))  <- can ADD a member and take the" -f $withOwners, $groups.Count, $ownerEdges) $(if ($withOwners) { 'Yellow' } else { 'Green' })
Line ("                          privilege WITHOUT passing through PIM's approval flow") 'DarkGray'
Line ("`n  Nothing was changed. Cleanup is deliberate and separate:") 'DarkGray'
Line ("    tests\live\Manage-PimCoreEngineTest.ps1 -Cleanup   (deletes ONLY marker-prefixed objects)") 'DarkGray'

if ($FailIfFound) { exit 3 }
exit 0
