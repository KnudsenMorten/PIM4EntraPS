#Requires -Version 5.1

<#
.SYNOPSIS
  Moves each PIM Manager app and job of one install from its current identity (system-assigned, or a shared user-assigned identity) to its own user-assigned identity id-pim-<role>, with the same rights, proven, and only then removes the old identity's copied rights.

.DESCRIPTION
  NAM-03 (framework 12.11c item 3 + CR8). Without -Apply the script only PLANS (read-only): per role the apps / jobs, the
  identity each signs in with today, the target id-pim-<role> and whether it exists, every right to copy (Graph application
  roles, PIM group memberships, directory roles, Azure role assignments at every scope -- Key Vault RBAC and AcrPull among
  them -- Key Vault access policies, the database user) and the settings that name the identity (registry pull identity,
  Key Vault secret references, PIM_ManagedIdentityClientId, every env value equal to an old client id).

  With -Apply -Role <role>[,<role>] it moves those roles, in this order, each step read back before the next:
    identity -> Graph app roles + PIM groups + directory roles -> Azure role assignments -> Key Vault access policies ->
    database user (the in-network database job) -> attach + switch the settings on each app / job -> PROOF (the web app's
    new revision healthy and signing in as the new identity; the engine: one tick run Succeeded; another job: its next run
    after the switch) -> only then the old identity's copied rights are removed (a system-assigned identity stays enabled
    with its rights stripped; a shared user-assigned identity is detached from the app, and its rights go only when nothing
    in the group still uses it).
  A failure at any step stops the run and writes a rollback record (everything done, in order, with the exact undo command).
  A right at the tenant root where the Support app has no root User Access Administrator is a CUSTOMER step (the exact
  command is printed); the role does not switch until it reads back. -WhatIf writes nothing.

  Run it in a PowerShell session connected to the install's tenant through the Invardia Support app (its REST context).
  Never touches an identity, app or group that is not PIM's own.

.PARAMETER SubscriptionId
  The subscription of the PIM install.
.PARAMETER ResourceGroup
  The resource group of the PIM install (its container apps, jobs and identities).
.PARAMETER TenantId
  The tenant id (names the tenant root management group). Default: the session's.
.PARAMETER Apply
  Move the roles in -Role. Without it the script only plans.
.PARAMETER Role
  The roles to move with -Apply: web, engine, updater, downlink, publish, requests, mcp, dbinit, asbuilt.
.PARAMETER SupportHasRootAccess
  The Support app holds User Access Administrator at the tenant root of this install. Without it every root right is a
  customer step.
.PARAMETER ExtraScopes
  More scopes to read the old identity's Azure roles at (for example a registry outside the subscription).
.PARAMETER PimGroupNames
  More PIM group names whose membership moves (grp-pim-* always does).
.PARAMETER StartJobRoles
  The roles whose job the script starts once for the proof. Default: engine (one tick).
.PARAMETER NoCleanup
  Stop after the proof; the old rights stay (a later run without it removes them).
.PARAMETER LogDir
  Where the plan and the per-role records are written as JSON.

.EXAMPLE
  .\Move-PimIdentities.ps1 -SubscriptionId <sub> -ResourceGroup <rg>
.EXAMPLE
  .\Move-PimIdentities.ps1 -SubscriptionId <sub> -ResourceGroup <rg> -SupportHasRootAccess -Apply -Role web -LogDir C:\temp\move

.NOTES
  Requirements:
    PowerShell: 5.1 or 7.
    Role: the Invardia Support app (AppRoleAssignment.ReadWrite.All, RoleManagement.ReadWrite.Directory, GroupMember.ReadWrite.All; Contributor + User Access Administrator at the PIM subscription).
    Hosts: management.azure.com, graph.microsoft.com, login.microsoftonline.com

.LINK
  https://invardia.com/docs/pim/scripts/Move-PimIdentities/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$TenantId = '',
    [switch]$Apply,
    [ValidateSet('web', 'engine', 'updater', 'downlink', 'publish', 'requests', 'mcp', 'dbinit', 'asbuilt')][string[]]$Role = @(),
    [switch]$SupportHasRootAccess,
    [string[]]$ExtraScopes = @(),
    [string[]]$PimGroupNames = @(),
    [string[]]$StartJobRoles = @('engine'),
    [switch]$NoCleanup,
    [string]$LogDir = '',
    # TEST seams (tests\Test-PimIdentityMove.ps1): replace ARM / Graph / the database job / the proof / the wait
    [scriptblock]$Arm,
    [scriptblock]$Graph,
    [scriptblock]$DbInit,
    [scriptblock]$Prove,
    [scriptblock]$Sleep
)
$ErrorActionPreference = 'Stop'
$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)   # tools\setup -> tools -> <solution root>
. (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-IdentitySplit.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-IdentityMove.ps1')
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Move-PimIdentities'
try {
    function Say($m, $c = 'Gray') { Write-Host $m -ForegroundColor $c }
    $dry = [bool]$WhatIfPreference
    if (-not $Arm)   { $Arm   = { param($m, $p, $b) if ($null -ne $b) { Invoke-PimArm -Method $m -Path $p -Body $b } else { Invoke-PimArm -Method $m -Path $p } } }
    if (-not $Graph) { $Graph = { param($m, $p, $b) if ($null -ne $b) { Invoke-PimGraph -Method $m -Path $p -Body $b } else { Invoke-PimGraph -Method $m -Path $p } } }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    $tid = if ("$TenantId".Trim()) { "$TenantId".Trim() } else { "$($global:PIM_TenantId)".Trim() }
    if (-not "$LogDir".Trim()) { $LogDir = Join-Path ([IO.Path]::GetTempPath()) 'pim-identity-move' }
    if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
    $stamp = [datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')
    # the SQL access catalog (the database roles of each role's user), when it loads
    try { . (Join-Path $solRoot 'engine\_shared\PIM-SqlAccess.ps1') } catch { Say "  (the SQL access catalog did not load: $($_.Exception.Message) -- the built-in role list is used)" 'DarkGray' }

    Say "=== NAM-03 identity move: $ResourceGroup ($(if ($Apply) { if ($dry) { 'APPLY, What if' } else { 'APPLY ' + ($Role -join ', ') } } else { 'PLAN, read-only' })) ===" 'Cyan'
    Say "  subscription $SubscriptionId  tenant $(if ($tid) { $tid } else { '(not known: root scopes read as / only)' })  root access for the Support app: $(if ($SupportHasRootAccess) { 'yes' } else { 'NO -- root rights are customer steps' })" 'DarkGray'
    if ($Apply -and -not @($Role).Count) { throw '-Apply needs -Role (one role at a time is the agreed way: web, engine, updater, ...)' }

    $plan = Get-PimIdentityMovePlan -Arm $Arm -Graph $Graph -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -TenantId $tid `
                -SupportHasRootAccess:$SupportHasRootAccess -ExtraScopes $ExtraScopes -PimGroupNames $PimGroupNames
    foreach ($mvRp in @($plan.roles)) {
        Say ''
        Say ("[{0}] {1} -> {2}{3}" -f $mvRp.state, $mvRp.role, $mvRp.target, $(if ($mvRp.targetExists) { ' (exists)' } else { ' (to create)' })) $(if ($mvRp.state -eq 'ok') { 'Green' } else { 'White' })
        foreach ($mvRes in @($mvRp.resources)) {
            Say ("    {0} ({1}) signs in as: {2}" -f $mvRes.resource, $mvRes.kind, $(if ($mvRes.signsInAsTarget) { $mvRes.target } elseif ($mvRes.currentClientId) { "client id $($mvRes.currentClientId)" } else { 'the system-assigned identity' })) 'Gray'
            foreach ($mvSrc in @($mvRes.sources)) { Say "      old identity: $($mvSrc.name) ($($mvSrc.kind))" 'DarkGray' }
            foreach ($mvIgn in @($mvRes.ignored)) { Say "      not PIM's, never touched: $mvIgn" 'DarkGray' }
            foreach ($mvSet in @($mvRes.settings)) { Say "      setting to switch: $($mvSet.where) $($mvSet.name)" 'DarkGray' }
        }
        $mvTc = $mvRp.toCopy
        Say ("    to copy: {0} app role(s), {1} PIM group(s), {2} directory role(s), {3} Azure role(s), {4} Key Vault access polic(ies){5}" -f @($mvTc.graph).Count, @($mvTc.groups).Count, @($mvTc.dirRoles).Count, @($mvTc.azure).Count, @($mvTc.kv).Count, $(if ($mvRp.sql.needed) { ", database user $($mvRp.sql.user) ($(@($mvRp.sql.roles) -join ', ')) via $(if ($mvRp.sql.job) { $mvRp.sql.job } else { 'the database job -- NOT ON THIS INSTALL' })" } else { '' })) 'Gray'
        foreach ($mvAz in @($mvTc.azure)) { Say "      Azure: $(@("$($mvAz.roleDefinitionId)" -split '/')[-1]) at $($mvAz.scope)" 'DarkGray' }
        foreach ($mvGr in @($mvTc.graph)) { Say "      app role: $($mvGr.appRoleId) of $(if ($mvGr.resourceDisplayName) { $mvGr.resourceDisplayName } else { $mvGr.resourceId })" 'DarkGray' }
        foreach ($mvCs in @($mvRp.customerSteps)) { Say "    CUSTOMER STEP ($($mvCs.when)): $($mvCs.what)" 'Yellow'; Say "      $($mvCs.command)" 'Yellow' }
    }
    $planOut = Join-Path $LogDir "identity-move-plan-$stamp.json"
    $planJson = [pscustomobject]@{ subscriptionId = $plan.subscriptionId; resourceGroup = $plan.resourceGroup; tenantId = $plan.tenantId; supportHasRootAccess = $plan.supportHasRootAccess
        roles = @($plan.roles | ForEach-Object { [pscustomobject]@{ role = $_.role; target = $_.target; targetExists = $_.targetExists; state = $_.state
            resources = @($_.resources | ForEach-Object { [pscustomobject]@{ resource = $_.resource; kind = $_.kind; signsInAsTarget = $_.signsInAsTarget; sources = @($_.sources | ForEach-Object { $_.name }); ignored = @($_.ignored); settings = @($_.settings) } })
            toCopy = $_.toCopy; customerSteps = $_.customerSteps; sql = $_.sql } }) }
    Set-Content -LiteralPath $planOut -Value ($planJson | ConvertTo-Json -Depth 12) -Encoding UTF8
    Say "`n  plan written: $planOut" 'DarkGray'

    if (-not $Apply) { Say "`nPLAN ONLY -- nothing was changed. Move a role with -Apply -Role <role>." 'Cyan'; exit 0 }

    $records = New-Object System.Collections.Generic.List[object]
    $bad = $false
    foreach ($ro in @($Role)) {
        Say "`n--- $ro ---" 'Cyan'
        if ($dry) { Say "What if: Performing the operation `"move to id-pim-$ro`" on target `"$ResourceGroup`" -- every step below is what WOULD happen; nothing is written." 'Yellow' }
        $mvRec = Invoke-PimIdentityMoveRole -Plan $plan -Role $ro -Arm $Arm -Graph $Graph -DbInit $DbInit -Prove $Prove -Sleep $Sleep -StartJobRoles $StartJobRoles -DryRun:$dry -NoCleanup:$NoCleanup
        $records.Add($mvRec)
        foreach ($mvStep in @($mvRec.steps.ToArray())) {
            $mvLine = '  [' + [string]$mvStep.step + '] ' + [string]$mvStep.what
            if ([string]$mvStep.readBack) { $mvLine += '  (' + [string]$mvStep.readBack + ')' }
            Say $mvLine 'Gray'
        }
        foreach ($mvKept in $mvRec.kept.ToArray()) { Say "  kept: $mvKept" 'DarkGray' }
        foreach ($mvCs2 in $mvRec.customerSteps.ToArray()) { Say "  CUSTOMER STEP ($($mvCs2.when)): $($mvCs2.what)" 'Yellow'; Say "    $($mvCs2.command)" 'Yellow' }
        $col = switch ($mvRec.state) { 'done' { 'Green' } 'nothing-to-do' { 'Green' } 'dry-run' { 'Yellow' } 'proven' { 'Green' } 'failed' { 'Red' } default { 'Yellow' } }
        Say "  RESULT $ro : $($mvRec.state)$(if ($mvRec.error) { ' -- ' + $mvRec.error })" $col
        if ($mvRec.state -eq 'failed') {
            $bad = $true
            Say "  STOPPED at step '$($mvRec.failedStep)'. Nothing old was removed. To undo what this run did (newest first):" 'Red'
            foreach ($mvUndo in @($mvRec.rollback)) { Say "    $($mvUndo.undo)" 'Red' }
        }
        $recOut = Join-Path $LogDir "identity-move-$ro-$stamp.json"
        Set-Content -LiteralPath $recOut -Value ([pscustomobject]$mvRec | ConvertTo-Json -Depth 10) -Encoding UTF8
        Say "  record written: $recOut" 'DarkGray'
        if ($bad) { break }
    }
    Say "`n  role | old -> new | state | copied (read back) | proof | old rights removed" 'Cyan'
    foreach ($mvRow in @(Format-PimIdentityMoveTable -Records $records.ToArray() -Plan $plan)) {
        Say ("  {0} | {1} -> {2} | {3} | {4} | {5} | {6}" -f $mvRow.role, $mvRow.old, $mvRow.new, $mvRow.state, $mvRow.copied, $mvRow.proof, $mvRow.removed) 'Gray'
    }
    if ($dry) { Say "`nWhat if: nothing was changed." 'Yellow' }
    if ($bad) { exit 1 }
    exit 0
} finally {
    Stop-PimScriptRun -Script 'Move-PimIdentities'
}
