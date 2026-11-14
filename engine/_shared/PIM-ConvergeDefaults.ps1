#Requires -Version 5.1
<#
.SYNOPSIS
    PIM REQUIREMENTS 100.40 / framework DOCS/REQUIREMENTS.md 12.16 CONVERGE-DEFAULTS -- the install defaults that the
    in-cloud updater (tools/pim-engine/update-job-entry.ps1, step 2d) brings an EXISTING installation to, on every update.

.DESCRIPTION
    WHY (owner 2026-10-09, "important finding"): a setup default that changes reaches only NEW installs unless the updater
    converges the existing ones. The 100.40 audit found these install-only defaults the updater CAN reach (its identity is
    Contributor on the PIM resource group + a member of the SQL admin group; no Graph app roles, no role-assignment write):

      alert-recipients  2.4.535 -- the install sets pim.Settings['Alerting'].recipients (given addresses, else the
                        SuperAdmins' mailboxes); every older install with an EMPTY list sends its alerts to nobody.
                        Apply = the setup script itself (tools/setup/Set-PimAlertRecipients.ps1 with its -Store/-Graph
                        seams) -- one implementation. Only an EMPTY list is ever written (a list someone set is kept).
      tick-start        pim.Settings 'SchedulerTickJobId' (the Manager starts the engine right after a commit) -- written
                        only by Initialize-PimHostingAccess.ps1 (MSP build / rebuilds), never by the single-tenant
                        install. Set here when ABSENT and the Manager already holds 'Container Apps Jobs Operator' on
                        the tick (else the start would only fail); a different value someone set is kept.
      role checks       the role assignments the install makes and the updater may NOT make (Contributor cannot write
                        Microsoft.Authorization): the Manager's Reader on the resource group (100.22 b, 2.4.538), the
                        Manager's 'Container Apps Jobs Operator' on the tick, the tick's Reader on itself (BUG-268,
                        2.4.468). READ over ARM; a missing one is ONE yellow line naming the script that grants it.

    Shape (framework 12.16): every decision is PURE (current state -> planned change) and offline-tested in
    tests/Test-PimConvergeDefaults.ps1; the applies reuse the setup code path; raise-only / additive (an explicit
    customer value always wins); idempotent (a converged install = 'noop'); one plain line per decision; NEVER throws.
    PS 5.1 + 7, no modules, no az.
#>

Set-StrictMode -Off

$script:PimConvergeRoleIds = @{
    Reader       = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'
    Contributor  = 'b24988ac-6180-42a0-ab88-20f7382dd24c'
    Owner        = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
    JobsOperator = 'b9a307c4-5aa3-4b52-ba60-2b17c136cd7b'   # Container Apps Jobs Operator
}
$script:PimConvergeAuthzApi = '2022-04-01'

function Resolve-PimConvergeSignInOid {
    # PURE. The object id of the identity a container app / job SIGNS IN AS: a container's PIM_ManagedIdentityClientId -> the
    # user-assigned identity with that client id (the identity move, id-pim-<role>, 2026-11-08); none named -> the
    # system-assigned identity. A client id that matches no attached identity -> '' (the caller reports "could not be
    # read"), never the system identity. (Same rule as PIM-UpdaterPermissionCheck's Resolve-PimUpdPermEngineObjectId; a copy
    # here so this library stays standalone.)
    param($Resource)
    if (-not $Resource) { return '' }
    $cid = ''
    foreach ($c in @($Resource.properties.template.containers | Where-Object { $_ })) {
        $v = @($c.env | Where-Object { "$($_.name)" -eq 'PIM_ManagedIdentityClientId' })[0]
        if ($v -and "$($v.value)".Trim()) { $cid = "$($v.value)".Trim(); break }
    }
    if (-not $cid) { return "$($Resource.identity.principalId)".Trim() }
    $ua = $Resource.identity.userAssignedIdentities
    if ($ua) { foreach ($p in @($ua.PSObject.Properties)) { if ("$($p.Value.clientId)".Trim() -ieq $cid) { return "$($p.Value.principalId)".Trim() } } }
    return ''
}

function Get-PimConvergeRoleGuid {
    # '/subscriptions/../providers/Microsoft.Authorization/roleDefinitions/<guid>' or a bare guid -> the lower-case guid.
    param([AllowNull()][string]$RoleDefinitionId)
    $s = "$RoleDefinitionId".Trim().TrimEnd('/')
    if (-not $s) { return '' }
    return ($s -split '/')[-1].ToLowerInvariant()
}

function Test-PimConvergeScopeCovers {
    <#
      PURE. Does a role assignment at -AssignmentScope apply to -TargetScope? Equal, or an ancestor (a path prefix on a
      '/'-boundary), or the root '/', or a management group (ARM lists an assignment for a scope only at, above or below
      it, and a management group is never below a resource group or a resource).
    #>
    param([AllowNull()][string]$AssignmentScope, [Parameter(Mandatory)][string]$TargetScope)
    $a = "$AssignmentScope".Trim().TrimEnd('/').ToLowerInvariant()
    $t = "$TargetScope".Trim().TrimEnd('/').ToLowerInvariant()
    if ("$AssignmentScope".Trim() -eq '/') { return $true }
    if (-not $a) { return $false }
    if ($a -like '/providers/microsoft.management/managementgroups/*') { return $true }
    return ($t -eq $a -or $t.StartsWith($a + '/'))
}

function Get-PimRbacConvergeDecision {
    <#
      PURE. One role the install grants that the updater cannot (role-assignment write needs Owner / User Access
      Administrator). -Assignments: the principal's assignments as ARM lists them (properties.scope / roleDefinitionId, or
      flat scope / roleDefinitionId); $null = they could not be read. -RoleIds: the role ids that satisfy it (the role
      itself, and Contributor / Owner where they include it).
      Returns @{ id; action = noop | report | unknown; line }. Never a write: a missing role is reported with -Fix.
    #>
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][string]$What, [AllowNull()][object[]]$Assignments,
          [Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string[]]$RoleIds, [string]$Fix = '', [string]$ReadError = '')
    if ($null -eq $Assignments) {
        return [pscustomobject]@{ id = $Id; action = 'unknown'; line = "$What -- not checked ($(if ($ReadError) { $ReadError } else { 'the role assignments could not be read' }))" }
    }
    $want = @($RoleIds | ForEach-Object { "$_".ToLowerInvariant() })
    foreach ($as in @($Assignments | Where-Object { $_ })) {
        $p = if ($as.PSObject.Properties['properties'] -and $as.properties) { $as.properties } else { $as }
        $rid = Get-PimConvergeRoleGuid -RoleDefinitionId "$($p.roleDefinitionId)"
        if ($want -contains $rid -and (Test-PimConvergeScopeCovers -AssignmentScope "$($p.scope)" -TargetScope $Scope)) {
            return [pscustomobject]@{ id = $Id; action = 'noop'; line = "$What -- present" }
        }
    }
    return [pscustomobject]@{ id = $Id; action = 'report'; line = "$What -- MISSING (the updater may not grant roles). Fix: $Fix" }
}

function Get-PimWebNeverRightDecision {
    <#
      PURE. SECURE-WEB-1 (framework 12.11f, 2026-11-14): the INTERNET-FACING Manager identity's role assignments (as ARM lists
      them; $null = not readable) checked against the never-rights -- any Container Apps job role, Contributor, Owner, User
      Access Administrator, RBAC Administrator, AcrPush, Key Vault Secrets Officer / Administrator / Contributor, Managed
      Identity Operator. Key Vault Secrets User is allowed ONLY on the one secret PIM-EmergencyPasscode (Invardia F1 b).
      Returns @{ level = info | warn; held = @(<role guid @ scope>); line }. Report only: removal is a Support-app action.
    #>
    param([AllowNull()][object[]]$Assignments, [string]$ReadError = '', [string]$ManagerApp = 'ca-pim-manager')
    $never = @{
        'b9a307c4-5aa3-4b52-ba60-2b17c136cd7b' = 'Container Apps Jobs Operator'
        'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
        '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
        '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'
        'f58310d9-a9f6-439a-9e8d-f62e7b41a168' = 'Role Based Access Control Administrator'
        '8311e382-0749-4cb8-b61a-304f252e45ec' = 'AcrPush'
        'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' = 'Key Vault Secrets Officer'
        '00482a5a-887f-4fb3-b363-3b7fe8e74483' = 'Key Vault Administrator'
        'f25e0fa2-a7c8-4377-a976-54943a77a395' = 'Key Vault Contributor'
        'f1a07417-d97a-45cb-824c-7a7467783830' = 'Managed Identity Operator'
        'e40ec5ca-96e0-45a2-b4ff-59039f2c2b59' = 'Managed Identity Contributor'
        '8b54135c-b56d-4d72-a534-26097cfdc8d8' = 'Key Vault Data Access Administrator'
        '57cc5028-e6a7-4284-868d-0611c5923f8d' = 'Container Apps ManagedEnvironments Contributor'
        '4633458b-17de-408a-b874-0445c86b69e6' = 'Key Vault Secrets User'
    }
    $what = "SECURE-WEB-1: $ManagerApp (internet-facing) holds no job right, Contributor, role-assignment write, AcrPush or Key Vault secrets right"
    if ($null -eq $Assignments) {
        return [pscustomobject]@{ level = 'warn'; held = @(); line = "$what -- not checked ($(if ($ReadError) { $ReadError } else { 'the role assignments could not be read' }))" }
    }
    $held = New-Object System.Collections.Generic.List[string]
    foreach ($as in @($Assignments | Where-Object { $_ })) {
        $p = if ($as.PSObject.Properties['properties'] -and $as.properties) { $as.properties } else { $as }
        $rid = Get-PimConvergeRoleGuid -RoleDefinitionId "$($p.roleDefinitionId)"
        if (-not $never.ContainsKey($rid)) { continue }
        $sc = "$($p.scope)"
        # Invardia F1 b: Key Vault Secrets User on the ONE secret PIM-EmergencyPasscode is the only allowed exception
        if ($rid -eq '4633458b-17de-408a-b874-0445c86b69e6' -and $sc -match '(?i)/providers/Microsoft\.KeyVault/vaults/[^/]+/secrets/PIM-EmergencyPasscode$') { continue }
        $held.Add("$($never[$rid]) @ $($sc -replace '^/subscriptions/[^/]+/resourceGroups/[^/]+', '<rg>')")
    }
    if ($held.Count) {
        return [pscustomobject]@{ level = 'warn'; held = @($held); line = "SECURITY $what -- HELD: $(@($held) -join '; '). The updater may not change role assignments: Invardia removes it through the Support app (recorded, read back)." }
    }
    return [pscustomobject]@{ level = 'info'; held = @(); line = "$what -- none held (correct)" }
}

function Get-PimTickJobIdConvergeDecision {
    <#
      PURE. pim.Settings 'SchedulerTickJobId' on an existing install.
        stored = this tick                      -> noop
        stored = something else (set by hand)   -> keep  (an explicit value wins; never overwritten here)
        absent + the Manager may start the tick -> set
        absent + it may not / unknown           -> report (writing it would only make every "Run now" fail)
      -ManagerMayStart: $true / $false / $null (not readable).
    #>
    param([AllowNull()][object]$Current, [Parameter(Mandatory)][AllowEmptyString()][string]$TickJobId, [AllowNull()][object]$ManagerMayStart, [string]$Fix = '')
    $cur = "$Current".Trim().Trim('"')
    $tid = "$TickJobId".Trim()
    if (-not $tid) { return [pscustomobject]@{ action = 'report'; value = ''; line = "immediate engine start -- not checked (the tick job's id is unknown)" } }
    if ($cur -and $cur -ieq $tid) { return [pscustomobject]@{ action = 'noop'; value = $cur; line = 'immediate engine start (SchedulerTickJobId) -- already set' } }
    if ($cur) { return [pscustomobject]@{ action = 'keep'; value = $cur; line = "immediate engine start (SchedulerTickJobId) -- kept: it names another job ('$cur'), set on purpose" } }
    if ($ManagerMayStart -eq $true) { return [pscustomobject]@{ action = 'set'; value = $tid; line = 'immediate engine start (SchedulerTickJobId) -- set' } }
    $why = if ($ManagerMayStart -eq $false) { "the Manager does not hold 'Container Apps Jobs Operator' on the tick" } else { "the Manager's right to start the tick could not be read" }
    return [pscustomobject]@{ action = 'report'; value = ''; line = "immediate engine start (SchedulerTickJobId) -- not set: $why (the engine still runs on its schedule). Fix: $Fix" }
}

function Set-PimTickJobIdSetting {
    <#
      The ONE write of pim.Settings 'SchedulerTickJobId' -- used by the setup (Initialize-PimHostingAccess.ps1, -Overwrite:
      the install knows the tick it just deployed) and by the updater (step 2d: only when absent, after the decision above).
      -Store { param($op = get|set|audit, $name, $value) } -- the same seam Set-PimAlertRecipients.ps1 takes.
      Write, READ BACK, audit. Returns @{ ok; action = noop | kept | set; before; after; reason }. Throws only on a failed
      read-back (the caller decides: the setup stops, the updater reports).
    #>
    param([Parameter(Mandatory)][string]$TickJobId, [Parameter(Mandatory)][scriptblock]$Store, [switch]$Overwrite)
    $before = "$(& $Store 'get' 'SchedulerTickJobId' $null)".Trim().Trim('"')
    if ($before -ieq $TickJobId) { return [pscustomobject]@{ ok = $true; action = 'noop'; before = $before; after = $before; reason = 'already set' } }
    if ($before -and -not $Overwrite) { return [pscustomobject]@{ ok = $true; action = 'kept'; before = $before; after = $before; reason = 'another value is set -- kept' } }
    [void](& $Store 'set' 'SchedulerTickJobId' $TickJobId)
    $back = "$(& $Store 'get' 'SchedulerTickJobId' $null)".Trim().Trim('"')
    if ($back -ne $TickJobId) { throw "read-back FAILED: SchedulerTickJobId is '$back'" }
    try { [void](& $Store 'audit' 'SchedulerTickJobId' @{ before = $before; after = $TickJobId; action = 'settings.scheduler.tickjobid' }) } catch { }
    return [pscustomobject]@{ ok = $true; action = 'set'; before = $before; after = $back; reason = 'set and read back' }
}

function Get-PimAlertRecipientsConvergeDecision {
    <#
      PURE. pim.Settings['Alerting'].recipients on an existing install (the 2.4.535 install default).
        a list is stored        -> noop (whatever is there was chosen; never replaced)
        empty + SuperAdmins     -> apply (Set-PimAlertRecipients.ps1: their mailboxes, the install's own rule)
        empty + no SuperAdmin   -> report
      -Current: the stored Alerting value (object or JSON). -SuperAdmins: the SuperAdmin identities in ManagerAccess.
    #>
    param([AllowNull()][object]$Current, [string[]]$SuperAdmins = @(), [string]$Fix = '')
    $cur = $Current
    if ($cur -is [string]) { try { $cur = $cur | ConvertFrom-Json } catch { $cur = $null } }
    $rec = @()
    if ($cur -and $cur.PSObject.Properties['recipients']) { $rec = @(@($cur.recipients) | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
    if ($rec.Count) { return [pscustomobject]@{ action = 'noop'; superAdmins = @(); line = "alert recipients -- set ($($rec.Count))" } }
    $sa = @(@($SuperAdmins) | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
    if (-not $sa.Count) { return [pscustomobject]@{ action = 'report'; superAdmins = @(); line = "alert recipients -- EMPTY and no SuperAdmin is known: alerts reach nobody. Fix: $Fix" } }
    return [pscustomobject]@{ action = 'apply'; superAdmins = $sa; line = "alert recipients -- empty: setting the SuperAdmins' mailboxes" }
}

function Get-PimManagerAccessSuperAdmins {
    <# PURE. The SuperAdmin identities in pim.Settings['ManagerAccess'] = {"managerAccess":[{identity,role}]} (a bare list
       is accepted too). #>
    param([AllowNull()][object]$ManagerAccess)
    $v = $ManagerAccess
    if ($v -is [string]) { try { $v = $v | ConvertFrom-Json } catch { $v = $null } }
    if ($v -and -not ($v -is [array]) -and $v.PSObject.Properties['managerAccess']) { $v = $v.managerAccess }
    return @(@($v) | Where-Object { $_ -and "$($_.role)".Trim() -eq 'SuperAdmin' } | ForEach-Object { "$($_.identity)".Trim() } | Where-Object { $_ } | Select-Object -Unique)
}

function Invoke-PimUpdateConvergeDefaults {
    <#
      Step 2d of the updater: every convergence above, one line each. NEVER throws.
        -Arm   { param($method, $path, $body) }  (same seam as Invoke-PimJobSizingUpdate)
        -Store { param($op, $name, $value) }    get | set | audit over pim.Settings ($null = no store: the store steps report)
        -Graph { param($path) }                 Microsoft Graph GET (relative to v1.0, no leading '/'), for the SuperAdmins' mail
        -AlertRecipientsScript                  path of tools/setup/Set-PimAlertRecipients.ps1 (the setup's own write)
      Returns @{ lines = @(@{ id; level = info | changed | warn; text }); changed = [int]; warnings = [int] }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [string]$ManagerApp = 'ca-pim-manager', [string]$TickJob = 'ca-pim-tick',
          # RIGHTS-LIVE-1: the updater's own job -- the engine's Jobs Operator + Contributor on it are checked ('' = not checked)
          [string]$UpdaterJob = '',
          [Parameter(Mandatory)][scriptblock]$Arm, [scriptblock]$Store, [scriptblock]$Graph,
          [string]$AlertRecipientsScript = '', [string]$SqlServer = '', [string]$TenantId = '',
          # PIM 95.2k: the Azure rows the store defines -- @{ assignments = <PIM-Assignments-Azure-Resources rows>; definitions =
          # <PIM-Definitions-Resources rows> } (or @{ error = '<why they could not be read>' }). $null = not passed: no line.
          # REPORT ONLY (engine/_shared/PIM-EngineAzureAccess.ps1 Get-PimEngineAzureAccessReport, GET only): the updater may
          # not grant roles; the grant is Confirm-PimInstall's repair, run by a person.
          [object]$EngineAzureRows = $null)
    $lines = New-Object System.Collections.Generic.List[object]
    $add = { param($id, $level, $text) $lines.Add([pscustomobject]@{ id = $id; level = $level; text = $text }) }
    $rgScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $tickScope = "$rgScope/providers/Microsoft.App/jobs/$TickJob"
    $hostingFix = "run tools/setup/Initialize-PimHostingAccess.ps1 -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup (an Owner / User Access Administrator of the resource group)"
    $rgReaderFix = "run tools/setup/Confirm-PimInstall.ps1 (or Initialize-PimHostingAccess.ps1) as an Owner / User Access Administrator of $ResourceGroup"

    # ---- the identities (principal ids), read once -------------------------------------------------------------------
    # the identity each SIGNS IN AS (NAM-03, 2026-11-08): reading only identity.principalId after the identity move reported
    # the OLD system identity -- whose rights the move removed, correctly -- as "jobs-operator missing" (internal / ring 1)
    $mgrOid = ''; $tickOid = ''
    try { $m = & $Arm 'GET' "$rgScope/providers/Microsoft.App/containerApps/$ManagerApp`?api-version=2024-03-01" $null; $mgrOid = Resolve-PimConvergeSignInOid -Resource $m } catch { }
    try { $t = & $Arm 'GET' "$tickScope`?api-version=2024-03-01" $null; $tickOid = Resolve-PimConvergeSignInOid -Resource $t } catch { }
    $readAssignments = {
        param($scope, $oid)
        if (-not $oid) { return @{ list = $null; error = 'the identity could not be read' } }
        try {
            $r = & $Arm 'GET' ("$scope/providers/Microsoft.Authorization/roleAssignments?`$filter=assignedTo('{0}')&api-version={1}" -f $oid, $script:PimConvergeAuthzApi) $null
            $v = if ($r -and $r.PSObject.Properties['value']) { @($r.value) } else { @($r) }
            return @{ list = @($v | Where-Object { $_ }); error = '' }
        } catch { return @{ list = $null; error = ((("$($_.Exception.Message)") -split "`n")[0]).Trim() } }
    }

    # ---- role checks (report only) ---------------------------------------------------------------------------------
    $ids = $script:PimConvergeRoleIds
    $mgrRg = & $readAssignments $rgScope $mgrOid
    $d = Get-PimRbacConvergeDecision -Id 'manager-rg-reader' -What "Reader for $ManagerApp on the resource group (Environment report)" -Assignments $mgrRg.list -ReadError $mgrRg.error `
            -Scope $rgScope -RoleIds @($ids.Reader, $ids.Contributor, $ids.Owner) -Fix $rgReaderFix
    & $add $d.id $(if ($d.action -eq 'noop') { 'info' } else { 'warn' }) $d.line
    # 🔒 SECURE-WEB-1 (framework 12.11f, 2026-11-14): the Manager is INTERNET-FACING and must hold NO never-right anywhere in
    # the resource group (it used to hold 'Container Apps Jobs Operator' on the tick -- a job start accepts a container
    # override). REPORT ONLY (the updater may not change role assignments): a held one is a SECURITY line; Invardia removes it
    # through the Support app. assignedTo() at the resource group lists assignments at, above and below it.
    $mgrNever = & $readAssignments $rgScope $mgrOid
    $dSw = Get-PimWebNeverRightDecision -Assignments $mgrNever.list -ReadError $mgrNever.error -ManagerApp $ManagerApp
    & $add 'manager-never-rights' $dSw.level $dSw.line
    $tickSelf = & $readAssignments $tickScope $tickOid
    $d = Get-PimRbacConvergeDecision -Id 'tick-self-reader' -What "Reader for $TickJob on itself (a stale engine lease is taken over at once)" -Assignments $tickSelf.list -ReadError $tickSelf.error `
            -Scope $tickScope -RoleIds @($ids.Reader, $ids.Contributor, $ids.Owner) -Fix $hostingFix
    & $add $d.id $(if ($d.action -eq 'noop') { 'info' } else { 'warn' }) $d.line
    # RIGHTS-LIVE-1 (owner rights decision 2026-11-09 "approved with A"): the ENGINE on the UPDATER job only -- update-expedite
    # starts it (Jobs Operator), the watchdog restores its image (Contributor). Report only: the updater may not grant roles.
    if ("$UpdaterJob".Trim()) {
        $updScope = "$rgScope/providers/Microsoft.App/jobs/$("$UpdaterJob".Trim())"
        $engUpd = & $readAssignments $updScope $tickOid
        $d = Get-PimRbacConvergeDecision -Id 'engine-updater-operator' -What "'Container Apps Jobs Operator' for $TickJob on $UpdaterJob (update-expedite starts the updater)" -Assignments $engUpd.list -ReadError $engUpd.error `
                -Scope $updScope -RoleIds @($ids.JobsOperator, $ids.Contributor, $ids.Owner) -Fix $hostingFix
        & $add $d.id $(if ($d.action -eq 'noop') { 'info' } else { 'warn' }) $d.line
        $d = Get-PimRbacConvergeDecision -Id 'engine-updater-contributor' -What "'Contributor' for $TickJob on $UpdaterJob (the watchdog restores the updater's image)" -Assignments $engUpd.list -ReadError $engUpd.error `
                -Scope $updScope -RoleIds @($ids.Contributor, $ids.Owner) -Fix $hostingFix
        & $add $d.id $(if ($d.action -eq 'noop') { 'info' } else { 'warn' }) $d.line
    }

    # ---- PIM 95.2k: the engine's Azure rights vs the DEFINED Azure scopes (report only) ------------------------------
    if ($null -ne $EngineAzureRows) {
        if (-not (Get-Command Get-PimEngineAzureAccessReport -ErrorAction SilentlyContinue)) { & $add 'engine-azure-scopes' 'warn' 'engine Azure access -- not checked (PIM-EngineAzureAccess.ps1 is not loaded)' }
        elseif ($EngineAzureRows -is [System.Collections.IDictionary] -and $EngineAzureRows.Contains('error')) { & $add 'engine-azure-scopes' 'warn' "engine Azure access -- not checked (the Azure definitions could not be read: $($EngineAzureRows['error']))" }
        else {
            $eaRows = if ($EngineAzureRows -is [System.Collections.IDictionary]) { $EngineAzureRows } else { @{} }
            $ea = Get-PimEngineAzureAccessReport -Arm $Arm -AssignmentRows @($eaRows['assignments']) -DefinitionRows @($eaRows['definitions']) -EngineObjectId $tickOid -TenantId $TenantId -Name $TickJob
            & $add 'engine-azure-scopes' $(if ($ea.action -eq 'noop') { 'info' } else { 'warn' }) $ea.line
        }
    }

    # ---- SchedulerTickJobId ----------------------------------------------------------------------------------------
    if (-not $Store) { & $add 'tick-start' 'warn' 'immediate engine start (SchedulerTickJobId) -- not checked (no store)' }
    else {
        try {
            # SECURE-WEB-1: the Manager never starts the engine (no job right), so an absent SchedulerTickJobId is correct and
            # never a warning; a stored one is left as it is (nothing reads it to start a job any more)
            $tickId = $(if ($t -and "$($t.id)".Trim()) { "$($t.id)".Trim() } elseif ($tickOid) { $tickScope } else { '' })
            $cur = & $Store 'get' 'SchedulerTickJobId' $null
            $dt = Get-PimTickJobIdConvergeDecision -Current $cur -TickJobId $tickId -ManagerMayStart $false -Fix $hostingFix
            if ($dt.action -eq 'report') { & $add 'tick-start' 'info' 'immediate engine start -- off by design (SECURE-WEB-1: the Manager starts no job; the engine runs on its schedule)' }
            else { & $add 'tick-start' 'info' $dt.line }
        } catch { & $add 'tick-start' 'warn' "immediate engine start (SchedulerTickJobId) -- not converged: $(((("$($_.Exception.Message)") -split "`n")[0]).Trim()). Fix: $hostingFix" }
    }

    # ---- alert recipients ------------------------------------------------------------------------------------------
    $alertFix = 'PIM Manager > Settings > Alerting > Recipients, or tools/setup/Set-PimAlertRecipients.ps1 -AlertRecipients <address>'
    if (-not $Store) { & $add 'alert-recipients' 'warn' 'alert recipients -- not checked (no store)' }
    else {
        try {
            $al = & $Store 'get' 'Alerting' $null
            $ma = & $Store 'get' 'ManagerAccess' $null
            $da = Get-PimAlertRecipientsConvergeDecision -Current $al -SuperAdmins (Get-PimManagerAccessSuperAdmins -ManagerAccess $ma) -Fix $alertFix
            if ($da.action -ne 'apply') { & $add 'alert-recipients' $(if ($da.action -eq 'report') { 'warn' } else { 'info' }) $da.line }
            elseif (-not "$AlertRecipientsScript".Trim() -or -not (Test-Path -LiteralPath $AlertRecipientsScript)) { & $add 'alert-recipients' 'warn' "alert recipients -- EMPTY (the setup script is not in this image). Fix: $alertFix" }
            else {
                $out = Join-Path ([IO.Path]::GetTempPath()) ("pim-alertrec-{0}.json" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
                $g = if ($Graph) { $Graph } else { { param($p) throw 'no Microsoft Graph access' } }
                try {
                    $srv = if ("$SqlServer".Trim()) { "$SqlServer".Trim() } else { 'store' }
                    $tn = if ("$TenantId".Trim()) { "$TenantId".Trim() } else { 'tenant' }
                    # the setup's own write (one implementation): read, plan (Resolve-PimAlertRecipientsPlan), write, READ BACK, audit.
                    & $AlertRecipientsScript -SqlServerFqdn $srv -TenantId $tn -SuperAdmins $da.superAdmins -Store $Store -Graph $g -OutFile $out 6>$null 3>$null | Out-Null
                    $res = $null; if (Test-Path -LiteralPath $out) { $res = Get-Content -LiteralPath $out -Raw | ConvertFrom-Json }
                    if ($res -and $res.ok -and "$($res.action)" -eq 'set') { & $add 'alert-recipients' 'changed' "alert recipients -- were empty, now: $(@($res.recipients) -join ', ') (read back)" }
                    elseif ($res -and $res.ok) { & $add 'alert-recipients' 'info' "alert recipients -- $($res.reason)" }
                    else { & $add 'alert-recipients' 'warn' ("alert recipients -- EMPTY, not set: $(if ($res) { $res.reason } else { 'no result' }) (the updater may not read the SuperAdmins' mailboxes). Fix: $alertFix") }
                } finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
            }
        } catch { & $add 'alert-recipients' 'warn' "alert recipients -- not converged: $(((("$($_.Exception.Message)") -split "`n")[0]).Trim()). Fix: $alertFix" }
    }

    $arr = @($lines.ToArray())
    return [pscustomobject]@{ lines = $arr; changed = @($arr | Where-Object { $_.level -eq 'changed' }).Count; warnings = @($arr | Where-Object { $_.level -eq 'warn' }).Count }
}
