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
          [Parameter(Mandatory)][scriptblock]$Arm, [scriptblock]$Store, [scriptblock]$Graph,
          [string]$AlertRecipientsScript = '', [string]$SqlServer = '', [string]$TenantId = '')
    $lines = New-Object System.Collections.Generic.List[object]
    $add = { param($id, $level, $text) $lines.Add([pscustomobject]@{ id = $id; level = $level; text = $text }) }
    $rgScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $tickScope = "$rgScope/providers/Microsoft.App/jobs/$TickJob"
    $hostingFix = "run tools/setup/Initialize-PimHostingAccess.ps1 -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup (an Owner / User Access Administrator of the resource group)"
    $rgReaderFix = "run tools/setup/Confirm-PimInstall.ps1 (or Initialize-PimHostingAccess.ps1) as an Owner / User Access Administrator of $ResourceGroup"

    # ---- the identities (principal ids), read once -------------------------------------------------------------------
    $mgrOid = ''; $tickOid = ''
    try { $m = & $Arm 'GET' "$rgScope/providers/Microsoft.App/containerApps/$ManagerApp`?api-version=2024-03-01" $null; $mgrOid = "$($m.identity.principalId)".Trim() } catch { }
    try { $t = & $Arm 'GET' "$tickScope`?api-version=2024-03-01" $null; $tickOid = "$($t.identity.principalId)".Trim() } catch { }
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
    $mgrTick = & $readAssignments $tickScope $mgrOid
    $dOp = Get-PimRbacConvergeDecision -Id 'manager-tick-operator' -What "'Container Apps Jobs Operator' for $ManagerApp on $TickJob (start the engine after a commit)" -Assignments $mgrTick.list -ReadError $mgrTick.error `
            -Scope $tickScope -RoleIds @($ids.JobsOperator, $ids.Contributor, $ids.Owner) -Fix $hostingFix
    & $add $dOp.id $(if ($dOp.action -eq 'noop') { 'info' } else { 'warn' }) $dOp.line
    $tickSelf = & $readAssignments $tickScope $tickOid
    $d = Get-PimRbacConvergeDecision -Id 'tick-self-reader' -What "Reader for $TickJob on itself (a stale engine lease is taken over at once)" -Assignments $tickSelf.list -ReadError $tickSelf.error `
            -Scope $tickScope -RoleIds @($ids.Reader, $ids.Contributor, $ids.Owner) -Fix $hostingFix
    & $add $d.id $(if ($d.action -eq 'noop') { 'info' } else { 'warn' }) $d.line

    # ---- SchedulerTickJobId ----------------------------------------------------------------------------------------
    if (-not $Store) { & $add 'tick-start' 'warn' 'immediate engine start (SchedulerTickJobId) -- not checked (no store)' }
    else {
        try {
            $may = switch ($dOp.action) { 'noop' { $true } 'report' { $false } default { $null } }
            $tickId = $(if ($t -and "$($t.id)".Trim()) { "$($t.id)".Trim() } elseif ($tickOid) { $tickScope } else { '' })
            $cur = & $Store 'get' 'SchedulerTickJobId' $null
            $dt = Get-PimTickJobIdConvergeDecision -Current $cur -TickJobId $tickId -ManagerMayStart $may -Fix $hostingFix
            if ($dt.action -eq 'set') {
                $r = Set-PimTickJobIdSetting -TickJobId $tickId -Store $Store
                & $add 'tick-start' 'changed' "immediate engine start (SchedulerTickJobId) -- $($r.reason)"
            } else { & $add 'tick-start' $(if ($dt.action -eq 'report') { 'warn' } else { 'info' }) $dt.line }
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
