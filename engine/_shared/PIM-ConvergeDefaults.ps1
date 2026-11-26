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

# SECURE-WEB-1 (3.1.26): the break-glass verifier (the one-time move from Key Vault into the PIM database, below)
if (-not (Get-Command New-PimEmergencyVerifier -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-EmergencyVerifier.ps1') }

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
      Access Administrator, RBAC Administrator, AcrPush, Managed Identity Operator / Contributor and EVERY Key Vault role.
      SECURE-WEB-1 (3.1.26, owner: "the internet-facing identity has NO Key Vault edge"): there is no exception any more --
      Key Vault Secrets User on the secret PIM-EmergencyPasscode (the break-glass hash before 3.1.26) is a finding like any
      Key Vault role, and so is the retired signin-front key's Crypto Service Encryption User.
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
        # SECURE-WEB-1 (3.1.26): every other built-in Key Vault role too
        '21090545-7ca7-4776-b22c-e363652d74d2' = 'Key Vault Reader'
        '12338af0-0e69-4776-bea7-57ae8d297424' = 'Key Vault Crypto User'
        '14b46e9e-c2b7-41b4-b07b-48a6ebf60603' = 'Key Vault Crypto Officer'
        'e147488a-f6f5-4113-8e2d-b22465e65bf6' = 'Key Vault Crypto Service Encryption User'
        '08bbd89e-9f13-488c-ac41-acfcb10c90ab' = 'Key Vault Crypto Service Release User'
        'a4417e6f-fecd-4de8-b567-7b0420556985' = 'Key Vault Certificates Officer'
        'db79e9a7-68ee-4b58-9aeb-b90e7c24fcba' = 'Key Vault Certificate User'
    }
    $what = "SECURE-WEB-1: $ManagerApp (internet-facing) holds no job right, Contributor, role-assignment write, AcrPush or Key Vault role"
    if ($null -eq $Assignments) {
        return [pscustomobject]@{ level = 'warn'; held = @(); line = "$what -- not checked ($(if ($ReadError) { $ReadError } else { 'the role assignments could not be read' }))" }
    }
    $held = New-Object System.Collections.Generic.List[string]
    foreach ($as in @($Assignments | Where-Object { $_ })) {
        $p = if ($as.PSObject.Properties['properties'] -and $as.properties) { $as.properties } else { $as }
        $rid = Get-PimConvergeRoleGuid -RoleDefinitionId "$($p.roleDefinitionId)"
        if (-not $never.ContainsKey($rid)) { continue }
        $sc = "$($p.scope)"
        # SECURE-WEB-1 (3.1.26): NO exception (the emergency-secret grant of earlier versions is a finding too)
        $held.Add("$($never[$rid]) @ $($sc -replace '^/subscriptions/[^/]+/resourceGroups/[^/]+', '<rg>')")
    }
    if ($held.Count) {
        return [pscustomobject]@{ level = 'warn'; held = @($held); line = "SECURITY $what -- HELD: $(@($held) -join '; '). The updater may not change role assignments: Invardia removes it through the Support app (recorded, read back)." }
    }
    return [pscustomobject]@{ level = 'info'; held = @(); line = "$what -- none held (correct)" }
}

function Get-PimEmergencyVerifierConvergeDecision {
    <#
      PURE. SECURE-WEB-1 (3.1.26): the break-glass verifier on an existing install.
        a usable verifier is stored            -> noop   (whatever is there was set on purpose; never replaced)
        none stored + the Manager names a vault -> migrate (an earlier version kept the SHA-256 hex in that vault: read it
                                                   ONCE with the updater's own identity, store the verifier derived from it)
        none stored + no vault                 -> none   (no passphrase was ever set up: nothing to move, info only)
      -Current: the stored value (or $null). -LegacyVault: the Manager's PIM_EmergencyVault ('' = none).
    #>
    param([AllowNull()][object]$Current, [AllowEmptyString()][string]$LegacyVault = '')
    if ($null -ne $Current -and (ConvertFrom-PimEmergencyVerifier -Value $Current).ok) { return [pscustomobject]@{ action = 'noop'; line = 'emergency passphrase check -- kept in the PIM database' } }
    if ("$LegacyVault".Trim()) { return [pscustomobject]@{ action = 'migrate'; line = "emergency passphrase check -- still only in key vault '$("$LegacyVault".Trim())': moving it into the PIM database once" } }
    return [pscustomobject]@{ action = 'none'; line = 'emergency passphrase check -- not set up (nothing to move; Settings > Emergency access shows the command)' }
}

function Invoke-PimEmergencyVerifierMigration {
    <#
      SECURE-WEB-1 (3.1.26): the ONE-TIME move of an existing break-glass passphrase from Key Vault into the PIM database, so the
      internet-facing Manager reads no Key Vault. -KeyVault { param($vault, $secret) } returns the old secret's value with the
      UPDATER's own identity (throws when refused). -Store = the converge's store seam. The value never leaves this function:
      only the derived verifier (PBKDF2, its own salt) is written, read back, checked against the same pre-hash and audited.
      Returns @{ level = info | changed | warn; text }. Never throws. The old secret and the Manager's old grant on it are left
      as they are (reported, the grant by the never-rights line; removing them is a Support-app action).
    #>
    param([AllowNull()][object]$Current, [AllowEmptyString()][string]$LegacyVault = '', [string]$SecretName = 'PIM-EmergencyPasscode',
          [Parameter(Mandatory)][scriptblock]$Store, [scriptblock]$KeyVault, [string]$Fix = '')
    $d = Get-PimEmergencyVerifierConvergeDecision -Current $Current -LegacyVault $LegacyVault
    if ($d.action -ne 'migrate') { return [pscustomobject]@{ level = 'info'; text = $d.line } }
    $v = "$LegacyVault".Trim(); $sn = if ("$SecretName".Trim()) { "$SecretName".Trim() } else { 'PIM-EmergencyPasscode' }
    if (-not $KeyVault) { return [pscustomobject]@{ level = 'warn'; text = "emergency passphrase check -- still only in key vault '$v' and this updater has no Key Vault reader: break-glass is refused until it is moved. Fix: $Fix" } }
    $pre = ''
    try { $pre = ConvertTo-PimEmergencyPreHashFromSecret -SecretValue (& $KeyVault $v $sn) }
    catch {
        $m = ((("$($_.Exception.Message)") -split "`n")[0]).Trim()
        $why = if ($m -match '(?i)\b403\b|Forbidden') { 'the updater may not read that secret' } elseif ($m -match '(?i)\b404\b|NotFound') { 'the secret is not there' } else { $m }
        return [pscustomobject]@{ level = 'warn'; text = "emergency passphrase check -- still only in key vault '$v' ($why): break-glass is refused until it is moved. Fix: $Fix" }
    }
    if (-not $pre) { return [pscustomobject]@{ level = 'warn'; text = "emergency passphrase check -- secret $sn in key vault '$v' is empty: nothing to move. Fix: $Fix" } }
    try {
        $ver = New-PimEmergencyVerifier -PreHashHex $pre -Source 'updater: moved from Key Vault'
        $name = Get-PimEmergencyVerifierSettingName
        [void](& $Store 'set' $name $ver)
        $back = & $Store 'get' $name $null
        if (-not (Test-PimEmergencyVerifier -Verifier $back -PreHashHex $pre)) { throw 'read-back FAILED: the stored check does not match' }
        try { [void](& $Store 'audit' $name @{ before = $null; after = @{ alg = 'pbkdf2-sha256'; iter = $ver.iter; source = $ver.source }; action = 'emergency.passphrase.migrated' }) } catch { }
        $pre = $null
        return [pscustomobject]@{ level = 'changed'; text = "emergency passphrase check -- moved from key vault '$v' into the PIM database (read back); the Manager reads no Key Vault any more" }
    } catch { return [pscustomobject]@{ level = 'warn'; text = "emergency passphrase check -- not moved: $(((("$($_.Exception.Message)") -split "`n")[0]).Trim()). Fix: $Fix" } }
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

function Get-PimWebSharedIdentityDecision {
    <#
      PURE. SECURE-WEB-1 (Invardia / owner 2026-11-14, 3.1.26) -- REPORT ONLY: is an identity of the INTERNET-FACING Manager
      (-Manager: its ARM resource; its system-assigned principal and every user-assigned identity it carries) ALSO attached to
      any job of the install (-Jobs: the resource group's Container Apps jobs as ARM lists them; $null = not readable)? A
      shared identity gives a job's rights to the internet-facing app. Matched by the user-assigned identity's resource id
      (case-insensitive) or by a principal id. Never strips anything: giving the job its own identity is a Support-app /
      Move-PimIdentities.ps1 step. Returns @{ level = info | warn; shared = @("<identity> on <job>"); line }.
    #>
    param([AllowNull()][object]$Manager, [AllowNull()][object[]]$Jobs, [string]$ReadError = '', [string]$ManagerApp = 'ca-pim-manager')
    $what = "SECURE-WEB-1: $ManagerApp (internet-facing) shares no identity with a job of the install"
    if ($null -eq $Manager) { return [pscustomobject]@{ level = 'warn'; shared = @(); line = "$what -- not checked (the Manager could not be read)" } }
    if ($null -eq $Jobs) { return [pscustomobject]@{ level = 'warn'; shared = @(); line = "$what -- not checked ($(if ($ReadError) { $ReadError } else { 'the jobs could not be read' }))" } }
    $idOf = { param($r)
        $o = @{ ua = @{}; pids = @{} }
        $ident = $null; if ($r -and $r.PSObject.Properties['identity']) { $ident = $r.identity }
        if ($ident) {
            $sp = "$($ident.principalId)".Trim(); if ($sp) { $o.pids[$sp.ToLowerInvariant()] = 'its system-assigned identity' }
            $uam = $ident.userAssignedIdentities
            if ($uam) {
                $pairs = if ($uam -is [System.Collections.IDictionary]) { @($uam.Keys | ForEach-Object { @{ k = "$_"; v = $uam[$_] } }) } else { @($uam.PSObject.Properties | ForEach-Object { @{ k = "$($_.Name)"; v = $_.Value } }) }
                foreach ($pp in $pairs) {
                    $nm = @(@("$($pp.k)" -split '/') | Where-Object { $_ })[-1]
                    $o.ua["$($pp.k)".Trim().TrimEnd('/').ToLowerInvariant()] = $nm
                    $upid = "$($pp.v.principalId)".Trim(); if ($upid) { $o.pids[$upid.ToLowerInvariant()] = $nm }
                }
            }
        }
        return $o
    }
    $mi = & $idOf $Manager
    $shared = New-Object System.Collections.Generic.List[string]
    foreach ($j in @($Jobs | Where-Object { $_ })) {
        $jn = "$($j.name)"; if (-not $jn) { $jn = @(@("$($j.id)" -split '/') | Where-Object { $_ })[-1] }
        $ji = & $idOf $j
        $hit = New-Object System.Collections.Generic.List[string]
        foreach ($k in @($ji.ua.Keys)) { if ($mi.ua.ContainsKey($k)) { $hit.Add("$($mi.ua[$k])") } }
        foreach ($k in @($ji.pids.Keys)) { if ($mi.pids.ContainsKey($k)) { $hit.Add("$($mi.pids[$k])") } }
        foreach ($h in @($hit | Select-Object -Unique)) { $shared.Add("$h on $jn") }
    }
    if ($shared.Count) {
        return [pscustomobject]@{ level = 'warn'; shared = @($shared); line = "SECURITY $what -- SHARED: $(@($shared) -join '; '). The updater changes no identity: the Support app (or Move-PimIdentities.ps1) gives the job its own identity (recorded, read back)." }
    }
    return [pscustomobject]@{ level = 'info'; shared = @(); line = "$what -- none shared (correct)" }
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
          [object]$EngineAzureRows = $null,
          # SECURE-WEB-1 (3.1.26): { param($vault, $secret) } -> the value of the OLD break-glass secret, read with the UPDATER's
          # own identity (the one-time move into the PIM database). Not passed = PIM-Rest's token client (Key Vault REST).
          [scriptblock]$KeyVault)
    $lines = New-Object System.Collections.Generic.List[object]
    $add = { param($id, $level, $text) $lines.Add([pscustomobject]@{ id = $id; level = $level; text = $text }) }
    $rgScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $tickScope = "$rgScope/providers/Microsoft.App/jobs/$TickJob"
    $hostingFix = "run tools/setup/Initialize-PimHostingAccess.ps1 -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup (an Owner / User Access Administrator of the resource group)"
    $rgReaderFix = "run tools/setup/Confirm-PimInstall.ps1 (or Initialize-PimHostingAccess.ps1) as an Owner / User Access Administrator of $ResourceGroup"

    # ---- the identities (principal ids), read once -------------------------------------------------------------------
    # the identity each SIGNS IN AS (NAM-03, 2026-11-08): reading only identity.principalId after the identity move reported
    # the OLD system identity -- whose rights the move removed, correctly -- as "jobs-operator missing" (internal / ring 1)
    $mgrOid = ''; $tickOid = ''; $mgrRes = $null
    try { $m = & $Arm 'GET' "$rgScope/providers/Microsoft.App/containerApps/$ManagerApp`?api-version=2024-03-01" $null; $mgrRes = $m; $mgrOid = Resolve-PimConvergeSignInOid -Resource $m } catch { }
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
    $d = Get-PimRbacConvergeDecision -Id 'manager-rg-reader' -What "Reader for $ManagerApp on the resource group (System Documentation)" -Assignments $mgrRg.list -ReadError $mgrRg.error `
            -Scope $rgScope -RoleIds @($ids.Reader, $ids.Contributor, $ids.Owner) -Fix $rgReaderFix
    & $add $d.id $(if ($d.action -eq 'noop') { 'info' } else { 'warn' }) $d.line
    # 🔒 SECURE-WEB-1 (framework 12.11f, 2026-11-14): the Manager is INTERNET-FACING and must hold NO never-right anywhere in
    # the resource group (it used to hold 'Container Apps Jobs Operator' on the tick -- a job start accepts a container
    # override). REPORT ONLY (the updater may not change role assignments): a held one is a SECURITY line; Invardia removes it
    # through the Support app. assignedTo() at the resource group lists assignments at, above and below it.
    $mgrNever = & $readAssignments $rgScope $mgrOid
    $dSw = Get-PimWebNeverRightDecision -Assignments $mgrNever.list -ReadError $mgrNever.error -ManagerApp $ManagerApp
    # SECURE-WEB-1 (3.1.26): an identity of the Manager ALSO attached to a job of the install = a SECURITY line (report only)
    $swJobs = $null; $swErr = ''
    try { $jr = & $Arm 'GET' "$rgScope/providers/Microsoft.App/jobs?api-version=2024-03-01" $null; $swJobs = @(if ($jr -and $jr.PSObject.Properties['value']) { @($jr.value) } else { @($jr) }) | Where-Object { $_ } }
    catch { $swErr = ((("$($_.Exception.Message)") -split "`n")[0]).Trim() }
    if ($null -eq $swJobs -and -not $swErr) { $swJobs = @() }
    $dSi = Get-PimWebSharedIdentityDecision -Manager $mgrRes -Jobs $swJobs -ReadError $swErr -ManagerApp $ManagerApp
    & $add 'manager-shared-identity' $dSi.level $dSi.line
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

    # ---- SECURE-WEB-1 (3.1.26): the break-glass check moves from Key Vault into the PIM database, ONCE ---------------
    # The Manager (internet-facing) reads no Key Vault from 3.1.26. An install set up before that has the SHA-256 hex in the
    # vault its Manager names (PIM_EmergencyVault): the updater reads it with ITS OWN identity and stores the PBKDF2 verifier.
    # Where the updater may not read it, ONE yellow line names the command (Set-PimEmergencyPassphrase.ps1 -MigrateFromKeyVault).
    if (-not $Store) { & $add 'emergency-verifier' 'warn' 'emergency passphrase check -- not checked (no store)' }
    else {
        try {
            $evVault = ''; $evSecret = 'PIM-EmergencyPasscode'
            if ($m) {
                foreach ($c in @($m.properties.template.containers | Where-Object { $_ })) {
                    foreach ($e in @($c.env | Where-Object { $_ })) {
                        if ("$($e.name)" -eq 'PIM_EmergencyVault' -and "$($e.value)".Trim()) { $evVault = "$($e.value)".Trim() }
                        if ("$($e.name)" -eq 'PIM_EmergencyPasscodeSecret' -and "$($e.value)".Trim()) { $evSecret = "$($e.value)".Trim() }
                    }
                }
            }
            $kvRead = $KeyVault
            if (-not $kvRead -and (Get-Command Invoke-PimRest -ErrorAction SilentlyContinue)) {
                $kvRead = { param($vn, $sn) "$((Invoke-PimRest -Method GET -Url ('https://{0}.vault.azure.net/secrets/{1}?api-version=7.4' -f $vn, $sn) -Resource 'https://vault.azure.net').value)" }
            }
            $evFix = "run Set-PimEmergencyPassphrase.ps1 -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -VaultName <the vault> -MigrateFromKeyVault (an administrator in the PIM SQL admin group who may read that secret; Settings > Emergency access shows the command)"
            $evCur = & $Store 'get' (Get-PimEmergencyVerifierSettingName) $null
            $ev = Invoke-PimEmergencyVerifierMigration -Current $evCur -LegacyVault $evVault -SecretName $evSecret -Store $Store -KeyVault $kvRead -Fix $evFix
            & $add 'emergency-verifier' $ev.level $ev.text
        } catch { & $add 'emergency-verifier' 'warn' "emergency passphrase check -- not checked: $(((("$($_.Exception.Message)") -split "`n")[0]).Trim())" }
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
