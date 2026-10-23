#Requires -Version 5.1
<#
.SYNOPSIS
    SECPACK-SQL-AUDIT (owner 2026-10-23 wizard, "SQL auditing at install"): the install's SQL server audits to the install's
    own Log Analytics workspace, kept 90 days -- what the security pack says ("SQL auditing is on (90 days)"; "every schema
    change is in the SQL audit, outside the database"). Before this, no installer step configured it: the claim was false.

.DESCRIPTION
    ONE converge, two call sites: the installer (New-PimHostingPrerequisites, after the SQL server exists) and the in-cloud
    updater (an EXISTING install, on its next update -- framework 12.16 CONVERGE-DEFAULTS). Three idempotent ARM writes, each
    only when the read differs:
      1. Microsoft.Sql/servers/<srv>/auditingSettings/default -- state Enabled, isAzureMonitorTargetEnabled true, the action
         groups below. A customer's OWN settings are kept: their action groups are added to, a storage target stays.
      2. Microsoft.Sql/servers/<srv>/databases/master/providers/Microsoft.Insights/diagnosticSettings/pim-sql-audit -- category
         SQLSecurityAuditEvents to the workspace, resource-specific tables (Azure sends SERVER audit to Log Analytics only
         through the master database's diagnostic setting).
      3. The workspace table SQLSecurityAuditEvents kept 90 days (raise only; a longer retention is the customer's).
    COST: the action groups are the security events only -- sign-ins (success + failure), schema / object changes,
    principal / role-member / permission changes, audit changes. NOT BATCH_COMPLETED_GROUP (every query): the engine and the
    Manager run queries all day, and that group alone would be most of the workspace's ingestion.
    Seam: -Arm { param($method, $path, $body) } with the api-version IN the path (the installer's $prereqArm and the updater's
    $armSeam both have this shape). Rights: Contributor on the resource group is enough for all three.
    Returns @{ ok; changed; warnings; lines = @(@{ id; level = info | changed | warn; text }); workspaceId }. NEVER throws.
#>

$script:PimSqlAuditSettingName = 'pim-sql-audit'

function Get-PimSqlAuditActionGroups {
    <# PURE. The audit action groups PIM switches on -- security events, never every query (see the file header: cost). #>
    @('SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP',
      'FAILED_DATABASE_AUTHENTICATION_GROUP',
      'SCHEMA_OBJECT_CHANGE_GROUP',
      'DATABASE_OBJECT_CHANGE_GROUP',
      'DATABASE_PRINCIPAL_CHANGE_GROUP',
      'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
      'DATABASE_PERMISSION_CHANGE_GROUP',
      'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
      'AUDIT_CHANGE_GROUP')
}

function Get-PimSqlAuditRetentionDays { return 90 }

function Get-PimSqlAuditPlan {
    <#
      PURE. The current auditingSettings resource ($null = none read) -> @{ write; body; reason }. write = $false when it
      already audits to Azure Monitor with every PIM group. The body keeps every property the customer set and only adds:
      state Enabled, isAzureMonitorTargetEnabled true, the union of the action groups.
    #>
    param([object]$Current)
    $want = @(Get-PimSqlAuditActionGroups)
    $cp = $(if ($Current -and $Current.properties) { $Current.properties } else { $null })
    $props = [ordered]@{ state = "$($cp.state)"; isAzureMonitorTargetEnabled = $cp.isAzureMonitorTargetEnabled; auditActionsAndGroups = @($cp.auditActionsAndGroups) }
    # The customer's OWN storage target is kept (GET returns an all-zero subscription and an empty endpoint when there is none --
    # those are never sent back). A storage target with a key needs the key again: such a PUT is refused and reported.
    if ($cp -and "$($cp.storageEndpoint)".Trim()) {
        foreach ($k in @('storageEndpoint', 'storageAccountSubscriptionId', 'retentionDays', 'isStorageSecondaryKeyInUse', 'isManagedIdentityInUse')) {
            if ($null -ne $cp.$k) { $props[$k] = $cp.$k }
        }
    }
    if ($cp -and $null -ne $cp.isDevopsAuditEnabled) { $props['isDevopsAuditEnabled'] = $cp.isDevopsAuditEnabled }
    if ($cp -and [int]"$($cp.queueDelayMs)" -gt 0) { $props['queueDelayMs'] = [int]$cp.queueDelayMs }
    $haveGroups = @(@($props['auditActionsAndGroups']) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToUpperInvariant() })
    $missing = @($want | Where-Object { $haveGroups -notcontains $_ })
    $reasons = @()
    if ("$($props['state'])" -ne 'Enabled') { $reasons += "state $(if ("$($props['state'])".Trim()) { "$($props['state'])" } else { 'not set' })" }
    if ($props['isAzureMonitorTargetEnabled'] -ne $true) { $reasons += 'no Log Analytics target' }
    if ($missing.Count) { $reasons += "$($missing.Count) action group(s) missing" }
    if (-not $reasons.Count) { return @{ write = $false; body = $null; reason = 'already on' } }
    $props['state'] = 'Enabled'
    $props['isAzureMonitorTargetEnabled'] = $true
    $props['auditActionsAndGroups'] = @(@($haveGroups) + @($missing))
    # A storage target the customer did not set must not be half-configured: no storage fields are invented here.
    return @{ write = $true; body = @{ properties = $props }; reason = ($reasons -join ', ') }
}

function Get-PimSqlAuditDiagnosticBody {
    <# PURE. The master database's diagnostic setting: SQLSecurityAuditEvents -> the workspace, resource-specific tables. #>
    param([Parameter(Mandatory)][string]$WorkspaceResourceId)
    @{ properties = @{ workspaceId = $WorkspaceResourceId; logAnalyticsDestinationType = 'Dedicated'
                       logs = @(@{ category = 'SQLSecurityAuditEvents'; enabled = $true }) } }
}

function Test-PimSqlAuditDiagnosticOk {
    <# PURE. Does a diagnostic setting already send SQLSecurityAuditEvents to this workspace? #>
    param([object]$Current, [Parameter(Mandatory)][string]$WorkspaceResourceId)
    if (-not $Current -or -not $Current.properties) { return $false }
    if ("$($Current.properties.workspaceId)".Trim().ToLowerInvariant() -ne "$WorkspaceResourceId".Trim().ToLowerInvariant()) { return $false }
    $cat = @(@($Current.properties.logs) | Where-Object { $_ -and "$($_.category)" -eq 'SQLSecurityAuditEvents' -and $_.enabled -eq $true })
    return [bool]$cat.Count
}

function Invoke-PimSqlAuditConverge {
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [AllowEmptyString()][string]$SqlServer,
        [Parameter(Mandatory)][scriptblock]$Arm,
        [string]$Workspace = '',              # the workspace NAME; '' = the one in the resource group (law-pim-* first)
        [string]$SqlResourceGroup = ''        # '' = -ResourceGroup
    )
    $lines = New-Object System.Collections.Generic.List[object]
    $add = { param($id, $level, $text) $lines.Add([pscustomobject]@{ id = $id; level = $level; text = $text }) }
    $get = { param($p) try { & $Arm 'GET' $p $null } catch { $null } }
    $changed = 0; $wsId = ''
    $done = { [pscustomobject]@{ ok = -not @($lines | Where-Object { $_.level -eq 'warn' }).Count; changed = $changed
                                 warnings = @($lines | Where-Object { $_.level -eq 'warn' }).Count; lines = @($lines.ToArray()); workspaceId = $wsId } }
    # an FQDN (tcp:x.database.windows.net,1433) or a name -> the name
    $srv = ("$SqlServer".Trim() -replace '^tcp:', '' -replace ',\d+$', '').Split('.')[0].ToLowerInvariant()
    if (-not $srv) { & $add 'sql-audit' 'warn' 'SQL auditing: no SQL server named -- not checked'; return (& $done) }
    $rg = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
    $srg = if ("$SqlResourceGroup".Trim()) { "/subscriptions/$SubscriptionId/resourceGroups/$("$SqlResourceGroup".Trim())" } else { $rg }
    $srvPath = "$srg/providers/Microsoft.Sql/servers/$srv"
    $sqlApi = 'api-version=2021-11-01'; $diagApi = 'api-version=2021-05-01-preview'; $lawApi = 'api-version=2022-10-01'
    try {
        # The server is usually in the install's resource group; an install whose SQL lives elsewhere is found in the subscription.
        if (-not (& $get "$srvPath`?$sqlApi")) {
            $sl = & $get "/subscriptions/$SubscriptionId/providers/Microsoft.Sql/servers?$sqlApi"
            $hit = @(@($sl.value) | Where-Object { $_ -and "$($_.name)".ToLowerInvariant() -eq $srv }) | Select-Object -First 1
            if (-not $hit) { & $add 'sql-audit' 'warn' "SQL auditing: SQL server '$srv' is not visible to this identity -- not checked"; return (& $done) }
            $srvPath = "$($hit.id)"
        }
        # ---- the workspace -------------------------------------------------------------------------------------------------
        $ws = $null
        if ("$Workspace".Trim()) { $ws = & $get "$rg/providers/Microsoft.OperationalInsights/workspaces/$("$Workspace".Trim())`?$lawApi" }
        if (-not $ws) {
            $list = & $get "$rg/providers/Microsoft.OperationalInsights/workspaces`?$lawApi"
            $all = @(@($list.value) | Where-Object { $_ -and "$($_.id)" })
            $ws = @($all | Where-Object { "$($_.name)" -like 'law-pim-*' } | Select-Object -First 1)[0]
            if (-not $ws -and $all.Count -eq 1) { $ws = $all[0] }
        }
        if (-not $ws -or -not "$($ws.id)".Trim()) {
            & $add 'sql-audit' 'warn' "SQL auditing: no Log Analytics workspace found in $ResourceGroup -- SQL auditing was NOT switched on (name one with -Workspace)"
            return (& $done)
        }
        $wsId = "$($ws.id)".Trim()
        # ---- 1. the server's auditing settings ---------------------------------------------------------------------------------
        $cur = & $get "$srvPath/auditingSettings/default`?$sqlApi"
        $plan = Get-PimSqlAuditPlan -Current $cur
        if ($plan.write) {
            [void](& $Arm 'PUT' "$srvPath/auditingSettings/default`?$sqlApi" $plan.body)
            $changed++; & $add 'sql-audit-server' 'changed' "SQL auditing: switched on for $srv ($($plan.reason))"
        } else { & $add 'sql-audit-server' 'info' "SQL auditing: on for $srv" }
        # ---- 2. the master database's diagnostic setting -> the workspace --------------------------------------------------------
        $dsPath = "$srvPath/databases/master/providers/Microsoft.Insights/diagnosticSettings/$($script:PimSqlAuditSettingName)`?$diagApi"
        $ds = & $get $dsPath
        if (-not (Test-PimSqlAuditDiagnosticOk -Current $ds -WorkspaceResourceId $wsId)) {
            [void](& $Arm 'PUT' $dsPath (Get-PimSqlAuditDiagnosticBody -WorkspaceResourceId $wsId))
            $changed++; & $add 'sql-audit-target' 'changed' "SQL auditing: audit events of $srv go to the workspace $($ws.name)"
        } else { & $add 'sql-audit-target' 'info' "SQL auditing: audit events go to the workspace $($ws.name)" }
        # ---- 3. 90 days in the workspace (raise only) -----------------------------------------------------------------------------
        $days = Get-PimSqlAuditRetentionDays
        $tPath = "$wsId/tables/SQLSecurityAuditEvents`?$lawApi"
        $t = & $get $tPath
        if (-not $t) {
            & $add 'sql-audit-retention' 'info' "SQL auditing: the audit table is not in the workspace yet (it appears with the first event) -- the next update sets $days days"
        } elseif ([int]"$($t.properties.retentionInDays)" -lt $days) {
            try {
                [void](& $Arm 'PATCH' $tPath @{ properties = @{ retentionInDays = $days } })
                $changed++; & $add 'sql-audit-retention' 'changed' "SQL auditing: audit events kept $days days (was $([int]"$($t.properties.retentionInDays)"))"
            } catch { & $add 'sql-audit-retention' 'warn' "SQL auditing: the $days-day retention was refused: $($_.Exception.Message)" }
        } else { & $add 'sql-audit-retention' 'info' "SQL auditing: audit events kept $([int]"$($t.properties.retentionInDays)") days" }
    } catch {
        & $add 'sql-audit' 'warn' "SQL auditing: not completed: $($_.Exception.Message)"
    }
    return (& $done)
}
