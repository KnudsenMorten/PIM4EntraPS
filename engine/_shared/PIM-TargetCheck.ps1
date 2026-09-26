<#
  PIM-TargetCheck.ps1 -- §79.1 THE DAILY TARGET CHECK (operator 2026-09-25): "make daily check if the actual azure
  resource exist and role exist and report it if it doesn't exist anymore, so delegation can be removed in pim. Make
  option in settings to send mail if issues found - super admin must be able to define cadence in settings".

  Scheduler job 'target-check' (daily by default; enable + cadence on the Jobs page, whose schedule is SuperAdmin-only).
  For every delegation row it reads, it asks whether the thing the row points at still EXISTS:
    * Azure scope   -- the AzScope of a PIM-Assignments-Azure-Resources row: management group, subscription, resource
                       group or resource (ARM GET; a resource through Resource Graph, its resource group deciding "gone"
                       vs "cannot tell")
    * Azure role    -- the role that row grants (AzScopePermission), looked up by name AT that scope (custom roles too)
    * Entra role    -- RoleDefinitionName of PIM-Assignments-Roles-Groups / -Roles-AUs / -Roles-Direct rows, against the
                       tenant's role catalog (built-in and custom)
  A target that answers 404 / is absent is MISSING; one the engine cannot read (403, throttled, error) is UNVERIFIABLE --
  never reported as gone. 🔒 §74: this REPORTS only. Removing the delegation is the operator's decision (the Coverage &
  gaps page lists the rows; they remove them like any other row).

  Stores pim.TenantCache kind 'target-check'; mails NEW missing targets (event 'target-missing', on/off under Alerting)
  with a link to the Coverage & gaps page. Runs on pwsh 7 and Windows PowerShell 5.1.
#>

Set-StrictMode -Off
$script:PimTargetCheckJobType = 'target-check'
$script:PimTargetCheckCacheKind = 'target-check'
$script:PimTargetCheckAlertEvent = 'target-missing'

function Get-PimTargetCheckField {
    param([AllowNull()][object]$Row, [string[]]$Names)
    if ($null -eq $Row) { return '' }
    foreach ($n in $Names) {
        $v = if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { $Row[$n] } else { $null } } else { $p = $Row.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
        if ("$v".Trim()) { return "$v".Trim() }
    }
    return ''
}

function Get-PimTargetCheckFindings {
    <#
      PURE. Rows + three lookups -> findings. -AzScopeState { param($scope) 'yes'|'no'|'unknown' }, -AzRoleState
      { param($scope, $role) 'yes'|'no'|'unknown' }, -EntraRoleNames: the tenant's role display names (or $null when the
      catalog could not be read -> every Entra role is UNVERIFIABLE). Rows marked Action=Remove are skipped (they are on
      their way out already). Returns [ { kind; target; scope; state = missing|unverifiable; rows[]; detail } ].
    #>
    param(
        [AllowNull()][AllowEmptyCollection()][object[]]$AzureRows = @(),
        [AllowNull()][AllowEmptyCollection()][object[]]$EntraRows = @(),
        [Parameter(Mandatory)][scriptblock]$AzScopeState,
        [Parameter(Mandatory)][scriptblock]$AzRoleState,
        [AllowNull()][object]$EntraRoleNames
    )
    $out = New-Object System.Collections.Generic.List[object]
    $isRemove = { param($r) (Get-PimTargetCheckField $r @('Action')) -match '^(?i)remove' }
    $who = { param($r) $t = Get-PimTargetCheckField $r @('GroupTag', 'UserPrincipalName', 'Username'); if ($t) { $t } else { '(row)' } }
    # Azure: one lookup per distinct scope, one per distinct (scope, role).
    $byScope = [ordered]@{}
    foreach ($r in @($AzureRows)) {
        if ($null -eq $r -or (& $isRemove $r)) { continue }
        $sc = Get-PimTargetCheckField $r @('AzScope', 'Scope'); if (-not $sc) { continue }
        $k = $sc.ToLowerInvariant()
        if (-not $byScope.Contains($k)) { $byScope[$k] = @{ scope = $sc; roles = [ordered]@{}; rows = New-Object System.Collections.Generic.List[string] } }
        $byScope[$k].rows.Add((& $who $r))
        $role = Get-PimTargetCheckField $r @('AzScopePermission', 'RoleDefinitionName', 'RoleName')
        if ($role) {
            $rk = $role.ToLowerInvariant()
            if (-not $byScope[$k].roles.Contains($rk)) { $byScope[$k].roles[$rk] = @{ role = $role; rows = New-Object System.Collections.Generic.List[string] } }
            $byScope[$k].roles[$rk].rows.Add((& $who $r))
        }
    }
    foreach ($k in @($byScope.Keys)) {
        $e = $byScope[$k]
        $st = "$(& $AzScopeState $e.scope)"
        if ($st -eq 'no') {
            $out.Add([pscustomobject]@{ kind = 'azure-scope'; target = $e.scope; scope = $e.scope; state = 'missing'; rows = @($e.rows | Select-Object -Unique); detail = 'the Azure scope no longer exists' })
            continue   # its roles cannot be checked on a scope that is gone -- the scope finding says it all
        }
        if ($st -ne 'yes') {
            $out.Add([pscustomobject]@{ kind = 'azure-scope'; target = $e.scope; scope = $e.scope; state = 'unverifiable'; rows = @($e.rows | Select-Object -Unique); detail = 'the engine cannot read this scope (no access, or the read failed) -- NOT reported as gone' })
            continue
        }
        foreach ($rk in @($e.roles.Keys)) {
            $ro = $e.roles[$rk]
            $rs = "$(& $AzRoleState $e.scope $ro.role)"
            if ($rs -eq 'no') { $out.Add([pscustomobject]@{ kind = 'azure-role'; target = $ro.role; scope = $e.scope; state = 'missing'; rows = @($ro.rows | Select-Object -Unique); detail = "the Azure role '$($ro.role)' no longer exists at this scope" }) }
            elseif ($rs -ne 'yes') { $out.Add([pscustomobject]@{ kind = 'azure-role'; target = $ro.role; scope = $e.scope; state = 'unverifiable'; rows = @($ro.rows | Select-Object -Unique); detail = 'the role definitions at this scope could not be read' }) }
        }
    }
    # Entra: against the role catalog (display names, case-insensitive).
    $names = $null
    if ($null -ne $EntraRoleNames) { $names = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase); foreach ($n in @($EntraRoleNames)) { if ("$n".Trim()) { [void]$names.Add("$n".Trim()) } } }
    $byRole = [ordered]@{}
    foreach ($r in @($EntraRows)) {
        if ($null -eq $r -or (& $isRemove $r)) { continue }
        $rn = Get-PimTargetCheckField $r @('RoleDefinitionName', 'RoleName'); if (-not $rn) { continue }
        $k = $rn.ToLowerInvariant()
        if (-not $byRole.Contains($k)) { $byRole[$k] = @{ role = $rn; rows = New-Object System.Collections.Generic.List[string] } }
        $byRole[$k].rows.Add((& $who $r))
    }
    foreach ($k in @($byRole.Keys)) {
        $e = $byRole[$k]
        if ($null -eq $names) { $out.Add([pscustomobject]@{ kind = 'entra-role'; target = $e.role; scope = 'directory'; state = 'unverifiable'; rows = @($e.rows | Select-Object -Unique); detail = 'the directory role catalog could not be read' }); continue }
        if (-not $names.Contains($e.role)) { $out.Add([pscustomobject]@{ kind = 'entra-role'; target = $e.role; scope = 'directory'; state = 'missing'; rows = @($e.rows | Select-Object -Unique); detail = 'no directory role (built-in or custom) has this name any more' }) }
    }
    return @($out.ToArray())
}

function Get-PimTargetCheckAzScopeState {
    # LIVE. ARM answers for a scope: 200 -> yes, 404 -> no, anything else -> unknown. A resource (deeper than a resource
    # group) goes through Resource Graph; if Graph does not return it, its RESOURCE GROUP decides: gone RG -> no, readable
    # RG -> no (the resource is gone from a group we can read), unreadable -> unknown.
    param([Parameter(Mandatory)][string]$Scope)
    $s = "$Scope".Trim().TrimEnd('/')
    # 🔴 R25-19: ARM answers a subscription the caller has NO RIGHTS on with 404 SubscriptionNotFound -- the same answer a
    # deleted one gets. That (for the subscription, or anything under it) is 'no' ONLY when the subscription list the
    # engine can read shows it Deleted; otherwise 'unknown' -- never a false "gone" for a subscription it merely cannot see.
    $subGone = {
        param($subPath)
        $sid = ("$subPath" -replace '(?i)^/subscriptions/', '').Trim('/').ToLowerInvariant()
        try {
            $l = Invoke-PimArm -Path '/subscriptions' -ApiVersion '2022-12-01'
            $hit = @(@($l.value) | Where-Object { "$($_.subscriptionId)".ToLowerInvariant() -eq $sid }) | Select-Object -First 1
            if ($hit -and "$($hit.state)" -match '(?i)^deleted$') { return 'no' }
        } catch { }
        return 'unknown'
    }
    $probe = {
        param($path, $api)
        try { [void](Invoke-PimArm -Path $path -ApiVersion $api); return 'yes' }
        catch {
            $m = "$($_.Exception.Message)"
            if ($m -match 'SubscriptionNotFound') { $sp = [regex]::Match($path, '(?i)^/subscriptions/[^/]+').Value; if ($sp) { return (& $subGone $sp) }; return 'unknown' }
            if ($m -match 'HTTP 404|ResourceNotFound|ResourceGroupNotFound|NotFound') { return 'no' } ; return 'unknown'
        }
    }
    if ($s -match '(?i)^/providers/Microsoft\.Management/managementGroups/[^/]+$') { return (& $probe $s '2021-04-01') }
    if ($s -match '(?i)^/subscriptions/[^/]+$') { return (& $probe $s '2022-12-01') }
    if ($s -match '(?i)^(/subscriptions/[^/]+/resourceGroups/[^/]+)$') { return (& $probe $s '2021-04-01') }
    if ($s -match '(?i)^(?<rg>/subscriptions/[^/]+/resourceGroups/[^/]+)/providers/.+') {
        $rg = $Matches['rg']
        $rgState = & $probe $rg '2021-04-01'
        if ($rgState -eq 'no') { return 'no' }          # the whole resource group is gone
        if ($rgState -ne 'yes') { return 'unknown' }    # cannot read the group -> cannot tell
        # The group is readable. Only a Resource Graph query that SUCCEEDED and returned nothing says "gone"; a query that
        # failed (no permission, throttled) says nothing -- reporting that as a deleted resource would be a false alarm.
        try {
            $q = @{ query = ("resources | where id =~ '{0}' | project id" -f $s.Replace("'", "''")) }
            $res = Invoke-PimArm -Method POST -Path '/providers/Microsoft.ResourceGraph/resources' -ApiVersion '2022-10-01' -Body $q
            if (@($res.data).Count -gt 0) { return 'yes' }
            return 'no'
        } catch { return 'unknown' }
    }
    return 'unknown'
}

function Get-PimTargetCheckAzRoleState {
    # LIVE. A role by NAME at the scope (built-in and the custom roles assignable there): found -> yes, none -> no,
    # read failed -> unknown.
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$Role)
    try {
        $f = [uri]::EscapeDataString("roleName eq '$($Role.Replace("'", "''"))'")
        $r = Invoke-PimArm -Path ("{0}/providers/Microsoft.Authorization/roleDefinitions?`$filter={1}" -f "$Scope".TrimEnd('/'), $f) -ApiVersion '2022-04-01'
        if (@($r.value).Count -gt 0) { return 'yes' } else { return 'no' }
    } catch { return 'unknown' }
}

function Invoke-PimTargetCheckJob {
    <#
      The job handler. Reads the rows, asks the tenant, stores { checkedUtc; missing; unverifiable; findings[] } in
      pim.TenantCache 'target-check', and mails NEW missing targets (event 'target-missing'). A finding is not a job
      failure: the job succeeds and says how many targets are gone. Never removes anything (§74).
    #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    # 🔴 R25-27: a row read that FAILS is not "no rows". It used to be swallowed, and a SQL failure then stored and reported
    # "0 row(s) checked -- 0 target(s) no longer exist" as a clean run, over the last real result.
    $readErrors = New-Object System.Collections.Generic.List[string]
    # Get-PimDesiredRowsFromStore catches a SQL failure itself (a warning + an empty set) and records it only as
    # $global:PIM_DesiredResolved[<entity>] = $false -- so that flag is read too, not just an exception.
    $rows = {
        param($e)
        if ($global:PIM_DesiredResolved -is [hashtable]) { [void]$global:PIM_DesiredResolved.Remove($e) }
        $got = @()
        try { $got = @(Get-PimDesiredRows -Entity $e | Where-Object { $null -ne $_ }) } catch { $readErrors.Add("${e}: $($_.Exception.Message)"); return @() }
        if ($global:PIM_DesiredResolved -is [hashtable] -and $global:PIM_DesiredResolved.ContainsKey($e) -and -not $global:PIM_DesiredResolved[$e] -and (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue)) {
            $readErrors.Add("${e}: the store read did not resolve (see the warning above)")
        }
        return $got
    }
    # 🪤 @() around EACH call: one row comes back unrolled as a bare object, and object + object throws.
    $az = @(& $rows 'PIM-Assignments-Azure-Resources')
    $en = @(@(& $rows 'PIM-Assignments-Roles-Groups') + @(& $rows 'PIM-Assignments-Roles-AUs') + @(& $rows 'PIM-Assignments-Roles-Direct'))
    if ($readErrors.Count) { throw ("[target-check] the delegation rows could not be read -- nothing was checked and the last result stands: " + ($readErrors -join '; ')) }
    $names = $null
    if ($en.Count) {
        try { $names = @(Invoke-PimGraph -Path '/roleManagement/directory/roleDefinitions?$select=displayName' -All | ForEach-Object { "$($_.displayName)" }) }
        catch { $names = $null }
    }
    $findings = @(Get-PimTargetCheckFindings -AzureRows $az -EntraRows $en -EntraRoleNames $names `
                    -AzScopeState { param($s) Get-PimTargetCheckAzScopeState -Scope $s } -AzRoleState { param($s, $r) Get-PimTargetCheckAzRoleState -Scope $s -Role $r })
    $missing = @($findings | Where-Object { $_.state -eq 'missing' })
    $unver = @($findings | Where-Object { $_.state -eq 'unverifiable' })
    $prev = $null
    if (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue) { try { $prev = Get-PimTenantCacheEntry -Kind $script:PimTargetCheckCacheKind } catch { $prev = $null } }
    $prevKeys = @{}
    if ($prev) { $pv = if ($prev.PSObject.Properties['value']) { $prev.value } else { $prev }; foreach ($f in @($pv.findings)) { if ($f -and "$($f.state)" -eq 'missing') { $prevKeys["$($f.kind)|$($f.scope)|$($f.target)".ToLowerInvariant()] = $true } } }
    $new = @($missing | Where-Object { -not $prevKeys.ContainsKey("$($_.kind)|$($_.scope)|$($_.target)".ToLowerInvariant()) })
    $doc = [ordered]@{ checkedUtc = $NowUtc.ToUniversalTime().ToString('o'); azureRows = $az.Count; entraRows = $en.Count
                       missing = $missing.Count; unverifiable = $unver.Count; findings = @($findings) }
    if (-not $WhatIf -and (Get-Command Set-PimTenantCacheEntry -ErrorAction SilentlyContinue)) { [void](Set-PimTenantCacheEntry -Kind $script:PimTargetCheckCacheKind -Value $doc) }
    if ($new.Count -and -not $WhatIf -and (Get-Command Send-PimJobAlertViaNotify -ErrorAction SilentlyContinue)) {
        $enc = { param($t) [System.Net.WebUtility]::HtmlEncode("$t") }
        $lines = @($new | Select-Object -First 20 | ForEach-Object { '&bull; <b>' + (& $enc $_.target) + '</b> (' + (& $enc $_.kind) + $(if ($_.kind -ne 'entra-role') { ' @ ' + (& $enc $_.scope) } else { '' }) + ') &mdash; ' + (& $enc $_.detail) + '<br>&nbsp;&nbsp;&nbsp;delegations: ' + (& $enc (@($_.rows) -join ', ')) })
        $detail = ("{0} delegation target(s) no longer exist. PIM changed NOTHING -- decide whether to remove the delegation rows.<br><br>" -f $new.Count) + ($lines -join '<br>') + $(if ($new.Count -gt 20) { "<br>... and $($new.Count - 20) more on the Coverage & gaps page." } else { '' })
        try { [void](Send-PimJobAlertViaNotify -Event $script:PimTargetCheckAlertEvent -Title ("{0} delegation target(s) no longer exist" -f $new.Count) -Detail $detail -LinkTab 'coverage' -DebounceMinutes 1440 `
                        -Headline 'Some delegations point at Azure resources or roles that no longer exist.' -Action 'Open Coverage &amp; gaps, review the delegations listed and remove the ones that are no longer needed. PIM never removes them by itself.') } catch { Write-Warning "[target-check] the alert could not be sent: $($_.Exception.Message)" }
    }
    [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf
        detail = ("target-check: {0} Azure row(s), {1} Entra role row(s) checked -- {2} target(s) no longer exist ({3} new), {4} could not be verified" -f $az.Count, $en.Count, $missing.Count, $new.Count, $unver.Count) }
}
