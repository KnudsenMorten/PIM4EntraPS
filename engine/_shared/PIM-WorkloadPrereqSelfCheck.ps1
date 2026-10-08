<#
  PIM4EntraPS -- 97.1 WORKLOAD PREREQUISITES, CHECKED BY PIM ITSELF (scheduler job 'workload-prereqs').

  Owner 2026-10-08, on the Templates page of a new production managing tenant: "we dont support certificates. furthermore
  i dont understand the need to onboard entra id roles, azure roles, etc. does the engine not have the necessary
  permissions for this". The engine there held all 28 Graph application roles, and still every template said "not
  checked -- run Initialize-PimWorkloadPrereqs.ps1 ..." with a management app id and a certificate thumbprint to fill in,
  and the Intune role assignment was HELD until a person had run that script.

  What this file does: the tick runs every prerequisite an API can answer AS THE ENGINE ITSELF -- the same checks
  (tools\setup\_PimWorkloadPrereqRunner.ps1, in its read-only self-check mode: it never grants, creates or changes
  anything) -- and records the result in the SAME pim.Settings 'WorkloadPrereqs' (ranBy 'engine self-check'), MERGED with
  what a person recorded (Merge-PimWorkloadPrereqRecord: a portal confirmation is kept, a verified result the engine
  cannot read itself is kept), read back and audited. A check the engine cannot read stays "not checked" with the reason
  -- never green by assumption. The assignment gate (Get-PimWorkloadAssignmentGate) is unchanged: hold until green; green
  now comes from here, so Entra roles and Intune on a fully permissioned engine turn green with no human step.

  Cadence: daily (the job catalog, Jobs page) + "Check again" on the prerequisite chips (Run now on this job). The job only
  READS the tenant and writes one pim.Settings row, so it holds no engine area (job:workload-prereqs only).

  Every live call is through the seams the runner already uses (Invoke-PimGraph / Invoke-PimArm / Invoke-PimRest /
  Get-PimRestToken), so tests\Test-PimWorkloadPrereqSelfCheck.ps1 runs the whole job offline against stubs.
  PS 5.1-safe.
#>

Set-StrictMode -Off

$script:PimWorkloadPrereqSelfCheckJobType = 'workload-prereqs'
$script:PimWorkloadPrereqSelfCheckActor   = 'engine self-check'

function Get-PimWorkloadPrereqSelfCheckRoot {
    # The solution root (engine\_shared -> ..\..). A function: a dot-sourced file's $PSScriptRoot is only valid at load.
    if ($script:PimWorkloadPrereqSelfCheckSolRoot) { return $script:PimWorkloadPrereqSelfCheckSolRoot }
    return (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
}
$script:PimWorkloadPrereqSelfCheckSolRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function Get-PimWorkloadPrereqRoleMapFromSource {
    <#
      The Engine Graph application role map (name -> id) READ from tools\setup\_PimSetupShared.ps1 by parsing it (the
      $script:PimGraphAppRoles hashtable) -- never dot-sourced: that file is a 1,000-line setup helper with side effects
      the tick must not take on, and copying the list here would be a second role map (BUG-147 / BUG-181: two lists drift).
      Returns an ordered hashtable; THROWS when the map is not found (a self-check against no list proves nothing).
    #>
    param([string]$Path = (Join-Path (Get-PimWorkloadPrereqSelfCheckRoot) 'tools\setup\_PimSetupShared.ps1'))
    if (-not (Test-Path -LiteralPath $Path)) { throw "the Graph role map source is missing: $Path" }
    $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errs)
    $asg = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and "$($n.Left.Extent.Text)" -ieq '$script:PimGraphAppRoles' }, $true))
    if (-not $asg.Count) { throw "no `$script:PimGraphAppRoles map in $Path" }
    $ht = @($asg[0].Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true))[0]
    if (-not $ht) { throw "`$script:PimGraphAppRoles in $Path is not a hashtable literal" }
    $map = [ordered]@{}
    foreach ($kv in $ht.KeyValuePairs) {
        $k = if ($kv.Item1 -is [System.Management.Automation.Language.StringConstantExpressionAst]) { "$($kv.Item1.Value)" } else { "$($kv.Item1.Extent.Text)".Trim("'", '"') }
        $v = "$($kv.Item2.Extent.Text)".Trim().Trim("'", '"')
        if ($k) { $map[$k] = $v }
    }
    if (-not $map.Count) { throw "`$script:PimGraphAppRoles in $Path is empty" }
    return $map
}

function Get-PimWorkloadPrereqSelfCheckToolVersion {
    try { return "$(Get-Content -Raw -LiteralPath (Join-Path (Get-PimWorkloadPrereqSelfCheckRoot) 'VERSION'))".Trim() } catch { return '' }
}

function Import-PimWorkloadPrereqRunner {
    # The runner's functions, loaded when the tick has not loaded them yet. Returns $true when they are available.
    if (Get-Command Invoke-PimWorkloadPrereqRun -ErrorAction SilentlyContinue) { return $true }
    $p = Join-Path (Get-PimWorkloadPrereqSelfCheckRoot) 'tools\setup\_PimWorkloadPrereqRunner.ps1'
    if (-not (Test-Path -LiteralPath $p)) { return $false }
    . $p
    # Dot-sourced inside a function the definitions are local to it -- re-export the ones the job calls.
    foreach ($f in @(Get-Command -CommandType Function | Where-Object { $_.ScriptBlock.File -and "$($_.ScriptBlock.File)" -ieq $p })) {
        Set-Item -Path "function:global:$($f.Name)" -Value $f.ScriptBlock
    }
    return [bool](Get-Command Invoke-PimWorkloadPrereqRun -ErrorAction SilentlyContinue)
}

function Get-PimWorkloadPrereqSelfCheckIdentity {
    <#
      WHO the engine is, from its own Graph token (oid / appid / tid / roles) -- the identity the checks are about and
      the caller at the same time. displayName from Graph when readable. THROWS when no token can be had: a self-check
      that cannot even sign in has nothing to record.
    #>
    $tok = Get-PimRestToken -Resource 'graph'
    $claims = ConvertFrom-PimPrereqJwt -Token $tok
    if (-not $claims -or -not "$($claims.oid)".Trim()) { throw 'the engine''s Graph token could not be read (no object id) -- nothing was checked' }
    $oid = "$($claims.oid)".Trim().ToLowerInvariant()
    $sp = $null
    try { $sp = Invoke-PimGraph -Path "/servicePrincipals/$oid`?`$select=id,appId,displayName,servicePrincipalType" } catch { $sp = $null }
    $kind = if ($sp -and "$($sp.servicePrincipalType)" -ieq 'ManagedIdentity') { 'managedIdentity' } elseif ($sp) { 'application' } elseif ("$($claims.xms_mirid)".Trim()) { 'managedIdentity' } else { 'application' }
    $engine = @{ objectId = $oid; appId = $(if ($sp -and "$($sp.appId)") { "$($sp.appId)" } else { "$($claims.appid)" })
                 displayName = $(if ($sp -and "$($sp.displayName)") { "$($sp.displayName)" } else { 'PIM engine' }); kind = $kind }
    return [pscustomobject]@{ claims = $claims; engine = $engine; tenantId = "$($claims.tid)".Trim().ToLowerInvariant(); tokenRoles = @($claims.roles | Where-Object { "$_".Trim() }) }
}

function New-PimWorkloadPrereqSelfCheckContext {
    # The runner context for the read-only self-check: the engine is both the caller and the identity checked.
    param([Parameter(Mandatory)][object]$Identity, [hashtable]$RoleMap = @{}, [object[]]$AzureRows = @(), [string]$PowerBiGroupName = 'grp-pim-powerbi-admin-api')
    $names = @(@($RoleMap.Keys) | Where-Object { "$_" -and "$_" -ne 'Mail.Send' } | Sort-Object)
    return @{
        tenantId = "$($Identity.tenantId)"; engine = $Identity.engine; callerClaims = $Identity.claims; ranBy = $script:PimWorkloadPrereqSelfCheckActor
        roleMap = $RoleMap; engineRoleNames = $names; tokenRoles = @($Identity.tokenRoles)
        confirm = @(); skipDataOperations = $false; sentinelWorkspaceId = ''; enableSentinel = $false
        hostingSubscriptionId = ''; hostingResourceGroup = ''; pollSeconds = 5
        powerBiGroupName = $(if ("$PowerBiGroupName".Trim()) { "$PowerBiGroupName".Trim() } else { 'grp-pim-powerbi-admin-api' })
        azureScopes = @(); grantUaa = $false; engineCertThumbprint = ''; graphSp = $null; engineAssignments = $null; azureRows = @($AzureRows)
        selfCheck = $true
        should = { param($t, $a) $false }
    }
}

function Get-PimWorkloadPrereqSelfCheckGroupName {
    # The Power BI admin-API group a person's run used (a -PowerBiSecurityGroupName other than the default is kept).
    param([object]$Stored)
    $r = Get-PimWorkloadPrereqStoredRecord -Stored $Stored -Workload 'PowerBI'
    foreach ($c in @(Get-PimWorkloadPrereqRecordField -Object $r -Name 'checks')) {
        if ($c -and "$($c.id)" -in @('powerbi.group', 'powerbi.groupMember')) {
            $g = "$(Get-PimWorkloadPrereqRecordField -Object $c -Name 'groupName')".Trim()
            if ($g) { return $g }
            if ("$($c.id)" -eq 'powerbi.group' -and "$($c.detail)" -match "^(created )?'([^']+)'") { return $Matches[2] }
        }
    }
    return 'grp-pim-powerbi-admin-api'
}

function Invoke-PimWorkloadPrereqSelfCheck {
    <#
      The self-check, every seam injected (the job handler passes the live ones; the tests pass stubs):
        -ReadStored  { }            -> the current pim.Settings 'WorkloadPrereqs' value (parsed) or $null; THROW = unreadable
        -WriteStored { param($v) }  -> write the whole value (and nothing else)
        -Audit       { param($action, $target, $before, $after) }
        -AzureRows   { }            -> the PIM-Assignments-Azure-Resources rows; THROW = unreadable (AzureRbac stays as stored)
      Returns @{ ok; whatIf; results = @{ <workload> = <merged record> }; errors = @{ <workload> = <message> }; detail }.
      A workload whose run throws keeps its stored record (the error is reported, never recorded as a result).
    #>
    param([Parameter(Mandatory)][object]$Identity, [hashtable]$RoleMap = @{}, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf,
          [string[]]$Workloads = @(), [Parameter(Mandatory)][scriptblock]$ReadStored, [Parameter(Mandatory)][scriptblock]$WriteStored,
          [scriptblock]$Audit = { param($a, $t, $b, $f) }, [scriptblock]$AzureRows = { @() })
    $want = @(if (@($Workloads | Where-Object { "$_".Trim() }).Count) { @($Workloads | Where-Object { (Get-PimWorkloadPrereqWorkloads) -contains "$_" }) } else { Get-PimWorkloadPrereqWorkloads })
    $stored = & $ReadStored
    $rowsErr = ''; $rows = @()
    try { $rows = @(& $AzureRows | Where-Object { $null -ne $_ }) } catch { $rowsErr = "$($_.Exception.Message)" }
    $ctx = New-PimWorkloadPrereqSelfCheckContext -Identity $Identity -RoleMap $RoleMap -AzureRows $rows -PowerBiGroupName (Get-PimWorkloadPrereqSelfCheckGroupName -Stored $stored)
    $ver = Get-PimWorkloadPrereqSelfCheckToolVersion
    $fresh = [ordered]@{}; $errors = [ordered]@{}
    foreach ($w in $want) {
        if ($w -eq 'AzureRbac' -and $rowsErr) { $errors[$w] = "the delegation rows (PIM-Assignments-Azure-Resources) could not be read: $rowsErr"; continue }
        try {
            $checks = @(Invoke-PimWorkloadPrereqRun -Workload $w -Ctx $ctx)
            $at = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            $checks = @($checks | ForEach-Object { Copy-PimWorkloadPrereqCheck -Check $_ -Set @{ by = $script:PimWorkloadPrereqSelfCheckActor; checkedUtc = $at } })
            $fresh[$w] = Get-PimWorkloadPrereqResult -Workload $w -Checks $checks -RanUtc $NowUtc -RanBy $script:PimWorkloadPrereqSelfCheckActor -ToolVersion $ver `
                           -TenantId "$($Identity.tenantId)" -EngineIdentity "$($Identity.engine.displayName) ($($Identity.engine.objectId))" -EngineObjectId "$($Identity.engine.objectId)"
        } catch { $errors[$w] = "$($_.Exception.Message)" }
    }
    $res = [ordered]@{ ok = $true; whatIf = [bool]$WhatIf; results = [ordered]@{}; errors = $errors; detail = '' }
    if (-not $fresh.Count) {
        $res.ok = $false
        $res.detail = "workload-prereqs: nothing could be checked -- $(@($errors.Keys | ForEach-Object { "${_}: $($errors[$_])" }) -join '; ')"
        return $res
    }
    if (-not $WhatIf) {
        # Re-read right before the write: a person may have pressed Confirm while the checks ran (seconds to minutes).
        $cur = & $ReadStored
        $value = $cur; $before = [ordered]@{}; $after = [ordered]@{}
        foreach ($w in @($fresh.Keys)) {
            $old = Get-PimWorkloadPrereqStoredRecord -Stored $cur -Workload $w
            $before[$w] = $(if ($old) { "$($old.state)" } else { 'notRun' })
            $m = Merge-PimWorkloadPrereqRecord -Stored $old -Fresh $fresh[$w]
            $value = Merge-PimWorkloadPrereqsSetting -Current $value -Result $m
            $res.results[$w] = $m; $after[$w] = "$($m.state)"
        }
        & $WriteStored $value
        $back = & $ReadStored
        foreach ($w in @($res.results.Keys)) {
            $b = Get-PimWorkloadPrereqStoredRecord -Stored $back -Workload $w
            $bRan = ConvertTo-PimWorkloadPrereqUtcText -Value (Get-PimWorkloadPrereqRecordField -Object $b -Name 'ranUtc')
            if (-not $b -or "$($b.state)" -ne "$($res.results[$w].state)" -or $bRan -ne "$($res.results[$w].ranUtc)") {
                throw "[workload-prereqs] read-back FAILED: pim.Settings WorkloadPrereqs.$w is '$($b.state)' @ '$bRan', expected '$($res.results[$w].state)' @ '$($res.results[$w].ranUtc)'"
            }
        }
        try { & $Audit 'settings.workloadprereqs.selfcheck' 'WorkloadPrereqs' $before $after } catch { Write-Warning "[workload-prereqs] the audit event could not be written: $($_.Exception.Message)" }
    } else {
        foreach ($w in @($fresh.Keys)) { $res.results[$w] = Merge-PimWorkloadPrereqRecord -Stored (Get-PimWorkloadPrereqStoredRecord -Stored $stored -Workload $w) -Fresh $fresh[$w] }
    }
    $parts = @($res.results.Keys | ForEach-Object { "$_=$($res.results[$_].state)" })
    $errTxt = if ($errors.Count) { " | not checked: $(@($errors.Keys | ForEach-Object { "${_} ($($errors[$_]))" }) -join '; ')" } else { '' }
    $res.detail = "workload-prereqs: $($parts -join ', ') (checked as $($Identity.engine.displayName))$errTxt$(if ($WhatIf) { ' (what-if: nothing written)' })"
    return $res
}

function Invoke-PimWorkloadPrereqSelfCheckJob {
    <#
      The scheduler handler for 'workload-prereqs' (registered by tools\pim-scheduler\Start-PimScheduler.ps1; the Manager
      only QUEUES it -- "Check again" is Run now on this job). Live seams: the tick's own identity (managed identity or the
      engine SPN), the SQL settings store, pim.AuditEvents. A store that cannot be read or written FAILS the run.
    #>
    param([object]$Job, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf)
    if (-not (Import-PimWorkloadPrereqRunner)) { throw '[workload-prereqs] the prerequisite runner (tools\setup\_PimWorkloadPrereqRunner.ps1) is not in this image -- nothing was checked' }
    $cs = "$($global:PIM_SqlConnectionString)".Trim()
    $read = if ($cs -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) { { $v = Get-PimSqlSetting -ConnectionString $global:PIM_SqlConnectionString -Name 'WorkloadPrereqs'; if ($v -is [string] -and "$v".Trim()) { $v = $v | ConvertFrom-Json }; $v } }
            elseif (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { { $v = Get-PimSetting -Name 'WorkloadPrereqs'; if ($v -is [string] -and "$v".Trim()) { $v = $v | ConvertFrom-Json }; $v } }
            else { $null }
    if (-not $read) { throw '[workload-prereqs] no settings store is wired in this process -- nothing was checked' }
    $write = if ($cs -and (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) { { param($v) Set-PimSqlSetting -ConnectionString $global:PIM_SqlConnectionString -Name 'WorkloadPrereqs' -ValueJson (ConvertTo-Json -InputObject $v -Depth 12 -Compress) } }
             else { { param($v) Set-PimSetting -Name 'WorkloadPrereqs' -Value $v } }
    $audit = {
        param($a, $t, $b, $f)
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) { Write-PimAuditEvent -Action $a -Target $t -Before $b -After $f -Actor 'job:workload-prereqs' }
        elseif ("$($global:PIM_SqlConnectionString)".Trim() -and (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue)) { Write-PimSqlAuditEvent -ConnectionString $global:PIM_SqlConnectionString -Actor 'job:workload-prereqs' -Action $a -Target $t -Before $b -After $f }
    }
    $rowsFn = {
        if ($global:PIM_DesiredResolved -is [hashtable]) { [void]$global:PIM_DesiredResolved.Remove('PIM-Assignments-Azure-Resources') }
        $got = @()
        if (Get-Command Get-PimDesiredRows -ErrorAction SilentlyContinue) { $got = @(Get-PimDesiredRows -Entity 'PIM-Assignments-Azure-Resources' | Where-Object { $null -ne $_ }) }
        elseif ("$($global:PIM_SqlConnectionString)".Trim() -and (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue)) { $got = @(Get-PimSqlRows -ConnectionString $global:PIM_SqlConnectionString -Entity 'PIM-Assignments-Azure-Resources') }
        else { throw 'no delegation store is wired in this process' }
        if ($global:PIM_DesiredResolved -is [hashtable] -and $global:PIM_DesiredResolved.ContainsKey('PIM-Assignments-Azure-Resources') -and -not $global:PIM_DesiredResolved['PIM-Assignments-Azure-Resources']) { throw 'the store read did not resolve' }
        $got
    }
    $id = Get-PimWorkloadPrereqSelfCheckIdentity
    $map = @{}; $m = Get-PimWorkloadPrereqRoleMapFromSource; foreach ($k in $m.Keys) { $map[$k] = $m[$k] }
    $r = Invoke-PimWorkloadPrereqSelfCheck -Identity $id -RoleMap $map -NowUtc $NowUtc -WhatIf:$WhatIf -ReadStored $read -WriteStored $write -Audit $audit -AzureRows $rowsFn
    if (-not $r.ok) { throw "[workload-prereqs] $($r.detail)" }
    return [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf; detail = "$($r.detail)" }
}
