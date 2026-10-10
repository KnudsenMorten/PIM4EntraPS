#Requires -Version 5.1
<#
.SYNOPSIS
    The rules of Import-PimEnvironmentBackup.ps1 -- PURE (no SQL, no network), so they are tested offline
    (tests/Test-PimEnvironmentImport.ps1).
.DESCRIPTION
    An environment's PIM store, restored from its backup (a BACPAC), is copied into ANOTHER environment that already
    runs: its definitions (pim.Rows), its settings (pim.Settings), its audit trail (pim.AuditEvents) and its commit undo
    snapshots (pim.Backups). Operator 2026-10-04, after the internal environment was deleted without an export: "everything
    into r1-pro-ca, keep the audit trail too".

    SETTINGS -- one action per name (Get-PimImportSettingAction):
      skip    the TARGET environment's own identity or runtime state; copying it would make the target pose as the source
              (licence, mail sender, URLs, update/scheduler state, run history, uplink / install keys, RFA store, caches,
              stale mass-change holds) -- Test-PimImportSettingNeverCopy names them.
      union   people lists: ManagerAccess.managerAccess and PortalAdmins.portalAdmins, joined on `identity`. Nobody loses
              access; on a clash the TARGET's entry (role) wins -- importing never raises or lowers a current admin.
      copy    the target has none.
      merge   both are JSON objects: the source's keys win, keys only the target has are KEPT, nested objects merged the
              same way (FeatureGates.gates, NamingConventions, AdminTapIssuance ...). AdminTapIssuance matters: without it the
              engine would treat every imported admin as never having had a TAP.
      replace both exist and are arrays / plain values: the source wins.
      same    identical: nothing to do.
    ROWS: a (Entity, Key) the target lacks is inserted; one it has is LEFT ALONE and reported (never overwritten).
    AUDIT: every source row is APPENDED (append-only: nothing in the target is changed) with its original time and actor;
           one more row records the import itself. A re-run appends nothing twice (the import marker carries the source
           range and is checked first).
    BACKUPS: a snapshot id the target lacks is inserted.
    CHANGE QUEUE: never imported -- an old environment's queued work must not run again (reported by status).
#>

$script:PimImportNeverCopyExact = @(
    'License', 'MailSender', 'ManagerUrl', 'UpdateState', 'SchedulerTriggers', 'SchedulerTickJobId', 'JobRunHistory',
    'ConvergenceState', 'EngineItemFailures', 'HybridWorkerHeartbeat', 'HybridAdSyncLive', 'HybridAdSyncLiveWatch',
    'RecalcSignature', 'RecalcEntitySignatures', 'CommitWatch', 'CommitOutcomes', 'AlertFeed', 'DriftAlertState', 'ApiKeys',
    'UplinkState', 'TelemetryInstallId', 'InvardiaInstallKey', 'InstallKeyClaimState', 'LicenceRequestState',
    'LicenceRequestToken', 'InstallId', 'EditionUpgrade', 'RfaSettings', 'UnmanagedAdmins', 'AzResPolicyMassHold',
    'AzResPolicyMassChangeApproval', 'GroupsPolicyMassHold', 'RemoveRowAbsentSeen', 'TenantCacheState', 'RingOrder',
    'EnvironmentName',  # this environment's own display name ("EFIF (test)") -- never carried to another one
    'DemoMode', 'DemoGuestGroup',   # s98: a live demo's own switch -- an import never turns another environment into a demo
    'LogRepeatSeen',    # §100.46: which repeating log lines THIS environment already printed (runtime state)
    'WorkloadPrereqs'   # checks made against the SOURCE's engine identity (2026-10-04: r1-pro-ca showed mfnpr's green checks)
)
$script:PimImportNeverCopyPrefix = @('JobRunOutput:', 'SchedulerState', 'SchedulerLease', 'JobScope')
$script:PimImportUnion = @{ ManagerAccess = 'managerAccess'; PortalAdmins = 'portalAdmins' }

function Test-PimImportSettingNeverCopy {
    <# PURE. True for a setting that is the TARGET environment's own identity / runtime state. #>
    param([Parameter(Mandatory)][string]$Name)
    if ($script:PimImportNeverCopyExact -contains $Name) { return $true }
    foreach ($p in $script:PimImportNeverCopyPrefix) { if ($Name.StartsWith($p, [System.StringComparison]::OrdinalIgnoreCase)) { return $true } }
    return $false
}

function ConvertFrom-PimImportJson {
    param([AllowNull()][AllowEmptyString()][string]$Json)
    if (-not "$Json".Trim()) { return $null }
    try { return ($Json | ConvertFrom-Json) } catch { return "$Json" }
}

function Merge-PimImportObject {
    <# PURE. Deep merge: the source's keys win, keys only the target has are kept; nested objects merged the same way. #>
    param([AllowNull()][object]$Target, [AllowNull()][object]$Source)
    $isObj = { param($v) $null -ne $v -and $v -is [System.Management.Automation.PSCustomObject] }
    if (-not (& $isObj $Target) -or -not (& $isObj $Source)) { return $Source }
    $out = [ordered]@{}
    foreach ($p in $Target.PSObject.Properties) { $out[$p.Name] = $p.Value }
    foreach ($p in $Source.PSObject.Properties) {
        if ($out.Contains($p.Name) -and (& $isObj $out[$p.Name]) -and (& $isObj $p.Value)) { $out[$p.Name] = Merge-PimImportObject -Target $out[$p.Name] -Source $p.Value }
        else { $out[$p.Name] = $p.Value }
    }
    return [pscustomobject]$out
}

function Join-PimImportPeople {
    <# PURE. Union of two people lists on `identity` (case-insensitive); the TARGET's entry wins a clash. Returns @{ list; added }. #>
    param([object[]]$Target = @(), [object[]]$Source = @())
    $seen = @{}; $list = New-Object System.Collections.Generic.List[object]; $added = New-Object System.Collections.Generic.List[string]
    foreach ($e in @($Target)) { if ($null -eq $e) { continue }; $k = "$($e.identity)".Trim().ToLowerInvariant(); if ($k) { $seen[$k] = $true }; $list.Add($e) }
    foreach ($e in @($Source)) { if ($null -eq $e) { continue }; $k = "$($e.identity)".Trim().ToLowerInvariant(); if (-not $k -or $seen.ContainsKey($k)) { continue }; $seen[$k] = $true; $list.Add($e); $added.Add("$($e.identity)") }
    return @{ list = $list.ToArray(); added = $added.ToArray() }
}

function Get-PimImportSettingAction {
    <#
      PURE. One setting -> @{ name; action = skip|union|copy|merge|replace|same; valueJson (what to write, '' for skip/same);
      note }. -SourceJson / -TargetJson are the stored ValueJson ('' / $null = absent).
    #>
    param([Parameter(Mandatory)][string]$Name, [AllowNull()][AllowEmptyString()][string]$SourceJson, [AllowNull()][AllowEmptyString()][string]$TargetJson)
    $r = @{ name = $Name; action = 'same'; valueJson = ''; note = '' }
    if (Test-PimImportSettingNeverCopy -Name $Name) { $r.action = 'skip'; $r.note = 'the target environment''s own identity / runtime state'; return $r }
    if (-not "$SourceJson".Trim()) { $r.note = 'absent in the source'; return $r }
    if (-not "$TargetJson".Trim()) { $r.action = 'copy'; $r.valueJson = $SourceJson; return $r }
    if ("$SourceJson" -ceq "$TargetJson") { return $r }
    $s = ConvertFrom-PimImportJson $SourceJson; $t = ConvertFrom-PimImportJson $TargetJson
    if ($script:PimImportUnion.ContainsKey($Name)) {
        $prop = $script:PimImportUnion[$Name]
        $j = Join-PimImportPeople -Target @($t.$prop) -Source @($s.$prop)
        if (-not $j.added.Count) { return $r }
        $o = [ordered]@{}; foreach ($p in $t.PSObject.Properties) { $o[$p.Name] = $p.Value }; $o[$prop] = @($j.list)
        $r.action = 'union'; $r.valueJson = ([pscustomobject]$o | ConvertTo-Json -Depth 20 -Compress); $r.note = "+$($j.added.Count): $($j.added -join ', ')"
        return $r
    }
    # The JSON TEXT decides "object": ConvertFrom-Json unrolls a one-element array '[{...}]' into a bare object, which
    # would then be merged instead of replaced (caught by Test-PimEnvironmentImport).
    $bothObjects = ("$SourceJson".TrimStart().StartsWith('{') -and "$TargetJson".TrimStart().StartsWith('{'))
    if ($bothObjects -and $s -is [System.Management.Automation.PSCustomObject] -and $t -is [System.Management.Automation.PSCustomObject]) {
        $m = Merge-PimImportObject -Target $t -Source $s
        $mj = $m | ConvertTo-Json -Depth 20 -Compress
        if ($mj -ceq ($t | ConvertTo-Json -Depth 20 -Compress)) { return $r }
        $r.action = 'merge'; $r.valueJson = $mj; return $r
    }
    $r.action = 'replace'; $r.valueJson = $SourceJson; return $r
}

function Get-PimImportRowPlan {
    <# PURE. -Source / -Target: @( @{ Entity; Key } ). Returns @{ insert = @(source rows); conflict = @('Entity|Key'); perEntity = @{ entity = @{ insert; conflict } } }. #>
    param([object[]]$Source = @(), [object[]]$Target = @())
    $have = @{}; foreach ($t in @($Target)) { $have["$($t.Entity)|$($t.Key)".ToLowerInvariant()] = $true }
    $ins = New-Object System.Collections.Generic.List[object]; $con = New-Object System.Collections.Generic.List[string]; $per = @{}
    foreach ($s in @($Source)) {
        $k = "$($s.Entity)|$($s.Key)"
        if (-not $per.ContainsKey("$($s.Entity)")) { $per["$($s.Entity)"] = @{ insert = 0; conflict = 0 } }
        if ($have.ContainsKey($k.ToLowerInvariant())) { $con.Add($k); $per["$($s.Entity)"].conflict++ } else { $ins.Add($s); $per["$($s.Entity)"].insert++ }
    }
    return @{ insert = $ins.ToArray(); conflict = $con.ToArray(); perEntity = $per }
}
