<#
  CONFIG-1.3 / CONFIG-1.4 (framework DOCS/REQUIREMENTS.md) / PIM §96.3 + §96.4 -- CONFIGURATION BACKUP and PICK-WHAT-YOU-RESTORE.

  Operator 2026-10-06: "backup the configurations in pim (dept, external companies, delegations, admins, settings and other
  relevant things). save length must be configurable, default 90 days" and "restore the backup, but be able to select what
  we want from the restore".

  WHAT IS IN A BACKUP (operator, second wizard 2026-10-06 -- PIM §96.9):
    * pim.Rows of every CONFIGURATION entity: Account-Definitions-* (admins, central admins, external companies +
      consultants), every PIM-Definitions-* (group definitions, departments, AUs) and every PIM-Assignments-* (delegations,
      workload bindings). Other pim.Rows entities (queued actions, offboarding requests, discovery, catalogs) are NOT
      configuration and are listed in the backup's manifest as excluded.
    * pim.Settings -- every setting EXCEPT the deny list below: secrets (by name AND by value), and runtime state (job run
      history, leases, caches, heartbeats, requests, campaigns, holds ...). Inside a kept setting (and a kept row) every
      property whose NAME or VALUE looks like a secret is dropped and its path recorded (Remove-PimConfigBackupSecrets).
    * MSP configuration when the tables exist: platform.Tenants (the managed-tenant registry) and pim.CentralAdmins.
  NEVER: secrets, the audit trail (pim.AuditEvents), the journal (pim.CommitJournal), caches (pim.TenantCache), run logs.

  STORE: pim.ConfigBackups (one row per backup: BackupId, TakenUtc, TakenBy, Trigger, Version, ContentHash, Pinned,
  NoChange, SameAs, counts, manifest) + pim.ConfigBackupEntities (one GZIP-compressed JSON document per entity). A backup
  whose content hash equals the last real backup's is recorded as NoChange (SameAs = that backup) with no copy.
  RETENTION: pim.Settings 'ConfigBackupRetentionDays' (default 90, 1..3650). Pinned backups are kept past it, the newest
  real backup is always kept (there is always a restore point), and a real backup a kept "no change" record points at is
  kept. Pruning is audited (config.backup.prune).
  RESTORE never writes here: the Manager computes the diff (Compare-PimConfigBackupSnapshot), the person ticks rows and they
  are STAGED as pending changes for the normal commit (journal Source 'restore'); settings are restored one by one through
  the Manager's settings writer (old -> new), current secrets kept.

  PURE helpers first (no SQL), then the store functions. Windows PowerShell 5.1 + pwsh 7. ASCII only.
#>
Set-StrictMode -Off

# ---------------------------------------------------------------------------------------------------------------------
# What is configuration (PURE)
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimConfigBackupEntityPatterns { @('^Account-Definitions-', '^PIM-Definitions-', '^PIM-Assignments-') }

function Test-PimConfigBackupEntityIncluded {
    <# PURE. True for a pim.Rows entity that is configuration (Account-Definitions-*, PIM-Definitions-*, PIM-Assignments-*). #>
    param([string]$Entity)
    foreach ($p in (Get-PimConfigBackupEntityPatterns)) { if ("$Entity" -match $p) { return $true } }
    return $false
}

function Get-PimConfigBackupSettingDenyList {
    <#
      PURE. The pim.Settings names a backup NEVER holds, with the reason. secret = a key / token / password lives in it;
      state = runtime state the product writes itself (not something a customer configures); identity = this install's
      own identity / licence, which a restore must never overwrite.
    #>
    [ordered]@{
        secret   = @('ApiKeys', 'InvardiaInstallKey', 'LicenceRequestToken', 'EmergencyPassphrase', 'SqlConnectionString',
                     'StorePointer', 'SqlStore', 'ClientSecret', 'SupportClientSecret')
        # REVIEW FIXES 2026-10-13: ReconcileRemovalMode, EnableAutomaticOffboarding and GuardReleaseSecondPerson are this
        # environment's own protection switches. A restore wrote them as any other setting -- or BLANKED them: a ticked
        # name the backup does not hold is written as NULL, and a blank removal-mode row means ENFORCE -- past the
        # confirmation and the "count you saw" check of the Settings page, tools/pim-manager/_settings.ps1, and it
        # switched the second person of a guard release off with no 'settings.guard-release-second-person' audit.
        # They are changed on their own pages only.
        identity = @('License', 'Licence', 'LicenceState', 'Edition', 'EditionUpgrade', 'InstallId', 'TelemetryInstallId',
                     'ReconcileRemovalMode', 'EnableAutomaticOffboarding', 'GuardReleaseSecondPerson',
                     'InstallKeyClaimState', 'SchedulerTickJobId', 'DemoMode', 'DemoGuestGroup')   # s98: a restore never flips demo mode
        state    = @('UpdateState', 'SchedulerTriggers', 'JobRunHistory', 'ConvergenceState', 'EngineItemFailures',
                     'HybridWorkerHeartbeat', 'HybridAdSyncLive', 'HybridAdSyncLiveWatch', 'RecalcSignature', 'RecalcEntitySignatures',
                     'CommitWatch', 'CommitOutcomes', 'AlertFeed', 'DriftAlertState', 'UplinkState', 'LicenceRequestState',
                     'UnmanagedAdmins', 'AzResPolicyMassHold', 'AzResPolicyMassChangeApproval', 'GroupsPolicyMassHold',
                     'GroupsPolicyMassChangeApproval', 'EntraRolePolicyMassHold', 'EntraRolePolicyMassChangeApproval',   # CODE REVIEW 2 (2026-10-13): a restore never brings back a policy hold or approval
                     'RemoveRowAbsentSeen', 'TenantCacheState', 'RingOrder', 'WorkloadPrereqs', 'CutoverState', 'PendingChanges',
                     'ApprovalRequests', 'GuardTrips', 'AccessReviewCampaigns', 'AccessReviewCycleState', 'AccessReviewReminders',
                     'AutoExtendDecisions', 'AutoExtendOutlook', 'CompanyReviewCampaigns', 'OwnerReviews', 'RfaRequests',
                     'DiscoveryBaseline', 'DiscoveryRoleBaseline', 'DownlinkIntents', 'DownlinkIntentsApplied', 'DownlinkApplied',
                     'EngineDesiredCounts', 'AdminOffboardState', 'ConformanceTemplateState',
                     'DefenderRoleCreatePending', 'IntakeRequests', 'LifecycleEscalationLog', 'ChangeQueue', 'DesiredState',
                     'DockerBuildRequest', 'SchedulerState', 'SchedulerLease',
                     # PIM 100.119 B1: the guards' own records. An old copy written over the live one would make a consumed or
                     # revoked approval / release ACTIVE again (used = []), and move a limit with no 'guard.limit' audit.
                     # A limit is set by a SuperAdmin on the Guards page, never by a restore.
                     'GuardApprovals', 'GuardReleases', 'GuardHolds', 'GuardLimits',
                     # review 1 fixes 2026-10-13 (decision 54): a restored delete pin would make a tombstone ACTIVE again
                     'AdminDeletePins',
                     # PIM 100.123: the AD clean-up / server-group approvals and the worker's own records -- an old approval restored would be usable again
                     'HybridAdCleanupApproval', 'HybridAdServerAutoGroupsApproval', 'AdServerAutoGroups', 'AdServerAutoGroupsWaiting', 'AdServerAutoGroupsProgress', 'AdCleanupResult', 'AdCleanupLocalAdmin',
                     # SNAP-INC (owner 2026-10-20): the snapshot's group delta link + last full read -- runtime state of THIS store's rows
                     'ActiveAssignmentsGroupDelta',
                     # s98.3: the nightly demo baseline restore's own record of the slot it acted on
                     'DemoBaselineRestoreState')
        statePrefix = @('JobRunOutput:', 'SchedulerState', 'SchedulerLease', 'JobScope', 'HybridAdSyncMemory', 'DeltaSkipState:')   # 100.122 F1: the AD sync's memory (Entra ids of THIS tenant) is never restored; 70.17: a job's last-run skip state
        # ...Change (case-sensitive, PascalCase) = a PENDING change request (e.g. the break-glass maker/checker request) --
        # runtime state, never configuration. Named by pattern on purpose: the engine never names that request row
        # (Test-PimBreakGlassMakerChecker), and 'Exchange' never matches.
        statePattern = '(?i)(Lease|Heartbeat|History|Feed|Cache|Seen|Log)$|(?-i:[a-z]Change)$'
    }
}

function Test-PimConfigBackupSecretName {
    <# PURE. True when a setting / property NAME says it holds a secret. #>
    param([string]$Name)
    $n = "$Name".Trim()
    if (-not $n) { return $false }
    return ($n -match '(?i)(secret|passw|passphrase|^pwd$|token|api[-_]?keys?$|^apikey|private[-_]?key|signing[-_]?key|install[-_]?key|connection[-_]?string|credential|webhook|^sas$|sas[-_]?(token|url|uri)$|account[-_]?key|shared[-_]?access[-_]?key|pfx|^key$|cert(ificate)?[-_]?(data|blob|pem|base64)$)')
}

function Test-PimConfigBackupSecretValue {
    <# PURE. True when a string VALUE looks like a secret whatever its name: a PIM API key, a JWT, a SAS signature, a
       connection string carrying a key / password, a PEM private key. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or -not ($Value -is [string])) { return $false }
    $s = "$Value"
    if ($s.Length -lt 8) { return $false }
    if ($s -match '^pimk_') { return $true }
    if ($s -match '^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.') { return $true }
    if ($s -match '(?i)(^|[?&;])sig=[A-Za-z0-9%/+=]{16,}') { return $true }
    if ($s -match '(?i)(AccountKey|Password|Pwd|SharedAccessKey|client_secret)\s*=') { return $true }
    if ($s -match '-----BEGIN [A-Z ]*PRIVATE KEY-----') { return $true }
    return $false
}

function Test-PimConfigBackupSettingExcluded {
    <# PURE. @{ excluded; reason } for one pim.Settings name (the deny list, then the secret-name rule). #>
    param([Parameter(Mandatory)][string]$Name)
    $d = Get-PimConfigBackupSettingDenyList
    foreach ($k in @('secret', 'identity', 'state')) {
        foreach ($x in @($d[$k])) { if ([string]::Equals("$x", $Name, [StringComparison]::OrdinalIgnoreCase)) { return @{ excluded = $true; reason = $k } } }
    }
    foreach ($p in @($d.statePrefix)) { if ($Name.StartsWith($p, [StringComparison]::OrdinalIgnoreCase)) { return @{ excluded = $true; reason = 'state' } } }
    if ($Name -match $d.statePattern) { return @{ excluded = $true; reason = 'state' } }
    if (Test-PimConfigBackupSecretName -Name $Name) { return @{ excluded = $true; reason = 'secret' } }
    return @{ excluded = $false; reason = '' }
}

# ---------------------------------------------------------------------------------------------------------------------
# Secret removal + canonical form + hashing + compression (PURE)
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimConfigBackupRedactedNode {
    # Internal. Returns @{ drop; value }; adds the dropped paths to -Redacted.
    param([AllowNull()][object]$Value, [string]$Path, [System.Collections.Generic.List[string]]$Redacted)
    if ($null -eq $Value) { return @{ drop = $false; value = $null } }
    if ($Value -is [string]) {
        if (Test-PimConfigBackupSecretValue -Value $Value) { return @{ drop = $true; value = $null } }
        return @{ drop = $false; value = $Value }
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in @($Value.Keys)) {
            $p = if ($Path) { "$Path.$k" } else { "$k" }
            if (Test-PimConfigBackupSecretName -Name "$k") { $Redacted.Add($p); continue }
            $r = Get-PimConfigBackupRedactedNode -Value $Value[$k] -Path $p -Redacted $Redacted
            if ($r.drop) { $Redacted.Add($p); continue }
            $o["$k"] = $r.value
        }
        return @{ drop = $false; value = [pscustomobject]$o }
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $o = [ordered]@{}
        foreach ($pr in @($Value.PSObject.Properties)) {
            $p = if ($Path) { "$Path.$($pr.Name)" } else { "$($pr.Name)" }
            if (Test-PimConfigBackupSecretName -Name $pr.Name) { $Redacted.Add($p); continue }
            $r = Get-PimConfigBackupRedactedNode -Value $pr.Value -Path $p -Redacted $Redacted
            if ($r.drop) { $Redacted.Add($p); continue }
            $o[$pr.Name] = $r.value
        }
        return @{ drop = $false; value = [pscustomobject]$o }
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $l = New-Object System.Collections.Generic.List[object]
        $i = 0
        foreach ($e in $Value) {
            $r = Get-PimConfigBackupRedactedNode -Value $e -Path ("{0}[{1}]" -f $Path, $i) -Redacted $Redacted
            if ($r.drop) { $Redacted.Add(("{0}[{1}]" -f $Path, $i)) } else { $l.Add($r.value) }
            $i++
        }
        return @{ drop = $false; value = $l.ToArray() }
    }
    return @{ drop = $false; value = $Value }
}

function Remove-PimConfigBackupSecrets {
    <#
      PURE. A value with every secret removed: a property whose NAME is a secret name, and any string VALUE that looks like a
      secret (an array element is dropped). Returns @{ value; redacted = @(paths); dropAll } -- dropAll = the whole value
      itself is a secret string.
    #>
    param([AllowNull()][object]$Value)
    $red = New-Object System.Collections.Generic.List[string]
    $r = Get-PimConfigBackupRedactedNode -Value $Value -Path '' -Redacted $red
    return @{ value = $r.value; redacted = @($red.ToArray()); dropAll = [bool]$r.drop }
}

function ConvertTo-PimConfigBackupCanonical {
    <# PURE. A deterministic JSON text (object keys sorted ordinal, dates ISO-8601 UTC) -- used to compare and hash, never stored. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return (ConvertTo-Json -InputObject $Value -Compress) }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [datetime]) { return (ConvertTo-Json -InputObject ($Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')) -Compress) }
    if ($Value -is [ValueType]) { return [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0}', $Value) }
    if ($Value -is [System.Collections.IDictionary]) {
        $keys = @($Value.Keys | ForEach-Object { "$_" }); [Array]::Sort($keys, [StringComparer]::Ordinal)
        return '{' + (@($keys | ForEach-Object { (ConvertTo-Json -InputObject $_ -Compress) + ':' + (ConvertTo-PimConfigBackupCanonical -Value $Value[$_]) }) -join ',') + '}'
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $keys = @($Value.PSObject.Properties | ForEach-Object { "$($_.Name)" }); [Array]::Sort($keys, [StringComparer]::Ordinal)
        return '{' + (@($keys | ForEach-Object { (ConvertTo-Json -InputObject $_ -Compress) + ':' + (ConvertTo-PimConfigBackupCanonical -Value $Value.PSObject.Properties[$_].Value) }) -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        return '[' + (@(foreach ($e in $Value) { ConvertTo-PimConfigBackupCanonical -Value $e }) -join ',') + ']'
    }
    return (ConvertTo-Json -InputObject "$Value" -Compress)
}

function ConvertFrom-PimConfigBackupJson {
    <# PURE. JSON text -> value; a text that is not JSON stays the text. $null / '' -> $null. #>
    param([AllowNull()][string]$Json)
    if ($null -eq $Json -or "$Json".Trim() -eq '') { return $null }
    try { return (ConvertFrom-Json -InputObject $Json) } catch { return "$Json" }
}

function ConvertFrom-PimConfigBackupJsonValue {
    <#
      PURE. As ConvertFrom-PimConfigBackupJson, but a JSON LIST stays a list -- also a list of ONE item (BUG-BACKUP-LIST-KEY):
      ConvertFrom-Json enumerates a top-level array on pwsh 7 and a plain `return` unrolls it on Windows PowerShell 5.1, so
      '[{"key":"all"}]' came back as the object {key}. The list is read as the property of a wrapper object (never
      enumerated on either edition) and returned with the unary comma. Callers ASSIGN the result ($v = ...), never pipe it.
    #>
    param([AllowNull()][string]$Json)
    if ($null -eq $Json -or "$Json".Trim() -eq '') { return $null }
    $t = "$Json".Trim()
    try {
        if ($t.StartsWith('[')) {
            $w = ConvertFrom-Json -InputObject ('{"v":' + $t + '}')
            $list = $w.v
            if ($null -eq $list) { return $null }
            return , ([object[]]@($list))
        }
        return (ConvertFrom-Json -InputObject $t)
    } catch { return "$Json" }
}

function Copy-PimConfigBackupValue {
    <#
      Internal, PURE. A deep copy of a parsed setting value: an object (PSCustomObject or dictionary) becomes a new
      PSCustomObject, a list a new object[] -- a list of ONE item stays a list (returned with the unary comma; callers
      assign it, never pipe it). Strings and value types are returned as they are.
    #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [ValueType]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in @($Value.Keys)) { $c = Copy-PimConfigBackupValue -Value $Value[$k]; $o["$k"] = $c }
        return [pscustomobject]$o
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $l = New-Object System.Collections.Generic.List[object]
        foreach ($e in $Value) { $c = Copy-PimConfigBackupValue -Value $e; $l.Add($c) }
        return , ($l.ToArray())
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $o = [ordered]@{}
        foreach ($pr in @($Value.PSObject.Properties)) { $c = Copy-PimConfigBackupValue -Value $pr.Value; $o[$pr.Name] = $c }
        return [pscustomobject]$o
    }
    return $Value
}

function Get-PimConfigBackupHash {
    <# PURE. Lower-case hex SHA-256 of a UTF-8 text. #>
    param([AllowNull()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes("$Text")) | ForEach-Object { $_.ToString('x2') })) }
    finally { $sha.Dispose() }
}

function Compress-PimConfigBackupText {
    <# PURE. GZIP of a UTF-8 text -> byte[]. #>
    param([AllowNull()][string]$Text)
    $ms = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
    $b = [Text.Encoding]::UTF8.GetBytes("$Text")
    $gz.Write($b, 0, $b.Length); $gz.Dispose()
    $out = $ms.ToArray(); $ms.Dispose()
    return ,$out
}

function Expand-PimConfigBackupText {
    <# PURE. byte[] (GZIP) -> the UTF-8 text. #>
    param([Parameter(Mandatory)][byte[]]$Bytes)
    $ms = New-Object System.IO.MemoryStream(, $Bytes)
    $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
    $rd = New-Object System.IO.StreamReader($gz, [Text.Encoding]::UTF8)
    try { return $rd.ReadToEnd() } finally { $rd.Dispose(); $gz.Dispose(); $ms.Dispose() }
}

# ---------------------------------------------------------------------------------------------------------------------
# The snapshot (PURE): what a backup holds, built from raw store rows
# ---------------------------------------------------------------------------------------------------------------------
function New-PimConfigBackupSnapshot {
    <#
      PURE. -Rows: @({ Entity; Key; DataJson }) (pim.Rows). -Settings: @({ Name; ValueJson }) (pim.Settings). -Tables:
      @{ '<table>' = @({ key; json }) } (MSP tables, already keyed). Returns
        @{ entities = [ordered]@{ '<entity>' = @{ entity; kind = rows|settings|table; items = @(@{ key; json }) ; hash; redacted } }
           excluded = @{ settings = @(@{ name; reason }); entities = @(@{ entity; rows }) }; hash; itemCount }
      Every item's json is the stored text, re-serialized ONLY when a secret had to be removed from it.
    #>
    param([object[]]$Rows = @(), [object[]]$Settings = @(), [hashtable]$Tables = @{})
    $entities = [ordered]@{}
    $exclSettings = New-Object System.Collections.Generic.List[object]
    $exclEntities = @{}
    $redactAll = New-Object System.Collections.Generic.List[string]
    $mkItem = {
        param($key, $json, $label)
        # a list stays a list, also with ONE item (BUG-BACKUP-LIST-KEY): its redacted paths are then "[0].key", which the
        # restore puts back by index -- an unrolled one-item list was recorded as the object path "key" of a non-list
        $parsed = ConvertFrom-PimConfigBackupJsonValue -Json $json
        if ($null -eq $parsed) { return @{ item = @{ key = "$key"; json = $null }; redacted = @(); dropAll = $false } }
        $rs = Remove-PimConfigBackupSecrets -Value $parsed
        if ($rs.dropAll) { return @{ item = $null; redacted = @("$label"); dropAll = $true } }
        $out = if (@($rs.redacted).Count) { ConvertTo-Json -InputObject $rs.value -Depth 30 -Compress } else { "$json" }
        return @{ item = @{ key = "$key"; json = $out }; redacted = @($rs.redacted | ForEach-Object { "${label}:$_" }); dropAll = $false }
    }
    # pim.Rows
    $byEntity = @{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $e = "$($r.Entity)"
        if (-not (Test-PimConfigBackupEntityIncluded -Entity $e)) { if (-not $exclEntities.ContainsKey($e)) { $exclEntities[$e] = 0 }; $exclEntities[$e]++; continue }
        if (-not $byEntity.ContainsKey($e)) { $byEntity[$e] = New-Object System.Collections.Generic.List[object] }
        $byEntity[$e].Add($r)
    }
    foreach ($e in @($byEntity.Keys | Sort-Object)) {
        $items = New-Object System.Collections.Generic.List[object]; $red = New-Object System.Collections.Generic.List[string]
        foreach ($r in @($byEntity[$e] | Sort-Object { "$($_.Key)" })) {
            $x = & $mkItem "$($r.Key)" $(if ($null -eq $r.DataJson -or $r.DataJson -is [DBNull]) { $null } else { "$($r.DataJson)" }) "$e/$($r.Key)"
            foreach ($p in @($x.redacted)) { $red.Add($p) }
            if ($x.item) { $items.Add($x.item) }
        }
        $entities[$e] = @{ entity = $e; kind = 'rows'; items = @($items.ToArray()); redacted = @($red.ToArray()) }
        foreach ($p in $red) { $redactAll.Add($p) }
    }
    # pim.Settings
    $sItems = New-Object System.Collections.Generic.List[object]; $sRed = New-Object System.Collections.Generic.List[string]
    foreach ($s in @($Settings | Where-Object { $_ } | Sort-Object { "$($_.Name)" })) {
        $n = "$($s.Name)"
        $ex = Test-PimConfigBackupSettingExcluded -Name $n
        if ($ex.excluded) { $exclSettings.Add(@{ name = $n; reason = $ex.reason }); continue }
        $x = & $mkItem $n $(if ($null -eq $s.ValueJson -or $s.ValueJson -is [DBNull]) { $null } else { "$($s.ValueJson)" }) $n
        if ($x.dropAll) { $exclSettings.Add(@{ name = $n; reason = 'secret' }); continue }
        foreach ($p in @($x.redacted)) { $sRed.Add($p) }
        if ($x.item) { $sItems.Add($x.item) }
    }
    $entities['pim.Settings'] = @{ entity = 'pim.Settings'; kind = 'settings'; items = @($sItems.ToArray()); redacted = @($sRed.ToArray()) }
    foreach ($p in $sRed) { $redactAll.Add($p) }
    # MSP tables
    foreach ($t in @($Tables.Keys | Sort-Object)) {
        $items = New-Object System.Collections.Generic.List[object]; $red = New-Object System.Collections.Generic.List[string]
        foreach ($r in @($Tables[$t] | Where-Object { $_ } | Sort-Object { "$($_.key)" })) {
            $x = & $mkItem "$($r.key)" "$($r.json)" "$t/$($r.key)"
            foreach ($p in @($x.redacted)) { $red.Add($p) }
            if ($x.item) { $items.Add($x.item) }
        }
        $entities["$t"] = @{ entity = "$t"; kind = 'table'; items = @($items.ToArray()); redacted = @($red.ToArray()) }
    }
    # hashes: per entity over its (key, json) pairs; the backup's over the entity hashes
    $count = 0
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($e in @($entities.Keys)) {
        $ent = $entities[$e]
        $ent.hash = Get-PimConfigBackupHash -Text (@($ent.items | ForEach-Object { "$($_.key)" + [char]1 + "$($_.json)" }) -join [string][char]2)
        $count += @($ent.items).Count
        $parts.Add("$e=$($ent.hash)")
    }
    return @{
        entities = $entities
        excluded = @{ settings = @($exclSettings.ToArray()); entities = @($exclEntities.Keys | Sort-Object | ForEach-Object { @{ entity = $_; rows = $exclEntities[$_] } }) }
        redacted = @($redactAll.ToArray())
        hash = Get-PimConfigBackupHash -Text (@($parts.ToArray()) -join "`n")
        itemCount = $count
    }
}

# ---------------------------------------------------------------------------------------------------------------------
# The difference between a backup and now (PURE)
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimConfigBackupFieldDiff {
    <# PURE. The fields that differ between two values, as @(@{ field; now; backup }). Non-objects: one field '*'. #>
    param([AllowNull()][object]$Now, [AllowNull()][object]$Backup)
    $isObj = { param($x) $null -ne $x -and ($x -is [System.Management.Automation.PSCustomObject] -or $x -is [System.Collections.IDictionary]) }
    if (-not (& $isObj $Now) -or -not (& $isObj $Backup)) {
        if ((ConvertTo-PimConfigBackupCanonical -Value $Now) -ceq (ConvertTo-PimConfigBackupCanonical -Value $Backup)) { return @() }
        return @(@{ field = '*'; now = $Now; backup = $Backup })
    }
    $names = { param($x) if ($x -is [System.Collections.IDictionary]) { @($x.Keys | ForEach-Object { "$_" }) } else { @($x.PSObject.Properties | ForEach-Object { "$($_.Name)" }) } }
    $get = { param($x, $n) if ($x -is [System.Collections.IDictionary]) { if ($x.Contains($n)) { $x[$n] } else { $null } } else { $p = $x.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } } }
    $all = @(@(& $names $Now) + @(& $names $Backup) | Sort-Object -Unique)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($n in $all) {
        $a = & $get $Now $n; $b = & $get $Backup $n
        $ca = ConvertTo-PimConfigBackupCanonical -Value $a; $cb = ConvertTo-PimConfigBackupCanonical -Value $b
        # a blank and an absent field are the same thing in a row (the grid writes '' for a column a row does not carry)
        if ($ca -ceq $cb) { continue }
        if (($ca -eq 'null' -or $ca -eq '""') -and ($cb -eq 'null' -or $cb -eq '""')) { continue }
        $out.Add(@{ field = $n; now = $a; backup = $b })
    }
    return @($out.ToArray())
}

function Compare-PimConfigBackupEntity {
    <#
      PURE. One entity: backup items vs current items (each @{ key; json }), keyed case-insensitively.
      Returns @{ entity; kind; added = @(@{ key; now }); removed = @(@{ key; backup }); changed = @(@{ key; fields; now; backup }); same }
        added   = exists NOW, not in the backup (added since -> a restore removes it)
        removed = in the backup, not now        (removed since -> a restore adds it back)
        changed = in both, different            (changed since -> a restore puts the backup's fields back)
    #>
    param([string]$Entity, [string]$Kind = 'rows', [object[]]$BackupItems = @(), [object[]]$CurrentItems = @())
    $bk = @{}; foreach ($i in @($BackupItems | Where-Object { $_ })) { $bk["$($i.key)".ToLowerInvariant()] = $i }
    $cu = @{}; foreach ($i in @($CurrentItems | Where-Object { $_ })) { $cu["$($i.key)".ToLowerInvariant()] = $i }
    $added = New-Object System.Collections.Generic.List[object]; $removed = New-Object System.Collections.Generic.List[object]
    $changed = New-Object System.Collections.Generic.List[object]; $same = 0
    foreach ($k in @($cu.Keys | Sort-Object)) {
        if (-not $bk.ContainsKey($k)) { $added.Add(@{ key = "$($cu[$k].key)"; now = (ConvertFrom-PimConfigBackupJson -Json $cu[$k].json) }); continue }
        $nj = "$($cu[$k].json)"; $bj = "$($bk[$k].json)"
        if ([string]::Equals($nj, $bj, [StringComparison]::Ordinal)) { $same++; continue }
        $nv = ConvertFrom-PimConfigBackupJson -Json $cu[$k].json; $bv = ConvertFrom-PimConfigBackupJson -Json $bk[$k].json
        $f = @(Get-PimConfigBackupFieldDiff -Now $nv -Backup $bv)
        if (-not $f.Count) { $same++; continue }
        $changed.Add(@{ key = "$($cu[$k].key)"; fields = $f; now = $nv; backup = $bv })
    }
    foreach ($k in @($bk.Keys | Sort-Object)) {
        if (-not $cu.ContainsKey($k)) { $removed.Add(@{ key = "$($bk[$k].key)"; backup = (ConvertFrom-PimConfigBackupJson -Json $bk[$k].json) }) }
    }
    return @{ entity = $Entity; kind = $Kind; added = @($added.ToArray()); removed = @($removed.ToArray()); changed = @($changed.ToArray()); same = $same }
}

function Compare-PimConfigBackupSnapshot {
    <# PURE. Every entity of either snapshot (backup / current, as New-PimConfigBackupSnapshot returns), compared. #>
    param([Parameter(Mandatory)][hashtable]$Backup, [Parameter(Mandatory)][hashtable]$Current)
    $names = @(@($Backup.entities.Keys) + @($Current.entities.Keys) | Sort-Object -Unique)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in $names) {
        $b = $Backup.entities[$e]; $c = $Current.entities[$e]
        $kind = if ($b) { "$($b.kind)" } elseif ($c) { "$($c.kind)" } else { 'rows' }
        $out.Add((Compare-PimConfigBackupEntity -Entity $e -Kind $kind -BackupItems @($(if ($b) { $b.items } else { @() })) -CurrentItems @($(if ($c) { $c.items } else { @() }))))
    }
    return @($out.ToArray())
}

function ConvertTo-PimConfigBackupPathTokens {
    <#
      Internal, PURE. A redacted path ("[0].key", "a[2].b", "a.b") -> @(@{ name; index }) top-down; index -1 = a property
      name, otherwise a list position. $null when the text is not a path this code reads (nothing is guessed).
    #>
    param([string]$Path)
    $ms = [regex]::Matches("$Path", '\[(\d+)\]|([^.\[\]]+)')
    $l = New-Object System.Collections.Generic.List[object]
    $rebuilt = ''
    foreach ($m in $ms) {
        if ($m.Groups[1].Success) { $l.Add(@{ name = ''; index = [int]$m.Groups[1].Value }); $rebuilt += "[$($m.Groups[1].Value)]" }
        else { $l.Add(@{ name = $m.Groups[2].Value; index = -1 }); $rebuilt += $(if ($rebuilt) { '.' } else { '' }) + $m.Groups[2].Value }
    }
    if (-not $l.Count -or $rebuilt -ne "$Path") { return $null }
    return , ($l.ToArray())
}

function Get-PimConfigBackupSettingRestoreResult {
    <#
      PURE. The value a settings restore WRITES, and what could not be put back. The backup's value (a deep copy -- a list
      stays a list, also with ONE item) with every secret the backup could not hold taken from the CURRENT value (the
      redacted paths of that setting), so a restore never blanks a key or a webhook.
        * an OBJECT path ("teams.webhookUrl") is put back as it always was: from the current value when it has it, nothing
          when it does not (there is no secret to keep);
        * a path INSIDE A LIST ("[0].key", "a[2].b" -- BUG-BACKUP-LIST-KEY) is put back from the current value BY INDEX, and
          ONLY while the list still lines up: at every list on the way the backup and the current value hold the same
          number of items, and the current item at that index has the field. Otherwise the path is NOT restored and is
          listed in notRestored with the reason (inList = $true) -- no value is invented. A list item that was itself a
          secret ("a[1]") is never put back (the backup holds the list without it): listed, inList = $false.
      A current list PowerShell unrolled into its one item (a reader that returned [{..}] as {..}) counts as that one-item list.
      Returns @{ value; restored = @(paths); notRestored = @(@{ path; reason; inList }) }.
    #>
    param([AllowNull()][object]$Backup, [AllowNull()][object]$Current, [string[]]$RedactedPaths = @())
    $restored = New-Object System.Collections.Generic.List[string]
    $notRestored = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Backup) { return @{ value = $null; restored = @(); notRestored = @() } }
    $copy = Copy-PimConfigBackupValue -Value $Backup
    $isObj = { param($x) $null -ne $x -and -not ($x -is [string]) -and -not ($x -is [System.Collections.IEnumerable]) -and $x -is [System.Management.Automation.PSCustomObject] }
    $isList = { param($x) $null -ne $x -and $x -is [System.Collections.IList] }
    foreach ($p in @($RedactedPaths | Where-Object { "$_".Trim() })) {
        if ("$p" -notmatch '\[') {
            # OBJECT path -- unchanged behaviour
            $parts = @("$p" -split '\.')
            $src = $Current; $ok = $true
            foreach ($seg in $parts) { if ($null -ne $src -and $src -is [System.Management.Automation.PSCustomObject] -and $src.PSObject.Properties[$seg]) { $src = $src.PSObject.Properties[$seg].Value } else { $ok = $false; break } }
            if (-not $ok) { continue }
            $dst = $copy
            for ($i = 0; $i -lt $parts.Count - 1; $i++) {
                $seg = $parts[$i]
                if (-not ($dst -is [System.Management.Automation.PSCustomObject])) { $ok = $false; break }
                if (-not $dst.PSObject.Properties[$seg]) { $dst | Add-Member -NotePropertyName $seg -NotePropertyValue ([pscustomobject]@{}) }
                $dst = $dst.PSObject.Properties[$seg].Value
            }
            if (-not $ok -or -not ($dst -is [System.Management.Automation.PSCustomObject])) { continue }
            $last = $parts[$parts.Count - 1]
            if ($dst.PSObject.Properties[$last]) { $dst.PSObject.Properties[$last].Value = $src } else { $dst | Add-Member -NotePropertyName $last -NotePropertyValue $src }
            $restored.Add("$p")
            continue
        }
        # LIST path -- by index, only while the backup and the current value line up
        $tok = ConvertTo-PimConfigBackupPathTokens -Path "$p"
        if ($null -eq $tok) { $notRestored.Add(@{ path = "$p"; reason = 'the path could not be read'; inList = $true }); continue }
        $last = $tok[$tok.Count - 1]
        if ($last.index -ge 0) { $notRestored.Add(@{ path = "$p"; reason = 'a list item that was itself a secret is not put back (the backup holds the list without it)'; inList = $false }); continue }
        $d = $copy; $s = $Current; $why = $null; $at = ''
        for ($i = 0; $i -lt $tok.Count - 1; $i++) {
            $t = $tok[$i]
            if ($t.index -ge 0) {
                $here = if ($at) { $at } else { 'the top' }
                if (-not (& $isList $d)) { $why = "the backup holds no list at $here"; break }
                $sl = $null
                if (& $isList $s) { $sl = $s } elseif (& $isObj $s) { $sl = @($s) }
                if ($null -eq $sl) { $why = "the current value holds no list at $here"; break }
                if ($sl.Count -ne $d.Count) { $why = "the list at $here holds $($d.Count) item(s) in the backup and $($sl.Count) now -- its items no longer line up"; break }
                if ($t.index -ge $d.Count) { $why = "the list at $here has no item [$($t.index)]"; break }
                $d = $d[$t.index]; $s = $sl[$t.index]
                $at += "[$($t.index)]"
            } else {
                $name = "$($t.name)"
                $at += $(if ($at) { '.' } else { '' }) + $name
                if (-not (& $isObj $d) -or -not $d.PSObject.Properties[$name]) { $why = "the backup holds no $at"; break }
                if (-not (& $isObj $s) -or -not $s.PSObject.Properties[$name]) { $why = "the current value holds no $at"; break }
                $d = $d.PSObject.Properties[$name].Value; $s = $s.PSObject.Properties[$name].Value
            }
        }
        if (-not $why) {
            $name = "$($last.name)"
            if (-not (& $isObj $d)) { $why = "the backup holds no item at $at" }
            elseif (-not (& $isObj $s)) { $why = "the current value holds no item at $at" }
            elseif (-not $s.PSObject.Properties[$name]) { $why = "the current item at $at has no $name to put back" }
        }
        if ($why) { $notRestored.Add(@{ path = "$p"; reason = $why; inList = $true }); continue }
        $v = $s.PSObject.Properties[$name].Value
        if ($d.PSObject.Properties[$name]) { $d.PSObject.Properties[$name].Value = $v } else { $d | Add-Member -NotePropertyName $name -NotePropertyValue $v }
        $restored.Add("$p")
    }
    return @{ value = $copy; restored = @($restored.ToArray()); notRestored = @($notRestored.ToArray()) }
}

function Get-PimConfigBackupSettingRestoreValue {
    <#
      PURE. The value a settings restore WRITES (Get-PimConfigBackupSettingRestoreResult .value): the backup's value with
      the current secrets put back -- object paths, and paths inside a list by index while the list still lines up. A list
      is returned AS a list, also with one item (unary comma); assign the result, never pipe it.
    #>
    param([AllowNull()][object]$Backup, [AllowNull()][object]$Current, [string[]]$RedactedPaths = @())
    $r = Get-PimConfigBackupSettingRestoreResult -Backup $Backup -Current $Current -RedactedPaths $RedactedPaths
    $v = $r.value
    if ($null -eq $v) { return $null }
    if ($v -is [System.Collections.IList]) { return , $v }
    return $v
}

# ---------------------------------------------------------------------------------------------------------------------
# Retention + who may do what (PURE)
# ---------------------------------------------------------------------------------------------------------------------
function ConvertTo-PimConfigBackupRetentionDays {
    <# PURE. A retention value -> days (1..3650). Blank / $null -> 90 (the default). Anything else throws. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or "$Value".Trim() -eq '') { return 90 }
    $n = 0
    if (-not [int]::TryParse("$Value".Trim(), [ref]$n)) { throw "the backup retention must be a whole number of days (1-3650), not '$Value'" }
    if ($n -lt 1 -or $n -gt 3650) { throw "the backup retention must be between 1 and 3650 days (got $n)" }
    return $n
}

function Get-PimConfigBackupRetentionPlan {
    <#
      PURE. Which backups to keep and which to prune. -Backups: @({ BackupId; TakenUtc; Pinned; NoChange; SameAs }).
      Kept: pinned; taken within the retention; the NEWEST real (not "no change") backup -- always one restore point; and a
      real backup a kept "no change" record points at. Everything else is pruned.
      Returns @{ keep = @(@{ id; reason }); prune = @(ids); cutoffUtc }.
    #>
    param([object[]]$Backups = @(), [int]$RetentionDays = 90, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($RetentionDays -lt 1) { $RetentionDays = 90 }
    $cutoff = $NowUtc.ToUniversalTime().AddDays(-$RetentionDays)
    $all = @($Backups | Where-Object { $_ -and "$($_.BackupId)".Trim() })
    $reason = [ordered]@{}
    # A DATETIME2 read from SQL comes back with Kind Unspecified -- it IS UTC; ToUniversalTime() would shift it by the host's offset.
    $tsOf = { param($b) $t = $b.TakenUtc; if ($t -is [datetime]) { if ($t.Kind -eq [DateTimeKind]::Unspecified) { [datetime]::SpecifyKind($t, [DateTimeKind]::Utc) } else { $t.ToUniversalTime() } } else { ([datetime]::Parse("$t", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)) } }
    foreach ($b in $all) {
        $id = "$($b.BackupId)"
        if ([bool]$b.Pinned) { $reason[$id] = 'pinned'; continue }
        if ((& $tsOf $b) -ge $cutoff) { $reason[$id] = 'within retention' }
    }
    $real = @($all | Where-Object { -not [bool]$_.NoChange } | Sort-Object { & $tsOf $_ } -Descending)
    if ($real.Count -and -not $reason.Contains("$($real[0].BackupId)")) { $reason["$($real[0].BackupId)"] = 'latest restore point' }
    foreach ($b in @($all | Where-Object { [bool]$_.NoChange -and "$($_.SameAs)".Trim() })) {
        if ($reason.Contains("$($b.BackupId)") -and -not $reason.Contains("$($b.SameAs)") -and @($all | Where-Object { "$($_.BackupId)" -eq "$($b.SameAs)" }).Count) {
            $reason["$($b.SameAs)"] = 'base of a kept no-change record'
        }
    }
    $keep = @($reason.Keys | ForEach-Object { @{ id = "$_"; reason = "$($reason[$_])" } })
    $prune = @($all | Where-Object { -not $reason.Contains("$($_.BackupId)") } | ForEach-Object { "$($_.BackupId)" })
    return @{ keep = $keep; prune = $prune; cutoffUtc = $cutoff.ToString('o') }
}

function Get-PimConfigBackupAccess {
    <#
      PURE. What a Manager role may do with configuration backups (CONFIG-1.3 / 1.4, PIM §96.9 D3):
        list + "Back up now" + pin: Admin and SuperAdmin; unpin (lets a backup be pruned), the diff, every restore and the
        retention setting: SuperAdmin ONLY. Reader / Delegated / None: nothing.
    #>
    param([string]$Role)
    $r = "$Role".Trim()
    $admin = ($r -eq 'Admin' -or $r -eq 'SuperAdmin'); $sa = ($r -eq 'SuperAdmin')
    return @{ list = $admin; backupNow = $admin; pin = $admin; unpin = $sa; diff = $sa; restore = $sa; retention = $sa }
}

function Get-PimConfigBackupSettingRestoreRoute {
    <#
      PURE. How ONE setting is restored. 'direct' = the settings writer (old -> new); 'breakglass' = its own maker/checker
      request (a second SuperAdmin approves); 'none' = shown, never restored from a backup (a time-boxed incident state, or a
      name the deny list keeps out).
    #>
    param([Parameter(Mandatory)][string]$Name)
    if ((Test-PimConfigBackupSettingExcluded -Name $Name).excluded) { return 'none' }
    if ($Name -ieq 'BreakGlassAccounts') { return 'breakglass' }
    if ($Name -ieq 'EmergencyOverride') { return 'none' }
    return 'direct'
}

function ConvertTo-PimConfigBackupDiffView {
    <#
      PURE. The Manager's view of a diff (Compare-PimConfigBackupSnapshot output): per entity, HOW it can be restored --
        rows     = staged as pending changes on the Manager page (the entity is one -RestorableBases names);
        settings = per setting: 'direct' (the settings writer), 'breakglass' (its own maker/checker request), 'none';
        none     = shown, not restorable from here (-HowTo says where it is changed).
      Entities with no difference are summarised (same = n) and carry no rows.
    #>
    param([object[]]$Entities = @(), [string[]]$RestorableBases = @())
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($d in @($Entities | Where-Object { $_ })) {
        $kind = "$($d.kind)"
        $restore = 'none'; $how = ''
        if ($kind -eq 'settings') { $restore = 'settings' }
        elseif ($kind -eq 'rows' -and @($RestorableBases | Where-Object { "$_" -ieq "$($d.entity)" }).Count) { $restore = 'rows' }
        elseif ($kind -eq 'table') { $how = 'MSP configuration: change it on Reviews & controls > Managed tenant registry (shown here so you can see what changed).' }
        else { $how = 'This entity is not edited on a Manager page; restore it with the full-entity tools (shown here so you can see what changed).' }
        $sett = { param($name) if ($kind -eq 'settings') { Get-PimConfigBackupSettingRestoreRoute -Name $name } else { '' } }
        $out.Add([ordered]@{
            entity = "$($d.entity)"; kind = $kind; restore = $restore; howTo = $how; same = [int]$d.same
            added   = @($d.added   | ForEach-Object { [ordered]@{ key = "$($_.key)"; now = $_.now; route = (& $sett "$($_.key)") } })
            removed = @($d.removed | ForEach-Object { [ordered]@{ key = "$($_.key)"; backup = $_.backup; route = (& $sett "$($_.key)") } })
            changed = @($d.changed | ForEach-Object { [ordered]@{ key = "$($_.key)"; route = (& $sett "$($_.key)"); backup = $_.backup
                                                                 fields = @($_.fields | ForEach-Object { [ordered]@{ field = "$($_.field)"; now = $_.now; backup = $_.backup } }) } })
        })
    }
    return @($out.ToArray())
}

function Invoke-PimConfigBackupSettingsRestore {
    <#
      Restores the ticked SETTINGS of one backup (CONFIG-1.4: per setting, old -> new). -Backup: Get-PimConfigBackupContent
      output. -Reader { param($Name) <current stored value or $null> }; -Writer { param($Name, $ValueJson) } ($null = clear the
      setting); -Audit { param($Name, $Before, $After) }. A setting the backup holds is written with the CURRENT secrets put back
      (Get-PimConfigBackupSettingRestoreResult -- also inside a list, by index); a setting added since the backup is cleared.
      Only route 'direct' is written -- the break-glass list (maker/checker), the emergency override and every deny-listed
      name are refused here. BUG-BACKUP-LIST-KEY: a setting with a redacted field inside a list that cannot be put back (the
      list no longer lines up with the current one) is NOT written -- skipped with the paths; a list item that was itself a
      secret stays out as before and is listed in notRestored.
      Returns @{ written = @(names); skipped = @(@{ name; reason [; paths] }); errors = @(@{ name; error });
                 notRestored = @(@{ name; path; reason }) }.
    #>
    param([Parameter(Mandatory)][hashtable]$Backup, [string[]]$Names = @(), [Parameter(Mandatory)][scriptblock]$Reader,
          [Parameter(Mandatory)][scriptblock]$Writer, [scriptblock]$Audit = $null)
    $ent = $Backup.entities['pim.Settings']
    $items = @{}; if ($ent) { foreach ($i in @($ent.items)) { $items["$($i.key)".ToLowerInvariant()] = $i } }
    $red = @(if ($ent) { @($ent.redacted) } else { @() })
    $written = New-Object System.Collections.Generic.List[string]; $skipped = New-Object System.Collections.Generic.List[object]; $errors = New-Object System.Collections.Generic.List[object]
    $notRestored = New-Object System.Collections.Generic.List[object]
    foreach ($n in @($Names | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Select-Object -Unique)) {
        $route = Get-PimConfigBackupSettingRestoreRoute -Name $n
        if ($route -ne 'direct') {
            $why = switch ($route) { 'breakglass' { 'the break-glass list is changed by its own request, approved by a second SuperAdmin (Emergency access)' } default { 'this setting is never restored from a backup (a secret, runtime state or a time-boxed emergency override)' } }
            $skipped.Add(@{ name = $n; reason = $why }); continue
        }
        try {
            $cur = & $Reader $n
            $it = $items[$n.ToLowerInvariant()]
            if ($it) {
                $paths = @($red | Where-Object { "$_".StartsWith("${n}:", [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object { "$_".Substring($n.Length + 1) })
                # a list stays a list, also with one item (BUG-BACKUP-LIST-KEY: Filters [{..}] was written back as {..})
                $bv = ConvertFrom-PimConfigBackupJsonValue -Json $it.json
                $rr = Get-PimConfigBackupSettingRestoreResult -Backup $bv -Current $cur -RedactedPaths $paths
                # A field INSIDE A LIST the backup could not hold, and the current value no longer lines up to put it back:
                # writing the setting would store list items WITHOUT that field. Not written -- skipped, with the paths.
                $lost = @($rr.notRestored | Where-Object { $_.inList })
                if ($lost.Count) {
                    $skipped.Add(@{ name = $n; reason = ('not restored: the backup could not hold ' + (@($lost | ForEach-Object { "$($_.path) ($($_.reason))" }) -join '; ') +
                                                          ' -- writing it would leave those list items without them. Change it on its own page.')
                                    paths = @($lost | ForEach-Object { "$($_.path)" }) })
                    continue
                }
                foreach ($x in @($rr.notRestored)) { $notRestored.Add(@{ name = $n; path = "$($x.path)"; reason = "$($x.reason)" }) }
                $nv = $rr.value
                $json = if ($null -eq $nv) { $null } else { ConvertTo-Json -InputObject $nv -Depth 30 -Compress }
                & $Writer $n $json
                if ($Audit) { & $Audit $n (Remove-PimConfigBackupSecrets -Value $cur).value $bv }
            } else {
                & $Writer $n $null
                if ($Audit) { & $Audit $n (Remove-PimConfigBackupSecrets -Value $cur).value $null }
            }
            $written.Add($n)
        } catch { $errors.Add(@{ name = $n; error = "$($_.Exception.Message)" }) }
    }
    return @{ written = @($written.ToArray()); skipped = @($skipped.ToArray()); errors = @($errors.ToArray()); notRestored = @($notRestored.ToArray()) }
}

function Test-PimConfigBackupItemRedacted {
    <# PURE. True when the backup could not hold ROW <Entity>/<Key> whole: a property was redacted, or the row was dropped. #>
    param([string]$Entity, [string]$Key, [string[]]$Redacted = @())
    $label = "$Entity/$Key"
    foreach ($p in @($Redacted)) {
        $s = "$p"
        if ($s.Equals($label, [StringComparison]::OrdinalIgnoreCase) -or $s.StartsWith("${label}:", [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function New-PimConfigBackupRestoreRowPlan {
    <#
      PURE. PIM s98.3 -- the FULL row set ONE pim.Rows entity holds after it is put back to a backup, for a full-set commit
      (Invoke-PimConfigBackupRestoreCommit). -Diff: one entity of Compare-PimConfigBackupSnapshot (added / removed / changed
      since the backup). -LiveItems: the rows as stored NOW (@{ key; json }, the stored text). -BackupItems /
      -BackupRedacted: that entity of the backup (Get-PimConfigBackupContent).
        * a row the diff does not name stays EXACTLY as stored (its live text -- a secret in it is kept);
        * changed since    -> the backup's row;
        * removed since    -> the backup's row is added back;
        * added since      -> taken out.
      A changed / removed / added row whose backup copy is REDACTED (a secret the backup could not hold) is never restored
      by this path -- writing it would blank the secret -- and makes the plan refused (ok = $false, refused[] says which).
      Returns @{ entity; ok; refused; items = @(@{ key; json; op = Keep|Modify|Add }); beforeCount; afterCount; adds;
      modifies; removes; removedKeys }.
    #>
    param([Parameter(Mandatory)][hashtable]$Diff, [object[]]$LiveItems = @(), [object[]]$BackupItems = @(), [string[]]$BackupRedacted = @())
    $entity = "$($Diff.entity)"
    $bk = @{}; foreach ($i in @($BackupItems | Where-Object { $_ })) { $bk["$($i.key)".ToLowerInvariant()] = $i }
    $drop = @{}; foreach ($a in @($Diff.added | Where-Object { $_ })) { $drop["$($a.key)".ToLowerInvariant()] = $true }
    $chg = @{}; foreach ($c in @($Diff.changed | Where-Object { $_ })) { $chg["$($c.key)".ToLowerInvariant()] = $true }
    $refused = New-Object System.Collections.Generic.List[string]
    $items = New-Object System.Collections.Generic.List[object]
    $removedKeys = New-Object System.Collections.Generic.List[string]
    $liveKeys = @{}; $adds = 0; $mods = 0
    $live = @($LiveItems | Where-Object { $_ -and "$($_.key)".Trim() })
    foreach ($li in $live) {
        $k = "$($li.key)"; $lk = $k.ToLowerInvariant(); $liveKeys[$lk] = $true
        if ($drop.ContainsKey($lk)) {
            if (Test-PimConfigBackupItemRedacted -Entity $entity -Key $k -Redacted $BackupRedacted) { $refused.Add("$entity/$k is not in the backup because the backup could not hold it (a secret) -- it is never taken out by a restore") ; continue }
            $removedKeys.Add($k); continue
        }
        if ($chg.ContainsKey($lk)) {
            $b = $bk[$lk]
            if (Test-PimConfigBackupItemRedacted -Entity $entity -Key $k -Redacted $BackupRedacted) { $refused.Add("$entity/$k holds a secret the backup could not keep -- restoring it would blank that secret"); continue }
            if (-not $b -or $null -eq $b.json -or "$($b.json)".Trim() -eq '') { $refused.Add("$entity/$k has no stored value in the backup"); continue }
            $items.Add(@{ key = $k; json = "$($b.json)"; op = 'Modify' }); $mods++; continue
        }
        $items.Add(@{ key = $k; json = "$($li.json)"; op = 'Keep' })
    }
    foreach ($r in @($Diff.removed | Where-Object { $_ })) {
        $k = "$($r.key)"; $lk = $k.ToLowerInvariant()
        if ($liveKeys.ContainsKey($lk)) { continue }   # stored again since the diff was taken: kept as it is
        $b = $bk[$lk]
        if (Test-PimConfigBackupItemRedacted -Entity $entity -Key $k -Redacted $BackupRedacted) { $refused.Add("$entity/$k holds a secret the backup could not keep -- adding it back would leave that secret blank"); continue }
        if (-not $b -or $null -eq $b.json -or "$($b.json)".Trim() -eq '') { $refused.Add("$entity/$k has no stored value in the backup"); continue }
        $items.Add(@{ key = $k; json = "$($b.json)"; op = 'Add' }); $adds++
    }
    return @{ entity = $entity; ok = ($refused.Count -eq 0); refused = @($refused.ToArray()); items = @($items.ToArray())
              beforeCount = $live.Count; afterCount = $items.Count; adds = $adds; modifies = $mods; removes = $removedKeys.Count; removedKeys = @($removedKeys.ToArray()) }
}

# ---------------------------------------------------------------------------------------------------------------------
# The store (SQL)
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimConfigBackupDdl {
    @"
IF OBJECT_ID('pim.ConfigBackups') IS NULL
CREATE TABLE pim.ConfigBackups (
    BackupId     NVARCHAR(64)  NOT NULL CONSTRAINT PK_pim_ConfigBackups PRIMARY KEY,
    TakenUtc     DATETIME2     NOT NULL CONSTRAINT DF_ConfigBackups_Ts DEFAULT SYSUTCDATETIME(),
    TakenBy      NVARCHAR(200) NOT NULL,
    [Trigger]    NVARCHAR(40)  NOT NULL,
    Version      NVARCHAR(40)  NULL,
    ContentHash  NVARCHAR(64)  NOT NULL,
    Pinned       BIT           NOT NULL CONSTRAINT DF_ConfigBackups_Pinned DEFAULT 0,
    PinnedBy     NVARCHAR(200) NULL,
    PinnedUtc    DATETIME2     NULL,
    NoChange     BIT           NOT NULL CONSTRAINT DF_ConfigBackups_NoChange DEFAULT 0,
    SameAs       NVARCHAR(64)  NULL,
    Entities     INT           NOT NULL CONSTRAINT DF_ConfigBackups_Entities DEFAULT 0,
    Items        INT           NOT NULL CONSTRAINT DF_ConfigBackups_Items DEFAULT 0,
    Bytes        INT           NOT NULL CONSTRAINT DF_ConfigBackups_Bytes DEFAULT 0,
    ManifestJson NVARCHAR(MAX) NULL,
    Note         NVARCHAR(400) NULL
);
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'IX_pim_ConfigBackups_Taken')
CREATE INDEX IX_pim_ConfigBackups_Taken ON pim.ConfigBackups (TakenUtc DESC);
IF OBJECT_ID('pim.ConfigBackupEntities') IS NULL
CREATE TABLE pim.ConfigBackupEntities (
    BackupId     NVARCHAR(64)   NOT NULL,
    Entity       NVARCHAR(200)  NOT NULL,
    Kind         NVARCHAR(20)   NOT NULL,
    ItemCount    INT            NOT NULL,
    ContentHash  NVARCHAR(64)   NOT NULL,
    ContentGz    VARBINARY(MAX) NOT NULL,
    CONSTRAINT PK_pim_ConfigBackupEntities PRIMARY KEY (BackupId, Entity),
    CONSTRAINT FK_pim_ConfigBackupEntities_Backup FOREIGN KEY (BackupId) REFERENCES pim.ConfigBackups (BackupId) ON DELETE CASCADE
);
"@
}

function Confirm-PimConfigBackupStoreReady {
    <#
      Framework §12.23 run 2 prerequisite (PIM 100.156): the RUNTIME half (the config-backup job, the Manager's backup page).
      Read-only check that both tables are there -- the schema step (Initialize-PimSqlStore, the updater) creates them; the
      create (Initialize-PimConfigBackupStore) is only a one-time fallback. Never throws: @{ ok; detail }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    $r = Confirm-PimSqlSchemaObject -ConnectionString $ConnectionString -Objects @('pim.ConfigBackups', 'pim.ConfigBackupEntities') `
            -Fallback { $i = Initialize-PimConfigBackupStore -ConnectionString $ConnectionString; if (-not $i.ok) { throw "$($i.detail)" } }
    if ($r.ok) { return @{ ok = $true; detail = 'pim.ConfigBackups + pim.ConfigBackupEntities in place' } }
    return @{ ok = $false; detail = "backup tables NOT in place: $($r.message)" }
}

function Initialize-PimConfigBackupStore {
    <# Creates the two tables. Never throws (a store must still open); returns @{ ok; detail }. #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    try {
        [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimConfigBackupDdl))
        return @{ ok = $true; detail = 'pim.ConfigBackups + pim.ConfigBackupEntities in place' }
    } catch {
        $m = "$($_.Exception.Message)"
        Write-Warning "[config-backup] the backup tables could not be created -- no configuration backup can be taken: $m"
        return @{ ok = $false; detail = "backup tables NOT in place: $m" }
    }
}

function Get-PimConfigBackupProductVersion {
    try {
        $v = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'VERSION'
        if (Test-Path -LiteralPath $v) { return ("$(Get-Content -Raw -LiteralPath $v)").Trim() }
    } catch { }
    return ''
}

function Get-PimConfigBackupRetentionDays {
    <# The stored retention (pim.Settings 'ConfigBackupRetentionDays'); 90 when unset or unreadable as a number. #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    $v = $null
    try { $v = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'ConfigBackupRetentionDays' } catch { $v = $null }
    try { return (ConvertTo-PimConfigBackupRetentionDays -Value $v) } catch { return 90 }
}

function Get-PimConfigBackupCurrentSnapshot {
    <# The configuration as it is NOW, in backup form (New-PimConfigBackupSnapshot over the live store). #>
    param([Parameter(Mandatory)][string]$ConnectionString)
    $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql 'SELECT Entity, [Key], DataJson FROM pim.Rows')
    $settings = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql 'SELECT Name, ValueJson FROM pim.Settings')
    $tables = @{}
    # MSP configuration: read only where the table exists (a managing tenant). The column list is read as JSON per row.
    $have = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT CASE WHEN OBJECT_ID('platform.Tenants') IS NULL THEN 0 ELSE 1 END AS t, CASE WHEN OBJECT_ID('pim.CentralAdmins') IS NULL THEN 0 ELSE 1 END AS c")
    if ($have.Count -and [int]$have[0].t -eq 1) {
        $tables['platform.Tenants'] = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT CONVERT(nvarchar(50), TenantId) AS k, (SELECT t2.* FROM platform.Tenants t2 WHERE t2.TenantId = t.TenantId FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) AS j FROM platform.Tenants t" |
            ForEach-Object { @{ key = "$($_.k)"; json = "$($_.j)" } })
    }
    if ($have.Count -and [int]$have[0].c -eq 1) {
        $tables['pim.CentralAdmins'] = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT UserName AS k, (SELECT c2.* FROM pim.CentralAdmins c2 WHERE c2.UserName = c.UserName FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) AS j FROM pim.CentralAdmins c" |
            ForEach-Object { @{ key = "$($_.k)"; json = "$($_.j)" } })
    }
    return (New-PimConfigBackupSnapshot -Rows $rows -Settings $settings -Tables $tables)
}

function Write-PimConfigBackupAudit {
    param([string]$ConnectionString, [string]$Actor, [string]$ActorSource, [string]$Action, [string]$Target, [object]$Before, [object]$After, [string]$Result = 'ok')
    if (-not (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue)) { return }
    try { Write-PimSqlAuditEvent -ConnectionString $ConnectionString -Actor $(if ("$Actor".Trim()) { $Actor } else { 'system' }) -ActorSource $ActorSource -Action $Action -Target $Target -Before $Before -After $After -Result $Result }
    catch { Write-Warning "[config-backup] the audit event $Action could not be written: $($_.Exception.Message)" }
}

function New-PimConfigBackup {
    <#
      Takes ONE configuration backup (CONFIG-1.3). Unchanged since the last REAL backup (same content hash) -> a "no change"
      record (NoChange = 1, SameAs = that backup), no copy. Header + entity documents are written in ONE transaction.
      Audited config.backup. Returns @{ backupId; noChange; sameAs; hash; entities; items; bytes; excluded; redacted }.
      -WhatIf: builds the snapshot and reports, writes nothing.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [string]$TakenBy = 'system', [string]$Trigger = 'manual',
          [string]$Version = '', [string]$Note = '', [switch]$WhatIf, [hashtable]$Snapshot = $null, [datetime]$NowUtc = [datetime]::UtcNow)
    $snap = if ($Snapshot) { $Snapshot } else { Get-PimConfigBackupCurrentSnapshot -ConnectionString $ConnectionString }
    if (-not "$Version".Trim()) { $Version = Get-PimConfigBackupProductVersion }
    $last = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql 'SELECT TOP 1 BackupId, ContentHash FROM pim.ConfigBackups WHERE NoChange = 0 ORDER BY TakenUtc DESC, BackupId DESC')
    $noChange = ($last.Count -and "$($last[0].ContentHash)" -eq "$($snap.hash)")
    $id = 'cb-' + $NowUtc.ToUniversalTime().ToString('yyyyMMdd-HHmmss') + '-' + ([guid]::NewGuid().ToString('N').Substring(0, 6))
    $manifest = [ordered]@{
        excludedSettings = @($snap.excluded.settings | ForEach-Object { [ordered]@{ name = "$($_.name)"; reason = "$($_.reason)" } })
        excludedEntities = @($snap.excluded.entities | ForEach-Object { [ordered]@{ entity = "$($_.entity)"; rows = [int]$_.rows } })
        redacted         = @($snap.redacted)
        entities         = @($snap.entities.Keys | ForEach-Object { [ordered]@{ entity = "$_"; kind = "$($snap.entities[$_].kind)"; items = @($snap.entities[$_].items).Count } })
    }
    $docs = New-Object System.Collections.Generic.List[object]; $bytes = 0
    if (-not $noChange) {
        foreach ($e in @($snap.entities.Keys)) {
            $ent = $snap.entities[$e]
            $doc = [ordered]@{ entity = "$e"; kind = "$($ent.kind)"; redacted = @($ent.redacted); items = @($ent.items | ForEach-Object { [ordered]@{ key = "$($_.key)"; json = $_.json } }) }
            $gz = Compress-PimConfigBackupText -Text (ConvertTo-Json -InputObject $doc -Depth 6 -Compress)
            $bytes += $gz.Length
            $docs.Add(@{ entity = "$e"; kind = "$($ent.kind)"; count = @($ent.items).Count; hash = "$($ent.hash)"; gz = $gz })
        }
    }
    $res = [ordered]@{ backupId = $id; noChange = [bool]$noChange; sameAs = $(if ($noChange) { "$($last[0].BackupId)" } else { '' }); hash = "$($snap.hash)"
                       entities = @($snap.entities.Keys).Count; items = [int]$snap.itemCount; bytes = $bytes; whatIf = [bool]$WhatIf
                       excludedSettings = @($snap.excluded.settings).Count; redacted = @($snap.redacted).Count }
    if ($WhatIf) { return [pscustomobject]$res }
    $c = New-PimSqlConnection -ConnectionString $ConnectionString; $tx = $null
    try {
        $c.Open(); $tx = $c.BeginTransaction()
        $cmd = $c.CreateCommand(); $cmd.Transaction = $tx
        $cmd.CommandText = @"
INSERT INTO pim.ConfigBackups (BackupId, TakenUtc, TakenBy, [Trigger], Version, ContentHash, NoChange, SameAs, Entities, Items, Bytes, ManifestJson, Note)
VALUES (@id, @ts, @by, @tr, @v, @h, @nc, @sa, @en, @it, @by2, @mf, @no);
"@
        $p = [ordered]@{ id = $id; ts = $NowUtc.ToUniversalTime(); by = $(if ("$TakenBy".Trim()) { "$TakenBy" } else { 'system' }); tr = "$Trigger"; v = "$Version"; h = "$($snap.hash)"
                         nc = [int][bool]$noChange; sa = $(if ($noChange) { "$($last[0].BackupId)" } else { $null }); en = [int]$res.entities; it = [int]$res.items; by2 = [int]$bytes
                         mf = (ConvertTo-Json -InputObject $manifest -Depth 6 -Compress); no = $(if ("$Note".Trim()) { "$Note" } else { $null }) }
        foreach ($k in $p.Keys) { [void]$cmd.Parameters.AddWithValue("@$k", $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) }
        [void]$cmd.ExecuteNonQuery()
        foreach ($d in $docs) {
            $ec = $c.CreateCommand(); $ec.Transaction = $tx
            $ec.CommandText = 'INSERT INTO pim.ConfigBackupEntities (BackupId, Entity, Kind, ItemCount, ContentHash, ContentGz) VALUES (@id, @e, @k, @n, @h, @g)'
            [void]$ec.Parameters.AddWithValue('@id', $id); [void]$ec.Parameters.AddWithValue('@e', $d.entity); [void]$ec.Parameters.AddWithValue('@k', $d.kind)
            [void]$ec.Parameters.AddWithValue('@n', [int]$d.count); [void]$ec.Parameters.AddWithValue('@h', $d.hash)
            $gp = $ec.Parameters.Add('@g', [System.Data.SqlDbType]::VarBinary, -1); $gp.Value = [byte[]]$d.gz
            [void]$ec.ExecuteNonQuery()
        }
        $tx.Commit(); $tx = $null
    } catch {
        if ($tx) { try { $tx.Rollback() } catch { } }
        throw
    } finally { if ($c) { $c.Close(); $c.Dispose() } }
    Write-PimConfigBackupAudit -ConnectionString $ConnectionString -Actor $TakenBy -ActorSource $Trigger -Action 'config.backup' -Target "pim.ConfigBackups:$id" `
        -After ([ordered]@{ backupId = $id; trigger = $Trigger; noChange = [bool]$noChange; sameAs = $res.sameAs; hash = "$($snap.hash)"; entities = $res.entities; items = $res.items; bytes = $bytes; excludedSettings = $res.excludedSettings; redacted = $res.redacted; version = $Version }) `
        -Result $(if ($noChange) { 'no-change' } else { 'ok' })
    return [pscustomobject]$res
}

function Get-PimConfigBackupList {
    <# The backups, newest first (headers only). #>
    param([Parameter(Mandatory)][string]$ConnectionString, [int]$Top = 500)
    return @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters @{ t = $Top } -Sql @"
SELECT TOP (@t) BackupId, TakenUtc, TakenBy, [Trigger], Version, ContentHash, Pinned, PinnedBy, PinnedUtc, NoChange, SameAs, Entities, Items, Bytes, Note, ManifestJson
FROM pim.ConfigBackups ORDER BY TakenUtc DESC, BackupId DESC
"@)
}

function Get-PimConfigBackupContent {
    <#
      One backup's snapshot (the shape New-PimConfigBackupSnapshot returns: entities -> items + redacted). A "no change"
      record resolves to the backup it points at. Returns $null when the backup does not exist.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$BackupId)
    $h = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters @{ id = $BackupId } -Sql 'SELECT BackupId, NoChange, SameAs, ContentHash, TakenUtc FROM pim.ConfigBackups WHERE BackupId = @id')
    if (-not $h.Count) { return $null }
    $src = if ([bool]$h[0].NoChange -and "$($h[0].SameAs)".Trim()) { "$($h[0].SameAs)" } else { $BackupId }
    $docs = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters @{ id = $src } -Sql 'SELECT Entity, Kind, ContentHash, ContentGz FROM pim.ConfigBackupEntities WHERE BackupId = @id ORDER BY Entity')
    if ([bool]$h[0].NoChange -and -not $docs.Count) { throw "backup $BackupId records 'no change since $src', and $src is no longer stored" }
    $ents = [ordered]@{}
    foreach ($d in $docs) {
        $doc = (Expand-PimConfigBackupText -Bytes ([byte[]]$d.ContentGz)) | ConvertFrom-Json
        $ents["$($d.Entity)"] = @{ entity = "$($d.Entity)"; kind = "$($d.Kind)"; hash = "$($d.ContentHash)"; redacted = @($doc.redacted | Where-Object { $_ })
                                   items = @($doc.items | Where-Object { $_ } | ForEach-Object { @{ key = "$($_.key)"; json = $(if ($null -eq $_.json) { $null } else { "$($_.json)" }) } }) }
    }
    return @{ backupId = $BackupId; source = $src; hash = "$($h[0].ContentHash)"; takenUtc = $h[0].TakenUtc; entities = $ents }
}

function Get-PimConfigBackupDiff {
    <# The difference between one backup and the configuration NOW (Compare-PimConfigBackupSnapshot). $null = no such backup. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$BackupId)
    $b = Get-PimConfigBackupContent -ConnectionString $ConnectionString -BackupId $BackupId
    if (-not $b) { return $null }
    $now = Get-PimConfigBackupCurrentSnapshot -ConnectionString $ConnectionString
    return @{ backup = $b; current = $now; entities = @(Compare-PimConfigBackupSnapshot -Backup $b -Current $now) }
}

function Set-PimConfigBackupPinned {
    <# Pins / unpins one backup (a pinned backup is kept past the retention). Audited config.backup.pin / .unpin. $false = no such backup. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$BackupId, [bool]$Pinned = $true, [string]$By = 'system', [string]$Note = '')
    $n = Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Parameters @{ id = $BackupId; p = [int]$Pinned; by = $(if ($Pinned) { $By } else { $null }); no = $(if ("$Note".Trim()) { "$Note" } else { $null }) } -Sql @"
UPDATE pim.ConfigBackups SET Pinned = @p, PinnedBy = @by, PinnedUtc = CASE WHEN @p = 1 THEN SYSUTCDATETIME() ELSE NULL END, Note = COALESCE(@no, Note) WHERE BackupId = @id
"@
    if ([int]$n -lt 1) { return $false }
    Write-PimConfigBackupAudit -ConnectionString $ConnectionString -Actor $By -ActorSource 'manager' -Action $(if ($Pinned) { 'config.backup.pin' } else { 'config.backup.unpin' }) -Target "pim.ConfigBackups:$BackupId" -After ([ordered]@{ backupId = $BackupId; pinned = $Pinned; note = "$Note" })
    return $true
}

function Invoke-PimConfigBackupPrune {
    <#
      Deletes the backups the retention plan prunes (Get-PimConfigBackupRetentionPlan). Audited config.backup.prune with the ids
      (one event per run that deleted something). -WhatIf reports only. Returns @{ pruned = @(ids); kept; retentionDays }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [int]$RetentionDays = 0, [datetime]$NowUtc = [datetime]::UtcNow, [string]$By = 'system', [switch]$WhatIf)
    if ($RetentionDays -lt 1) { $RetentionDays = Get-PimConfigBackupRetentionDays -ConnectionString $ConnectionString }
    $all = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql 'SELECT BackupId, TakenUtc, Pinned, NoChange, SameAs FROM pim.ConfigBackups')
    $plan = Get-PimConfigBackupRetentionPlan -Backups $all -RetentionDays $RetentionDays -NowUtc $NowUtc
    $ids = @($plan.prune)
    if ($ids.Count -and -not $WhatIf) {
        # "no change" records first (they point at real backups), then the rest; ON DELETE CASCADE removes the documents.
        foreach ($id in $ids) {
            [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Parameters @{ id = $id } -Sql 'DELETE FROM pim.ConfigBackups WHERE BackupId = @id AND Pinned = 0')
        }
        Write-PimConfigBackupAudit -ConnectionString $ConnectionString -Actor $By -ActorSource 'scheduler' -Action 'config.backup.prune' -Target 'pim.ConfigBackups' `
            -After ([ordered]@{ retentionDays = $RetentionDays; cutoffUtc = $plan.cutoffUtc; pruned = $ids; kept = @($plan.keep).Count })
    }
    return [pscustomobject]@{ pruned = $ids; kept = @($plan.keep).Count; retentionDays = $RetentionDays; whatIf = [bool]$WhatIf; keep = @($plan.keep) }
}

function Invoke-PimConfigBackupJob {
    <#
      The scheduled 'config-backup' job: one backup (or a "no change" record), then the retention prune. A failed backup
      THROWS (the run fails; never reported as done). -WhatIf builds the snapshot and the plan, writes nothing.
    #>
    param([object]$Job = $null, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [string]$ConnectionString = '')
    $cs = $ConnectionString
    if (-not $cs -and (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue)) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = '' } }
    if (-not $cs) { throw '[config-backup] no SQL store -- the configuration cannot be read' }
    # §12.23 run 2 (PIM 100.156): a read-only check; the schema step creates the tables
    $cbReady = Confirm-PimConfigBackupStoreReady -ConnectionString $cs
    if (-not $cbReady.ok) { throw "[config-backup] $($cbReady.detail)" }
    $b = New-PimConfigBackup -ConnectionString $cs -TakenBy 'system:config-backup' -Trigger 'scheduled' -NowUtc $NowUtc -WhatIf:$WhatIf
    $p = Invoke-PimConfigBackupPrune -ConnectionString $cs -NowUtc $NowUtc -By 'system:config-backup' -WhatIf:$WhatIf
    $what = if ($b.noChange) { "no change since $($b.sameAs) (recorded, no copy)" } else { "backup $($b.backupId): $($b.entities) entities, $($b.items) items, $($b.bytes) bytes compressed" }
    return [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf; backupId = "$($b.backupId)"; noChange = [bool]$b.noChange; pruned = @($p.pruned).Count
        detail = ("config backup{0}: {1}; retention {2} days: {3} pruned, {4} kept" -f $(if ($WhatIf) { ' (what-if)' } else { '' }), $what, $p.retentionDays, @($p.pruned).Count, $p.kept) }
}

# ---------------------------------------------------------------------------------------------------------------------
# PIM s98.3 -- the UNATTENDED entity restore: commit a restore plan as the SYSTEM actor
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimConfigBackupLiveRowItems {
    <# The rows of one pim.Rows entity EXACTLY as stored: @(@{ key; json }) (the stored [Key] and DataJson text). #>
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Entity)
    return @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Parameters @{ e = $Entity } -Sql 'SELECT [Key], DataJson FROM pim.Rows WHERE Entity = @e ORDER BY [Key]' |
        ForEach-Object { @{ key = "$($_.Key)"; json = $(if ($null -eq $_.DataJson -or $_.DataJson -is [DBNull]) { $null } else { "$($_.DataJson)" }) } })
}

function Invoke-PimConfigBackupRestoreCommit {
    <#
      PIM s98.3 / CONFIG-1.4: COMMIT A RESTORE PLAN (New-PimConfigBackupRestoreRowPlan, one per entity) server-side, as -Actor
      (default: the system actor of this process). The SAME store path the Manager's restore commit ends in: a full-set
      replace per entity (Set-PimSqlEntityRowsTransactional, one transaction each), journaled in pim.CommitJournal with
      Source 'restore' under ONE commit id for the whole restore, audited config.restore per entity, and the engine asked to
      reconcile (Request-PimCommit) -- never a direct pim.Rows write. Shared by the demo-baseline-restore job and any
      server-side caller (the GUI's restore commit can call it with the signed-in person as -Actor).
      THE MASS-CHANGE BREAKER STAYS IN FORCE: the commit removal check (Test-PimCommitDeltaGuard -- the count limit, "keeps
      none of the rows", "few left") is evaluated for EVERY entity BEFORE ANY write. One hold = NOTHING is written: the
      result is held = $true with the holds, audited config.restore.held. There is no -Approved / -Confirm here: an
      unattended caller has no SuperAdmin to approve exactly these rows, so it stops and reports -- it never forces.
      A refused plan (a row whose secret the backup could not hold) = nothing is written either.
      No guard library or no journal loaded = THROWS before any write (a restore that cannot be checked is not applied).
      -WhatIf: the checks and the plan, nothing written. Returns @{ ok; held; holds; refused; whatIf; commitId; written =
      @(@{ entity; adds; modifies; removes; rowCount }); errors = @(@{ entity; error }) }.
    #>
    param([Parameter(Mandatory)][string]$ConnectionString, [object[]]$Plans = @(), [string]$BackupId = '', [string]$Actor = '',
          [string]$ActorSource = 'scheduler', [string]$CommitId = '', [switch]$WhatIf)
    if (-not (Get-Command Test-PimCommitDeltaGuard -ErrorAction SilentlyContinue)) { throw '[restore] the guard library (PIM-ManagerWriteGuards.ps1) is not loaded -- nothing was restored: the removal check of this restore cannot run' }
    if (-not (Get-Command New-PimCommitJournalContext -ErrorAction SilentlyContinue)) { throw '[restore] the change journal (PIM-CommitJournal.ps1) is not loaded -- nothing was restored: a restore is always journaled' }
    if (-not "$Actor".Trim()) { $Actor = Get-PimCommitJournalSystemActor }
    $plans = @($Plans | Where-Object { $_ })
    $res = [ordered]@{ ok = $false; held = $false; holds = @(); refused = @(); whatIf = [bool]$WhatIf; commitId = ''; written = @(); errors = @(); actor = "$Actor"; backupId = "$BackupId" }
    $refused = @($plans | Where-Object { -not $_.ok } | ForEach-Object { @($_.refused) })
    if ($refused.Count) { $res.refused = $refused; return [pscustomobject]$res }
    # 1) the breaker, for every entity, before any write
    $holds = New-Object System.Collections.Generic.List[object]
    foreach ($p in $plans) {
        $g = Test-PimCommitDeltaGuard -BeforeCount ([int]$p.beforeCount) -AfterCount ([int]$p.afterCount) -RemoveCount ([int]$p.removes)
        if (-not $g.allowed) { $holds.Add([ordered]@{ entity = "$($p.entity)"; rule = "$($g.rule)"; reason = "$($g.reason)"; removeCount = [int]$g.removeCount; limit = [int]$g.limit; removedKeys = @($p.removedKeys) }) }
    }
    if ($holds.Count) {
        $res.held = $true; $res.holds = @($holds.ToArray())
        if (-not $WhatIf) {
            Write-PimConfigBackupAudit -ConnectionString $ConnectionString -Actor $Actor -ActorSource $ActorSource -Action 'config.restore.held' -Target "pim.ConfigBackups:$BackupId" `
                -After ([ordered]@{ backupId = "$BackupId"; holds = @($holds.ToArray() | ForEach-Object { [ordered]@{ entity = $_.entity; rule = $_.rule; removeCount = $_.removeCount; limit = $_.limit } }); note = 'nothing was restored -- a SuperAdmin restores it from Backups & restore (and approves the removal there)' }) -Result 'held'
        }
        return [pscustomobject]$res
    }
    $todo = @($plans | Where-Object { ([int]$_.adds + [int]$_.modifies + [int]$_.removes) -gt 0 })
    if ($WhatIf) {
        $res.ok = $true
        $res.written = @($todo | ForEach-Object { [ordered]@{ entity = "$($_.entity)"; adds = [int]$_.adds; modifies = [int]$_.modifies; removes = [int]$_.removes; rowCount = [int]$_.afterCount } })
        return [pscustomobject]$res
    }
    if (-not $todo.Count) { $res.ok = $true; return [pscustomobject]$res }
    # 2) the writes: ONE commit id, Source 'restore', the actor named on every journal row
    $cid = if ("$CommitId".Trim()) { "$CommitId".Trim() } else { [guid]::NewGuid().ToString('N') }
    $res.commitId = $cid
    $ctx = New-PimCommitJournalContext -CommitId $cid -Source 'restore' -InitiatedBy $Actor
    $prev = Set-PimCommitJournalContext -Context $ctx
    $written = New-Object System.Collections.Generic.List[object]; $errors = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($p in $todo) {
            $rows = @($p.items | ForEach-Object { ConvertFrom-PimConfigBackupJson -Json $_.json } | Where-Object { $null -ne $_ })
            try {
                $w = Set-PimSqlEntityRowsTransactional -ConnectionString $ConnectionString -Entity "$($p.entity)" -Base "$($p.entity)" -Rows $rows -AllowEmpty
                $one = [ordered]@{ entity = "$($p.entity)"; adds = [int]$p.adds; modifies = [int]$p.modifies; removes = [int]$p.removes; rowCount = $(if ($w -and $null -ne $w.rowCount) { [int]$w.rowCount } else { $rows.Count }) }
                $written.Add($one)
                Write-PimConfigBackupAudit -ConnectionString $ConnectionString -Actor $Actor -ActorSource $ActorSource -Action 'config.restore' -Target "rows:$($p.entity)" `
                    -Before ([ordered]@{ rows = [int]$p.beforeCount }) -After ([ordered]@{ backupId = "$BackupId"; commitId = $cid; rows = [int]$p.afterCount; adds = [int]$p.adds; modifies = [int]$p.modifies; removes = [int]$p.removes; removedKeys = @($p.removedKeys) })
            } catch {
                $errors.Add([ordered]@{ entity = "$($p.entity)"; error = "$($_.Exception.Message)" })
                Write-PimConfigBackupAudit -ConnectionString $ConnectionString -Actor $Actor -ActorSource $ActorSource -Action 'config.restore' -Target "rows:$($p.entity)" `
                    -After ([ordered]@{ backupId = "$BackupId"; commitId = $cid; error = "$($_.Exception.Message)" }) -Result 'error'
                break   # the entities after it are not written: the run fails and the next run starts again from the diff
            }
        }
    } finally { [void](Set-PimCommitJournalContext -Context $prev) }
    # 3) like every commit: the engine reconciles what was put back
    if ($written.Count -and (Get-Command Request-PimCommit -ErrorAction SilentlyContinue)) {
        try { Request-PimCommit -Scope 'All' -Reason "restore:$BackupId" } catch { Write-Warning "[restore] the rows were restored, but the engine run could not be queued: $($_.Exception.Message) -- the next scheduled reconcile applies them" }
    }
    $res.written = @($written.ToArray()); $res.errors = @($errors.ToArray()); $res.ok = (-not $errors.Count)
    return [pscustomobject]$res
}
