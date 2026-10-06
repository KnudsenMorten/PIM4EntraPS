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
        identity = @('License', 'Licence', 'LicenceState', 'Edition', 'EditionUpgrade', 'InstallId', 'TelemetryInstallId',
                     'InstallKeyClaimState', 'SchedulerTickJobId')
        state    = @('UpdateState', 'SchedulerTriggers', 'JobRunHistory', 'ConvergenceState', 'EngineItemFailures',
                     'HybridWorkerHeartbeat', 'HybridAdSyncLive', 'HybridAdSyncLiveWatch', 'RecalcSignature', 'RecalcEntitySignatures',
                     'CommitWatch', 'CommitOutcomes', 'AlertFeed', 'DriftAlertState', 'UplinkState', 'LicenceRequestState',
                     'UnmanagedAdmins', 'AzResPolicyMassHold', 'AzResPolicyMassChangeApproval', 'GroupsPolicyMassHold',
                     'RemoveRowAbsentSeen', 'TenantCacheState', 'RingOrder', 'WorkloadPrereqs', 'CutoverState', 'PendingChanges',
                     'ApprovalRequests', 'GuardTrips', 'AccessReviewCampaigns', 'AccessReviewCycleState', 'AccessReviewReminders',
                     'AutoExtendDecisions', 'AutoExtendOutlook', 'CompanyReviewCampaigns', 'OwnerReviews', 'RfaRequests',
                     'DiscoveryBaseline', 'DiscoveryRoleBaseline', 'DownlinkIntents', 'DownlinkIntentsApplied', 'DownlinkApplied',
                     'EngineDesiredCounts', 'AdminOffboardState', 'ConformanceTemplateState',
                     'DefenderRoleCreatePending', 'IntakeRequests', 'LifecycleEscalationLog', 'ChangeQueue', 'DesiredState',
                     'DockerBuildRequest', 'SchedulerState', 'SchedulerLease')
        statePrefix = @('JobRunOutput:', 'SchedulerState', 'SchedulerLease', 'JobScope')
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
        $parsed = ConvertFrom-PimConfigBackupJson -Json $json
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

function Get-PimConfigBackupSettingRestoreValue {
    <#
      PURE. The value a settings restore WRITES: the backup's value with every secret the backup could not hold taken from the
      CURRENT value (the redacted paths of that setting), so a restore never blanks a key or a webhook. Paths are dotted
      top-down names (array positions are not carried back -- an array element that was a secret stays out).
    #>
    param([AllowNull()][object]$Backup, [AllowNull()][object]$Current, [string[]]$RedactedPaths = @())
    if ($null -eq $Backup) { return $null }
    $copy = ConvertFrom-PimConfigBackupJson -Json (ConvertTo-Json -InputObject $Backup -Depth 30 -Compress)
    foreach ($p in @($RedactedPaths | Where-Object { "$_".Trim() -and "$_" -notmatch '\[' })) {
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
    }
    return $copy
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
      (Get-PimConfigBackupSettingRestoreValue); a setting added since the backup is cleared. Only route 'direct' is written --
      the break-glass list (maker/checker), the emergency override and every deny-listed name are refused here.
      Returns @{ written = @(names); skipped = @(@{ name; reason }); errors = @(@{ name; error }) }.
    #>
    param([Parameter(Mandatory)][hashtable]$Backup, [string[]]$Names = @(), [Parameter(Mandatory)][scriptblock]$Reader,
          [Parameter(Mandatory)][scriptblock]$Writer, [scriptblock]$Audit = $null)
    $ent = $Backup.entities['pim.Settings']
    $items = @{}; if ($ent) { foreach ($i in @($ent.items)) { $items["$($i.key)".ToLowerInvariant()] = $i } }
    $red = @(if ($ent) { @($ent.redacted) } else { @() })
    $written = New-Object System.Collections.Generic.List[string]; $skipped = New-Object System.Collections.Generic.List[object]; $errors = New-Object System.Collections.Generic.List[object]
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
                $bv = ConvertFrom-PimConfigBackupJson -Json $it.json
                $nv = Get-PimConfigBackupSettingRestoreValue -Backup $bv -Current $cur -RedactedPaths $paths
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
    return @{ written = @($written.ToArray()); skipped = @($skipped.ToArray()); errors = @($errors.ToArray()) }
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
    [void](Initialize-PimConfigBackupStore -ConnectionString $cs)
    $b = New-PimConfigBackup -ConnectionString $cs -TakenBy 'system:config-backup' -Trigger 'scheduled' -NowUtc $NowUtc -WhatIf:$WhatIf
    $p = Invoke-PimConfigBackupPrune -ConnectionString $cs -NowUtc $NowUtc -By 'system:config-backup' -WhatIf:$WhatIf
    $what = if ($b.noChange) { "no change since $($b.sameAs) (recorded, no copy)" } else { "backup $($b.backupId): $($b.entities) entities, $($b.items) items, $($b.bytes) bytes compressed" }
    return [pscustomobject]@{ ran = $true; whatIf = [bool]$WhatIf; backupId = "$($b.backupId)"; noChange = [bool]$b.noChange; pruned = @($p.pruned).Count
        detail = ("config backup{0}: {1}; retention {2} days: {3} pruned, {4} kept" -f $(if ($WhatIf) { ' (what-if)' } else { '' }), $what, $p.retentionDays, @($p.pruned).Count, $p.kept) }
}
