#Requires -Version 5.1
<#
.SYNOPSIS
    REQ-N -- the MSP master's MANAGED-TENANT REGISTRY (platform.Tenants): read it, and write it through ONE writer that
    tools/setup/Register-PimManagedTenant.ps1 and the Manager's "Managed tenant registry" page both call.

.DESCRIPTION
    Operator 2026-09-19: "where do i define the tags and names for the tenants ? in settings ?". Until REQ-N the name, the
    master's copy of the ring, the tags and Enabled of a managed tenant could only be written by the setup script or the
    MSP build config. The Manager page now edits the same row, and it goes through the SAME code:
      * Get-PimManagedTenantRegistration (PIM-MspBuild.ps1, PURE) validates the values and builds the parameterised MERGE;
      * Set-PimManagedTenantRegistration (here) refuses what the registry must never hold (the master's own tenant, a
        second row for a tenant already registered, a second tenant with the same name), runs the MERGE and READS IT
        BACK. The callers audit (the script with Write-PimSetupAudit, the Manager with Write-PimManagerAuditEvent).
    One writer means the script and the page can never disagree about what a valid registration is.

    🔒 BUG-175 -- THE RING HERE IS THE MASTER'S COPY. Every ring is LOCAL in the managed tenant (its own -SlaveRing gates
    its pull); platform.Tenants.Ring is only what the master previews with. Everything this file returns labels it so.

    🔑 THE TAGS ARE WHAT TARGETING READS. The bundle producer signs platform.Tenants.Tags into the bundle
    (payload.tenantTags), and a row's Target (tag:<key:value>, tag:a+b, tenant:<id>) is evaluated against them. A tag is
    therefore validated with the grammar a Target can name (ConvertTo-PimTenantTags), and the words a Target reserves
    (all, none, tag:, tenant:) are refused as tags.

    PS 5.1 COMPATIBLE (the setup script runs under Windows PowerShell): no ?. / ??, no ternary, null-guarded.
#>

Set-StrictMode -Off

# The pure validation core lives with the MSP build (the build config registers tenants through it too).
if ($PSScriptRoot -and -not (Get-Command Get-PimManagedTenantRegistration -ErrorAction SilentlyContinue)) {
    $__mb = Join-Path $PSScriptRoot 'PIM-MspBuild.ps1'
    if (Test-Path -LiteralPath $__mb) { . $__mb }
}

function Get-PimMspRegistryValue {
    # PURE. Null-safe read across hashtable / IDictionary / PSCustomObject.
    param([object]$Object, [Parameter(Mandatory)][string]$Key)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Key)) { return $Object[$Key] }; return $null }
    $p = $Object.PSObject.Properties[$Key]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-PimMspRegistryUtcText {
    # PURE. A SQL datetime2 / string / $null -> 'yyyy-MM-ddTHH:mm:ssZ' or ''. SQL stores UTC (SYSUTCDATETIME), so an
    # Unspecified DateTime is UTC, never local.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return '' }
    $d = $null
    if ($Value -is [datetime]) { $d = $Value }
    else {
        $s = "$Value".Trim(); if (-not $s) { return '' }
        $p = [datetime]::MinValue
        if (-not [datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$p)) { return '' }
        $d = $p
    }
    if ($d.Kind -eq [System.DateTimeKind]::Local) { $d = $d.ToUniversalTime() }
    return $d.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-PimMspRingCopyLabel {
    # PURE. The one wording for the registry's ring field (REQ-N): it is the MASTER'S COPY, and the tenant's own ring decides.
    return "Ring (master's copy -- each managed tenant's own ring decides)"
}

function ConvertTo-PimManagedTenantView {
    # PURE. One platform.Tenants row -> what the page and the API show. The ring is labelled as the master's copy.
    param([Parameter(Mandatory)][object]$Row)
    $tid = "$(Get-PimMspRegistryValue $Row 'TenantId')".Trim().ToLowerInvariant()
    $ringRaw = "$(Get-PimMspRegistryValue $Row 'Ring')".Trim()
    $ring = $null; $r = 0
    if ($ringRaw -match '^\d+$' -and [int]::TryParse($ringRaw, [ref]$r)) { $ring = $r }
    $en = Get-PimMspRegistryValue $Row 'Enabled'
    $enabled = $false
    if ($en -is [bool]) { $enabled = $en } elseif ("$en".Trim() -match '^(1|true)$') { $enabled = $true }
    $tags = @("$(Get-PimMspRegistryValue $Row 'Tags')" -split '[;,]' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    return [ordered]@{
        tenantId     = $tid
        name         = "$(Get-PimMspRegistryValue $Row 'DisplayName')"
        ring         = $ring
        ringKnown    = ($null -ne $ring)
        ringSource   = 'master-copy'
        ringLabel    = Get-PimMspRingCopyLabel
        tags         = @($tags)
        tagsText     = ($tags -join ';')
        enabled      = $enabled
        notes        = "$(Get-PimMspRegistryValue $Row 'Notes')"
        createdUtc   = ConvertTo-PimMspRegistryUtcText (Get-PimMspRegistryValue $Row 'CreatedAtUtc')
        updatedUtc   = ConvertTo-PimMspRegistryUtcText (Get-PimMspRegistryValue $Row 'UpdatedAtUtc')
    }
}

function Get-PimManagedTenantRegistry {
    <#
      Every registered managed tenant -- ENABLED AND DISABLED (the page edits both; the reach preview reads only enabled
      ones through Get-PimManagerDownlinkTenants). Returns @{ available; reason; tenants = @(<ConvertTo-PimManagedTenantView>) }.
      🔒 An unreadable registry is available=$false WITH the reason -- never an empty list that reads as "no tenants".
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ConnectionString)
    $probe = $null
    try { $probe = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT CASE WHEN OBJECT_ID('platform.Tenants') IS NULL THEN 0 ELSE 1 END AS HasRegistry, CASE WHEN COL_LENGTH('platform.Tenants','Tags') IS NULL THEN 0 ELSE 1 END AS HasTags") }
    catch { return [ordered]@{ available = $false; reason = "the master registry could not be read: $($_.Exception.Message)"; tenants = @() } }
    $hasReg = $false; $hasTags = $false
    if ($probe.Count) { $hasReg = ("$($probe[0].HasRegistry)" -eq '1'); $hasTags = ("$($probe[0].HasTags)" -eq '1') }
    if (-not $hasReg) {
        return [ordered]@{ available = $false; tenants = @()
                           reason = 'platform.Tenants does not exist in this store -- it is not an MSP master registry yet (tools/setup/Initialize-PimMasterRegistry.ps1 creates it).' }
    }
    $tagCol = if ($hasTags) { 'Tags' } else { 'CAST(NULL AS nvarchar(400)) AS Tags' }
    try {
        $rows = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT CONVERT(nvarchar(50), TenantId) AS TenantId, DisplayName, Ring, Enabled, $tagCol, Notes, CreatedAtUtc, UpdatedAtUtc FROM platform.Tenants ORDER BY DisplayName")
    } catch { return [ordered]@{ available = $false; reason = "the master registry could not be read: $($_.Exception.Message)"; tenants = @() } }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in $rows) { if ($null -ne $r) { $out.Add((ConvertTo-PimManagedTenantView -Row $r)) | Out-Null } }
    return [ordered]@{ available = $true; reason = ''; tagsColumn = $hasTags; tenants = @($out.ToArray()) }
}

function Test-PimManagedTenantTagsReserved {
    # PURE. The tags a TARGET reserves cannot be tenant tags: 'all' / 'none' are Target keywords, and a tag whose key is
    # 'tag' or 'tenant' would be read as a Target prefix (tag:tag:x, tenant:...) -- a tenant tagged that way could be
    # matched by nothing, or by the wrong thing. Returns the offending tags (empty = fine).
    param([AllowEmptyCollection()][string[]]$Tags = @())
    return @(@($Tags) | Where-Object { $t = "$_".Trim().ToLowerInvariant(); $t -in @('all', 'none', '*') -or $t -like 'tag:*' -or $t -like 'tenant:*' })
}

function Set-PimManagedTenantRegistration {
    <#
      THE ONE WRITER of a platform.Tenants row (REQ-N). Validates (Get-PimManagedTenantRegistration), refuses, MERGEs,
      READS BACK. Returns @{ ok; status; reason; action = register|update; before; after; parameters }.
        status 400 -- a value is invalid (not a GUID, blank name, ring outside 0..2, a malformed or reserved tag)
        status 404 -- -Mode Update and the tenant is not registered
        status 409 -- the master's OWN tenant, a tenant already registered (-Mode Create), a name another tenant carries,
                      no registry in this store, or the master's tenant id is unknown (it cannot be ruled out)
        status 500 -- the write failed, or the read-back does not hold what was written
      -Mode Upsert (the setup script, idempotent) | Create (POST: refuse an existing row) | Update (PUT: refuse a missing row).
      -Notes: pass it to set it; leave it out to KEEP the stored notes (an edit of the tags must not wipe them).
      -MasterTenantId: the tenant this master runs in. REQUIRED and checked, fail closed: an unknown master id is refused,
      because "is this the master's own tenant?" could not be answered.
      🔒 It never DELETES: disabling keeps the row (Enabled = 0), exactly as the script's -Disable always did.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][AllowEmptyString()][string]$TenantId,
        [AllowEmptyString()][string]$DisplayName,
        [int]$Ring = 0,
        [object]$Tags,
        [bool]$Enabled = $true,
        [AllowNull()][object]$Notes = $null,
        [ValidateSet('Upsert', 'Create', 'Update')][string]$Mode = 'Upsert',
        [Parameter(Mandatory)][AllowEmptyString()][string]$MasterTenantId
    )
    $fail = { param($st, $why) return [ordered]@{ ok = $false; status = $st; reason = "$why"; action = ''; before = $null; after = $null; parameters = $null } }
    $tidIn = "$TenantId".Trim().ToLowerInvariant()
    $master = "$MasterTenantId".Trim().ToLowerInvariant()
    $guid = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

    # tags: the grammar (ConvertTo-PimTenantTags inside the registration), then the words a Target reserves
    $tagList = @()
    if ($null -ne $Tags) { if ($Tags -is [string]) { $tagList = @("$Tags" -split '[;,]') } else { $tagList = @(@($Tags) | ForEach-Object { "$_" -split '[;,]' }) } }
    $reserved = @(Test-PimManagedTenantTagsReserved -Tags @($tagList | ForEach-Object { "$_".Trim() } | Where-Object { $_ }))
    if ($reserved.Count) { return (& $fail 400 "reserved tag(s): $($reserved -join ', ') -- 'all', 'none' and tags starting 'tag:' or 'tenant:' are Target words, not tenant tags") }

    $prevNotes = ''
    $reg0 = Get-PimManagedTenantRegistration -TenantId $TenantId -DisplayName $DisplayName -Ring $Ring -Tags $Tags -Enabled $Enabled -Notes ''
    if (-not $reg0.ok) { return (& $fail 400 $reg0.reason) }
    $tid = "$($reg0.parameters.tid)"

    if ($master -notmatch $guid) { return (& $fail 409 "the master's own tenant id is not known here, so a registration cannot be checked against it -- refused (fail closed)") }
    if ($tid -eq $master) { return (& $fail 409 "tenant $tid is the MSP master's OWN tenant -- the master is not a managed tenant of itself") }

    $cur = Get-PimManagedTenantRegistry -ConnectionString $ConnectionString
    if (-not $cur.available) { return (& $fail 409 $cur.reason) }
    $before = @(@($cur.tenants) | Where-Object { $_.tenantId -eq $tid })[0]
    if ($Mode -eq 'Create' -and $before) { return (& $fail 409 "tenant $tid is already registered (as '$($before.name)') -- edit it instead of registering it again") }
    if ($Mode -eq 'Update' -and -not $before) { return (& $fail 404 "tenant $tid is not registered -- register it first") }
    $name = "$($reg0.parameters.name)"
    $clash = @(@($cur.tenants) | Where-Object { $_.tenantId -ne $tid -and "$($_.name)".Trim() -ieq $name })
    if ($clash.Count) { return (& $fail 409 "the name '$name' is already used by tenant $($clash[0].tenantId) -- every managed tenant needs its own name (the reach preview and the overview name tenants by it)") }

    if ($null -ne $Notes) { $prevNotes = "$Notes" } elseif ($before) { $prevNotes = "$($before.notes)" }
    $reg = Get-PimManagedTenantRegistration -TenantId $TenantId -DisplayName $DisplayName -Ring $Ring -Tags $Tags -Enabled $Enabled -Notes $prevNotes
    $params = @{}
    foreach ($k in @($reg.parameters.Keys)) { $params[$k] = $reg.parameters[$k] }
    try { [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql $reg.sql -Parameters $params) }
    catch { return (& $fail 500 "platform.Tenants was NOT changed: $($_.Exception.Message)") }

    # READ BACK: what the store now holds, compared with what was written.
    $back = Get-PimManagedTenantRegistry -ConnectionString $ConnectionString
    $after = $null
    if ($back.available) { $after = @(@($back.tenants) | Where-Object { $_.tenantId -eq $tid })[0] }
    $okBack = $after -and "$($after.name)" -eq $params.name -and $after.ringKnown -and [int]$after.ring -eq [int]$params.ring -and
              [bool]$after.enabled -eq [bool]$params.enabled -and "$($after.tagsText)" -eq "$($params.tags)"
    $action = if ($before) { 'update' } else { 'register' }
    if (-not $okBack) {
        $got = if ($after) { ($after | ConvertTo-Json -Compress -Depth 4) } else { '(no row)' }
        $r = & $fail 500 "read-back FAILED: platform.Tenants does not hold what was written for $tid (got: $got)"
        $r.action = $action; $r.before = $before; $r.after = $after; $r.parameters = $params
        return $r
    }
    return [ordered]@{ ok = $true; status = 200; reason = ''; action = $action; before = $before; after = $after; parameters = $params }
}

function Get-PimManagedTenantPublishState {
    <#
      PURE. "When did the master last publish for this tenant?" -- answered from what IS recorded. The publish job records
      ONE last run for the whole bundle (pim.Settings['PublishLastRun']: startedUtc, finishedUtc, state), so per tenant the
      honest answer is whether that run came AFTER the tenant's registry row last changed (its tags are then in the
      signed bundle) or not. Returns @{ state; text; lastPublishUtc }.
        published -- the last publish succeeded after this row last changed
        pending   -- the row changed after the last successful publish: the next publish carries it
        running / failed / held -- the last run's own state
        unknown   -- no publish recorded (or none readable) -- said, never shown as "published"
        disabled  -- the tenant is disabled: its tags are not signed into the bundle
    #>
    param([Parameter(Mandatory)][object]$Tenant, [AllowNull()][object]$LastRun)
    $en = [bool](Get-PimMspRegistryValue $Tenant 'enabled')
    if (-not $en) { return [ordered]@{ state = 'disabled'; lastPublishUtc = ''; text = 'Disabled -- the publish does not sign its tags into the bundle.' } }
    $started = ConvertTo-PimMspRegistryUtcText (Get-PimMspRegistryValue $LastRun 'startedUtc')
    $finished = ConvertTo-PimMspRegistryUtcText (Get-PimMspRegistryValue $LastRun 'finishedUtc')
    $state = "$(Get-PimMspRegistryValue $LastRun 'state')".Trim().ToLowerInvariant()
    if (-not $started -and -not $finished) { return [ordered]@{ state = 'unknown'; lastPublishUtc = ''; text = 'No publish is recorded on this master yet.' } }
    if ($state -eq 'running') { return [ordered]@{ state = 'running'; lastPublishUtc = ''; text = "A publish is running (started $started)." } }
    if ($state -eq 'failed')  { return [ordered]@{ state = 'failed'; lastPublishUtc = ''; text = "The last publish FAILED ($(if ($finished) { $finished } else { $started })) -- see Jobs." } }
    if ($state -eq 'held')    { return [ordered]@{ state = 'held'; lastPublishUtc = ''; text = "The last publish was held ($(if ($finished) { $finished } else { $started }))." } }
    if ($state -ne 'succeeded' -or -not $finished) { return [ordered]@{ state = 'unknown'; lastPublishUtc = ''; text = "The last publish is recorded as '$state' -- not known whether it carried this tenant." } }
    $upd = "$(Get-PimMspRegistryValue $Tenant 'updatedUtc')"
    if ($upd -and [string]::CompareOrdinal($upd, $finished) -gt 0) {
        return [ordered]@{ state = 'pending'; lastPublishUtc = $finished; text = "Changed after the last publish ($finished) -- the next publish carries it." }
    }
    return [ordered]@{ state = 'published'; lastPublishUtc = $finished; text = "Published $finished (the last publish carries this entry)." }
}

function Get-PimMspTenantRegistryView {
    <#
      What GET /api/msp/tenants returns: the registry, each tenant with its publish state, labelled as the master's copy of
      the ring. -LastRun is the master's pim.Settings['PublishLastRun'] value (the caller reads it; $null = none recorded).
    #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ConnectionString, [AllowNull()][object]$LastRun, [bool]$CanWrite, [string]$MasterTenantId)
    $reg = Get-PimManagedTenantRegistry -ConnectionString $ConnectionString
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($reg.tenants)) {
        $p = Get-PimManagedTenantPublishState -Tenant $t -LastRun $LastRun
        $t['publish'] = $p
        $rows.Add($t) | Out-Null
    }
    $lr = $null
    if ($null -ne $LastRun) {
        $lr = [ordered]@{ state = "$(Get-PimMspRegistryValue $LastRun 'state')"; startedUtc = ConvertTo-PimMspRegistryUtcText (Get-PimMspRegistryValue $LastRun 'startedUtc')
                          finishedUtc = ConvertTo-PimMspRegistryUtcText (Get-PimMspRegistryValue $LastRun 'finishedUtc'); trigger = "$(Get-PimMspRegistryValue $LastRun 'trigger')" }
    }
    return [ordered]@{
        master         = $true
        available      = [bool]$reg.available
        reason         = "$($reg.reason)"
        tenants        = @($rows.ToArray())
        canWrite       = [bool]$CanWrite
        masterTenantId = "$MasterTenantId".Trim().ToLowerInvariant()
        lastPublish    = $lr
        ringLabel      = Get-PimMspRingCopyLabel
        ringSource     = 'master-copy'
        ringNote       = "The ring here is the MASTER'S COPY. Each managed tenant sets its own ring locally, and that ring gates its real pull; the master uses its copy only for its previews (reach, Replication overview, Managed tenants). Keep the two equal."
        tagGrammar     = 'word or key:value (letters, digits, - _ .), separated by ; -- a replication Target names them as tag:<tag>, tag:a+b (all of), or tenant:<id>'
    }
}
