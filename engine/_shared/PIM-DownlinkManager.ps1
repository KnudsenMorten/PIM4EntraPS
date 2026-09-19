# =============================================================================
# PIM-DownlinkManager.ps1 -- the MANAGER-side glue for the MSP downlink surface
# (control #1/#2, framework MSP-2). Read the registry, compose the PURE plan over
# the SIGNED baseline, edit the per-relationship policy, and run a sync.
#
# 🔒 THE DECISION IS NEVER MADE HERE. Every view composes Get-PimDownlinkPlan, which
# verifies the signature and applies ring + policy itself. This file gathers facts and
# formats them for the GUI. If it formed its own opinion, the preview and the apply
# could disagree -- about who holds privilege in someone else's tenant.
#
# 🔴 THIS FILE READS AND PLANS. IT NEVER TOUCHES A MANAGED TENANT -- not to write, and
# not to read either. Two reasons, and the second one bites even if you accept the first:
#   * docs/REQUIREMENTS.md §22: "MSP never writes to a customer tenant; customer data
#     never leaves the tenant." Reaching in for a "harmless" read is the second half of
#     that sentence.
#   * A Manager in the MASTER holds the MASTER's ambient identity, and
#     Get-PimSqlConnectionString mints its Azure SQL token from it -- so any connection
#     aimed at a managed store authenticates as the WRONG tenant. It does not work, and
#     if it did it would be the master acting inside a customer.
#
# 📌 Under the agreed model (framework MSP-3) the managed tenant PULLS the signed
# baseline, decides locally with its own identity, and its own admin ACCEPTS before
# anything applies. So everything here is computed from the SIGNED BUNDLE plus the
# MASTER's own registry -- both of which the master legitimately holds.
#
# PS 5.1 COMPATIBLE: no ?./??, no ternary, Set-StrictMode -Off, null-guarded.
# =============================================================================

Set-StrictMode -Off

if ($PSScriptRoot) {
    if (-not (Get-Command Get-PimDownlinkPlan -ErrorAction SilentlyContinue)) {
        $__dl = Join-Path $PSScriptRoot 'PIM-Downlink.ps1'
        if (Test-Path -LiteralPath $__dl) { . $__dl }
    }
    if (-not (Get-Command Get-PimSqlRows -ErrorAction SilentlyContinue)) {
        $__ss = Join-Path $PSScriptRoot 'PIM-SqlStore.ps1'
        if (Test-Path -LiteralPath $__ss) { . $__ss }
    }
}

# --- registry reads ----------------------------------------------------------

function Get-PimManagerDownlinkTenants {
    <#
      The managed relationships from the master registry. Returns @() when the
      platform schema is not applied -- a single-tenant deployment has no
      relationships, which is a legitimate empty answer, not an error.
    #>
    [CmdletBinding()] param([string]$ConnectionString)
    if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString }
    try {
        # §71: Tags ride along when the registry has the column -- the reach preview evaluates targets
        # against them. A registry predating the column still answers, untagged.
        return @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql @"
IF COL_LENGTH('platform.Tenants','Tags') IS NULL
    SELECT CONVERT(nvarchar(50), TenantId) AS TenantId, DisplayName, Ring, Enabled, CAST(NULL AS nvarchar(400)) AS Tags
    FROM platform.Tenants WHERE Enabled = 1 ORDER BY DisplayName
ELSE
    SELECT CONVERT(nvarchar(50), TenantId) AS TenantId, DisplayName, Ring, Enabled, Tags
    FROM platform.Tenants WHERE Enabled = 1 ORDER BY DisplayName
"@)
    } catch { return @() }
}

# --- BUG-175: THE RING THE MASTER PREVIEWS WITH IS ONLY ITS COPY ---------------
#
# 🔒 Every ring is LOCAL in the slave (DESIGN; operator 2026-09-18). The real pull is gated by the managed tenant's
# OWN -SlaveRing -- its downlink job argument, set in the slave -- and nothing reports it back to the master. What the
# master holds is platform.Tenants.Ring, written by Register-PimManagedTenant: a COPY that can drift. So every preview
# here ("reaches N tenants", the overview, the dry run) is labelled as computed from the master's copy, and the
# value is never made authoritative. The slave reports the ring that actually decided in its own pull result and
# acceptance record (slaveRing, slaveRingSource = 'local').
# One parser for all three previews: they used to disagree on a missing value (the reach preview read it as ring 2,
# the overview and the dry run as ring 0 -- `[int]("0" + '')`), so one view said "reaches" and another "held back".
function Get-PimMasterRingCopy {
    [CmdletBinding()] param([AllowNull()][object]$Value)
    $s = "$Value".Trim()
    $r = 0
    if ($s -match '^\d+$' -and [int]::TryParse($s, [ref]$r)) {
        return [ordered]@{ ring = $r; known = $true; source = 'master-copy'
                           note = "ring $r is the MASTER'S COPY (platform.Tenants.Ring). The tenant's own local -SlaveRing gates its real pull; this preview is right only while the two agree." }
    }
    return [ordered]@{ ring = 2; known = $false; source = 'master-copy'
                       note = "the master holds no readable ring for this tenant ('$s') -- previewed as ring 2 (the pull job's default). The tenant's own local -SlaveRing decides." }
}

# --- §71: THE REPLICATION REACH PREVIEW ---------------------------------------
#
# 🔑 "THIS WILL REACH N TENANTS" IS THE SIGNED BUNDLE'S OWN ANSWER, NOT A SECOND OPINION. The preview
# builds the payload with the producer's own Select-PimBaselineBundleContent, signs it with a throwaway
# key, and runs the SAME Get-PimDownlinkPlan every managed tenant runs -- once per registered tenant.
# A browser-side reach calculation could disagree with what the tenants then receive; this cannot,
# because it is the same code on the same rows (framework MSP-4 SURFACE item 9).
# PURE except for the clock and the ephemeral key: the caller supplies every row.

function Get-PimReplicationRowId {
    # A stable id for one replicable row, shared by the preview's input rows and the plan's output rows.
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Entity, [object]$Row)
    $kind = Get-PimReplicationKindForEntity -Entity $Entity
    $v = { param($k) "$(Get-PimDownlinkValue -Object $Row -Key $k)".Trim() }
    $local = { param($u) $x = "$u".Trim(); $at = $x.IndexOf('@'); if ($at -gt 0) { $x.Substring(0, $at) } else { $x } }
    $id = switch ($kind) {
        'admin'      { $u = & $v 'UserName'; if (-not $u) { $u = & $local (& $v 'UserPrincipalName') }; "admin|$u" }
        'membership' { $u = & $v 'Username'; if (-not $u) { $u = & $v 'UserName' }; "membership|$(& $local $u)|$(& $v 'GroupTag')" }
        'group'      { "group|$(& $v 'GroupTag')" }
        'nesting'    { "nesting|$(& $v 'TargetGroupTag')|$(& $v 'SourceGroupTag')" }
        'binding'    { "binding|$(& $v 'GroupTag')|$(& $v 'RoleDefinitionName')" }
        'resource'   {
            $k = if (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue) { Get-PimStoreRowKey -Base $Entity -Row $Row } else { & $v 'GroupTag' }
            "resource|$Entity|$k"
        }
        default      { '' }
    }
    return "$id".ToLowerInvariant()
}

function Get-PimReplicationPreview {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][object[]]$RegistryRows = @(),
        [hashtable]$RegistryReplicate = @{},
        [hashtable]$Entities = @{},
        # @{ tenantId; name; ring; tags } -- the master's registered managed tenants
        [AllowEmptyCollection()][object[]]$Tenants = @(),
        # tenant id (lowercase) -> @( @{ Mode; GroupTag } ), as the bundle carries it
        [object]$ProjectionPolicy = ([ordered]@{})
    )
    $content = Select-PimBaselineBundleContent -RegistryRows @($RegistryRows) -RegistryReplicate $RegistryReplicate -Entities $Entities
    $tagMap = [ordered]@{}
    $tlist = New-Object System.Collections.Generic.List[object]
    foreach ($t in @($Tenants)) {
        if ($null -eq $t) { continue }
        $tid = "$(Get-PimDownlinkValue -Object $t -Key 'tenantId')".Trim(); if (-not $tid) { $tid = "$(Get-PimDownlinkValue -Object $t -Key 'TenantId')".Trim() }
        if (-not $tid) { continue }
        $name = "$(Get-PimDownlinkValue -Object $t -Key 'name')"; if (-not $name) { $name = "$(Get-PimDownlinkValue -Object $t -Key 'DisplayName')" }; if (-not $name) { $name = $tid }
        $ringRaw = "$(Get-PimDownlinkValue -Object $t -Key 'ring')"; if (-not $ringRaw) { $ringRaw = "$(Get-PimDownlinkValue -Object $t -Key 'Ring')" }
        # BUG-175: the master's COPY of the ring, labelled as such (see Get-PimMasterRingCopy).
        $rc = Get-PimMasterRingCopy -Value $ringRaw
        $ring = [int]$rc.ring
        $tagsRaw = Get-PimDownlinkValue -Object $t -Key 'tags'; if ($null -eq $tagsRaw) { $tagsRaw = Get-PimDownlinkValue -Object $t -Key 'Tags' }
        $tags = @(@($tagsRaw) | ForEach-Object { "$_" -split '[;,]' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if ($tags.Count) { $tagMap[$tid.ToLowerInvariant()] = $tags }
        $tlist.Add([ordered]@{ tenantId = $tid; name = $name; ring = $ring; ringKnown = [bool]$rc.known; ringSource = 'master-copy'; tags = $tags }) | Out-Null
    }
    $now = [datetime]::UtcNow
    $payload = New-PimBaselinePayload -Content $content -ProjectionPolicy $ProjectionPolicy -TenantTags $tagMap -Version 1 `
                 -GeneratedAtUtc $now.ToString('yyyy-MM-ddTHH:mm:ssZ') -ValidToUtc $now.AddDays(1).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 8 -Compress))
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $reach = @{}; $warnings = New-Object System.Collections.Generic.List[object]; $errors = New-Object System.Collections.Generic.List[string]
    try {
        $sig = $rsa.SignData($bytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $doc = [pscustomobject]@{ product = 'PIM4EntraPS'; payloadB64 = [Convert]::ToBase64String($bytes); signature = [Convert]::ToBase64String($sig); keyThumbprint = 'REACH-PREVIEW' }
        $add = { param($id, $tname) if (-not "$id".Trim()) { return }; if (-not $reach.ContainsKey($id)) { $reach[$id] = New-Object System.Collections.Generic.List[string] }; if (-not $reach[$id].Contains($tname)) { $reach[$id].Add($tname) } }
        foreach ($t in $tlist.ToArray()) {
            $plan = Get-PimDownlinkPlan -Scenario 'S6' -Doc $doc -PublicKey $rsa -TenantId $t.tenantId -SlaveRing ([int]$t.ring) `
                        -LocalRoot ([System.IO.Path]::GetTempPath()) -TenantTags @($t.tags)
            if (-not $plan.ok) { $errors.Add("$($t.name): $($plan.reason)") | Out-Null; continue }
            foreach ($a in @($plan.admins))      { & $add ("admin|$(Get-PimDownlinkValue -Object $a -Key 'UserName')".ToLowerInvariant()) $t.name }
            foreach ($a in @($plan.assignments)) { & $add ("membership|$(Get-PimDownlinkValue -Object $a -Key 'UserName')|$(Get-PimDownlinkValue -Object $a -Key 'GroupTag')".ToLowerInvariant()) $t.name }
            if ($plan.definitions) {
                foreach ($g in @($plan.definitions.create))       { & $add ("group|$(Get-PimDownlinkValue -Object $g -Key 'GroupTag')".ToLowerInvariant()) $t.name }
                foreach ($n in @($plan.definitions.nestings))     { & $add ("nesting|$(Get-PimDownlinkValue -Object $n -Key 'TargetGroupTag')|$(Get-PimDownlinkValue -Object $n -Key 'SourceGroupTag')".ToLowerInvariant()) $t.name }
                foreach ($b in @($plan.definitions.roleBindings)) { & $add ("binding|$(Get-PimDownlinkValue -Object $b -Key 'GroupTag')|$(Get-PimDownlinkValue -Object $b -Key 'RoleDefinitionName')".ToLowerInvariant()) $t.name }
                foreach ($x in @($plan.definitions.resourceBindings)) {
                    $e = "$(Get-PimDownlinkValue -Object $x -Key 'Entity')"
                    & $add (Get-PimReplicationRowId -Entity $e -Row $x) $t.name
                }
            }
            foreach ($w in @($plan.autoIncluded)) {
                $warnings.Add([ordered]@{ tenantId = $t.tenantId; tenant = $t.name; kind = "$($w.kind)"; GroupTag = "$($w.GroupTag)"; dependent = "$($w.dependent)"
                                          reason = ("$($w.reason)" -replace [regex]::Escape("tenant $($t.tenantId)"), "tenant $($t.name)") }) | Out-Null
            }
        }
    } finally { $rsa.Dispose() }
    $out = @{}
    foreach ($k in $reach.Keys) { $out[$k] = @($reach[$k].ToArray() | Sort-Object) }
    return [ordered]@{
        tenantCount        = $tlist.Count
        tenants            = @($tlist.ToArray())
        # BUG-175: "reaches N tenants" is computed from the MASTER'S COPY of each tenant's ring.
        ringSource         = 'master-copy'
        ringNote           = "Computed with the master's copy of each tenant's ring (platform.Tenants.Ring). Each tenant's own local ring gates its real pull, so a tenant whose ring differs from the master's copy receives what ITS ring admits."
        reach              = $out
        warnings           = @($warnings.ToArray())
        notPublished       = @($content.report.notPublished)
        dependencyIncluded = @($content.report.dependencyIncluded)
        errors             = @($errors.ToArray())
    }
}

function Get-PimReplicationRowReach {
    # One row's line in "this will reach: N tenants" -- from a Get-PimReplicationPreview result.
    [CmdletBinding()] param([Parameter(Mandatory)][object]$Preview, [Parameter(Mandatory)][string]$Entity, [object]$Row)
    $id = Get-PimReplicationRowId -Entity $Entity -Row $Row
    $names = @()
    if ($id -and $Preview.reach.ContainsKey($id)) { $names = @($Preview.reach[$id]) }
    $tag = "$(Get-PimDownlinkValue -Object $Row -Key 'GroupTag')".Trim().ToLowerInvariant()
    $w = @(@($Preview.warnings) | Where-Object { $tag -and "$($_.GroupTag)".Trim().ToLowerInvariant() -eq $tag -and (Get-PimReplicationKindForEntity -Entity $Entity) -eq 'group' })
    return [ordered]@{
        id = $id; count = $names.Count; tenantCount = [int]$Preview.tenantCount; tenants = $names
        summary = ("{0} of {1} tenant(s)" -f $names.Count, [int]$Preview.tenantCount)
        warnings = @($w)
    }
}

function Get-PimReplicationMasterModel {
    <#
      The master's store, read the way Get-PimBaselineBundlePayload reads it, for the reach preview: registry
      rows (+ Replicate), every replicable entity, the projection policy and the tenant registry.
      -Overlay: entity -> rows that REPLACE the stored rows of that entity (the grid's pending set).
      -Draft:   @( @{ entity; row } ) upserted by natural key (a wizard's not-yet-staged row).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ConnectionString, [hashtable]$Overlay = @{}, [object[]]$Draft = @())
    $registry = @(); $repMap = @{}
    try { $registry = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT UserName, DisplayName, FirstName, LastName, Initials, UsageLocation, Purpose, Ring, Template, Target FROM pim.CentralAdmins WHERE Owner='MSP' AND Enabled=1 ORDER BY Ring") }
    catch {
        # a registry predating Target still has admins; one with no registry at all has none
        try { $registry = @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT UserName, DisplayName, FirstName, LastName, Initials, UsageLocation, Purpose, Ring, Template FROM pim.CentralAdmins WHERE Owner='MSP' AND Enabled=1 ORDER BY Ring") } catch { $registry = @() }
    }
    try { foreach ($rr in @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT UserName, Replicate FROM pim.CentralAdmins WHERE Owner='MSP' AND Enabled=1")) { if ("$($rr.Replicate)".Trim()) { $repMap["$($rr.UserName)".Trim().ToLowerInvariant()] = "$($rr.Replicate)".Trim() } } } catch { }
    $entities = @{}
    foreach ($e in @(Get-PimReplicationEntities) + @('PIM-Definitions-AU', 'PIM-Definitions')) {
        if ($Overlay.ContainsKey($e)) { $entities[$e] = @(@($Overlay[$e]) | Where-Object { $null -ne $_ }); continue }
        try { $entities[$e] = @(Get-PimSqlRows -ConnectionString $ConnectionString -Entity $e) } catch { $entities[$e] = @() }
    }
    foreach ($d in @($Draft)) {
        $e = "$(Get-PimDownlinkValue -Object $d -Key 'entity')".Trim(); $row = Get-PimDownlinkValue -Object $d -Key 'row'
        if (-not $e -or $null -eq $row) { continue }
        $row = [pscustomobject]$row
        $k = if (Get-Command Get-PimStoreRowKey -ErrorAction SilentlyContinue) { Get-PimStoreRowKey -Base $e -Row $row } else { '' }
        $rest = @(@($entities[$e]) | Where-Object { -not $k -or (Get-PimStoreRowKey -Base $e -Row $_) -ne $k })
        $entities[$e] = @($rest) + @($row)
    }
    $policy = [ordered]@{}
    try {
        foreach ($p in @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT CONVERT(nvarchar(50), TenantId) AS TenantId, Mode, GroupTag FROM pim.TenantRoleProjection")) {
            $tid = "$($p.TenantId)".Trim().ToLowerInvariant(); if (-not $tid) { continue }
            if (-not $policy.Contains($tid)) { $policy[$tid] = @() }
            $policy[$tid] = @($policy[$tid]) + @([ordered]@{ Mode = "$($p.Mode)"; GroupTag = "$($p.GroupTag)" })
        }
    } catch { }
    $tenants = @(Get-PimManagerDownlinkTenants -ConnectionString $ConnectionString | ForEach-Object {
        # BUG-175: passed RAW -- Get-PimReplicationPreview parses it once (Get-PimMasterRingCopy), so a missing value is
        # labelled "no readable ring" instead of silently becoming ring 0 here and ring 2 there.
        [ordered]@{ tenantId = "$($_.TenantId)"; name = "$($_.DisplayName)"; ring = "$($_.Ring)".Trim(); tags = @("$($_.Tags)" -split '[;,]' | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
    })
    return @{ RegistryRows = $registry; RegistryReplicate = $repMap; Entities = $entities; Tenants = $tenants; ProjectionPolicy = $policy }
}

function Get-PimManagerDownlinkPolicy {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$TenantId, [string]$ConnectionString)
    if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString }
    try {
        return @(Invoke-PimSqlQuery -ConnectionString $ConnectionString -Sql "SELECT Mode, GroupTag FROM pim.TenantRoleProjection WHERE TenantId = @t ORDER BY Mode, GroupTag" -Parameters @{ t = $TenantId } |
            ForEach-Object { [ordered]@{ Mode = "$($_.Mode)"; GroupTag = "$($_.GroupTag)" } })
    } catch { return @() }
}

function Set-PimManagerDownlinkPolicyMany {
    <#
      Replace the rule set for N relationships, IN ONE TRANSACTION.

      🔒 THE TRANSACTION IS THE WHOLE POINT, NOT TIDINESS. This is DELETE-then-INSERT, and
      "no rows for a tenant" is not a neutral state -- it means ALLOW ALL. So a failure
      between the delete and the last insert would leave the relationship projecting
      EVERYTHING the master publishes: an error that silently WIDENS privilege. That is
      ESTATE-14's failure class (an unchecked failure presented as a state of the world),
      and it is the reason this cannot be two separate statements.

      🔴 AND WHY *MANY*: the MSP-4 write is TAG-centric -- "this role reaches these 5 of 28"
      -- so one operator action edits up to 28 relationships. Committing them one at a time
      would let a failure at tenant 12 leave the estate half-narrowed, with no record of
      which half. Half a narrowing is not a smaller narrowing; it is an estate whose reach
      matches neither the old intent nor the new one, in tenants the operator does not own.

      Validation happens BEFORE any write for the same reason: a rule rejected halfway
      through would already have had its predecessors committed.

      -Edits: @( @{ TenantId; Rules = @( @{ Mode; GroupTag } ) } ). A tenant with an empty
      Rules list is reset to ALLOW ALL -- which is a widening, and therefore is exactly the
      case the caller must have decided deliberately.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Edits,
        [string]$ConnectionString,
        [string]$Note = 'set from the Manager'
    )
    if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString }

    # validate EVERY edit first -- nothing is written unless all of them are acceptable
    $clean = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Edits)) {
        $tid = "$(Get-PimDownlinkValue -Object $e -Key 'TenantId')".Trim()
        if (-not $tid) { throw "an edit is missing its TenantId (nothing was written)." }
        $rules = New-Object System.Collections.Generic.List[object]
        foreach ($r in @(Get-PimDownlinkValue -Object $e -Key 'Rules')) {
            $m = "$(Get-PimDownlinkValue -Object $r -Key 'Mode')".Trim().ToLowerInvariant()
            $g = "$(Get-PimDownlinkValue -Object $r -Key 'GroupTag')".Trim()
            if ($m -notin @('allow','deny')) { throw "invalid Mode '$m' for tenant $tid -- must be allow or deny (nothing was written)." }
            if (-not $g) { throw "a rule for tenant $tid is missing its GroupTag (nothing was written)." }
            $rules.Add([ordered]@{ Mode = $m; GroupTag = $g }) | Out-Null
        }
        $clean.Add([ordered]@{ TenantId = $tid; Rules = @($rules.ToArray()) }) | Out-Null
    }
    if (-not $clean.Count) { return 0 }

    $cn = New-PimSqlConnection -ConnectionString $ConnectionString
    $tx = $null
    try {
        $cn.Open()
        $tx = $cn.BeginTransaction()
        foreach ($e in $clean.ToArray()) {
            $del = $cn.CreateCommand(); $del.Transaction = $tx
            $del.CommandText = 'DELETE FROM pim.TenantRoleProjection WHERE TenantId = @t'
            [void]$del.Parameters.AddWithValue('@t', $e.TenantId)
            [void]$del.ExecuteNonQuery()
            foreach ($c in @($e.Rules)) {
                $ins = $cn.CreateCommand(); $ins.Transaction = $tx
                $ins.CommandText = 'INSERT INTO pim.TenantRoleProjection (TenantId, Mode, GroupTag, Notes) VALUES (@t, @m, @g, @n)'
                [void]$ins.Parameters.AddWithValue('@t', $e.TenantId)
                [void]$ins.Parameters.AddWithValue('@m', $c.Mode)
                [void]$ins.Parameters.AddWithValue('@g', $c.GroupTag)
                [void]$ins.Parameters.AddWithValue('@n', $Note)
                [void]$ins.ExecuteNonQuery()
            }
        }
        $tx.Commit(); $tx = $null
    } catch {
        if ($tx) { try { $tx.Rollback() } catch {} }
        throw "projection policy NOT changed (rolled back): $($_.Exception.Message)"
    } finally {
        try { $cn.Close() } catch {}
    }
    return $clean.Count
}

function Set-PimManagerDownlinkPolicy {
    <#
      Replace the rule set for ONE relationship. Full-set replace is correct here: the rows
      are scoped by TenantId so no other relationship is touched, and the GUI always submits
      the complete list it rendered.

      🔑 ONE WRITER, TWO ENTRY POINTS -- NOT TWO WRITERS. The tag-axis (MSP-4) and tenant-axis
      surfaces both narrow privilege in customer tenants, and the moment they have separate
      SQL the two can disagree about what "replace the rules" means, in the direction of
      widening. Session 32 escalated exactly this as a two-bad-options decision (duplicate it,
      or accept a weaker path) when the third option -- share it -- needed nobody's ruling.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$TenantId,
        [object[]]$Rules = @(),
        [string]$ConnectionString
    )
    [void](Set-PimManagerDownlinkPolicyMany -Edits @(,([ordered]@{ TenantId = $TenantId; Rules = @($Rules) })) -ConnectionString $ConnectionString)
}

# --- the baseline the plan is computed from ----------------------------------

function Test-PimBaselineDocUrl {
    <#
      PURE. 71.40 -- is this a URL the Manager may read the published bundle from? The PLAIN blob URL only: https, no query
      string and no fragment. A '?' means a SAS (a credential) -- the public-but-signed / private-endpoint transport has
      none, and a credential must never ride in a Manager env var. Returns @{ ok; reason }.
    #>
    param([AllowEmptyString()][AllowNull()][string]$Url)
    $u = "$Url".Trim()
    if (-not $u) { return @{ ok = $false; reason = 'empty' } }
    if ($u -match '\s') { return @{ ok = $false; reason = 'contains whitespace' } }
    if ($u.Contains('?') -or $u.Contains('#')) { return @{ ok = $false; reason = "carries a query string or fragment -- a SAS is a credential; give the PLAIN blob URL (public-but-signed or private endpoint)" } }
    $parsed = $null
    if (-not [uri]::TryCreate($u, [UriKind]::Absolute, [ref]$parsed)) { return @{ ok = $false; reason = 'not an absolute URL' } }
    if ($parsed.Scheme -ne 'https') { return @{ ok = $false; reason = "scheme '$($parsed.Scheme)' -- https only" } }
    if (-not "$($parsed.AbsolutePath)".Trim('/')) { return @{ ok = $false; reason = 'names no blob (no path)' } }
    return @{ ok = $true; reason = '' }
}

function Get-PimManagerBaselineEnvPlan {
    <#
      PURE. 71.40 -- the two Manager environment variables that let the hosted Downlink view verify what the master
      publishes: PIM_BaselineTrustedKeys (the signing key id(s) this Manager pins) and PIM_BaselineDocUrl (the plain URL the
      bundle is published to). Used by Setup-PimContainers (create + update of ca-pim-manager).
      🔒 THE PIN CHECK IS THE PULL JOB'S, NOT A LOOSER COPY: Deploy-PimDownlinkJob.ps1 splits on , ; whitespace and REFUSES
      any entry that is not 43 characters of base64url -- a typo would otherwise pin nothing and look configured. Same
      split, same regex, same refusal here, so the Manager and the managed tenants reject the same inputs.
      Returns @{ ok; reason; env = [string[]] 'NAME=value' pairs; keys; url }. Nothing given -> ok with no env.
    #>
    param([AllowNull()][AllowEmptyCollection()][string[]]$TrustedKeys = @(), [AllowNull()][AllowEmptyString()][string]$DocUrl)
    $flat = @(@($TrustedKeys) | ForEach-Object { "$_" -split '[,;\s]+' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $bad  = @($flat | Where-Object { $_ -cnotmatch '^[A-Za-z0-9_-]{43}$' })
    if ($bad.Count) {
        return @{ ok = $false; env = @(); keys = @(); url = ''
                  reason = "REFUSED: -BaselineTrustedKeys '$($bad -join ', ')' is not a signing key id (43 characters of base64url, as the master's signingkey step prints)." }
    }
    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($k in $flat) { if (-not $keys.Contains($k)) { $keys.Add($k) } }
    $env = New-Object System.Collections.Generic.List[string]
    if ($keys.Count) { $env.Add("PIM_BaselineTrustedKeys=$($keys.ToArray() -join ',')") }
    $u = "$DocUrl".Trim()
    if ($u) {
        $chk = Test-PimBaselineDocUrl -Url $u
        if (-not $chk.ok) { return @{ ok = $false; env = @(); keys = @(); url = ''; reason = "REFUSED: -BaselineDocUrl $($chk.reason)" } }
        $env.Add("PIM_BaselineDocUrl=$u")
    }
    return @{ ok = $true; reason = ''; env = @($env.ToArray()); keys = @($keys.ToArray()); url = $u }
}

function Get-PimManagerBaselineDoc {
    <#
      The signed bundle the Manager plans against. Preference order:
        1. an explicit -Path / $global:PIM_BaselineDocPath (a staged local document)
        2. $env:PIM_BaselineDocPath
        3. 71.40: an explicit -Url / $global:PIM_BaselineDocUrl / $env:PIM_BaselineDocUrl -- the PLAIN blob URL the master
           publishes to (anonymous read, public-but-signed or over the private endpoint). This is what a HOSTED Manager
           has: no local file ever exists in the container, so without it the Downlink view said "no baseline document
           configured" on every hosted environment, whatever was pinned.
      Returns @{ doc; source; error }. NEVER fabricates a document -- a missing
      baseline is reported, because planning without one would report "nothing
      projects", which is indistinguishable from a correct empty answer.
      🪤 A URL that cannot be fetched is NOT "no baseline configured": it is configured and unreachable, and the reason
      says which (DNS, timeout, 403 ...). Reading it as "not configured" would send an operator to fix the wrong thing.
      -Fetcher is a test seam: { param($url, $timeoutSec) <returns the body as a string> }.
    #>
    [CmdletBinding()] param([string]$Path, [string]$Url, [scriptblock]$Fetcher, [int]$TimeoutSec = 15)
    if (-not $Path) { $Path = "$($global:PIM_BaselineDocPath)" }
    if (-not $Path) { $Path = "$($env:PIM_BaselineDocPath)" }
    if (-not "$Path".Trim()) {
        if (-not $Url) { $Url = "$($global:PIM_BaselineDocUrl)" }
        if (-not $Url) { $Url = "$($env:PIM_BaselineDocUrl)" }
        if ("$Url".Trim()) {
            $Url = "$Url".Trim()
            $chk = Test-PimBaselineDocUrl -Url $Url
            if (-not $chk.ok) { return @{ doc = $null; source = ''; error = "PIM_BaselineDocUrl refused: $($chk.reason)" } }
            if (-not $Fetcher) {
                $Fetcher = {
                    param($u, $t)
                    $r = Invoke-WebRequest -Uri $u -Method GET -UseBasicParsing -TimeoutSec $t -Headers @{ 'x-ms-version' = '2021-08-06' } -ErrorAction Stop
                    if ($r.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($r.Content) } else { "$($r.Content)" }
                }
            }
            $body = $null
            try { $body = & $Fetcher $Url $TimeoutSec }
            catch {
                $m = "$($_.Exception.Message)"
                return @{ doc = $null; source = $Url; error = "could not fetch the published baseline from ${Url}: $($m.Substring(0, [Math]::Min(300, $m.Length)))" }
            }
            $txt = "$body"
            $br = $txt.IndexOf('{'); if ($br -gt 0) { $txt = $txt.Substring($br) }   # BOM / preamble
            if (-not $txt.Trim()) { return @{ doc = $null; source = $Url; error = "the published baseline at $Url is empty" } }
            try { return @{ doc = ($txt | ConvertFrom-Json); source = $Url; error = '' } }
            catch { return @{ doc = $null; source = $Url; error = "the published baseline at $Url is not valid JSON: $($_.Exception.Message)" } }
        }
        return @{ doc = $null; source = ''; error = 'no baseline document configured (set PIM_BaselineDocUrl to the plain URL the master publishes to, or PIM_BaselineDocPath to a staged copy)' }
    }
    if (-not (Test-Path -LiteralPath $Path)) { return @{ doc = $null; source = "$Path"; error = "baseline document not found at $Path" } }
    try {
        $doc = (Get-Content -LiteralPath $Path -Raw) | ConvertFrom-Json
        return @{ doc = $doc; source = "$Path"; error = '' }
    } catch { return @{ doc = $null; source = "$Path"; error = "baseline document is not valid JSON: $($_.Exception.Message)" } }
}

function Get-PimManagerBaselineTrustedKeyIds {
    <#
      71.35 -- the master signing key ids THIS Manager pins. Read EXACTLY as the managed tenant's pull job
      reads them (tools/pim-engine/downlink-job-entry.ps1 -> Test-PimBaselineDoc -> Get-PimBaselineTrustedKeyIds):
      $global:PIM_BaselineTrustedKeys when set, else $env:PIM_BaselineTrustedKeys; comma / semicolon / space
      separated; anything that is not a 43-character base64url key id is ignored (never widened to "any key").
      One reader, so the banner and the per-relationship plan (which verifies through the same function) can
      never disagree about whether a bundle is trusted.
    #>
    [CmdletBinding()] param()
    if (Get-Command Get-PimBaselineTrustedKeyIds -ErrorAction SilentlyContinue) { return @(Get-PimBaselineTrustedKeyIds) }
    $raw = @()
    if ("$(@($global:PIM_BaselineTrustedKeys) -join ',')".Trim()) { $raw = @($global:PIM_BaselineTrustedKeys) } else { $raw = @("$($env:PIM_BaselineTrustedKeys)") }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($r in $raw) { foreach ($x in @("$r" -split '[,;\s]+')) { $t = "$x".Trim(); if ($t -cmatch '^[A-Za-z0-9_-]{43}$' -and -not $out.Contains($t)) { $out.Add($t) } } }
    return @($out.ToArray())
}

function Get-PimManagerBaselineVerification {
    <#
      The banner's verdict on the signed bundle, with the reason when it is NOT verified.
      * A bundle carrying signingKey (the master's cloud publish job, Key Vault key) verifies only when its key id
        is PINNED here (Get-PimManagerBaselineTrustedKeyIds) and RS256 checks out.
      * A bundle without signingKey verifies against the embedded CN=PIM4EntraPS-Baseline certificate, exactly as
        before -- no pin needed, and a pin does not change it.
      Same verifier the pull job reaches (Test-PimBaselineDoc, with the pins passed EXPLICITLY), then the same
      freshness gate (Test-PimDownlinkBaselineFinish). Returns
      @{ verified; signer = 'key'|'certificate'|''; keyId; pinnedKeyIds; reason }. Never throws.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][object]$Doc,
        [string[]]$TrustedKeyIds,
        [datetime]$NowUtc = ([datetime]::UtcNow)
    )
    $pins = @()
    if ($PSBoundParameters.ContainsKey('TrustedKeyIds')) { $pins = @(@($TrustedKeyIds) | Where-Object { "$_" -cmatch '^[A-Za-z0-9_-]{43}$' }) }
    else { $pins = @(Get-PimManagerBaselineTrustedKeyIds) }
    $res = [ordered]@{ verified = $false; signer = ''; keyId = ''; pinnedKeyIds = @($pins); reason = '' }

    $sk = $null
    if ($Doc -is [System.Collections.IDictionary]) { if ($Doc.Contains('signingKey')) { $sk = $Doc['signingKey'] } }
    else { $skp = $Doc.PSObject.Properties['signingKey']; if ($skp) { $sk = $skp.Value } }
    if ($null -ne $sk) {
        $res.signer = 'key'
        try {
            $n = $null; $e = $null
            if ($sk -is [System.Collections.IDictionary]) { $n = $sk['n']; $e = $sk['e'] } else { $n = $sk.n; $e = $sk.e }
            if ("$n".Trim() -and "$e".Trim() -and (Get-Command Get-PimBaselineKeyId -ErrorAction SilentlyContinue)) { $res.keyId = "$(Get-PimBaselineKeyId -N "$n" -E "$e")" }
        } catch { $res.keyId = '' }
    } else { $res.signer = 'certificate' }

    if (-not (Get-Command Test-PimBaselineDoc -ErrorAction SilentlyContinue)) {
        $res.reason = 'the baseline verifier (PIM-Baseline.ps1) is not loaded in this Manager'
        return $res
    }
    $payload = $null
    try { $payload = Test-PimBaselineDoc -Doc $Doc -TrustedKeyIds @($pins) }
    catch {
        $msg = "$($_.Exception.Message)"
        if ($res.signer -eq 'key' -and $msg -match '^UNTRUSTED SIGNING KEY') {
            $res.reason = ("signed by Key Vault key {0}, which this Manager does not pin ({1} key id(s) in PIM_BaselineTrustedKeys). The managed tenants decide with their OWN pins; set the same id on the Manager to verify it here." -f $res.keyId, @($pins).Count)
        } else { $res.reason = $msg }
        return $res
    }
    if (Get-Command Test-PimDownlinkBaselineFinish -ErrorAction SilentlyContinue) {
        $fin = Test-PimDownlinkBaselineFinish -PayloadObject $payload -NowUtc $NowUtc
        if (-not $fin.ok) { $res.reason = "$($fin.reason)"; return $res }
    }
    $res.verified = $true
    $res.reason = $(if ($res.signer -eq 'key') { "signed by pinned Key Vault key $($res.keyId)" } else { 'signed by the product baseline certificate' })
    return $res
}

# --- the GUI payload ---------------------------------------------------------

function Get-PimManagerDownlinkOverview {
    <#
      Everything /api/downlink renders: one entry per managed relationship, each
      carrying the PURE plan's own projected / excluded / unresolved lists (with the
      reason strings the core produced) plus the groups it would create vs defer.
    #>
    # -BaselineFetcher: test seam, passed to Get-PimManagerBaselineDoc (71.40 URL read).
    [CmdletBinding()] param([string]$ConnectionString, [string]$BaselinePath, [scriptblock]$BaselineFetcher)
    if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString }
    $canWrite = $true
    if (Get-Command Test-PimManagerRoleAtLeast -ErrorAction SilentlyContinue) {
        try { $canWrite = [bool](Test-PimManagerRoleAtLeast -Minimum 'SuperAdmin') } catch { $canWrite = $false }
    }
    $tenants = @(Get-PimManagerDownlinkTenants -ConnectionString $ConnectionString)
    $blArgs = @{ Path = $BaselinePath }; if ($BaselineFetcher) { $blArgs['Fetcher'] = $BaselineFetcher }
    $bl = Get-PimManagerBaselineDoc @blArgs

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($t in $tenants) {
        $tid = "$($t.TenantId)"
        $rc = Get-PimMasterRingCopy -Value $t.Ring
        $entry = [ordered]@{
            tenantId       = $tid
            name           = "$($t.DisplayName)"
            # BUG-175: the MASTER'S COPY of the ring -- labelled, never authoritative (the tenant's local ring gates its pull).
            ring           = [int]$rc.ring
            ringKnown      = [bool]$rc.known
            ringSource     = 'master-copy'
            ringNote       = "$($rc.note)"
            adminCount     = 0
            projected      = @(); excluded = @(); unresolved = @()
            # 🔴 THESE TWO WERE COMPUTED BY THE PLAN AND THROWN AWAY HERE, AND THAT MADE A REAL
            # NARROWING INVISIBLE. A role narrowed by its `Target` selector never reaches
            # projected/excluded/unresolved at all -- it is filtered out UPSTREAM of the projection
            # -- so the tenant appeared in NEITHER the reaches list NOR the withheld list. The
            # reach view's own contract is "four narrowings, kept apart, each with its own fix",
            # and two of the four could not be seen from the surface that promises them.
            # 🪤 It fails the quiet way: no error, no empty state, just a tenant that is absent.
            notTargeted    = @(); classHeld = @()
            groupsToCreate = @(); groupsDeferred = @()
            policy         = @(Get-PimManagerDownlinkPolicy -TenantId $tid -ConnectionString $ConnectionString)
            error          = ''
        }
        if (-not $bl.doc) { $entry.error = $bl.error }
        else {
            try {
                # 🔴 NO -SlaveGroupTags, ON PURPOSE. Knowing which tags the customer already
                # owns would mean READING THEIR STORE, and §22 is explicit that customer data
                # never leaves their tenant -- a "harmless" read is still a reach-in. It also
                # could not work: the master's ambient identity has no rights there.
                # Omitting it makes the plan treat every tag the bundle defines as creatable,
                # which is the honest MASTER-SIDE view: "this is what we would OFFER". Which
                # of those the customer already owns is resolved by the customer, when they
                # pull -- and that is exactly where MSP-3 puts the decision.
                # 🔴 NOT $env:TEMP -- unset in the Linux container this runs in. It would not throw
                # here (an empty LocalRoot is handled), which is worse: the plan would quietly
                # stage nothing and report a reason nobody reads.
                $planArgs = @{
                    Scenario = 'S6'; Doc = $bl.doc; TenantId = $tid
                    SlaveRing = $entry.ring; LocalRoot = [System.IO.Path]::GetTempPath()
                }
                $plan = Get-PimDownlinkPlan @planArgs
                if (-not $plan.ok) { $entry.error = "$($plan.reason)" }
                else {
                    $entry.adminCount = @($plan.admins).Count
                    $entry.notTargeted = @($plan.notTargeted)
                    $entry.classHeld   = @($plan.classHeld)
                    if ($plan.projection) {
                        $entry.projected  = @($plan.projection.projected)
                        $entry.excluded   = @($plan.projection.excluded)
                        $entry.unresolved = @($plan.projection.unresolved)
                    }
                    if ($plan.definitions) {
                        $entry.groupsToCreate = @(@($plan.definitions.create) | ForEach-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')" })
                        $entry.groupsDeferred = @(@($plan.definitions.defer)  | ForEach-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')" })
                    }
                }
            } catch { $entry.error = "plan failed: $($_.Exception.Message)" }
        }
        $out.Add($entry) | Out-Null
    }

    $blInfo = $null
    if ($bl.doc) {
        $ver = 0
        try {
            $p = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("$($bl.doc.payloadB64)")) | ConvertFrom-Json
            $ver = $p.version
        } catch {}
        # 🪤 `verified` must reflect a REAL verification, not the fact that a file parsed.
        # It was hardcoded $true, so a bundle with a broken signature still showed
        # "signature verified" in the banner while every relationship below it carried a
        # refusal. Derive it from an ACTUAL verify of the document.
        # 71.35: a Key Vault signed bundle verifies only against a PINNED key id, read the same way the pull job
        # reads it (Get-PimManagerBaselineTrustedKeyIds); a certificate-signed bundle verifies as before. The
        # reason travels with the verdict, so "NOT verified" says WHICH of the two it is.
        $vf = [ordered]@{ verified = $false; signer = ''; keyId = ''; pinnedKeyIds = @(); reason = '' }
        try { $vf = Get-PimManagerBaselineVerification -Doc $bl.doc } catch { $vf.reason = "verify failed: $($_.Exception.Message)" }
        $blInfo = [ordered]@{ version = $ver; source = "$($bl.source)"; verified = [bool]$vf.verified
                              signer = "$($vf.signer)"; keyId = "$($vf.keyId)"; pinnedKeyCount = @($vf.pinnedKeyIds).Count; verifyReason = "$($vf.reason)" }
    }
    return [ordered]@{
        relationships = @($out.ToArray())
        baseline      = $blInfo
        # 71.40: why there is no baseline, kept even when "no managed tenants" wins the headline below -- an unreachable
        # published bundle must stay visible to whoever reads the API, not only when a tenant is registered.
        baselineError = "$($bl.error)"
        baselineSource = "$($bl.source)"
        # BUG-175: what every relationship above was planned with.
        ringSource    = 'master-copy'
        ringNote      = "Each relationship is previewed with the master's copy of its ring (platform.Tenants.Ring). The managed tenant's own local ring gates its real pull and is reported in its acceptance record (slaveRing)."
        canWrite      = $canWrite
        reason        = $(if (-not $tenants.Count) { 'No managed tenants are registered in platform.Tenants.' } elseif (-not $bl.doc) { "$($bl.error)" } else { '' })
    }
}

function Get-PimProjectionWithholdAxis {
    <#
      WHICH narrowing held a tag back, as a FIELD -- classified once, here.

      🔑 PROSE PROTECTS A HUMAN READING A LOG; A FIELD PROTECTS THE NEXT COMPONENT. The plan has
      always produced a good English reason, and the reach view rendered it. But the WRITE half
      (MSP-4 authoring) has to make a decision on it -- "can a policy edit actually deliver the
      reach you asked for?" -- and a decision keyed on a sentence breaks the day somebody improves
      the sentence. Session 31 learned this on `retracts`; this is the same lesson, one surface on.

      Returns: targeting | policy | ring | unresolved | capability | other.
      🔒 `other` IS THE FAIL-CLOSED ANSWER and it is deliberately not called 'unknown-but-probably-
      policy'. The write path refuses to promise a grant it cannot classify, because the failure it
      is avoiding is reporting privilege as granted in a customer tenant when it was not.
    #>
    [CmdletBinding()] param([string]$Bucket, [string]$Reason)
    $b = "$Bucket".Trim().ToLowerInvariant()
    # The bucket is stronger evidence than the prose, so it is read first: a row that arrived in
    # the notTargeted list IS a targeting narrowing whatever its message says.
    if ($b -eq 'unresolved')  { return 'unresolved' }
    if ($b -eq 'nottargeted') { return 'targeting' }
    if ($b -eq 'classheld')   { return 'capability' }
    # 🪤 `.Contains()`, NOT `-like`/`-match`: reason strings carry '[' and ']' (and a stray '*'
    # from a deny pattern), which -like reads as a character class. That trap cost a run in
    # session 32 and it is one line away from here.
    $r = "$Reason".ToLowerInvariant()
    if ($r.Contains('not targeted') -or $r.Contains('target selector')) { return 'targeting' }
    if ($r.Contains('blocked'))          { return 'capability' }
    if ($r.Contains("tenant's ring"))    { return 'ring' }
    if ($r.Contains('relationship policy') -or $r.Contains('allow-list')) { return 'policy' }
    return 'other'
}

function Get-PimProjectionReach {
    <#
      MSP-4 -- THE SURFACE. Pure.

      🔑 THE OPERATOR'S QUESTION IS THE INVERSE OF THE ONE THE MANAGER COULD ALREADY ANSWER.
      `/api/downlink` is TENANT-centric: pick a relationship, see what it gets. The ask -- *"this
      role goes to only 5 of 28 tenants"* -- is ARTIFACT-centric: pick a role, see which tenants it
      reaches. Same data, transposed, and the transpose is the whole feature: nobody can audit
      "5 of 28" by opening 28 tabs and remembering.

      🪤 AND WITHOUT IT, NARROWING IS UNVERIFIABLE IN THE DIRECTION THAT MATTERS. Every narrowing
      axis works and is tested, but the only way to see the RESULT was to read hand-written SQL
      against `pim.TenantRoleProjection` and a `Target` column, per tenant, and hold the answer in
      your head. A control you cannot audit is a control you cannot trust -- and this one grants
      privilege in tenants the operator does not own.

      Returns one entry per GROUP TAG: which tenants it reaches, which it does not, and WHY NOT --
      distinguishing the four narrowings the plan already keeps separate, because collapsing them
      is what makes "why did this role not arrive" unanswerable:
        * `targeting`  -- the artifact's own Target selector never offered it to this tenant
        * `policy`     -- the relationship's allow/deny rules excluded it
        * `ring`       -- the admin holding it sits above the tenant's ring
        * `unresolved` -- offered, but the tenant has no group for that tag
      PURE: takes the already-computed per-tenant overview entries; no SQL, no network. That keeps
      the transpose testable offline and means it can never disagree with the per-tenant view --
      it is literally the same numbers, rotated.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Relationships)

    # 🔴 THE UNIT OF THIS VIEW IS A TENANT, NOT AN ASSIGNMENT ROW -- and the first version counted
    # rows. `projected` carries one row per (admin, tag), so a tenant where TWO admins hold the
    # same role was added TWICE, and the operator's headline sentence read "2 of 2 tenant(s),
    # not narrowed" for an estate where the truth was "1 of 2, NARROWED". Measured, not reasoned.
    # 🪤 IT FAILS TOWARD "NOT NARROWED", which is the direction that hides the thing this view
    # exists to show -- and with three admins it printed "3 of 2 tenant(s)", an impossible number
    # nobody was going to see because nobody re-reads a summary line that looks plausible.
    # So: one cell per (tag, tenant), and a tenant REACHES if ANY of its assignments project.
    $byTag = @{}
    function Add-ReachCell($tag, $tenant, $state, $why, $bucket) {
        if (-not "$tag".Trim()) { return }
        $k = "$tag".Trim()
        if (-not $byTag.ContainsKey($k)) { $byTag[$k] = [ordered]@{} }
        $tid = "$($tenant.tenantId)"
        if (-not $byTag[$k].Contains($tid)) {
            $byTag[$k][$tid] = [ordered]@{
                tenantId = $tid; name = "$($tenant.name)"; ring = $tenant.ring
                reaches  = $false
                reasons  = New-Object System.Collections.Generic.List[object]
            }
        }
        $cell = $byTag[$k][$tid]
        if ($state -eq 'reach') { $cell.reaches = $true; return }
        $axis = Get-PimProjectionWithholdAxis -Bucket $bucket -Reason "$why"
        # Two admins denied for the same reason is ONE fact about the tenant, not two.
        $sig = "$axis|$why"
        if (-not @($cell.reasons.ToArray() | Where-Object { "$($_.sig)" -eq $sig }).Count) {
            [void]$cell.reasons.Add([ordered]@{ sig = $sig; axis = $axis; reason = "$why" })
        }
    }

    $allTenants = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Relationships)) {
        if (-not $r) { continue }
        $allTenants.Add([ordered]@{ tenantId = "$($r.tenantId)"; name = "$($r.name)" }) | Out-Null
        foreach ($p in @($r.projected))  { Add-ReachCell (Get-PimDownlinkValue -Object $p -Key 'GroupTag') $r 'reach'    '' 'projected' }
        foreach ($e in @($r.excluded))   { Add-ReachCell (Get-PimDownlinkValue -Object $e -Key 'GroupTag') $r 'withheld' (Get-PimDownlinkValue -Object $e -Key 'reason') 'excluded' }
        foreach ($u in @($r.unresolved)) { Add-ReachCell (Get-PimDownlinkValue -Object $u -Key 'GroupTag') $r 'withheld' (Get-PimDownlinkValue -Object $u -Key 'reason') 'unresolved' }
        # The two narrowings that happen UPSTREAM of the projection. Without these the tenant is
        # in neither list and the row silently shrinks its own denominator -- see the overview.
        foreach ($n in @(Get-PimDownlinkValue -Object $r -Key 'notTargeted')) {
            Add-ReachCell (Get-PimDownlinkValue -Object $n -Key 'GroupTag') $r 'withheld' (Get-PimDownlinkValue -Object $n -Key 'reason') 'notTargeted'
        }
        foreach ($c in @(Get-PimDownlinkValue -Object $r -Key 'classHeld')) {
            Add-ReachCell (Get-PimDownlinkValue -Object $c -Key 'GroupTag') $r 'withheld' (Get-PimDownlinkValue -Object $c -Key 'reason') 'classHeld'
        }
    }

    $total = @($Relationships).Count
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($k in ($byTag.Keys | Sort-Object)) {
        $cells = @(@($byTag[$k].Values) | Sort-Object @{ e = { "$($_.name)".ToLowerInvariant() } })
        $reach = New-Object System.Collections.Generic.List[object]
        $held  = New-Object System.Collections.Generic.List[object]
        foreach ($c in $cells) {
            $reasons = @($c.reasons.ToArray())
            if ($c.reaches) {
                # The role DOES land here. If another admin's copy of the same tag was held back
                # in this tenant, that is worth showing -- but it is not a withholding of the ROLE,
                # and counting it as one is what produced the impossible numbers above.
                $reach.Add([ordered]@{
                    tenantId = $c.tenantId; name = $c.name; ring = $c.ring
                    partial  = ($reasons.Count -gt 0)
                    partialReason = $(if ($reasons.Count) { "$($reasons[0].reason)" } else { '' })
                }) | Out-Null
            } else {
                $axes = @(@($reasons | ForEach-Object { "$($_.axis)" }) | Select-Object -Unique)
                $axis = 'other'
                if ($axes.Count -eq 1) { $axis = "$($axes[0])" } elseif ($axes.Count -gt 1) { $axis = 'mixed' }
                $held.Add([ordered]@{
                    tenantId = $c.tenantId; name = $c.name; ring = $c.ring
                    # 🔒 `axis` is what the WRITE half reads. `mixed` is not policy, so it refuses.
                    axis     = $axis
                    axes     = @($axes)
                    reason   = $(if ($reasons.Count) { "$($reasons[0].reason)" } else { '' })
                    reasons  = @($reasons | ForEach-Object { [ordered]@{ axis = "$($_.axis)"; reason = "$($_.reason)" } })
                }) | Out-Null
            }
        }
        $reachArr = @($reach.ToArray()); $heldArr = @($held.ToArray())
        # 🔒 THE ACCOUNTING LINE EXISTS BECAUSE THE BUG ABOVE WAS INVISIBLE. A tenant that appears
        # in NEITHER list does not make the view look wrong -- it makes the denominator quietly
        # smaller, which reads as a perfectly ordinary answer. Stating reaches + withheld against
        # the tenant count turns "absent" into something a test and an operator can both see.
        $missing = @(@($allTenants.ToArray()) | Where-Object { -not $byTag[$k].Contains("$($_.tenantId)") })
        $out.Add([ordered]@{
            groupTag      = $k
            reachCount    = $reachArr.Count
            tenantCount   = $total
            # The sentence the operator actually asked for, precomputed so the GUI cannot
            # render a different arithmetic than the API reported.
            summary       = ("{0} of {1} tenant(s)" -f $reachArr.Count, $total)
            # 🔒 A tag that reaches EVERY tenant is not narrowed. Flagged so "5 of 28" stands out
            # from "28 of 28" at a glance -- the whole point is spotting the narrow ones.
            narrowed      = ($reachArr.Count -lt $total)
            reaches       = $reachArr
            withheld      = $heldArr
            accountedFor  = ($reachArr.Count + $heldArr.Count)
            unaccounted   = $missing.Count
            unaccountedTenants = @($missing | ForEach-Object { "$($_.name)" })
        }) | Out-Null
    }
    return @($out.ToArray())
}

# --- MSP-4, the WRITE half: authoring narrowing along the TAG axis -----------

function Get-PimProjectionReachEdit {
    <#
      MSP-4 -- THE WRITE HALF, as a PURE plan. Given "'$GroupTag' should reach exactly these
      tenants", work out the per-relationship rule sets that would deliver it -- or REFUSE.

      🔑 THE REACH VIEW WAS BUILT FIRST AND KEPT READ-ONLY ON PURPOSE: you cannot safely author
      a narrowing you cannot yet audit. This is the other half, and it is deliberately the same
      shape -- the operator edits the TRANSPOSE (one role, N tenants) and the store still holds
      per-tenant rows, so this function is the translation and nothing else writes.

      🔴 THE FAILURE THIS EXISTS TO PREVENT IS "GRANTED" REPORTED FOR A GRANT THAT DID NOT
      HAPPEN. Four different narrowings can hold a role out of a tenant and only ONE of them --
      `policy` -- is writable from here. Ticking a tenant that is held back by its RING, by the
      artifact's own Target selector, or by a capability the customer blocked would write a rule,
      commit cleanly, change nothing, and show a green result. That is this codebase's most
      expensive recurring defect (phantom applied work, BUG-70b), pointed at someone else's
      tenant. So an undeliverable grant is REFUSED, by name, before anything is written.

      🔒 THE TWO DIRECTIONS ARE DELIBERATELY ASYMMETRIC, and the asymmetry always errs toward
      LESS privilege:
        * a GRANT is refused unless `policy` is demonstrably the only thing in the way;
        * a WITHHOLD is always written, even when the role is already held back by another axis,
          because that other axis can change (a ring is raised, a Target is rewritten) and the
          operator's intent must outlive it. It is reported as `alreadyWithheldBy` so the record
          does not pretend the deny is what is doing the work today.

      🪤 A WILDCARD DENY IS NOT MINE TO REMOVE. If `ROLE-*` is what excludes this tag, deleting
      it to grant one role silently widens the tenant's projection to every role that pattern was
      holding back. Refused, naming the rule, and sent to the per-tenant policy panel where the
      blast radius is visible.

      PURE: no SQL, no network. Takes the reach entry, the estate list and the current rules.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GroupTag,
        [AllowEmptyCollection()][string[]]$DesiredTenantIds = @(),
        $ReachEntry,
        [AllowEmptyCollection()][object[]]$Tenants = @(),
        $CurrentPolicies
    )
    $tag = "$GroupTag".Trim()
    $tagLc = $tag.ToLowerInvariant()

    $want = New-Object System.Collections.Generic.HashSet[string]
    foreach ($t in @($DesiredTenantIds)) { [void]$want.Add("$t".Trim().ToLowerInvariant()) }

    # tenantId -> the reach view's own verdict for this tag
    $state = @{}
    foreach ($r in @(Get-PimDownlinkValue -Object $ReachEntry -Key 'reaches')) {
        $k = "$(Get-PimDownlinkValue -Object $r -Key 'tenantId')".Trim().ToLowerInvariant()
        if ($k) { $state[$k] = [ordered]@{ reaches = $true; axis = ''; reason = '' } }
    }
    foreach ($w in @(Get-PimDownlinkValue -Object $ReachEntry -Key 'withheld')) {
        $k = "$(Get-PimDownlinkValue -Object $w -Key 'tenantId')".Trim().ToLowerInvariant()
        if ($k) { $state[$k] = [ordered]@{ reaches = $false
                                           axis    = "$(Get-PimDownlinkValue -Object $w -Key 'axis')"
                                           reason  = "$(Get-PimDownlinkValue -Object $w -Key 'reason')" } }
    }

    $refusals  = New-Object System.Collections.Generic.List[object]
    $edits     = New-Object System.Collections.Generic.List[object]
    $unchanged = New-Object System.Collections.Generic.List[object]

    foreach ($t in @($Tenants)) {
        $tid  = "$(Get-PimDownlinkValue -Object $t -Key 'tenantId')".Trim()
        if (-not $tid) { continue }
        $key  = $tid.ToLowerInvariant()
        $name = "$(Get-PimDownlinkValue -Object $t -Key 'name')"
        if (-not $name) { $name = $tid }
        $wantReach = $want.Contains($key)

        $rules = @()
        if ($null -ne $CurrentPolicies) {
            $got = Get-PimDownlinkValue -Object $CurrentPolicies -Key $key
            if ($null -eq $got) { $got = Get-PimDownlinkValue -Object $CurrentPolicies -Key $tid }
            if ($null -ne $got) { $rules = @($got) }
        }
        $denyHits = @(@($rules) | Where-Object {
            "$(Get-PimDownlinkValue -Object $_ -Key 'Mode')".Trim().ToLowerInvariant() -eq 'deny' -and
            (Test-PimProjectionTagMatch -Tag $tag -Pattern "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')") })
        $allowRules = @(@($rules) | Where-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'Mode')".Trim().ToLowerInvariant() -eq 'allow' })
        $allowHits  = @($allowRules | Where-Object { Test-PimProjectionTagMatch -Tag $tag -Pattern "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')" })

        $st = $null
        if ($state.ContainsKey($key)) { $st = $state[$key] }

        if ($wantReach) {
            if ($null -eq $st) {
                $refusals.Add([ordered]@{ tenantId = $tid; name = $name; want = 'reach'; axis = 'absent'
                    reason = "'$tag' is not part of $name's plan at all -- there is no assignment here to let through." }) | Out-Null
                continue
            }
            if ($st.reaches) {
                $unchanged.Add([ordered]@{ tenantId = $tid; name = $name; action = 'none'; note = "already reaches $name" }) | Out-Null
                continue
            }
            if ("$($st.axis)" -ne 'policy') {
                $refusals.Add([ordered]@{ tenantId = $tid; name = $name; want = 'reach'; axis = "$($st.axis)"
                    reason = "$name is held back by $($st.axis), not by the relationship policy -- a rule written here would change nothing and report success. ($($st.reason))" }) | Out-Null
                continue
            }
            $broad = @($denyHits | Where-Object { "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')".Trim().ToLowerInvariant() -ne $tagLc })
            if ($broad.Count) {
                $refusals.Add([ordered]@{ tenantId = $tid; name = $name; want = 'reach'; axis = 'policy'
                    reason = "a WILDCARD deny ('$(Get-PimDownlinkValue -Object $broad[0] -Key 'GroupTag')') is what excludes '$tag' in $name; removing it here would widen that tenant's projection to every role it covers. Edit it on $name's own policy panel, where that blast radius is visible." }) | Out-Null
                continue
            }
            $newRules = New-Object System.Collections.Generic.List[object]
            foreach ($r in @($rules)) {
                $isHit = @($denyHits | Where-Object {
                    "$(Get-PimDownlinkValue -Object $_ -Key 'Mode')" -eq "$(Get-PimDownlinkValue -Object $r -Key 'Mode')" -and
                    "$(Get-PimDownlinkValue -Object $_ -Key 'GroupTag')" -eq "$(Get-PimDownlinkValue -Object $r -Key 'GroupTag')" })
                if ($isHit.Count) { continue }
                $newRules.Add([ordered]@{ Mode = "$(Get-PimDownlinkValue -Object $r -Key 'Mode')".Trim().ToLowerInvariant()
                                          GroupTag = "$(Get-PimDownlinkValue -Object $r -Key 'GroupTag')".Trim() }) | Out-Null
            }
            # An allow-LIST is only a list while it has entries: with allow rules present, a tag
            # that matches none of them is excluded even with every deny gone.
            if ($allowRules.Count -and -not $allowHits.Count) {
                $newRules.Add([ordered]@{ Mode = 'allow'; GroupTag = $tag }) | Out-Null
            }
            $edits.Add([ordered]@{ tenantId = $tid; name = $name; action = 'grant'; rules = @($newRules.ToArray()) }) | Out-Null
            continue
        }

        # want = withhold
        if ($null -eq $st) {
            $unchanged.Add([ordered]@{ tenantId = $tid; name = $name; action = 'none'; note = "'$tag' is not in $name's plan -- nothing to withhold." }) | Out-Null
            continue
        }
        if ($denyHits.Count) {
            $unchanged.Add([ordered]@{ tenantId = $tid; name = $name; action = 'none'; note = "already denied by '$(Get-PimDownlinkValue -Object $denyHits[0] -Key 'GroupTag')'" }) | Out-Null
            continue
        }
        $newRules = New-Object System.Collections.Generic.List[object]
        foreach ($r in @($rules)) {
            $newRules.Add([ordered]@{ Mode = "$(Get-PimDownlinkValue -Object $r -Key 'Mode')".Trim().ToLowerInvariant()
                                      GroupTag = "$(Get-PimDownlinkValue -Object $r -Key 'GroupTag')".Trim() }) | Out-Null
        }
        $newRules.Add([ordered]@{ Mode = 'deny'; GroupTag = $tag }) | Out-Null
        $already = ''
        if (-not $st.reaches) { $already = "$($st.axis)" }
        $edits.Add([ordered]@{ tenantId = $tid; name = $name; action = 'withhold'
                               alreadyWithheldBy = $already; rules = @($newRules.ToArray()) }) | Out-Null
    }

    return [ordered]@{
        ok        = (@($refusals.ToArray()).Count -eq 0)
        groupTag  = $tag
        refusals  = @($refusals.ToArray())
        edits     = @($edits.ToArray())
        unchanged = @($unchanged.ToArray())
    }
}

function Set-PimProjectionReach {
    <#
      MSP-4 -- apply a tag-axis reach edit, then MEASURE what it actually did.

      🔴 THE VERDICT IS RE-MEASURED, NOT ASSUMED. The plan above says what the rules should
      deliver; this re-composes the whole downlink overview AFTER the commit and reads the reach
      back out. "I wrote the rows I intended" and "the role now reaches the tenants you asked
      for" are different claims, and only the second is the one the operator made. If they
      disagree the result is NOT ok -- loudly, with the difference named -- even though the write
      succeeded. A write that reports success it cannot demonstrate is how this project has
      repeatedly shipped phantom work.

      Nothing is written when the plan carries a single refusal: a partial narrowing is not a
      smaller narrowing, and the operator asked for one estate-wide statement.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GroupTag,
        [AllowEmptyCollection()][string[]]$TenantIds = @(),
        [string]$ConnectionString,
        [string]$BaselinePath
    )
    if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString }
    $tag = "$GroupTag".Trim()

    $ovArgs = @{ ConnectionString = $ConnectionString }
    if ($BaselinePath) { $ovArgs['BaselinePath'] = $BaselinePath }

    $before      = Get-PimManagerDownlinkOverview @ovArgs
    $reachBefore = @(Get-PimProjectionReach -Relationships @($before.relationships))
    $entry       = @($reachBefore | Where-Object { "$($_.groupTag)".Trim().ToLowerInvariant() -eq $tag.ToLowerInvariant() })
    if (-not $entry.Count) {
        throw "'$tag' is not a role in the current plan -- nothing was written. (Roles come from the SIGNED baseline; a tag the bundle does not define cannot be narrowed.)"
    }

    $tenants  = @(@($before.relationships) | ForEach-Object { [ordered]@{ tenantId = "$($_.tenantId)"; name = "$($_.name)" } })
    $policies = [ordered]@{}
    foreach ($r in @($before.relationships)) { $policies["$($r.tenantId)".Trim().ToLowerInvariant()] = @($r.policy) }

    $plan = Get-PimProjectionReachEdit -GroupTag $tag -DesiredTenantIds @($TenantIds) `
                -ReachEntry $entry[0] -Tenants $tenants -CurrentPolicies $policies
    if (-not $plan.ok) {
        return [ordered]@{
            ok = $false; wrote = $false; groupTag = $tag
            refusals = @($plan.refusals); edits = @($plan.edits); unchanged = @($plan.unchanged)
            before = "$($entry[0].summary)"; after = "$($entry[0].summary)"
            detail = "REFUSED -- nothing was written. $(@($plan.refusals).Count) tenant(s) cannot be set from this view."
        }
    }

    $wrote = 0
    if (@($plan.edits).Count) {
        $wrote = Set-PimManagerDownlinkPolicyMany -Edits @(@($plan.edits) | ForEach-Object { [ordered]@{ TenantId = "$($_.tenantId)"; Rules = @($_.rules) } }) `
                    -ConnectionString $ConnectionString -Note "MSP-4 reach edit for '$tag'"
    }

    $after      = Get-PimManagerDownlinkOverview @ovArgs
    $reachAfter = @(Get-PimProjectionReach -Relationships @($after.relationships))
    $entryAfter = @($reachAfter | Where-Object { "$($_.groupTag)".Trim().ToLowerInvariant() -eq $tag.ToLowerInvariant() })

    $got = New-Object System.Collections.Generic.HashSet[string]
    if ($entryAfter.Count) {
        foreach ($r in @($entryAfter[0].reaches)) { [void]$got.Add("$($r.tenantId)".Trim().ToLowerInvariant()) }
    }
    $askedFor = New-Object System.Collections.Generic.HashSet[string]
    foreach ($t in @($TenantIds)) { [void]$askedFor.Add("$t".Trim().ToLowerInvariant()) }

    $missing = @(@($askedFor) | Where-Object { -not $got.Contains($_) })
    $extra   = @(@($got)      | Where-Object { -not $askedFor.Contains($_) })
    $delivered = ((@($missing).Count -eq 0) -and (@($extra).Count -eq 0))

    $nameOf = @{}
    foreach ($t in $tenants) { $nameOf["$($t.tenantId)".Trim().ToLowerInvariant()] = "$($t.name)" }
    $named = { param($ids) @(@($ids) | ForEach-Object { if ($nameOf.ContainsKey("$_")) { $nameOf["$_"] } else { "$_" } }) }

    $detail = "'$tag' now reaches $(if ($entryAfter.Count) { "$($entryAfter[0].summary)" } else { "0 of $(@($tenants).Count) tenant(s)" }); $wrote relationship(s) rewritten."
    if (-not $delivered) {
        $detail = "WROTE $wrote relationship(s), BUT THE RESULT IS NOT WHAT WAS ASKED FOR. " +
                  "$(if (@($missing).Count) { "still not reaching: $((& $named $missing) -join ', '). " } else { '' })" +
                  "$(if (@($extra).Count) { "unexpectedly reaching: $((& $named $extra) -join ', '). " } else { '' })" +
                  "The rules were committed; the reach was re-measured and disagrees."
    }
    return [ordered]@{
        ok        = $delivered
        wrote     = ($wrote -gt 0)
        groupTag  = $tag
        refusals  = @()
        edits     = @($plan.edits)
        unchanged = @($plan.unchanged)
        before    = "$($entry[0].summary)"
        after     = $(if ($entryAfter.Count) { "$($entryAfter[0].summary)" } else { '' })
        missing   = @(& $named $missing)
        extra     = @(& $named $extra)
        detail    = $detail
    }
}

# --- the run -----------------------------------------------------------------

function Invoke-PimManagerDownlinkRun {
    <#
      PREVIEW ONLY, and deliberately so.

      🔴 THIS USED TO WRITE INTO THE MANAGED TENANT'S STORE, AND THAT WAS WRONG TWICE OVER.
      It broke the standing Do-Not in docs/REQUIREMENTS.md §22 -- "MSP never writes to a
      customer tenant" -- and the pull-not-push tenet PIM-Downlink.ps1 asserts throughout.
      It was also simply broken: a Manager in the master holds the MASTER's ambient
      identity, and Get-PimSqlConnectionString mints its Azure SQL token from that, so the
      connection authenticated as the wrong tenant entirely.

      📌 THE AGREED MODEL (framework MSP-3, operator 2026-08-13) removes the need rather
      than licensing it: the managed tenant PULLS, decides locally with its own identity,
      and its own administrator ACCEPTS before anything applies. So the master side of this
      feature PUBLISHES a version; it never reaches in.

      What remains is the PREVIEW an MSP operator legitimately needs -- "what would this
      customer receive if they pulled right now" -- computed from the signed bundle and the
      master's own registry, touching nothing.
      ◻ The publish/release action and the customer-side accept surface are MSP-3 work and
      are not built yet. This function must NOT grow a write path back.
    #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$TenantId,
        [string]$ConnectionString,
        [string]$BaselinePath,
        [switch]$WhatIfMode = $true
    )
    if (-not $ConnectionString) { $ConnectionString = Get-PimSqlConnectionString }
    $t = @(Get-PimManagerDownlinkTenants -ConnectionString $ConnectionString | Where-Object { "$($_.TenantId)" -eq $TenantId }) | Select-Object -First 1
    if (-not $t) { return @{ ok = $false; detail = "tenant $TenantId is not a registered managed relationship." } }

    if (-not $WhatIfMode) {
        # Refuse LOUDLY rather than silently downgrading to a preview: an operator who asked
        # to apply must never be shown a green "done" for something that did nothing.
        return @{ ok = $false; whatIf = $true; detail = @(
            'REFUSED: the master does not write into a managed tenant.',
            '',
            'Under the agreed model (framework MSP-3) the managed tenant PULLS the signed baseline,',
            'decides locally with its own identity, and its own administrator ACCEPTS it before',
            'anything applies. Nothing crosses a tenant boundary in the other direction.',
            '',
            'Use Dry run to preview what this customer would receive. To make it real, publish the',
            'baseline version for their ring; their engine collects it on its next run.'
        ) -join "`n" }
    }

    $bl = Get-PimManagerBaselineDoc -Path $BaselinePath
    if (-not $bl.doc) { return @{ ok = $false; detail = "$($bl.error)" } }

    # No slave-side tag list: reading one would mean reaching into the customer's store.
    # Omitting it makes the plan treat every tag the bundle defines as creatable, which is
    # the honest preview -- the tenant resolves the rest itself when it pulls.
    # 🔴 NOT $env:TEMP -- unset in the Linux container (see the sibling call above).
    # BUG-175: planned with the MASTER'S COPY of the ring, and the preview says so on its first lines.
    $rc = Get-PimMasterRingCopy -Value $t.Ring
    $planArgs = @{ Scenario = 'S6'; Doc = $bl.doc; TenantId = $TenantId; SlaveRing = [int]$rc.ring; LocalRoot = [System.IO.Path]::GetTempPath() }
    $plan = Get-PimDownlinkPlan @planArgs
    if (-not $plan.ok) { return @{ ok = $false; detail = "refused: $($plan.reason)"; ringSource = 'master-copy'; ringNote = "$($rc.note)" } }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("PREVIEW for $($t.DisplayName) -- nothing was written.") | Out-Null
    $lines.Add("ring used  : $($rc.note)") | Out-Null
    $lines.Add("$($plan.reason)") | Out-Null
    $lines.Add("admins offered : $(@($plan.admins).Count)") | Out-Null
    $lines.Add("roles offered  : $(@($plan.assignments).Count)") | Out-Null
    if ($plan.definitions) { $lines.Add("groups offered : $(@($plan.definitions.create).Count)") | Out-Null }
    foreach ($e in @($plan.projection.excluded))   { $lines.Add("held back  $($e.UserName) -> $($e.GroupTag): $($e.reason)") | Out-Null }
    foreach ($u in @($plan.projection.unresolved)) { $lines.Add("UNRESOLVED $($u.UserName) -> $($u.GroupTag): $($u.reason)") | Out-Null }
    return @{ ok = $true; whatIf = $true; detail = ($lines.ToArray() -join "`n"); ringSource = 'master-copy'; ringNote = "$($rc.note)" }
}
