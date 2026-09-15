# IMP-02: the locale-safe stamp reader. Loaded defensively so this file stays correct
# when a test dot-sources it on its own (PIM-Functions.psm1 also loads it up front).
if (-not (Get-Command Get-PimUtcStamp -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'PIM-DateSafe.ps1') }
#Requires -Version 5.1
# PIM-WorkloadMap.ps1 -- live workload-assignment CRAWL MAP + RECONCILIATION.
#
# WHY this file exists:
#   The Delegation Map's 4th target kind (workload-target) is sourced from the
#   DESIRED CSV (PIM-Assignments-Workloads). To tell the operator whether each
#   desired binding is actually live in the workload, we crawl every connector's
#   listAssignments (the SAME crawl Apply-PimWorkloadAssignments uses to decide
#   idempotency), persist it as a per-instance cache, and reconcile desired-vs-
#   live per PIM group:
#       mapped    -- live assignment exists for this group+role(+scope)
#       missing   -- desired but not live (candidate to push via the connector)
#       exempted  -- explicitly excused (mandatory reason + expiry, like
#                    PIM-WarningOverrides.ps1 / the exemptions model)
#
# CONTRACTS:
#   * Engine stays the WRITER. The crawl sweep (Update-PimWorkloadCrawlMap) is
#     called by the scheduler/discovery; the GUI only READS the cache + reconciles.
#   * No live calls happen on the GUI read path -- reconciliation is pure over the
#     cached crawl + the desired row + the exemption list.
#   * PS 5.1-safe: no ?./??, no RSA.ImportFromPem. Never throws on a bad/absent value.
#
# STORAGE -- SQL ONLY (operator, 2026-09-12: "we dont use settings files anymore, sql only").
#   Both documents used to be FILES: the crawl map in the instance cache dir
#   (workload-crawl-map.json) and the exemptions in config/PIM-WorkloadExemptions.custom.json.
#   A hosted deployment has no persistent volume, so the crawl vanished on every revision roll,
#   and exemptions could only be set by editing a file on the server. They now live in
#   pim.Settings['WorkloadCrawlMap'] and pim.Settings['WorkloadExemptions'], read and written
#   through the Get-/Set-PimSetting bridge the Manager and the scheduler both provide (or a
#   direct SQL read when only a connection string exists). The -CacheDir / -ConfigRoot / -Path
#   parameters are still ACCEPTED so existing callers bind, and are IGNORED.
#
# CACHE SHAPE (JSON, written by Update-PimWorkloadCrawlMap):
#   {
#     "crawledUtc": "2026-06-18T10:00:00Z",
#     "workloads": {
#       "defender-xdr": {
#         "ok": true,
#         "assignments": [ { "roleId": "...", "roleName": "...", "scope": "/",
#                            "principalIds": ["<groupObjectId>"] }, ... ]
#       },
#       "intune": { "ok": false, "error": "403 ..." }
#     }
#   }
#
# EXEMPTION STORE (pim.Settings['WorkloadExemptions']):
#   { "exemptions": [ { "workload","role","groupTag"?,"scope"?,
#                       "reason"(REQ),"createdBy"?,"expiresOn"(REQ unless noExpiry),
#                       "noExpiry"? } ] }
#   Honoured by the ENGINE too (WorkloadConnectors scope): an active exemption excuses a missing
#   Assign binding, so it is reported and not created.

Set-StrictMode -Off
# Setting names are literals at each use, not $script: variables: in a dot-sourced function
# $script: binds to the CALLER's script scope, where they would be $null.

# ---------------------------------------------------------------------------
# Store seam (SQL pim.Settings)
# ---------------------------------------------------------------------------

function Get-PimWorkloadStoreValue {
    # Read a pim.Settings value: the Get-PimSetting bridge, else a direct SQL read. $null when
    # absent or unreadable. A JSON string is parsed (the store keeps scalars as text).
    param([Parameter(Mandatory)][string]$Name)
    $v = $null
    if (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) {
        try { $v = Get-PimSetting -Name $Name } catch { $v = $null }
    } else {
        $cs = if ("$($global:PIM_EngineSqlCs)".Trim()) { "$($global:PIM_EngineSqlCs)" } elseif ("$($global:PIM_SqlConnectionString)".Trim()) { "$($global:PIM_SqlConnectionString)" } else { '' }
        if ($cs -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) {
            try { $v = Get-PimSqlSetting -ConnectionString $cs -Name $Name } catch { $v = $null }
        }
    }
    for ($i = 0; $i -lt 2 -and $v -is [string]; $i++) {
        $s = "$v".Trim()
        if (-not $s) { return $null }
        try { $v = $s | ConvertFrom-Json } catch { return $null }
    }
    return $v
}

function Set-PimWorkloadStoreValue {
    # Write a pim.Settings value as JSON. Throws when no store is wired: these documents have no
    # other home, and "saved nowhere" must not read as saved.
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][object]$Value)
    $json = if ($Value -is [string]) { $Value } else { ConvertTo-Json -InputObject $Value -Depth 12 -Compress }
    if (Get-Command Set-PimSetting -ErrorAction SilentlyContinue) { Set-PimSetting -Name $Name -Value $json | Out-Null; return $true }
    $cs = if ("$($global:PIM_EngineSqlCs)".Trim()) { "$($global:PIM_EngineSqlCs)" } elseif ("$($global:PIM_SqlConnectionString)".Trim()) { "$($global:PIM_SqlConnectionString)" } else { '' }
    if ($cs -and (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) { Set-PimSqlSetting -ConnectionString $cs -Name $Name -Value $json | Out-Null; return $true }
    throw ("no SQL settings store is wired in this process -- '{0}' is stored in pim.Settings only." -f $Name)
}

function Get-PimWorkloadCrawlMapPath {
    # RETIRED (SQL only). Kept so an old caller binds; there is no file path any more.
    [CmdletBinding()]
    param([string]$CacheDir)
    return $null
}

# ---------------------------------------------------------------------------
# Crawl (WRITER -- engine/scheduler only)
# ---------------------------------------------------------------------------

function Get-PimWorkloadCrawlAssignments {
    <#
      Crawl ONE connector's listAssignments into a normalized array:
        @( @{ roleId; roleName; scope; principalIds = string[]; displayName } )
      Pure-ish: relies on Invoke-PimWorkloadApi / Get-PimWorkloadAssignmentPrincipals
      from PIM-Functions.psm1 for the live call. Throws are caught by the caller.
      $RoleNameById lets the caller pass a roleId->name lookup (from listRoles) so
      the crawl carries human role names for the recon view.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Connector,
        [hashtable]$RoleNameById = @{},
        [hashtable]$Tokens = @{}
    )
    $la = $Connector.api.listAssignments
    if (-not $la) { return @() }
    # v2 REST runtime (PIM-WorkloadConnectors.ps1) when loaded; the v1 module helpers otherwise.
    $v2 = [bool](Get-Command Invoke-PimWorkloadConnectorApi -ErrorAction SilentlyContinue)
    if ($v2) {
        $resp  = Invoke-PimWorkloadConnectorApi -Connector $Connector -Op $la -Tokens $Tokens
        $items = @(Get-PimWorkloadConnectorItems -Response $resp -Op $la)
    } else {
        $resp  = Invoke-PimWorkloadApi -Connector $Connector -Op $la -Tokens $Tokens
        $items = if ($la.itemsPath) { @(Get-PimNestedProp $resp $la.itemsPath) } else { @($resp) }
    }
    $out = New-Object System.Collections.ArrayList
    foreach ($it in @($items)) {
        if ($v2) {
            $pv = if ($la.principalIds) { Get-PimWorkloadConnectorProp -Object $it -Path "$($la.principalIds)" } else { $null }
            $norm = @{ principals = @(@($pv) | Where-Object { $null -ne $_ } | ForEach-Object { "$_" }); displayName = "$(Get-PimWorkloadConnectorProp -Object $it -Path 'displayName')" }
            $rid  = "$(Get-PimWorkloadConnectorProp -Object $it -Path "$($la.roleId)")"
            $out.Add([ordered]@{
                roleId       = "$rid"
                roleName     = $(if ($rid -and $RoleNameById.ContainsKey("$rid")) { "$($RoleNameById["$rid"])" } else { '' })
                scope        = $(if ($la.scope) { "$(Get-PimWorkloadConnectorProp -Object $it -Path "$($la.scope)")" } elseif ($it.PSObject.Properties['directoryScopeIds']) { "$(@($it.directoryScopeIds) | Select-Object -First 1)" } else { '' })
                principalIds = @($norm.principals)
                displayName  = "$($norm.displayName)"
            }) | Out-Null
            continue
        }
        $norm = Get-PimWorkloadAssignmentPrincipals -Connector $Connector -Item $it
        $rid  = "$(Get-PimNestedProp $it $la.roleId)"
        $scope = ''
        if ($la.scope) { $scope = "$(Get-PimNestedProp $it $la.scope)" }
        elseif ($it.PSObject.Properties['directoryScopeIds']) { $scope = (@($it.directoryScopeIds) | Select-Object -First 1) }
        $rname = if ($rid -and $RoleNameById.ContainsKey("$rid")) { "$($RoleNameById["$rid"])" } else { '' }
        [void]$out.Add([ordered]@{
            roleId       = "$rid"
            roleName     = "$rname"
            scope        = "$scope"
            principalIds = @($norm.principals)
            displayName  = "$($norm.displayName)"
        })
    }
    return @($out.ToArray())
}

function Update-PimWorkloadCrawlMap {
    <#
    .SYNOPSIS
        WRITER. Crawl every connector's live assignments and persist the result
        in pim.Settings['WorkloadCrawlMap']. Called by the scheduler / discovery
        sweep / the Manager's "run crawl" action -- NOT on the GUI read path. Each
        connector is best-effort: a 403/throw is recorded as { ok=false; error } and
        never aborts the sweep.
    .OUTPUTS
        'sql:WorkloadCrawlMap' when written. Throws when no SQL settings store is wired.
    #>
    [CmdletBinding()]
    param(
        [string]$ConnectorsDir,
        [string]$CacheDir,          # ignored -- SQL only
        [hashtable]$Tokens = @{}
    )
    $connectors = @()
    if (Get-Command Get-PimWorkloadConnectorCatalog -ErrorAction SilentlyContinue) {
        $cat = Get-PimWorkloadConnectorCatalog -Directory $ConnectorsDir
        $connectors = @($cat.Keys | Sort-Object | ForEach-Object { $cat[$_] })
    } elseif ((Get-Command Read-PimWorkloadConnectors -ErrorAction SilentlyContinue) -and "$ConnectorsDir".Trim()) {
        $connectors = @(Read-PimWorkloadConnectors -ConnectorsDir $ConnectorsDir)
    }
    $wl = [ordered]@{}
    foreach ($c in $connectors) {
        $id = "$($c.id)".Trim()
        if (-not $id) { continue }
        try {
            $roleMap = @{}
            try {
                $roles = if (Get-Command Get-PimWorkloadConnectorRoles -ErrorAction SilentlyContinue) { @(Get-PimWorkloadConnectorRoles -Connector $c -Tokens $Tokens) } else { @(Get-PimWorkloadRoles -Connector $c -Tokens $Tokens) }
                foreach ($r in $roles) {
                    if ("$($r.id)".Trim()) { $roleMap["$($r.id)"] = "$($r.name)" }
                }
            } catch { $roleMap = @{} }
            $asg = Get-PimWorkloadCrawlAssignments -Connector $c -RoleNameById $roleMap -Tokens $Tokens
            $wl[$id] = [ordered]@{ ok = $true; assignments = @($asg) }
        } catch {
            $wl[$id] = [ordered]@{ ok = $false; error = "$($_.Exception.Message)"; assignments = @() }
        }
    }
    $body = [ordered]@{
        crawledUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        workloads  = $wl
    }
    [void](Set-PimWorkloadStoreValue -Name 'WorkloadCrawlMap' -Value $body)
    return 'sql:WorkloadCrawlMap'
}

# ---------------------------------------------------------------------------
# Read (GUI path) -- crawl map + exemptions
# ---------------------------------------------------------------------------

function Read-PimWorkloadCrawlMap {
    <#
      Read the crawl map from pim.Settings['WorkloadCrawlMap']. Absent / unreadable -> $null
      (the GUI then shows no recon badges). Never throws. -CacheDir is ignored (SQL only).
    #>
    [CmdletBinding()]
    param([string]$CacheDir)
    try { return (Get-PimWorkloadStoreValue -Name 'WorkloadCrawlMap') } catch { return $null }
}

function Save-PimWorkloadExemptions {
    <#
      Persist the workload-exemption list to pim.Settings['WorkloadExemptions']. Only well-formed
      entries are kept (workload or role, a reason, and expiresOn unless noExpiry) -- the same
      contract the reader enforces, applied at the door so a bad entry is refused, not stored.
      Returns the normalised list written. Throws when no SQL store is wired.
    #>
    [CmdletBinding()]
    param([object[]]$Exemptions = @())
    $norm = @(Read-PimWorkloadExemptions -Config ([pscustomobject]@{ exemptions = @($Exemptions) }))
    $keep = @($norm | Where-Object { ($_.workload -or $_.role) -and $_.reason -and ($_.noExpiry -or $_.expiresOn) })
    [void](Set-PimWorkloadStoreValue -Name 'WorkloadExemptions' -Value ([ordered]@{ exemptions = @($keep) }))
    return $keep
}

function Read-PimWorkloadExemptions {
    <#
      Read + normalize the workload-exemption store (pim.Settings['WorkloadExemptions']). Mirrors
      the PIM-WarningOverrides contract: reason MANDATORY; expiresOn MANDATORY unless
      noExpiry:true; an expired entry does NOT exempt (the binding resurfaces as missing).
      -Config supplies the document directly (tests / a caller that already has it).
      -ConfigRoot / -Path are ignored: there is no exemptions FILE in v2.
      Returns an array of normalized hashtables (never throws).
    #>
    [CmdletBinding()]
    param([string]$ConfigRoot, [string]$Path, [object]$Config)
    $raw = $null
    if ($Config) { $raw = $Config }
    else {
        try { $raw = Get-PimWorkloadStoreValue -Name 'WorkloadExemptions' } catch { $raw = $null }
    }
    if (-not $raw) { return @() }

    function _wexField([object]$obj, [string]$name) {
        if ($null -eq $obj) { return $null }
        if ($obj -is [System.Collections.IDictionary]) { if ($obj.Contains($name)) { return $obj[$name] }; return $null }
        $p = $obj.PSObject.Properties[$name]; if ($p) { return $p.Value }; return $null
    }
    $list = _wexField $raw 'exemptions'
    # An EMPTY exemptions array comes back from _wexField as $null (PowerShell unrolls it), which used to
    # fall into the bare-list branch and return the wrapper document itself as one blank exemption.
    $hasExProp = if ($raw -is [System.Collections.IDictionary]) { $raw.Contains('exemptions') } elseif ($raw -isnot [string] -and $raw -isnot [System.Array]) { [bool]$raw.PSObject.Properties['exemptions'] } else { $false }
    if ($null -eq $list -and $hasExProp) { return @() }
    if ($null -eq $list) {
        if ($raw -is [System.Collections.IEnumerable] -and $raw -isnot [string]) { $list = $raw } else { $list = @($raw) }
    }
    $out = New-Object System.Collections.ArrayList
    foreach ($o in @($list)) {
        if (-not $o) { continue }
        [void]$out.Add([ordered]@{
            workload  = "$(_wexField $o 'workload')".Trim()
            role      = "$(_wexField $o 'role')".Trim()
            groupTag  = "$(_wexField $o 'groupTag')".Trim()
            scope     = "$(_wexField $o 'scope')".Trim()
            reason    = "$(_wexField $o 'reason')".Trim()
            createdBy = "$(_wexField $o 'createdBy')".Trim()
            expiresOn = "$(_wexField $o 'expiresOn')".Trim()
            noExpiry  = [bool](_wexField $o 'noExpiry')
        })
    }
    return @($out.ToArray())
}

function Test-PimWorkloadExemptionActive {
    <#
      An exemption is ACTIVE (suppresses a missing binding) only when it is
      well-formed (reason + (expiresOn|noExpiry)) AND not expired as of $AsOf.
      Fail-safe: a malformed or unparseable-date entry is NOT active.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Exemption, [datetime]$AsOf = ([datetime]::UtcNow))
    if (-not $Exemption.reason) { return $false }
    if ($Exemption.noExpiry) { return $true }
    if (-not $Exemption.expiresOn) { return $false }
    # IMP-02: locale-safe. Fails SAFE as before -- an unreadable expiry grants no exemption.
    $exp = Get-PimUtcStamp $Exemption.expiresOn
    if ($null -eq $exp) { return $false }
    $expEnd = $exp.Date.AddDays(1).AddTicks(-1)
    return ($AsOf.ToUniversalTime() -le $expEnd.ToUniversalTime())
}

function Test-PimWorkloadExemptionMatches {
    <#
      Does an exemption cover this desired row? workload + role must match
      (case-insensitive); groupTag/scope match only when the exemption specifies
      them (omitted = any). $GroupId optionally lets a future group-id form match.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Exemption, [Parameter(Mandatory)][object]$Row)
    $wl = "$($Row.Workload)".Trim()
    $rn = "$($Row.RoleName)".Trim()
    $gt = "$($Row.GroupTag)".Trim()
    $sc = "$($Row.Scope)".Trim()
    if ($Exemption.workload -and ($Exemption.workload -ine $wl)) { return $false }
    if ($Exemption.role     -and ($Exemption.role     -ine $rn)) { return $false }
    if ($Exemption.groupTag -and ($Exemption.groupTag -ine $gt)) { return $false }
    if ($Exemption.scope    -and ($Exemption.scope    -ine $sc)) { return $false }
    # An exemption with neither workload nor role is too broad -> never matches.
    if (-not $Exemption.workload -and -not $Exemption.role) { return $false }
    return $true
}

# ---------------------------------------------------------------------------
# Reconcile (PURE) -- desired row vs crawl map vs exemptions
# ---------------------------------------------------------------------------

function Get-PimWorkloadReconStatus {
    <#
    .SYNOPSIS
        PURE reconciliation of ONE desired PIM-Assignments-Workloads row against
        the live crawl map + exemptions. No network. Returns:
          @{ status = 'mapped'|'missing'|'exempted'|'unknown'; reason; crawledUtc }
        'unknown' = no crawl data for this workload (sweep hasn't run / errored),
        so the GUI shows a neutral "not yet crawled" rather than a false 'missing'.
    .PARAMETER GroupId
        The Entra group object id this GroupTag resolves to, if known (the live
        crawl records principalIds as object ids). When omitted, mapping falls
        back to matching by role(+scope) presence only (best-effort).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Row,
        [object]$CrawlMap,
        [object[]]$Exemptions = @(),
        [string]$GroupId,
        [datetime]$AsOf = ([datetime]::UtcNow)
    )
    $wl = "$($Row.Workload)".Trim()
    $rn = "$($Row.RoleName)".Trim()
    $sc = "$($Row.Scope)".Trim()
    if (-not $wl -or -not $rn) { return $null }

    $crawledUtc = if ($CrawlMap) { "$($CrawlMap.crawledUtc)" } else { '' }

    # Is it live? Look up the workload's crawled assignments.
    $wlNode = $null
    if ($CrawlMap -and $CrawlMap.workloads) {
        $p = $CrawlMap.workloads.PSObject.Properties[$wl]
        if (-not $p) {
            # case-insensitive fallback
            foreach ($pp in $CrawlMap.workloads.PSObject.Properties) { if ("$($pp.Name)" -ieq $wl) { $p = $pp; break } }
        }
        if ($p) { $wlNode = $p.Value }
    }

    if (-not $wlNode -or -not $wlNode.ok) {
        # No usable crawl for this workload. Was it explicitly exempted anyway?
        foreach ($e in @($Exemptions)) {
            if ((Test-PimWorkloadExemptionMatches -Exemption $e -Row $Row) -and (Test-PimWorkloadExemptionActive -Exemption $e -AsOf $AsOf)) {
                return [ordered]@{ status = 'exempted'; reason = "$($e.reason)"; crawledUtc = $crawledUtc }
            }
        }
        return [ordered]@{ status = 'unknown'; reason = $(if ($wlNode -and $wlNode.error) { "$($wlNode.error)" } else { 'not yet crawled' }); crawledUtc = $crawledUtc }
    }

    $live = $false
    foreach ($a in @($wlNode.assignments)) {
        $roleHit = ("$($a.roleName)" -ieq $rn) -or ("$($a.roleId)" -ieq $rn)
        if (-not $roleHit) { continue }
        if ($sc -and "$($a.scope)".Trim() -and ("$($a.scope)".Trim() -ine $sc)) { continue }
        if ($GroupId) {
            if (@($a.principalIds) -notcontains $GroupId) { continue }
        }
        $live = $true; break
    }
    if ($live) { return [ordered]@{ status = 'mapped'; reason = ''; crawledUtc = $crawledUtc } }

    # Desired but not live -> exempted (if an active exemption covers it) else missing.
    foreach ($e in @($Exemptions)) {
        if ((Test-PimWorkloadExemptionMatches -Exemption $e -Row $Row) -and (Test-PimWorkloadExemptionActive -Exemption $e -AsOf $AsOf)) {
            return [ordered]@{ status = 'exempted'; reason = "$($e.reason)"; crawledUtc = $crawledUtc }
        }
    }
    return [ordered]@{ status = 'missing'; reason = 'desired but not present in the live crawl'; crawledUtc = $crawledUtc }
}

function Get-PimWorkloadReconSummary {
    <#
      Roll up reconciliation across a set of desired rows: counts per status.
      Used by the small reconciliation summary in the GUI.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [object]$CrawlMap,
        [object[]]$Exemptions = @(),
        [datetime]$AsOf = ([datetime]::UtcNow)
    )
    $c = [ordered]@{ mapped = 0; missing = 0; exempted = 0; unknown = 0; total = 0 }
    foreach ($r in @($Rows)) {
        if (-not "$($r.Workload)".Trim() -or -not "$($r.RoleName)".Trim() -or -not "$($r.GroupTag)".Trim()) { continue }
        $st = Get-PimWorkloadReconStatus -Row $r -CrawlMap $CrawlMap -Exemptions $Exemptions -AsOf $AsOf
        if (-not $st) { continue }
        $c.total++
        switch ("$($st.status)") {
            'mapped'   { $c.mapped++ }
            'missing'  { $c.missing++ }
            'exempted' { $c.exempted++ }
            default    { $c.unknown++ }
        }
    }
    if ($CrawlMap) { $c.crawledUtc = "$($CrawlMap.crawledUtc)" }
    return $c
}
