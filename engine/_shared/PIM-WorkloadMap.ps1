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
#   * PS 5.1-safe: no ?./??, no RSA.ImportFromPem; ConvertFrom-Json + Set-Content
#     UTF-8-no-BOM only. Never throws on a bad/absent cache or exemption file.
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
# EXEMPTION STORE (config/PIM-WorkloadExemptions.custom.json, gitignored):
#   { "exemptions": [ { "workload","role","groupTag"?,"scope"?,
#                       "reason"(REQ),"createdBy"?,"expiresOn"(REQ unless noExpiry),
#                       "noExpiry"? } ] }

Set-StrictMode -Off

# ---------------------------------------------------------------------------
# Cache path
# ---------------------------------------------------------------------------

function Get-PimWorkloadCrawlMapPath {
    <#
      Resolve the crawl-map cache file. Prefers the Manager instance cache dir
      (Get-PimTenantCacheRoot, per-tenant in MSP mode); callers may override with
      -CacheDir for tests / out-of-Manager engine sweeps.
    #>
    [CmdletBinding()]
    param([string]$CacheDir)
    if (-not $CacheDir) {
        if (Get-Command Get-PimTenantCacheRoot -ErrorAction SilentlyContinue) {
            try { $CacheDir = Get-PimTenantCacheRoot } catch { $CacheDir = $null }
        }
    }
    if (-not $CacheDir) { return $null }
    if (-not (Test-Path -LiteralPath $CacheDir)) {
        try { New-Item -ItemType Directory -Path $CacheDir -Force | Out-Null } catch { return $null }
    }
    return (Join-Path $CacheDir 'workload-crawl-map.json')
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
    $resp  = Invoke-PimWorkloadApi -Connector $Connector -Op $la -Tokens $Tokens
    $items = if ($la.itemsPath) { @(Get-PimNestedProp $resp $la.itemsPath) } else { @($resp) }
    $out = New-Object System.Collections.ArrayList
    foreach ($it in @($items)) {
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
        as the per-instance workload-crawl-map cache. Called by the scheduler /
        discovery sweep -- NOT on the GUI read path. Each connector is best-effort:
        a 403/throw is recorded as { ok=false; error } and never aborts the sweep.
    .OUTPUTS
        The path written (or $null if no cache dir).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConnectorsDir,
        [string]$CacheDir,
        [hashtable]$Tokens = @{}
    )
    $path = Get-PimWorkloadCrawlMapPath -CacheDir $CacheDir
    if (-not $path) { return $null }
    $connectors = @()
    if (Get-Command Read-PimWorkloadConnectors -ErrorAction SilentlyContinue) {
        $connectors = @(Read-PimWorkloadConnectors -ConnectorsDir $ConnectorsDir)
    }
    $wl = [ordered]@{}
    foreach ($c in $connectors) {
        $id = "$($c.id)".Trim()
        if (-not $id) { continue }
        try {
            $roleMap = @{}
            try {
                foreach ($r in @(Get-PimWorkloadRoles -Connector $c -Tokens $Tokens)) {
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
    $json = $body | ConvertTo-Json -Depth 12
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $tmp = "$path.tmp"
    [System.IO.File]::WriteAllText($tmp, $json, $utf8)
    Move-Item -LiteralPath $tmp -Destination $path -Force
    return $path
}

# ---------------------------------------------------------------------------
# Read (GUI path) -- crawl map + exemptions
# ---------------------------------------------------------------------------

function Read-PimWorkloadCrawlMap {
    <#
      Read + parse the crawl-map cache. Absent / parse error -> $null (GUI then
      simply shows no recon badges). Never throws.
    #>
    [CmdletBinding()]
    param([string]$CacheDir)
    $path = Get-PimWorkloadCrawlMapPath -CacheDir $CacheDir
    if (-not $path -or -not (Test-Path -LiteralPath $path)) { return $null }
    try {
        $raw = [System.IO.File]::ReadAllText($path, [System.Text.UTF8Encoding]::new($false))
        if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
        return ($raw | ConvertFrom-Json)
    } catch { return $null }
}

function Read-PimWorkloadExemptions {
    <#
      Read + normalize the workload-exemption store. Mirrors the
      PIM-WarningOverrides contract: reason MANDATORY; expiresOn MANDATORY unless
      noExpiry:true; an expired entry does NOT exempt (the binding resurfaces as
      missing). Returns an array of normalized hashtables (never throws).
    #>
    [CmdletBinding()]
    param([string]$ConfigRoot, [string]$Path, [object]$Config)
    $raw = $null
    if ($Config) { $raw = $Config }
    else {
        if (-not $Path -and $ConfigRoot) { $Path = Join-Path $ConfigRoot 'PIM-WorkloadExemptions.custom.json' }
        if ($Path -and (Test-Path -LiteralPath $Path)) {
            try {
                $text = [System.IO.File]::ReadAllText($Path, [System.Text.UTF8Encoding]::new($false))
                if ($text.Length -gt 0 -and [int][char]$text[0] -eq 0xFEFF) { $text = $text.Substring(1) }
                $raw = $text | ConvertFrom-Json
            } catch { return @() }
        }
    }
    if (-not $raw) { return @() }

    function _wexField([object]$obj, [string]$name) {
        if ($null -eq $obj) { return $null }
        if ($obj -is [System.Collections.IDictionary]) { if ($obj.Contains($name)) { return $obj[$name] }; return $null }
        $p = $obj.PSObject.Properties[$name]; if ($p) { return $p.Value }; return $null
    }
    $list = _wexField $raw 'exemptions'
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
    $exp = [datetime]::MinValue
    if (-not [datetime]::TryParse($Exemption.expiresOn, [ref]$exp)) { return $false }
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
