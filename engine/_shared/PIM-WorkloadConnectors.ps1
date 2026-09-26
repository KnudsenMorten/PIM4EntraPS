#Requires -Version 5.1
<#
  PIM4EntraPS v2 -- WORKLOAD CONNECTOR RUNTIME (REST, no modules).

  WHY THIS FILE EXISTS
    v1 applied PIM-Assignments-Workloads with Apply-PimWorkloadAssignments (PIM-Functions.psm1
    ~L2825-3004): one generic, data-driven applier that dispatched every row by its Workload
    column to a declarative connector (workloads/connectors/<id>.connector.json), for BOTH the
    flat model (list roles + list assignments + POST/DELETE) and the nested-membership model
    (resolve the group's container, then attach/detach the role on it). The v1 CSV engine ran it
    whenever the CSV existed (PIM-Baseline-Management-CSV.ps1 L1426-1436).

    v2 never ported it. The v2 engine is REST-only (Invoke-PimRest, app-only certificate / MI
    token for any audience) and does not load PIM-Functions.psm1, whose applier also depended on
    Get-AzAccessToken / Get-MgGroup. Migration imports PIM-Assignments-Workloads into pim.Rows and
    NOTHING read it -- every migrated workload row was silently never applied.

    This file is that applier's v2 runtime: the same connector definitions, the same token
    expansion, the same role / assignment / container resolution, through Invoke-PimRest. The
    engine provider that drives it is New-PimWorkloadConnectorsProvider (PIM-EngineProviders.ps1).

  WHAT IS READ FROM DISK, AND WHY IT IS NOT A SETTINGS FILE
    workloads/connectors/*.connector.json are PRODUCT CODE shipped in the image (API descriptors:
    paths, token names, body templates) -- the same class of artefact as a .ps1. They carry no
    customer state and no configuration. Customer data (the rows) and customer decisions
    (exemptions, crawl results) are SQL only. Tests inject definitions through
    $global:PIM_WorkloadConnectorDefinitions.

  PS 5.1 compatible; pure ASCII.
#>
Set-StrictMode -Off

# The v1 connector auth adapters -> the token AUDIENCE Invoke-PimRest mints for. v1
# (Get-PimWorkloadToken, PIM-Functions.psm1 ~L2687-2707) used the same resources with
# Get-AzAccessToken; v2 mints them with the engine identity instead. A FUNCTION, not a $script:
# table: $script: in a dot-sourced function binds to the CALLER's script scope (see PIM-Rest.ps1).
function Get-PimWorkloadConnectorAudienceMap {
    @{
        graph           = 'graph'
        arm             = 'arm'
        powerbi         = 'powerbi'
        devops          = '499b84ac-1321-427f-aa17-267ca6975798'
        businesscentral = 'https://api.businesscentral.dynamics.com'
        powerplatform   = 'https://service.powerapps.com'
    }
}

function Get-PimWorkloadConnectorProp {
    # Read a possibly-dotted property path ('properties.roleName') off an object or dictionary.
    param([object]$Object, [string]$Path)
    if (-not $Path) { return $null }
    $cur = $Object
    foreach ($seg in ($Path -split '\.')) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) { if ($cur.Contains($seg)) { $cur = $cur[$seg] } else { return $null } }
        else { $p = $cur.PSObject.Properties[$seg]; if ($p) { $cur = $p.Value } else { return $null } }
    }
    return $cur
}

function Expand-PimWorkloadConnectorTokens {
    # PURE. {token} / {token|default} -> value from $Tokens (v1 Expand-PimWorkloadTokens semantics).
    param([AllowEmptyString()][string]$Text, [hashtable]$Tokens = @{})
    if ($null -eq $Text) { return '' }
    return ([regex]::Replace($Text, '\{([A-Za-z][A-Za-z0-9]*)(\|([^}]*))?\}', {
        param($m)
        $k = $m.Groups[1].Value
        if ($Tokens.ContainsKey($k) -and $null -ne $Tokens[$k] -and "$($Tokens[$k])" -ne '') { return "$($Tokens[$k])" }
        if ($m.Groups[2].Success) { return $m.Groups[3].Value }
        return ''
    }))
}

function Get-PimWorkloadConnectorDirectory {
    if ("$($global:PIM_WorkloadConnectorsDir)".Trim()) { return "$($global:PIM_WorkloadConnectorsDir)".Trim() }
    # $PSScriptRoot inside a function = the directory of the file that DEFINES it (engine/_shared).
    $solutionRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    return (Join-Path (Join-Path $solutionRoot 'workloads') 'connectors')
}

function Get-PimWorkloadConnectorCatalog {
    <#
      id (lower-case) -> connector definition. Injected definitions win (tests); otherwise the
      shipped descriptors. A descriptor that does not parse is reported and skipped -- a row that
      references it then fails as an UNKNOWN connector, which is visible, rather than silently.
    #>
    param([string]$Directory)
    $defs = @()
    if ($null -ne $global:PIM_WorkloadConnectorDefinitions) {
        $defs = @($global:PIM_WorkloadConnectorDefinitions)
    } else {
        $dir = if ("$Directory".Trim()) { "$Directory".Trim() } else { Get-PimWorkloadConnectorDirectory }
        $list = New-Object System.Collections.ArrayList
        if ($dir -and (Test-Path -LiteralPath $dir)) {
            foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.connector.json' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
                try {
                    $raw = [System.IO.File]::ReadAllText($f.FullName, (New-Object System.Text.UTF8Encoding($false)))
                    if ($raw.Length -gt 0 -and [int][char]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
                    [void]$list.Add(($raw | ConvertFrom-Json))
                } catch {
                    Write-Warning ("  [workloads] connector definition {0} could not be parsed: {1}" -f $f.Name, $_.Exception.Message)
                }
            }
        }
        $defs = $list.ToArray()
    }
    $h = @{}
    foreach ($c in @($defs)) {
        if ($null -eq $c) { continue }
        $id = "$($c.id)".Trim().ToLowerInvariant()
        if ($id) { $h[$id] = $c }
    }
    return $h
}

function Get-PimWorkloadConnectorAudience {
    # The token audience for a connector's auth adapter. Throws on an adapter this engine cannot
    # mint for, so a new connector type fails loudly instead of calling an API with no token.
    param([Parameter(Mandatory)][object]$Connector, [hashtable]$Tokens = @{})
    $auth = "$($Connector.auth)".Trim().ToLowerInvariant()
    $map = Get-PimWorkloadConnectorAudienceMap
    if ($map.ContainsKey($auth)) { return $map[$auth] }
    if ($auth -eq 'dataverse') {
        # Per-environment audience = the org host. v1 expected a launcher-minted token here.
        if ("$($Connector.tokenResource)".Trim()) { return (Expand-PimWorkloadConnectorTokens -Text "$($Connector.tokenResource)" -Tokens $Tokens) }
        $base = Expand-PimWorkloadConnectorTokens -Text "$($Connector.api.baseUrl)" -Tokens $Tokens
        if ($base -match '^(https://[^/{}]+)') { return $Matches[1] }
        throw ("WORKLOAD-RESOURCE-MISSING: connector '{0}' needs the Dataverse org host in the row's Resource column to request a token." -f $Connector.id)
    }
    throw ("WORKLOAD-CONNECTOR-AUTH: connector '{0}' uses auth adapter '{1}', which this engine has no token audience for." -f $Connector.id, $auth)
}

function Invoke-PimWorkloadConnectorApi {
    <#
      Execute one connector API descriptor through the engine's REST client. A GET whose items
      live under 'value' is PAGED (@odata.nextLink / nextLink) and returned as @{ value = @(...) }
      so itemsPath still applies -- v1 read only the first page.
    #>
    param(
        [Parameter(Mandatory)][object]$Connector,
        [object]$Op,
        [hashtable]$Tokens = @{},
        [object]$Body = $null
    )
    if (-not $Op) { throw ("connector '{0}' does not define the API operation this step needs." -f $Connector.id) }
    $uri = (Expand-PimWorkloadConnectorTokens -Text "$($Connector.api.baseUrl)" -Tokens $Tokens) + (Expand-PimWorkloadConnectorTokens -Text "$($Op.path)" -Tokens $Tokens)
    $method = if ("$($Op.method)".Trim()) { "$($Op.method)".Trim().ToUpperInvariant() } else { 'GET' }
    $aud = Get-PimWorkloadConnectorAudience -Connector $Connector -Tokens $Tokens
    if (-not (Get-Command Invoke-PimRest -ErrorAction SilentlyContinue)) {
        throw ("connector '{0}' cannot run: the REST client (Invoke-PimRest, PIM-Rest.ps1) is not loaded in this process." -f $Connector.id)
    }
    if ($method -eq 'GET' -and "$($Op.itemsPath)" -eq 'value') {
        $items = @(Invoke-PimRest -Method 'GET' -Url $uri -Resource $aud -All)
        return [pscustomobject]@{ value = $items }
    }
    if ($null -ne $Body) { return (Invoke-PimRest -Method $method -Url $uri -Resource $aud -Body $Body) }
    return (Invoke-PimRest -Method $method -Url $uri -Resource $aud)
}

function New-PimWorkloadConnectorBody {
    # PURE. A connector body template with its {tokens} expanded. Values are JSON-escaped before
    # substitution, so a role name carrying a quote cannot break the document.
    param([object]$Template, [hashtable]$Tokens = @{})
    if ($null -eq $Template) { return $null }
    $esc = @{}
    foreach ($k in @($Tokens.Keys)) {
        $j = ConvertTo-Json -InputObject ("$($Tokens[$k])") -Compress
        $esc[$k] = $j.Substring(1, $j.Length - 2)
    }
    $json = ConvertTo-Json -InputObject $Template -Depth 10 -Compress
    $json = Expand-PimWorkloadConnectorTokens -Text $json -Tokens $esc
    return ($json | ConvertFrom-Json)
}

function Get-PimWorkloadConnectorItems {
    param([object]$Response, [object]$Op)
    if ($Op -and "$($Op.itemsPath)".Trim()) { return @(Get-PimWorkloadConnectorProp -Object $Response -Path "$($Op.itemsPath)") }
    return @($Response)
}

function Get-PimWorkloadConnectorRoles {
    # Live role definitions: @( @{ id; name; description } ). Static roles[] when there is no API.
    param([Parameter(Mandatory)][object]$Connector, [hashtable]$Tokens = @{})
    $op = $Connector.api.listRoles
    $out = New-Object System.Collections.ArrayList
    if (-not $op) {
        foreach ($r in @($Connector.roles)) {
            if ($null -eq $r) { continue }
            [void]$out.Add(@{ id = "$($r.id)"; name = "$($r.name)"; description = "$($r.description)" })
        }
        return $out.ToArray()
    }
    $resp = Invoke-PimWorkloadConnectorApi -Connector $Connector -Op $op -Tokens $Tokens
    foreach ($r in @(Get-PimWorkloadConnectorItems -Response $resp -Op $op)) {
        if ($null -eq $r) { continue }
        [void]$out.Add(@{
            id          = "$(Get-PimWorkloadConnectorProp -Object $r -Path "$($op.roleId)")"
            name        = "$(Get-PimWorkloadConnectorProp -Object $r -Path "$($op.roleName)")"
            description = $(if ($op.roleDescription) { "$(Get-PimWorkloadConnectorProp -Object $r -Path "$($op.roleDescription)")" } else { '' })
        })
    }
    return $out.ToArray()
}

function Get-PimWorkloadConnectorAssignments {
    <#
      FLAT model current state: the assignment objects for one role, each normalised to
      @{ id; principals = string[]; displayName }. v1 L2940-2956: list, keep items whose roleId
      contains the role id (when the descriptor names one), and fetch the detail record when the
      list shape omits the members (Intune).
    #>
    param([Parameter(Mandatory)][object]$Connector, [hashtable]$Tokens = @{}, [string]$RoleId)
    $la = $Connector.api.listAssignments
    if (-not $la) { throw ("connector '{0}' has no listAssignments operation." -f $Connector.id) }
    $resp = Invoke-PimWorkloadConnectorApi -Connector $Connector -Op $la -Tokens $Tokens
    $items = @(Get-PimWorkloadConnectorItems -Response $resp -Op $la)
    if ($la.roleId -and "$RoleId".Trim()) {
        $items = @($items | Where-Object { "$(Get-PimWorkloadConnectorProp -Object $_ -Path "$($la.roleId)")" -match [regex]::Escape("$RoleId") })
    }
    $out = New-Object System.Collections.ArrayList
    foreach ($it in $items) {
        if ($null -eq $it) { continue }
        $id = "$(Get-PimWorkloadConnectorProp -Object $it -Path "$($la.assignmentId)")"
        $principals = @()
        $pv = $null
        if ($la.principalIds) { $pv = Get-PimWorkloadConnectorProp -Object $it -Path "$($la.principalIds)" }
        if ($null -ne $pv) {
            $principals = @(@($pv) | ForEach-Object { "$_" })
        } elseif ($Connector.api.getAssignment) {
            $ga = $Connector.api.getAssignment
            $t2 = @{} + $Tokens; $t2['assignmentId'] = $id
            $detail = Invoke-PimWorkloadConnectorApi -Connector $Connector -Op $ga -Tokens $t2
            $dv = $null
            if ($ga.principalIds) { $dv = Get-PimWorkloadConnectorProp -Object $detail -Path "$($ga.principalIds)" }
            if ($null -ne $dv) { $principals = @(@($dv) | ForEach-Object { "$_" }) }
        }
        [void]$out.Add(@{ id = $id; principals = @($principals); displayName = "$(Get-PimWorkloadConnectorProp -Object $it -Path 'displayName')"; roleId = $(if ($la.roleId) { "$(Get-PimWorkloadConnectorProp -Object $it -Path "$($la.roleId)")" } else { '' }) })
    }
    return $out.ToArray()
}

function Select-PimWorkloadConnectorContainerItem {
    # PURE (v1 Select-PimWorkloadContainerItem): client-side match when the descriptor names one.
    param([Parameter(Mandatory)][object]$Op, [object[]]$Items = @(), [hashtable]$Tokens = @{})
    $items = @($Items | Where-Object { $null -ne $_ })
    if ($Op.matchField) {
        $want = if ($Op.matchToken -and $Tokens.ContainsKey("$($Op.matchToken)")) { "$($Tokens["$($Op.matchToken)"])" } else { '' }
        $items = @($items | Where-Object { "$(Get-PimWorkloadConnectorProp -Object $_ -Path "$($Op.matchField)")" -ieq $want })
    }
    return (@($items) | Select-Object -First 1)
}

function Get-PimWorkloadConnectorContainerId {
    # NESTED-MEMBERSHIP model: the group's container id (team / security group / subject), or $null.
    param([Parameter(Mandatory)][object]$Connector, [Parameter(Mandatory)][hashtable]$Tokens)
    $op = $Connector.api.resolveContainer
    if (-not $op) { return $null }
    $resp = Invoke-PimWorkloadConnectorApi -Connector $Connector -Op $op -Tokens $Tokens
    $first = Select-PimWorkloadConnectorContainerItem -Op $op -Items @(Get-PimWorkloadConnectorItems -Response $resp -Op $op) -Tokens $Tokens
    if (-not $first) { return $null }
    $idf = if ($op.idField) { "$($op.idField)" } else { 'id' }
    $id = "$(Get-PimWorkloadConnectorProp -Object $first -Path $idf)"
    if ([string]::IsNullOrWhiteSpace($id)) { return $null }
    return $id
}

function Get-PimWorkloadConnectorContainerRoleIds {
    # NESTED-MEMBERSHIP model: role ids already attached to the container (lower-case set).
    param([Parameter(Mandatory)][object]$Connector, [Parameter(Mandatory)][hashtable]$Tokens)
    $lc = $Connector.api.listContainerRoles
    if (-not $lc) { throw ("connector '{0}' has no listContainerRoles operation." -f $Connector.id) }
    $resp = Invoke-PimWorkloadConnectorApi -Connector $Connector -Op $lc -Tokens $Tokens
    $set = @{}
    foreach ($ci in @(Get-PimWorkloadConnectorItems -Response $resp -Op $lc)) {
        if ($null -eq $ci) { continue }
        $v = "$(Get-PimWorkloadConnectorProp -Object $ci -Path "$($lc.roleId)")".ToLowerInvariant()
        if ($v) { $set[$v] = $true }
    }
    return $set
}

# ---------------------------------------------------------------------------
# Row model
# ---------------------------------------------------------------------------
function Get-PimWorkloadRowField {
    param([object]$Row, [string[]]$Names)
    foreach ($n in $Names) {
        if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { return "$($Row[$n])".Trim() } }
        elseif ($null -ne $Row) { $p = $Row.PSObject.Properties[$n]; if ($p) { return "$($p.Value)".Trim() } }
    }
    return ''
}

function ConvertTo-PimWorkloadRow {
    # PURE. A PIM-Assignments-Workloads row -> the normalised binding row, or $null when it lacks
    # the three columns v1 required (Workload, RoleName, GroupTag -- v1 L2845).
    param([object]$Row)
    $wl  = Get-PimWorkloadRowField -Row $Row -Names @('Workload')
    $rn  = Get-PimWorkloadRowField -Row $Row -Names @('RoleName')
    $gt  = Get-PimWorkloadRowField -Row $Row -Names @('GroupTag')
    if (-not $wl -or -not $rn -or -not $gt) { return $null }
    $act = Get-PimWorkloadRowField -Row $Row -Names @('Action')
    if (-not $act) { $act = 'Assign' }
    return [pscustomobject]@{
        Workload = $wl
        RoleName = $rn
        GroupTag = $gt
        Resource = (Get-PimWorkloadRowField -Row $Row -Names @('Resource'))
        Scope    = (Get-PimWorkloadRowField -Row $Row -Names @('Scope'))
        Company  = (Get-PimWorkloadRowField -Row $Row -Names @('Company'))
        Action   = $act
        Notes    = (Get-PimWorkloadRowField -Row $Row -Names @('Notes'))
    }
}

function Get-PimWorkloadConnectorKey {
    # PURE. One binding = workload + group + resource + scope + role (case-insensitive).
    param([object]$Row)
    $parts = @(
        (Get-PimWorkloadRowField -Row $Row -Names @('Workload')),
        (Get-PimWorkloadRowField -Row $Row -Names @('GroupTag')),
        (Get-PimWorkloadRowField -Row $Row -Names @('Resource')),
        (Get-PimWorkloadRowField -Row $Row -Names @('Scope')),
        (Get-PimWorkloadRowField -Row $Row -Names @('RoleName'))
    )
    return (($parts -join '|').ToLowerInvariant())
}

# ---------------------------------------------------------------------------
# REQ-U (2026-09-19) -- which definition Workloads have a WORKLOAD BINDING, and where it lives.
# Operator: "otherwise we will end with orphaned permission groups that are not connected with the actual
# workload". A definition row's Workload is free text ('Intune', 'Defender-XDR', 'PowerBI', ...); a binding row is
# a PIM-Assignments-Intune / -Defender row, or a PIM-Assignments-Workloads row whose Workload is a connector id
# ('intune', 'defender-xdr', 'powerbi', ...). Both spellings map to ONE kind here, so the Groups provider's gate
# warning and the validator's PIM-WL-004 pair them the same way. Workloads bound by other entities (Entra-ID ->
# PIM-Assignments-Roles-*, Azure-RBAC -> PIM-Assignments-Azure-Resources, Exchange, Sentinel) are not in scope: ''.
# ---------------------------------------------------------------------------
function ConvertTo-PimWorkloadBindingKind {
    # PURE. A Workload value -> 'intune' | 'defender' | a generic connector id | '' (no workload binding).
    param([AllowNull()][string]$Workload)
    $w = ("$Workload".Trim().ToLowerInvariant()) -replace '[^a-z0-9]', ''
    if (-not $w) { return '' }
    if ($w -in @('intune', 'microsoftintune', 'endpointmanager', 'mem', 'intunerbac')) { return 'intune' }
    if ($w -in @('defender', 'defenderxdr', 'microsoftdefender', 'microsoftdefenderxdr', 'm365defender', 'microsoft365defender', 'mde', 'defenderforendpoint')) { return 'defender' }
    switch ($w) {
        'powerbi'         { return 'powerbi' }
        'azuredevops'     { return 'azure-devops' }
        'azdevops'        { return 'azure-devops' }
        'dataverse'       { return 'dataverse' }
        'businesscentral' { return 'business-central' }
        'powerplatform'   { return 'power-platform' }
        'entraapprole'    { return 'entra-approle' }
    }
    return ''
}

function Get-PimWorkloadBindingEntities {
    # PURE. The entities that can hold a binding row for a kind (ConvertTo-PimWorkloadBindingKind).
    param([AllowNull()][string]$Kind)
    switch ("$Kind") {
        ''         { return @() }
        'intune'   { return @('PIM-Assignments-Intune', 'PIM-Assignments-Workloads') }
        'defender' { return @('PIM-Assignments-Defender', 'PIM-Assignments-Workloads') }
        default    { return @('PIM-Assignments-Workloads') }
    }
}

function Get-PimWorkloadGateWarnings {
    <#
      REQ-U. PURE over its inputs. Definition rows ({ GroupName; GroupTag; Workload }) whose Workload has a binding
      provider -> one warning line per group whose workload ROLE is not assigned by this run, naming every reason:
        * the binding provider is GATED OFF (-BindingAvailable $false, -Reason);
        * REQ-W: NO binding row names the group (-BoundTagsByKind: kind -> tag(lower) -> $true; a kind absent from the
          map is not judged);
        * REQ-W: the kind's workload prerequisites are not green (-PrereqHeldByKind: kind -> the held gate, or $null).
      REQ-W (operator 2026-09-19: "it should be possible to deploy groups"): the group is CREATED (or kept) either
      way -- the REQ-U wave-2 create hold is gone. Without this line the group would exist with no workload role and
      nobody told; the orphan / coverage warnings show the same gap from the live side.
    #>
    param([object[]]$Rows = @(), [bool]$BindingAvailable = $true, [string]$Reason = '', [hashtable]$BoundTagsByKind = @{}, [hashtable]$PrereqHeldByKind = @{})
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $kind = ConvertTo-PimWorkloadBindingKind -Workload "$(Get-PimWorkloadRowField -Row $r -Names @('Workload'))"
        if (-not $kind) { continue }
        $gn = Get-PimWorkloadRowField -Row $r -Names @('GroupName')
        $gt = Get-PimWorkloadRowField -Row $r -Names @('GroupTag')
        $ents = (Get-PimWorkloadBindingEntities -Kind $kind) -join ' / '
        $why = New-Object System.Collections.Generic.List[string]
        if (-not $BindingAvailable) { $why.Add($(if ("$Reason".Trim()) { "$Reason" } else { 'the workload connectors are gated off' })) }
        if ($BoundTagsByKind -and $BoundTagsByKind.ContainsKey($kind) -and $BoundTagsByKind[$kind] -is [hashtable] -and -not ($gt -and $BoundTagsByKind[$kind].ContainsKey($gt.ToLowerInvariant()))) {
            $why.Add("no binding row names it ($ents)")
        }
        $hg = if ($PrereqHeldByKind -and $PrereqHeldByKind.ContainsKey($kind)) { $PrereqHeldByKind[$kind] } else { $null }
        if ($hg -and $hg.held) { $why.Add(("the {0} prerequisites are not green ({1}) -- run Initialize-PimWorkloadPrereqs.ps1 -Workload {0}" -f $hg.workload, $hg.state)) }
        if (-not $why.Count) { continue }
        $out.Add(("group '{0}' (tag '{1}', workload {2}) is created (an existing one is kept); its {2} role is NOT assigned by this run: {3}. It is assigned on the first run where its binding ({4}) can be applied." -f $gn, $gt, $kind, ($why.ToArray() -join '; '), $ents))
    }
    return @($out.ToArray())
}

function Resolve-PimWorkloadGroupId {
    <#
      GroupTag -> live Entra group id, by EXACT name only, in this order:
        1. the GroupName the tag's DEFINITION ROW names ($TagToName, from the definition entities);
        2. the tag itself as a name (v1 L2863 -- a v1 tag was often the full group name);
        3. the tag under the TENANT's naming pattern (Resolve-PimGroupNameFromTag, PimGroupPattern).
      REQ-U (2026-09-19). Step 3 used to be a hard-coded 'PIM-' + tag, and after the exact names came v1's
      last resort: the first cached group whose display name CONTAINED the tag (v1 L2859-2861). That bound the
      WRONG group whenever another name merely included the tag ('Intune-Reader' inside
      'PIM-Intune-Reader-Legacy') -- a workload role granted to a group nobody asked for. "Is this ours" is
      decided by the definition row / the tag, never by a substring or a generic prefix.
    #>
    param([string]$Tag, [hashtable]$TagToName = @{})
    $t = "$Tag".Trim()
    if (-not $t) { return $null }
    $names = New-Object System.Collections.Generic.List[string]
    if ($TagToName -and $TagToName.ContainsKey($t.ToLowerInvariant()) -and "$($TagToName[$t.ToLowerInvariant()])".Trim()) { $names.Add("$($TagToName[$t.ToLowerInvariant()])".Trim()) }
    if (-not $names.Contains($t)) { $names.Add($t) }
    # 2026-09-21: the pattern now fills its tokens, so a group named under the OLD rule (tokens deleted) carries a
    # different name than the pattern gives today -- try both (Get-PimGroupNameCandidatesFromTag), current first.
    if (Get-Command Get-PimGroupNameCandidatesFromTag -ErrorAction SilentlyContinue) {
        foreach ($byPattern in @(Get-PimGroupNameCandidatesFromTag -Tag $t)) { if ($byPattern -and -not $names.Contains($byPattern)) { $names.Add($byPattern) } }
    } elseif (Get-Command Resolve-PimGroupNameFromTag -ErrorAction SilentlyContinue) {
        $byPattern = "$(Resolve-PimGroupNameFromTag -Tag $t)".Trim()
        if ($byPattern -and -not $names.Contains($byPattern)) { $names.Add($byPattern) }
    }
    if (Get-Command Resolve-PimLiveGroupIdByName -ErrorAction SilentlyContinue) {
        foreach ($n in $names) { $gid = Resolve-PimLiveGroupIdByName $n; if ($gid) { return "$gid" } }
    } else {
        foreach ($n in $names) {
            $g = @($Global:Groups_All_ID) | Where-Object { $null -ne $_ -and "$($_.DisplayName)" -ieq $n } | Select-Object -First 1
            if ($g) { return "$($g.Id)" }
        }
    }
    return $null
}

function Test-PimWorkloadCreatedByTool {
    # v1 L2983-2988 refused to delete a FLAT assignment it had not created (display name prefix
    # 'PIM4EntraPS:'). v2's own Defender/Intune providers name theirs 'PIM4EntraPS - <role>'.
    param([string]$DisplayName)
    $d = "$DisplayName"
    return ($d -like 'PIM4EntraPS:*' -or $d -like 'PIM4EntraPS - *')
}

function Resolve-PimWorkloadBinding {
    <#
      Resolve ONE normalised row against the live workload: connector, group, role, container and
      whether the binding is present. Never throws -- a problem is returned as .error, carrying a
      code the failure catalog classifies, so the engine turns it into a visible failure item
      instead of a skipped row. $Cache is a per-run hashtable (roles, assignment lists, groups).
    #>
    param(
        [Parameter(Mandatory)][object]$Row,
        [Parameter(Mandatory)][hashtable]$Connectors,
        [hashtable]$TagToName = @{},
        [hashtable]$Cache = @{}
    )
    foreach ($k in @('roles','assign','groups','containers')) { if (-not $Cache.ContainsKey($k)) { $Cache[$k] = @{} } }
    $b = [pscustomobject]@{
        key = (Get-PimWorkloadConnectorKey -Row $Row); row = $Row; action = "$($Row.Action)"; error = ''
        connector = $null; tokens = @{}; role = $null; groupId = ''; membership = $false
        container = ''; present = $false; existing = $null
    }
    $wid = "$($Row.Workload)".Trim().ToLowerInvariant()
    $conn = $Connectors[$wid]
    if (-not $conn) {
        $known = (@($Connectors.Keys) | Sort-Object) -join ', '
        $b.error = ("WORKLOAD-CONNECTOR-UNKNOWN: the row names workload '{0}', but no connector with that id exists (supported: {1})." -f $Row.Workload, $known)
        return $b
    }
    $b.connector = $conn
    $b.membership = [bool]$conn.membershipModel
    if ($b.action -notin @('Assign','Remove')) {
        $b.error = ("WORKLOAD-ACTION-UNKNOWN: Action '{0}' is not supported (expected Assign or Remove)." -f $Row.Action)
        return $b
    }
    if ($conn.perRowResource -and -not "$($Row.Resource)".Trim()) {
        $b.error = ("WORKLOAD-RESOURCE-MISSING: connector '{0}' needs a per-row Resource (see the connector's prerequisites), but the row has none." -f $wid)
        return $b
    }
    $tagKey = "$($Row.GroupTag)".ToLowerInvariant()
    if ($Cache.groups.ContainsKey($tagKey)) { $gid = $Cache.groups[$tagKey] }
    else { $gid = Resolve-PimWorkloadGroupId -Tag $Row.GroupTag -TagToName $TagToName; $Cache.groups[$tagKey] = $gid }
    if (-not $gid) {
        $b.error = ("WORKLOAD-GROUP-UNRESOLVED: GroupTag '{0}' could not be resolved to an Entra group." -f $Row.GroupTag)
        return $b
    }
    $b.groupId = "$gid"
    $tokens = @{ groupId = "$gid"; groupTag = "$($Row.GroupTag)"; resource = "$($Row.Resource)"; scope = "$($Row.Scope)"; company = "$($Row.Company)" }

    $rk = "$wid|$($Row.Resource)|$($Row.Scope)|$($Row.Company)".ToLowerInvariant()
    if (-not $Cache.roles.ContainsKey($rk)) {
        try { $Cache.roles[$rk] = @{ ok = $true; roles = @(Get-PimWorkloadConnectorRoles -Connector $conn -Tokens $tokens) } }
        catch { $Cache.roles[$rk] = @{ ok = $false; error = "$($_.Exception.Message)" } }
    }
    $rc = $Cache.roles[$rk]
    if (-not $rc.ok) {
        $b.error = ("workload '{0}' role listing failed: {1}" -f $wid, $rc.error)
        return $b
    }
    $role = @($rc.roles | Where-Object { "$($_.name)" -ieq "$($Row.RoleName)".Trim() }) | Select-Object -First 1
    if (-not $role) {
        $valid = @($rc.roles | ForEach-Object { "$($_.name)" } | Select-Object -First 25) -join ', '
        $b.error = ("WORKLOAD-ROLE-NOT-FOUND: workload '{0}' has no role named '{1}'{2}. Valid: {3}" -f $wid, $Row.RoleName, $(if ("$($Row.Resource)".Trim()) { " on resource '$($Row.Resource)'" } else { '' }), $valid)
        return $b
    }
    $b.role = $role
    $tokens['roleId'] = "$($role.id)"; $tokens['roleName'] = "$($role.name)"

    if ($b.membership) {
        try {
            $ck = "$wid|$($Row.Resource)|$($Row.Company)|$gid".ToLowerInvariant()
            if ($Cache.containers.ContainsKey($ck)) { $container = $Cache.containers[$ck] }
            else { $container = Get-PimWorkloadConnectorContainerId -Connector $conn -Tokens $tokens; $Cache.containers[$ck] = $container }
        } catch {
            $b.error = ("workload '{0}' could not resolve the container for '{1}': {2}" -f $wid, $Row.GroupTag, $_.Exception.Message)
            return $b
        }
        if (-not $container) {
            $kind = if ("$($conn.containerKind)".Trim()) { "$($conn.containerKind)" } else { 'membership container' }
            $b.error = ("WORKLOAD-CONTAINER-MISSING: {0}: group '{1}' has no {2} yet -- provision it in the workload first." -f $conn.name, $Row.GroupTag, $kind)
            return $b
        }
        $b.container = "$container"; $tokens['container'] = "$container"
        try { $present = Get-PimWorkloadConnectorContainerRoleIds -Connector $conn -Tokens $tokens }
        catch {
            $b.error = ("workload '{0}' could not list the roles on the container of '{1}': {2}" -f $wid, $Row.GroupTag, $_.Exception.Message)
            return $b
        }
        $b.present = $present.ContainsKey("$($role.id)".ToLowerInvariant())
    } else {
        $ak = ("$wid|$($Row.Resource)|$($Row.Scope)|$($Row.Company)|" + (Expand-PimWorkloadConnectorTokens -Text "$($conn.api.listAssignments.path)" -Tokens $tokens) + "|$($role.id)").ToLowerInvariant()
        if (-not $Cache.assign.ContainsKey($ak)) {
            try { $Cache.assign[$ak] = @{ ok = $true; items = @(Get-PimWorkloadConnectorAssignments -Connector $conn -Tokens $tokens -RoleId "$($role.id)") } }
            catch { $Cache.assign[$ak] = @{ ok = $false; error = "$($_.Exception.Message)" } }
        }
        $ac = $Cache.assign[$ak]
        if (-not $ac.ok) {
            $b.error = ("workload '{0}' assignment listing failed: {1}" -f $wid, $ac.error)
            return $b
        }
        foreach ($it in @($ac.items)) {
            if (@($it.principals) -contains "$gid") { $b.existing = $it; break }
        }
        $b.present = ($null -ne $b.existing)
    }
    $b.tokens = $tokens
    return $b
}

function Invoke-PimWorkloadBindingAssign {
    # Create the binding (v1 L2921-2926 membership, L2967-2976 flat).
    param([Parameter(Mandatory)][object]$Binding)
    $conn = $Binding.connector
    $tokens = @{} + $Binding.tokens
    $tokens['newId'] = [guid]::NewGuid().ToString()
    $body = $null
    if ($conn.api.assign -and $null -ne $conn.api.assign.body) { $body = New-PimWorkloadConnectorBody -Template $conn.api.assign.body -Tokens $tokens }
    return (Invoke-PimWorkloadConnectorApi -Connector $conn -Op $conn.api.assign -Tokens $tokens -Body $body)
}

function Invoke-PimWorkloadBindingRemove {
    <#
      Remove the binding exactly as v1 did: a NESTED-MEMBERSHIP role is detached (v1 L2928-2934);
      a FLAT assignment is deleted only when this tool created it, otherwise it is REPORTED and left
      for a human (v1 L2983-2988). Returns the API response, or a pimApplied=$false report.
    #>
    param([Parameter(Mandatory)][object]$Binding)
    $conn = $Binding.connector
    $tokens = @{} + $Binding.tokens
    if (-not $Binding.membership) {
        $ex = $Binding.existing
        if (-not (Test-PimWorkloadCreatedByTool -DisplayName "$($ex.displayName)")) {
            $msg = ("{0} assignment '{1}' for '{2}' was not created by PIM4EntraPS -- remove it in the workload's portal (shared or manual assignments are never deleted)." -f $conn.name, $(if ("$($ex.displayName)".Trim()) { $ex.displayName } else { $ex.id }), $Binding.row.GroupTag)
            Write-Host ("    [workloads] {0}" -f $msg) -ForegroundColor Yellow
            return [pscustomobject]@{ pimApplied = $false; reason = $msg }
        }
        $tokens['assignmentId'] = "$($ex.id)"
    }
    # A removal that is itself a REQUEST (PIM: adminRemove / AdminRemove schedule requests) has a body and, for ARM,
    # a client-chosen request id -- the same shape as the assign.
    $tokens['newId'] = [guid]::NewGuid().ToString()
    if ($conn.api.remove -and $null -ne $conn.api.remove.body) {
        $body = New-PimWorkloadConnectorBody -Template $conn.api.remove.body -Tokens $tokens
        return (Invoke-PimWorkloadConnectorApi -Connector $conn -Op $conn.api.remove -Tokens $tokens -Body $body)
    }
    return (Invoke-PimWorkloadConnectorApi -Connector $conn -Op $conn.api.remove -Tokens $tokens)
}
