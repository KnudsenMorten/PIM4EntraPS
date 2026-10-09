#Requires -Version 5.1
<#
  PIM Manager -- CUSTOM WORKLOADS (REQUIREMENTS 100.17 CUSTOM-WORKLOAD).

  Owner 2026-10-09: "i want to make a custom workload permission group for SAP, but when i click resource delegation, i
  cannot choose to make custom. Iether I must be able to define workloads somewhere (preferred), where i can create the
  groups needed, so it comes here - o i must be able to create custom (quick) groups here. can i get both. think of this
  as a draft for a later template for SAP".

  WHAT A CUSTOM WORKLOAD IS. A catalog entry of kind 'group-only' beside the shipped connectors
  (workloads/connectors/*.connector.json). Access reaches the application through ENTRA GROUP MEMBERSHIP that the app
  consumes (its SSO claims, its SCIM provisioning or its own role mapping) -- PIM manages the permission groups, their
  nesting and their PIM-for-Groups eligibility + policy, exactly as for every other permission group, and NEVER calls
  the application. A delegation of a custom workload is the same unit as a connector delegation: a group DEFINITION row
  (PIM-Definitions-Tasks, Workload = the custom id) + a PIM-Assignments-Workloads binding row (Workload = the custom id,
  RoleName = one of the workload's roles). The engine's WorkloadConnectors dispatcher sees the custom id in its catalog
  as a group-only connector: the binding is satisfied when the group exists -- no token, no API call.

  STORE. pim.Settings['CustomWorkloads'] (SQL; PIM v2 has no files): { schema = 1; workloads = [ <definition> ] }.
  Written only by the Manager's audited routes (POST /api/custom-workloads, /delete, /import -- Admin and above), read by
  the engine through Get-PimWorkloadStoreValue / Get-PimSetting. Tests inject $global:PIM_CustomWorkloadDefinitions.

  DEFINITION (normalised by ConvertTo-PimCustomWorkloadDefinition):
    id                'custom-<slug>' -- the 'custom-' prefix keeps every custom id apart from the shipped connector ids
    name              display name ('SAP'); its name segment ('SAP') is the {Workload} part of group names
    description       free text
    accessModel       how the app consumes the group: group-membership | sso-claims | scim | app-role-mapping
    roles[]           { name; tier (0|1|2); description; defaultPolicyTemplate }
    scopeLevels[]     optional ('System', 'Client'); the VALUES are typed per delegation ('PRD', '100')
    groupNamePattern  optional; blank = the tenant's permission-group naming (the same as every built-in workload)
    notes             free text
    createdUtc/createdBy/updatedUtc/updatedBy

  PURE except Read-PimCustomWorkloads (one store read). PS 5.1; ASCII only.
#>
Set-StrictMode -Off

function Get-PimCustomWorkloadStoreName { 'CustomWorkloads' }
function Get-PimCustomWorkloadIdPrefix { 'custom-' }

function Get-PimCustomWorkloadAccessModels {
    # The ways an application consumes the Entra group. PIM does the same thing for every one of them (it manages the
    # group); the value documents the wiring for whoever maintains the app side.
    [ordered]@{
        'group-membership' = 'Entra group membership consumed by the application (generic)'
        'sso-claims'       = 'Group claim in the SSO token (SAML / OIDC) mapped to a role in the application'
        'scim'             = 'Group provisioned to the application by SCIM, mapped to a role there'
        'app-role-mapping' = 'The application maps the Entra group to its own role (role mapping in the app)'
    }
}

function Get-PimCustomWorkloadPatternTokens {
    # The naming-catalog tokens a custom workload's group-name pattern may use (Expand-PimGroupNamePattern fills them).
    @('Workload', 'Service', 'Scope', 'Permission', 'Role', 'Level', 'Tier', 'Plane', 'Domain', 'Platform', 'EnvironmentSuffix', 'TenantCommonName')
}

function Get-PimCwField {
    param([object]$Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { if ($Obj.Contains($Name)) { return $Obj[$Name] }; return $null }
    $p = $Obj.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function ConvertTo-PimCustomWorkloadSlug {
    # PURE. 'SAP S/4HANA' -> 'sap-s-4hana'. Lower-case letters, digits and single hyphens.
    param([AllowNull()][string]$Text)
    $s = ("$Text".Trim().ToLowerInvariant()) -replace '[^a-z0-9]+', '-'
    return $s.Trim('-')
}

function ConvertTo-PimCustomWorkloadId {
    # PURE. The id a NEW custom workload gets from its name: 'custom-' + slug.
    param([AllowNull()][string]$Name)
    $slug = ConvertTo-PimCustomWorkloadSlug -Text $Name
    if (-not $slug) { return '' }
    return ((Get-PimCustomWorkloadIdPrefix) + $slug)
}

function Test-PimCustomWorkloadId {
    # PURE. Is this Workload value a custom-workload id (by its shape)? Shipped connector ids never carry the prefix.
    param([AllowNull()][string]$Id)
    $i = "$Id".Trim().ToLowerInvariant()
    return ($i.Length -gt (Get-PimCustomWorkloadIdPrefix).Length -and $i.StartsWith((Get-PimCustomWorkloadIdPrefix)))
}

function ConvertTo-PimCustomWorkloadTier {
    # PURE. 0 / '0' / 'T0' / 't1' -> 0..2 ; anything else -> $null.
    param([AllowNull()][object]$Value)
    $s = "$Value".Trim()
    if ($s -match '^(?i)T?([0-2])$') { return [int]$Matches[1] }
    return $null
}

function ConvertTo-PimCustomWorkloadDefinition {
    <#
      PURE. Any input shape (a parsed JSON object, a hashtable, the GUI's body) -> the normalised [ordered] definition.
      Nothing is validated here (Test-PimCustomWorkloadDefinition does that); unknown fields are dropped. A blank id is
      derived from the name. Tier text ('T0') becomes a number; a tier that cannot be read stays as text so the
      validator can name it.
    #>
    param([AllowNull()][object]$InputObject)
    $g = { param($n) $v = Get-PimCwField -Obj $InputObject -Name $n; if ($null -eq $v) { '' } else { "$v".Trim() } }
    $name = & $g 'name'
    $id = (& $g 'id').ToLowerInvariant()
    if (-not $id) { $id = ConvertTo-PimCustomWorkloadId -Name $name }
    $roles = New-Object System.Collections.ArrayList
    foreach ($r in @(Get-PimCwField -Obj $InputObject -Name 'roles')) {
        if ($null -eq $r) { continue }
        if ($r -is [string]) { $r = @{ name = $r } }
        $rn = "$(Get-PimCwField -Obj $r -Name 'name')".Trim()
        $rtRaw = Get-PimCwField -Obj $r -Name 'tier'
        $rt = ConvertTo-PimCustomWorkloadTier -Value $rtRaw
        [void]$roles.Add([ordered]@{
            name = $rn
            tier = $(if ($null -ne $rt) { $rt } elseif ($null -eq $rtRaw -or "$rtRaw".Trim() -eq '') { 1 } else { "$rtRaw".Trim() })
            description = "$(Get-PimCwField -Obj $r -Name 'description')".Trim()
            defaultPolicyTemplate = "$(Get-PimCwField -Obj $r -Name 'defaultPolicyTemplate')".Trim()
        })
    }
    $levels = New-Object System.Collections.ArrayList
    $rawLevels = Get-PimCwField -Obj $InputObject -Name 'scopeLevels'
    if ($rawLevels -is [string]) { $rawLevels = @("$rawLevels" -split '[,;]') }
    foreach ($l in @($rawLevels)) { $t = "$l".Trim(); if ($t) { [void]$levels.Add($t) } }
    $am = (& $g 'accessModel').ToLowerInvariant()
    if (-not $am) { $am = 'group-membership' }
    return [ordered]@{
        id = $id
        name = $name
        description = (& $g 'description')
        accessModel = $am
        roles = @($roles.ToArray())
        scopeLevels = @($levels.ToArray())
        groupNamePattern = (& $g 'groupNamePattern')
        notes = (& $g 'notes')
        createdUtc = (& $g 'createdUtc'); createdBy = (& $g 'createdBy')
        updatedUtc = (& $g 'updatedUtc'); updatedBy = (& $g 'updatedBy')
    }
}

function Test-PimCustomWorkloadDefinition {
    <#
      PURE. A normalised definition -> the list of problems (empty = valid). Every message names the field, so the GUI
      can show it as it is.
    #>
    param([Parameter(Mandatory)][object]$Definition)
    $e = New-Object System.Collections.Generic.List[string]
    $d = $Definition
    $name = "$(Get-PimCwField -Obj $d -Name 'name')"
    $id = "$(Get-PimCwField -Obj $d -Name 'id')"
    if (-not $name.Trim()) { $e.Add('Name is required.') }
    elseif ($name.Length -gt 40) { $e.Add('Name is longer than 40 characters.') }
    elseif ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._/-]*$') { $e.Add("Name '$name' may use letters, digits, space, '.', '_', '-' and '/' and must start with a letter or digit.") }
    if (-not (Test-PimCustomWorkloadId -Id $id)) { $e.Add("Id '$id' must start with '$(Get-PimCustomWorkloadIdPrefix)' followed by letters, digits or '-'.") }
    elseif ($id -notmatch '^custom-[a-z0-9]+(-[a-z0-9]+)*$' -or $id.Length -gt 48) { $e.Add("Id '$id' may use lower-case letters, digits and single '-' (at most 48 characters).") }
    if ("$(Get-PimCwField -Obj $d -Name 'description')".Length -gt 500) { $e.Add('Description is longer than 500 characters.') }
    if ("$(Get-PimCwField -Obj $d -Name 'notes')".Length -gt 2000) { $e.Add('Notes are longer than 2000 characters.') }
    $am = "$(Get-PimCwField -Obj $d -Name 'accessModel')"
    if (-not (Get-PimCustomWorkloadAccessModels).Contains($am)) { $e.Add("Access model '$am' is not one of: " + (@((Get-PimCustomWorkloadAccessModels).Keys) -join ', ') + '.') }
    $roles = @(Get-PimCwField -Obj $d -Name 'roles') | Where-Object { $null -ne $_ }
    if (-not @($roles).Count) { $e.Add('At least one role is required (the roles are what a delegation grants).') }
    if (@($roles).Count -gt 100) { $e.Add('At most 100 roles per workload.') }
    $seen = @{}
    foreach ($r in @($roles)) {
        $rn = "$(Get-PimCwField -Obj $r -Name 'name')".Trim()
        if (-not $rn) { $e.Add('A role has no name.'); continue }
        if ($rn.Length -gt 64) { $e.Add("Role '$rn' is longer than 64 characters.") }
        if ($rn -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._/-]*$') { $e.Add("Role '$rn' may use letters, digits, space, '.', '_', '-' and '/' and must start with a letter or digit.") }
        $k = $rn.ToLowerInvariant()
        if ($seen.ContainsKey($k)) { $e.Add("Role '$rn' is listed twice.") } else { $seen[$k] = $true }
        $t = Get-PimCwField -Obj $r -Name 'tier'
        if ($null -eq (ConvertTo-PimCustomWorkloadTier -Value $t)) { $e.Add("Role '$rn' has tier '$t' -- use 0, 1 or 2.") }
        if ("$(Get-PimCwField -Obj $r -Name 'description')".Length -gt 400) { $e.Add("Role '$rn': description is longer than 400 characters.") }
        $pt = "$(Get-PimCwField -Obj $r -Name 'defaultPolicyTemplate')"
        if ($pt -and $pt -notmatch '^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$') { $e.Add("Role '$rn': default policy template '$pt' is not a template id.") }
    }
    $levels = @(Get-PimCwField -Obj $d -Name 'scopeLevels') | Where-Object { "$_".Trim() }
    if (@($levels).Count -gt 4) { $e.Add('At most 4 scope levels.') }
    $ls = @{}
    foreach ($l in @($levels)) {
        $t = "$l".Trim()
        if ($t.Length -gt 32 -or $t -notmatch '^[A-Za-z0-9][A-Za-z0-9 _-]*$') { $e.Add("Scope level '$t' may use letters, digits, space, '_' and '-' (at most 32 characters).") }
        if ($ls.ContainsKey($t.ToLowerInvariant())) { $e.Add("Scope level '$t' is listed twice.") } else { $ls[$t.ToLowerInvariant()] = $true }
    }
    $pat = "$(Get-PimCwField -Obj $d -Name 'groupNamePattern')".Trim()
    if ($pat) {
        if ($pat.Length -gt 200) { $e.Add('Group name pattern is longer than 200 characters.') }
        $known = @(Get-PimCustomWorkloadPatternTokens | ForEach-Object { $_.ToLowerInvariant() })
        foreach ($m in [regex]::Matches($pat, '\{([^}]*)\}')) {
            if ($known -notcontains $m.Groups[1].Value.ToLowerInvariant()) { $e.Add("Group name pattern: unknown token {$($m.Groups[1].Value)} (known: " + ((Get-PimCustomWorkloadPatternTokens | ForEach-Object { "{$_}" }) -join ' ') + ').') }
        }
        if ($pat -notmatch '(?i)\{(Permission|Role)\}') { $e.Add('Group name pattern must contain {Permission} or {Role}, or every role of the workload would get the same group name.') }
        if (($pat -replace '\{[^}]*\}', '') -notmatch '^[A-Za-z0-9 ._-]*$') { $e.Add("Group name pattern may use letters, digits, '.', '_', '-' and space outside its {tokens}.") }
    }
    return @($e.ToArray())
}

function ConvertTo-PimCustomWorkloadList {
    # PURE. The stored value (object, JSON string, a bare array) -> an array of normalised definitions. $null -> @().
    param([AllowNull()][object]$Value)
    $v = $Value
    for ($i = 0; $i -lt 2 -and $v -is [string]; $i++) { $s = "$v".Trim(); if (-not $s) { return @() }; try { $v = $s | ConvertFrom-Json } catch { return @() } }
    if ($null -eq $v) { return @() }
    $items = $null
    $w = Get-PimCwField -Obj $v -Name 'workloads'
    if ($null -ne $w) { $items = @($w) }
    elseif ($v -is [System.Array] -or ($v -is [System.Collections.IEnumerable] -and $v -isnot [System.Collections.IDictionary])) { $items = @($v) }
    else { $items = @() }
    $out = New-Object System.Collections.ArrayList
    foreach ($it in @($items)) { if ($null -ne $it) { [void]$out.Add((ConvertTo-PimCustomWorkloadDefinition -InputObject $it)) } }
    return @($out.ToArray())
}

function ConvertTo-PimCustomWorkloadStoreValue {
    # PURE. A list of definitions -> the document stored in pim.Settings['CustomWorkloads'].
    param([object[]]$List = @())
    return [ordered]@{ schema = 1; workloads = @(@($List) | Where-Object { $null -ne $_ } | Sort-Object { "$(Get-PimCwField -Obj $_ -Name 'name')" }) }
}

function Read-PimCustomWorkloads {
    <#
      The custom workloads of this environment. Injected definitions win ($global:PIM_CustomWorkloadDefinitions, tests);
      otherwise pim.Settings['CustomWorkloads'] through the engine / Manager store bridge. -Strict throws when the store
      cannot be read (a caller that must not mistake "unreadable" for "none" -- the Manager's routes); without it an
      unreadable store reads as none (the engine: a binding then fails visibly as an unknown workload).
    #>
    param([switch]$Strict)
    if ($null -ne $global:PIM_CustomWorkloadDefinitions) { return @(ConvertTo-PimCustomWorkloadList -Value ([ordered]@{ workloads = @($global:PIM_CustomWorkloadDefinitions) })) }
    $name = Get-PimCustomWorkloadStoreName
    $v = $null
    try {
        if (Get-Command Get-PimWorkloadStoreValue -ErrorAction SilentlyContinue) {
            if ($Strict -and (Get-Command Get-PimSetting -ErrorAction SilentlyContinue)) { $v = Get-PimSetting -Name $name }
            else { $v = Get-PimWorkloadStoreValue -Name $name }
        } elseif (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { $v = Get-PimSetting -Name $name }
    } catch {
        if ($Strict) { throw }
        $v = $null
    }
    return @(ConvertTo-PimCustomWorkloadList -Value $v)
}

function Find-PimCustomWorkload {
    # PURE. The definition with this id (case-insensitive), or $null.
    param([object[]]$List = @(), [AllowNull()][string]$Id)
    $i = "$Id".Trim().ToLowerInvariant()
    if (-not $i) { return $null }
    foreach ($d in @($List)) { if ("$(Get-PimCwField -Obj $d -Name 'id')".ToLowerInvariant() -eq $i) { return $d } }
    return $null
}

function Find-PimCustomWorkloadRole {
    # PURE. The role of a definition with this name (case-insensitive), or $null.
    param([object]$Definition, [AllowNull()][string]$RoleName)
    $n = "$RoleName".Trim().ToLowerInvariant()
    foreach ($r in @(Get-PimCwField -Obj $Definition -Name 'roles')) { if ("$(Get-PimCwField -Obj $r -Name 'name')".Trim().ToLowerInvariant() -eq $n) { return $r } }
    return $null
}

function Set-PimCustomWorkloadEntry {
    <#
      PURE. Create or update ONE definition in a list. -Mode create refuses an id that exists (409); update refuses an id
      that does not (404); an invalid definition is refused (400) with every problem named. Keeps createdUtc/createdBy on
      update. Returns @{ ok; code; error; errors; list; before; after; id }.
    #>
    param([object[]]$List = @(), [Parameter(Mandatory)][object]$Definition, [ValidateSet('create', 'update', 'upsert')][string]$Mode = 'create',
          [string]$By = '', [datetime]$NowUtc = ([datetime]::UtcNow))
    $d = ConvertTo-PimCustomWorkloadDefinition -InputObject $Definition
    $errs = @(Test-PimCustomWorkloadDefinition -Definition $d)
    $res = [ordered]@{ ok = $false; code = 400; error = ''; errors = $errs; list = @($List); before = $null; after = $null; id = "$($d.id)" }
    if ($errs.Count) { $res.error = ($errs -join ' '); return $res }
    $existing = Find-PimCustomWorkload -List $List -Id $d.id
    if ($Mode -eq 'create' -and $existing) { $res.code = 409; $res.error = "A custom workload with id '$($d.id)' already exists -- edit it instead, or choose another name."; return $res }
    if ($Mode -eq 'update' -and -not $existing) { $res.code = 404; $res.error = "There is no custom workload with id '$($d.id)'."; return $res }
    # Two workloads with one display name read as one in the picker -- refused, whatever the ids.
    foreach ($o in @($List)) {
        if ("$(Get-PimCwField -Obj $o -Name 'id')" -ine "$($d.id)" -and "$(Get-PimCwField -Obj $o -Name 'name')".Trim() -ieq "$($d.name)".Trim()) {
            $res.code = 409; $res.error = "Another custom workload is already named '$($d.name)'."; return $res
        }
    }
    $stamp = $NowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    if ($existing) { $d.createdUtc = "$(Get-PimCwField -Obj $existing -Name 'createdUtc')"; $d.createdBy = "$(Get-PimCwField -Obj $existing -Name 'createdBy')" }
    else { $d.createdUtc = $stamp; $d.createdBy = $By }
    $d.updatedUtc = $stamp; $d.updatedBy = $By
    $out = New-Object System.Collections.ArrayList
    foreach ($o in @($List)) { if ("$(Get-PimCwField -Obj $o -Name 'id')" -ine "$($d.id)") { [void]$out.Add($o) } }
    [void]$out.Add($d)
    $res.ok = $true; $res.code = 200; $res.list = @($out.ToArray()); $res.before = $existing; $res.after = $d
    return $res
}

function Get-PimCustomWorkloadUsage {
    <#
      PURE. Which stored (or pending) rows use a custom workload: PIM-Assignments-Workloads rows and group DEFINITION rows
      (PIM-Definitions-*) whose Workload is the id. -RowsByBase: base -> rows. Returns @{ count; rows = @(@{ base; groupTag;
      role; groupName }) }.
    #>
    param([Parameter(Mandatory)][string]$Id, [hashtable]$RowsByBase = @{})
    $i = "$Id".Trim().ToLowerInvariant()
    $hits = New-Object System.Collections.ArrayList
    foreach ($b in @($RowsByBase.Keys | Sort-Object)) {
        if ("$b" -ne 'PIM-Assignments-Workloads' -and ("$b" -notlike 'PIM-Definitions-*' -or "$b" -eq 'PIM-Definitions-AU')) { continue }
        foreach ($r in @($RowsByBase[$b])) {
            if ($null -eq $r) { continue }
            if ("$(Get-PimCwField -Obj $r -Name 'Workload')".Trim().ToLowerInvariant() -ne $i) { continue }
            [void]$hits.Add([ordered]@{ base = "$b"; groupTag = "$(Get-PimCwField -Obj $r -Name 'GroupTag')"; role = "$(Get-PimCwField -Obj $r -Name 'RoleName')"; groupName = "$(Get-PimCwField -Obj $r -Name 'GroupName')" })
        }
    }
    return [ordered]@{ count = $hits.Count; rows = @($hits.ToArray()) }
}

function Remove-PimCustomWorkloadEntry {
    <#
      PURE. Delete ONE definition -- REFUSED (409) while any row uses it (-Usage from Get-PimCustomWorkloadUsage): a
      delegation whose workload vanished would fail on every run as an unknown workload. Returns @{ ok; code; error; list;
      before }.
    #>
    param([object[]]$List = @(), [Parameter(Mandatory)][string]$Id, [object]$Usage)
    $res = [ordered]@{ ok = $false; code = 404; error = ''; list = @($List); before = $null }
    $existing = Find-PimCustomWorkload -List $List -Id $Id
    if (-not $existing) { $res.error = "There is no custom workload with id '$Id'."; return $res }
    $n = 0; if ($Usage) { $n = [int](Get-PimCwField -Obj $Usage -Name 'count') }
    if ($n -gt 0) {
        $res.code = 409
        $res.error = ("'{0}' is used by {1} row(s) (delegations or group definitions) -- remove those delegations first (and commit), then delete the workload." -f "$(Get-PimCwField -Obj $existing -Name 'name')", $n)
        $res.before = $existing
        return $res
    }
    $res.ok = $true; $res.code = 200; $res.before = $existing
    $res.list = @(@($List) | Where-Object { "$(Get-PimCwField -Obj $_ -Name 'id')" -ine "$Id".Trim() })
    return $res
}

function ConvertTo-PimCustomWorkloadConnector {
    <#
      PURE. A definition -> the connector-catalog entry the engine's WorkloadConnectors dispatcher reads: kind
      'group-only', groupOnly = $true, no auth adapter, no api block, its roles static. Resolve-PimWorkloadBinding treats
      it as satisfied once the group exists -- it never builds a token or calls an API for it.
    #>
    param([Parameter(Mandatory)][object]$Definition)
    $roles = @(foreach ($r in @(Get-PimCwField -Obj $Definition -Name 'roles')) {
        if ($null -eq $r) { continue }
        $rn = "$(Get-PimCwField -Obj $r -Name 'name')".Trim()
        if ($rn) { [pscustomobject]@{ id = $rn; name = $rn; tier = (ConvertTo-PimCustomWorkloadTier -Value (Get-PimCwField -Obj $r -Name 'tier')) } }
    })
    return [pscustomobject]@{
        id = "$(Get-PimCwField -Obj $Definition -Name 'id')"
        name = "$(Get-PimCwField -Obj $Definition -Name 'name')"
        kind = 'group-only'
        groupOnly = $true
        custom = $true
        auth = 'none'
        perRowResource = $false
        membershipModel = $false
        accessModel = "$(Get-PimCwField -Obj $Definition -Name 'accessModel')"
        roles = @($roles)
        permissionsNeeded = @()
        status = 'custom workload (group-only): PIM manages the Entra permission groups; the application consumes their membership. No connector API is called.'
    }
}

function Get-PimCustomWorkloadConnectors {
    # id (lower-case) -> group-only connector entry, for every custom workload of this environment.
    param([object[]]$List)
    $defs = if ($PSBoundParameters.ContainsKey('List')) { @($List) } else { @(Read-PimCustomWorkloads) }
    $h = @{}
    foreach ($d in $defs) {
        if ($null -eq $d) { continue }
        $id = "$(Get-PimCwField -Obj $d -Name 'id')".Trim().ToLowerInvariant()
        if ($id) { $h[$id] = ConvertTo-PimCustomWorkloadConnector -Definition $d }
    }
    return $h
}

function Get-PimCustomWorkloadSegment {
    # PURE. The {Workload} name segment of a custom workload: its display name compressed ('SAP S/4' -> 'SAPS4').
    param([Parameter(Mandatory)][object]$Definition)
    $n = "$(Get-PimCwField -Obj $Definition -Name 'name')"
    $seg = (($n -replace '[^A-Za-z0-9 ]', ' ') -split '\s+' | Where-Object { $_ } | ForEach-Object { if ($_.Length -gt 1) { $_.Substring(0, 1).ToUpper() + $_.Substring(1) } else { $_.ToUpper() } }) -join ''
    if (-not $seg) { $seg = (ConvertTo-PimCustomWorkloadSlug -Text "$(Get-PimCwField -Obj $Definition -Name 'id')") -replace '-', '' }
    return $seg
}

function Get-PimCustomWorkloadDerivation {
    <#
      The target-first wizard's derivation for a custom-workload delegation: the SAME Get-PimWorkloadDerivation every
      workload uses, with {Workload} = the workload's name segment and the TIER of the chosen role (the role carries it;
      the page does not ask). A workload with its own group-name pattern gets the name from that pattern, every naming
      token filled (Expand-PimGroupNamePattern); the TAG keeps the fixed grammar the engine parses. Returns the
      derivation with custom = $true, workloadId, and policyTemplate = the role's default policy template.
    #>
    param([Parameter(Mandatory)][object]$Definition, [Parameter(Mandatory)][string[]]$Roles, [string]$Scope = '',
          [Nullable[int]]$Level, [Nullable[int]]$Tier, [string]$Plane = '', [string]$Domain = '', [string]$BundleName = '')
    if (-not (Get-Command Get-PimWorkloadDerivation -ErrorAction SilentlyContinue)) { throw 'Get-PimCustomWorkloadDerivation: PIM-PermissionWizard.ps1 is not loaded.' }
    $seg = Get-PimCustomWorkloadSegment -Definition $Definition
    $roleList = @(@($Roles) | Where-Object { "$_".Trim() })
    $first = Find-PimCustomWorkloadRole -Definition $Definition -RoleName $(if ($roleList.Count) { $roleList[0] } else { '' })
    $p = @{ Workload = $seg; Roles = $roleList; Scope = $Scope; BundleName = $BundleName }
    $t = $null
    if ($null -ne $Tier) { $t = [int]$Tier } elseif ($first) { $t = ConvertTo-PimCustomWorkloadTier -Value (Get-PimCwField -Obj $first -Name 'tier') }
    if ($null -ne $t) { $p['Tier'] = [int]$t }
    if ($null -ne $Level) { $p['Level'] = [int]$Level }
    if ("$Plane".Trim()) { $p['Plane'] = $Plane }
    if ("$Domain".Trim()) { $p['Domain'] = $Domain }
    $d = Get-PimWorkloadDerivation @p
    $pat = "$(Get-PimCwField -Obj $Definition -Name 'groupNamePattern')".Trim()
    if ($pat -and (Get-Command Expand-PimGroupNamePattern -ErrorAction SilentlyContinue)) {
        $tok = @{}
        if (Get-Command Get-PimGroupNameTokensFromTag -ErrorAction SilentlyContinue) { $tok = Get-PimGroupNameTokensFromTag -Tag "$($d.groupTag)" }
        $tok.Workload = $seg; $tok.Service = $seg
        $tok.Scope = $(if ("$Scope".Trim() -and (Get-Command ConvertTo-PimNameSegment -ErrorAction SilentlyContinue)) { ConvertTo-PimNameSegment $Scope } else { '' })
        $tok.Permission = "$($d.nameSegment)"; $tok.Role = "$($d.nameSegment)"
        $tok.Level = "$($d.level)"; $tok.Tier = "$($d.tier)"; $tok.Plane = "$($d.plane)"; $tok.Domain = "$($d.domain)"
        $d.groupName = Expand-PimGroupNamePattern -Pattern $pat -Tokens $tok
    }
    $d | Add-Member -NotePropertyName custom -NotePropertyValue $true -Force
    $d | Add-Member -NotePropertyName workloadId -NotePropertyValue "$(Get-PimCwField -Obj $Definition -Name 'id')" -Force
    $d | Add-Member -NotePropertyName workloadName -NotePropertyValue "$(Get-PimCwField -Obj $Definition -Name 'name')" -Force
    $d | Add-Member -NotePropertyName policyTemplate -NotePropertyValue $(if ($first) { "$(Get-PimCwField -Obj $first -Name 'defaultPolicyTemplate')" } else { '' }) -Force
    return $d
}

function Get-PimCustomWorkloadSample {
    <#
      PURE. The "Start from SAP example" prefill -- an EXAMPLE to adapt (role names follow common SAP practice; the tiers
      are a starting point, not advice for any one landscape). Never saved by itself.
    #>
    param([string]$Kind = 'sap')
    return (ConvertTo-PimCustomWorkloadDefinition -InputObject ([ordered]@{
        name = 'SAP'
        description = 'EXAMPLE -- adapt before use. SAP access through Entra groups: the SAP system maps each group to its role (SSO claim or SCIM provisioning).'
        accessModel = 'sso-claims'
        roles = @(
            [ordered]@{ name = 'SAP_BASIS_ADMIN'; tier = 0; description = 'Basis administration of the SAP system (example).' }
            [ordered]@{ name = 'SAP_SECURITY_ADMIN'; tier = 0; description = 'User and role administration in SAP (example).' }
            [ordered]@{ name = 'SAP_FI_SUPERUSER'; tier = 1; description = 'Finance key user (example).' }
            [ordered]@{ name = 'SAP_HR_ADMIN'; tier = 1; description = 'HR administration (example).' }
        )
        scopeLevels = @('System', 'Client')
        groupNamePattern = ''
        notes = 'Example definition -- check role names, tiers and scope levels against your SAP landscape before you delegate.'
    }))
}

function Get-PimCustomWorkloadTemplateKind { 'pim-custom-workload-template' }

function ConvertTo-PimCustomWorkloadTemplate {
    <#
      PURE. EXPORT: a custom workload as a permission-template pack (the templates/*.template.json shape that
      Get-PimTemplatePackPlan plans) -- the definition in 'customWorkload', and the STRUCTURE of its delegations in
      'rows': the group definition rows and their PIM-Assignments-Workloads binding rows. NO PEOPLE: no Owners, no admin
      assignments, no replication or ownership stamps. -RowsByBase: the stored rows (base -> rows); -GroupNamePattern: the
      exporting tenant's PimGroupPattern, so an importing tenant re-expresses the names in its own convention.
    #>
    param([Parameter(Mandatory)][object]$Definition, [hashtable]$RowsByBase = @{}, [string]$GroupNamePattern = 'PIM-{Role}',
          [string]$ProductVersion = '', [datetime]$NowUtc = ([datetime]::UtcNow))
    $d = ConvertTo-PimCustomWorkloadDefinition -InputObject $Definition
    $id = "$($d.id)"
    $defCols = @('GroupName', 'GroupDescription', 'GroupTag', 'IsRoleAssignable', 'Workload', 'Level', 'TierLevel', 'Plane', 'CPPlatform', 'PolicyTemplate')
    $bindCols = @('Workload', 'RoleName', 'GroupTag', 'Scope', 'Action', 'Notes')
    $pick = { param($r, $cols) $o = [ordered]@{}; foreach ($c in $cols) { $v = Get-PimCwField -Obj $r -Name $c; $o[$c] = $(if ($null -eq $v) { '' } else { "$v" }) }; $o }
    $usage = Get-PimCustomWorkloadUsage -Id $id -RowsByBase $RowsByBase
    $tags = @{}
    foreach ($u in @($usage.rows)) { if ("$($u.groupTag)".Trim()) { $tags["$($u.groupTag)".Trim().ToLowerInvariant()] = $true } }
    $rows = [ordered]@{}
    foreach ($b in @($RowsByBase.Keys | Sort-Object)) {
        if ("$b" -notlike 'PIM-Definitions-*' -or "$b" -eq 'PIM-Definitions-AU') { continue }
        $list = @(foreach ($r in @($RowsByBase[$b])) {
            if ($null -eq $r) { continue }
            if ("$(Get-PimCwField -Obj $r -Name 'Workload')".Trim() -ine $id) { continue }
            $o = & $pick $r $defCols
            $o['IsRoleAssignable'] = 'FALSE'          # a group-only workload group holds no Entra role
            [pscustomobject]$o
        })
        if ($list.Count) { $rows[$b] = $list }
    }
    $bind = @(foreach ($r in @($RowsByBase['PIM-Assignments-Workloads'])) {
        if ($null -eq $r) { continue }
        if ("$(Get-PimCwField -Obj $r -Name 'Workload')".Trim() -ine $id) { continue }
        if ("$(Get-PimCwField -Obj $r -Name 'Action')".Trim() -ieq 'Remove') { continue }
        [pscustomobject](& $pick $r $bindCols)
    })
    if ($bind.Count) { $rows['PIM-Assignments-Workloads'] = $bind }
    $clean = [ordered]@{}
    foreach ($k in @('id', 'name', 'description', 'accessModel', 'roles', 'scopeLevels', 'groupNamePattern', 'notes')) { $clean[$k] = $d[$k] }
    return [ordered]@{
        kind = (Get-PimCustomWorkloadTemplateKind)
        schema = 1
        id = $id
        name = "$($d.name) delegation (custom workload)"
        version = 1
        description = $(if ("$($d.description)".Trim()) { "$($d.description)" } else { "Custom workload '$($d.name)' -- group-only: PIM manages the Entra permission groups the application consumes." })
        groupNamePattern = $(if ("$GroupNamePattern".Trim()) { "$GroupNamePattern" } else { 'PIM-{Role}' })
        exportedUtc = $NowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        productVersion = "$ProductVersion"
        _doc = 'PIM Manager custom-workload template: the workload definition (customWorkload) and the structure of its delegations (rows: group definitions + their workload bindings). It carries no people -- no owners, no admin assignments.'
        customWorkload = $clean
        rows = $rows
    }
}

function ConvertFrom-PimCustomWorkloadTemplate {
    <#
      PURE. IMPORT: a template (parsed JSON or text) -> @{ ok; error; definition; pack }. Refused: not this kind of
      template, an invalid definition, a row that names another workload, or any row that carries PEOPLE (Owners, an
      admin assignment, an Account-* entity) -- a template is structure only.
    #>
    param([Parameter(Mandatory)][AllowNull()][object]$Template)
    $res = [ordered]@{ ok = $false; error = ''; definition = $null; pack = $null }
    $t = $Template
    if ($t -is [string]) { try { $t = $t | ConvertFrom-Json } catch { $res.error = "The file is not valid JSON: $($_.Exception.Message)"; return $res } }
    if ($null -eq $t) { $res.error = 'No template was given.'; return $res }
    if ("$(Get-PimCwField -Obj $t -Name 'kind')" -ne (Get-PimCustomWorkloadTemplateKind)) { $res.error = "This is not a custom-workload template (kind must be '$(Get-PimCustomWorkloadTemplateKind)')."; return $res }
    $cw = Get-PimCwField -Obj $t -Name 'customWorkload'
    if ($null -eq $cw) { $res.error = 'The template has no customWorkload definition.'; return $res }
    $d = ConvertTo-PimCustomWorkloadDefinition -InputObject $cw
    $errs = @(Test-PimCustomWorkloadDefinition -Definition $d)
    if ($errs.Count) { $res.error = 'The workload definition is not valid: ' + ($errs -join ' '); return $res }
    $rows = Get-PimCwField -Obj $t -Name 'rows'
    if ($null -ne $rows) {
        $props = if ($rows -is [System.Collections.IDictionary]) { @($rows.Keys) } else { @($rows.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($b in $props) {
            if ("$b" -like 'Account-*' -or "$b" -eq 'PIM-Assignments-Admins') { $res.error = "The template carries '$b' rows -- a template is structure only, never people."; return $res }
            if ("$b" -ne 'PIM-Assignments-Workloads' -and ("$b" -notlike 'PIM-Definitions-*' -or "$b" -eq 'PIM-Definitions-AU')) { $res.error = "The template carries '$b' rows -- only group definitions and their workload bindings belong in it."; return $res }
            foreach ($r in @(Get-PimCwField -Obj $rows -Name $b)) {
                if ($null -eq $r) { continue }
                if ("$(Get-PimCwField -Obj $r -Name 'Workload')".Trim() -ine "$($d.id)") { $res.error = "A '$b' row names workload '$(Get-PimCwField -Obj $r -Name 'Workload')', not '$($d.id)'."; return $res }
                if ("$(Get-PimCwField -Obj $r -Name 'Owners')".Trim()) { $res.error = "A '$b' row carries Owners -- a template is structure only, never people."; return $res }
                if ("$b" -eq 'PIM-Assignments-Workloads' -and -not (Find-PimCustomWorkloadRole -Definition $d -RoleName "$(Get-PimCwField -Obj $r -Name 'RoleName')")) {
                    $res.error = "A binding names role '$(Get-PimCwField -Obj $r -Name 'RoleName')', which the workload does not define."; return $res
                }
            }
        }
    }
    $res.ok = $true; $res.definition = $d; $res.pack = $t
    return $res
}
