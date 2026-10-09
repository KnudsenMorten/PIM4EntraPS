#Requires -Version 5.1
<#
  PIM-EnvironmentReport.ps1 -- framework §12.8 ENV-REPORT-1, PIM Manager's half (owner 2026-10-09: "i need a documentation
  in si,pim,invardia with all relevant architecture and security info from the customer env. name of identies, permissions,
  features, flows, everything. it must be exportable to pdf in nice report").

  Builds the architecture & security report of THIS environment from what is deployed, at request time:
    summary, architecture, identities, permissions (expected / missing / extra against PIM-EnvironmentReport.expected.json),
    features, data flows, change history, findings -- plus a list of every source and whether it could be read.

  RULES
    * Read from the live environment, never from design docs. Every read goes through a scriptblock the caller binds
      (-Graph / -Arm / -Sql) or a named source (-Sources), so the suite (tests/Test-PimEnvironmentReport.ps1) drives it offline.
    * UNREADABLE IS SAID, NEVER OMITTED: a source that throws becomes "not readable: <reason>" in its section and in
      sources[] -- the report is still built. A missing grant is "missing" only when the grants WERE read.
    * NO SECRET VALUES: names and ids only. Every string in the finished report passes Protect-PimEnvReportText (JWTs, bearer
      tokens, SAS signatures, connection-string passwords / keys, PEM blocks, client secrets -> '***'), and the count is
      reported (redactions).
    * A source that fails never stops the report; only a defect in this file can throw (the route answers 500 then).
#>

Set-StrictMode -Off

$script:PimEnvReportLibDir = $PSScriptRoot
# 100.31 / framework 12.15: a job's size vs the tenant count recorded on it (pure). Loaded HERE, never behind a Get-Command guard.
. (Join-Path $PSScriptRoot 'PIM-TenantSizing.ps1')

function Get-PimEnvReportSchema { 'pim-environment-report/1' }

function Get-PimEnvReportExpectedPath { Join-Path $script:PimEnvReportLibDir 'PIM-EnvironmentReport.expected.json' }

function Read-PimEnvReportExpected {
    <# The declared permission set (one data file in the solution). Throws when the file is absent or not JSON. #>
    param([string]$Path = (Get-PimEnvReportExpectedPath))
    if (-not (Test-Path -LiteralPath $Path)) { throw "the declared permission set is missing ($Path)" }
    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

# ---------------------------------------------------------------------------------------------------------------------
# secrets
# ---------------------------------------------------------------------------------------------------------------------
function Protect-PimEnvReportText {
    <# PURE. A string with anything credential-shaped replaced by '***'. Returns @{ text; hits }. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text -or $Text -eq '') { return [pscustomobject]@{ text = $Text; hits = 0 } }
    $t = $Text; $hits = 0
    $rules = @(
        ,@('-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----[\s\S]*?(-----END [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----|$)', '***')
        ,@('\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(\.[A-Za-z0-9_-]*)?', '***')
        ,@('(?i)\bBearer\s+[A-Za-z0-9\-\._~\+/]{8,}=*', 'Bearer ***')
        ,@('(?i)([?&](sig|skoid|sktid|skv|sks|ske|skt)=)(?!\*\*\*)[^&\s"'']+', '$1***')
        ,@('(?i)\b(password|pwd|accountkey|sharedaccesskey|shared access key|client_secret|clientsecret|apikey|api_key|access_token|refresh_token|secret)(\s*[=:]\s*)(?!\*\*\*)("[^"]*"|''[^'']*''|[^;\s,&]+)', '$1$2***')
        ,@('(?i)\b(inv|ek)-[A-Za-z0-9_-]{16,}', '$1-***')
    )
    foreach ($r in $rules) {
        $m = [regex]::Matches($t, $r[0])
        if ($m.Count) { $hits += $m.Count; $t = [regex]::Replace($t, $r[0], $r[1]) }
    }
    return [pscustomobject]@{ text = $t; hits = $hits }
}

function ConvertTo-PimEnvReportSafe {
    <# PURE. A copy of any object tree (dictionaries / objects / arrays / scalars) with every string scrubbed. -Counter = [ref] int. #>
    param($Value, [ref]$Counter, [int]$Depth = 0)
    if ($null -eq $Value) { return $null }
    if ($Depth -gt 40) { return '(too deep)' }
    if ($Value -is [string]) { $p = Protect-PimEnvReportText -Text $Value; if ($Counter) { $Counter.Value += $p.hits }; return $p.text }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o') }
    if ($Value -is [ValueType]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in @($Value.Keys)) { $o["$k"] = ConvertTo-PimEnvReportSafe -Value $Value[$k] -Counter $Counter -Depth ($Depth + 1) }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $l = New-Object System.Collections.Generic.List[object]
        foreach ($x in $Value) { $l.Add((ConvertTo-PimEnvReportSafe -Value $x -Counter $Counter -Depth ($Depth + 1))) }
        return ,($l.ToArray())
    }
    $props = @($Value.PSObject.Properties | Where-Object { $_.MemberType -in @('NoteProperty', 'Property') })
    if (-not $props.Count) { $p = Protect-PimEnvReportText -Text "$Value"; if ($Counter) { $Counter.Value += $p.hits }; return $p.text }
    $o = [ordered]@{}
    foreach ($p in $props) { $o[$p.Name] = ConvertTo-PimEnvReportSafe -Value $p.Value -Counter $Counter -Depth ($Depth + 1) }
    return $o
}

function Find-PimEnvReportSecretLike {
    <# PURE. Every string in a tree that still looks like a credential (used by the suite and as a last check). #>
    param($Value, [string]$Path = '$')
    $out = New-Object System.Collections.Generic.List[string]
    $walk = $null
    $walk = {
        param($v, $p, $d)
        if ($null -eq $v -or $d -gt 40) { return }
        if ($v -is [string]) { if ((Protect-PimEnvReportText -Text $v).hits -gt 0) { $out.Add("$p = $v") }; return }
        if ($v -is [ValueType]) { return }
        if ($v -is [System.Collections.IDictionary]) { foreach ($k in @($v.Keys)) { & $walk $v[$k] "$p.$k" ($d + 1) }; return }
        if ($v -is [System.Collections.IEnumerable]) { $i = 0; foreach ($x in $v) { & $walk $x "$p[$i]" ($d + 1); $i++ }; return }
        foreach ($pp in @($v.PSObject.Properties | Where-Object { $_.MemberType -in @('NoteProperty', 'Property') })) { & $walk $pp.Value "$p.$($pp.Name)" ($d + 1) }
    }
    & $walk $Value $Path 0
    return @($out)
}

# ---------------------------------------------------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimEnvReportField {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { if ($Object.Contains($Name)) { return $Object[$Name] } else { return $null } }
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function ConvertTo-PimEnvReportReason {
    <# One plain line for a failed read: the HTTP status when there is one, scrubbed, at most 300 characters. #>
    param($ErrorRecord)
    $m = ''
    try { $m = "$($ErrorRecord.Exception.Message)" } catch { $m = "$ErrorRecord" }
    if (-not $m) { $m = "$ErrorRecord" }
    $m = (($m -split "`n")[0]).Trim()
    if ($m -match '(?i)\b403\b|Forbidden|AuthorizationFailed|Authorization_RequestDenied|Insufficient privileges') { $m = "access denied (403): $m" }
    elseif ($m -match '(?i)\b401\b|Unauthorized') { $m = "not signed in (401): $m" }
    elseif ($m -match '(?i)\b404\b|NotFound|ResourceNotFound') { $m = "not found (404): $m" }
    $m = (Protect-PimEnvReportText -Text $m).text
    if ($m.Length -gt 300) { $m = $m.Substring(0, 300) + ' ...' }
    return $m
}

function ConvertFrom-PimEnvReportSid {
    <# An Entra contained user's SID (0x + 32 hex) -> the app id GUID, or ''. #>
    param($Sid)
    try {
        $hex = "$Sid" -replace '^0x', ''
        if ($hex -notmatch '^[0-9a-fA-F]{32}$') { return '' }
        $b = New-Object byte[] 16
        for ($i = 0; $i -lt 16; $i++) { $b[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
        return ([guid]::new([byte[]]$b)).ToString().ToLowerInvariant()
    } catch { return '' }
}

function Get-PimEnvReportKnownAzureRoles {
    @{
        'acdd72a7-3385-48ef-bd42-f606fba81ae7' = 'Reader'
        'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
        '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
        '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'
        'f58310d9-a9f6-439a-9e8d-f62e7b41a168' = 'Role Based Access Control Administrator'
        '7f951dda-4ed3-4680-a7ca-43fe172d538d' = 'AcrPull'
        '8311e382-0749-4cb8-b61a-304f252e45ec' = 'AcrPush'
        'b9a307c4-5aa3-4b52-ba60-2b17c136cd7b' = 'Container Apps Jobs Operator'
        '4633458b-17de-408a-b874-0445c86b69e6' = 'Key Vault Secrets User'
        'b86a8fe4-44ce-4948-aee5-eccb2c155cd7' = 'Key Vault Secrets Officer'
        '21090545-7ca7-4776-b22c-e363652d74d2' = 'Key Vault Reader'
        '00482a5a-887f-4fb3-b363-3b7fe8e74483' = 'Key Vault Administrator'
        'ba92f5b4-2d11-453d-a403-e96b0029c9fe' = 'Storage Blob Data Contributor'
        '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1' = 'Storage Blob Data Reader'
    }
}

function Get-PimEnvReportSeverityRank { param([string]$Severity) switch ("$Severity") { 'high' { 0 } 'medium' { 1 } 'low' { 2 } default { 3 } } }

# ---------------------------------------------------------------------------------------------------------------------
# the permission comparison (PURE)
# ---------------------------------------------------------------------------------------------------------------------
function Compare-PimEnvReportNamedSet {
    <#
      PURE. Declared names vs held names in one area (Graph application permissions, directory roles, SQL roles, delegated
      scopes). -Declared: objects { permission|role; why; required? }. -Held: names. -Readable:$false -> every declared row is
      'not readable' and nothing is called extra. -Undeclared: the identity has no declared set -> held rows are 'held'.
      Returns rows { area; permission; scope; status expected|missing|extra|held|not readable; required; why; forbidden }.
    #>
    param([string]$Area, [object[]]$Declared = @(), [string[]]$Held = @(), [bool]$Readable = $true, [string]$Reason = '',
          [object[]]$Forbidden = @(), [string]$Scope = '', [switch]$Undeclared)
    $rows = New-Object System.Collections.Generic.List[object]
    $heldSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($h in @($Held)) { if ("$h".Trim()) { [void]$heldSet.Add("$h".Trim()) } }
    $declSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($d in @($Declared | Where-Object { $_ })) {
        $name = "$(Get-PimEnvReportField $d 'permission')"; if (-not $name) { $name = "$(Get-PimEnvReportField $d 'role')" }
        if (-not $name) { continue }
        [void]$declSet.Add($name)
        $req = Get-PimEnvReportField $d 'required'; $req = if ($null -eq $req) { $true } else { [bool]$req }
        $st = if (-not $Readable) { 'not readable' } elseif ($heldSet.Contains($name)) { 'expected' } else { 'missing' }
        $rows.Add([pscustomobject][ordered]@{ area = $Area; permission = $name; scope = $Scope; status = $st; required = $req
            why = "$(Get-PimEnvReportField $d 'why')"; forbidden = $false; reason = $(if (-not $Readable) { $Reason } else { '' }) })
    }
    if (-not $Readable -and -not $rows.Count) {
        # nothing declared and nothing readable: still say so -- an unread area is never a silent blank
        $rows.Add([pscustomobject][ordered]@{ area = $Area; permission = "($Area)"; scope = $Scope; status = 'not readable'; required = $false; why = ''; forbidden = $false; reason = $Reason })
    }
    if ($Readable) {
        $forb = @{}; foreach ($f in @($Forbidden | Where-Object { $_ })) { $fn = "$(Get-PimEnvReportField $f 'permission')"; if (-not $fn) { $fn = "$f" }; if ($fn) { $forb[$fn.ToLowerInvariant()] = "$(Get-PimEnvReportField $f 'why')" } }
        foreach ($h in @($heldSet | Sort-Object)) {
            if ($declSet.Contains($h)) { continue }
            $isForb = $forb.ContainsKey($h.ToLowerInvariant())
            $rows.Add([pscustomobject][ordered]@{ area = $Area; permission = $h; scope = $Scope
                status = $(if ($Undeclared -and -not $isForb) { 'held' } else { 'extra' }); required = $false
                why = $(if ($isForb) { $forb[$h.ToLowerInvariant()] } elseif ($Undeclared) { 'no declared set for this identity' } else { 'not in the declared set' })
                forbidden = $isForb; reason = '' })
        }
    }
    return @($rows.ToArray())
}

function Get-PimEnvReportScopeClasses {
    <# PURE. Which declared scope classes one Azure assignment scope belongs to. #>
    param([string]$Scope, [hashtable]$Context = @{})
    $s = "$Scope".Trim().TrimEnd('/').ToLowerInvariant()
    $c = New-Object System.Collections.Generic.List[string]
    $tid = "$($Context['tenantId'])".ToLowerInvariant()
    if ($s -eq '' -or ($tid -and $s -eq "/providers/microsoft.management/managementgroups/$tid")) { $c.Add('tenantRoot') }
    if ($s -match '/providers/microsoft\.keyvault/vaults/') { $c.Add('keyVault') }
    if ($s -match '/providers/microsoft\.containerregistry/registries/') { $c.Add('registry') }
    if ($s -match '/providers/microsoft\.storage/storageaccounts/') { $c.Add('storage') }
    $job = "$($Context['engineJobId'])".TrimEnd('/').ToLowerInvariant(); if ($job -and $s -eq $job) { $c.Add('engineJob') }
    $self = "$($Context['selfResourceId'])".TrimEnd('/').ToLowerInvariant(); if ($self -and $s -eq $self) { $c.Add('self') }
    $rg = "$($Context['resourceGroupId'])".TrimEnd('/').ToLowerInvariant(); if ($rg -and $s -eq $rg) { $c.Add('resourceGroup') }
    if ($s -match '^/subscriptions/[^/]+$') { $c.Add('subscription') }
    if ($s -match '^/providers/microsoft\.management/managementgroups/') { $c.Add('managementGroup') }
    return @($c)
}

function Test-PimEnvReportScopeCovers {
    <# PURE. Does a role held at -HeldScope reach the declared scope class -Want (inheritance: a parent scope covers its children)? #>
    param([string]$HeldScope, [string]$Want, [hashtable]$Context = @{})
    $cls = @(Get-PimEnvReportScopeClasses -Scope $HeldScope -Context $Context)
    if ($Want -eq 'any' -or $cls -contains $Want) { return $true }
    if ($cls -contains 'tenantRoot') { return $true }          # the root management group is a parent of everything
    $h = "$HeldScope".Trim().TrimEnd('/').ToLowerInvariant()
    if ($Want -eq 'tenantRoot') { return $false }
    $target = switch ($Want) { 'engineJob' { "$($Context['engineJobId'])" } 'self' { "$($Context['selfResourceId'])" } 'resourceGroup' { "$($Context['resourceGroupId'])" } default { '' } }
    $target = "$target".TrimEnd('/').ToLowerInvariant()
    if ($target) { return ($h -and $target.StartsWith($h + '/')) }
    # a class with no one known resource (keyVault / registry / storage): a subscription or the product's resource group covers it
    return (($cls -contains 'subscription') -or ($cls -contains 'resourceGroup'))
}

function Compare-PimEnvReportAzure {
    <#
      PURE. Declared Azure RBAC rows { role; scope (class); required; coveredBy[]; why } vs held assignments { role; scope }.
      A declared row is 'expected' when the role (or one that covers it) is held at its scope or a parent scope; every held
      assignment that satisfied nothing is 'extra' (or 'held' for an identity with no declared set).
    #>
    param([object[]]$Declared = @(), [object[]]$Held = @(), [bool]$Readable = $true, [string]$Reason = '', [hashtable]$Context = @{}, [switch]$Undeclared)
    $rows = New-Object System.Collections.Generic.List[object]
    $used = New-Object 'System.Collections.Generic.HashSet[int]'
    $heldArr = @($Held | Where-Object { $_ })
    foreach ($d in @($Declared | Where-Object { $_ })) {
        $role = "$(Get-PimEnvReportField $d 'role')"; $want = "$(Get-PimEnvReportField $d 'scope')"
        $req = Get-PimEnvReportField $d 'required'; $req = if ($null -eq $req) { $true } else { [bool]$req }
        $ok = @($role) + @(@(Get-PimEnvReportField $d 'coveredBy') | Where-Object { $_ })
        $hitScope = ''; $hitRole = ''
        if ($Readable) {
            for ($i = 0; $i -lt $heldArr.Count; $i++) {
                $h = $heldArr[$i]
                if (@($ok | Where-Object { "$_" -ieq "$($h.role)" }).Count -and (Test-PimEnvReportScopeCovers -HeldScope "$($h.scope)" -Want $want -Context $Context)) {
                    if (-not $hitScope) { $hitScope = "$($h.scope)"; $hitRole = "$($h.role)" }
                    if ("$($h.role)" -ieq $role) { [void]$used.Add($i) }   # only the exact role is "used up"; a covering one stays visible as extra
                }
            }
        }
        $st = if (-not $Readable) { 'not readable' } elseif ($hitScope) { 'expected' } else { 'missing' }
        $note = if ($hitScope -and $hitRole -and $hitRole -ine $role) { "covered by $hitRole at $hitScope" } elseif ($hitScope) { "held at $hitScope" } else { '' }
        $rows.Add([pscustomobject][ordered]@{ area = 'azure'; permission = $role; scope = $want; scopeDetail = $note; status = $st; required = $req
            why = "$(Get-PimEnvReportField $d 'why')"; forbidden = $false; reason = $(if (-not $Readable) { $Reason } else { '' }) })
    }
    if (-not $Readable -and -not $rows.Count) {
        $rows.Add([pscustomobject][ordered]@{ area = 'azure'; permission = '(Azure role assignments)'; scope = ''; scopeDetail = ''; status = 'not readable'; required = $false; why = ''; forbidden = $false; reason = $Reason })
    }
    if ($Readable) {
        for ($i = 0; $i -lt $heldArr.Count; $i++) {
            if ($used.Contains($i)) { continue }
            $h = $heldArr[$i]
            $cls = @(Get-PimEnvReportScopeClasses -Scope "$($h.scope)" -Context $Context)
            $area = if ($cls -contains 'keyVault') { 'keyVault' } else { 'azure' }
            $rows.Add([pscustomobject][ordered]@{ area = $area; permission = "$($h.role)"; scope = $(if ($cls.Count) { $cls[0] } else { 'other' }); scopeDetail = "$($h.scope)"
                status = $(if ($Undeclared) { 'held' } else { 'extra' }); required = $false
                why = $(if ($Undeclared) { 'no declared set for this identity' } else { 'not in the declared set' }); forbidden = $false; reason = '' })
        }
    }
    # a declared Key Vault row is shown in the Key Vault area
    foreach ($r in $rows) { if ($r.area -eq 'azure' -and "$($r.scope)" -eq 'keyVault') { $r.area = 'keyVault' } }
    return @($rows.ToArray())
}

# ---------------------------------------------------------------------------------------------------------------------
# the report
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimEnvironmentReport {
    <#
      -Sources   name -> scriptblock (each optional; an absent one is "not readable: not available in this build"):
                 tenant {tenantId; tenantName}, version, environmentName, mode, edition, license, updateState, diagnostics,
                 permissionHealth, identityContext {selfAppId; managerObjectId; tickObjectId; subscriptionId; resourceGroup;
                 tickJobId; tickJobName}, ownPrincipals {product[]; support[]}, breakGlass {accounts[]; storeOk; error},
                 mail {mode; sender; smtp; checks}, featureGates, featureFlags, securitySettings [ {name; value; why} ],
                 commits, settingsAudit, config {containerAppName; envDnsSuffix; hostnames[]; sqlServer; sqlDatabase; keyVault;
                 registry; engineAppId; hosted; sqlAdminGroup}, definedGroups {count; names[]}, activatorApps [names],
                 scriptDocs [manifest names]
      -Graph     { param($Method, $Path, $Body) }  -> the parsed Microsoft Graph answer
      -Arm       { param($Path) }                  -> the parsed Azure Resource Manager answer (path carries api-version)
      -Sql       { param($Query) }                 -> rows
      -Expected  the declared set (Read-PimEnvReportExpected)
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Sources = @{},
        [scriptblock]$Graph,
        [scriptblock]$Arm,
        [scriptblock]$Sql,
        $Expected,
        [string]$RequestedBy = '',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $srcLog = New-Object System.Collections.Generic.List[object]
    $note = { param($section, $name, $ok, $reason) $srcLog.Add([pscustomobject][ordered]@{ section = $section; source = $name; readable = [bool]$ok; reason = "$reason" }) }
    $read = {
        param($section, $name)
        $b = $null; if ($Sources.ContainsKey($name)) { $b = $Sources[$name] }
        if ($null -eq $b) { & $note $section $name $false 'not available in this build'; return [pscustomobject]@{ ok = $false; value = $null; reason = 'not available in this build' } }
        try { $v = & $b; & $note $section $name $true ''; return [pscustomobject]@{ ok = $true; value = $v; reason = '' } }
        catch { $r = ConvertTo-PimEnvReportReason $_; & $note $section $name $false $r; return [pscustomobject]@{ ok = $false; value = $null; reason = $r } }
    }
    $nr = { param($reason) "not readable: $reason" }
    # Graph / ARM / SQL with the failure as a value, never a throw
    $g = {
        param($path)
        if (-not $Graph) { throw 'Microsoft Graph is not reachable from this host' }
        & $Graph 'GET' $path $null
    }
    $gAll = {
        param($path)
        $acc = New-Object System.Collections.Generic.List[object]
        $r = & $g $path; $n = 0
        while ($true) {
            foreach ($x in @(Get-PimEnvReportField $r 'value')) { if ($null -ne $x) { $acc.Add($x) } }
            $next = "$(Get-PimEnvReportField $r '@odata.nextLink')"
            if (-not $next -or $n -ge 20) { break }
            $n++; $r = & $g $next
        }
        return $acc.ToArray()   # callers wrap in @(); a comma here would nest the list one level
    }
    $a = {
        param($path)
        if (-not $Arm) { throw 'Azure Resource Manager is not reachable from this host' }
        & $Arm $path
    }
    if (-not $Expected) {
        try { $Expected = Read-PimEnvReportExpected } catch { $Expected = $null; & $note 'permissions' 'declared permission set' $false (ConvertTo-PimEnvReportReason $_) }
    }

    # ---------------- facts --------------------------------------------------------------------------------------
    $tenant   = & $read 'summary' 'tenant'
    $version  = & $read 'summary' 'version'
    $envName  = & $read 'summary' 'environmentName'
    $mode     = & $read 'summary' 'mode'
    $edition  = & $read 'summary' 'edition'
    $license  = & $read 'summary' 'license'
    $upd      = & $read 'summary' 'updateState'
    $diag     = & $read 'summary' 'diagnostics'
    $permH    = & $read 'permissions' 'permissionHealth'
    $idc      = & $read 'identities' 'identityContext'
    $own      = & $read 'identities' 'ownPrincipals'
    $bg       = & $read 'identities' 'breakGlass'
    $mail     = & $read 'identities' 'mail'
    $gates    = & $read 'features' 'featureGates'
    $flags    = & $read 'features' 'featureFlags'
    $secSet   = & $read 'features' 'securitySettings'
    $commits  = & $read 'changeHistory' 'commits'
    $setAudit = & $read 'changeHistory' 'settingsAudit'
    $cfg      = & $read 'architecture' 'config'
    $defGrp   = & $read 'identities' 'definedGroups'
    $actApps  = & $read 'identities' 'activatorApps'
    $sDocs    = $null; if ($Sources.ContainsKey('scriptDocs')) { $sDocs = & $read 'permissions' 'scriptDocs' }

    $tid  = "$(Get-PimEnvReportField $tenant.value 'tenantId')".Trim()
    $ctx  = $idc.value
    $sub  = "$(Get-PimEnvReportField $ctx 'subscriptionId')".Trim()
    $rgN  = "$(Get-PimEnvReportField $ctx 'resourceGroup')".Trim()
    $rgId = if ($sub -and $rgN) { "/subscriptions/$sub/resourceGroups/$rgN" } else { '' }
    $tickJobId = "$(Get-PimEnvReportField $ctx 'tickJobId')".Trim()
    if (-not $tickJobId -and $rgId -and "$(Get-PimEnvReportField $ctx 'tickJobName')".Trim()) { $tickJobId = "$rgId/providers/Microsoft.App/jobs/$("$(Get-PimEnvReportField $ctx 'tickJobName')".Trim())" }
    $c = $cfg.value

    # ---------------- architecture -------------------------------------------------------------------------------
    $arch = [ordered]@{ subscriptionId = $sub; resourceGroup = $rgN; readable = $false; reason = ''; resources = @(); network = [ordered]@{}; createdUtc = '' }
    $resList = $null; $resErr = ''
    if ($rgId) {
        try {
            $r = & $a "$rgId/resources?`$expand=createdTime,changedTime&api-version=2021-04-01"
            $resList = @(Get-PimEnvReportField $r 'value')
            & $note 'architecture' 'Azure resource group (ARM)' $true ''
            $arch.readable = $true
        } catch { $resErr = ConvertTo-PimEnvReportReason $_; & $note 'architecture' 'Azure resource group (ARM)' $false $resErr; $arch.reason = $resErr }
    } else {
        $resErr = "the subscription and resource group are not known ($(if ($idc.ok) { 'this Manager does not run as a managed identity in Azure' } else { $idc.reason }))"
        & $note 'architecture' 'Azure resource group (ARM)' $false $resErr; $arch.reason = $resErr
    }
    # what to read in detail: the listed resources, or -- when the list is refused -- the ones the configuration names
    $cands = New-Object System.Collections.Generic.List[object]
    if ($resList) {
        foreach ($x in @($resList | Select-Object -First 40)) { $cands.Add([pscustomobject]@{ id = "$($x.id)"; name = "$($x.name)"; type = "$($x.type)"; location = "$($x.location)"; createdTime = "$(Get-PimEnvReportField $x 'createdTime')"; source = 'resource group' }) }
    } elseif ($rgId) {
        $caName = "$(Get-PimEnvReportField $c 'containerAppName')".Trim()
        if ($caName) { $cands.Add([pscustomobject]@{ id = "$rgId/providers/Microsoft.App/containerApps/$caName"; name = $caName; type = 'Microsoft.App/containerApps'; location = ''; createdTime = ''; source = 'configuration' }) }
        if ($tickJobId) { $cands.Add([pscustomobject]@{ id = $tickJobId; name = (($tickJobId -split '/')[-1]); type = 'Microsoft.App/jobs'; location = ''; createdTime = ''; source = 'configuration' }) }
        $sqlSrv = ("$(Get-PimEnvReportField $c 'sqlServer')".Trim() -replace '(?i)\.database\.windows\.net.*$', '' -replace '^tcp:', '' -replace ',\d+$', '')
        if ($sqlSrv) { $cands.Add([pscustomobject]@{ id = "$rgId/providers/Microsoft.Sql/servers/$sqlSrv"; name = $sqlSrv; type = 'Microsoft.Sql/servers'; location = ''; createdTime = ''; source = 'configuration' }) }
        $kvN = "$(Get-PimEnvReportField $c 'keyVault')".Trim(); if ($kvN) { $cands.Add([pscustomobject]@{ id = "$rgId/providers/Microsoft.KeyVault/vaults/$kvN"; name = $kvN; type = 'Microsoft.KeyVault/vaults'; location = ''; createdTime = ''; source = 'configuration' }) }
        $acrN = ("$(Get-PimEnvReportField $c 'registry')".Trim() -replace '(?i)\.azurecr\.io.*$', ''); if ($acrN) { $cands.Add([pscustomobject]@{ id = "$rgId/providers/Microsoft.ContainerRegistry/registries/$acrN"; name = $acrN; type = 'Microsoft.ContainerRegistry/registries'; location = ''; createdTime = ''; source = 'configuration' }) }
    }
    $apiFor = @{
        'microsoft.app/containerapps' = '2024-03-01'; 'microsoft.app/jobs' = '2024-03-01'; 'microsoft.app/managedenvironments' = '2024-03-01'
        'microsoft.sql/servers' = '2021-11-01'; 'microsoft.keyvault/vaults' = '2023-07-01'; 'microsoft.containerregistry/registries' = '2023-07-01'
        'microsoft.storage/storageaccounts' = '2023-01-01'; 'microsoft.network/natgateways' = '2023-09-01'; 'microsoft.network/privateendpoints' = '2023-09-01'
        'microsoft.network/virtualnetworks' = '2023-09-01'; 'microsoft.network/publicipaddresses' = '2023-09-01'
    }
    $resources = New-Object System.Collections.Generic.List[object]
    $sqlAdmin = $null
    foreach ($cd in $cands) {
        $t = "$($cd.type)".ToLowerInvariant()
        $e = [ordered]@{ name = $cd.name; type = $cd.type; kind = ''; id = $cd.id; location = $cd.location; createdUtc = $cd.createdTime; source = $cd.source
                         readable = $true; reason = ''; exposure = 'unknown'; details = [ordered]@{} }
        $e.kind = switch ($t) {
            'microsoft.app/containerapps' { 'Container app' } 'microsoft.app/jobs' { 'Container Apps job' } 'microsoft.app/managedenvironments' { 'Container Apps environment' }
            'microsoft.sql/servers' { 'SQL server' } 'microsoft.sql/servers/databases' { 'SQL database' } 'microsoft.keyvault/vaults' { 'Key Vault' }
            'microsoft.containerregistry/registries' { 'Container registry' } 'microsoft.storage/storageaccounts' { 'Storage account' }
            'microsoft.network/natgateways' { 'NAT gateway' } 'microsoft.network/privateendpoints' { 'Private endpoint' } 'microsoft.network/virtualnetworks' { 'Virtual network' }
            'microsoft.network/publicipaddresses' { 'Public IP address' } 'microsoft.managedidentity/userassignedidentities' { 'Managed identity (user-assigned)' }
            'microsoft.operationalinsights/workspaces' { 'Log Analytics workspace' } default { "$($cd.type)" }
        }
        if ($apiFor.ContainsKey($t)) {
            try {
                $d = & $a ("{0}?api-version={1}" -f $cd.id, $apiFor[$t])
                $p = Get-PimEnvReportField $d 'properties'
                if (-not $e.location) { $e.location = "$(Get-PimEnvReportField $d 'location')" }
                $idt = Get-PimEnvReportField $d 'identity'; if ($idt) { $e.details['identity'] = "$(Get-PimEnvReportField $idt 'type')"; $e.details['identityObjectId'] = "$(Get-PimEnvReportField $idt 'principalId')" }
                switch ($t) {
                    'microsoft.app/containerapps' {
                        $ing = Get-PimEnvReportField (Get-PimEnvReportField $p 'configuration') 'ingress'
                        $ipr = @(Get-PimEnvReportField $ing 'ipSecurityRestrictions' | Where-Object { $_ })
                        $e.details['fqdn'] = "$(Get-PimEnvReportField $ing 'fqdn')"
                        $e.details['ingressExternal'] = [bool](Get-PimEnvReportField $ing 'external')
                        $e.details['allowInsecure'] = [bool](Get-PimEnvReportField $ing 'allowInsecure')
                        $e.details['ipRestrictions'] = @($ipr | ForEach-Object { "$(Get-PimEnvReportField $_ 'action') $(Get-PimEnvReportField $_ 'ipAddressRange') ($(Get-PimEnvReportField $_ 'name'))" })
                        $e.details['image'] = "$(@(Get-PimEnvReportField (Get-PimEnvReportField $p 'template') 'containers')[0].image)"
                        $e.details['environment'] = (("$(Get-PimEnvReportField $p 'managedEnvironmentId')" -split '/')[-1])
                        $e.exposure = if (-not $ing) { 'no ingress' } elseif (-not $e.details['ingressExternal']) { 'internal (environment only)' } elseif ($ipr.Count) { 'public, IP-restricted' } else { 'public (internet)' }
                    }
                    'microsoft.app/jobs' {
                        $jc = Get-PimEnvReportField $p 'configuration'
                        $e.details['trigger'] = "$(Get-PimEnvReportField $jc 'triggerType')"
                        $e.details['schedule'] = "$(Get-PimEnvReportField (Get-PimEnvReportField $jc 'scheduleTriggerConfig') 'cronExpression')"
                        $e.details['image'] = "$(@(Get-PimEnvReportField (Get-PimEnvReportField $p 'template') 'containers')[0].image)"
                        # 100.31 / framework 12.15: each job's size + the tenant count it was sized from (its pim-sizing-* tags)
                        $jres = Get-PimEnvReportField (@(Get-PimEnvReportField (Get-PimEnvReportField $p 'template') 'containers')[0]) 'resources'
                        $e.details['cpu'] = "$(Get-PimEnvReportField $jres 'cpu')"
                        $e.details['memory'] = "$(Get-PimEnvReportField $jres 'memory')"
                        $e.details['replicaTimeout'] = "$(Get-PimEnvReportField $jc 'replicaTimeout')"
                        $szRec = ConvertFrom-PimTenantSizingTags -Tags (Get-PimEnvReportField $d 'tags') -Job $cd.name
                        if ($szRec.recorded) {
                            $e.details['sizedForObjects'] = "$($szRec.objects)"
                            $e.details['sizedFrom'] = ("{0} users + {1} groups + {2} service principals ({3}, {4}; {5})" -f $szRec.counts.Users, $szRec.counts.Groups, $szRec.counts.ServicePrincipals, $szRec.counted, $szRec.sizedUtc, $szRec.source)
                            $szU = Test-PimJobUndersized -Counts $szRec.counts -Cpu $e.details['cpu'] -Memory $e.details['memory'] -ReplicaTimeout ([int]"0$($e.details['replicaTimeout'])") -SubscriptionId $sub -ResourceGroup $rgN -JobName $cd.name
                            $e.details['sizing'] = "$($szU.reason)"
                            if ($szU.undersized) { $e.details['sizingFix'] = "$($szU.command)" }
                        } elseif ("$($cd.name)" -match '(?i)-tick$') { $e.details['sizing'] = 'no tenant size recorded on this job (installed before 2.4.539) -- the next update records it' }
                        $e.exposure = 'no ingress (outbound only)'
                    }
                    'microsoft.app/managedenvironments' {
                        $vn = Get-PimEnvReportField $p 'vnetConfiguration'
                        $e.details['internal'] = [bool](Get-PimEnvReportField $vn 'internal')
                        $e.details['subnet'] = (("$(Get-PimEnvReportField $vn 'infrastructureSubnetId')" -split '/')[-1])
                        $e.details['staticIp'] = "$(Get-PimEnvReportField $p 'staticIp')"
                        $e.exposure = if ($e.details['internal']) { 'internal (VNet)' } else { 'public load balancer' }
                    }
                    'microsoft.sql/servers' {
                        $e.details['publicNetworkAccess'] = "$(Get-PimEnvReportField $p 'publicNetworkAccess')"
                        $e.details['minimalTlsVersion'] = "$(Get-PimEnvReportField $p 'minimalTlsVersion')"
                        $adm = Get-PimEnvReportField $p 'administrators'
                        if ($adm) {
                            $sqlAdmin = [ordered]@{ login = "$(Get-PimEnvReportField $adm 'login')"; sid = "$(Get-PimEnvReportField $adm 'sid')"; principalType = "$(Get-PimEnvReportField $adm 'principalType')"; entraOnly = [bool](Get-PimEnvReportField $adm 'azureADOnlyAuthentication') }
                            $e.details['entraAdmin'] = "$($sqlAdmin.login) ($($sqlAdmin.principalType))"; $e.details['entraOnlyAuthentication'] = $sqlAdmin.entraOnly
                        }
                        try {
                            $fw = @(Get-PimEnvReportField (& $a ("{0}/firewallRules?api-version=2021-11-01" -f $cd.id)) 'value')
                            $e.details['firewallRules'] = @($fw | ForEach-Object { "$($_.name): $(Get-PimEnvReportField $_.properties 'startIpAddress') - $(Get-PimEnvReportField $_.properties 'endIpAddress')" })
                        } catch { $e.details['firewallRules'] = (& $nr (ConvertTo-PimEnvReportReason $_)) }
                        try {
                            $dbs = @(Get-PimEnvReportField (& $a ("{0}/databases?api-version=2021-11-01" -f $cd.id)) 'value' | Where-Object { "$($_.name)" -ne 'master' })
                            $e.details['databases'] = @($dbs | ForEach-Object { "$($_.name) ($(Get-PimEnvReportField $_.sku 'name'))" })
                        } catch { $e.details['databases'] = (& $nr (ConvertTo-PimEnvReportReason $_)) }
                        $pub = "$($e.details['publicNetworkAccess'])"
                        $e.exposure = if ($pub -ieq 'Disabled') { 'private endpoint only' } elseif (@($e.details['firewallRules']).Count -and $e.details['firewallRules'] -isnot [string]) { 'public, firewall rules' } else { 'public endpoint, no firewall rule (deny)' }
                    }
                    'microsoft.keyvault/vaults' {
                        $acl = Get-PimEnvReportField $p 'networkAcls'
                        $e.details['publicNetworkAccess'] = "$(Get-PimEnvReportField $p 'publicNetworkAccess')"
                        $e.details['defaultAction'] = "$(Get-PimEnvReportField $acl 'defaultAction')"
                        $e.details['ipRules'] = @(@(Get-PimEnvReportField $acl 'ipRules') | Where-Object { $_ } | ForEach-Object { "$(Get-PimEnvReportField $_ 'value')" })
                        $e.details['rbacAuthorization'] = [bool](Get-PimEnvReportField $p 'enableRbacAuthorization')
                        $e.details['softDelete'] = [bool](Get-PimEnvReportField $p 'enableSoftDelete')
                        $e.details['purgeProtection'] = [bool](Get-PimEnvReportField $p 'enablePurgeProtection')
                        $e.exposure = if ("$($e.details['publicNetworkAccess'])" -ieq 'Disabled') { 'private endpoint only' } elseif ("$($e.details['defaultAction'])" -ieq 'Deny') { 'public, network rules (deny by default)' } else { 'public (internet)' }
                    }
                    'microsoft.containerregistry/registries' {
                        $e.details['sku'] = "$(Get-PimEnvReportField (Get-PimEnvReportField $d 'sku') 'name')"
                        $e.details['publicNetworkAccess'] = "$(Get-PimEnvReportField $p 'publicNetworkAccess')"
                        $e.details['adminUserEnabled'] = [bool](Get-PimEnvReportField $p 'adminUserEnabled')
                        $e.details['defaultAction'] = "$(Get-PimEnvReportField (Get-PimEnvReportField $p 'networkRuleSet') 'defaultAction')"
                        $e.exposure = if ("$($e.details['publicNetworkAccess'])" -ieq 'Disabled') { 'private endpoint only' } elseif ("$($e.details['defaultAction'])" -ieq 'Deny') { 'public, network rules' } else { 'public (internet)' }
                    }
                    'microsoft.storage/storageaccounts' {
                        $acl = Get-PimEnvReportField $p 'networkAcls'
                        $e.details['publicNetworkAccess'] = "$(Get-PimEnvReportField $p 'publicNetworkAccess')"
                        $e.details['defaultAction'] = "$(Get-PimEnvReportField $acl 'defaultAction')"
                        $e.details['allowBlobPublicAccess'] = [bool](Get-PimEnvReportField $p 'allowBlobPublicAccess')
                        $sk = Get-PimEnvReportField $p 'allowSharedKeyAccess'; $e.details['allowSharedKeyAccess'] = $(if ($null -eq $sk) { $true } else { [bool]$sk })
                        $e.details['minimumTlsVersion'] = "$(Get-PimEnvReportField $p 'minimumTlsVersion')"
                        $e.exposure = if ("$($e.details['publicNetworkAccess'])" -ieq 'Disabled') { 'private endpoint only' } elseif ("$($e.details['defaultAction'])" -ieq 'Deny') { 'public, network rules (deny by default)' } else { 'public (internet)' }
                    }
                    'microsoft.network/natgateways' { $e.details['publicIps'] = @(@(Get-PimEnvReportField $p 'publicIpAddresses') | ForEach-Object { (("$(Get-PimEnvReportField $_ 'id')" -split '/')[-1]) }); $e.exposure = 'outbound only' }
                    'microsoft.network/privateendpoints' { $e.details['target'] = (("$(@(Get-PimEnvReportField $p 'privateLinkServiceConnections')[0].properties.privateLinkServiceId)" -split '/')[-1]); $e.exposure = 'private' }
                    'microsoft.network/publicipaddresses' { $e.details['ipAddress'] = "$(Get-PimEnvReportField $p 'ipAddress')"; $e.exposure = 'public IP' }
                    'microsoft.network/virtualnetworks' { $e.details['addressSpace'] = @(Get-PimEnvReportField (Get-PimEnvReportField $p 'addressSpace') 'addressPrefixes'); $e.exposure = 'private' }
                }
            } catch {
                $e.readable = $false; $e.reason = ConvertTo-PimEnvReportReason $_
            }
        }
        $resources.Add([pscustomobject]$e)
    }
    foreach ($x in $resources) { if (-not $x.readable) { & $note 'architecture' "$($x.kind) $($x.name)" $false $x.reason } }
    $arch.resources = @($resources.ToArray())
    $created = @($resources | Where-Object { "$($_.createdUtc)".Trim() } | ForEach-Object { "$($_.createdUtc)" } | Sort-Object) | Select-Object -First 1
    $arch.createdUtc = "$created"
    $mgrRes = @($resources | Where-Object { "$($_.type)" -ieq 'Microsoft.App/containerApps' -and ("$($_.name)" -ieq "$(Get-PimEnvReportField $c 'containerAppName')" -or "$($_.details['identityObjectId'])" -ieq "$(Get-PimEnvReportField $ctx 'managerObjectId')") }) | Select-Object -First 1
    $managerUrl = ''
    $caN = "$(Get-PimEnvReportField $c 'containerAppName')".Trim(); $dns = "$(Get-PimEnvReportField $c 'envDnsSuffix')".Trim()
    if ($caN -and $dns) { $managerUrl = "https://$caN.$dns" }
    $arch.network = [ordered]@{
        managerUrl       = $managerUrl
        customHostnames  = @(@(Get-PimEnvReportField $c 'hostnames') | Where-Object { "$_".Trim() })
        managerExposure  = $(if ($mgrRes -and $mgrRes.readable) { "$($mgrRes.exposure)" } elseif ($mgrRes) { (& $nr $mgrRes.reason) } else { (& $nr $(if ($arch.reason) { $arch.reason } else { 'the Manager''s container app was not found in the resource group' })) })
        ipRestrictions   = $(if ($mgrRes -and $mgrRes.readable) { @($mgrRes.details['ipRestrictions']) } else { @() })
        signIn           = 'Microsoft Entra ID sign-in in front of the app; PIM Manager roles from the store'
        sqlServer        = "$(Get-PimEnvReportField $c 'sqlServer')"
        sqlDatabase      = "$(Get-PimEnvReportField $c 'sqlDatabase')"
        natGateway       = [bool](@($resources | Where-Object { "$($_.type)" -ieq 'Microsoft.Network/natGateways' }).Count)
        privateEndpoints = @($resources | Where-Object { "$($_.type)" -ieq 'Microsoft.Network/privateEndpoints' } | ForEach-Object { "$($_.name)" })
    }

    # ---------------- identities ---------------------------------------------------------------------------------
    $expIds = @(); if ($Expected) { $expIds = @($Expected.identities) }
    $expFor = { param($role) @($expIds | Where-Object { "$($_.role)" -eq $role }) | Select-Object -First 1 }
    $identities = New-Object System.Collections.Generic.List[object]
    $addId = {
        param($role, $kind, $name, $id, $appId, $purpose, $source, $obj)
        $exist = @($identities | Where-Object { $id -and "$($_.id)" -ieq "$id" }) | Select-Object -First 1
        if ($exist) { return $exist }
        $rid = ''; if ($obj) { $rid = @(@(Get-PimEnvReportField $obj 'alternativeNames') | Where-Object { "$_" -match '^/subscriptions/' }) | Select-Object -First 1 }
        $x = [pscustomobject][ordered]@{ role = $role; kind = $kind; name = "$name"; id = "$id"; appId = "$appId"; resourceId = "$rid"; purpose = "$purpose"; source = "$source"; readable = $true; reason = '' }
        $identities.Add($x); return $x
    }
    $mgrOid = "$(Get-PimEnvReportField $ctx 'managerObjectId')".Trim().ToLowerInvariant()
    $tickOid = "$(Get-PimEnvReportField $ctx 'tickObjectId')".Trim().ToLowerInvariant()
    $prodIds = @(); $supIds = @()
    if ($own.ok -and $own.value) { $prodIds = @(@(Get-PimEnvReportField $own.value 'product') | Where-Object { "$_".Trim() }); $supIds = @(@(Get-PimEnvReportField $own.value 'support') | Where-Object { "$_".Trim() }) }
    $wantIds = @(@($prodIds) + @($supIds) + @($mgrOid, $tickOid) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".ToLowerInvariant() } | Select-Object -Unique)
    $spObjs = @{}
    if ($wantIds.Count) {
        try {
            $body = (@{ ids = @($wantIds); types = @('servicePrincipal') } | ConvertTo-Json -Depth 4 -Compress)
            if (-not $Graph) { throw 'Microsoft Graph is not reachable from this host' }
            foreach ($o in @(Get-PimEnvReportField (& $Graph 'POST' '/directoryObjects/getByIds' $body) 'value')) { if ($o) { $spObjs["$($o.id)".ToLowerInvariant()] = $o } }
            & $note 'identities' 'service principals (Microsoft Graph)' $true ''
        } catch { & $note 'identities' 'service principals (Microsoft Graph)' $false (ConvertTo-PimEnvReportReason $_) }
    }
    $rolePurpose = { param($r) $e = & $expFor $r; if ($e) { "$($e.purpose)" } else { '' } }
    $roleLabel = { param($r) $e = & $expFor $r; if ($e) { "$($e.label)" } else { '' } }
    foreach ($id in $wantIds) {
        $o = $spObjs[$id]
        $name = if ($o) { "$($o.displayName)" } else { '' }
        $role = 'product'
        if ($id -eq $mgrOid) { $role = 'manager' } elseif ($id -eq $tickOid) { $role = 'engine' } elseif ($supIds -contains $id) { $role = 'support' }
        else { foreach ($e in $expIds) { $mn = "$(Get-PimEnvReportField $e.match 'managedIdentityName')"; if ($mn -and $name -ieq $mn) { $role = "$($e.role)" } } }
        $kind = if ($role -eq 'support') { 'Application (Invardia Support app)' } elseif ($o -and "$($o.servicePrincipalType)" -eq 'ManagedIdentity') { 'Managed identity' } elseif ($o) { "Service principal ($($o.servicePrincipalType))" } else { 'Service principal' }
        $purpose = & $rolePurpose $role; if (-not $purpose -and $role -eq 'product') { $purpose = 'A PIM Manager identity (in the product resource group or PIM''s SQL admin group); no declared permission set' }
        $x = & $addId $role $kind $name $id "$(if ($o) { $o.appId })" $purpose 'Microsoft Graph' $o
        if (-not $o) { $x.readable = $false; $x.reason = 'its directory object could not be read' }
    }
    if (-not $own.ok) { & $note 'identities' 'PIM Manager''s own identities' $false $own.reason }
    # the engine app registration (an engine that runs as an app, e.g. a managing tenant acting cross-tenant)
    $engApp = "$(Get-PimEnvReportField $c 'engineAppId')".Trim()
    if ($engApp) {
        try {
            $o = @(Get-PimEnvReportField (& $g ("/servicePrincipals?`$filter=appId eq '{0}'&`$select=id,appId,displayName,servicePrincipalType" -f $engApp)) 'value') | Select-Object -First 1
            if ($o) { [void](& $addId 'engine-app' 'Application (app registration)' "$($o.displayName)" "$($o.id)" "$($o.appId)" 'The engine app registration this installation is configured with (the engine signs in as it where it does not run as a managed identity).' 'configuration' $o) }
        } catch { & $note 'identities' 'engine app registration' $false (ConvertTo-PimEnvReportReason $_) }
    }
    # the SQL admin group + the server's Entra administrator
    $sqlGrpName = "$(Get-PimEnvReportField $c 'sqlAdminGroup')".Trim(); if (-not $sqlGrpName) { $sqlGrpName = 'grp-pim-sql-admins' }
    try {
        $f = [uri]::EscapeDataString("displayName eq '$($sqlGrpName.Replace("'", "''"))'")
        $gr = @(Get-PimEnvReportField (& $g "/groups?`$filter=$f&`$select=id,displayName,securityEnabled") 'value') | Select-Object -First 1
        if ($gr) { [void](& $addId 'sql-admin-group' 'Group (SQL admin group)' "$($gr.displayName)" "$($gr.id)" '' 'Members administer PIM''s SQL database (the deploy, the in-cloud bootstrap, the engine and the Manager identities); never people for daily work' 'Microsoft Graph' $null) }
        & $note 'identities' 'SQL admin group (Microsoft Graph)' $true ''
    } catch { & $note 'identities' 'SQL admin group (Microsoft Graph)' $false (ConvertTo-PimEnvReportReason $_) }
    if ($sqlAdmin -and "$($sqlAdmin.sid)") {
        $sidL = "$($sqlAdmin.sid)".ToLowerInvariant()
        $ex = @($identities | Where-Object { "$($_.id)" -ieq $sidL -or "$($_.appId)" -ieq $sidL }) | Select-Object -First 1
        if ($ex) { $ex.purpose = "$($ex.purpose) -- the SQL server's Microsoft Entra administrator" }
        else { [void](& $addId 'sql-admin' "SQL server Entra administrator ($($sqlAdmin.principalType))" "$($sqlAdmin.login)" $sidL '' 'The Microsoft Entra administrator of the SQL server' 'Azure Resource Manager' $null) }
    }
    # break-glass accounts (as defined in PIM Manager)
    $bgList = @()
    if ($bg.ok -and $bg.value) {
        $bgList = @(@(Get-PimEnvReportField $bg.value 'accounts') | Where-Object { "$_".Trim() -and "$_" -notmatch '^<' })
        if ((Get-PimEnvReportField $bg.value 'storeConfigured') -and -not (Get-PimEnvReportField $bg.value 'storeOk')) { & $note 'identities' 'break-glass account list' $false "$(Get-PimEnvReportField $bg.value 'error')" }
        foreach ($acc in @($bgList | Select-Object -First 25)) {
            $u = $null; $why = ''
            try { $u = & $g ("/users/{0}?`$select=id,displayName,userPrincipalName" -f [uri]::EscapeDataString("$acc")) } catch { $why = ConvertTo-PimEnvReportReason $_ }
            $x = & $addId 'break-glass' 'User (break-glass account)' $(if ($u) { "$($u.userPrincipalName)" } else { "$acc" }) $(if ($u) { "$($u.id)" } else { '' }) '' 'Emergency account PIM never revokes, disables or offboards' 'PIM Manager settings' $null
            if (-not $u) { $x.readable = $false; $x.reason = $why }
        }
    }
    # the mail sender
    $mv = $mail.value
    $mailMode = "$(Get-PimEnvReportField $mv 'mode')"
    $sender = "$(Get-PimEnvReportField $mv 'sender')".Trim()
    if ($mailMode -eq 'smtp') {
        $from = "$(Get-PimEnvReportField (Get-PimEnvReportField $mv 'smtp') 'from')"
        if ($from) { [void](& $addId 'mail-sender' 'SMTP relay sender address' $from '' '' 'The From address of the SMTP relay' 'PIM Manager settings' $null) }
    } elseif ($sender) {
        $u = $null; $why = ''
        try { $u = & $g ("/users/{0}?`$select=id,displayName,userPrincipalName" -f [uri]::EscapeDataString($sender)) } catch { $why = ConvertTo-PimEnvReportReason $_ }
        $x = & $addId 'mail-sender' 'Mailbox (mail sender)' $sender $(if ($u) { "$($u.id)" } else { '' }) '' 'The one mailbox PIM sends TAP codes, approvals and alerts as (Exchange RBAC for Applications scope)' 'PIM Manager settings' $null
        if (-not $u) { $x.readable = $false; $x.reason = $why }
    }
    # the PIM Activator app registrations
    foreach ($an in @(@($actApps.value) | Where-Object { "$_".Trim() } | Select-Object -Unique)) {
        try {
            $esc = "$an".Replace("'", "''")
            $ap = @(Get-PimEnvReportField (& $g "/applications?`$filter=displayName eq '$esc'&`$select=id,appId,displayName") 'value') | Select-Object -First 1
            if (-not $ap) { continue }
            if (@($identities | Where-Object { "$($_.appId)" -ieq "$($ap.appId)" }).Count) { continue }
            $sp = @(Get-PimEnvReportField (& $g ("/servicePrincipals?`$filter=appId eq '{0}'&`$select=id,appId,displayName" -f $ap.appId)) 'value') | Select-Object -First 1
            [void](& $addId 'activator' 'Application (PIM Activator, delegated)' "$($ap.displayName)" $(if ($sp) { "$($sp.id)" } else { "$($ap.id)" }) "$($ap.appId)" (& $rolePurpose 'activator') 'Microsoft Graph' $null)
        } catch { & $note 'identities' "PIM Activator app '$an'" $false (ConvertTo-PimEnvReportReason $_) }
    }
    # the PIM-managed groups (definitions in the store) -- one line, the names in the details
    $groupsSummary = $null
    if ($defGrp.ok -and $defGrp.value) {
        $groupsSummary = [ordered]@{ count = [int](Get-PimEnvReportField $defGrp.value 'count'); names = @(@(Get-PimEnvReportField $defGrp.value 'names') | Select-Object -First 60) }
    }

    # ---------------- permissions per identity --------------------------------------------------------------------
    $perm = New-Object System.Collections.Generic.List[object]
    $graphRoleNames = @{}; $graphSpId = ''; $graphRolesErr = ''
    try {
        $gsp = @(Get-PimEnvReportField (& $g "/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,appRoles") 'value') | Select-Object -First 1
        $graphSpId = "$($gsp.id)"
        foreach ($r in @($gsp.appRoles)) { $graphRoleNames["$($r.id)".ToLowerInvariant()] = "$($r.value)" }
    } catch { $graphRolesErr = ConvertTo-PimEnvReportReason $_ }
    $otherRes = @{}
    $azRoleCache = Get-PimEnvReportKnownAzureRoles
    $sqlRows = $null; $sqlErr = ''; $sqlFull = $false; $sqlSelf = ''
    if ($Sql) {
        try {
            $sqlRows = @(& $Sql "SELECT p.name AS principalName, p.type AS principalType, CONVERT(varchar(100), p.sid, 1) AS sidHex, r.name AS roleName, USER_NAME() AS me FROM sys.database_principals p LEFT JOIN sys.database_role_members m ON m.member_principal_id = p.principal_id LEFT JOIN sys.database_principals r ON r.principal_id = m.role_principal_id WHERE p.type IN ('E','X','S','U','G') AND p.name NOT IN ('dbo','guest','INFORMATION_SCHEMA','sys')")
            $sqlSelf = "$(@($sqlRows | Where-Object { $_ } | Select-Object -First 1).me)"
            $sqlFull = (@($sqlRows | Where-Object { $_ -and "$($_.principalName)" -ne $sqlSelf } | ForEach-Object { "$($_.principalName)" } | Select-Object -Unique).Count -gt 0)
            & $note 'permissions' 'SQL database roles' $true ''
        } catch { $sqlErr = ConvertTo-PimEnvReportReason $_; & $note 'permissions' 'SQL database roles' $false $sqlErr }
    } else { $sqlErr = 'no SQL store is wired in this host'; & $note 'permissions' 'SQL database roles' $false $sqlErr }
    $mailLines = @(@(Get-PimEnvReportField (Get-PimEnvReportField $mv 'checks') 'lines') | Where-Object { $_ })

    foreach ($idn in @($identities | Where-Object { $_.role -in @('engine', 'manager', 'updater', 'product', 'support', 'engine-app', 'activator') -and "$($_.id)" })) {
        $exp = & $expFor $(if ($idn.role -eq 'engine-app') { 'engine' } else { $idn.role })
        $undeclared = (-not $exp) -or ($exp.PSObject.Properties['declared'] -and $exp.declared -eq $false)
        $add = { param($rows) foreach ($r in @($rows)) { if ($r) { $r | Add-Member -NotePropertyName identity -NotePropertyValue $idn.name -Force; $r | Add-Member -NotePropertyName identityId -NotePropertyValue $idn.id -Force; $r | Add-Member -NotePropertyName identityRole -NotePropertyValue $idn.role -Force; $perm.Add($r) } } }
        if ($idn.role -eq 'activator') {
            $scopes = @(); $ok = $true; $why = ''
            try { foreach ($gr in @(& $gAll ("/oauth2PermissionGrants?`$filter=clientId eq '{0}'" -f $idn.id))) { $scopes += @("$($gr.scope)" -split '\s+' | Where-Object { $_ }) } }
            catch { $ok = $false; $why = ConvertTo-PimEnvReportReason $_ }
            & $add (Compare-PimEnvReportNamedSet -Area 'delegated' -Declared @($exp.delegated) -Held @($scopes | Select-Object -Unique) -Readable $ok -Reason $why)
            continue
        }
        # Graph (and other APIs') application permissions
        $held = @(); $heldOther = @(); $ok = $true; $why = ''
        if ($graphRolesErr) { $ok = $false; $why = $graphRolesErr }
        else {
            try {
                foreach ($erAsg in @(& $gAll "/servicePrincipals/$($idn.id)/appRoleAssignments")) {
                    $rid = "$($erAsg.resourceId)"
                    if ($rid -eq $graphSpId) { $n = $graphRoleNames["$($erAsg.appRoleId)".ToLowerInvariant()]; if ($n) { $held += $n } else { $held += "$($erAsg.appRoleId)" } }
                    else {
                        if (-not $otherRes.ContainsKey($rid)) {
                            $m = @{}; $nm = "$($erAsg.resourceDisplayName)"
                            try { $rs = & $g "/servicePrincipals/$rid`?`$select=displayName,appRoles"; foreach ($r in @($rs.appRoles)) { $m["$($r.id)".ToLowerInvariant()] = "$($r.value)" }; if ("$($rs.displayName)") { $nm = "$($rs.displayName)" } } catch { }
                            $otherRes[$rid] = @{ name = $nm; roles = $m }
                        }
                        $rn = $otherRes[$rid].roles["$($erAsg.appRoleId)".ToLowerInvariant()]; if (-not $rn) { $rn = "$($erAsg.appRoleId)" }
                        $heldOther += [pscustomobject]@{ resource = $otherRes[$rid].name; role = $rn }
                    }
                }
            } catch { $ok = $false; $why = ConvertTo-PimEnvReportReason $_ }
        }
        $graphDecl = if ($undeclared) { @() } else { @($exp.graph) }
        & $add (Compare-PimEnvReportNamedSet -Area 'graph' -Declared $graphDecl -Held $held -Readable $ok -Reason $why -Forbidden @($exp.graphForbidden) -Undeclared:$undeclared)
        foreach ($ho in $heldOther) {
            & $add @([pscustomobject][ordered]@{ area = 'app-role'; permission = "$($ho.role)"; scope = "$($ho.resource)"; status = $(if ($undeclared) { 'held' } else { 'extra' }); required = $false; why = $(if ($undeclared) { 'no declared set for this identity' } else { 'an application permission on another API, not in the declared set' }); forbidden = $false; reason = '' })
        }
        if ($idn.role -eq 'engine-app') { continue }
        # Entra directory roles (none are declared: PIM uses application permissions, never a directory role)
        $dr = @(); $ok = $true; $why = ''
        try { foreach ($x in @(& $gAll ("/roleManagement/directory/roleAssignments?`$filter=principalId eq '{0}'&`$expand=roleDefinition" -f $idn.id))) { $n = "$(Get-PimEnvReportField (Get-PimEnvReportField $x 'roleDefinition') 'displayName')"; if (-not $n) { $n = "$($x.roleDefinitionId)" }; $dr += $n } }
        catch { $ok = $false; $why = ConvertTo-PimEnvReportReason $_ }
        $drDecl = if ($undeclared) { @() } else { @($exp.directoryRoles) }
        $drRows = @(Compare-PimEnvReportNamedSet -Area 'directoryRole' -Declared $drDecl -Held $dr -Readable $ok -Reason $why -Scope 'tenant' -Undeclared:$undeclared)
        if (-not $ok) { $drRows = @([pscustomobject][ordered]@{ area = 'directoryRole'; permission = '(directory roles)'; scope = 'tenant'; status = 'not readable'; required = $false; why = 'PIM uses application permissions; no directory role is declared'; forbidden = $false; reason = $why }) }
        & $add $drRows
        # Azure RBAC (incl. the tenant root management group and Key Vault)
        if ($idn.role -ne 'support') {
            $azHeld = New-Object System.Collections.Generic.List[object]; $seen = @{}; $azOk = $false; $azWhy = ''
            $paths = @()
            if ($sub) { $paths += ("/subscriptions/{0}/providers/Microsoft.Authorization/roleAssignments?`$filter=assignedTo('{1}')&api-version=2022-04-01" -f $sub, $idn.id) }
            if ($tid) { $paths += ("/providers/Microsoft.Management/managementGroups/{0}/providers/Microsoft.Authorization/roleAssignments?`$filter=assignedTo('{1}')&api-version=2022-04-01" -f $tid, $idn.id) }
            if (-not $paths.Count) { $azWhy = 'neither the subscription nor the tenant is known here' }
            foreach ($pth in $paths) {
                try {
                    foreach ($erRa in @(Get-PimEnvReportField (& $a $pth) 'value')) {
                        $pp = Get-PimEnvReportField $erRa 'properties'
                        $key = "$($erRa.id)"; if ($seen.ContainsKey($key)) { continue }; $seen[$key] = $true
                        $erRd = "$(Get-PimEnvReportField $pp 'roleDefinitionId')"; $gd = (($erRd -split '/')[-1]).ToLowerInvariant()
                        if (-not $azRoleCache.ContainsKey($gd)) {
                            $nm = $gd; try { $def = & $a ("{0}?api-version=2022-04-01" -f $erRd); if ("$(Get-PimEnvReportField (Get-PimEnvReportField $def 'properties') 'roleName')") { $nm = "$($def.properties.roleName)" } } catch { }
                            $azRoleCache[$gd] = $nm
                        }
                        $azHeld.Add([pscustomobject]@{ role = $azRoleCache[$gd]; scope = "$(Get-PimEnvReportField $pp 'scope')" })
                    }
                    $azOk = $true
                } catch { if (-not $azWhy) { $azWhy = ConvertTo-PimEnvReportReason $_ } }
            }
            $actx = @{ tenantId = $tid; engineJobId = $tickJobId; selfResourceId = "$($idn.resourceId)"; resourceGroupId = $rgId }
            $azDecl = if ($undeclared) { @() } else { @($exp.azure) }
            & $add (Compare-PimEnvReportAzure -Declared $azDecl -Held @($azHeld.ToArray()) -Readable $azOk -Reason $azWhy -Context $actx -Undeclared:$undeclared)
        }
        # SQL database roles (the contained user is created from the app id as its SID)
        $sqlDecl = if ($exp) { @($exp.sql) } else { @() }
        if ($null -ne $sqlRows -or $sqlErr) {
            $mine = @(); $found = $false
            if ($null -ne $sqlRows) {
                foreach ($sr in @($sqlRows | Where-Object { $_ })) {
                    $sApp = ConvertFrom-PimEnvReportSid -Sid "$($sr.sidHex)"
                    if (($sApp -and $idn.appId -and $sApp -ieq "$($idn.appId)") -or ("$($sr.principalName)" -ieq $idn.name)) { $found = $true; if ("$($sr.roleName)") { $mine += "$($sr.roleName)" } }
                }
            }
            $sqlReadable = ($null -ne $sqlRows) -and ($found -or $sqlFull)
            $sqlWhy = if ($null -eq $sqlRows) { $sqlErr } elseif (-not $sqlReadable) { 'this Manager''s database user sees only its own role memberships (SQL metadata visibility)' } else { '' }
            if ($sqlDecl.Count -or $mine.Count) {
                $forbSql = @(@($exp.sqlForbidden) | Where-Object { $_ } | ForEach-Object { @{ permission = "$_"; why = 'db_owner can manage users and permissions and drop the database; the runtime identities never hold it' } })
                $rows = @(Compare-PimEnvReportNamedSet -Area 'sql' -Declared $sqlDecl -Held @($mine | Select-Object -Unique) -Readable $sqlReadable -Reason $sqlWhy -Forbidden $forbSql -Scope "$(Get-PimEnvReportField $c 'sqlDatabase')" -Undeclared:(-not $exp))
                if ($sqlReadable -and -not $found -and $sqlDecl.Count) { foreach ($r in $rows) { if ($r.status -eq 'missing') { $r.why = "$($r.why) -- no database user for this identity" } } }
                & $add $rows
            }
        }
        # Exchange RBAC for Applications (shared mailbox mode): proven by the identity's own last real send
        foreach ($xr in @(@($exp.exchange) | Where-Object { $_ })) {
            if ("$($xr.when)" -and "$($xr.when)" -ne $mailMode -and -not ($mailMode -eq '' -and $sender)) { continue }
            $line = @($mailLines | Where-Object { "$($_.id)" -eq "mail-send-$($idn.role)" }) | Select-Object -First 1
            $st = 'not readable'; $why2 = 'Exchange RBAC for Applications cannot be read with the Manager''s permissions; only a real send proves it'
            if (-not $mail.ok) { $why2 = $mail.reason }
            elseif ($line) {
                switch ("$($line.state)") { 'ok' { $st = 'expected'; $why2 = '' } 'failed' { $st = 'missing'; $why2 = '' } 'missing' { $st = 'missing'; $why2 = '' } default { $why2 = "$($line.detail)" } }
            }
            & $add @([pscustomobject][ordered]@{ area = 'exchange'; permission = "$($xr.role)"; scope = $(if ($sender) { "$($xr.scope): $sender" } else { "$($xr.scope)" }); status = $st; required = $(if ($null -eq $xr.required) { $true } else { [bool]$xr.required })
                why = "$($xr.why)"; forbidden = $false; reason = $why2; detail = $(if ($line) { "$($line.detail)" } else { '' }) })
        }
    }

    # ---------------- features -----------------------------------------------------------------------------------
    $features = New-Object System.Collections.Generic.List[object]
    $secRx = '(?i)telemetry|licence|license|update|mail|alert|emergency|break|approval|guard|reconcile|downlink|replicat|rfa|mcp|api|review|consultant|disable|offboard|connector'
    if ($gates.ok -and $gates.value) {
        $eff = Get-PimEnvReportField $gates.value 'effective'
        $keys = @(); if ($eff -is [System.Collections.IDictionary]) { $keys = @($eff.Keys) } elseif ($eff) { $keys = @($eff.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($k in $keys) {
            $e = Get-PimEnvReportField $eff $k
            $on = Get-PimEnvReportField $e 'effectiveEnabled'; if ($null -eq $on) { $on = Get-PimEnvReportField $e 'enabled' }
            $features.Add([pscustomobject][ordered]@{ key = "$k"; label = "$(Get-PimEnvReportField $e 'label')"; group = "$(Get-PimEnvReportField $e 'group')"; enabled = [bool]$on
                licensed = $(if ($null -eq (Get-PimEnvReportField $e 'licensed')) { $true } else { [bool](Get-PimEnvReportField $e 'licensed') }); license = "$(Get-PimEnvReportField $e 'license')"; source = 'feature catalog'
                securityRelevant = [bool]("$k $(Get-PimEnvReportField $e 'label')" -match $secRx) })
        }
    }
    if ($flags.ok -and $flags.value) {
        $fl = Get-PimEnvReportField $flags.value 'flags'
        foreach ($cat in @(Get-PimEnvReportField $flags.value 'catalog')) {
            $fid = "$(Get-PimEnvReportField $cat 'id')"; if (-not $fid -or @($features | Where-Object { $_.key -eq $fid }).Count) { continue }
            $v = Get-PimEnvReportField $fl $fid
            $features.Add([pscustomobject][ordered]@{ key = $fid; label = "$(Get-PimEnvReportField $cat 'label')"; group = 'Pages and surfaces'; enabled = [bool]$v; licensed = $true; license = ''; source = 'feature flags'; securityRelevant = [bool]("$fid" -match $secRx) })
        }
    }
    $securitySettings = @(@($secSet.value) | Where-Object { $_ } | ForEach-Object { [pscustomobject][ordered]@{ name = "$(Get-PimEnvReportField $_ 'name')"; value = "$(Get-PimEnvReportField $_ 'value')"; why = "$(Get-PimEnvReportField $_ 'why')" } })
    $isOn = { param($key) $f = @($features | Where-Object { $_.key -eq $key }) | Select-Object -First 1; if ($f) { [bool]$f.enabled } else { $null } }

    # ---------------- data flows ---------------------------------------------------------------------------------
    $modeTxt = "$($mode.value)"
    $editionTxt = "$(Get-PimEnvReportField $license.value 'edition')"; if (-not $editionTxt) { $editionTxt = "$(Get-PimEnvReportField $edition.value 'edition')" }
    $isPro = ($editionTxt -match '(?i)pro')
    $flows = New-Object System.Collections.Generic.List[object]
    foreach ($df in @(if ($Expected) { @($Expected.dataFlows) })) {
        $w = "$($df.enabledWhen)"; $en = $null; $basis = ''
        switch -Regex ($w) {
            '^always$' { $en = $true }
            '^sql$' { $en = [bool]("$(Get-PimEnvReportField $c 'sqlServer')".Trim()); $basis = 'a SQL store is configured' }
            '^mail:(.+)$' { $want = $Matches[1]; $m2 = if ($mailMode) { $mailMode } elseif ($sender) { 'sharedMailbox' } else { '' }; $en = $(if ($mail.ok) { $m2 -eq $want } else { $null }); $basis = "mail mode: $(if ($m2) { $m2 } else { 'not chosen' })" }
            '^feature:(.+)$' { $en = & $isOn $Matches[1]; $basis = "feature $($Matches[1])" }
            '^community$' { $en = $(if ($editionTxt) { -not $isPro } else { $null }); $basis = "edition: $editionTxt" }
            '^msp$' { $en = $(if ($mode.ok) { $modeTxt -match '(?i)managing|managed' } else { $null }); $basis = "mode: $modeTxt" }
            '^activator$' { $en = [bool](@($identities | Where-Object { $_.role -eq 'activator' }).Count); $basis = 'a PIM Activator app registration exists' }
        }
        $flows.Add([pscustomobject][ordered]@{ id = "$($df.id)"; from = "$($df.from)"; to = "$($df.to)"; direction = "$($df.direction)"; protocol = "$($df.protocol)"; auth = "$($df.auth)"; data = "$($df.data)"
            enabled = $en; basis = $basis })
    }

    # ---------------- change history -----------------------------------------------------------------------------
    $history = New-Object System.Collections.Generic.List[object]
    foreach ($cm in @(@($commits.value) | Where-Object { $_ } | Select-Object -First 60)) {
        $history.Add([pscustomobject][ordered]@{ whenUtc = "$(Get-PimEnvReportField $cm 'CommittedUtc')"; kind = 'commit'; who = "$(Get-PimEnvReportField $cm 'InitiatedBy')"; approvedBy = "$(Get-PimEnvReportField $cm 'ApprovedBy')"
            summary = ("{0} row(s) in {1} entit{2}{3}{4}" -f (Get-PimEnvReportField $cm 'Rows'), (Get-PimEnvReportField $cm 'Entities'), $(if ([int](Get-PimEnvReportField $cm 'Entities') -eq 1) { 'y' } else { 'ies' }), $(if ("$(Get-PimEnvReportField $cm 'Entity')") { " (first: $(Get-PimEnvReportField $cm 'Entity'))" } else { '' }), $(if ("$(Get-PimEnvReportField $cm 'UndoOf')") { ' -- an undo' } else { '' }))
            source = "$(Get-PimEnvReportField $cm 'Source')"; id = "$(Get-PimEnvReportField $cm 'CommitId')" })
    }
    foreach ($ev in @(@($setAudit.value) | Where-Object { $_ } | Select-Object -First 60)) {
        $history.Add([pscustomobject][ordered]@{ whenUtc = "$(Get-PimEnvReportField $ev 'ts')"; kind = 'setting'; who = "$(Get-PimEnvReportField $ev 'actor')"; approvedBy = ''
            summary = "$(Get-PimEnvReportField $ev 'action') $(Get-PimEnvReportField $ev 'target') ($(Get-PimEnvReportField $ev 'result'))"; source = 'audit trail'; id = '' })
    }
    $uv = $upd.value
    if ($upd.ok -and $uv -and "$(Get-PimEnvReportField $uv 'lastRunUtc')") {
        $history.Add([pscustomobject][ordered]@{ whenUtc = "$(Get-PimEnvReportField $uv 'lastRunUtc')"; kind = 'update'; who = 'update job'; approvedBy = ''
            summary = "update run: $(Get-PimEnvReportField $uv 'lastAction') $(Get-PimEnvReportField $uv 'lastOutcome') (running $(Get-PimEnvReportField $uv 'runningVersion'), approved $(Get-PimEnvReportField $uv 'approvedVersion'))"; source = 'update state'; id = '' })
    }
    $histSorted = @($history | Sort-Object { "$($_.whenUtc)" } -Descending)
    $scriptJournal = [ordered]@{ readable = $false; reason = 'the setup scripts report their runs to Invardia (install tracking); this environment''s store records commits, settings changes and update runs, listed here'
                                 manifests = @(@($sDocs.value) | Where-Object { $_ }) }
    & $note 'changeHistory' 'script journal (setup scripts)' $false $scriptJournal.reason

    # ---------------- summary ------------------------------------------------------------------------------------
    $lv = $license.value
    $installUtc = ''; $installSrc = ''
    if ($arch.createdUtc) { $installUtc = $arch.createdUtc; $installSrc = 'the oldest Azure resource in the resource group' }
    elseif ($histSorted.Count) { $first = @($histSorted | Where-Object { $_.kind -eq 'commit' } | Select-Object -Last 1); if ($first) { $installUtc = "$($first.whenUtc)"; $installSrc = 'the first recorded commit (the Azure resources could not be read)' } }
    $ph = $permH.value
    $health = New-Object System.Collections.Generic.List[object]
    if ($permH.ok -and $ph) { $health.Add([pscustomobject][ordered]@{ area = 'permissions'; status = $(if ([bool](Get-PimEnvReportField $ph 'ok')) { 'ok' } else { "$(Get-PimEnvReportField $ph 'severity')" }); detail = "$(Get-PimEnvReportField $ph 'headline')" }) }
    else { $health.Add([pscustomobject][ordered]@{ area = 'permissions'; status = 'unknown'; detail = (& $nr $permH.reason) }) }
    if ($diag.ok -and $diag.value) {
        $ov = "$(Get-PimEnvReportField $diag.value 'overall')"
        $bad = @(@(Get-PimEnvReportField $diag.value 'checks') | Where-Object { "$($_.status)" -eq 'fail' } | ForEach-Object { "$($_.surface)" })
        $health.Add([pscustomobject][ordered]@{ area = 'connectivity'; status = $(switch ($ov) { 'pass' { 'ok' } 'fail' { 'error' } default { 'unknown' } }); detail = $(if ($bad.Count) { "failing: $($bad -join ', ')" } else { "SQL / Microsoft Graph / Azure checks: $ov" }) })
    } else { $health.Add([pscustomobject][ordered]@{ area = 'connectivity'; status = 'unknown'; detail = (& $nr $diag.reason) }) }
    if ($upd.ok -and $uv) { $health.Add([pscustomobject][ordered]@{ area = 'updates'; status = $(switch ("$(Get-PimEnvReportField $uv 'state')") { 'current' { 'ok' } 'installed' { 'ok' } 'failing' { 'error' } 'behind' { 'warning' } 'held' { 'warning' } default { 'unknown' } }); detail = "$(Get-PimEnvReportField $uv 'headline')" }) }
    else { $health.Add([pscustomobject][ordered]@{ area = 'updates'; status = 'unknown'; detail = (& $nr $upd.reason) }) }
    if ($license.ok -and $lv) { $health.Add([pscustomobject][ordered]@{ area = 'licence'; status = $(switch ("$(Get-PimEnvReportField $lv 'status')") { 'Valid' { 'ok' } 'Missing' { 'ok' } 'Grace' { 'warning' } default { 'error' } }); detail = "$(Get-PimEnvReportField $lv 'statusText')" }) }
    $worst = 'ok'; foreach ($h in $health) { $s = "$($h.status)"; if ($s -eq 'error') { $worst = 'error' } elseif ($s -eq 'warning' -and $worst -ne 'error') { $worst = 'warning' } elseif ($s -eq 'unknown' -and $worst -eq 'ok') { $worst = 'unknown' } }
    $modeLabel = switch -Regex ($modeTxt) { '(?i)^master$|managing' { 'Managing tenant' } '(?i)^slave$|managed' { 'Managed tenant' } default { 'Single tenant' } }
    $summary = [ordered]@{
        product        = 'PIM Manager'
        customer       = $(if ("$(Get-PimEnvReportField $lv 'customer')".Trim()) { "$(Get-PimEnvReportField $lv 'customer')".Trim() } else { "$(Get-PimEnvReportField $tenant.value 'tenantName')" })
        tenantName     = "$(Get-PimEnvReportField $tenant.value 'tenantName')"
        tenantId       = $tid
        environmentName = "$($envName.value)"
        mode           = $(if ($mode.ok) { $modeLabel } else { (& $nr $mode.reason) })
        edition        = $(if ($editionTxt) { $editionTxt } else { (& $nr $license.reason) })
        dimension      = $(if ("$(Get-PimEnvReportField $lv 'dimensionText')") { "$(Get-PimEnvReportField $lv 'dimensionText')" } else { "$(Get-PimEnvReportField $lv 'dimension')" })
        licence        = [ordered]@{ status = "$(Get-PimEnvReportField $lv 'status')"; text = "$(Get-PimEnvReportField $lv 'statusText')"; validTo = "$(Get-PimEnvReportField $lv 'validTo')"; graceUntil = "$(Get-PimEnvReportField $lv 'graceUntil')"; readable = [bool]$license.ok; reason = "$($license.reason)" }
        version        = $(if ($version.ok) { "$($version.value)" } else { (& $nr $version.reason) })
        updateRing     = $(if ($upd.ok -and $uv) { "$(Get-PimEnvReportField $uv 'ringLabel')" } else { (& $nr $upd.reason) })
        updateState    = $(if ($upd.ok -and $uv) { "$(Get-PimEnvReportField $uv 'headline')" } else { '' })
        approvedVersion = "$(Get-PimEnvReportField $uv 'approvedVersion')"
        installedUtc   = $(if ($installUtc) { $installUtc } else { (& $nr 'neither the Azure resources nor the change journal could be read') })
        installedSource = $installSrc
        health         = [ordered]@{ status = $worst; items = @($health.ToArray()) }
    }

    # ---------------- findings -----------------------------------------------------------------------------------
    $fnd = New-Object System.Collections.Generic.List[object]
    $addF = { param($sev, $area, $title, $detail, $fix) $fnd.Add([pscustomobject][ordered]@{ severity = $sev; area = $area; title = $title; detail = "$detail"; fix = "$fix" }) }
    $grantCmd = { param($oid, $perms)
        "Invoke-WebRequest https://invardia.com/support/pim/Grant-PimEnginePermissions.ps1 -OutFile Grant-PimEnginePermissions.ps1`n" +
        ".\Grant-PimEnginePermissions.ps1 -TenantId '$(if ($tid) { $tid } else { '<tenant id>' })' -EngineObjectId '$oid' -GraphPermissions $(@($perms | ForEach-Object { "'$_'" }) -join ',')" }
    foreach ($grp in @($perm | Where-Object { $_.status -eq 'missing' -and $_.required } | Group-Object identityId, area)) {
        $f0 = $grp.Group[0]; $names = @($grp.Group | ForEach-Object { $_.permission })
        $fix = switch ($f0.area) {
            'graph' { & $grantCmd $f0.identityId $names }
            'azure' {
                $rootRoles = @($grp.Group | Where-Object { "$($_.scope)" -eq 'tenantRoot' -and $_.permission -in @('Reader', 'User Access Administrator') } | ForEach-Object { $_.permission } | Select-Object -Unique)
                $other = @($grp.Group | Where-Object { -not ("$($_.scope)" -eq 'tenantRoot' -and $_.permission -in @('Reader', 'User Access Administrator')) })
                $parts = @()
                if ($rootRoles.Count -and (Get-Command Get-PimRootAzureFixCommand -ErrorAction SilentlyContinue)) { $parts += (Get-PimRootAzureFixCommand -TenantId $tid -EngineObjectId $f0.identityId -Roles $rootRoles) }
                elseif ($rootRoles.Count) { $other = @($grp.Group) }
                if ($other.Count) { $parts += "Assign to $($f0.identity) ($($f0.identityId)): $(@($other | ForEach-Object { "$($_.permission) at $($_.scope)" }) -join ', ') (Azure portal > Access control (IAM)), or re-run the PIM Manager setup" }
                $parts -join "`n"
            }
            'sql' { "Re-run the store setup (tools/setup/Initialize-PimTenantStore.ps1) so $($f0.identity) gets $($names -join ' + '); the contained user is created from the app id as a SID" }
            'exchange' { 'https://invardia.com/support/pim/Initialize-PimMailSender.ps1 -- grants Application Mail.Send scoped to the sender mailbox (Get Started > Mail sender shows the command with this environment''s values)' }
            default { "Grant $($names -join ', ') to $($f0.identity)" }
        }
        & $addF 'high' 'permissions' "$($f0.identity): $($names.Count) required $($f0.area) permission(s) missing" ("Missing: " + ($names -join ', ') + ". " + (@($grp.Group | ForEach-Object { "$($_.permission): $($_.why)" }) -join '; ')) $fix
    }
    foreach ($p in @($perm | Where-Object { $_.status -eq 'extra' })) {
        $sev = 'medium'
        if ($p.forbidden) { $sev = 'high' }
        elseif ($p.area -eq 'directoryRole') { $sev = 'high' }
        elseif ($p.area -in @('azure', 'keyVault') -and $p.permission -in @('Owner', 'Contributor', 'User Access Administrator', 'Role Based Access Control Administrator') -and $p.scope -in @('tenantRoot', 'subscription', 'managementGroup')) { $sev = 'high' }
        elseif ($p.area -eq 'graph' -and $p.identityRole -eq 'manager' -and $p.permission -match '\.(ReadWrite|Remove)\.') { $sev = 'high' }
        $where = if ("$($p.scopeDetail)") { " at $($p.scopeDetail)" } elseif ("$($p.scope)") { " ($($p.scope))" } else { '' }
        $fix = switch ($p.area) {
            'graph' { "Remove the application permission $($p.permission) from $($p.identity) (Entra admin center > Enterprise applications > $($p.identity) > Permissions), or record why it is kept" }
            'directoryRole' { "Remove the directory role $($p.permission) from $($p.identity) (Entra admin center > Roles and administrators): PIM needs no directory role" }
            'sql' { "ALTER ROLE [$($p.permission)] DROP MEMBER [<database user of $($p.identity)>] -- or re-run tools/setup/Initialize-PimTenantStore.ps1, which takes db_owner back" }
            default { "Remove the $($p.permission) assignment$where from $($p.identity) (Azure portal > Access control (IAM)), or record why it is kept" }
        }
        & $addF $sev 'permissions' "$($p.identity): extra $($p.area) permission $($p.permission)$where" "$($p.why)" $fix
    }
    foreach ($r in @($resources | Where-Object { $_.readable })) {
        $d = $r.details
        switch ("$($r.type)".ToLowerInvariant()) {
            'microsoft.app/jobs' { if ("$($d['sizingFix'])".Trim()) { & $addF 'medium' 'capacity' "$($r.name) is smaller than this tenant needs" "$($d['sizing']). An undersized engine job runs out of memory (the next update raises it by itself)." "$($d['sizingFix'])" } }
            'microsoft.app/containerapps' { if ($d['ingressExternal'] -and -not @($d['ipRestrictions']).Count) { & $addF 'medium' 'network' "$($r.name) is reachable from the internet" 'External ingress with no IP restriction; every request still needs a Microsoft Entra sign-in and a PIM Manager role.' 'Container app > Ingress > IP restrictions: allow only your admin networks (or put the app behind a private environment)' }
                                            if ($d['allowInsecure']) { & $addF 'high' 'network' "$($r.name) accepts plain HTTP" 'allowInsecure is on' 'Container app > Ingress: switch off "Allow insecure connections"' } }
            'microsoft.sql/servers' { if ("$($d['publicNetworkAccess'])" -ine 'Disabled' -and $d['firewallRules'] -isnot [string] -and @($d['firewallRules']).Count) {
                                            $allAzure = @($d['firewallRules'] | Where-Object { "$_" -match '0\.0\.0\.0 - 0\.0\.0\.0' }).Count
                                            & $addF $(if ($allAzure) { 'medium' } else { 'low' }) 'network' "SQL server $($r.name) has a public endpoint with $(@($d['firewallRules']).Count) firewall rule(s)" ($(if ($allAzure) { '"Allow Azure services" (0.0.0.0) lets any Azure tenant''s resources try to connect; ' } else { '' }) + 'Microsoft Entra-only authentication: ' + "$($d['entraOnlyAuthentication'])") 'SQL server > Networking: remove the rules you do not need, or disable public access and use the private endpoint' }
                                      if ($d.Contains('entraOnlyAuthentication') -and -not $d['entraOnlyAuthentication']) { & $addF 'medium' 'identity' "SQL server $($r.name) accepts SQL logins" 'Microsoft Entra-only authentication is off' 'SQL server > Microsoft Entra ID: tick "Support only Microsoft Entra authentication"' } }
            'microsoft.keyvault/vaults' { if ("$($r.exposure)" -eq 'public (internet)') { & $addF 'medium' 'network' "Key Vault $($r.name) is open to the internet" 'Public network access with default action Allow' 'Key Vault > Networking: allow selected networks only, or disable public access' }
                                          if (-not $d['purgeProtection']) { & $addF 'low' 'data' "Key Vault $($r.name) has no purge protection" 'A deleted secret can be purged before the retention ends' 'Key Vault > Properties: enable purge protection' } }
            'microsoft.containerregistry/registries' { if ($d['adminUserEnabled']) { & $addF 'high' 'identity' "Container registry $($r.name) has its admin user enabled" 'A shared admin password can push images' 'Container registry > Access keys: disable the admin user (PIM pulls with its managed identity)' } }
            'microsoft.storage/storageaccounts' { if ($d['allowBlobPublicAccess']) { & $addF 'high' 'data' "Storage account $($r.name) allows anonymous blob access" 'allowBlobPublicAccess is on' 'Storage account > Configuration: disable "Allow Blob anonymous access"' }
                                                  if ($d['allowSharedKeyAccess']) { & $addF 'low' 'identity' "Storage account $($r.name) allows shared-key access" 'Account keys and SAS still work beside Microsoft Entra access' 'Storage account > Configuration: disable "Allow storage account key access" once nothing uses a key' } }
        }
    }
    if ($license.ok -and $lv) {
        $ls = "$(Get-PimEnvReportField $lv 'status')"
        if ($ls -eq 'Grace') { & $addF 'high' 'licence' 'The Pro licence has expired (grace period)' "$(Get-PimEnvReportField $lv 'statusText')" 'Renew the licence at invardia.com (contact info@invardia.com); register it in Settings > Licence' }
        elseif ($ls -eq 'Valid' -and "$(Get-PimEnvReportField $lv 'validTo')") {
            $vt = [datetime]::MinValue
            if ([datetime]::TryParse("$(Get-PimEnvReportField $lv 'validTo')", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal,AssumeUniversal', [ref]$vt) -and ($vt - $NowUtc).TotalDays -lt 30) { & $addF 'medium' 'licence' "The Pro licence expires on $(Get-PimEnvReportField $lv 'validTo')" "$([math]::Max(0, [int]($vt - $NowUtc).TotalDays)) day(s) left" 'Renew the licence at invardia.com (contact info@invardia.com)' }
        }
        elseif ($ls -notin @('Valid', 'Missing', '')) { & $addF 'high' 'licence' "The licence is $ls" "$(Get-PimEnvReportField $lv 'statusText')" 'Settings > Licence: register a valid licence (contact info@invardia.com)' }
    }
    if ($upd.ok -and $uv) {
        if ([bool](Get-PimEnvReportField $uv 'failing')) { & $addF 'high' 'updates' 'The nightly update is failing' "$(Get-PimEnvReportField $uv 'lastError')" 'Operations > Support: send the diagnostics bundle to Invardia support' }
        elseif ([bool](Get-PimEnvReportField $uv 'behind')) { & $addF 'medium' 'updates' "Running $(Get-PimEnvReportField $uv 'runningVersion'), approved $(Get-PimEnvReportField $uv 'approvedVersion')" "$(Get-PimEnvReportField $uv 'headline')" 'The update job rolls the approved version on its next run; check Jobs > Engine logs if it does not' }
        elseif ([bool](Get-PimEnvReportField $uv 'stale')) { & $addF 'low' 'updates' 'The update job has not reported for more than 48 hours' "$(Get-PimEnvReportField $uv 'headline')" 'Check that the update job is enabled and its schedule runs' }
    }
    if ($permH.ok -and $ph) {
        foreach ($ed in @(@(Get-PimEnvReportField $ph 'engineDenied') | Where-Object { $_ } | Select-Object -First 5)) { & $addF 'high' 'permissions' "The engine was refused: $($ed.label)" "$($ed.message)" 'Grant the missing permission to the engine identity (see Permissions); a new grant can take up to ~30 minutes to reach its token' }
    }
    if ($bg.ok -and -not $bgList.Count) { & $addF 'medium' 'identity' 'No break-glass account is defined' 'PIM never touches the break-glass accounts defined in PIM Manager; none is defined, so an emergency account is not protected from a revoke' 'Settings > Emergency access (break-glass): add the emergency accounts' }
    if ($mail.ok -and $mv -and (Get-PimEnvReportField $mv 'checks') -and -not [bool](Get-PimEnvReportField (Get-PimEnvReportField $mv 'checks') 'complete')) { & $addF 'low' 'mail' 'Mail is not complete' "$(Get-PimEnvReportField (Get-PimEnvReportField $mv 'checks') 'summary')" 'Get Started > Mail sender' }
    $unread = @($srcLog | Where-Object { -not $_.readable -and $_.source -ne 'script journal (setup scripts)' })
    if ($unread.Count) { & $addF 'info' 'report' "$($unread.Count) source(s) could not be read -- those parts are not verified" (@($unread | ForEach-Object { "$($_.source): $($_.reason)" }) -join ' | ') 'Grant the PIM Manager identity read access where it is refused (e.g. Reader on the resource group) and refresh the report' }
    $findings = @($fnd | Sort-Object { Get-PimEnvReportSeverityRank $_.severity }, area)

    # ---------------- assemble + scrub ---------------------------------------------------------------------------
    $counts = [ordered]@{
        identities = $identities.Count
        permissions = [ordered]@{ expected = @($perm | Where-Object { $_.status -eq 'expected' }).Count; missing = @($perm | Where-Object { $_.status -eq 'missing' }).Count
                                  extra = @($perm | Where-Object { $_.status -eq 'extra' }).Count; notReadable = @($perm | Where-Object { $_.status -eq 'not readable' }).Count; held = @($perm | Where-Object { $_.status -eq 'held' }).Count }
        findings = [ordered]@{ high = @($findings | Where-Object { $_.severity -eq 'high' }).Count; medium = @($findings | Where-Object { $_.severity -eq 'medium' }).Count; low = @($findings | Where-Object { $_.severity -eq 'low' }).Count; info = @($findings | Where-Object { $_.severity -eq 'info' }).Count }
        unreadableSources = @($srcLog | Where-Object { -not $_.readable }).Count
    }
    $report = [ordered]@{
        schema        = (Get-PimEnvReportSchema)
        product       = 'PIM Manager'
        generatedUtc  = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        requestedBy   = $RequestedBy
        summary       = $summary
        architecture  = $arch
        identities    = @($identities.ToArray())
        managedGroups = $groupsSummary
        permissions   = @($perm.ToArray())
        expectedSource = [ordered]@{ file = 'engine/_shared/PIM-EnvironmentReport.expected.json'; schema = "$(if ($Expected) { $Expected.schema })"; scriptDocManifests = @(@($sDocs.value) | Where-Object { $_ }).Count }
        features      = @($features.ToArray())
        securitySettings = @($securitySettings)
        dataFlows     = @($flows.ToArray())
        changeHistory = [ordered]@{ entries = @($histSorted); scriptJournal = $scriptJournal; commitsReadable = [bool]$commits.ok; settingsReadable = [bool]$setAudit.ok
                                    reason = (@(@($commits, $setAudit) | Where-Object { -not $_.ok } | ForEach-Object { $_.reason }) -join ' | ') }
        findings      = @($findings)
        counts        = $counts
        sources       = @($srcLog.ToArray())
    }
    $n = 0
    $safe = ConvertTo-PimEnvReportSafe -Value $report -Counter ([ref]$n)
    $safe['redactions'] = $n
    return $safe
}
