#Requires -Version 5.1
<#
.SYNOPSIS
    WEB-GRAPH-MIN-1 (3.0.69, owner decision 2026-11-09): the directory facts the ENGINE reads and records, and the
    cache-only readers the web app uses instead of calling Microsoft Graph / Azure Resource Manager itself.

.DESCRIPTION
    Owner, 2026-11-09: "i have never approved that the web app had full AD permissions ... i thought it runs through the
    engine". The web app (identity id-pim-web) makes NO Graph call except the people / group pickers and the UPN -> object
    id lookups an admin triggers by typing a name, and NO Azure read above its own resource group. Every other directory
    read is made HERE, by the engine's tenant-cache job (tools/pim-manager/_tenantSync.ps1 Invoke-PimTenantListRefresh,
    run by the scheduler as id-pim-engine), and stored in pim.TenantCache. The web app reads those rows.

    Two halves, one file:
      ENGINE (live reads; called only from Invoke-PimTenantListRefresh):
        Get-PimEngineTenantOrgFact        -> kind 'tenant-org'        { tenantId; tenantName; displayName; id; domains[] }
                                             (+ kind 'tenant-domains' { domains[] }, the shape the Settings page reads)
        Get-PimEngineAdminTapFact         -> kind 'admin-tap-state'   { accounts = { upn-lower = { status; detail; createdDateTime } } }
        Get-PimEngineDemoGroupFact        -> kind 'demo-group'        { on; group; ok; id; members[]; error }
        Get-PimEngineAppRegistrationsFact -> kind 'pim-app-registrations' { apps = { name-lower = { found; appId; displayName; redirectUris[] } } }
        Get-PimEngineWorkloadRolesFact    -> kind 'workload-roles'    { connectors = { id = { read; reason; roles[] } } }
        Get-PimEngineDirectoryAnswers     -> kind 'pim-identities'    the RECORDED ANSWERS: every Graph / ARM read the web
                                             app's identity / permission / mail / environment-report panels make, made once
                                             by the engine and stored by a normalised key (see ConvertTo-PimDirectoryAnswerKey)
        Invoke-PimEngineAdminImportReads  -> kind 'admin-import-reads' the account reads an "Import" asked for (queued)
      WEB (no Graph, no ARM -- the cache only):
        Read-PimEngineFact, Invoke-PimEngineRecordedGraph, Invoke-PimEngineRecordedArm, Get-PimEngineFactPendingText,
        ConvertFrom-PimEngineFactJwt (the web app's OWN identity from its OWN token -- no Graph call)

    A fact the engine has not recorded yet reads "the engine has not recorded this yet -- it does on its next run" --
    never an error page, never a live fallback call from the web app.

    PS 5.1 + 7, ASCII, no modules. The ENGINE half depends on PIM-Rest.ps1 (Invoke-PimGraph / Invoke-PimArm /
    Get-PimRestToken) and PIM-SqlStore.ps1 (Get-/Set-PimSqlSetting); every call is guarded with Get-Command.
#>
Set-StrictMode -Off

function Get-PimEngineFactPendingText { return 'the engine has not recorded this yet -- it does on its next run' }

# The setting the web app writes at start (its own identity, read from its own token -- no Graph), so the engine knows
# which service principal is the web app's, and the app names / accounts the web panels ask about.
function Get-PimManagerRuntimeIdentitySettingName { return 'ManagerRuntimeIdentity' }
# The setting the "Import" button writes: the accounts whose reads the engine makes on its next tenant-cache run.
function Get-PimAdminImportRequestSettingName { return 'AdminImportRequests' }

function ConvertFrom-PimEngineFactJwt {
    # PURE. The payload claims of a JWT (no signature check -- used only to name the caller's own identity).
    param([string]$Token)
    try {
        $parts = "$Token".Split('.')
        if ($parts.Count -lt 2) { return $null }
        $p = $parts[1].Replace('-', '+').Replace('_', '/')
        switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } 1 { return $null } }
        return ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json)
    } catch { return $null }
}

function Get-PimIdentityFromClaims {
    <# PURE. { appId; objectId; resourceId; name; subscriptionId; resourceGroup; tenantId } from a token's claims. A managed
       identity's token carries xms_mirid (its Azure resource id): the name is its last segment, the subscription and
       resource group come from it. Nothing here calls Graph. #>
    param($Claims)
    $o = [ordered]@{ appId = ''; objectId = ''; resourceId = ''; name = ''; subscriptionId = ''; resourceGroup = ''; tenantId = '' }
    if (-not $Claims) { return [pscustomobject]$o }
    $o.appId = "$($Claims.appid)".Trim().ToLowerInvariant(); if (-not $o.appId) { $o.appId = "$($Claims.azp)".Trim().ToLowerInvariant() }
    $o.objectId = "$($Claims.oid)".Trim().ToLowerInvariant()
    $o.tenantId = "$($Claims.tid)".Trim().ToLowerInvariant()
    $mir = "$($Claims.xms_mirid)".Trim()
    if ($mir) {
        $o.resourceId = $mir
        $o.name = @($mir -split '/')[-1]
        if ($mir -match '(?i)^/subscriptions/([^/]+)/resourcegroups/([^/]+)/') { $o.subscriptionId = $Matches[1]; $o.resourceGroup = $Matches[2] }
    }
    return [pscustomobject]$o
}

# ---------------------------------------------------------------------------------------------------------------------
# THE ANSWER KEY -- one normalisation for the recorder (engine) and the replay (web), so the web panels keep their exact
# Graph / ARM paths and the engine only has to record each read once with a broad $select.
# ---------------------------------------------------------------------------------------------------------------------
function ConvertTo-PimDirectoryAnswerKey {
    <# PURE. "<METHOD> <path>[?$filter=<filter>]" -- lower-case, URL-decoded, the service prefix and every query option
       except $filter dropped ($select / $top / $expand / $count / $orderby / api-version only shape the answer). #>
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Path)
    $p = "$Path".Trim()
    $p = $p -replace '(?i)^https://graph\.microsoft\.com/(v1\.0|beta)', '' -replace '(?i)^https://management\.azure\.com', ''
    $q = ''
    $i = $p.IndexOf('?')
    if ($i -ge 0) { $q = $p.Substring($i + 1); $p = $p.Substring(0, $i) }
    try { $p = [uri]::UnescapeDataString($p) } catch { }
    $p = $p.TrimEnd('/').ToLowerInvariant()
    $flt = ''
    foreach ($pair in @($q -split '&')) {
        if (-not $pair) { continue }
        $kv = $pair -split '=', 2
        $k = ''; try { $k = [uri]::UnescapeDataString($kv[0]) } catch { $k = $kv[0] }
        if ($k -ieq '$filter' -and $kv.Count -gt 1) {
            $v = $kv[1]; try { $v = [uri]::UnescapeDataString($v.Replace('+', ' ')) } catch { }
            $flt = ($v -replace '\s+', ' ').Trim().ToLowerInvariant()
        }
    }
    $key = "$("$Method".Trim().ToUpperInvariant()) $p"
    if ($flt) { $key += "?`$filter=$flt" }
    return $key
}

function New-PimDirectoryAnswerBook { return @{ answers = @{}; objects = @{} } }

function Add-PimDirectoryAnswer {
    # Records one answer (or its error) under its normalised key; service principals / users / groups / applications
    # inside it are indexed by id too, for the getByIds replay.
    param([Parameter(Mandatory)][hashtable]$Book, [string]$Method = 'GET', [Parameter(Mandatory)][string]$Path, $Value, [string]$ErrorText = '')
    $k = ConvertTo-PimDirectoryAnswerKey -Method $Method -Path $Path
    if ("$ErrorText".Trim()) { $Book.answers[$k] = [ordered]@{ ok = $false; error = "$ErrorText" }; return }
    $Book.answers[$k] = [ordered]@{ ok = $true; value = $Value }
    # index directory OBJECTS only (service principals, users, groups, applications) -- never assignments
    if ($k -notmatch '^GET /(serviceprincipals|users|groups|applications)(\?|/[^/?]+$|/[^/]+/members/microsoft\.graph\.serviceprincipal$)') { return }
    $items = @()
    if ($null -ne $Value -and $Value.PSObject.Properties['value']) { $items = @($Value.value) } elseif ($null -ne $Value -and $Value.PSObject.Properties['id']) { $items = @($Value) }
    foreach ($x in $items) { if ($x -and "$($x.id)".Trim() -and -not $x.PSObject.Properties['appRoleId']) { $Book.objects["$($x.id)".ToLowerInvariant()] = $x } }
}

function Invoke-PimDirectoryRecordedRead {
    # ENGINE: one live read, recorded (answer or error). Returns the answer ($null on error). -Arm reads Azure.
    param([Parameter(Mandatory)][hashtable]$Book, [Parameter(Mandatory)][string]$Path, [string]$RecordAs = '', [switch]$All, [switch]$Arm, [hashtable]$Headers = @{}, [string]$ApiVersion = '2022-04-01')
    $key = if ($RecordAs) { $RecordAs } else { $Path }
    try {
        if ($Arm) {
            $r = if ($All) { [pscustomobject]@{ value = @(Invoke-PimArm -Path $Path -ApiVersion $ApiVersion -All) } } else { Invoke-PimArm -Path $Path -ApiVersion $ApiVersion }
        } else {
            $r = if ($All) { [pscustomobject]@{ value = @(Invoke-PimGraph -Path $Path -All -Headers $Headers) } } else { Invoke-PimGraph -Path $Path -Headers $Headers }
        }
        Add-PimDirectoryAnswer -Book $Book -Path $key -Value $r
        return $r
    } catch {
        $m = (("$($_.Exception.Message) $($_.ErrorDetails.Message)" -split "`n")[0]).Trim()
        Add-PimDirectoryAnswer -Book $Book -Path $key -ErrorText $m
        return $null
    }
}

# ---------------------------------------------------------------------------------------------------------------------
# WEB half -- the cache only. NO Graph, NO ARM below this line until "ENGINE half".
# ---------------------------------------------------------------------------------------------------------------------
function Read-PimEngineFact {
    <# One engine-written cache kind for a web panel: { ok; value; refreshedUtc; reason }. ok=$false = not recorded yet
       (reason = the pending text) or unreadable (reason = why). Never throws, never calls Graph. #>
    param([Parameter(Mandatory)][string]$Kind)
    $v = $null; $why = ''
    if (-not (Get-Command Get-PimTenantCacheEntry -ErrorAction SilentlyContinue)) { return [pscustomobject]@{ ok = $false; value = $null; refreshedUtc = ''; reason = (Get-PimEngineFactPendingText) } }
    try { $v = Get-PimTenantCacheEntry -Kind $Kind } catch { $v = $null; $why = "$($_.Exception.Message)" }
    if ($v -is [string]) { try { $v = $v | ConvertFrom-Json } catch { } }
    if ($null -eq $v) {
        if (-not $why -and (Get-Command Get-PimTenantCacheReadError -ErrorAction SilentlyContinue)) { $why = Get-PimTenantCacheReadError -Kind $Kind }
        return [pscustomobject]@{ ok = $false; value = $null; refreshedUtc = ''; reason = $(if ("$why".Trim()) { "the engine's record could not be read: $why" } else { Get-PimEngineFactPendingText }) }
    }
    $ru = ''; if ($v.PSObject.Properties['refreshedUtc']) { $ru = "$($v.refreshedUtc)" }
    return [pscustomobject]@{ ok = $true; value = $v; refreshedUtc = $ru; reason = '' }
}

$script:PimRecordedBookCache = $null
function Get-PimEngineRecordedBook {
    # The 'pim-identities' answer book (read once per 60 s); $null when the engine has not recorded it yet.
    $now = [datetime]::UtcNow
    if ($script:PimRecordedBookCache -and ($now - $script:PimRecordedBookCache.at).TotalSeconds -lt 60) { return $script:PimRecordedBookCache.book }
    $f = Read-PimEngineFact -Kind 'pim-identities'
    $b = if ($f.ok) { $f.value } else { $null }
    $script:PimRecordedBookCache = @{ at = $now; book = $b }
    return $b
}

function Get-PimRecordedField { param($Object, [string]$Name) if ($null -eq $Object) { return $null }; if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }; $p = $Object.PSObject.Properties[$Name]; if ($p) { return $p.Value }; return $null }

function Invoke-PimEngineRecordedGraph {
    <# WEB. The Graph-shaped answer the ENGINE recorded for this read. Same shape as Invoke-PimGraph (-All = the items).
       A read the engine recorded as refused throws its error; a read it has not recorded throws the pending text. A
       POST /directoryObjects/getByIds is answered from every object the engine recorded. Never calls Graph.
       -Book: a test seam (an answer book), else the cache. #>
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Path, $Body, [switch]$All, [hashtable]$Headers = @{}, $Book)
    $bk = if ($null -ne $Book) { $Book } else { Get-PimEngineRecordedBook }
    if ($null -eq $bk) { throw (Get-PimEngineFactPendingText) }
    $answers = Get-PimRecordedField $bk 'answers'
    $objects = Get-PimRecordedField $bk 'objects'
    $key = ConvertTo-PimDirectoryAnswerKey -Method $Method -Path $Path
    if ($key -like 'POST /directoryobjects/getbyids') {
        $b = $Body; if ($b -is [string]) { try { $b = $b | ConvertFrom-Json } catch { $b = $null } }
        $ids = @(Get-PimRecordedField $b 'ids')
        $hits = New-Object System.Collections.Generic.List[object]
        foreach ($id in $ids) { $o = Get-PimRecordedField $objects ("$id".ToLowerInvariant()); if ($o) { $hits.Add($o) } }
        $res = [pscustomobject]@{ value = @($hits.ToArray()) }
        if ($All) { return @($res.value) }
        return $res
    }
    $a = Get-PimRecordedField $answers $key
    if ($null -eq $a) {
        # a single object by id ('/servicePrincipals/<id>', '/users/<id>', '/groups/<id>') -- any recorded copy answers
        if ($key -match '^GET /(serviceprincipals|users|groups|applications)/([^/?]+)$') {
            $o = Get-PimRecordedField $objects $Matches[2]
            if ($o) { return $o }
        }
        throw (Get-PimEngineFactPendingText)
    }
    if (-not (Get-PimRecordedField $a 'ok')) { throw "$(Get-PimRecordedField $a 'error')" }
    $v = Get-PimRecordedField $a 'value'
    if ($All) { if ($null -ne $v -and $v.PSObject.Properties['value']) { return @($v.value) }; return @($v) }
    return $v
}

function Invoke-PimEngineRecordedArm {
    # WEB. An Azure read ABOVE the web app's resource group, answered from what the engine recorded (never live).
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Path, [string]$ApiVersion = '', [switch]$All, $Book)
    return (Invoke-PimEngineRecordedGraph -Method $Method -Path $Path -All:$All -Book $Book)
}

function Test-PimArmPathInResourceGroup {
    # PURE. Is this ARM path inside -ResourceGroupId (/subscriptions/<s>/resourceGroups/<rg>)? The web app reads only there.
    param([string]$Path, [string]$ResourceGroupId)
    $rg = "$ResourceGroupId".Trim().TrimEnd('/').ToLowerInvariant()
    if (-not $rg -or $rg -notmatch '^/subscriptions/[^/]+/resourcegroups/[^/]+$') { return $false }
    $p = ("$Path".Trim() -replace '(?i)^https://management\.azure\.com', '').ToLowerInvariant()
    $i = $p.IndexOf('?'); if ($i -ge 0) { $p = $p.Substring(0, $i) }
    return ($p -eq $rg -or $p.StartsWith("$rg/"))
}

# ---------------------------------------------------------------------------------------------------------------------
# ENGINE half -- live reads, run ONLY by the tenant-cache job (Invoke-PimTenantListRefresh, the scheduler, id-pim-engine).
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimEngineFactStoreCs {
    if (Get-Command Get-PimTenantCacheStoreCs -ErrorAction SilentlyContinue) { try { return (Get-PimTenantCacheStoreCs) } catch { } }
    return $null
}
function Get-PimEngineFactSetting {
    param([Parameter(Mandatory)][string]$Name)
    $cs = Get-PimEngineFactStoreCs
    if ($cs -and (Get-Command Get-PimSqlSetting -ErrorAction SilentlyContinue)) { try { $v = Get-PimSqlSetting -ConnectionString $cs -Name $Name; if ($v -is [string]) { try { $v = $v | ConvertFrom-Json } catch { } }; return $v } catch { return $null } }
    return $null
}
function Get-PimEngineNow { return (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }

function ConvertTo-PimEngineDomainList {
    # PURE. organization.verifiedDomains -> [{ id; isDefault; isInitial }] (lower-case, unique, default first).
    param([object[]]$VerifiedDomains)
    $seen = @{}; $out = New-Object System.Collections.Generic.List[object]
    foreach ($d0 in @($VerifiedDomains)) {
        foreach ($d in @($d0)) {
            if (-not $d) { continue }
            $n = "$(Get-PimRecordedField $d 'name')".Trim().ToLowerInvariant(); if (-not $n) { $n = "$(Get-PimRecordedField $d 'id')".Trim().ToLowerInvariant() }
            if (-not $n -or $n -match '\s' -or $seen.ContainsKey($n)) { continue }
            $seen[$n] = $true
            $out.Add([ordered]@{ id = $n; isDefault = [bool](Get-PimRecordedField $d 'isDefault'); isInitial = [bool](Get-PimRecordedField $d 'isInitial') })
        }
    }
    return @(@($out.ToArray()) | Sort-Object @{ Expression = { -not $_.isDefault } }, @{ Expression = { $_.id } })
}

function Get-PimEngineTenantOrgFact {
    # ENGINE. kind 'tenant-org' -- the organisation (Organization.Read.All / Directory.Read.All); also writes 'tenant-domains'.
    $org = @(Invoke-PimGraph -Path '/organization?$select=id,displayName,verifiedDomains' -All) | Select-Object -First 1
    if (-not $org) { throw 'Graph /organization returned no organisation' }
    $tid = "$($global:PIM_TenantId)".Trim(); if (-not $tid) { $tid = "$($global:AzureTenantID)".Trim() }; if (-not $tid) { $tid = "$($org.id)" }
    $domains = @(ConvertTo-PimEngineDomainList -VerifiedDomains @($org.verifiedDomains))
    $now = Get-PimEngineNow
    if ($domains.Count -and (Get-Command Set-PimTenantCacheEntry -ErrorAction SilentlyContinue)) {
        try { [void](Set-PimTenantCacheEntry -Kind 'tenant-domains' -Value ([ordered]@{ domains = @($domains); refreshedUtc = $now; source = 'engine' })) } catch { Write-Warning "  [tenant-cache] tenant-domains not written: $($_.Exception.Message)" }
    }
    return [pscustomobject][ordered]@{ tenantId = $tid; tenantName = "$($org.displayName)"; displayName = "$($org.displayName)"; id = "$($org.id)"; domains = @($domains); refreshedUtc = $now }
}

function Get-PimEngineAdminTapFact {
    <# ENGINE. kind 'admin-tap-state' -- each PIM admin's Temporary Access Pass state (UserAuthenticationMethod.Read.All;
       the engine holds UserAuthenticationMethod.ReadWrite.All). Two reads per admin, at most 500 admins per run.
       status: usable | expired | none | unknown (never 'none' for a read that failed). #>
    $acc = [ordered]@{}
    $n = 0
    foreach ($r in @(Get-PimTenantSyncRows -Entity 'Account-Definitions-Admins')) {
        if ($null -eq $r) { continue }
        $upn = "$($r.UserPrincipalName)".Trim()
        if (-not $upn -or "$($r.TargetPlatform)".Trim() -ieq 'AD') { continue }
        $k = $upn.ToLowerInvariant(); if ($acc.Contains($k)) { continue }
        if (++$n -gt 500) { break }
        $e = [ordered]@{ status = 'unknown'; detail = ''; createdDateTime = ''; readUtc = (Get-PimEngineNow) }
        try {
            $uid = "$((Invoke-PimGraph -Path ("/users/{0}?`$select=id" -f [uri]::EscapeDataString($upn))).id)"
            if (-not $uid.Trim()) { $e.detail = 'account not found in the directory (not yet created?)' }
            else {
                $taps = @(Invoke-PimGraph -All -Path "/users/$uid/authentication/temporaryAccessPassMethods")   # -All: the items, never the wrapper (BUG-51)
                if (-not $taps.Count) { $e.status = 'none'; $e.detail = 'no TAP -- the engine mints one on its next run' }
                else {
                    $t = $taps[0]; $e.createdDateTime = "$($t.createdDateTime)"
                    if ("$($t.isUsable)" -match '(?i)true') { $e.status = 'usable'; $e.detail = 'active' }
                    else { $e.status = 'expired'; $e.detail = $(if ("$($t.methodUsabilityReason)".Trim()) { "$($t.methodUsabilityReason)" } else { 'not usable' }) }
                }
            }
        } catch {
            $m = "$($_.Exception.Message)"
            if ($m -match '(?i)\b404\b|Request_ResourceNotFound|does not exist') { $e.detail = 'account not found in the directory (not yet created?)' }
            elseif (Get-Command Test-PimTenantSyncPermissionError -ErrorAction SilentlyContinue) {
                if (Test-PimTenantSyncPermissionError -Message $m) { throw "PERMISSION: UserAuthenticationMethod.Read.All is not granted to the engine identity ($m)" }
                $e.detail = "the engine could not read it: $((($m -split "`n")[0]).Trim())"
            } else { $e.detail = "the engine could not read it: $((($m -split "`n")[0]).Trim())" }
        }
        $acc[$k] = [pscustomobject]$e
    }
    return [pscustomobject][ordered]@{ refreshedUtc = (Get-PimEngineNow); accounts = [pscustomobject]$acc }
}

function Get-PimEngineDemoGroupFact {
    # ENGINE. kind 'demo-group' -- the demo guest group's id and its (transitive) user members, only while demo mode is on.
    if (-not (Get-Command Test-PimDemoModeValue -ErrorAction SilentlyContinue)) {
        $dm = Join-Path $PSScriptRoot 'PIM-DemoMode.ps1'; if (Test-Path -LiteralPath $dm) { . $dm }
    }
    # Read while demo mode is on, and for the name a SuperAdmin is about to switch it on with (pim.Settings
    # 'DemoGuestGroupCheck', written by PUT /api/settings/demo-mode) -- so switching it on never waits on itself.
    $rawOn = Get-PimEngineFactSetting -Name 'DemoMode'; $rawGroup = Get-PimEngineFactSetting -Name 'DemoGuestGroup'
    $rawCheck = "$(Get-PimEngineFactSetting -Name 'DemoGuestGroupCheck')".Trim().Trim('"')
    $on = $false; $grp = 'Invardia-Demo-Guests'
    if (Get-Command Test-PimDemoModeValue -ErrorAction SilentlyContinue) { $on = [bool](Test-PimDemoModeValue -Value $rawOn); $grp = Resolve-PimDemoGuestGroupName -Value $rawGroup }
    if ($rawCheck -and -not $on) { $grp = $(if (Get-Command Resolve-PimDemoGuestGroupName -ErrorAction SilentlyContinue) { Resolve-PimDemoGuestGroupName -Value $rawCheck } else { $rawCheck }) }
    $out = [ordered]@{ on = $on; group = "$grp"; ok = $false; id = ''; members = @(); error = ''; refreshedUtc = (Get-PimEngineNow) }
    if (-not $on -and -not $rawCheck) { return [pscustomobject]$out }
    try {
        $gid = ''
        if ("$grp" -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { $gid = "$grp".ToLowerInvariant() }
        else {
            $flt = [uri]::EscapeDataString("displayName eq '$("$grp".Replace("'", "''"))'")
            $hits = @(Invoke-PimGraph -Path "/groups?`$filter=$flt&`$select=id,displayName" -All)
            if ($hits.Count -ne 1) { throw ("the demo guest group was found {0} time(s) by its name (expected exactly once)" -f $hits.Count) }
            $gid = "$($hits[0].id)".ToLowerInvariant()
        }
        $mem = @(Invoke-PimGraph -All -Path "/groups/$gid/transitiveMembers/microsoft.graph.user?`$select=id,userPrincipalName,mail,otherMails&`$top=999" |
            ForEach-Object { [pscustomobject]@{ id = "$($_.id)"; userPrincipalName = "$($_.userPrincipalName)"; mail = "$($_.mail)"; otherMails = @($_.otherMails) } })
        $out.ok = $true; $out.id = $gid; $out.members = @($mem)
    } catch { $out.error = "$((($_.Exception.Message -split "`n")[0]).Trim())" }
    return [pscustomobject]$out
}

function Get-PimEngineManagerRecord {
    # The web app's own record (written by the web app at start from its own token; no Graph): appId, objectId, names, ...
    $v = Get-PimEngineFactSetting -Name (Get-PimManagerRuntimeIdentitySettingName)
    if ($null -eq $v) { return [pscustomobject]@{} }
    return $v
}

function Get-PimEngineAppRegistrationsFact {
    # ENGINE. kind 'pim-app-registrations' -- the PIM Activator app registrations by name (Application.Read.All).
    $rec = Get-PimEngineManagerRecord
    $names = @(@(Get-PimRecordedField $rec 'activatorAppNames') | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() } | Select-Object -Unique)
    $apps = [ordered]@{}
    foreach ($nm in $names) {
        $e = [ordered]@{ name = $nm; found = $false; appId = ''; displayName = ''; redirectUris = @(); error = '' }
        try {
            $esc = [uri]::EscapeDataString("displayName eq '$($nm.Replace("'", "''"))'")
            $r = @(Invoke-PimGraph -Path "/applications?`$filter=$esc&`$select=appId,displayName,spa" -All)
            if ($r.Count) { $e.found = $true; $e.appId = "$($r[0].appId)"; $e.displayName = "$($r[0].displayName)"; $e.redirectUris = @($r[0].spa.redirectUris) }
        } catch { $e.error = "$((($_.Exception.Message -split "`n")[0]).Trim())" }
        $apps[$nm.ToLowerInvariant()] = [pscustomobject]$e
    }
    return [pscustomobject][ordered]@{ refreshedUtc = (Get-PimEngineNow); names = @($names); apps = [pscustomobject]$apps }
}

function Get-PimEngineWorkloadRolesFact {
    # ENGINE. kind 'workload-roles' -- each built-in workload connector's live role catalog (the role pickers). A connector
    # that lists per target resource (perRowResource) is not read here: it needs a target the admin names.
    $out = [ordered]@{}
    $dir = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'workloads\connectors'
    if (-not (Get-Command Read-PimWorkloadConnectors -ErrorAction SilentlyContinue)) {
        $wc = Join-Path $PSScriptRoot 'PIM-WorkloadConnectors.ps1'; if (Test-Path -LiteralPath $wc) { . $wc }
    }
    if (-not (Get-Command Read-PimWorkloadConnectors -ErrorAction SilentlyContinue) -or -not (Get-Command Get-PimWorkloadConnectorRoles -ErrorAction SilentlyContinue)) {
        throw 'the workload connector runtime (PIM-WorkloadConnectors.ps1) is not loaded in the engine'
    }
    foreach ($c in @(Read-PimWorkloadConnectors -ConnectorsDir $dir)) {
        if (-not $c -or -not "$($c.id)".Trim() -or $c.perRowResource) { continue }
        $e = [ordered]@{ read = $false; reason = ''; roles = @(); readUtc = (Get-PimEngineNow) }
        try { $e.roles = @(Get-PimWorkloadConnectorRoles -Connector $c); $e.read = $true }
        catch { $e.reason = "$((($_.Exception.Message -split "`n")[0]).Trim())" }
        $out["$($c.id)".ToLowerInvariant()] = [pscustomobject]$e
    }
    return [pscustomobject][ordered]@{ refreshedUtc = (Get-PimEngineNow); connectors = [pscustomobject]$out }
}

function Get-PimEngineDirectoryAnswers {
    <#
      ENGINE. kind 'pim-identities' -- THE RECORDED ANSWERS. The reads the web app's identity, permission-health, mail,
      review and environment-report panels used to make themselves, made here once with the engine's identity
      (Application.Read.All, Directory.Read.All, RoleManagement.Read.All; Reader at the tenant root for Azure) and stored by
      ConvertTo-PimDirectoryAnswerKey. The web replays them (Invoke-PimEngineRecordedGraph / -Arm). Bounded: at most 25
      service principals, 10 subscriptions.
    #>
    $book = New-PimDirectoryAnswerBook
    $sel = 'id,appId,displayName,servicePrincipalType,alternativeNames,tags'
    $graphAppId = '00000003-0000-0000-c000-000000000000'
    $sps = [ordered]@{}   # id -> sp
    $addSp = { param($s) if ($s -and "$($s.id)".Trim()) { $sps["$($s.id)".ToLowerInvariant()] = $s } }
    $rec = Get-PimEngineManagerRecord

    # 1. the engine itself (its own token)
    $eng = [pscustomobject]@{ appId = ''; objectId = ''; tenantId = '' }
    try { $eng = Get-PimIdentityFromClaims -Claims (ConvertFrom-PimEngineFactJwt -Token (Get-PimRestToken -Resource 'graph')) } catch { }
    $engRgPrefix = ''
    if ($eng.objectId) {
        $s = Invoke-PimDirectoryRecordedRead -Book $book -Path "/servicePrincipals/$($eng.objectId)?`$select=$sel"
        if ($s) {
            & $addSp $s
            Add-PimDirectoryAnswer -Book $book -Path "/servicePrincipals?`$filter=appId eq '$($s.appId)'" -Value ([pscustomobject]@{ value = @($s) })
            $rid = @(@($s.alternativeNames) | Where-Object { "$_" -match '^/subscriptions/' }) | Select-Object -First 1
            if ("$rid" -match '(?i)^(/subscriptions/[^/]+/resourcegroups/[^/]+/)') { $engRgPrefix = $Matches[1].ToLowerInvariant() }
        }
    }
    # 2. the web app (its own record) and every product app id either side knows
    $appIds = New-Object System.Collections.Generic.List[string]
    foreach ($a in @((Get-PimRecordedField $rec 'appId'), @(Get-PimRecordedField $rec 'productAppIds'), $global:PIM_ClientId, $global:PIM_EngineClientId, $global:PIM_ManagedIdentityClientId,
                     $global:PIM_ManagerMiAppId, $global:PIM_SqlClientId, $global:PIM_SqlAdminIdentityClientId, $env:AZURE_CLIENT_ID, $graphAppId)) {
        foreach ($a1 in @($a)) { $t = "$a1".Trim().ToLowerInvariant(); if ($t -and -not $appIds.Contains($t)) { $appIds.Add($t) } }
    }
    $webOid = "$(Get-PimRecordedField $rec 'objectId')".Trim().ToLowerInvariant()
    if ($webOid) { $s = Invoke-PimDirectoryRecordedRead -Book $book -Path "/servicePrincipals/$webOid`?`$select=$sel"; & $addSp $s }
    foreach ($a in $appIds) {
        $p = if ($a -eq $graphAppId) { "/servicePrincipals?`$filter=appId eq '$a'&`$select=id,appId,displayName,appRoles" } else { "/servicePrincipals?`$filter=appId eq '$a'&`$select=$sel" }
        $r = Invoke-PimDirectoryRecordedRead -Book $book -Path $p
        foreach ($x in @($r.value)) { if ($a -ne $graphAppId) { & $addSp $x } }
    }
    # 3. the engine identity by its standard names in its resource group (the web panels' fallback when the job cannot be read)
    $engJob = if (Get-Command Get-PimInstallName -ErrorAction SilentlyContinue) { Get-PimInstallName -Role engine } elseif ("$($env:PIM_ENGINE_JOB_NAME)".Trim()) { "$($env:PIM_ENGINE_JOB_NAME)".Trim() } else { 'ca-pim-tick' }
    foreach ($nm in @('id-pim-engine', $engJob, 'id-pim-web', "$(Get-PimRecordedField $rec 'name')") | Where-Object { "$_".Trim() } | Select-Object -Unique) {
        $r = Invoke-PimDirectoryRecordedRead -Book $book -Path "/servicePrincipals?`$filter=displayName eq '$($nm.Replace("'", "''"))'&`$select=$sel"
        foreach ($x in @($r.value)) { if (-not $engRgPrefix -or @(@($x.alternativeNames) | Where-Object { "$_".ToLowerInvariant().StartsWith($engRgPrefix) }).Count) { & $addSp $x } }
    }
    # 4. the Invardia Support app by its tag, and PIM's SQL admin group (by id, by name) with its service-principal members
    $r = Invoke-PimDirectoryRecordedRead -Book $book -Path ("/servicePrincipals?`$filter={0}&`$select=$sel" -f [uri]::EscapeDataString("tags/any(t:t eq 'InvardiaSupport')"))
    foreach ($x in @($r.value)) { & $addSp $x }
    $sqlGrpName = "$(Get-PimRecordedField $rec 'sqlAdminGroupName')".Trim(); if (-not $sqlGrpName) { $sqlGrpName = if (Get-Command Get-PimInstallName -ErrorAction SilentlyContinue) { Get-PimInstallName -Role sqlAdminGroup } else { 'grp-pim-sql-admins' } }
    $sqlGrpIds = New-Object System.Collections.Generic.List[string]
    foreach ($gid0 in @((Get-PimRecordedField $rec 'sqlAdminGroupId'), $env:PIM_SQL_ADMIN_GROUP_ID)) { $t = "$gid0".Trim().ToLowerInvariant(); if ($t -and -not $sqlGrpIds.Contains($t)) { $sqlGrpIds.Add($t) } }
    foreach ($gid0 in @($sqlGrpIds)) { [void](Invoke-PimDirectoryRecordedRead -Book $book -Path "/groups/$gid0`?`$select=id,displayName,securityEnabled") }
    $r = Invoke-PimDirectoryRecordedRead -Book $book -Path ("/groups?`$filter={0}&`$select=id,displayName,securityEnabled" -f [uri]::EscapeDataString("displayName eq '$($sqlGrpName.Replace("'", "''"))'"))
    foreach ($g in @($r.value)) { if ($g -and "$($g.id)".Trim() -and -not $sqlGrpIds.Contains("$($g.id)".ToLowerInvariant())) { $sqlGrpIds.Add("$($g.id)".ToLowerInvariant()) } }
    foreach ($gid0 in @($sqlGrpIds)) {
        $m = Invoke-PimDirectoryRecordedRead -Book $book -Path "/groups/$gid0/members/microsoft.graph.servicePrincipal?`$select=$sel&`$top=999" -All
        foreach ($x in @($m.value)) { & $addSp $x }
    }
    # 5. the Activator apps (by name), their service principals
    foreach ($nm in @(@(Get-PimRecordedField $rec 'activatorAppNames') | Where-Object { "$_".Trim() } | Select-Object -Unique)) {
        $ap = Invoke-PimDirectoryRecordedRead -Book $book -Path ("/applications?`$filter=displayName eq '{0}'&`$select=id,appId,displayName,spa" -f "$nm".Replace("'", "''"))
        foreach ($x in @($ap.value)) {
            if (-not "$($x.appId)".Trim()) { continue }
            $sr = Invoke-PimDirectoryRecordedRead -Book $book -Path "/servicePrincipals?`$filter=appId eq '$($x.appId)'&`$select=$sel"
            foreach ($y in @($sr.value)) { [void](Invoke-PimDirectoryRecordedRead -Book $book -Path "/oauth2PermissionGrants?`$filter=clientId eq '$($y.id)'" -All) }
        }
    }
    # 6. per service principal: its application permissions (+ the other APIs' role names) and its directory roles
    $graphSpId = ''
    $gsp = Get-PimRecordedField (Get-PimRecordedField $book.answers (ConvertTo-PimDirectoryAnswerKey -Path "/servicePrincipals?`$filter=appId eq '$graphAppId'")) 'value'
    if ($gsp) { $g1 = @($gsp.value) | Select-Object -First 1; if ($g1) { $graphSpId = "$($g1.id)"; Add-PimDirectoryAnswer -Book $book -Path "/servicePrincipals/$graphSpId" -Value $g1 } }
    $otherRes = @{}
    foreach ($id in @(@($sps.Keys) | Select-Object -First 25)) {
        $asg = Invoke-PimDirectoryRecordedRead -Book $book -Path "/servicePrincipals/$id/appRoleAssignments" -All
        foreach ($x in @($asg.value)) {
            $rid = "$($x.resourceId)".ToLowerInvariant()
            if ($rid -and $rid -ne $graphSpId.ToLowerInvariant() -and -not $otherRes.ContainsKey($rid)) {
                $otherRes[$rid] = $true; [void](Invoke-PimDirectoryRecordedRead -Book $book -Path "/servicePrincipals/$rid`?`$select=displayName,appRoles")
            }
        }
        [void](Invoke-PimDirectoryRecordedRead -Book $book -Path "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$id'&`$expand=roleDefinition" -All)
    }
    # 7. people the panels name: the mail sender, the break-glass accounts (the web app's record lists them)
    $who = New-Object System.Collections.Generic.List[string]
    foreach ($u in @((Get-PimEngineFactSetting -Name 'MailSender'), "$($global:PIM_MailSender)", @(Get-PimRecordedField $rec 'breakGlassAccounts'))) {
        foreach ($u1 in @($u)) { $t = "$u1".Trim().Trim('"').ToLowerInvariant(); if ($t -match '^[^@\s]+@[^@\s]+$' -and -not $who.Contains($t)) { $who.Add($t) } }
    }
    foreach ($u in @($who | Select-Object -First 30)) { [void](Invoke-PimDirectoryRecordedRead -Book $book -Path ("/users/{0}?`$select=id,displayName,userPrincipalName,mail" -f $u)) }
    # 8. Azure, as the engine (Reader at the tenant root): the role assignments of each PIM identity at its subscription
    #    and at the tenant root management group, the first subscriptions, and the role names they use.
    if (Get-Command Invoke-PimArm -ErrorAction SilentlyContinue) {
        $tid = "$($global:PIM_TenantId)".Trim(); if (-not $tid) { $tid = "$($eng.tenantId)" }
        $subs = Invoke-PimDirectoryRecordedRead -Book $book -Arm -Path '/subscriptions' -ApiVersion '2022-12-01'
        $subIds = New-Object System.Collections.Generic.List[string]
        if ($engRgPrefix -match '^/subscriptions/([^/]+)/') { $subIds.Add($Matches[1]) }
        foreach ($s in @(@($subs.value) | Select-Object -First 10)) { $t = "$($s.subscriptionId)"; if ($t -and -not $subIds.Contains($t)) { $subIds.Add($t) } }
        $roleDefs = @{}
        # bounded: the engine at every listed subscription (permission health's writer-scope verdict); every other PIM
        # identity in the product resource group (or the web app) at its own subscription + the tenant root only
        $armIds = @(@($sps.Keys) | Where-Object {
            $x = $sps[$_]; $_ -eq "$($eng.objectId)" -or $_ -eq $webOid -or
            ($engRgPrefix -and @(@($x.alternativeNames) | Where-Object { "$_".ToLowerInvariant().StartsWith($engRgPrefix) }).Count) } | Select-Object -First 8)
        foreach ($id in $armIds) {
            $mySubs = if ($id -eq "$($eng.objectId)") { @($subIds) } else { @($subIds | Select-Object -First 1) }
            $paths = @(); foreach ($sub in $mySubs) { $paths += "/subscriptions/$sub/providers/Microsoft.Authorization/roleAssignments?`$filter=assignedTo('$id')" }
            if ($tid) { $paths += "/providers/Microsoft.Management/managementGroups/$tid/providers/Microsoft.Authorization/roleAssignments?`$filter=assignedTo('$id')" }
            foreach ($p in $paths) {
                $ra = Invoke-PimDirectoryRecordedRead -Book $book -Arm -Path $p
                foreach ($x in @($ra.value)) { $rd = "$($x.properties.roleDefinitionId)"; if ($rd -and -not $roleDefs.ContainsKey($rd.ToLowerInvariant())) { $roleDefs[$rd.ToLowerInvariant()] = $rd } }
            }
        }
        foreach ($rd in @(@($roleDefs.Values) | Select-Object -First 40)) { [void](Invoke-PimDirectoryRecordedRead -Book $book -Arm -Path $rd) }
    }
    $okN = @($book.answers.Values | Where-Object { $_.ok }).Count
    return [pscustomobject][ordered]@{
        refreshedUtc = (Get-PimEngineNow); recordedBy = [ordered]@{ objectId = "$($eng.objectId)"; appId = "$($eng.appId)" }
        engineObjectId = "$($eng.objectId)"; webObjectId = $webOid; graphServicePrincipalId = $graphSpId
        answered = $okN; refused = (@($book.answers.Keys).Count - $okN)
        answers = [pscustomobject]$book.answers; objects = [pscustomobject]$book.objects
    }
}

function Invoke-PimEngineAdminImportReads {
    <# ENGINE. kind 'admin-import-reads' -- for each account an admin pressed "Import" on (pim.Settings 'AdminImportRequests'):
       the account's profile (User.Read.All via the engine) and its own PIM-for-Groups schedules, with the PIM groups'
       names. Kept per account; the request list is emptied once read. The web app builds the import preview from it. #>
    $reqs = @(@(Get-PimEngineFactSetting -Name (Get-PimAdminImportRequestSettingName)) | Where-Object { $_ })
    $prev = $null; try { $prev = Get-PimTenantCacheEntry -Kind 'admin-import-reads' } catch { $prev = $null }
    $acc = [ordered]@{}
    if ($prev -and $prev.PSObject.Properties['accounts'] -and $prev.accounts) { foreach ($p in @($prev.accounts.PSObject.Properties)) { $acc[$p.Name] = $p.Value } }
    foreach ($q in $reqs) {
        $upn = "$(if ($q -is [string]) { $q } else { $q.upn })".Trim().ToLowerInvariant()
        if ($upn -notmatch '^[^@\s]+@[^@\s]+$') { continue }
        $e = [ordered]@{ upn = $upn; readUtc = (Get-PimEngineNow); found = $false; user = $null; eligible = @(); active = @(); groupNames = [ordered]@{}; error = ''; membershipError = '' }
        try {
            $e.user = Invoke-PimGraph -Path ("/users/{0}?`$select=id,userPrincipalName,givenName,surname,displayName,department,companyName,usageLocation,userType,accountEnabled" -f [uri]::EscapeDataString($upn))
            $e.found = [bool]"$($e.user.id)"
        } catch { $m = "$($_.Exception.Message)"; $e.error = $(if ($m -match 'Request_ResourceNotFound|404') { 'not-found' } else { (($m -split "`n")[0]).Trim() }) }
        if ($e.found) {
            try {
                $uid = "$($e.user.id)"
                $e.eligible = @(Invoke-PimGraph -All -Path ("/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=principalId eq '{0}'" -f $uid))
                $e.active = @(Invoke-PimGraph -All -Path ("/identityGovernance/privilegedAccess/group/assignmentSchedules?`$filter=principalId eq '{0}'" -f $uid))
                foreach ($gid in @(@($e.eligible) + @($e.active) | ForEach-Object { "$($_.groupId)".Trim().ToLowerInvariant() } | Where-Object { $_ } | Select-Object -Unique)) {
                    try { $e.groupNames[$gid] = "$((Invoke-PimGraph -Path "/groups/$gid`?`$select=displayName").displayName)" } catch { }
                }
            } catch { $e.membershipError = (("$($_.Exception.Message)" -split "`n")[0]).Trim() }
        }
        $acc[$upn] = [pscustomobject]$e
    }
    # keep the newest 50 accounts
    $keep = [ordered]@{}
    foreach ($k in @(@($acc.Keys) | Sort-Object { "$($acc[$_].readUtc)" } -Descending | Select-Object -First 50)) { $keep[$k] = $acc[$k] }
    if ($reqs.Count) {
        $cs = Get-PimEngineFactStoreCs
        if ($cs -and (Get-Command Set-PimSqlSetting -ErrorAction SilentlyContinue)) {
            # a request list that cannot be emptied is SAID (the accounts are read again next run -- harmless, but visible)
            try { Set-PimSqlSetting -ConnectionString $cs -Name (Get-PimAdminImportRequestSettingName) -ValueJson '[]' | Out-Null }
            catch { Write-Warning ("  [tenant-cache] admin-import: the request list was not emptied ({0}) -- those accounts are read again on the next run" -f $_.Exception.Message) }
        }
    }
    return [pscustomobject][ordered]@{ refreshedUtc = (Get-PimEngineNow); accounts = [pscustomobject]$keep }
}
