#Requires -Version 5.1
<#
.SYNOPSIS
    71.18 -- THE ONE-SHOT MSP BUILD (pure core). Decides, for an MSP MASTER (S3) or a MANAGED tenant (S6, locally hosted
    pull), every step that made the EFIF -> RIDE test pair work, in order, with the exact script and arguments. The runner
    is tools/setup/Invoke-PimMspBuild.ps1; offline-tested by tests/Test-PimMspBuild.ps1.

.DESCRIPTION
    Operator 2026-09-15: "did you update the setup scripts so it includes all additions/fixes. on friday we must use it to
    build efif and ride in prod". The audit that day found the build spread over four entry points, none end to end:
    Invoke-PimDeployAll.ps1 (hosting only), the phased onboarding script (three phases broken; deleted 2026-09-18, SEC-27),
    the framework estate build (test tenants only), and hand steps -- the scenario setting, registering the managed tenant
    on the master (SQL), publishing and scheduling the signed bundle, the pull job, the weekly read-link rotation, the tick
    and Manager Graph roles on an existing environment, the Manager's right to start the tick, and the SQL admin group
    membership of the tick and Manager identities.

    This file is PURE: no az, no SQL, no network. It validates a machine-local build config (ids and names only -- a
    config that carries a secret is REFUSED) and returns the plan. Values that only exist at run time (a managed identity
    object id, the minted read link) are PLACEHOLDERS the runner resolves: {{mi-job:<name>}}, {{mi-app:<name>}},
    {{step:<id>}} (the pipeline output of an earlier step), {{pem:deploy}} (a per-run certificate PEM).

    NO SECRET, EVER. The build runs as a CERTIFICATE identity (deployIdentity) or as the SIGNED-IN az user (no
    deployIdentity, 71.33); the environments it builds run as managed identities. No step is given a client secret, an
    account key or a SAS. The managed tenant pulls the bundle PUBLIC-BUT-SIGNED (71.34, DESIGN 13.7): a plain blob URL,
    reachable only from the networks the master's storage firewall names, trusted only because the signature verifies.
    71.35: the master PUBLISHES from a Container Apps job (ca-pim-publish) as its managed identity, signing with a
    non-exportable Key Vault key; the managed tenant PINS that key's id (master.signingKeyIds), taken from the master's
    build output.

    Operator steps (a decision or a human) are returned separately, each with the exact command: the first-run policy
    mass-change approval is DELIBERATELY not automated.
#>

$script:PimMspBuildSecretKey = '(?i)(secret|password|passwd|pwd|sasurl|accountkey|connectionstring|privatekey|pem$)'
$script:PimMspGuid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

function Get-PimMspBuildValue {
    # PURE. Read a (possibly nested, dotted) key from a hashtable / PSCustomObject config. Missing -> $null.
    param([object]$Object, [Parameter(Mandatory)][string]$Path)
    $cur = $Object
    foreach ($seg in ($Path -split '\.')) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) { $cur = if ($cur.Contains($seg)) { $cur[$seg] } else { $null } }
        else { $p = $cur.PSObject.Properties[$seg]; $cur = if ($p) { $p.Value } else { $null } }
    }
    return $cur
}

function Find-PimMspBuildSecretKeys {
    # PURE. Every key path in the config whose NAME says it holds a credential. A certificate THUMBPRINT is an identifier
    # (allowed); a secret, password, account key, SAS URL, connection string or PEM is not.
    param([object]$Object, [string]$Prefix = '')
    $hits = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Object -or $Object -is [string] -or $Object -is [ValueType]) { return @() }
    if ($Object -is [System.Collections.IEnumerable] -and -not ($Object -is [System.Collections.IDictionary])) {
        $i = 0; foreach ($e in $Object) { foreach ($h in @(Find-PimMspBuildSecretKeys -Object $e -Prefix "$Prefix[$i]")) { $hits.Add($h) }; $i++ }
        return @($hits.ToArray())
    }
    $names = if ($Object -is [System.Collections.IDictionary]) { @($Object.Keys) } else { @($Object.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($n in $names) {
        $path = if ($Prefix) { "$Prefix.$n" } else { "$n" }
        if ("$n" -match $script:PimMspBuildSecretKey -and "$n" -notmatch '(?i)thumbprint|keyvaultname') { $hits.Add($path) }
        $v = if ($Object -is [System.Collections.IDictionary]) { $Object[$n] } else { $Object.$n }
        # a VALUE that is a credential whatever its key is called: a SAS signature, an account key, a PEM
        if ($v -is [string] -and $v -match '(?i)([?&]sig=|AccountKey=|SharedAccessKey=|-----BEGIN [A-Z ]*PRIVATE KEY)') { $hits.Add("$path (value)") }
        foreach ($h in @(Find-PimMspBuildSecretKeys -Object $v -Prefix $path)) { $hits.Add($h) }
    }
    return @($hits.ToArray())
}

function ConvertTo-PimTenantTags {
    # PURE. Normalise a tenant's tags (array or ';'/','-separated) to the stored form: lower-case, trimmed, de-duplicated,
    # sorted, joined with ';'. A tag is <word>[:<word>] of letters, digits, '-', '_' and '.'. Returns @{ ok; value; bad }.
    param([object]$Tags)
    $raw = @()
    if ($null -eq $Tags) { $raw = @() }
    elseif ($Tags -is [string]) { $raw = @("$Tags" -split '[;,]') }
    else { $raw = @($Tags | ForEach-Object { "$_" -split '[;,]' }) }
    $seen = @{}; $bad = New-Object System.Collections.Generic.List[string]
    foreach ($t in $raw) {
        $x = "$t".Trim().ToLowerInvariant()
        if (-not $x) { continue }
        if ($x -notmatch '^[a-z0-9][a-z0-9_.\-]*(:[a-z0-9][a-z0-9_.\-]*)?$') { $bad.Add("$t".Trim()); continue }
        # REQ-N: the words a replication Target reserves are not tenant tags ('all' / 'none' are Target keywords; a
        # 'tag:' or 'tenant:' key would be read as a Target prefix). One rule for the script, the build and the Manager.
        if ($x -in @('all', 'none') -or $x -like 'tag:*' -or $x -like 'tenant:*') { $bad.Add("$t".Trim()); continue }
        $seen[$x] = $true
    }
    $vals = @($seen.Keys | Sort-Object)
    return @{ ok = ($bad.Count -eq 0); value = ($vals -join ';'); tags = $vals; bad = @($bad.ToArray()) }
}

$script:PimSubnetIdPattern = '^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[^/]+/providers/Microsoft\.Network/virtualNetworks/[^/]+/subnets/[^/]+$'

function Test-PimBaselineNetworkSource {
    <#
      PURE. 71.34 -- is -Value an allowable source for the bundle store's network rules? Returns @{ ok; kind; value; reason }.
        subnet : a fully qualified subnet resource id (it may live in ANOTHER tenant -- Azure accepts that by id).
        ip     : a PUBLIC IPv4 address or a CIDR range /0../30. Refused, as Azure refuses them: private (RFC 1918) ranges,
                 /31 and /32 CIDR (give the single address instead), anything that is not IPv4.
    #>
    param([string]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return @{ ok = $false; kind = ''; value = ''; reason = 'empty network source' } }
    if ($v -match '^/subscriptions/') {
        if ($v -notmatch $script:PimSubnetIdPattern) { return @{ ok = $false; kind = 'subnet'; value = $v; reason = "'$v' is not a subnet resource id (/subscriptions/<id>/resourceGroups/<rg>/providers/Microsoft.Network/virtualNetworks/<vnet>/subnets/<subnet>)" } }
        return @{ ok = $true; kind = 'subnet'; value = $v; reason = '' }
    }
    if ($v -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/(\d{1,2}))?$') { return @{ ok = $false; kind = 'ip'; value = $v; reason = "'$v' is neither a subnet resource id nor an IPv4 address/range" } }
    $o = @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4])
    if (@($o | Where-Object { $_ -gt 255 }).Count) { return @{ ok = $false; kind = 'ip'; value = $v; reason = "'$v' is not a valid IPv4 address" } }
    if ($Matches[6] -and ([int]$Matches[6] -gt 30)) { return @{ ok = $false; kind = 'ip'; value = $v; reason = "'$v': Azure Storage does not accept /31 or /32 ranges -- give the single address" } }
    if ($o[0] -eq 10 -or ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) -or ($o[0] -eq 192 -and $o[1] -eq 168) -or $o[0] -eq 127) {
        return @{ ok = $false; kind = 'ip'; value = $v; reason = "'$v' is a PRIVATE address -- storage IP rules accept public internet addresses only (use the subnet id for traffic from a virtual network)" }
    }
    return @{ ok = $true; kind = 'ip'; value = $v; reason = '' }
}

function Get-PimBaselinePullUrl {
    # PURE. 71.34 -- the plain HTTPS address a managed tenant pulls: no query string, no credential, nothing that expires.
    param([Parameter(Mandatory)][string]$StorageAccount, [string]$Container = 'baselines', [string]$Blob = 'baseline-latest.json')
    return ('https://{0}.blob.core.windows.net/{1}/{2}' -f "$StorageAccount".Trim().ToLowerInvariant(), "$Container".Trim(), "$Blob".Trim())
}

function Get-PimBaselineNetworkPlan {
    <#
      PURE. 71.34 -- what to change on the MASTER's bundle store so it is PUBLIC-BUT-SIGNED for exactly the named networks.
      -Current: @{ defaultAction; allowBlobPublicAccess; containerPublicAccess; subnetIds[]; ipRules[] } as read from ARM.
      -SubnetIds / -IpAddresses: the sources to ADD (or, with -Remove, to take away). Nothing else is ever removed.
      -EnsurePosture: also make it anonymous-read for blobs only (no listing) and default-action Deny.
      Returns @{ ok; reason; actions = @(@{ op; value }) } in apply order: rule adds, rule removes, posture, Deny LAST.
      REFUSED: an invalid source; and a Deny that would leave NO allowed network at all (it would lock out the publisher).
    #>
    param([Parameter(Mandatory)][object]$Current, [string[]]$SubnetIds = @(), [string[]]$IpAddresses = @(), [switch]$Remove, [switch]$EnsurePosture)
    $haveSub = @{}; foreach ($x in @($Current.subnetIds)) { if ("$x".Trim()) { $haveSub["$x".Trim().ToLowerInvariant()] = $true } }
    $haveIp = @{};  foreach ($x in @($Current.ipRules))   { if ("$x".Trim()) { $haveIp["$x".Trim()] = $true } }
    $actions = New-Object System.Collections.Generic.List[object]
    foreach ($s in @($SubnetIds | Where-Object { "$_".Trim() })) {
        $c = Test-PimBaselineNetworkSource -Value $s
        if (-not $c.ok -or $c.kind -ne 'subnet') { return @{ ok = $false; reason = $(if ($c.reason) { $c.reason } else { "'$s' is not a subnet resource id" }); actions = @() } }
        $k = $c.value.ToLowerInvariant()
        if ($Remove) { if ($haveSub.ContainsKey($k)) { $actions.Add(@{ op = 'remove-subnet'; value = $c.value }); $haveSub.Remove($k) } }
        elseif (-not $haveSub.ContainsKey($k)) { $actions.Add(@{ op = 'add-subnet'; value = $c.value }); $haveSub[$k] = $true }
    }
    foreach ($p in @($IpAddresses | Where-Object { "$_".Trim() })) {
        $c = Test-PimBaselineNetworkSource -Value $p
        if (-not $c.ok -or $c.kind -ne 'ip') { return @{ ok = $false; reason = $(if ($c.reason) { $c.reason } else { "'$p' is not an IP address" }); actions = @() } }
        if ($Remove) { if ($haveIp.ContainsKey($c.value)) { $actions.Add(@{ op = 'remove-ip'; value = $c.value }); $haveIp.Remove($c.value) } }
        elseif (-not $haveIp.ContainsKey($c.value)) { $actions.Add(@{ op = 'add-ip'; value = $c.value }); $haveIp[$c.value] = $true }
    }
    if ($EnsurePosture) {
        if (-not [bool]$Current.allowBlobPublicAccess) { $actions.Add(@{ op = 'allow-blob-public-access'; value = 'true' }) }
        if ("$($Current.containerPublicAccess)".Trim().ToLowerInvariant() -ne 'blob') { $actions.Add(@{ op = 'container-public-access'; value = 'blob' }) }
        if ("$($Current.defaultAction)".Trim() -ne 'Deny') {
            if (($haveSub.Count + $haveIp.Count) -eq 0) {
                return @{ ok = $false; reason = 'REFUSED: default-action Deny with NO allowed network would lock out every reader AND the publisher -- name at least one subnet or IP first'; actions = @() }
            }
            $actions.Add(@{ op = 'default-deny'; value = 'Deny' })
        }
    }
    if ($Remove -and ("$($Current.defaultAction)".Trim() -eq 'Deny') -and ($haveSub.Count + $haveIp.Count) -eq 0) {
        return @{ ok = $false; reason = 'REFUSED: removing this rule would leave the bundle store with NO allowed network (the publisher would be locked out too) -- add the publisher''s rule first'; actions = @() }
    }
    return @{ ok = $true; reason = ''; actions = @($actions.ToArray()) }
}

function Get-PimPullSubnetEndpointPlan {
    <#
      PURE. 71.34 -- the managed tenant's side: its Container Apps subnet must carry the Azure Storage service endpoint so
      the master's storage sees the traffic as coming FROM THAT SUBNET (which is what its VNet rule allows).
      -Current: the subnet's service endpoint names. -Want: Microsoft.Storage (master storage in the same region) or
      Microsoft.Storage.Global (any region). A subnet can carry only ONE of the two, so the other one already present is
      REFUSED rather than replaced (replacing it could cut something else on that subnet off its storage).
      Returns @{ action = 'none'|'add'|'refuse'; endpoints; reason }. 'add' carries the MERGED list (--service-endpoints replaces).
    #>
    param([string[]]$Current = @(), [Parameter(Mandatory)][ValidateSet('Microsoft.Storage', 'Microsoft.Storage.Global')][string]$Want)
    $cur = @($Current | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($cur -contains $Want) { return @{ action = 'none'; endpoints = $cur; reason = "the subnet already carries $Want" } }
    $other = if ($Want -eq 'Microsoft.Storage') { 'Microsoft.Storage.Global' } else { 'Microsoft.Storage' }
    if ($cur -contains $other) {
        return @{ action = 'refuse'; endpoints = $cur; reason = ("the subnet already carries $other, and a subnet can hold only one of Microsoft.Storage / Microsoft.Storage.Global. " +
                  $(if ($other -eq 'Microsoft.Storage') { "It works as-is IF the master's storage is in the SAME region -- set baselineServiceEndpoint to Microsoft.Storage. " } else { "Microsoft.Storage.Global already covers every region -- set baselineServiceEndpoint to Microsoft.Storage.Global. " }) +
                  'Not replaced automatically: another workload on this subnet may depend on it.') }
    }
    return @{ action = 'add'; endpoints = @($cur + $Want); reason = "adding $Want to the subnet's service endpoints" }
}

function Test-PimPrivateIPv4 {
    # PURE. 71.36 -- an RFC 1918 IPv4 address (a private endpoint's address), no CIDR.
    param([string]$Value)
    $v = "$Value".Trim()
    if ($v -notmatch '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') { return $false }
    $o = @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4])
    if (@($o | Where-Object { $_ -gt 255 }).Count) { return $false }
    return ($o[0] -eq 10 -or ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) -or ($o[0] -eq 192 -and $o[1] -eq 168))
}

function Get-PimBaselineAccessMode {
    <#
      PURE. 71.36 -- HOW a managed tenant reaches the master's bundle store, decided by the config alone:
        publicSigned    (default, 71.34) anonymous blob read on the public endpoint, storage firewall Deny + a VNet rule per
                        managed tenant subnet (service endpoints). For networks that are NOT connected to each other.
        privateEndpoint (operator 2026-09-17) public network access DISABLED, one private endpoint in the master's VNet,
                        managed tenants reach it over VNet peering and resolve it through their OWN private DNS zone.
      Master: baseline.access. Managed tenant: master.access, or implied by master.privateEndpointIp.
    #>
    param([Parameter(Mandatory)][ValidateSet('Master','Slave')][string]$Role, [Parameter(Mandatory)][object]$Config)
    $raw = if ($Role -eq 'Master') { "$(Get-PimMspBuildValue -Object $Config -Path 'baseline.access')".Trim() } else { "$(Get-PimMspBuildValue -Object $Config -Path 'master.access')".Trim() }
    if (-not $raw -and $Role -eq 'Slave' -and "$(Get-PimMspBuildValue -Object $Config -Path 'master.privateEndpointIp')".Trim()) { return 'privateEndpoint' }
    if (-not $raw) { return 'publicSigned' }
    return $raw
}

function Test-PimMspPrivateStore {
    # PURE. 71.36 -- is this environment's SQL store PRIVATE (private endpoint, public access closed after the build)?
    # -Exposure internal turns the SQL private endpoint on in the hosting step, so the build must close public access too.
    param([Parameter(Mandatory)][object]$Config)
    $e = "$(Get-PimMspBuildValue -Object $Config -Path 'exposure')".Trim()
    $explicit = Get-PimMspBuildValue -Object $Config -Path 'sql.private'
    if ($null -ne $explicit -and "$explicit".Trim()) { return [bool]("$explicit" -match '^(?i)(true|1|yes)$') }
    return ($e -eq 'internal')
}

function Test-PimSqlBuildWindowState {
    <#
      PURE. 71.36 -- is the store's build window CLOSED, as read back from ARM?
      -State @{ publicNetworkAccess; firewallRules[]; vnetRules[]; privateEndpoints[] }.
        private-endpoint shape (privateEndpoints non-empty): publicNetworkAccess must be Disabled.
        VNet-only shape: NO firewall rule at all (no AllowSetupHost, no AllowAzureServices, nothing else) and at least one
        virtual network rule (the environment's own subnet) -- the public endpoint then admits that subnet only.
      Returns @{ ok; reasons[]; summary }.
    #>
    param([Parameter(Mandatory)][hashtable]$State, [ValidateSet('Closed')][string]$Want = 'Closed')
    $r = New-Object System.Collections.Generic.List[string]
    $pes = @($State.privateEndpoints | Where-Object { "$_".Trim() }); $fw = @($State.firewallRules | Where-Object { "$_".Trim() }); $vr = @($State.vnetRules | Where-Object { "$_".Trim() })
    if ($pes.Count) {
        if ("$($State.publicNetworkAccess)" -ne 'Disabled') { $r.Add("publicNetworkAccess is '$($State.publicNetworkAccess)', want Disabled (the server has a private endpoint)") }
        $sum = 'private endpoint only (public network access Disabled)'
    } else {
        if ($fw.Count) { $r.Add("firewall rule(s) still present: $($fw -join ', ')") }
        if (-not $vr.Count) { $r.Add('no virtual network rule -- the environment could not reach its own database') }
        $sum = "public endpoint admits ONLY the virtual network rule(s) $($vr -join ', ') (no IP rule, no Azure-services rule)"
    }
    return @{ ok = ($r.Count -eq 0); reasons = @($r.ToArray()); summary = $sum }
}

function Get-PimBaselinePrivateDnsPlan {
    <#
      PURE. 71.36 -- the managed tenant's A record for the master store in its own privatelink.blob.core.windows.net zone must
      hold EXACTLY the master's private endpoint IP. Returns @{ actions = @(@{ op = 'add'|'remove'; ip }); summary }.
      Add first, then remove stale ones (never leaves the name without an address mid-change).
    #>
    param([string[]]$CurrentIps = @(), [Parameter(Mandatory)][string]$WantIp)
    $want = "$WantIp".Trim()
    $cur = @($CurrentIps | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Select-Object -Unique)
    $acts = New-Object System.Collections.Generic.List[object]
    if ($cur -notcontains $want) { $acts.Add(@{ op = 'add'; ip = $want }) }
    foreach ($c in $cur) { if ($c -ne $want) { $acts.Add(@{ op = 'remove'; ip = $c }) } }
    $sum = if (-not $acts.Count) { "already exactly $want" } else { (@($acts | ForEach-Object { "$($_.op) $($_.ip)" }) -join ', ') }
    return @{ actions = @($acts.ToArray()); summary = $sum }
}

function Test-PimBaselinePrivateEndpointState {
    <#
      PURE. 71.36 -- verdict on the master store's private-endpoint posture as READ BACK from ARM:
      @{ publicNetworkAccess; allowBlobPublicAccess; containerPublicAccess; endpointIp; dnsRecordIps[]; linkResolutionPolicy;
         linkVnetId; expectedVnetId } -> @{ ok; reasons[]; lines[] }.
    #>
    param([Parameter(Mandatory)][hashtable]$State)
    $r = New-Object System.Collections.Generic.List[string]; $l = New-Object System.Collections.Generic.List[string]
    $chk = {
        param($name, $ok, $got, $want)
        $l.Add(("{0,-28} {1,-30} {2}" -f $name, "$got", $(if ($ok) { 'OK' } else { "FAIL (want $want)" })))
        if (-not $ok) { $r.Add("$name is '$got', want $want") }
    }
    & $chk 'publicNetworkAccess' ("$($State.publicNetworkAccess)" -eq 'Disabled') $State.publicNetworkAccess 'Disabled'
    & $chk 'allowBlobPublicAccess' ([bool]$State.allowBlobPublicAccess) $State.allowBlobPublicAccess 'True (anonymous blob read; no cross-tenant identity exists for the pull)'
    & $chk 'container publicAccess' ("$($State.containerPublicAccess)" -ieq 'Blob') $State.containerPublicAccess 'Blob (no listing)'
    $ip = "$($State.endpointIp)".Trim()
    & $chk 'private endpoint IP' (Test-PimPrivateIPv4 -Value $ip) $ip 'a private IPv4'
    $recs = @($State.dnsRecordIps | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    & $chk 'zone A record' ($recs.Count -eq 1 -and $recs[0] -eq $ip) ($recs -join ',') "exactly $ip"
    & $chk 'zone link resolution' ("$($State.linkResolutionPolicy)" -eq 'NxDomainRedirect') $State.linkResolutionPolicy 'NxDomainRedirect'
    & $chk 'zone link VNet' ("$($State.linkVnetId)".Trim() -and "$($State.linkVnetId)" -ieq "$($State.expectedVnetId)") (($("$($State.linkVnetId)" -split '/')[-1])) ($("$($State.expectedVnetId)" -split '/')[-1])
    return @{ ok = ($r.Count -eq 0); reasons = @($r.ToArray()); lines = @($l.ToArray()) }
}

function Get-PimManagedTenantRegistration {
    <#
      PURE. The registration of ONE managed tenant on the master (platform.Tenants): validated values + the parameterised
      MERGE. Replaces the documented hand SQL ("no product command registers a managed tenant", §71 gap 2).
      Ring 0..2 (0 = dev, 1 = test, 2 = broad -- §77.20). Tags as ConvertTo-PimTenantTags. Returns @{ ok; reason; sql; parameters }.
    #>
    param(
        [string]$TenantId,
        [string]$DisplayName,
        [int]$Ring = 0,
        [object]$Tags,
        [bool]$Enabled = $true,
        [string]$Notes = ''
    )
    $tid = "$TenantId".Trim()
    if ($tid -notmatch $script:PimMspGuid) { return @{ ok = $false; reason = "TenantId '$TenantId' is not a GUID" } }
    if (-not "$DisplayName".Trim()) { return @{ ok = $false; reason = 'DisplayName is required (it is what the Manager lists)' } }
    if ($Ring -lt 0 -or $Ring -gt 2) { return @{ ok = $false; reason = "Ring $Ring is outside 0..2 (0 = dev, 1 = test, 2 = broad)" } }
    $tg = ConvertTo-PimTenantTags -Tags $Tags
    if (-not $tg.ok) { return @{ ok = $false; reason = "malformed tag(s): $($tg.bad -join ', ') -- use word or key:value (letters, digits, - _ .); 'all', 'none', 'tag:...' and 'tenant:...' are reserved by the replication Target" } }
    $sql = @"
MERGE platform.Tenants AS t
USING (SELECT CONVERT(uniqueidentifier, @tid) AS TenantId) AS s ON t.TenantId = s.TenantId
WHEN MATCHED THEN UPDATE SET DisplayName = @name, Ring = @ring, Enabled = @enabled, Tags = @tags, Notes = @notes, UpdatedAtUtc = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (TenantId, DisplayName, Ring, Enabled, Tags, Notes) VALUES (s.TenantId, @name, @ring, @enabled, @tags, @notes);
"@
    return @{
        ok = $true; reason = ''
        sql = $sql
        parameters = [ordered]@{ tid = $tid.ToLowerInvariant(); name = "$DisplayName".Trim(); ring = [int]$Ring; enabled = [int][bool]$Enabled; tags = $tg.value; notes = "$Notes" }
        tags = $tg.tags
    }
}

function Get-PimMspBuildAuthMode {
    <#
      PURE. 71.33 -- WHO the build runs as, decided by the config and nothing else (one source, no second switch to
      disagree with it):
        Certificate -- 'deployIdentity' is present: az logs in as that application by certificate (the MSP management
                       host's automation pattern; mgmt1 and the EFIF/RIDE build).
        SignedIn    -- no 'deployIdentity': the administrator signed in to az (az login) IS the deploy identity. The
                       customer's pattern. No certificate, no secret, nothing credential-shaped written anywhere.
    #>
    param([Parameter(Mandatory)][object]$Config)
    $di = Get-PimMspBuildValue -Object $Config -Path 'deployIdentity'
    if ($null -eq $di) { return 'SignedIn' }
    if ($di -is [string] -and -not "$di".Trim()) { return 'SignedIn' }
    return 'Certificate'
}

function Get-PimMspBuildUpdateRing {
    <#
      PURE. BUG-162 -- WHICH UPDATE RING THIS BUILD ASKS FOR, said out loud instead of cast.
      The plan used to build the hosting step with `UpdateRing = [int](& $V 'updater.ring')`, and
      [int]$null is 0 -- so a config with no 'updater.ring' silently asked for RING 0, the ring that
      takes every build. A cast is not a decision: the three cases are different and each is stated.
        'updater.ring' 0..3     -> that ring, source 'config'
        absent / empty          -> the DOCUMENTED default ring 2 (the safe customer ring), source 'default'
        anything else           -> THROW, naming the value. Never 0 by accident, never guessed.
      Returns { ring; source; message }. Test-PimMspBuildConfig still REFUSES a config without a ring;
      this exists so the plan cannot invent one behind that check either.
    #>
    param([Parameter(Mandatory)][object]$Config)
    $raw = Get-PimMspBuildValue -Object $Config -Path 'updater.ring'
    $s = "$raw".Trim()
    if (-not $s) {
        return [pscustomobject]@{ ring = 2; source = 'default'
            message = "no 'updater.ring' in the build config -- applying the DOCUMENTED default ring 2 (the safe customer ring). Internal and test environments set 'updater': { 'ring': 1 }." }
    }
    if ($s -notmatch '^(?i)(ring)?([0-3])$') {
        throw ("Get-PimMspBuildUpdateRing: 'updater.ring' is '$s', which is not a ring (0..3). REFUSING to guess one -- " +
               'a wrong ring approves a different VERSION, which is how an environment rolls somewhere nobody asked for.')
    }
    $r = [int]$Matches[2]
    [pscustomobject]@{ ring = $r; source = 'config'; message = "update ring $r (from the build config)" }
}

function Test-PimMspBuildConfig {
    <#
      PURE. Validate a build config for one role. Returns @{ ok; errors; warnings; authMode }.
      Required (both roles): tenantId, subscriptionId, resourceGroup, location, token, sqlServerName, acrName, envName,
      managerSuperAdmins, updater.ring. (The release feed URL is a credential and comes from $env:PIM_UPDATE_SOURCE_URL
      at run time, never from the file.)
      deployIdentity.clientId + deployIdentity.certThumbprint: OPTIONAL since 71.33. Present = certificate mode (then both
      are required and validated exactly as before); absent = signed-in mode (Get-PimMspBuildAuthMode).
      Master: baseline.storageAccount; slaves[] each tenantId + displayName (+ ring, tags).
      Slave : adminPrefixes; master.tenantId, master.subscriptionId, master.storageAccount; master.deployIdentity.* in
              certificate mode (a signed-in slave build never holds the master's certificate -- the steps that need it
              are planned as NOT RUNNABLE, see Get-PimMspBuildPlan).
    #>
    param([Parameter(Mandatory)][ValidateSet('Master','Slave')][string]$Role, [Parameter(Mandatory)][object]$Config)
    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]
    foreach ($k in @(Find-PimMspBuildSecretKeys -Object $Config)) { $errors.Add("REFUSED: '$k' looks like a credential -- a build config holds ids and names only (certificate thumbprints, never secrets)") }
    $V = { param($p) Get-PimMspBuildValue -Object $Config -Path $p }
    $authMode = Get-PimMspBuildAuthMode -Config $Config
    $idPaths = @('tenantId', 'subscriptionId')
    if ($authMode -eq 'Certificate') { $idPaths += 'deployIdentity.clientId' }
    foreach ($p in $idPaths) {
        if ("$(& $V $p)".Trim() -notmatch $script:PimMspGuid) { $errors.Add("'$p' must be a GUID") }
    }
    # NOT updater.sourceUrlTemplate: the release feed URL carries its (policy-backed) SAS, so it never goes in this file --
    # the hosting step takes it from $env:PIM_UPDATE_SOURCE_URL of the session that runs the build (Invoke-PimDeployAll's
    # own default), and the runner refuses to apply without it.
    foreach ($p in 'resourceGroup', 'location', 'token', 'sqlServerName', 'acrName', 'envName', 'managerSuperAdmins') {
        if (-not "$(& $V $p)".Trim()) { $errors.Add("'$p' is required") }
    }
    if ($authMode -eq 'Certificate' -and "$(& $V 'deployIdentity.certThumbprint')".Trim() -notmatch '^[0-9a-fA-F]{40}$') { $errors.Add("'deployIdentity.certThumbprint' must be a 40-hex certificate thumbprint (or remove 'deployIdentity' entirely to build as the signed-in az user)") }
    $ring = & $V 'updater.ring'
    if ($null -eq $ring -or "$ring" -notmatch '^[0-3]$') { $errors.Add("'updater.ring' must be 0..3") }
    # 🔴 71.29 -- FAIL FAST ON THE ADDRESS PLAN. Without it the hosting step's prereq refuses, but only after the
    # keyvault step has already run and ~6 minutes in. The config check is where that must surface: nothing is
    # touched, and the message says exactly which key to add. (Rehearsal 2026-09-17: both sides failed this way.)
    $cidr = "$(& $V 'network.vnetAddressPrefix')".Trim(); $snet = "$(& $V 'network.subnetAddressPrefix')".Trim()
    $idx  = "$(& $V 'network.index')"
    if (-not ($cidr -and $snet) -and $idx -notmatch '^\d+$') {
        $errors.Add("'network' is required: give EITHER 'network.vnetAddressPrefix' + 'network.subnetAddressPrefix' (the customer's own range, e.g. 10.220.104.0/21 + 10.220.104.0/23) OR 'network.index' (the estate scheme <addressBase>.<index*8>.0/21). The hosting step REFUSES to guess -- two environments sharing a CIDR cannot be un-peered.")
    } else {
        foreach ($p in @(@{ n = 'network.vnetAddressPrefix'; v = $cidr }, @{ n = 'network.subnetAddressPrefix'; v = $snet })) {
            if ($p.v -and $p.v -notmatch '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') { $errors.Add("'$($p.n)' is not a CIDR ('$($p.v)')") }
        }
        if ($cidr -xor $snet) { $errors.Add("'network.vnetAddressPrefix' and 'network.subnetAddressPrefix' go together -- give both, or give 'network.index' instead") }
    }
    # 71.36 PRIVATE NETWORKING (same shape as the private customer deployments): exposure, the private-endpoint subnet, the registry, the hub.
    $expo = "$(& $V 'exposure')".Trim()
    if ($expo -and $expo -notin @('internal', 'external')) { $errors.Add("'exposure' must be internal (VNet-internal Container Apps environment, private SQL) or external") }
    $peCidr = "$(& $V 'network.privateEndpointSubnetAddressPrefix')".Trim()
    if ($peCidr -and $peCidr -notmatch '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') { $errors.Add("'network.privateEndpointSubnetAddressPrefix' is not a CIDR ('$peCidr')") }
    $acrSku = "$(& $V 'acr.sku')".Trim(); $acrPub = "$(& $V 'acr.publicAccess')".Trim(); $acrPool = "$(& $V 'acr.agentPoolName')".Trim()
    if ($acrSku -and $acrSku -notin @('Basic', 'Standard', 'Premium')) { $errors.Add("'acr.sku' must be Basic, Standard or Premium") }
    if ($acrPub -and $acrPub -notin @('true', 'false')) { $errors.Add("'acr.publicAccess' must be true or false") }
    if ($acrPub -eq 'false') {
        if ($acrSku -and $acrSku -ne 'Premium') { $errors.Add("'acr.publicAccess' false needs 'acr.sku' Premium (Basic/Standard have no network controls)") }
        if (-not $acrPool) { $errors.Add("'acr.publicAccess' false needs 'acr.agentPoolName': az acr build cannot reach a private registry from ACR's own agents, and the nightly updater builds into it") }
    }
    if ([bool](& $V 'sql.privateEndpoint')) { $warnings.Add("'sql.privateEndpoint' true: the build host must resolve <server>.privatelink.database.windows.net (to the endpoint, or publicly) -- mgmt1's DNS answers NXDOMAIN and every store step then fails with 'No such host is known' (measured 2026-09-17)") }
    if ($expo -eq 'internal') {
        if (-not $peCidr) { $warnings.Add("exposure internal: 'network.privateEndpointSubnetAddressPrefix' not set -- the hosting step REFUSES if the private-endpoint subnet '$(if ("$(& $V 'network.privateEndpointSubnetName')".Trim()) { "$(& $V 'network.privateEndpointSubnetName')".Trim() } else { 'pim-endpoints' })' does not already exist") }
        if (-not "$(& $V 'hub.vnetName')".Trim()) { $warnings.Add("exposure internal with no 'hub.vnetName': the Manager is reachable ONLY from inside its own VNet or a network the operator peers to it (plus DNS for its private zone). The hosted smoke gate cannot run from this host and is skipped -- verify from inside.") }
    }
    $cfgRole = "$(& $V 'role')".Trim()
    if ($cfgRole -and $cfgRole -ine $Role) { $errors.Add("the config says role '$cfgRole' but the build was asked for '$Role'") }
    if ($Role -eq 'Master') {
        if (-not "$(& $V 'baseline.storageAccount')".Trim()) { $errors.Add("'baseline.storageAccount' is required on the master (the signed bundle's store)") }
        $slaves = @(& $V 'slaves')
        if (-not @($slaves | Where-Object { $null -ne $_ }).Count) { $warnings.Add('no slaves[] listed -- the bundle will be published for no managed tenant; register them later with Register-PimManagedTenant.ps1') }
        $i = 0
        foreach ($s in @($slaves | Where-Object { $null -ne $_ })) {
            $r = Get-PimManagedTenantRegistration -TenantId (Get-PimMspBuildValue $s 'tenantId') -DisplayName (Get-PimMspBuildValue $s 'displayName') `
                    -Ring $(if ($null -ne (Get-PimMspBuildValue $s 'ring')) { [int](Get-PimMspBuildValue $s 'ring') } else { 2 }) -Tags (Get-PimMspBuildValue $s 'tags')
            if (-not $r.ok) { $errors.Add("slaves[$i]: $($r.reason)") }
            foreach ($x in @(Get-PimMspBuildValue $s 'subnetResourceId') + @(Get-PimMspBuildValue $s 'egressIp')) {
                if ($null -eq $x -or -not "$x".Trim()) { continue }
                $chk = Test-PimBaselineNetworkSource -Value "$x"
                if (-not $chk.ok) { $errors.Add("slaves[$i]: $($chk.reason)") }
            }
            if ((Get-PimBaselineAccessMode -Role Master -Config $Config) -eq 'publicSigned' -and -not "$(Get-PimMspBuildValue $s 'subnetResourceId')".Trim() -and -not "$(Get-PimMspBuildValue $s 'egressIp')".Trim()) {
                $warnings.Add("slaves[$i] ($(Get-PimMspBuildValue $s 'displayName')): no subnetResourceId / egressIp yet -- its network rule on the bundle store is planned as NOT RUNNABLE until the managed tenant's build prints its subnet id; add it here and re-run -From network-$i")
            }
            $i++
        }
        # 71.35 CLOUD PUBLISH: the publisher is the master's own Container Apps job, so its network is the master's own
        # subnet (the plan allows it on the store before Deny). baseline.publisherSubnetIds / publisherIps are no longer
        # needed; when given they are still validated and still allowed (e.g. a host that publishes during a migration).
        $pubSources = @(@(& $V 'baseline.publisherSubnetIds') + @(& $V 'baseline.publisherIps') | Where-Object { $null -ne $_ -and "$_".Trim() })
        foreach ($x in $pubSources) { $chk = Test-PimBaselineNetworkSource -Value "$x"; if (-not $chk.ok) { $errors.Add("baseline publisher: $($chk.reason)") } }
        # The signing key lives in a Key Vault of the master: baseline.signingKeyVaultName, else the tenant vault.
        $signVault = "$(& $V 'baseline.signingKeyVaultName')".Trim(); if (-not $signVault) { $signVault = "$(& $V 'keyVaultName')".Trim() }
        if (-not $signVault) { $errors.Add("'keyVaultName' or 'baseline.signingKeyVaultName' is required on the master: the bundle is signed by a non-exportable key in that Key Vault (71.35)") }
        elseif ($signVault -notmatch '^[A-Za-z][A-Za-z0-9-]{1,22}[A-Za-z0-9]$') { $errors.Add("signing Key Vault name '$signVault' is not a Key Vault name") }
        $skn = "$(& $V 'baseline.signingKeyName')".Trim()
        if ($skn -and $skn -notmatch '^[A-Za-z0-9-]{1,127}$') { $errors.Add("'baseline.signingKeyName' '$skn' is not a Key Vault key name") }
        $sks = "$(& $V 'baseline.signingKeySize')".Trim()
        if ($sks -and $sks -notin @('2048', '3072', '4096')) { $errors.Add("'baseline.signingKeySize' must be 2048, 3072 or 4096") }
        $bse = "$(& $V 'baseline.serviceEndpoint')".Trim()
        if ($bse -and $bse -notin @('Microsoft.Storage', 'Microsoft.Storage.Global')) { $errors.Add("'baseline.serviceEndpoint' must be Microsoft.Storage (the store in the SAME region as the environment) or Microsoft.Storage.Global") }
        $bvd = "$(& $V 'baseline.validDays')".Trim()
        if ($bvd -and ($bvd -notmatch '^\d+$' -or [int]$bvd -lt 2)) { $errors.Add("'baseline.validDays' must be a whole number of at least 2 (the daily publish needs overlap)") }
        $bacc = Get-PimBaselineAccessMode -Role Master -Config $Config
        if ($bacc -notin @('publicSigned', 'privateEndpoint')) { $errors.Add("'baseline.access' must be publicSigned (default) or privateEndpoint") }
        if ($bacc -eq 'privateEndpoint' -and -not "$(& $V 'network.privateEndpointSubnetAddressPrefix')".Trim()) {
            $warnings.Add("baseline.access privateEndpoint: 'network.privateEndpointSubnetAddressPrefix' not set -- the privateendpoint step REFUSES if the private-endpoint subnet does not already exist")
        }
        $cron = "$(& $V 'baseline.publishCron')".Trim()
        if ($cron -and @($cron -split '\s+').Count -ne 5) { $errors.Add("'baseline.publishCron' '$cron' is not a 5-field cron expression") }
    } else {
        # 71.34 PUBLIC-BUT-SIGNED (DESIGN 13.7): the slave needs NOTHING from the master but the blob's address. No master
        # identity, no SAS, no rotation -- trust is the bundle signature, access is the master's storage network rule.
        if ("$(& $V 'master.tenantId')".Trim() -notmatch $script:PimMspGuid) { $errors.Add("'master.tenantId' must be a GUID (the master this tenant pulls from)") }
        $mStoreName = "$(& $V 'master.storageAccount')".Trim()
        if (-not $mStoreName) { $errors.Add("'master.storageAccount' is required (where the master publishes the signed bundle)") }
        elseif ($mStoreName -notmatch '^[a-z0-9]{3,24}$') { $errors.Add("'master.storageAccount' '$mStoreName' is not a storage account name (3-24 lowercase letters/digits)") }
        if ($null -ne (& $V 'master.deployIdentity')) { $warnings.Add("'master.deployIdentity' is no longer used: a managed tenant pulls the public-but-signed bundle with no master credential (71.34) -- remove it.") }
        $dlCron = "$(& $V 'downlinkCron')".Trim()
        if ($dlCron -and @($dlCron -split '\s+').Count -ne 5) { $errors.Add("'downlinkCron' '$dlCron' is not a 5-field cron expression (UTC), e.g. '*/30 * * * *'") }
        # 71.35 TRUST ANCHOR: the master's signing key id(s), from the master's build output (its 'signingkey' step) --
        # never from the bundle store. More than one may be pinned, so a key roll never breaks this tenant.
        $pins = @(@(& $V 'master.signingKeyIds') | Where-Object { $null -ne $_ -and "$_".Trim() } | ForEach-Object { "$_".Trim() })
        if (-not $pins.Count) { $errors.Add("'master.signingKeyIds' is required: the key id(s) the master's build printed at its 'signingkey' step. The pull REFUSES a bundle signed by a key this tenant does not pin (71.35).") }
        foreach ($pin in $pins) { if ($pin -cnotmatch '^[A-Za-z0-9_-]{43}$') { $errors.Add("'master.signingKeyIds' entry '$pin' is not a signing key id (43 characters of base64url, as printed by the master's signingkey step)") } }
        $sacc = Get-PimBaselineAccessMode -Role Slave -Config $Config
        if ($sacc -notin @('publicSigned', 'privateEndpoint')) { $errors.Add("'master.access' must be publicSigned (default) or privateEndpoint") }
        if ($sacc -eq 'privateEndpoint') {
            $pip = "$(& $V 'master.privateEndpointIp')".Trim()
            if (-not (Test-PimPrivateIPv4 -Value $pip)) { $errors.Add("'master.privateEndpointIp' must be the private IPv4 address of the master store's private endpoint (printed by the master's 'privateendpoint' step as master.privateEndpointIp = <ip>); got '$pip'") }
            if ("$(& $V 'baselineServiceEndpoint')".Trim()) { $warnings.Add("'baselineServiceEndpoint' is ignored in privateEndpoint mode -- no storage service endpoint is added (the store is reached over the peering)") }
        }
        $sep = "$(& $V 'baselineServiceEndpoint')".Trim()
        if ($sep -and $sep -notin @('Microsoft.Storage', 'Microsoft.Storage.Global')) { $errors.Add("'baselineServiceEndpoint' must be Microsoft.Storage (master storage in the SAME region) or Microsoft.Storage.Global (any region)") }
        if (-not @(& $V 'adminPrefixes' | Where-Object { "$_".Trim() }).Count) { $errors.Add("'adminPrefixes' is required on a managed tenant (IMP-13: the MSP admin prefix is mandatory)") }
        # BUG-175: slaveRing is THE ring of this tenant (every ring is local in the slave) -- the master's slaves[i].ring is
        # only its copy. A value that is set but not 0..2 used to fall silently to 2; a typo in the one authoritative ring
        # is refused instead.
        $sr = "$(& $V 'slaveRing')".Trim()
        if (-not $sr) { $warnings.Add("'slaveRing' not set -- the pull job uses ring 0 (dev). This value is THE ring of this tenant (local); the master's slaves[].ring is only its copy.") }
        elseif ($sr -notmatch '^[0-2]$') { $errors.Add("'slaveRing' '$sr' is not a ring (0, 1 or 2) -- refusing rather than defaulting the tenant's own ring") }
        # 71.19: no fallback address here. A synced admin's mail/TAP recipient is its SPONSOR DEPARTMENT's owners,
        # replicated with the admin -- a build-level address would be the "manager on the person" §62 forbids.
        if ("$(& $V 'defaultManagerEmail')".Trim()) { $errors.Add("REFUSED: 'defaultManagerEmail' is no longer used (71.19). An admin's mail and TAP go to its SPONSOR DEPARTMENT's owners -- set Department on the admin at the master and Owners on that department; remove this key.") }
    }
    if ("$(& $V 'master.tenantId')".Trim() -and "$(& $V 'master.tenantId')".Trim() -eq "$(& $V 'tenantId')".Trim()) { $errors.Add('master.tenantId equals tenantId -- a managed tenant cannot pull from itself') }
    # (71.35: the signed-in warning about the unattended daily publish is gone -- the publish is a cloud job on the master's
    # managed identity, so a signed-in master build has nothing it cannot run.)
    return @{ ok = ($errors.Count -eq 0); errors = @($errors.ToArray()); warnings = @($warnings.ToArray()); authMode = $authMode }
}

function New-PimMspBuildStep {
    param([string]$Id, [string]$Title, [string]$Script, [hashtable]$Arguments = @{}, [ValidateSet('pwsh','powershell')][string]$HostExe = 'pwsh',
          [string[]]$Switches = @(), [string]$Why = '', [switch]$CapturesOutput, [switch]$AzPowerShell, [string]$Blocked = '')
    # 71.33: -Blocked = WHY this step cannot run under the build's identity. The runner never executes (or resolves the
    # placeholders of) a blocked step; it prints the reason, carries on, and ends the build INCOMPLETE (exit 2).
    [pscustomobject]@{ id = $Id; title = $Title; kind = 'script'; script = $Script; args = $Arguments; switches = @(@($Switches) | Where-Object { "$_".Trim() }); host = $HostExe
                       why = $Why; capturesOutput = [bool]$CapturesOutput; azPowerShell = [bool]$AzPowerShell; blocked = "$Blocked" }
}

function Get-PimMspBuildPlan {
    <#
      PURE. The ordered, idempotent step list for one role. Every step re-runs safely (each script converges), so a failed
      build resumes with -From <id>. Script paths are relative to the solution root (PlatformConfiguration ones to the repo).
    #>
    param([Parameter(Mandatory)][ValidateSet('Master','Slave')][string]$Role, [Parameter(Mandatory)][object]$Config)
    $V = { param($p) Get-PimMspBuildValue -Object $Config -Path $p }
    $tid = "$(& $V 'tenantId')".Trim(); $sub = "$(& $V 'subscriptionId')".Trim(); $rg = "$(& $V 'resourceGroup')".Trim()
    $loc = "$(& $V 'location')".Trim(); $token = "$(& $V 'token')".Trim()
    $sqlName = "$(& $V 'sqlServerName')".Trim(); $sqlFqdn = "$sqlName.database.windows.net"
    $db = if ("$(& $V 'sqlDatabase')".Trim()) { "$(& $V 'sqlDatabase')".Trim() } else { 'PimPlatform' }
    $acr = "$(& $V 'acrName')".Trim(); $env = "$(& $V 'envName')".Trim()
    $cid = "$(& $V 'deployIdentity.clientId')".Trim(); $thumb = "$(& $V 'deployIdentity.certThumbprint')".Trim().ToUpperInvariant()
    $tick = if ("$(& $V 'tickJobName')".Trim()) { "$(& $V 'tickJobName')".Trim() } else { 'ca-pim-tick' }
    $mgr = if ("$(& $V 'managerApp')".Trim()) { "$(& $V 'managerApp')".Trim() } else { 'ca-pim-manager' }
    $kv = "$(& $V 'keyVaultName')".Trim(); $bootApp = "$(& $V 'bootstrapAppId')".Trim()
    $scenario = if ($Role -eq 'Master') { 'S3' } else { 'S6' }
    $certArgs = @{ TenantId = $tid; ClientId = $cid; CertThumbprint = $thumb }
    # 71.33 -- SIGNED-IN MODE. Every certificate argument below is replaced by the step's own signed-in form
    # (-UseSignedInAccount, or no credential where the script already means "the signed-in az context"); the user's
    # object id is the run-time placeholder {{signed-in-user}}. CERTIFICATE MODE IS UNCHANGED, argument for argument.
    $signedIn = ((Get-PimMspBuildAuthMode -Config $Config) -eq 'SignedIn')
    # BUG-162: the ring is DECIDED, not cast ([int]$null was 0 = the ring that takes every build).
    $updRing = Get-PimMspBuildUpdateRing -Config $Config
    $storeArgs = if ($signedIn) { @{ TenantId = $tid } } else { $certArgs }
    $storeSwitches = if ($signedIn) { @('UseSignedInAccount') } else { @() }
    $steps = New-Object System.Collections.Generic.List[object]

    if ($kv -and $bootApp) {
        $steps.Add((New-PimMspBuildStep -Id 'keyvault' -Title 'tenant Key Vault + the bootstrap identity''s read grant' `
            -Script '..\PlatformConfiguration\INTERNAL\Provision\New-PlatformKeyVault.ps1' `
            -Arguments @{ VaultName = $kv; ResourceGroup = $rg; Location = $loc; SubscriptionId = $sub; BootstrapAppId = $bootApp } -AzPowerShell `
            -Why 'the bootstrap cert -> vault -> Modern-AppId/Modern-Thumbprint chain (a deleted resource group takes the vault role assignments with it)'))
    }

    # 🔴 71.30 (rehearsal 2026-09-17) -- THE SCHEMA STEP'S CONNECTION STRING. Found live: after the address plan was
    # fixed, BOTH sides ran prereq/image/infra/sqlaccess and then died at step 6 of 13 --
    #   "no -SqlConnectionString, so the SQL schema CANNOT be applied ... Refusing to report a schema upgrade
    #    that did not happen."
    # The plan passed the server and database but never the connection string, and the build config CANNOT carry one:
    # Find-PimMspBuildSecretKeys refuses any key matching 'connectionstring'. So it is DERIVED here.
    # 🔒 IT CARRIES NO CREDENTIAL, BY DESIGN, AND NOTHING CERT-BASED IS LEFT BEHIND (operator 2026-09-17: "we dont use
    # certs ... updater runs with managed identity"). Azure SQL here is Entra-only: the string is address-only and the
    # caller MINTS a token with SqlAdminClientId/SqlAdminCertThumbprint -- the DEPLOYING SESSION's own identity, used
    # for the minutes the build runs and never written into the environment. At RUNTIME the environment authenticates
    # as its MANAGED IDENTITY (the UAMI and ca-pim-update's system MI, both members of grp-pim-sql-admins).
    # Same shape Invoke-PimDeployAll prints as its own fallback and PIM-SqlStore.ps1 builds for the MI path.
    $hosting = @{
        Scenario = $scenario; TenantId = $tid; SubscriptionId = $sub; ResourceGroup = $rg; Location = $loc; PrereqToken = $token
        AcrName = $acr; EnvName = $env; SqlServerFqdn = $sqlFqdn; SqlDatabase = $db; WorkerMode = 'cron'; TickJobName = $tick; ManagerApp = $mgr
        SqlConnectionString = "Server=tcp:$sqlFqdn,1433;Database=$db;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30"
        AdminAppId = $cid; AdminCertPem = '{{pem:deploy}}'; SqlAdminClientId = $cid; SqlAdminCertThumbprint = $thumb
        ManagerSuperAdmins = "$(& $V 'managerSuperAdmins')".Trim()
        UpdateRing = $updRing.ring; SqlAdminGroupName = 'grp-pim-sql-admins'; TroubleshootingAppId = $cid
        Exposure = $(if ("$(& $V 'exposure')".Trim()) { "$(& $V 'exposure')".Trim() } else { 'external' })
    }
    if ("$(& $V 'logAnalyticsName')".Trim()) { $hosting['LogAnalyticsWorkspaceName'] = "$(& $V 'logAnalyticsName')".Trim() }
    if ("$(& $V 'imageTag')".Trim())        { $hosting['ImageTag'] = "$(& $V 'imageTag')".Trim() }
    # 🔴 71.29 (rehearsal 2026-09-17) -- THE ADDRESS PLAN. The hosting step's FIRST action, `prereq`, refuses without
    # one ("PREREQ needs an address plan ... Refusing to guess: two environments sharing a CIDR cannot be un-peered"),
    # and the plan had no way to express one and never forwarded anything. So the one-shot build could NOT stand up a
    # greenfield environment at all: it failed at step 2 of 10, on BOTH sides of the rehearsal pair, after the keyvault
    # step had already made changes. Warm environments (EFIF/RIDE) hid it, because their VNets already existed.
    # Either source is accepted, exactly as the prereq step accepts them -- a customer with their own range is not made
    # to invent an estate index, and our estate is not made to hand-write a CIDR it derives from the index.
    $netCidr = "$(& $V 'network.vnetAddressPrefix')".Trim(); $netSub = "$(& $V 'network.subnetAddressPrefix')".Trim()
    if ($netCidr -and $netSub) { $hosting['PrereqVnetAddressPrefix'] = $netCidr; $hosting['PrereqSubnetAddressPrefix'] = $netSub }
    elseif ("$(& $V 'network.index')" -match '^\d+$') { $hosting['PrereqIndex'] = [int](& $V 'network.index') }
    if ("$(& $V 'network.addressBase')".Trim()) { $hosting['PrereqAddressBase'] = "$(& $V 'network.addressBase')".Trim() }
    if ("$(& $V 'network.subnetName')".Trim())  { $hosting['PrereqSubnetName']  = "$(& $V 'network.subnetName')".Trim() }
    # 71.36 PRIVATE NETWORKING (operator 2026-09-17: private only, like the private customer deployments). Forwarded exactly as Invoke-PimDeployAll names them.
    $privateStore = Test-PimMspPrivateStore -Config $Config
    $peSubnetName = if ("$(& $V 'network.privateEndpointSubnetName')".Trim()) { "$(& $V 'network.privateEndpointSubnetName')".Trim() } else { 'pim-endpoints' }
    if ("$(& $V 'network.privateEndpointSubnetName')".Trim())          { $hosting['PrivateEndpointSubnetName'] = $peSubnetName }
    if ("$(& $V 'network.privateEndpointSubnetAddressPrefix')".Trim()) { $hosting['PrivateEndpointSubnetAddressPrefix'] = "$(& $V 'network.privateEndpointSubnetAddressPrefix')".Trim() }
    if ("$(& $V 'acr.sku')".Trim())           { $hosting['AcrSku'] = "$(& $V 'acr.sku')".Trim() }
    if ("$(& $V 'acr.publicAccess')".Trim())  { $hosting['AcrPublicAccess'] = "$(& $V 'acr.publicAccess')".Trim() }
    if ("$(& $V 'acr.agentPoolName')".Trim()) { $hosting['AcrAgentPoolName'] = "$(& $V 'acr.agentPoolName')".Trim() }
    if ("$(& $V 'hub.vnetName')".Trim())          { $hosting['HubVnetName'] = "$(& $V 'hub.vnetName')".Trim() }
    if ("$(& $V 'hub.resourceGroup')".Trim())     { $hosting['HubVnetResourceGroup'] = "$(& $V 'hub.resourceGroup')".Trim() }
    if ("$(& $V 'hub.subscriptionId')".Trim())    { $hosting['HubVnetSubscriptionId'] = "$(& $V 'hub.subscriptionId')".Trim() }
    if ("$(& $V 'hub.privateDnsResourceGroup')".Trim()) { $hosting['PrivateDnsResourceGroup'] = "$(& $V 'hub.privateDnsResourceGroup')".Trim() }
    # 🔴 71.36 (rehearsal 2026-09-17) -- NO SQL PRIVATE ENDPOINT BY DEFAULT. Invoke-PimDeployAll turns one on for
    # -Exposure internal, and from mgmt1 that made the store unreachable: once the endpoint exists the server's public
    # name is a CNAME to <server>.privatelink.database.windows.net, which mgmt1's DNS answers NXDOMAIN ("No such host is
    # known") -- so the hosting step's own code/update checks and every store step below failed. The store instead admits
    # ONLY the environment's subnet (VNet rule over the Microsoft.Sql service endpoint); the build window (sqlopen/sqlclose)
    # adds and removes this host. 'sql.privateEndpoint': true restores the endpoint for a build host whose DNS resolves it.
    if ($hosting['Exposure'] -eq 'internal' -and -not [bool](& $V 'sql.privateEndpoint')) { $hosting['SqlPrivateEndpoint'] = $false }
    # 🔴 71.40 -- WHAT THE MANAGER'S DOWNLINK VIEW VERIFIES AGAINST. Nothing deployed either value, so every hosted Manager
    # said "no baseline document configured" and could not verify a Key Vault signed bundle even with one in hand.
    #   slave  : the master's pinned key id(s) (the SAME master.signingKeyIds its pull job pins) + the master's bundle URL
    #   master : its own bundle URL. Its own key id does not exist yet at this step (signingkey runs later), so the pin
    #            is an operator step printed after the build (Get-PimMspOperatorSteps), never a guess.
    # Both are identifiers, never credentials: the URL is the plain blob URL (no query string -- refused downstream).
    $mgrDocUrl = ''
    if ($Role -eq 'Slave') {
        $mgrStore = "$(& $V 'master.storageAccount')".Trim()
        $mgrCont  = if ("$(& $V 'master.container')".Trim()) { "$(& $V 'master.container')".Trim() } else { 'baselines' }
        if ($mgrStore) { $mgrDocUrl = Get-PimBaselinePullUrl -StorageAccount $mgrStore -Container $mgrCont }
        $mgrPins = @(@(& $V 'master.signingKeyIds') | Where-Object { $null -ne $_ -and "$_".Trim() } | ForEach-Object { "$_".Trim() })
        if ($mgrPins.Count) { $hosting['BaselineTrustedKeys'] = $mgrPins }
    } else {
        $mgrStore = "$(& $V 'baseline.storageAccount')".Trim()
        $mgrCont  = if ("$(& $V 'baseline.container')".Trim()) { "$(& $V 'baseline.container')".Trim() } else { 'baselines' }
        if ($mgrStore) { $mgrDocUrl = Get-PimBaselinePullUrl -StorageAccount $mgrStore -Container $mgrCont }
    }
    if ($mgrDocUrl) { $hosting['BaselineDocUrl'] = $mgrDocUrl }
    # SEC-44 (C2A, 2026-09-18) -- WHO MAY SIGN IN TO THE MANAGER. Invoke-PimDeployAll now REFUSES a new Manager without an
    # explicit Easy Auth access choice, and the plan never made one, so a greenfield build stopped at step 2. Choice, in order:
    #   easyAuth.allowedPrincipals (explicit)  >  easyAuth.allowAllTenantUsers = true  >  managerSuperAdmins (required config)
    # -- the named principals are preferred; "every member account" is taken only when the config says so, or when there is
    # nobody to name. The choice is written into the step title, so it is visible before anything runs.
    $eaExplicit = @(@(& $V 'easyAuth.allowedPrincipals') | ForEach-Object { "$_" -split '[,;]' } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $eaAll      = [bool]("$(& $V 'easyAuth.allowAllTenantUsers')" -match '^(?i)(true|1|yes)$')
    $eaSupers   = @("$(& $V 'managerSuperAdmins')" -split '[,;]' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $eaChoice = ''
    $hostingSwitches = @('Apply', 'SkipAppReg')
    if ($eaExplicit.Count) { $hosting['EasyAuthAllowedPrincipals'] = $eaExplicit; $eaChoice = "sign-in: $($eaExplicit -join ', ') (easyAuth.allowedPrincipals)" }
    elseif ($eaAll)        { $hostingSwitches += 'EasyAuthAllowAllTenantUsers'; $eaChoice = 'sign-in: every member account of the tenant (easyAuth.allowAllTenantUsers)' }
    elseif ($eaSupers.Count) { $hosting['EasyAuthAllowedPrincipals'] = $eaSupers; $eaChoice = "sign-in: $($eaSupers -join ', ') (managerSuperAdmins)" }
    else { $hostingSwitches += 'EasyAuthAllowAllTenantUsers'; $eaChoice = 'sign-in: every member account of the tenant (no principal configured)' }
    # IMP-49 t (C2A) -- KEEP THE SETUP-HOST FIREWALL RULE ACROSS THE HOSTING STEP. Invoke-PimDeployAll now removes the
    # 'AllowSetupHost' rule it created at the END of its run, so on a greenfield public store the store steps that follow
    # (access, scenario, registry, register, publishjob / downlink) were refused by the SQL firewall. The build owns the
    # window instead: kept here, closed by the LAST step ('sqlclose' on a private store, 'sqlhostclose' otherwise).
    $hostingSwitches += 'KeepSetupHostRule'
    if ($hosting['Exposure'] -eq 'internal') {
        # The Manager FQDN does not resolve outside its VNet: the smoke gate cannot run from a build host (NOT a pass).
        $hostingSwitches += 'SkipHostedSmoke'
        if ([bool](& $V 'hub.skipPeering')) { $hostingSwitches += 'SkipPeering' }
    }
    if ($signedIn) {
        # No deploy application, no PEM, no SQL admin application: Invoke-PimDeployAll -UseSignedInAccount runs every
        # sub-step as the signed-in user (and makes that user a member of the SQL admin group before any SQL is used).
        foreach ($k in 'AdminAppId', 'AdminCertPem', 'SqlAdminClientId', 'SqlAdminCertThumbprint', 'TroubleshootingAppId') { $hosting.Remove($k) }
        $hostingSwitches += 'UseSignedInAccount'
    }
    $sqlWindowArgs = @{ SubscriptionId = $sub; ResourceGroup = $rg; SqlServerName = $sqlName }
    if ($privateStore) {
        $steps.Add((New-PimMspBuildStep -Id 'sqlopen' -Title "PRIVATE store: open the build window on $sqlName for THIS host (AllowSetupHost; closed by the last step)" `
            -Script 'tools\setup\Set-PimSqlBuildWindow.ps1' -Arguments ($sqlWindowArgs + @{ Mode = 'Open' }) `
            -Why 'the hosting step (code/update checks) and the store steps connect from the build host, which is not in the VNet; on a re-run a previous sqlclose removed this host. Entra-only auth, grp-pim-sql-admins members only'))
    }
    $steps.Add((New-PimMspBuildStep -Id 'hosting' -Title "hosting ($scenario): prerequisites, image, containers, schema, mail sender, Easy Auth ($eaChoice), code, updater, access, smoke gate" `
        -Script 'tools\setup\Invoke-PimDeployAll.ps1' -Arguments $hosting -Switches $hostingSwitches `
        -Why "managed-identity only (no engine app registration, no secret); the smoke gate runs inside; $($updRing.message)"))

    # (parenthesised: the comma operator binds tighter than +, so the unwrapped form built ONE string -- caught by B5)
    $members = @(("{{mi-job:$tick}}"), ("{{mi-app:$mgr}}"))
    $sqlGroupArgs = @{ SubscriptionId = $sub; ResourceGroup = $rg; SqlServerName = $sqlName; TenantId = $tid; ClientId = $cid; CertThumbprint = $thumb; TroubleshootingAppId = $cid; ExtraMemberObjectIds = $members }
    if ($signedIn) {
        # Initialize-PimSqlAdminGroup with no -ClientId/-CertThumbprint = the signed-in az context (its own convention).
        # The signed-in administrator stays a member: it is who re-runs this build and who the store steps connect as.
        $sqlGroupArgs = @{ SubscriptionId = $sub; ResourceGroup = $rg; SqlServerName = $sqlName; TenantId = $tid
                           ExtraMemberObjectIds = @(("{{mi-job:$tick}}"), ("{{mi-app:$mgr}}"), ('{{signed-in-user}}')) }
    }
    $steps.Add((New-PimMspBuildStep -Id 'sqlgroup' -Title 'SQL admin group grp-pim-sql-admins: tick + Manager identities + the troubleshooting identity' `
        -Script 'tools\setup\Initialize-PimSqlAdminGroup.ps1' -HostExe 'powershell' `
        -Arguments $sqlGroupArgs `
        -Why 'the prerequisites add the environment, deploy and updater identities; the tick and Manager system identities and the troubleshooting SPN were never added'))


    $accessArgs = @{ SubscriptionId = $sub; ResourceGroup = $rg; SqlServerFqdn = $sqlFqdn; SqlDatabase = $db; TickJobName = $tick; ManagerApp = $mgr } + $storeArgs
    $steps.Add((New-PimMspBuildStep -Id 'access' -Title 'tick Graph (Engine set), Manager Graph (read-only set), Manager may start the tick, SchedulerTickJobId' `
        -Script 'tools\setup\Initialize-PimHostingAccess.ps1' -HostExe 'powershell' `
        -Arguments $accessArgs -Switches $storeSwitches `
        -Why 'the infra step (the only place these were granted) is SKIPPED on an existing environment; EFIF and RIDE held 12 and 9 roles and lacked the 5 required ones'))

    $steps.Add((New-PimMspBuildStep -Id 'scenario' -Title "deployment scenario $scenario in pim.Settings" -Script 'tools\setup\Set-PimScenario.ps1' -HostExe 'powershell' `
        -Arguments (@{ SqlServerFqdn = $sqlFqdn; SqlDatabase = $db; Scenario = $scenario } + $storeArgs) -Switches $storeSwitches `
        -Why 'unset, every tenant resolves as S1 (single) -- no master publishes, no slave pulls'))

    if ($Role -eq 'Master') {
        $store = "$(& $V 'baseline.storageAccount')".Trim()
        $container = if ("$(& $V 'baseline.container')".Trim()) { "$(& $V 'baseline.container')".Trim() } else { 'baselines' }
        $valid = if ("$(& $V 'baseline.validDays')" -match '^\d+$') { [int](& $V 'baseline.validDays') } else { 30 }
        $steps.Add((New-PimMspBuildStep -Id 'registry' -Title 'MSP master registry schema (platform.Tenants, pim.CentralAdmins, targeting columns)' `
            -Script 'tools\setup\Initialize-PimMasterRegistry.ps1' -HostExe 'powershell' -Arguments @{ SqlServer = $sqlFqdn; Database = $db } `
            -Why 'the estate schema step creates the pim store, not the platform registry'))
        # 71.35 CLOUD PUBLISH (operator 2026-09-17: "go with cloud job publish"). The bundle is published by a Container Apps
        # job on THIS environment (ca-pim-publish), as its system-assigned identity, signed by a non-exportable Key Vault
        # key. No host, no certificate, no scheduled task. So the store's PUBLISHER network is this environment's subnet:
        #   publishnetwork  the Microsoft.Storage service endpoint on the master's own Container Apps subnet
        #   storage         the VNet rule for that subnet is added BEFORE default-action Deny (one call, rules first)
        # ...and only then the job that writes through it (signingkey -> publishjob -> publish).
        $signVault = "$(& $V 'baseline.signingKeyVaultName')".Trim(); if (-not $signVault) { $signVault = $kv }
        $signVaultRg = "$(& $V 'baseline.signingKeyVaultResourceGroup')".Trim()
        $keyName = if ("$(& $V 'baseline.signingKeyName')".Trim()) { "$(& $V 'baseline.signingKeyName')".Trim() } else { 'pim-baseline-signing' }
        $publishJob = if ("$(& $V 'baseline.publishJobName')".Trim()) { "$(& $V 'baseline.publishJobName')".Trim() } else { 'ca-pim-publish' }
        $pubEndpoint = if ("$(& $V 'baseline.serviceEndpoint')".Trim()) { "$(& $V 'baseline.serviceEndpoint')".Trim() } else { 'Microsoft.Storage' }
        $masterAccess = Get-PimBaselineAccessMode -Role Master -Config $Config
        if ($masterAccess -eq 'publicSigned') {
        $steps.Add((New-PimMspBuildStep -Id 'publishnetwork' -Title "service endpoint $pubEndpoint on this environment's subnet -- the publish job's network" `
            -Script 'tools\setup\Initialize-PimBaselinePullNetwork.ps1' `
            -Arguments @{ SubscriptionId = $sub; ResourceGroup = $rg; EnvName = $env; ServiceEndpoint = $pubEndpoint; MasterStorageAccount = $store; MasterContainer = $container } -Switches @('ForPublisher') `
            -Why 'a storage VNet rule only matches traffic that arrives over a service endpoint; the rule must exist before the firewall denies'))
        }
        $storageArgs = @{ SubscriptionId = $sub; ResourceGroup = $rg; Location = $loc; StorageAccount = $store; Container = $container; PublisherEnvName = $env }
        # 71.34 PUBLIC-BUT-SIGNED (DESIGN 13.7): anonymous read on the BLOB only (no listing), storage firewall Deny, and
        # an allow rule for the publisher network here and for each managed tenant below. No SAS, no stored access policy,
        # no account key, nothing with an expiry date in the access path. Trust = the RSA signature every pull verifies.
        # Publisher networks named in the config are still honoured (not required any more).
        $pubSubnets = @(& $V 'baseline.publisherSubnetIds' | Where-Object { $null -ne $_ -and "$_".Trim() } | ForEach-Object { "$_".Trim() })
        $pubIps     = @(& $V 'baseline.publisherIps' | Where-Object { $null -ne $_ -and "$_".Trim() } | ForEach-Object { "$_".Trim() })
        if ($pubSubnets.Count) { $storageArgs['PublisherSubnetResourceIds'] = $pubSubnets }
        if ($pubIps.Count)     { $storageArgs['PublisherIpAddresses'] = $pubIps }
        if ($masterAccess -eq 'publicSigned') {
        $steps.Add((New-PimMspBuildStep -Id 'storage' -Title "signed-baseline store $store/$($container) -- public-but-signed (anonymous blob read; this environment's subnet allowed, THEN firewall Deny)" `
            -Script 'tools\setup\New-PimBaselineStorage.ps1' -Arguments $storageArgs -Switches @('PublicSignedRead', 'NoHostPublisher') `
            -Why 'the build host is not a publisher any more: no data role for it and no probe from its (denied) network'))
        } else {
            # 71.36 PRIVATE ENDPOINT: account + container only (no firewall posture), then the private endpoint, the zone,
            # anonymous blob read and public network access Disabled -- in that order -- in the next step.
            $storageArgs.Remove('PublisherEnvName'); $storageArgs.Remove('PublisherSubnetResourceIds'); $storageArgs.Remove('PublisherIpAddresses')
            $steps.Add((New-PimMspBuildStep -Id 'storage' -Title "signed-baseline store $store/$($container) -- account + container (private-endpoint mode: no firewall rules)" `
                -Script 'tools\setup\New-PimBaselineStorage.ps1' -Arguments $storageArgs -Switches @('NoHostPublisher') `
                -Why 'the store the publish job writes to; its network posture is the private endpoint, set next'))
            $peArgs = @{ SubscriptionId = $sub; ResourceGroup = $rg; StorageAccount = $store; Container = $container; PrivateEndpointSubnetName = $peSubnetName }
            if ("$(& $V 'network.vnetName')".Trim()) { $peArgs['VnetName'] = "$(& $V 'network.vnetName')".Trim() } else { $peArgs['VnetName'] = "vnet-pim-$token" }
            if ("$(& $V 'network.privateEndpointSubnetAddressPrefix')".Trim()) { $peArgs['PrivateEndpointSubnetAddressPrefix'] = "$(& $V 'network.privateEndpointSubnetAddressPrefix')".Trim() }
            $steps.Add((New-PimMspBuildStep -Id 'privateendpoint' -Title "private endpoint for $store (blob) + privatelink zone on this VNet + anonymous blob read + public network access DISABLED; PRINTS master.privateEndpointIp" `
                -Script 'tools\setup\Set-PimBaselinePrivateEndpoint.ps1' -Arguments $peArgs `
                -Why 'private networks joined by VNet peering: the store is reachable only through this endpoint; managed tenants resolve its IP through their own zone'))
        }
        $i = 0
        foreach ($s in @(& $V 'slaves' | Where-Object { $null -ne $_ })) {
            $reg = @{ SqlServerFqdn = $sqlFqdn; SqlDatabase = $db; ManagedTenantId = "$(Get-PimMspBuildValue $s 'tenantId')".Trim(); DisplayName = "$(Get-PimMspBuildValue $s 'displayName')".Trim()
                      Ring = $(if ($null -ne (Get-PimMspBuildValue $s 'ring')) { [int](Get-PimMspBuildValue $s 'ring') } else { 2 }); Tags = (ConvertTo-PimTenantTags -Tags (Get-PimMspBuildValue $s 'tags')).value } + $storeArgs
            # BUG-175: slaves[i].ring is the MASTER'S COPY of the tenant's ring (previews + fleet view only). The pull is gated by
            # the slave's OWN slaveRing (its job argument, set in the slave's build) -- nothing reconciles the two, so say so.
            $steps.Add((New-PimMspBuildStep -Id "register-$i" -Title "register managed tenant $($reg.DisplayName) (master's copy of its ring: $($reg.Ring) -- the slave's own slaveRing decides; tags '$($reg.Tags)')" `
                -Script 'tools\setup\Register-PimManagedTenant.ps1' -HostExe 'powershell' -Arguments $reg -Switches $storeSwitches -Why 'replaces the documented hand SQL on platform.Tenants'))
            if ($masterAccess -ne 'publicSigned') { $i++; continue }   # 71.36: over a private endpoint the peering is the access -- no per-tenant storage rule
            $slSubnet = "$(Get-PimMspBuildValue $s 'subnetResourceId')".Trim(); $slIp = "$(Get-PimMspBuildValue $s 'egressIp')".Trim()
            $net = @{ SubscriptionId = $sub; ResourceGroup = $rg; StorageAccount = $store; Container = $container; ManagedTenantId = $reg.ManagedTenantId
                      SqlServerFqdn = $sqlFqdn; SqlDatabase = $db } + $storeArgs
            if ($slSubnet) { $net['SubnetResourceId'] = @($slSubnet) }
            if ($slIp)     { $net['IpAddress'] = @($slIp) }
            $netBlocked = if (-not $slSubnet -and -not $slIp) { "slaves[$i] has no subnetResourceId / egressIp yet. Build the managed tenant first: its 'pullnetwork' step prints the subnet id. Add it as slaves[$i].subnetResourceId and re-run -From network-$i." } else { '' }
            $steps.Add((New-PimMspBuildStep -Id "network-$i" -Title "let $($reg.DisplayName) read the bundle: storage network rule for its subnet/IP (read back, audited)" `
                -Script 'tools\setup\Set-PimBaselineNetworkAccess.ps1' -HostExe 'powershell' -Arguments $net -Switches $storeSwitches -Blocked $netBlocked `
                -Why 'the firewall denies every network not named; one rule per managed tenant, set once, nothing to renew'))
            $i++
        }
        # 71.35 -- the publish leaves the host (the host publisher + its SYSTEM task were deleted with the SAS cluster, SEC-27,
        # 2026-09-18; EFIF publishes from ca-pim-publish). Same steps in certificate and signed-in mode: every one runs on the az
        # context the build established, and nothing unattended depends on a person's sign-in afterwards.
        $keyArgs = @{ SubscriptionId = $sub; ResourceGroup = $rg; Location = $loc; KeyVaultName = $signVault; KeyName = $keyName }
        # §71.40 -- the master's OWN Manager pins the key the moment it exists (merged into PIM_BaselineTrustedKeys, read
        # back), so its Downlink view verifies what it publishes without an operator step.
        $keyArgs['PinOnManagerApp'] = if ("$(& $V 'managerApp')".Trim()) { "$(& $V 'managerApp')".Trim() } else { 'ca-pim-manager' }
        if ($signVaultRg) { $keyArgs['KeyVaultResourceGroup'] = $signVaultRg }
        if ("$(& $V 'baseline.signingKeySize')".Trim()) { $keyArgs['KeySize'] = [int](& $V 'baseline.signingKeySize') }
        $keySwitches = if ([bool](& $V 'baseline.createSigningKeyVault')) { @('CreateVaultIfMissing') } else { @() }
        $steps.Add((New-PimMspBuildStep -Id 'signingkey' -Title "signing key $keyName in $signVault (non-exportable RSA, sign+verify; PRINTS the key id every managed tenant pins)" `
            -Script 'tools\setup\New-PimBaselineSigningKey.ps1' -Arguments $keyArgs -Switches $keySwitches `
            -Why 'the bundle signature is the only trust a managed tenant has; the key never leaves the vault'))
        $jobArgs = @{ SubscriptionId = $sub; ResourceGroup = $rg; EnvName = $env; AcrName = $acr; JobName = $publishJob; ManagerApp = $mgr
                      SqlServerFqdn = $sqlFqdn; SqlDatabase = $db; StorageAccount = $store; Container = $container
                      KeyVaultName = $signVault; KeyName = $keyName; ValidDays = $valid; Scope = 'fleet' }
        if ($signVaultRg) { $jobArgs['KeyVaultResourceGroup'] = $signVaultRg }
        if ("$(& $V 'baseline.publishCron')".Trim()) { $jobArgs['Cron'] = "$(& $V 'baseline.publishCron')".Trim() }
        if ("$(& $V 'imageTag')".Trim()) { $jobArgs['ImageTag'] = "$(& $V 'imageTag')".Trim() }
        $idSwitch = @()   # identical in both identity modes: these scripts use the az context the build established
        $steps.Add((New-PimMspBuildStep -Id 'publishjob' -Title "publish job $publishJob (cadence from the Manager's Job schedule, daily by default, + on demand; system identity; Blob Data Contributor on the container, Crypto User on the key, SQL reader user)" `
            -Script 'tools\setup\Deploy-PimBaselinePublishJob.ps1' -Arguments $jobArgs -Switches $idSwitch `
            -Why "an unpublished bundle EXPIRES after $valid days and every managed tenant then refuses it"))
        $steps.Add((New-PimMspBuildStep -Id 'publish' -Title "first publish: start $publishJob and WAIT for Succeeded (the job reads the blob back anonymously and verifies it)" `
            -Script 'tools\setup\Start-PimBaselinePublish.ps1' -Arguments @{ SubscriptionId = $sub; ResourceGroup = $rg; JobName = $publishJob } -Switches $idSwitch `
            -Why 'a managed tenant has nothing to pull until baseline-latest.json exists; this host cannot read it (its network is denied), the job can'))
    } else {
        # 71.34 -- NO READ LINK, NO ROTATION, NO MASTER CREDENTIAL (operator 2026-09-17: "go back to original design").
        # The SAS + weekly certificate rotation is gone from the plan entirely (not behind a flag). The managed tenant:
        #   pullnetwork -- puts the Azure Storage service endpoint on its OWN Container Apps subnet and PRINTS that subnet's id
        #                  for the master (the master's storage VNet rule names it; nothing is exchanged but an address)
        #   downlink    -- the pull job gets the PLAIN blob URL (no query string, no ACA secret); the pull still REFUSES a
        #                  bundle whose signature does not verify (Test-PimBaselineDoc), so the network grants reach, not trust.
        $mStore = "$(& $V 'master.storageAccount')".Trim()
        $mContainer = if ("$(& $V 'master.container')".Trim()) { "$(& $V 'master.container')".Trim() } else { 'baselines' }
        $job = if ("$(& $V 'downlinkJobName')".Trim()) { "$(& $V 'downlinkJobName')".Trim() } else { 'ca-pim-downlink-s6' }
        $endpoint = if ("$(& $V 'baselineServiceEndpoint')".Trim()) { "$(& $V 'baselineServiceEndpoint')".Trim() } else { 'Microsoft.Storage.Global' }
        if ((Get-PimBaselineAccessMode -Role Slave -Config $Config) -eq 'privateEndpoint') {
            # 71.36: no service endpoint and nothing for the master -- the master store's name resolves to its private
            # endpoint through THIS tenant's own zone, and the traffic crosses the operator's VNet peering.
            $steps.Add((New-PimMspBuildStep -Id 'privatedns' -Title "privatelink.blob.core.windows.net on this VNet: $mStore -> $("$(& $V 'master.privateEndpointIp')".Trim()) (the master's private endpoint, over the peering)" `
                -Script 'tools\setup\Initialize-PimBaselinePrivateDns.ps1' `
                -Arguments @{ SubscriptionId = $sub; ResourceGroup = $rg; EnvName = $env; MasterStorageAccount = $mStore; PrivateEndpointIp = "$(& $V 'master.privateEndpointIp')".Trim() } `
                -Why 'a private DNS zone cannot be linked across tenants, so the name is published in this tenant'))
        } else {
        $steps.Add((New-PimMspBuildStep -Id 'pullnetwork' -Title "service endpoint $endpoint on this environment's subnet; print the subnet id for the master" `
            -Script 'tools\setup\Initialize-PimBaselinePullNetwork.ps1' `
            -Arguments @{ SubscriptionId = $sub; ResourceGroup = $rg; EnvName = $env; ServiceEndpoint = $endpoint; MasterStorageAccount = $mStore; MasterContainer = $mContainer } `
            -Why "the master's bundle store denies every network it has not named; it names this subnet"))
        }
        $dl = @{ Scenario = 'S6'; TenantId = $tid; SlaveRing = $(if ("$(& $V 'slaveRing')" -match '^[0-2]$') { [int](& $V 'slaveRing') } else { 0 })
                 ResourceGroup = $rg; EnvName = $env; AcrName = $acr; SubscriptionId = $sub; JobName = $job; BaselineUrl = (Get-PimBaselinePullUrl -StorageAccount $mStore -Container $mContainer)
                 SqlServerFqdn = $sqlFqdn; SqlDatabase = $db; SlaveAdminPrefixes = @(& $V 'adminPrefixes' | Where-Object { "$_".Trim() })
                 # 71.35 TRUST ANCHOR: the pinned signing key id(s) -- config, not a secret, never read from the bundle store.
                 BaselineTrustedKeys = @(@(& $V 'master.signingKeyIds') | Where-Object { $null -ne $_ -and "$_".Trim() } | ForEach-Object { "$_".Trim() }) }
        if (-not $signedIn) { $dl['SqlAdminClientId'] = $cid; $dl['SqlAdminCertThumbprint'] = $thumb }   # signed-in: the job joins the SQL admin group as the signed-in user
        if ("$(& $V 'imageTag')".Trim()) { $dl['ImageTag'] = "$(& $V 'imageTag')".Trim() }
        # The pull cadence (operator 2026-09-18: "can the pull run every 30 min" ... "gui must be made to control"). The CADENCE
        # is set in the managed tenant's own Manager (Job schedule > Managed-tenant pull, 5-1440 min; nothing set = daily); the
        # job's TRIGGER is Deploy-PimDownlinkJob's default '*/5 * * * *' and the job gates itself (PIM-JobCadence.ps1).
        # 'downlinkCron' overrides the TRIGGER only -- a slower trigger caps how fast the GUI cadence can be honoured.
        if ("$(& $V 'downlinkCron')".Trim()) { $dl['Cron'] = "$(& $V 'downlinkCron')".Trim() }
        $dlSwitches = if ($signedIn) { @('Start', 'UseSignedInAccount') } else { @('Start') }
        $steps.Add((New-PimMspBuildStep -Id 'downlink' -Title "pull job $job (plain blob URL, signature-verified; system managed identity, Engine Graph set, SQL admin group; retraction report-only)" `
            -Script 'tools\setup\Deploy-PimDownlinkJob.ps1' -Arguments $dl -Switches $dlSwitches -Why 'no engine secret and no link secret: the job runs as its own system identity and reads a public-but-signed blob'))
    }
    if ($privateStore) {
        $steps.Add((New-PimMspBuildStep -Id 'sqlclose' -Title "PRIVATE store: close the build window on $sqlName (no IP / Azure-services rule left: the environment's subnet only; read back)" `
            -Script 'tools\setup\Set-PimSqlBuildWindow.ps1' -Arguments ($sqlWindowArgs + @{ Mode = 'Close' }) `
            -Why 'a completed build leaves the store reachable only from its own environment (VNet rule), or only through its private endpoint when it has one'))
    } else {
        # The hosting step KEEPS 'AllowSetupHost' (-KeepSetupHostRule), so a public store needs its own closing step. It removes
        # ONLY that rule (never AllowAzureServices / a VNet rule the environment itself depends on) and reads it back.
        $steps.Add((New-PimMspBuildStep -Id 'sqlhostclose' -Title "close this build host's SQL window on $sqlName (remove 'AllowSetupHost' only; read back)" `
            -Script 'tools\setup\Close-PimSqlSetupHostRule.ps1' -HostExe 'powershell' -Arguments $sqlWindowArgs `
            -Why "the hosting step kept this host's firewall rule so the store steps after it could connect; a finished build leaves no standing hole for the machine that built it"))
    }
    return @($steps.ToArray())
}

function Get-PimMspBuildRunOrder {
    # PURE. 71.36 -- the plan indexes to execute for -From <StartAt>: StartAt..end, preceded by 'sqlopen' when the resume point
    # lies after it (and the plan still has 'sqlclose' ahead), so a store step never runs against a closed private server.
    param([string[]]$StepIds = @(), [int]$StartAt = 0)
    $n = @($StepIds).Count
    if ($StartAt -ge $n) { return @() }
    $rest = @($StartAt..($n - 1))
    $open = [array]::IndexOf([string[]]$StepIds, 'sqlopen')
    $close = [array]::IndexOf([string[]]$StepIds, 'sqlclose')
    if ($open -ge 0 -and $StartAt -gt $open -and ($close -lt 0 -or $StartAt -lt $close)) { return @(@($open) + $rest) }
    return $rest
}

function Get-PimMspOperatorSteps {
    <#
      PURE. The steps that need a human or a decision, each with the exact command. Printed by the runner after the build
      and listed in the Friday runbook. NOT automated on purpose.
    #>
    param([Parameter(Mandatory)][ValidateSet('Master','Slave')][string]$Role, [Parameter(Mandatory)][object]$Config)
    $V = { param($p) Get-PimMspBuildValue -Object $Config -Path $p }
    $rg = "$(& $V 'resourceGroup')".Trim(); $sub = "$(& $V 'subscriptionId')".Trim(); $sql = "$(& $V 'sqlServerName')".Trim()
    $out = New-Object System.Collections.Generic.List[object]
    $out.Add([pscustomobject]@{ id = 'exchange'; title = 'Exchange Online plan present (TAP mail)'; when = 'before the build'
        command = "Graph: GET /subscribedSkus -- an Exchange-BEARING SKU (not EXCHANGE_S_FOUNDATION). Without it the mail-sender step warns and no TAP is delivered." })
    $out.Add([pscustomobject]@{ id = 'policy-approval'; title = 'first-run policy mass-change approval (DELIBERATELY not automated)'; when = 'after the first engine run that applies the policy templates'
        command = "Jobs > Engine logs & errors shows the held plan (status 'needs approval'). After reviewing that it weakens nothing: Approve-PimPolicyMassChange -Provider GroupsPolicies -PlanHash <hash from the hold> -By '<your UPN>'  (repeat per provider: EntraRolePolicies, AzResPolicies). The next run applies exactly that plan." })
    $out.Add([pscustomobject]@{ id = 'smoke'; title = 'sign in to the Manager once in a browser (Easy Auth)'; when = 'after the build'
        command = "Open the ca-pim-manager URL; confirm render mode SQL, read-write for a SuperAdmin, Jobs page green or amber (never red)." })
    if ($Role -eq 'Slave') {
        $out.Add([pscustomobject]@{ id = 'master-registration'; title = 'this tenant is registered on the master (ring + tags)'; when = 'before the first pull'
            command = "On the master build config add it to slaves[] and re-run Invoke-PimMspBuild.ps1 -Role Master -From register-0, or: Register-PimManagedTenant.ps1 -SqlServerFqdn <master sql> -ManagedTenantId $("$(& $V 'tenantId')".Trim()) -DisplayName <name> -Ring <0-2> -Tags <tags> -TenantId <master tenant> -ClientId <master deploy app> -CertThumbprint <thumb>" })
        if ((Get-PimBaselineAccessMode -Role Slave -Config $Config) -eq 'privateEndpoint') {
            $out.Add([pscustomobject]@{ id = 'peering'; title = "global VNet peering between this tenant's VNet and the master's VNet (OPERATOR -- the per-tenant deploy identities cannot authorise it)"; when = 'before the first pull succeeds'
                command = "Both directions, allowVirtualNetworkAccess on, no gateway transit: see the runbook's peering section (an identity with Network Contributor on BOTH VNets, e.g. an admin guest in the other tenant, az login to both tenants, then az network vnet peering create --remote-vnet <full id> in each). Until it is Connected on both sides the pull job's executions fail with a connect timeout to $("$(& $V 'master.privateEndpointIp')".Trim()):443." })
        } else {
        # 71.34: the ONLY thing the master needs from a managed tenant for the pull to work is an address.
        $out.Add([pscustomobject]@{ id = 'master-network'; title = "the master lets this tenant's subnet read the bundle (one-time; nothing expires)"; when = 'after the pullnetwork step; before the first pull succeeds'
            command = ("Give the master the subnet id the 'pullnetwork' step printed. On the master: set slaves[<n>].subnetResourceId in its build config and re-run Invoke-PimMspBuild.ps1 -Role Master -From network-<n> " +
                       "(or Set-PimBaselineNetworkAccess.ps1 -SubscriptionId <master sub> -ResourceGroup <master rg> -StorageAccount $("$(& $V 'master.storageAccount')".Trim()) -SubnetResourceId <id>). " +
                       "Until then the pull job's executions fail with 403 (AuthorizationFailure) -- the bundle is refused by the network, never accepted unsigned.") })
        }
        # 71.35: the trust anchor comes from the master's BUILD OUTPUT, not from its bundle store.
        $out.Add([pscustomobject]@{ id = 'master-signing-key'; title = "pin the master's signing key id(s) in this build config"; when = 'before this build (the config check refuses without it)'
            command = "master.signingKeyIds = [ '<the id the master's signingkey step printed>' ]. Ask the MSP for it over a channel you already trust -- never copy it from the bundle store. On a key roll the MSP gives you the NEW id first: add it (keep the old one), re-run -From downlink, and only then does the master switch." })
    } else {
        if ((Get-PimBaselineAccessMode -Role Master -Config $Config) -eq 'privateEndpoint') {
            $out.Add([pscustomobject]@{ id = 'slave-network'; title = 'each managed tenant: the privateEndpointIp + a global VNet peering (OPERATOR)'; when = 'after the privateendpoint step; before each managed tenant''s first pull'
                command = 'Give each managed tenant the value the privateendpoint step printed (master.privateEndpointIp = <ip>) for its build config, and create the VNet peering between this VNet and that tenant''s VNet (both directions; the runbook''s peering section). Removing a tenant''s access: delete the peering (and Register-PimManagedTenant.ps1 -Disable). Nothing expires.' })
        } else {
        $out.Add([pscustomobject]@{ id = 'slave-network'; title = 'each managed tenant''s subnet is allowed on the bundle store'; when = 'after each managed tenant''s build'
            command = 'Add slaves[<n>].subnetResourceId (printed by that tenant''s pullnetwork step) and re-run -From network-<n>. Removing a tenant''s access: Set-PimBaselineNetworkAccess.ps1 ... -SubnetResourceId <id> -Remove (and Register-PimManagedTenant.ps1 -Disable). No renewal exists or is needed.' })
        }
        $out.Add([pscustomobject]@{ id = 'signing-key-id'; title = 'give the SIGNING KEY ID to every managed tenant (an identifier, not a credential)'; when = 'after the signingkey step; before each managed tenant''s build'
            command = "The signingkey step printed 'master.signingKeyIds += <id>'. Each managed tenant puts it in its build config. KEY ROLL (never needed routinely): create a NEW key name (New-PimBaselineSigningKey.ps1 -KeyName <new>), give its id to every managed tenant and let them re-run -From downlink, THEN set baseline.signingKeyName to the new name and re-run -From signingkey. A tenant that has not pinned the new id refuses the new bundles and keeps its last applied state." })
        # 71.40: the master's OWN Manager pin is now DONE BY the signingkey step (-PinOnManagerApp: merged, read back).
        # This entry only says how to check it, and what to do on a master built before that step existed.
        $mgrApp = if ("$(& $V 'managerApp')".Trim()) { "$(& $V 'managerApp')".Trim() } else { 'ca-pim-manager' }
        $out.Add([pscustomobject]@{ id = 'manager-signing-key'; title = "CHECK the signing key id is pinned on this master's own Manager (the signingkey step pins it)"; when = 'after the signingkey step'
            command = "az containerapp show -g $rg -n $mgrApp --subscription $sub --query ""properties.template.containers[0].env[?name=='PIM_BaselineTrustedKeys'].value"" -o tsv   -- must list the id the signingkey step printed. A master built BEFORE this was automated: re-run -From signingkey (idempotent; it merges the pin). Until pinned the Downlink banner says 'signed by Key Vault key <id>, which this Manager does not pin' -- the managed tenants are unaffected: they decide with their OWN pins." })
    }
    if (Test-PimMspPrivateStore -Config $Config) {
        $out.Add([pscustomobject]@{ id = 'sql-window'; title = 'PRIVATE store: any later host-side store command needs the build window (mgmt1 is not an allowed network after the build)'; when = 'policy approval, pair test, troubleshooting from the build host'
            command = "Set-PimSqlBuildWindow.ps1 -SubscriptionId $sub -ResourceGroup $rg -SqlServerName $sql -Mode Open ... run the command ... Set-PimSqlBuildWindow.ps1 -SubscriptionId $sub -ResourceGroup $rg -SqlServerName $sql -Mode Close  (Close removes this host's AllowSetupHost and AllowAzureServices and refuses when no VNet rule would remain; on a private-endpoint server it disables public access)." })
    }
    if ((Get-PimMspBuildAuthMode -Config $Config) -eq 'SignedIn') {
        $out.Add([pscustomobject]@{ id = 'signed-in-sql'; title = 'the signed-in administrator is a member of grp-pim-sql-admins'; when = 'during the build (added automatically); review afterwards'
            command = 'The build adds the signed-in user to the SQL admin group so the store steps can connect. If your organisation does not want a person there permanently, remove the membership after the build -- a re-run adds it again.' })
    }
    $out.Add([pscustomobject]@{ id = 'verify'; title = 'live verification'; when = 'after the first pull (slave) / publish (master)'
        command = "pwsh -File tests\live\Test-PimMspLivePair.ps1  (for a pair with a SAMPLE model); otherwise tests\live\Test-PimManagerHostedSmoke.ps1 against $rg / sub $sub / SQL $sql" })
    return @($out.ToArray())
}

function Get-PimMspBuildAzExtensionDir {
    <#
      PURE. Rehearsal blocker #3 (2026-09-17): the certificate login points AZURE_CONFIG_DIR at an empty per-run directory,
      and az looks for its EXTENSIONS under the config directory unless AZURE_EXTENSION_DIR says otherwise -- so
      `az containerapp` had no extension there and the hosted smoke gate could not run. Returns the directory to set for
      the run, or '' to leave it alone: an explicit AZURE_EXTENSION_DIR always wins; otherwise the invoking user's
      <profile>\.azure\cliextensions.
    #>
    param([string]$Current, [string]$UserProfile)
    if ("$Current".Trim()) { return '' }
    if (-not "$UserProfile".Trim()) { return '' }
    return (Join-Path "$UserProfile".Trim() '.azure\cliextensions')
}

# (SEC-27, 2026-09-18: Get-PimBaselinePublishTaskArgLine is GONE with the host publisher it scheduled --
# setup\New-PimBaselineBundle.ps1 + tools\setup\Register-PimBaselinePublish.ps1 are deleted. The master publishes
# only through its cloud job, ca-pim-publish, signed by its Key Vault key.)

function Resolve-PimMspBuildArgument {
    <#
      PURE. Replace the run-time placeholders in ONE argument value. -Resolved maps placeholder -> value; an unresolved
      placeholder is an ERROR (never passed on as literal text). Arrays are resolved element by element.
      Returns @{ ok; value; missing }.
    #>
    param([object]$Value, [hashtable]$Resolved = @{})
    $missing = New-Object System.Collections.Generic.List[string]
    $one = {
        param($v)
        if (-not ($v -is [string])) { return $v }
        # (71.33: the colon is optional -- {{signed-in-user}} has none, and without this it passed through as literal text)
        $m = [regex]::Matches($v, '\{\{[a-z\-]+(:[^}]+)?\}\}')
        if (-not $m.Count) { return $v }
        $r = $v
        foreach ($x in $m) {
            if ($Resolved.ContainsKey($x.Value) -and "$($Resolved[$x.Value])".Trim()) { $r = $r.Replace($x.Value, "$($Resolved[$x.Value])") }
            else { $missing.Add($x.Value) }
        }
        return $r
    }
    $val = if ($Value -is [array]) { @($Value | ForEach-Object { & $one $_ }) } else { & $one $Value }
    return @{ ok = ($missing.Count -eq 0); value = $val; missing = @($missing.ToArray()) }
}
