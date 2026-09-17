#Requires -Version 5.1
<#
.SYNOPSIS
    71.35 -- the signed-baseline PRODUCER, shared by the two publishers:
      * setup/New-PimBaselineBundle.ps1   -- the legacy host publish, signed with the CN=PIM4EntraPS-Baseline machine
                                             certificate (EFIF uses it until it is migrated)
      * tools/pim-engine/publish-job-entry.ps1 -- the master's Container Apps job (ca-pim-publish), running as its
                                             SYSTEM-ASSIGNED managed identity, signing with a NON-EXPORTABLE Key Vault key
    Both build the payload with Get-PimBaselineBundlePayload, so what a managed tenant receives cannot depend on which
    publisher produced it. Only the SIGNER differs.

.DESCRIPTION
    Get-PimBaselineBundlePayload          the registry + delegation-model read and the payload (moved VERBATIM from
                                          New-PimBaselineBundle.ps1; key order and serialisation unchanged)
    ConvertTo-PimBaselineDocJson          { product, payloadB64, signature, keyThumbprint [, signingKey] }
    Invoke-PimBaselineKeyVaultSign        RS256 through the Key Vault REST 'sign' operation over the SHA-256 digest;
                                          the returned signature is checked locally against the key's public half
    Invoke-PimBaselinePublishRun          build -> sign -> self-verify (the slave's verifier, pinned to the signing key)
                                          -> upload versioned + latest -> anonymous read-back -> verify again
    Get-PimBaselinePublishJobSpec         PURE. the job's env + YAML; refuses anything credential-shaped
    Get-PimBaselinePublishJobGrants       PURE. the job identity's ONLY data-plane grants (container + key scope)
    Get-PimBaselineSigningKeyPlan         PURE. create / keep / REFUSE a signing key read from ARM
    Get-PimBaselinePublishExecutionVerdict PURE. what the first-publish step does with an execution status

    ASCII only; PS 5.1 and pwsh 7.
#>

if ($PSScriptRoot) {
    # FILE scope, not inside a function: a dot-source inside a function vanishes when it returns (71.32).
    if (-not (Get-Command Select-PimBaselineBundleContent -ErrorAction SilentlyContinue)) {
        $__dl = Join-Path $PSScriptRoot 'PIM-Downlink.ps1'
        if (Test-Path -LiteralPath $__dl) { . $__dl }
    }
    if (-not (Get-Command Test-PimBaselineDoc -ErrorAction SilentlyContinue)) {
        $__bl = Join-Path $PSScriptRoot 'PIM-Baseline.ps1'
        if (Test-Path -LiteralPath $__bl) { . $__bl }
    }
}

$script:PimBaselineKvApi = '7.4'
$script:PimBaselineKeyUrlPattern = '^https://[a-z0-9-]{3,24}\.(vault\.azure\.net|vault\.azure\.cn|vault\.usgovcloudapi\.net)/keys/[A-Za-z0-9-]{1,127}(/[0-9a-fA-F]{32})?$'

function Get-PimBaselineBundlePayload {
    <#
      Read the master registry + delegation model through -RunQuery (param($sql) -> rows) and build the payload.
      Returns @{ payload; payloadJson; payloadBytes; version; rowCount; assignmentCount }.
      -RunQuery is a PLAIN scriptblock from the caller's scope (see the GetNewClosure note in New-PimBaselineBundle.ps1).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$RunQuery,
        [string]$Scope = 'fleet',
        [int]$ValidDays = 30
    )
    $sql = "SELECT UserName, DisplayName, FirstName, LastName, Initials, UsageLocation, Purpose, Ring, Template FROM pim.CentralAdmins WHERE Owner='MSP' AND Enabled=1 ORDER BY Ring"
    $sqlWithTarget = "SELECT UserName, DisplayName, FirstName, LastName, Initials, UsageLocation, Purpose, Ring, Template, Target FROM pim.CentralAdmins WHERE Owner='MSP' AND Enabled=1 ORDER BY Ring"
    # Operator decision 2026-08-13: the TAP intent travels WITH the admin (71.17: CreateTap is NOT published any more --
    # a TAP is enforced for every Entra admin; lifetime and the delivery address still travel).
    $sqlWithTap = "SELECT UserName, DisplayName, FirstName, LastName, Initials, UsageLocation, Purpose, Ring, Template, Target, TapLifetimeHours, ManagerEmail FROM pim.CentralAdmins WHERE Owner='MSP' AND Enabled=1 ORDER BY Ring"
    # BUG-60 / 71.7 (a): every entity the engine creates groups from (Get-PimGroupDefinitionRows); 'PIM-Definitions'
    # stays so an estate seeded that way is not stranded.
    $defEntities = @('PIM-Definitions-Roles','PIM-Definitions-Services','PIM-Definitions-Organization','PIM-Definitions-Tasks',
                     'PIM-Definitions-Departments','PIM-Definitions-Processes','PIM-Definitions-Projects','PIM-Definitions-CrossOrg','PIM-Definitions')
    # REQUIREMENTS 68.6 row 35 + 71: admin definitions, tenant-scoped resource bindings and the AU definitions they need.
    $entityList  = @('PIM-Assignments-Admins','PIM-Assignments-Groups','PIM-Assignments-Roles-Groups','Account-Definitions-Admins',
                     'PIM-Assignments-Roles-AUs','PIM-Assignments-Azure-Resources','PIM-Assignments-Workloads','PIM-Definitions-AU') + $defEntities
    $sqlAssign = "SELECT Entity, DataJson FROM pim.Rows WHERE Entity IN ('" + ($entityList -join "','") + "')"

    $rows = @(& $RunQuery $sql)
    $assignRaw = @(& $RunQuery $sqlAssign)

    # Re-read WITH Target when the registry has the column; a registry that predates it keeps
    # working and simply publishes no targets (= every artifact reaches every managed tenant).
    $hasTarget = $false
    try { $rows = @(& $RunQuery $sqlWithTarget); $hasTarget = $true }
    catch { Write-Host "  (no Target column in pim.CentralAdmins -- no admin is narrowed by target)" -ForegroundColor DarkGray }
    # Widen once more to the TAP intent. Ordered after Target so a registry that has Target but not
    # the TAP columns still keeps its targets -- the widest successful read wins, never the last one.
    $hasTap = $false
    if ($hasTarget) {
        try { $rows = @(& $RunQuery $sqlWithTap); $hasTap = $true }
        catch { Write-Host "  (no TapLifetimeHours/ManagerEmail in pim.CentralAdmins -- the downlink will apply its own default)" -ForegroundColor DarkGray }
    }
    $select = @('UserName','DisplayName','FirstName','LastName','Initials','UsageLocation','Purpose','Ring','Template')
    if ($hasTarget) { $select += 'Target' }
    if ($hasTap)    { $select += @('TapLifetimeHours','ManagerEmail') }
    $rowObjs = @($rows | Select-Object $select)
    Write-Host "baseline rows (Owner=MSP): $($rowObjs.Count)"
    # 71 (framework MSP-4 SURFACE): the registry's own Replicate column, used only to decide publication.
    $registryReplicate = @{}
    try {
        foreach ($rr in @(& $RunQuery "SELECT UserName, Replicate FROM pim.CentralAdmins WHERE Owner='MSP' AND Enabled=1")) {
            if ("$($rr.Replicate)".Trim()) { $registryReplicate["$($rr.UserName)".Trim().ToLowerInvariant()] = "$($rr.Replicate)".Trim() }
        }
    } catch { Write-Host "  (no Replicate column in pim.CentralAdmins -- every registry row is published, as before)" -ForegroundColor DarkGray }

    # WHAT SHIPS -- decided by the PURE Select-PimBaselineBundleContent (PIM-Downlink.ps1), which the Manager's reach
    # preview also uses (BUG-59, BUG-61, 71.7).
    $byEntity = @{}
    foreach ($raw in $assignRaw) {
        $e = "$($raw.Entity)"
        if (-not $byEntity.ContainsKey($e)) { $byEntity[$e] = New-Object System.Collections.Generic.List[object] }
        $o = $null
        try { $o = "$($raw.DataJson)" | ConvertFrom-Json } catch { continue }
        if ($o) { $byEntity[$e].Add($o) | Out-Null }
    }
    $entities = @{}
    foreach ($k in $byEntity.Keys) { $entities[$k] = @($byEntity[$k].ToArray()) }
    $content = Select-PimBaselineBundleContent -RegistryRows $rowObjs -RegistryReplicate $registryReplicate -Entities $entities
    $rowObjs = @($content.rows)
    $defAdmins = $content.report.defAdmins
    Write-Host ("baseline rows from admin definitions (ManagementMode=msp): +{0}; not synced: {1}; msp without a Ring: {2}; AD-only (never synced): {3}" -f `
        $content.report.addedFromDefinitions, @($defAdmins.notSynced).Count, @($defAdmins.mspWithoutRing).Count, @($defAdmins.adOnly).Count)
    foreach ($x in @($defAdmins.mspWithoutRing)) { Write-Host "  NOT PUBLISHED $($x.UserName): $($x.reason)" -ForegroundColor Yellow }
    foreach ($x in @($content.report.notPublished)) { Write-Host "  NOT PUBLISHED ($($x.kind)) $($x.name): $($x.reason)" -ForegroundColor Yellow }
    foreach ($x in @($content.report.dependencyIncluded)) { Write-Host "  [warn] CARRIED AS A DEPENDENCY ($($x.kind)) $($x.name): $($x.reason)" -ForegroundColor Yellow }
    $assignArr = @($content.assignments)
    $skipped = [int]$content.report.skippedAssignments
    Write-Host "baseline role assignments (MSP admins): $($assignArr.Count)$(if ($skipped) { " ($skipped row(s) belonged to non-MSP admins -- not published)" })"
    $defArr  = @($content.definitions.groups)
    $nestArr = @($content.definitions.nestings)
    $bindArr = @($content.definitions.roleBindings)

    # 1d. The PER-RELATIONSHIP projection policy, carried IN the bundle (signed), keyed by tenant id: a downlink running
    # inside the slave has no credential for the master's registry.
    $policyMap = [ordered]@{}
    try {
        $polRaw = @(& $RunQuery "SELECT CONVERT(nvarchar(50), TenantId) AS TenantId, Mode, GroupTag FROM pim.TenantRoleProjection")
        foreach ($p in $polRaw) {
            $tid = "$($p.TenantId)".Trim().ToLowerInvariant()
            if (-not $tid) { continue }
            if (-not $policyMap.Contains($tid)) { $policyMap[$tid] = New-Object System.Collections.Generic.List[object] }
            $policyMap[$tid].Add([ordered]@{ Mode = "$($p.Mode)"; GroupTag = "$($p.GroupTag)" }) | Out-Null
        }
    } catch {
        Write-Host "  (no pim.TenantRoleProjection in this registry -- every relationship projects everything)" -ForegroundColor DarkGray
    }
    $policyOut = [ordered]@{}
    foreach ($k in $policyMap.Keys) { $policyOut[$k] = @($policyMap[$k].ToArray()) }
    $policyCount = 0; foreach ($k in $policyOut.Keys) { $policyCount += @($policyOut[$k]).Count }
    Write-Host "baseline projection policy: $policyCount rule(s) across $(@($policyOut.Keys).Count) relationship(s)"
    foreach ($k in $policyOut.Keys) {
        foreach ($r in @($policyOut[$k])) { Write-Host ("    {0}  {1}: {2}" -f $k, $r.Mode, $r.GroupTag) -ForegroundColor DarkGray }
    }

    # 1e. MSP-4 (BUG-62): the PER-TENANT TAG MAP, carried in the bundle for the same reason.
    $tagsOut = [ordered]@{}
    try {
        $tagRaw = @(& $RunQuery "SELECT CONVERT(nvarchar(50), TenantId) AS TenantId, Tags FROM platform.Tenants WHERE Enabled = 1")
        foreach ($t in $tagRaw) {
            $tid = "$($t.TenantId)".Trim().ToLowerInvariant()
            if (-not $tid) { continue }
            $list = @("$($t.Tags)" -split '[;,]' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
            if ($list.Count) { $tagsOut[$tid] = $list }
        }
    } catch {
        Write-Host "  (no Tags column in platform.Tenants -- no tenant is tagged, so no artifact is narrowed by target)" -ForegroundColor DarkGray
    }
    $tagCount = 0; foreach ($k in $tagsOut.Keys) { $tagCount += @($tagsOut[$k]).Count }
    Write-Host "baseline tenant tags: $tagCount tag(s) across $(@($tagsOut.Keys).Count) tenant(s)"

    $orphan = @($content.report.orphanTags)
    Write-Host "baseline definitions carried: $($defArr.Count) group(s), $($nestArr.Count) nesting(s), $($bindArr.Count) role binding(s)$(if ($content.definitions.Contains('resourceBindings')) { ", $(@($content.definitions.resourceBindings).Count) resource binding(s)" })"
    if ($orphan.Count) { Write-Host "  [warn] $($orphan.Count) projected tag(s) have NO group definition in the master: $($orphan -join ', ')" -ForegroundColor Yellow }
    foreach ($b in $bindArr) { Write-Host ("    binds {0,-42} -> {1}" -f $b.GroupTag, $b.RoleDefinitionName) -ForegroundColor DarkGray }

    # 2. Build the payload (key order identical to the pre-71.35 producer; the no-regression byte rule).
    $version = [int64](Get-Date -Format 'yyMMddHHmm')
    $payload = [ordered]@{
        product        = 'PIM4EntraPS'
        kind           = 'baseline'
        version        = $version
        scope          = $Scope
        generatedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        validToUtc     = (Get-Date).ToUniversalTime().AddDays($ValidDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
        rows           = $rowObjs
        assignments    = $assignArr
        definitions    = $content.definitions
        projectionPolicy = $policyOut
        tenantTags       = $tagsOut
    }
    $payloadJson  = ($payload | ConvertTo-Json -Depth 8 -Compress)
    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)
    return @{ payload = $payload; payloadJson = $payloadJson; payloadBytes = $payloadBytes; version = $version
              rowCount = $rowObjs.Count; assignmentCount = $assignArr.Count }
}

function ConvertTo-PimBaselineDocJson {
    <#
      The signed document. Certificate-signed: { product, payloadB64, signature, keyThumbprint } -- byte-identical to the
      pre-71.35 producer. Key Vault signed: the same four, keyThumbprint = the key id (RFC 7638), plus signingKey
      { kty, n, e, kid } -- carried so a verifier can check it, TRUSTED only when the key id is pinned by the reader.
    #>
    param(
        [Parameter(Mandatory)][byte[]]$PayloadBytes,
        [Parameter(Mandatory)][byte[]]$SignatureBytes,
        [Parameter(Mandatory)][string]$KeyThumbprint,
        [object]$SigningKey
    )
    $doc = [ordered]@{
        product       = 'PIM4EntraPS'
        payloadB64    = [Convert]::ToBase64String($PayloadBytes)
        signature     = [Convert]::ToBase64String($SignatureBytes)
        keyThumbprint = $KeyThumbprint
    }
    if ($null -ne $SigningKey) { $doc['signingKey'] = $SigningKey }
    return ($doc | ConvertTo-Json -Depth 3)
}

function Test-PimBaselineSigningKeyUrl {
    param([string]$KeyId)
    return [bool]("$KeyId".Trim() -match $script:PimBaselineKeyUrlPattern -and "$KeyId" -notmatch '[?#]')
}

function Invoke-PimBaselineKeyVaultRest {
    # The default -Rest for Invoke-PimBaselineKeyVaultSign: a Key Vault data-plane call as the ambient identity
    # (in the job: its managed identity, via Get-PimRestToken). Never a secret, never a certificate.
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, [object]$Body)
    $tok = Get-PimRestToken -Resource 'https://vault.azure.net'
    $h = @{ Authorization = "Bearer $tok" }
    if ($Method -eq 'GET') { return (Invoke-RestMethod -Method GET -Uri $Uri -Headers $h -ErrorAction Stop) }
    $json = $Body | ConvertTo-Json -Depth 5 -Compress
    return (Invoke-RestMethod -Method $Method -Uri $Uri -Headers $h -ContentType 'application/json' -Body ([System.Text.Encoding]::UTF8.GetBytes($json)) -ErrorAction Stop)
}

function Invoke-PimBaselineKeyVaultSign {
    <#
      Sign -PayloadBytes with a Key Vault RSA key. RS256 in Key Vault = RSASSA-PKCS1-v1_5 with SHA-256 over a DIGEST the
      caller computes: exactly RSA.SignData(payload, SHA256, Pkcs1) on the certificate path, and deterministic, so the
      slave's VerifyData(payload, sig, SHA256, Pkcs1) accepts it unchanged.
        1. GET  <key>?api-version=7.4           -> kid (with version), kty, n, e, key_ops, attributes
        2. POST <kid>/sign  { alg: RS256, value: base64url(SHA-256(payload)) }
        3. the base64url signature -> bytes, LEFT-PADDED to the modulus length (I2OSP), then VERIFIED locally against the
           public half from step 1 -- a signature that does not verify is never returned.
      REFUSED: a key that is not RSA, cannot sign, is exportable, is under 2048 bits, or a kid that changed between 1 and 2.
      -Rest: param($Method, $Uri, $Body) -> parsed JSON (test seam; default Invoke-PimBaselineKeyVaultRest).
      Returns @{ signatureBytes; keyId; kid; signingKey = [ordered]@{ kty; n; e; kid } }.
    #>
    param(
        [Parameter(Mandatory)][string]$KeyId,
        [Parameter(Mandatory)][byte[]]$PayloadBytes,
        [scriptblock]$Rest
    )
    if (-not $Rest) { $Rest = { param($Method, $Uri, $Body) Invoke-PimBaselineKeyVaultRest -Method $Method -Uri $Uri -Body $Body } }
    $url = "$KeyId".Trim().TrimEnd('/')
    if (-not (Test-PimBaselineSigningKeyUrl -KeyId $url)) { throw "signing key id '$KeyId' is not a Key Vault key URL (https://<vault>.vault.azure.net/keys/<name>[/<version>])" }
    $k = & $Rest 'GET' ($url + '?api-version=' + $script:PimBaselineKvApi) $null
    if ($null -eq $k -or $null -eq $k.key) { throw "Key Vault returned no key for $url" }
    $kty = "$($k.key.kty)"
    if ($kty -notmatch '^RSA(-HSM)?$') { throw "signing key $url is '$kty' -- REFUSED (RSA or RSA-HSM only)" }
    if (@($k.key.key_ops) -notcontains 'sign') { throw "signing key $url does not permit 'sign' (key_ops: $(@($k.key.key_ops) -join ','))" }
    if ($k.attributes -and $k.attributes.PSObject.Properties['exportable'] -and [bool]$k.attributes.exportable) { throw "signing key $url is EXPORTABLE -- REFUSED (the private key must never leave the vault)" }
    $kid = "$($k.key.kid)".Trim()
    if (-not (Test-PimBaselineSigningKeyUrl -KeyId $kid) -or $kid -notmatch '/[0-9a-fA-F]{32}$') { throw "Key Vault returned kid '$kid' without a version" }
    $n = "$($k.key.n)"; $e = "$($k.key.e)"
    $modBytes = Get-PimBaselineUnsignedBytes -Bytes (ConvertFrom-PimBaselineB64 -Value $n)
    if (($modBytes.Length * 8) -lt 2048) { throw "signing key $url is $($modBytes.Length * 8) bits -- REFUSED (2048 minimum)" }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $digest = $sha.ComputeHash($PayloadBytes) } finally { $sha.Dispose() }
    $resp = & $Rest 'POST' ($kid + '/sign?api-version=' + $script:PimBaselineKvApi) @{ alg = 'RS256'; value = (ConvertTo-PimBaselineB64Url -Bytes $digest) }
    if ($null -eq $resp -or -not "$($resp.value)".Trim()) { throw 'Key Vault sign returned no signature' }
    if ("$($resp.kid)".Trim() -and "$($resp.kid)".Trim() -ne $kid) { throw "Key Vault signed with '$($resp.kid)', not the key version read ('$kid') -- REFUSED" }
    $sig = ConvertFrom-PimBaselineB64 -Value "$($resp.value)"
    if ($sig.Length -gt $modBytes.Length) { throw "signature is $($sig.Length) bytes for a $($modBytes.Length)-byte modulus -- REFUSED" }
    if ($sig.Length -lt $modBytes.Length) {
        $padded = New-Object byte[] $modBytes.Length
        [Array]::Copy($sig, 0, $padded, $modBytes.Length - $sig.Length, $sig.Length)
        $sig = $padded
    }
    $rsa = New-PimBaselineRsaPublicKey -N $n -E $e
    try { $ok = $rsa.VerifyData($PayloadBytes, $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) }
    finally { $rsa.Dispose() }
    if (-not $ok) { throw 'the Key Vault signature does NOT verify against the key''s own public half -- nothing is published' }
    $signingKey = [ordered]@{
        kty = 'RSA'
        n   = ConvertTo-PimBaselineB64Url -Bytes $modBytes
        e   = ConvertTo-PimBaselineB64Url -Bytes (Get-PimBaselineUnsignedBytes -Bytes (ConvertFrom-PimBaselineB64 -Value $e))
        kid = $kid
    }
    return @{ signatureBytes = $sig; keyId = (Get-PimBaselineKeyId -N $n -E $e); kid = $kid; signingKey = $signingKey }
}

function Invoke-PimBaselinePublishRun {
    <#
      One publish, end to end, with every side effect behind a seam (the job wires the real ones):
        -RunQuery  param($sql) -> rows                        (the master store, as the managed identity)
        -Signer    param([byte[]]$payload) -> @{ signatureBytes; keyId; signingKey }
        -Upload    param($blobName, [string]$json)            (Put Blob as the managed identity)
        -Fetch     param($blobName) -> [string]               (ANONYMOUS GET -- the managed tenant's own read path)
      Order: build -> sign -> SELF-VERIFY with the slave's verifier pinned to exactly the signing key -> upload
      baseline-v<version>.json, then baseline-latest.json -> anonymous read-back of latest -> byte-compare + verify again.
      Nothing is uploaded unless the self-verify passed. Returns @{ ok; reason; version; keyId; sha256; blobs; readBack }.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$RunQuery,
        [Parameter(Mandatory)][scriptblock]$Signer,
        [Parameter(Mandatory)][scriptblock]$Upload,
        [scriptblock]$Fetch,
        [string]$Scope = 'fleet',
        [int]$ValidDays = 30
    )
    if ($ValidDays -lt 2) { return @{ ok = $false; reason = 'ValidDays must be at least 2 (a daily publish needs overlap)' } }
    $built = Get-PimBaselineBundlePayload -RunQuery $RunQuery -Scope $Scope -ValidDays $ValidDays
    $s = & $Signer $built.payloadBytes
    if ($null -eq $s -or $null -eq $s.signatureBytes -or -not (Test-PimBaselineKeyIdFormat -KeyId "$($s.keyId)")) { return @{ ok = $false; reason = 'the signer returned no signature / key id' } }
    $docJson = ConvertTo-PimBaselineDocJson -PayloadBytes $built.payloadBytes -SignatureBytes ([byte[]]$s.signatureBytes) -KeyThumbprint "$($s.keyId)" -SigningKey $s.signingKey
    try { $null = Test-PimBaselineDoc -Doc ($docJson | ConvertFrom-Json) -TrustedKeyIds @("$($s.keyId)") }
    catch { return @{ ok = $false; reason = "SELF-VERIFY FAILED (nothing uploaded): $($_.Exception.Message)" } }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $docSha = (-join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($docJson)) | ForEach-Object { $_.ToString('x2') })) } finally { $sha.Dispose() }
    $blobs = @("baseline-v$($built.version).json", 'baseline-latest.json')
    foreach ($b in $blobs) { & $Upload $b $docJson }
    $readBack = 'not checked'
    if ($Fetch) {
        $got = "$(& $Fetch 'baseline-latest.json')"
        $br = $got.IndexOf('{'); if ($br -gt 0) { $got = $got.Substring($br) }
        if ($got.Trim() -ne $docJson.Trim()) { return @{ ok = $false; reason = 'READ-BACK MISMATCH: the anonymous GET of baseline-latest.json did not return the document just uploaded'; version = $built.version; keyId = "$($s.keyId)"; sha256 = $docSha; blobs = $blobs } }
        try { $null = Test-PimBaselineDoc -Doc ($got | ConvertFrom-Json) -TrustedKeyIds @("$($s.keyId)") }
        catch { return @{ ok = $false; reason = "READ-BACK VERIFY FAILED: $($_.Exception.Message)"; version = $built.version; keyId = "$($s.keyId)"; sha256 = $docSha; blobs = $blobs } }
        $readBack = 'anonymous GET returned the same bytes and they verify'
    }
    return @{ ok = $true; reason = "published v$($built.version) ($($built.rowCount) rows, $($built.assignmentCount) assignments)"; version = $built.version
              keyId = "$($s.keyId)"; sha256 = $docSha; blobs = $blobs; readBack = $readBack }
}

function Get-PimBaselinePublishJobGrants {
    <#
      PURE. The publish job identity's data-plane grants, and NOTHING wider:
        Storage Blob Data Contributor  on the bundle CONTAINER (not the account, not the resource group)
        Key Vault Crypto User          on the signing KEY (not the vault). The key's own key_ops are sign + verify, so
                                       the role's encrypt/decrypt/wrap data actions have nothing to act on: effectively
                                       sign + read the public key. (No built-in role is narrower without a custom role.)
      SQL is reached through the SQL admin group membership, not a role here. No secret, no account key, no SAS.
    #>
    param(
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$StorageResourceGroup,
        [Parameter(Mandatory)][string]$StorageAccount,
        [Parameter(Mandatory)][string]$Container,
        [Parameter(Mandatory)][string]$KeyVaultResourceGroup,
        [Parameter(Mandatory)][string]$KeyVaultName,
        [Parameter(Mandatory)][string]$KeyName
    )
    return @(
        [pscustomobject]@{ role = 'Storage Blob Data Contributor'; scope = "/subscriptions/$SubscriptionId/resourceGroups/$StorageResourceGroup/providers/Microsoft.Storage/storageAccounts/$StorageAccount/blobServices/default/containers/$Container"; why = 'write baseline-v<n>.json + baseline-latest.json' }
        [pscustomobject]@{ role = 'Key Vault Crypto User'; scope = "/subscriptions/$SubscriptionId/resourceGroups/$KeyVaultResourceGroup/providers/Microsoft.KeyVault/vaults/$KeyVaultName/keys/$KeyName"; why = 'sign the bundle (key_ops sign+verify); read the public half' }
    )
}

function Get-PimBaselinePublishJobSpec {
    <#
      PURE. The Container Apps job definition for ca-pim-publish. Returns @{ ok; reason; env ([ordered] name -> value); yaml }.
      REFUSED: a signing key that is not a Key Vault key URL; a store name that is not a storage account; ValidDays < 2; a cron
      that is not 5 fields; and any env value that looks like a credential (SAS signature, account key, private key,
      client secret, certificate thumbprint). The job runs as its SYSTEM-ASSIGNED identity; -RegistryIdentity only pulls.
    #>
    param(
        [Parameter(Mandatory)][string]$JobName,
        [Parameter(Mandatory)][string]$Image,
        [Parameter(Mandatory)][string]$EnvironmentId,
        [Parameter(Mandatory)][string]$Location,
        [string]$Cron = '0 4 * * *',
        [Parameter(Mandatory)][string]$RegistryServer,
        [string]$RegistryIdentity = 'system',
        [Parameter(Mandatory)][string]$SqlServerFqdn,
        [string]$SqlDatabase = 'PimPlatform',
        [Parameter(Mandatory)][string]$StorageAccount,
        [string]$Container = 'baselines',
        [Parameter(Mandatory)][string]$SigningKeyId,
        [int]$ValidDays = 30,
        [string]$Scope = 'fleet',
        [bool]$Exists = $false,
        [string]$EntryPath = '/app/PIM4EntraPS/tools/pim-engine/publish-job-entry.ps1'
    )
    if (-not (Test-PimBaselineSigningKeyUrl -KeyId $SigningKeyId) -or "$SigningKeyId" -notmatch '/[0-9a-fA-F]{32}$') { return @{ ok = $false; reason = "signing key id '$SigningKeyId' must be a VERSIONED Key Vault key URL (https://<vault>.vault.azure.net/keys/<name>/<version>): a key roll is then a deliberate redeploy, never a silent switch" } }
    if ("$StorageAccount" -notmatch '^[a-z0-9]{3,24}$') { return @{ ok = $false; reason = "'$StorageAccount' is not a storage account name" } }
    if ($ValidDays -lt 2) { return @{ ok = $false; reason = 'ValidDays must be at least 2 (a daily publish needs overlap)' } }
    if (@("$Cron".Trim() -split '\s+').Count -ne 5) { return @{ ok = $false; reason = "cron '$Cron' is not a 5-field expression" } }
    if ("$SqlServerFqdn" -notmatch '^[a-z0-9-]+\.database\.(windows\.net|chinacloudapi\.cn|usgovcloudapi\.net)$') { return @{ ok = $false; reason = "'$SqlServerFqdn' is not an Azure SQL server name" } }
    $env = [ordered]@{
        PIM_HOSTED                 = '1'
        PIM_UseGraphSdk            = 'false'
        PIM_StorageBackend         = 'sql'
        PIM_SqlServer              = "$SqlServerFqdn"
        PIM_SqlDatabase            = "$SqlDatabase"
        PIM_BaselineStorageAccount = "$StorageAccount"
        PIM_BaselineContainer      = "$Container"
        PIM_BaselineSigningKeyId   = "$SigningKeyId".Trim()
        PIM_BaselineValidDays      = "$ValidDays"
        PIM_BaselineScope          = "$Scope"
    }
    foreach ($k in @($env.Keys)) {
        $v = "$($env[$k])"
        if ($k -match '(?i)secret|password|thumbprint|sas|accountkey|connectionstring|privatekey' -or $v -match '(?i)([?&]sig=|AccountKey=|SharedAccessKey=|-----BEGIN|secretref:)') {
            return @{ ok = $false; reason = "REFUSED: env '$k' looks like a credential -- the publish job runs as its managed identity and carries none" }
        }
    }
    $identityYaml = 'identity: { type: SystemAssigned }'
    $regId = "$RegistryIdentity".Trim()
    if ($regId -and $regId -ne 'system') { $identityYaml = "identity: { type: `"SystemAssigned, UserAssigned`", userAssignedIdentities: { `"$regId`": {} } }" }
    else { $regId = 'system' }
    $y = New-Object System.Collections.Generic.List[string]
    [void]$y.Add("location: $Location")
    if (-not $Exists) { [void]$y.Add($identityYaml) }
    [void]$y.Add('properties:')
    [void]$y.Add("  environmentId: $EnvironmentId")
    [void]$y.Add('  configuration:')
    [void]$y.Add('    triggerType: Schedule')
    [void]$y.Add('    replicaTimeout: 1200')
    [void]$y.Add('    replicaRetryLimit: 1')
    [void]$y.Add('    scheduleTriggerConfig:')
    [void]$y.Add("      cronExpression: `"$("$Cron".Trim())`"")
    [void]$y.Add('      parallelism: 1')
    [void]$y.Add('      replicaCompletionCount: 1')
    [void]$y.Add("    registries: [ { server: `"$RegistryServer`", identity: `"$regId`" } ]")
    [void]$y.Add('  template:')
    [void]$y.Add('    containers:')
    [void]$y.Add("      - name: $JobName")
    [void]$y.Add("        image: $Image")
    [void]$y.Add('        command: [pwsh]')
    [void]$y.Add("        args: [`"-NoProfile`", `"-ExecutionPolicy`", `"Bypass`", `"-File`", `"$EntryPath`"]")
    [void]$y.Add('        env: [ ' + ((@($env.Keys) | ForEach-Object { "{ name: $_, value: `"$($env[$_])`" }" }) -join ', ') + ' ]')
    [void]$y.Add('        resources: { cpu: 0.5, memory: 1.0Gi }')
    return @{ ok = $true; reason = ''; env = $env; yaml = (($y.ToArray()) -join "`n") }
}

function Get-PimBaselineSigningKeyPlan {
    <#
      PURE. -Existing: the key as ARM returns it (properties.kty / keySize / keyOps / attributes.exportable), or $null.
      -VaultSku: standard | premium. Premium -> RSA-HSM (HSM-protected); standard -> RSA (software-protected). Both are
      non-exportable: no release policy is ever set.
      Returns @{ action = 'create'|'none'|'refuse'; kty; body; reason }. An existing key is NEVER modified or re-versioned
      (ARM PUT on an existing key is a no-op by contract, and this plan does not even send it): a key that is not RSA, can
      do more than sign/verify, is under 2048 bits or is exportable is REFUSED -- pick another -KeyName.
    #>
    param([object]$Existing, [string]$VaultSku = 'standard', [ValidateSet(2048, 3072, 4096)][int]$KeySize = 3072)
    $kty = if ("$VaultSku".Trim() -ieq 'premium') { 'RSA-HSM' } else { 'RSA' }
    if ($null -eq $Existing) {
        return @{ action = 'create'; kty = $kty; reason = "create $kty $KeySize (sign+verify, not exportable)"
                  body = @{ properties = @{ kty = $kty; keySize = $KeySize; keyOps = @('sign', 'verify'); attributes = @{ enabled = $true } } } }
    }
    $p = $Existing.properties
    $ek = "$($p.kty)"; $ops = @($p.keyOps | ForEach-Object { "$_".ToLowerInvariant() })
    if ($ek -notmatch '^RSA(-HSM)?$') { return @{ action = 'refuse'; kty = $ek; reason = "the existing key is '$ek', not RSA -- REFUSED (use another key name)" } }
    if ($ops -notcontains 'sign') { return @{ action = 'refuse'; kty = $ek; reason = 'the existing key cannot sign -- REFUSED' } }
    $extra = @($ops | Where-Object { $_ -notin @('sign', 'verify') })
    if ($extra.Count) { return @{ action = 'refuse'; kty = $ek; reason = "the existing key also permits $($extra -join ', ') -- REFUSED (a signing key does sign and verify only)" } }
    if ($null -ne $p.keySize -and [int]$p.keySize -lt 2048) { return @{ action = 'refuse'; kty = $ek; reason = "the existing key is $($p.keySize) bits -- REFUSED (2048 minimum)" } }
    if ($p.attributes -and [bool]$p.attributes.exportable) { return @{ action = 'refuse'; kty = $ek; reason = 'the existing key is EXPORTABLE -- REFUSED' } }
    return @{ action = 'none'; kty = $ek; reason = "key exists ($ek $($p.keySize), $($ops -join '+')) -- kept as is" }
}

function Get-PimBaselinePublishExecutionVerdict {
    <#
      PURE. The first-publish step after a job execution ENDS. Succeeded -> done. Failed/Degraded on an attempt before the
      last -> retry (a brand-new identity's storage/Key Vault role assignments can take minutes to reach the data plane).
      Anything else, or the last attempt -> fail. Returns @{ action = 'done'|'retry'|'fail'; reason }.
    #>
    param([string]$Status, [int]$Attempt = 1, [int]$MaxAttempts = 4)
    $s = "$Status".Trim()
    if ($s -eq 'Succeeded') { return @{ action = 'done'; reason = 'the publish execution Succeeded (it exits non-zero unless it signed, uploaded, read back anonymously and verified)' } }
    if ($s -in @('Failed', 'Degraded') -and $Attempt -lt $MaxAttempts) { return @{ action = 'retry'; reason = "execution $s on attempt $Attempt of $MaxAttempts -- role assignments on a new identity can take minutes; retrying" } }
    return @{ action = 'fail'; reason = "execution ended '$s' on attempt $Attempt of $MaxAttempts" }
}
