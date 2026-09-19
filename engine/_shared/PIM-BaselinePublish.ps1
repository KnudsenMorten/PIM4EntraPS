#Requires -Version 5.1
<#
.SYNOPSIS
    71.35 -- the signed-baseline PRODUCER. Its publisher is tools/pim-engine/publish-job-entry.ps1 -- the master's
    Container Apps job (ca-pim-publish), running as its SYSTEM-ASSIGNED managed identity and signing with a
    NON-EXPORTABLE Key Vault key.
    SEC-27 (operator 2026-09-18): the pre-71.35 HOST publisher (setup/New-PimBaselineBundle.ps1, signed with the
    CN=PIM4EntraPS-Baseline machine certificate, scheduled by tools/setup/Register-PimBaselinePublish.ps1) is RETIRED
    and deleted, together with the SAS transport. A managed tenant still VERIFIES certificate-signed bundles (the
    embedded public certificate in PIM-Baseline.ps1), but nothing in the product produces one any more.

.DESCRIPTION
    Get-PimBaselineBundlePayload          the registry + delegation-model read and the payload (moved VERBATIM from
                                          the retired host publisher; key order and serialisation unchanged)
    ConvertTo-PimBaselineDocJson          { product, payloadB64, signature, keyThumbprint [, signingKey] }
    Invoke-PimBaselineKeyVaultSign        RS256 through the Key Vault REST 'sign' operation over the SHA-256 digest;
                                          the returned signature is checked locally against the key's public half
    Invoke-PimBaselinePublishRun          build -> sign -> self-verify (the slave's verifier, pinned to the signing key)
                                          -> upload versioned + latest -> anonymous read-back -> verify again
    Get-PimBaselinePublishJobSpec         PURE. the job's env + YAML; refuses anything credential-shaped
    Get-PimBaselinePublishJobGrants       PURE. the job identity's ONLY data-plane grants (container + key scope)
    Get-PimBaselineSigningKeyPlan         PURE. create / keep / REFUSE a signing key read from ARM
    Get-PimBaselinePublishExecutionVerdict PURE. what the first-publish step does with an execution status
    New-PimCentralKillPayload / ConvertTo-PimCentralKillEntry  SEC-25: PURE. the signed central-kill manifest's payload
    Invoke-PimCentralKillPublishRun       SEC-25: sign (same signer + document shape as the bundle) -> the consumer's
                                          verdict = active -> upload -> anonymous read-back -> verdict again
    Invoke-PimCentralKillWithdrawRun      SEC-25: delete central-kill.json -> the consumer reads 404 = none
                                          (driven by tools/setup/Publish-PimCentralKill.ps1)

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
    # The published-entity list (shared with the Manager's publish-on-commit hook) and the job's cadence defaults.
    if (-not (Test-Path Function:\Get-PimBaselinePublishedEntities)) {
        $__jc = Join-Path $PSScriptRoot 'PIM-JobCadence.ps1'
        if (Test-Path -LiteralPath $__jc) { . $__jc }
    }
}

$script:PimBaselineKvApi = '7.4'
$script:PimBaselineKeyUrlPattern = '^https://[a-z0-9-]{3,24}\.(vault\.azure\.net|vault\.azure\.cn|vault\.usgovcloudapi\.net)/keys/[A-Za-z0-9-]{1,127}(/[0-9a-fA-F]{32})?$'

function Test-PimBaselineAbsentObjectError {
    <#
      PURE. Is this error a GENUINELY MISSING optional table / column -- and only that? SQL Server says so with error
      208 ("Invalid object name '<table>'") or 207 ("Invalid column name '<column>'"), naming the object. Anything else
      -- permission denied (229/230), a timeout, a dropped connection, a login failure -- is NOT "absent".
      WHY THIS MATTERS: each optional read below NARROWS what ships (Target, Replicate, the relationship policy,
      the tenant tags). Treating any failure as "absent" made the bundle fail OPEN: a transient or permission error on
      pim.TenantRoleProjection published "every relationship projects everything" -- privilege WIDENED in customer
      tenants, silently, by a read that merely failed. -Name must appear in the message, so a 208 about some OTHER
      object does not count either.
    #>
    param([Parameter(Mandatory)][object]$ErrorRecord, [Parameter(Mandatory)][string]$Name)
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } elseif ($ErrorRecord -is [System.Exception]) { $ErrorRecord } else { $null }
    $texts = New-Object System.Collections.Generic.List[string]
    $numbers = New-Object System.Collections.Generic.List[int]
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord] -and $null -eq $ex) { $texts.Add("$ErrorRecord") }
    $depth = 0
    while ($null -ne $ex -and $depth -lt 8) {
        $texts.Add("$($ex.Message)")
        $np = $ex.PSObject.Properties['Number']
        if ($np -and "$($np.Value)" -match '^\d+$') { $numbers.Add([int]$np.Value) }
        $ex = $ex.InnerException; $depth++
    }
    $all = $texts.ToArray() -join ' | '
    $named = $all.IndexOf($Name, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
    $isMissing = (@($numbers | Where-Object { $_ -eq 207 -or $_ -eq 208 }).Count -gt 0) -or ($all -match "Invalid (object|column) name")
    $otherNumber = @($numbers | Where-Object { $_ -ne 207 -and $_ -ne 208 -and $_ -ne 0 }).Count -gt 0 -and -not (@($numbers | Where-Object { $_ -eq 207 -or $_ -eq 208 }).Count)
    return [bool]($isMissing -and $named -and -not $otherNumber)
}

function Invoke-PimBaselineOptionalRead {
    # One optional read: rows on success; $null when the object is GENUINELY absent (reported); a THROW otherwise.
    param([Parameter(Mandatory)][scriptblock]$RunQuery, [Parameter(Mandatory)][string]$Sql, [Parameter(Mandatory)][string]$Name,
          [Parameter(Mandatory)][string]$What, [Parameter(Mandatory)][string]$AbsentNote)
    try { return , @(& $RunQuery $Sql) }
    catch {
        if (Test-PimBaselineAbsentObjectError -ErrorRecord $_ -Name $Name) { Write-Host "  ($AbsentNote)" -ForegroundColor DarkGray; return $null }
        throw ("BUNDLE REFUSED: reading $What failed ($($_.Exception.Message)). This is NOT treated as 'absent' -- that would " +
               "publish a WIDER bundle than the master defines. Fix the read (permissions / connectivity) and publish again.")
    }
}

function Get-PimBaselineBundlePayload {
    <#
      Read the master registry + delegation model through -RunQuery (param($sql) -> rows) and build the payload.
      Returns @{ payload; payloadJson; payloadBytes; version; rowCount; assignmentCount }.
      -RunQuery is a PLAIN scriptblock from the caller's scope. TRAP: NO .GetNewClosure() on it (found while building 71):
      a closure runs in a NEW module scope that chains to GLOBAL, not to the caller -- so a dot-sourced
      Invoke-PimSqlQuery was invisible inside it, every defensive re-read threw, was caught as "the registry predates
      the column", and the bundle silently shipped with NO Target and NO policy -- a failure that WIDENS reach.
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
    # BUG-60 / 71.7 (a) + REQUIREMENTS 68.6 row 35 + 71: the entities that ship. ONE list (PIM-JobCadence.ps1), shared with
    # the Manager's hook that requests a publish when a commit changed one of them -- so the two cannot drift apart.
    $entityList  = @(Get-PimBaselinePublishedEntities)
    $sqlAssign = "SELECT Entity, DataJson FROM pim.Rows WHERE Entity IN ('" + ($entityList -join "','") + "')"

    $rows = @(& $RunQuery $sql)
    $assignRaw = @(& $RunQuery $sqlAssign)

    # Re-read WITH Target when the registry has the column; a registry that predates it keeps
    # working and simply publishes no targets (= every artifact reaches every managed tenant).
    # Every optional read goes through Invoke-PimBaselineOptionalRead: ONLY a genuinely missing column/table (SQL 207 /
    # 208 naming it) counts as absent; any other failure REFUSES the bundle (it used to fail open -- see
    # Test-PimBaselineAbsentObjectError).
    $hasTarget = $false
    $rt = Invoke-PimBaselineOptionalRead -RunQuery $RunQuery -Sql $sqlWithTarget -Name 'Target' -What 'pim.CentralAdmins.Target' `
              -AbsentNote 'no Target column in pim.CentralAdmins -- no admin is narrowed by target'
    if ($null -ne $rt) { $rows = @($rt); $hasTarget = $true }
    # Widen once more to the TAP intent. Ordered after Target so a registry that has Target but not
    # the TAP columns still keeps its targets -- the widest successful read wins, never the last one.
    $hasTap = $false
    if ($hasTarget) {
        $rtap = $null
        try { $rtap = @(& $RunQuery $sqlWithTap) }
        catch {
            $absent = (Test-PimBaselineAbsentObjectError -ErrorRecord $_ -Name 'TapLifetimeHours') -or (Test-PimBaselineAbsentObjectError -ErrorRecord $_ -Name 'ManagerEmail')
            if (-not $absent) { throw ("BUNDLE REFUSED: reading the TAP columns of pim.CentralAdmins failed ($($_.Exception.Message)) -- not treated as 'absent'.") }
            Write-Host "  (no TapLifetimeHours/ManagerEmail in pim.CentralAdmins -- the downlink will apply its own default)" -ForegroundColor DarkGray
        }
        if ($null -ne $rtap) { $rows = @($rtap); $hasTap = $true }
    }
    $select = @('UserName','DisplayName','FirstName','LastName','Initials','UsageLocation','Purpose','Ring','Template')
    if ($hasTarget) { $select += 'Target' }
    if ($hasTap)    { $select += @('TapLifetimeHours','ManagerEmail') }
    $rowObjs = @($rows | Select-Object $select)
    Write-Host "baseline rows (Owner=MSP): $($rowObjs.Count)"
    # 71 (framework MSP-4 SURFACE): the registry's own Replicate column, used only to decide publication.
    $registryReplicate = @{}
    $rrep = Invoke-PimBaselineOptionalRead -RunQuery $RunQuery -Sql "SELECT UserName, Replicate FROM pim.CentralAdmins WHERE Owner='MSP' AND Enabled=1" `
                -Name 'Replicate' -What 'pim.CentralAdmins.Replicate' -AbsentNote 'no Replicate column in pim.CentralAdmins -- every registry row is published, as before'
    foreach ($rr in @($rrep)) {
        if ($null -eq $rr) { continue }
        if ("$($rr.Replicate)".Trim()) { $registryReplicate["$($rr.UserName)".Trim().ToLowerInvariant()] = "$($rr.Replicate)".Trim() }
    }

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
    # THE ONE THAT WIDENS THE MOST: "absent" here means "every relationship projects everything". Only SQL 208 naming
    # the table counts; a permission-denied / transient read REFUSES the bundle.
    $polRaw = Invoke-PimBaselineOptionalRead -RunQuery $RunQuery -Sql "SELECT CONVERT(nvarchar(50), TenantId) AS TenantId, Mode, GroupTag FROM pim.TenantRoleProjection" `
                  -Name 'TenantRoleProjection' -What 'pim.TenantRoleProjection (the per-relationship projection policy)' `
                  -AbsentNote 'no pim.TenantRoleProjection in this registry -- every relationship projects everything'
    foreach ($p in @($polRaw)) {
        if ($null -eq $p) { continue }
        $tid = "$($p.TenantId)".Trim().ToLowerInvariant()
        if (-not $tid) { continue }
        if (-not $policyMap.Contains($tid)) { $policyMap[$tid] = New-Object System.Collections.Generic.List[object] }
        $policyMap[$tid].Add([ordered]@{ Mode = "$($p.Mode)"; GroupTag = "$($p.GroupTag)" }) | Out-Null
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
    $tagRaw = Invoke-PimBaselineOptionalRead -RunQuery $RunQuery -Sql "SELECT CONVERT(nvarchar(50), TenantId) AS TenantId, Tags FROM platform.Tenants WHERE Enabled = 1" `
                  -Name 'Tags' -What 'platform.Tenants.Tags' -AbsentNote 'no Tags column in platform.Tenants -- no tenant is tagged, so no artifact is narrowed by target'
    foreach ($t in @($tagRaw)) {
        if ($null -eq $t) { continue }
        $tid = "$($t.TenantId)".Trim().ToLowerInvariant()
        if (-not $tid) { continue }
        $list = @("$($t.Tags)" -split '[;,]' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if ($list.Count) { $tagsOut[$tid] = $list }
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
    $built = $null
    try { $built = Get-PimBaselineBundlePayload -RunQuery $RunQuery -Scope $Scope -ValidDays $ValidDays }
    catch { return @{ ok = $false; reason = "BUILD REFUSED (nothing signed, nothing uploaded): $($_.Exception.Message)" } }
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
        # Every 5 minutes: the job GATES ITSELF against the cadence set in the Manager's Job schedule (PIM-JobCadence.ps1);
        # nothing set there = daily, the cadence the old '0 4 * * *' cron gave.
        [string]$Cron = '*/5 * * * *',
        # When the job was deployed (ISO UTC). The gate runs the publish once after a redeploy, so a deploy's inputs
        # (key, image) take effect on the next trigger and the build's first-publish step publishes. Omitted = no stamp.
        [string]$DeployedUtc = '',
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
    if ("$DeployedUtc".Trim()) {
        if ("$DeployedUtc".Trim() -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$') { return @{ ok = $false; reason = "DeployedUtc '$DeployedUtc' is not an ISO UTC stamp (yyyy-MM-ddTHH:mm:ssZ)" } }
        $env['PIM_CadenceDeployedUtc'] = "$DeployedUtc".Trim()
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
    param([string]$Status, [int]$Attempt = 1, [int]$MaxAttempts = 4, [AllowNull()][string]$LogText = '')
    $s = "$Status".Trim()
    # The cadence gate (PIM-JobCadence.ps1) exits 0 WITHOUT publishing when the publish is not due -- so 'Succeeded' alone
    # no longer proves a publish. When the execution's log is available, a skip line decides:
    #   not-due  -> done: the gate only says not-due after a publish that SUCCEEDED, so a verified bundle is in place
    #   in-progress / claimed-elsewhere -> retry: another execution is publishing right now
    #   disabled / backoff -> fail: publishing is switched off in the Manager, or keeps failing -- say which
    if ($s -eq 'Succeeded' -and "$LogText".Trim() -and (Get-Command Get-PimJobCadenceSkipFromLog -ErrorAction SilentlyContinue)) {
        $sk = Get-PimJobCadenceSkipFromLog -LogText $LogText
        if ($sk.skipped) {
            switch ($sk.code) {
                'not-due' { return @{ action = 'done'; reason = "the execution did not publish (not due) -- the last publish SUCCEEDED, so a verified bundle is in place: $($sk.line)" } }
                { $_ -in @('in-progress', 'claimed-elsewhere') } {
                    if ($Attempt -lt $MaxAttempts) { return @{ action = 'retry'; reason = "another execution is publishing right now ($($sk.line)); retrying" } }
                    return @{ action = 'fail'; reason = "another execution was still publishing on the last attempt: $($sk.line)" }
                }
                'disabled' { return @{ action = 'fail'; reason = "publishing is DISABLED in the master's Manager (Job schedule > Publish to managed tenants) -- enable it there, or use Publish now: $($sk.line)" } }
                default { return @{ action = 'fail'; reason = "the execution did not publish: $($sk.line)" } }
            }
        }
    }
    if ($s -eq 'Succeeded') { return @{ action = 'done'; reason = 'the publish execution Succeeded (it exits non-zero unless it signed, uploaded, read back anonymously and verified)' } }
    if ($s -in @('Failed', 'Degraded') -and $Attempt -lt $MaxAttempts) { return @{ action = 'retry'; reason = "execution $s on attempt $Attempt of $MaxAttempts -- role assignments on a new identity can take minutes; retrying" } }
    return @{ action = 'fail'; reason = "execution ended '$s' on attempt $Attempt of $MaxAttempts" }
}

# =====================================================================================================================
# SEC-25 remainder (2.4.373) -- THE CENTRAL-KILL PRODUCER. The managed-tenant pull already CONSUMES a signed
# kind='central-kill' manifest at <bundle container>/central-kill.json (PIM-Downlink.ps1: Get-PimCentralKillSource ->
# Get-PimCentralKillState; 404 = none in force), but nothing on a master published one. These build, sign and verify it
# with the SAME path and document shape as the bundle (ConvertTo-PimBaselineDocJson + the Key Vault signer), and the
# publisher (tools/setup/Publish-PimCentralKill.ps1) proves each publish and each withdraw with the CONSUMER's own code.
# Payload (what Get-PimCentralKillState / Resolve-PimCentralKill read):
#   { product:'PIM4EntraPS', kind:'central-kill', version, generatedAtUtc, validToUtc, reason,
#     kills: [ { upn, userName?, status: Disabled|Revoked, statusChangeCode?, reason } ] }
# =====================================================================================================================
$script:PimCentralKillBlob = 'central-kill.json'

function ConvertTo-PimCentralKillEntry {
    # PURE. One kill entry, normalised: a hashtable / object with upn|userName + status, or the text 'upn:Status'.
    # REFUSED (throws): no upn and no userName; a status other than Disabled | Revoked (the only two the consumer accepts).
    param([Parameter(Mandatory)][object]$Entry, [string]$DefaultReason = '')
    $get = {
        param($n)
        if ($Entry -is [System.Collections.IDictionary]) { if ($Entry.Contains($n)) { return "$($Entry[$n])".Trim() }; return '' }
        $p = $Entry.PSObject.Properties[$n]; if ($p) { return "$($p.Value)".Trim() }; return ''
    }
    $upn = ''; $user = ''; $status = ''; $code = ''; $why = ''
    if ($Entry -is [string]) {
        $parts = "$Entry".Split(':')
        $upn = "$($parts[0])".Trim()
        $status = $(if ($parts.Count -gt 1) { "$($parts[1])".Trim() } else { 'Disabled' })
    } else {
        $upn = & $get 'upn'; if (-not $upn) { $upn = & $get 'UserPrincipalName' }
        $user = & $get 'userName'
        $status = & $get 'status'; if (-not $status) { $status = 'Disabled' }
        $code = & $get 'statusChangeCode'
        $why = & $get 'reason'
    }
    if (-not $upn -and -not $user) { throw "central-kill entry '$Entry' names no account (upn or userName) -- REFUSED" }
    if ($status -ieq 'disabled') { $status = 'Disabled' } elseif ($status -ieq 'revoked') { $status = 'Revoked' }
    else { throw "central-kill entry for '$upn$user' has status '$status' -- REFUSED (Disabled or Revoked only)" }
    if (-not $why) { $why = "$DefaultReason".Trim() }
    $o = [ordered]@{}
    if ($upn)  { $o['upn'] = $upn }
    if ($user) { $o['userName'] = $user }
    $o['status'] = $status
    if ($code) { $o['statusChangeCode'] = $code }
    $o['reason'] = $why
    return $o
}

function New-PimCentralKillPayload {
    # PURE. The manifest payload + its bytes. -Kills must name at least one account: an EMPTY manifest reads as "no kill"
    # on the consumer, and lifting a kill is -Withdraw (delete), never a quietly empty document. Refuses duplicates.
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Kills,
        [Parameter(Mandatory)][string]$Reason,
        [int]$ValidHours = 72,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    if (-not "$Reason".Trim()) { throw 'a central kill needs a -Reason (it is shown on every managed tenant that refuses its pull)' }
    if ($ValidHours -lt 1 -or $ValidHours -gt 24 * 30) { throw "ValidHours $ValidHours is out of range (1..720): a kill expires so a forgotten one cannot stand for ever, and is re-published to extend it" }
    $entries = @(@($Kills) | Where-Object { $null -ne $_ -and "$_".Trim() } | ForEach-Object { ConvertTo-PimCentralKillEntry -Entry $_ -DefaultReason $Reason })
    if ($entries.Count -eq 0) { throw 'no account to kill -- an empty manifest means "no kill"; use -Withdraw to lift a kill' }
    $seen = @{}
    foreach ($e in $entries) {
        $k = ("$($e['upn'])|$($e['userName'])").ToLowerInvariant()
        if ($seen.ContainsKey($k)) { throw "the account '$($e['upn'])$($e['userName'])' is named twice -- REFUSED" }
        $seen[$k] = $true
    }
    $now = $NowUtc.ToUniversalTime()
    $payload = [ordered]@{
        product        = 'PIM4EntraPS'
        kind           = 'central-kill'
        version        = [int64]$now.ToString('yyMMddHHmm', [System.Globalization.CultureInfo]::InvariantCulture)
        generatedAtUtc = $now.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
        validToUtc     = $now.AddHours($ValidHours).ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
        reason         = "$Reason".Trim()
        kills          = @($entries)
    }
    $json = ($payload | ConvertTo-Json -Depth 6 -Compress)
    return @{ payload = $payload; payloadJson = $json; payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($json); version = $payload.version; count = $entries.Count }
}

function Invoke-PimCentralKillPublishRun {
    <#
      One central-kill publish, every side effect behind a seam (Publish-PimCentralKill.ps1 wires the real ones):
        -Signer  param([byte[]]$payload) -> @{ signatureBytes; keyId; signingKey }   (the bundle's Key Vault signer)
        -Upload  param($blobName, [string]$json)
        -Fetcher the CONSUMER's fetch seam for Get-PimCentralKillSource: param($url, $headers) -> doc | throw (404 = none)
        -KillUrl the anonymous URL the managed tenants read (<container>/central-kill.json)
      Order: build -> sign -> SELF-VERIFY with the managed tenant's own verdict (Get-PimCentralKillState, pinned to the
      signing key) = 'active' -> upload central-kill-v<version>.json (audit copy) then central-kill.json -> read back
      through Get-PimCentralKillSource exactly as the pull does -> byte-compare -> verdict again = 'active'.
      Nothing is uploaded unless the self-verify said 'active'. Returns @{ ok; reason; version; keyId; sha256; blobs; state }.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Kills,
        [Parameter(Mandatory)][string]$Reason,
        [Parameter(Mandatory)][scriptblock]$Signer,
        [Parameter(Mandatory)][scriptblock]$Upload,
        [Parameter(Mandatory)][scriptblock]$Fetcher,
        [Parameter(Mandatory)][string]$KillUrl,
        [int]$ValidHours = 72,
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    foreach ($fn in 'Get-PimCentralKillState', 'Get-PimCentralKillSource') {
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { return @{ ok = $false; reason = "the consumer's $fn is not loaded, so the manifest cannot be proven verifiable -- nothing signed, nothing uploaded" } }
    }
    $built = $null
    try { $built = New-PimCentralKillPayload -Kills $Kills -Reason $Reason -ValidHours $ValidHours -NowUtc $NowUtc }
    catch { return @{ ok = $false; reason = "BUILD REFUSED (nothing signed, nothing uploaded): $($_.Exception.Message)" } }
    $s = & $Signer $built.payloadBytes
    if ($null -eq $s -or $null -eq $s.signatureBytes -or -not (Test-PimBaselineKeyIdFormat -KeyId "$($s.keyId)")) { return @{ ok = $false; reason = 'the signer returned no signature / key id -- nothing uploaded' } }
    $docJson = ConvertTo-PimBaselineDocJson -PayloadBytes $built.payloadBytes -SignatureBytes ([byte[]]$s.signatureBytes) -KeyThumbprint "$($s.keyId)" -SigningKey $s.signingKey
    # The consumer verifies against the keys the managed tenant PINS (PIM_BaselineTrustedKeys). Pin exactly this key for
    # the self-check, and put the caller's value back whatever happens.
    $savedPins = $global:PIM_BaselineTrustedKeys
    try {
        $global:PIM_BaselineTrustedKeys = @("$($s.keyId)")
        $v1 = Get-PimCentralKillState -Doc ($docJson | ConvertFrom-Json) -NowUtc $NowUtc
        if ("$($v1.state)" -ne 'active') { return @{ ok = $false; reason = "SELF-VERIFY FAILED (nothing uploaded): the managed tenant's verdict would be '$($v1.state)' -- $($v1.reason)"; version = $built.version; keyId = "$($s.keyId)" } }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $docSha = (-join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($docJson)) | ForEach-Object { $_.ToString('x2') })) } finally { $sha.Dispose() }
        $blobs = @("central-kill-v$($built.version).json", $script:PimCentralKillBlob)
        foreach ($b in $blobs) { & $Upload $b $docJson }
        $src = Get-PimCentralKillSource -CentralKillUrl $KillUrl -Fetcher $Fetcher
        if (-not $src.checked -or "$($src.error)".Trim() -or $null -eq $src.doc) {
            return @{ ok = $false; reason = "READ-BACK FAILED: the anonymous read of $KillUrl did not return the manifest just uploaded ($(if ($src.error) { $src.error } elseif ($null -eq $src.doc) { 'not found' } else { 'not checked' })) -- managed tenants may not see it"; version = $built.version; keyId = "$($s.keyId)"; sha256 = $docSha; blobs = $blobs }
        }
        $gotJson = ($src.doc | ConvertTo-Json -Depth 5 -Compress)
        $sentJson = (($docJson | ConvertFrom-Json) | ConvertTo-Json -Depth 5 -Compress)
        if ($gotJson -ne $sentJson) { return @{ ok = $false; reason = "READ-BACK MISMATCH: $KillUrl does not hold the manifest just uploaded"; version = $built.version; keyId = "$($s.keyId)"; sha256 = $docSha; blobs = $blobs } }
        $v2 = Get-PimCentralKillState -Doc $src.doc -NowUtc $NowUtc
        if ("$($v2.state)" -ne 'active') { return @{ ok = $false; reason = "READ-BACK VERIFY FAILED: the managed tenant's verdict on the published manifest is '$($v2.state)' -- $($v2.reason)"; version = $built.version; keyId = "$($s.keyId)"; sha256 = $docSha; blobs = $blobs } }
        return @{ ok = $true; reason = "central kill v$($built.version) PUBLISHED ($($built.count) account(s), valid to $($built.payload.validToUtc)); the managed tenants' verdict: $($v2.reason)"
                  version = $built.version; keyId = "$($s.keyId)"; sha256 = $docSha; blobs = $blobs; state = "$($v2.state)"; validToUtc = "$($built.payload.validToUtc)" }
    } finally {
        $global:PIM_BaselineTrustedKeys = $savedPins
    }
}

function Invoke-PimCentralKillWithdrawRun {
    <#
      Lift a central kill: DELETE <container>/central-kill.json (the versioned audit copies stay), then read the location
      back through the consumer (Get-PimCentralKillSource + Get-PimCentralKillState) -- it must be 404 = 'none'.
        -Delete  param($blobName)   (an absent blob is not an error: it means no kill was standing)
      Returns @{ ok; reason; state }.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Delete,
        [Parameter(Mandatory)][scriptblock]$Fetcher,
        [Parameter(Mandatory)][string]$KillUrl
    )
    foreach ($fn in 'Get-PimCentralKillState', 'Get-PimCentralKillSource') {
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { return @{ ok = $false; reason = "the consumer's $fn is not loaded, so the withdraw cannot be proven" } }
    }
    & $Delete $script:PimCentralKillBlob
    $src = Get-PimCentralKillSource -CentralKillUrl $KillUrl -Fetcher $Fetcher
    $st = Get-PimCentralKillState -Doc $src.doc -Checked ([bool]$src.checked) -FetchError "$($src.error)" -NotCheckedReason "$($src.note)"
    if ("$($st.state)" -ne 'none' -or $null -ne $src.doc) { return @{ ok = $false; state = "$($st.state)"; reason = "WITHDRAW NOT PROVEN: after the delete, the managed tenants' verdict on $KillUrl is '$($st.state)' -- $($st.reason)" } }
    return @{ ok = $true; state = 'none'; reason = "central kill WITHDRAWN: $KillUrl answers 404, so the managed tenants' verdict is '$($st.state)' ($($st.reason))" }
}
