#Requires -Version 5.1
<#
.SYNOPSIS
    Baseline-courier PRODUCER (LIFECYCLE-GOVERNANCE § 19): export the MSP's
    Owner=MSP baseline from the central registry, sign it, and publish the
    signed bundle to private-endpoint blob storage for local engines to pull.

.DESCRIPTION
    MSP-side. Reads pim.CentralAdmins WHERE Owner='MSP' from the central
    registry, builds a versioned payload, signs it RSA-SHA256 with the
    CN=PIM4EntraPS-Baseline private key (non-exportable, machine cert store --
    never distributed), and uploads {payloadB64, signature, keyThumbprint} to
    the baseline container. Local engines pull + verify with the embedded
    PUBLIC cert (engine/_shared/PIM-Baseline.ps1). The bundle is signed, not
    encrypted -- integrity + authenticity, full transparency.

    SQL + blob are both reached over their private endpoints. Tokens (Azure SQL
    + blob storage) are minted over PURE REST via PIM-Rest (SPN + certificate /
    Managed Identity), so this script no longer needs Az.Accounts or Az.Storage
    -- only the SqlServer module for the registry read (SQL data plane). The
    blob upload uses the REST Put Blob API (Send-PimRestBlob).
#>
[CmdletBinding()]
param(
    [string]$CentralServer,
    [string]$Database = 'PimPlatform',
    [string]$StorageAccount,
    [string]$Container = 'baselines',
    [string]$Scope = 'fleet',
    [int]$ValidDays = 30,
    # TEST-12: produce a bundle WITHOUT publishing it. The S5/S6 downlink accepts a local
    # document (-BaselineDocPath), so the scenario matrix can exercise the real signed-pull
    # path with no blob account -- and a signing change can be verified before anything is
    # published to the fleet. When set, the upload step is skipped entirely.
    [string]$OutFile,
    # TEST-12: read the registry from a LOCAL SQL instance (the scratch scenario store)
    # using Windows auth, instead of Azure SQL + a bearer token. Chosen automatically for a
    # non-Azure server name, so nothing changes for the real MSP path.
    [switch]$LocalSql
)

$ErrorActionPreference = 'Stop'

# Pure-REST token acquisition + blob upload (drops Az.Accounts / Az.Storage).
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-Rest.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-AccountRest.ps1')

if (-not $CentralServer)  { $CentralServer  = (Get-Content C:\TMP\pim-sqlserver-name.txt -Raw).Trim() + '.database.windows.net' }
if (-not $StorageAccount -and -not $OutFile) { $StorageAccount = (Get-Content C:\TMP\pim-baseline-storage.txt -Raw).Trim() }

# A local instance is anything that is not an Azure SQL endpoint.
$useLocal = $LocalSql -or ($CentralServer -notmatch '\.database\.windows\.net$')

# MSP-4 (BUG-62): Target rides with the admin row. A registry predating the column would make
# this SELECT fail outright, so it is resolved defensively below rather than named here.
$sql = "SELECT UserName, DisplayName, FirstName, LastName, Initials, UsageLocation, Purpose, Ring, Template FROM pim.CentralAdmins WHERE Owner='MSP' AND Enabled=1 ORDER BY Ring"
$sqlWithTarget = "SELECT UserName, DisplayName, FirstName, LastName, Initials, UsageLocation, Purpose, Ring, Template, Target FROM pim.CentralAdmins WHERE Owner='MSP' AND Enabled=1 ORDER BY Ring"
# Operator decision 2026-08-13: the TAP intent travels WITH the admin, so the managed tenant's
# engine can mint a sign-in credential for it. Resolved with the same defensive re-read as
# Target -- a registry predating these columns keeps publishing, and the downlink then applies
# its own default (ON) rather than inheriting a silent FALSE.
$sqlWithTap = "SELECT UserName, DisplayName, FirstName, LastName, Initials, UsageLocation, Purpose, Ring, Template, Target, CreateTap, TapLifetimeHours, ManagerEmail FROM pim.CentralAdmins WHERE Owner='MSP' AND Enabled=1 ORDER BY Ring"
# MSP-2 / control #2: the master's delegation model. Stored in the engine row store as
# JSON (pim.Rows), not as columns, so it is read raw and parsed here: the admin->group
# memberships that ARE the projection, plus the group definitions, their nesting and
# their Entra role bindings -- because a membership grants nothing in a tenant that has
# no group with that tag (BUG-59: both managed tenants are empty).
#
# 🪤 BUG-60 -- WHICH ENTITY HOLDS A GROUP DEFINITION. This read used to name
# 'PIM-Definitions' only, and NOTHING authors that entity: the engine builds every group
# from PIM-Definitions-Roles / -Services / -Organization / -Tasks
# (Get-PimGroupDefinitionRows) and the row read matches the entity name EXACTLY. So a
# master authored the normal way published ZERO group definitions and the projected
# memberships arrived in the slave naming groups that were never carried. It looked like
# it worked only because a hand-written seeder had written 'PIM-Definitions' directly.
# All five are read now; 'PIM-Definitions' stays in the list so an estate already seeded
# that way is not stranded.
$defEntities = @('PIM-Definitions-Roles','PIM-Definitions-Services','PIM-Definitions-Organization','PIM-Definitions-Tasks','PIM-Definitions')
$entityList  = @('PIM-Assignments-Admins','PIM-Assignments-Groups','PIM-Assignments-Roles-Groups') + $defEntities
$sqlAssign = "SELECT Entity, DataJson FROM pim.Rows WHERE Entity IN ('" + ($entityList -join "','") + "')"
if ($useLocal) {
    # Module-free, same helpers the engine uses (the SqlServer module is deliberately not a
    # dependency here -- it drags an older Azure.Core that poisons app-only Graph auth).
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-ChangeQueue.ps1')
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-SqlStore.ps1')
    $global:PIM_SqlServer = $CentralServer; $global:PIM_SqlDatabase = $Database
    Write-Host "reading registry from LOCAL SQL $CentralServer / $Database (Windows auth)"
    $cs = Get-PimSqlConnectionString
    $rows = @(Invoke-PimSqlQuery -ConnectionString $cs -Sql $sql)
    $assignRaw = @(Invoke-PimSqlQuery -ConnectionString $cs -Sql $sqlAssign)
    # one query helper per auth branch, so later reads don't restate the branch
    $runQuery = { param($q) @(Invoke-PimSqlQuery -ConnectionString $cs -Sql $q) }.GetNewClosure()
} else {
    # 1. Read the Owner=MSP baseline rows from the central registry.
    #    Azure SQL access token via REST (SPN cert / MI) -- no Get-AzAccessToken.
    Import-Module SqlServer -ErrorAction Stop      # SQL data plane only -- no Az.* / Microsoft.Graph
    $sqlTok = Get-PimRestToken -Resource 'https://database.windows.net'
    $rows = Invoke-Sqlcmd -ServerInstance $CentralServer -Database $Database -AccessToken $sqlTok -Encrypt Mandatory -Query $sql
    $assignRaw = @(Invoke-Sqlcmd -ServerInstance $CentralServer -Database $Database -AccessToken $sqlTok -Encrypt Mandatory -Query $sqlAssign)
    $runQuery = { param($q) @(Invoke-Sqlcmd -ServerInstance $CentralServer -Database $Database -AccessToken $sqlTok -Encrypt Mandatory -Query $q) }.GetNewClosure()
}
# Re-read WITH Target when the registry has the column; a registry that predates it keeps
# working and simply publishes no targets (= every artifact reaches every managed tenant).
$hasTarget = $false
try { $rows = @(& $runQuery $sqlWithTarget); $hasTarget = $true }
catch { Write-Host "  (no Target column in pim.CentralAdmins -- no admin is narrowed by target)" -ForegroundColor DarkGray }
# Widen once more to the TAP intent. Ordered after Target so a registry that has Target but not
# the TAP columns still keeps its targets -- the widest successful read wins, never the last one.
$hasTap = $false
if ($hasTarget) {
    try { $rows = @(& $runQuery $sqlWithTap); $hasTap = $true }
    catch { Write-Host "  (no CreateTap/TapLifetimeHours/ManagerEmail in pim.CentralAdmins -- the downlink will apply its own default)" -ForegroundColor DarkGray }
}
$select = @('UserName','DisplayName','FirstName','LastName','Initials','UsageLocation','Purpose','Ring','Template')
if ($hasTarget) { $select += 'Target' }
if ($hasTap)    { $select += @('CreateTap','TapLifetimeHours','ManagerEmail') }
$rowObjs = @($rows | Select-Object $select)
Write-Host "baseline rows (Owner=MSP): $($rowObjs.Count)"

# 1b. Project each MSP admin's role memberships into the bundle.
#
# 🪤 THE TWO SIDES NAME THE ADMIN DIFFERENTLY. pim.CentralAdmins keys on the LOGIN
# name ('Admin-EFIF-MOK-ID'); PIM-Assignments-Admins keys on the master UPN
# ('admin-efif-mok-id@master.tld'). The bundle must carry the LOGIN name, because the
# fan-out rebuilds the UPN per slave (<UserName>@<slave default domain>) -- carrying
# the master UPN would project a principal that does not exist in the slave. So the
# UPN's local part is matched back to the login name here, and the login name is what
# ships. Matching is case-insensitive: the seed writes the UPN lowercased.
$adminByLower = @{}
foreach ($r in $rowObjs) { $adminByLower["$($r.UserName)".Trim().ToLowerInvariant()] = "$($r.UserName)".Trim() }
$assignObjs = New-Object System.Collections.Generic.List[object]
$skipped = 0
# split the four entities out of the single read
$byEntity = @{}
foreach ($raw in $assignRaw) {
    $e = "$($raw.Entity)"
    if (-not $byEntity.ContainsKey($e)) { $byEntity[$e] = New-Object System.Collections.Generic.List[object] }
    $o = $null
    try { $o = "$($raw.DataJson)" | ConvertFrom-Json } catch { continue }
    if ($o) { $byEntity[$e].Add($o) | Out-Null }
}
$getEnt = { param($n) if ($byEntity.ContainsKey($n)) { return @($byEntity[$n].ToArray()) } else { return @() } }
# Every group definition, from whichever entity holds it, stamped with WHERE IT CAME FROM.
# The slave writes each group back into the same entity (Invoke-PimDownlinkDefinitionApply),
# so a role group stays a role group there instead of being flattened into one bucket.
$getDefs = {
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($e in $defEntities) {
        foreach ($d in (& $getEnt $e)) {
            if (-not $d) { continue }
            Add-Member -InputObject $d -NotePropertyName '__srcEntity' -NotePropertyValue $e -Force
            $all.Add($d) | Out-Null
        }
    }
    return @($all.ToArray())
}.GetNewClosure()

foreach ($j in (& $getEnt 'PIM-Assignments-Admins')) {
    # the engine's own row reader accepts either casing; so do we
    $u = "$($j.Username)"; if (-not $u) { $u = "$($j.UserName)" }
    $u = $u.Trim(); if (-not $u) { continue }
    if ("$($j.Action)" -eq 'Remove') { continue }
    $local = $u; $at = $u.IndexOf('@'); if ($at -gt 0) { $local = $u.Substring(0, $at) }
    $key = $local.ToLowerInvariant()
    if (-not $adminByLower.ContainsKey($key)) { $skipped++; continue }   # a LOCAL admin's row, not an MSP one
    $assignObjs.Add([ordered]@{
        UserName            = $adminByLower[$key]
        GroupTag            = "$($j.GroupTag)"
        AssignmentType      = "$($j.AssignmentType)"
        Permanent           = "$($j.Permanent)"
        NumOfDaysWhenExpire = "$($j.NumOfDaysWhenExpire)"
        AutoExtend          = "$($j.AutoExtend)"
        # MSP-4 (BUG-62): carried through, because this fixed field list is exactly where the
        # operator's "this role goes to only 5 of the 28" was being silently dropped.
        Target              = "$($j.Target)"
    }) | Out-Null
}
$assignArr = @($assignObjs.ToArray() | Sort-Object @{ e = { "$($_.UserName)".ToLowerInvariant() } }, @{ e = { "$($_.GroupTag)".ToLowerInvariant() } })
Write-Host "baseline role assignments (MSP admins): $($assignArr.Count)$(if ($skipped) { " ($skipped row(s) belonged to non-MSP admins -- not published)" })"

# 1c. BUG-59 / operator decision 2026-08-13 ("MSP groups, customer may extend"): carry the
# GROUP DEFINITIONS the projected memberships depend on. A membership grants nothing in a
# tenant with no group of that tag, and a managed tenant is empty on day one -- so the
# baseline must be able to STAND UP the model, while still yielding to a customer group
# that already carries the tag (the downlink decides that per tenant, not here).
#
# Only the TRANSITIVE CLOSURE of what is actually projected ships -- never the master's whole
# delegation model. From each projected ROLE group: the nestings that name it, the SERVICE
# groups it draws from, and the Entra role bindings on those service groups. A group nobody is
# assigned to is not the customer's business.
#
# 🔴 BUG-61 -- DIRECTION. This matched on SourceGroupTag, and the shipped contract is the other
# way round: TargetGroupTag comes from PIM-Definitions-Roles (the ROLE group) and SourceGroupTag
# is the permission group the permission comes FROM (docs/DESIGN.md, the authoring dropdowns, and
# the engine's GroupNesting provider -- that last one verified against a live tenant, where the
# role group ends up a MEMBER OF each service group). Projected tags are ROLE tags, so matching
# on Source found NOTHING in real data: no nesting shipped, the closure never reached the service
# groups, and their role bindings did not ship either. It only ever produced output for
# hand-seeded data that had the two columns swapped.
$projTags = @{}
foreach ($a in $assignArr) { $projTags["$($a.GroupTag)".Trim().ToLowerInvariant()] = $true }

$allNest = @(& $getEnt 'PIM-Assignments-Groups' | Where-Object { "$($_.Action)" -ne 'Remove' })
$nestArr = @($allNest | Where-Object { $projTags.ContainsKey("$($_.TargetGroupTag)".Trim().ToLowerInvariant()) } | ForEach-Object {
    [ordered]@{
        TargetGroupTag = "$($_.TargetGroupTag)"; SourceGroupTag = "$($_.SourceGroupTag)"
        AssignmentType = "$($_.AssignmentType)"; Permanent = "$($_.Permanent)"
        NumOfDaysWhenExpire = "$($_.NumOfDaysWhenExpire)"; AutoExtend = "$($_.AutoExtend)"
    }
} | Sort-Object @{ e = { "$($_.SourceGroupTag)".ToLowerInvariant() } }, @{ e = { "$($_.TargetGroupTag)".ToLowerInvariant() } })

# the service groups reached through those nestings join the tag set (BUG-61: the SERVICE
# group is the SOURCE -- taking Target here just re-added the role group we started from)
$needTags = @{}
foreach ($k in $projTags.Keys) { $needTags[$k] = $true }
foreach ($n in $nestArr) { $needTags["$($n.SourceGroupTag)".Trim().ToLowerInvariant()] = $true }

$defArr = @(& $getDefs | Where-Object { $needTags.ContainsKey("$($_.GroupTag)".Trim().ToLowerInvariant()) } | ForEach-Object {
    [ordered]@{
        GroupTag = "$($_.GroupTag)"; GroupName = "$($_.GroupName)"; GroupDescription = "$($_.GroupDescription)"
        IsRoleAssignable = "$($_.IsRoleAssignable)"; Workload = "$($_.Workload)"; Level = "$($_.Level)"
        Plane = "$($_.Plane)"; CPPlatform = "$($_.CPPlatform)"; Department = "$($_.Department)"
        PolicyTemplate = "$($_.PolicyTemplate)"
        # BUG-60: the entity this group lives in on the master, so the slave can put it
        # back where its own engine will look for it.
        SourceEntity = "$($_.__srcEntity)"
    }
} | Sort-Object @{ e = { "$($_.GroupTag)".ToLowerInvariant() } })

$bindArr = @(& $getEnt 'PIM-Assignments-Roles-Groups' | Where-Object { "$($_.Action)" -ne 'Remove' -and $needTags.ContainsKey("$($_.GroupTag)".Trim().ToLowerInvariant()) } | ForEach-Object {
    [ordered]@{
        GroupTag = "$($_.GroupTag)"; RoleDefinitionName = "$($_.RoleDefinitionName)"
        AssignmentType = "$($_.AssignmentType)"; Permanent = "$($_.Permanent)"
        NumOfDaysWhenExpire = "$($_.NumOfDaysWhenExpire)"; AutoExtend = "$($_.AutoExtend)"
        Plane = "$($_.Plane)"; PermissionScope = "$($_.PermissionScope)"
    }
} | Sort-Object @{ e = { "$($_.GroupTag)".ToLowerInvariant() } }, @{ e = { "$($_.RoleDefinitionName)".ToLowerInvariant() } })

# A projected tag with no definition anywhere would be unresolvable in EVERY tenant --
# that is a master-side modelling error, and it is cheaper to say so at publish time.
# 1d. The PER-RELATIONSHIP projection policy, carried IN the bundle, keyed by tenant id.
#
# 🪤 WHY IT CANNOT STAY "read it from the master registry at downlink time". A process holds ONE
# ambient identity, and Get-PimSqlConnectionString mints its Azure SQL token from it -- so a single
# run cannot read the MASTER's pim.TenantRoleProjection and write the SLAVE's store, because those
# are different tenants with different credentials. In S6 the downlink runs INSIDE the slave, which
# has no credential for the master's SQL at all. Leaving the policy only in the registry therefore
# made it unreachable on the one topology IMP-11 says we can currently use.
#
# Carrying it here is also strictly better than a cross-tenant read: the policy is SIGNED with the
# rest of the payload, so a managed tenant cannot quietly widen its own projection, and no extra
# network path is opened between tenants (§31.3's hard constraint).
# The operator's decision is unchanged -- the policy is still AUTHORED in the master registry; this
# only changes how it is delivered.
$policyMap = [ordered]@{}
try {
    $polRaw = @(& $runQuery "SELECT CONVERT(nvarchar(50), TenantId) AS TenantId, Mode, GroupTag FROM pim.TenantRoleProjection")
    foreach ($p in $polRaw) {
        $tid = "$($p.TenantId)".Trim().ToLowerInvariant()
        if (-not $tid) { continue }
        if (-not $policyMap.Contains($tid)) { $policyMap[$tid] = New-Object System.Collections.Generic.List[object] }
        $policyMap[$tid].Add([ordered]@{ Mode = "$($p.Mode)"; GroupTag = "$($p.GroupTag)" }) | Out-Null
    }
} catch {
    # A master whose registry predates this table simply has no per-relationship policy,
    # which the downlink already reads as allow-all. Not an error.
    Write-Host "  (no pim.TenantRoleProjection in this registry -- every relationship projects everything)" -ForegroundColor DarkGray
}
$policyOut = [ordered]@{}
foreach ($k in $policyMap.Keys) { $policyOut[$k] = @($policyMap[$k].ToArray()) }
$policyCount = 0; foreach ($k in $policyOut.Keys) { $policyCount += @($policyOut[$k]).Count }
Write-Host "baseline projection policy: $policyCount rule(s) across $(@($policyOut.Keys).Count) relationship(s)"
foreach ($k in $policyOut.Keys) {
    foreach ($r in @($policyOut[$k])) { Write-Host ("    {0}  {1}: {2}" -f $k, $r.Mode, $r.GroupTag) -ForegroundColor DarkGray }
}

# 1e. MSP-4 (BUG-62): the PER-TENANT TAG MAP, carried in the bundle for the same reason the
# projection policy is -- a downlink running inside the slave has no credential for the
# master's registry, so a tag it cannot read is a target it cannot evaluate. Without this,
# Test-PimArtifactTarget only ever saw an empty tag set and answered "reaches every managed
# tenant" for every artifact: the targeting half of MSP-4 was built, correct, and unfed.
# Signed with the rest, so a managed tenant cannot tag itself into a wider scope.
$tagsOut = [ordered]@{}
try {
    $tagRaw = @(& $runQuery "SELECT CONVERT(nvarchar(50), TenantId) AS TenantId, Tags FROM platform.Tenants WHERE Enabled = 1")
    foreach ($t in $tagRaw) {
        $tid = "$($t.TenantId)".Trim().ToLowerInvariant()
        if (-not $tid) { continue }
        $list = @("$($t.Tags)" -split '[;,]' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if ($list.Count) { $tagsOut[$tid] = $list }
    }
} catch {
    # A registry predating the Tags column simply has no tagged tenants, which reads as
    # "every artifact reaches everyone" -- precisely the behaviour before MSP-4. Not an error.
    Write-Host "  (no Tags column in platform.Tenants -- no tenant is tagged, so no artifact is narrowed by target)" -ForegroundColor DarkGray
}
$tagCount = 0; foreach ($k in $tagsOut.Keys) { $tagCount += @($tagsOut[$k]).Count }
Write-Host "baseline tenant tags: $tagCount tag(s) across $(@($tagsOut.Keys).Count) tenant(s)"

$orphan = @($projTags.Keys | Where-Object { $t = $_; -not @($defArr | Where-Object { "$($_.GroupTag)".Trim().ToLowerInvariant() -eq $t }).Count })
Write-Host "baseline definitions carried: $($defArr.Count) group(s), $($nestArr.Count) nesting(s), $($bindArr.Count) role binding(s)"
if ($orphan.Count) { Write-Host "  [warn] $($orphan.Count) projected tag(s) have NO group definition in the master: $($orphan -join ', ')" -ForegroundColor Yellow }
foreach ($b in $bindArr) { Write-Host ("    binds {0,-42} -> {1}" -f $b.GroupTag, $b.RoleDefinitionName) -ForegroundColor DarkGray }

# 2. Build + sign the payload.
$version = [int64](Get-Date -Format 'yyMMddHHmm')
$payload = [ordered]@{
    product        = 'PIM4EntraPS'
    kind           = 'baseline'
    version        = $version
    scope          = $Scope
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    validToUtc     = (Get-Date).ToUniversalTime().AddDays($ValidDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
    rows           = $rowObjs
    # MSP-2 / control #2. SIGNED alongside the admin rows -- a tampered role
    # projection is exactly as serious as a tampered admin list, so it rides in the
    # same payload rather than in a second, separately-trusted artifact. A tenant
    # running an older engine ignores the key; a newer engine reading an older
    # bundle finds it absent and projects nothing.
    assignments    = $assignArr
    # BUG-59: the model the assignments need in order to mean anything. Signed with
    # everything else -- these bind real Entra roles, so a tampered definition is the
    # most dangerous row in the bundle, not the least.
    definitions    = [ordered]@{
        groups       = $defArr
        nestings     = $nestArr
        roleBindings = $bindArr
    }
    # per-relationship policy, keyed by tenant id (see 1d). Signed, so a managed
    # tenant cannot widen its own projection.
    projectionPolicy = $policyOut
    # MSP-4 (see 1e): tenant id -> tags, so an artifact's Target can be evaluated inside
    # the slave. An empty map means nothing is tagged, which narrows nothing.
    tenantTags       = $tagsOut
}
$payloadJson  = ($payload | ConvertTo-Json -Depth 8 -Compress)
$payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payloadJson)

$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq 'CN=PIM4EntraPS-Baseline' -and $_.HasPrivateKey } | Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { throw "CN=PIM4EntraPS-Baseline signing certificate not found in Cert:\LocalMachine\My -- bundles can only be produced on the MSP management host that owns the key." }
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
$sig = $rsa.SignData($payloadBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

$doc = [ordered]@{
    product       = 'PIM4EntraPS'
    payloadB64    = [Convert]::ToBase64String($payloadBytes)
    signature     = [Convert]::ToBase64String($sig)
    keyThumbprint = $cert.Thumbprint
}
$docJson = ($doc | ConvertTo-Json -Depth 3)

# 3. Upload to the private-endpoint blob (versioned + latest) over REST
#    (Put Blob API, OAuth bearer token) -- no Az.Storage module / account key.
if ($OutFile) {
    # TEST-12: signed, but NOT published. Same bytes the blob would carry, so the downlink
    # verifies exactly what the fleet would verify.
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [System.IO.File]::WriteAllText($OutFile, $docJson, (New-Object System.Text.UTF8Encoding($false)))   # no BOM
    Write-Host "BASELINE SIGNED (not published): v$version ($($rowObjs.Count) rows, $($assignArr.Count) assignments, signer $($cert.Thumbprint)) -> $OutFile"
    return
}

$tmp = Join-Path $env:TEMP ("baseline-v$version.json")
[System.IO.File]::WriteAllText($tmp, $docJson, (New-Object System.Text.UTF8Encoding($false)))   # no BOM
try {
    foreach ($name in @("baseline-v$version.json", 'baseline-latest.json')) {
        Send-PimRestBlob -StorageAccount $StorageAccount -Container $Container -Blob $name -FilePath $tmp
        Write-Host "  uploaded $name"
    }
} finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }

Write-Host "BASELINE PUBLISHED: v$version ($($rowObjs.Count) rows, $($assignArr.Count) assignments, signer $($cert.Thumbprint)) -> https://$StorageAccount.blob.core.windows.net/$Container/baseline-latest.json"
