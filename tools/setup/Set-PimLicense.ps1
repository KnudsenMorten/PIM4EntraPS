#Requires -Version 5.1
<#
.SYNOPSIS
  IMP-42 -- import an issued PIM4EntraPS licence into the store (pim.Settings['License']).

.DESCRIPTION
  PIM v2 keeps the licence in SQL, not in a file. It used to be FOUND by scanning config/ for
  *.pimlicense / *.aitlicense -- a directory the container image excludes, so every hosted
  environment read "Missing" whatever had been issued. Nothing reads such a file any more: the
  signed document (payloadB64 + signature, byte-identical to what was issued) is stored in
  pim.Settings['License'], and both containers read it from there.

  This is the supported way to put it there.
  SAME SAFETY RULES AS THE OTHER STORE-WRITING SETUP SCRIPTS:
    * The document is VERIFIED before the store is contacted for a write (Set-PimLicense refuses a
      tampered or foreign-signed document -- nothing is stored).
    * It reads back and compares. A write that is not verified is a hope.
    * Any failure says so and exits non-zero; nothing is reported as installed that is not.

  A licence that verifies but is outside its validity window (NotYetValid / Expired / Grace) is
  stored -- it is the issued document -- and the status is shown in plain words so the operator knows.

.PARAMETER LicensePath
  The issued licence file (.pimlicense / .aitlicense). Its CONTENT is imported; the file is not kept.
.PARAMETER LicenseJson
  The issued licence document as text (JSON with payloadB64 + signature), instead of -LicensePath.
.PARAMETER ConnectionString
  A ready connection string to the store (e.g. a local SQL Server with Integrated security).
.PARAMETER SqlServer
  The store's server instead of -ConnectionString. An Azure SQL FQDN connects with a token -- as the
  admin app (-TenantId -AdminAppId -AdminCertThumbprint) or as the signed-in az user
  (-UseSignedInAccount, a member of the SQL admin group) -- exactly like Set-PimManagerAccess.ps1.

.EXAMPLE
  pwsh -File Set-PimLicense.ps1 -LicensePath .\Contoso.pimlicense -SqlServer sql-x.database.windows.net `
       -TenantId <t> -AdminAppId <appid> -AdminCertThumbprint <thumb>
.EXAMPLE
  pwsh -File Set-PimLicense.ps1 -LicensePath .\Contoso.pimlicense -SqlServer sql-x.database.windows.net -TenantId <t> -UseSignedInAccount -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$LicensePath,
    [string]$LicenseJson,
    [string]$ConnectionString,
    [Alias('SqlServerFqdn')][string]$SqlServer,
    [Alias('SqlDatabase')][string]$Database = 'PimPlatform',
    [string]$TenantId,
    [string]$AdminAppId,
    [string]$AdminCertThumbprint,
    # 71.33: reach the store as the SIGNED-IN az user (a member of the SQL admin group) instead of -AdminAppId.
    [switch]$UseSignedInAccount,
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath
$sol  = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $sol 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $sol 'engine\_shared\PIM-SqlStore.ps1')
. (Join-Path $sol 'engine\_shared\PIM-License.ps1')

# Set-PimLicense / Get-PimLicenseFromStore speak to the store through Get-PimSetting / Set-PimSetting (the
# Manager and the scheduler bind those to their own store). Bind them here to the store this script targets.
$script:PimLicenseImportCs = ''
function Get-PimSetting { param([Parameter(Mandatory)][string]$Name) Get-PimSqlSetting -ConnectionString $script:PimLicenseImportCs -Name $Name }
function Set-PimSetting { param([Parameter(Mandatory)][string]$Name, [object]$Value) Set-PimSqlSetting -ConnectionString $script:PimLicenseImportCs -Name $Name -Value $Value }

function ConvertTo-PimStoredLicenseText {
    # The stored value comes back through ConvertFrom-Json: a string for what this script writes. Anything else
    # (a hand-written object) is re-serialised so it can still be verified.
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return "$Value" }
    return (ConvertTo-Json -InputObject $Value -Depth 6 -Compress)
}

function Import-PimLicenseToStore {
    <#
      Verify, store, read back, re-verify. Returns the outcome; THROWS on any failure (a refused document,
      an unreachable store, a read-back mismatch). -PublicCertB64 is the test seam Set-PimLicense already has
      (an ephemeral test key); the script itself never passes it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [Parameter(Mandatory)][string]$LicenseText,
        [string]$PublicCertB64,
        [switch]$WhatIfOnly
    )
    $text = "$LicenseText".Trim()
    if (-not $text) { throw 'the licence document is empty' }
    $verifyArgs = @{ LicenseText = $text }
    if ($PublicCertB64) { $verifyArgs['PublicCertB64'] = $PublicCertB64 }

    # 1. Verify BEFORE touching the store: a document that does not verify is never written.
    $pre = Get-PimLicense @verifyArgs
    if ($pre.Status -in @('Invalid','Missing')) { throw "licence NOT stored: $($pre.Reason)" }

    $script:PimLicenseImportCs = $ConnectionString
    # 2. What is there now (reported, so a replacement is visible). A store that cannot be read is not written.
    $prevId = ''
    try {
        $prevText = ConvertTo-PimStoredLicenseText -Value (Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'License')
        if ($prevText) {
            $pv = Get-PimLicense -LicenseText $prevText -PublicCertB64 $(if ($PublicCertB64) { $PublicCertB64 } else { '' })
            $prevId = if ("$($pv.LicenseId)".Trim()) { "$($pv.LicenseId)" } else { '(a stored document that does not verify)' }
        }
    } catch { throw "could not read the store before writing ($($_.Exception.Message)) -- nothing was stored" }

    $out = [ordered]@{ ok = $false; stored = $false; whatIf = [bool]$WhatIfOnly; status = "$($pre.Status)"; reason = "$($pre.Reason)"
                       licenseId = "$($pre.LicenseId)"; customer = "$($pre.Customer)"; sku = "$($pre.Sku)"
                       features = @($pre.Features); tenantIds = @($pre.TenantIds)
                       validTo = $(if ($pre.ValidTo) { $pre.ValidTo.ToString('yyyy-MM-dd') } else { '' }); previousLicenseId = $prevId }
    if ($WhatIfOnly) { $out.ok = $true; return [pscustomobject]$out }

    # 3. Store (Set-PimLicense verifies AGAIN and refuses before writing).
    $setArgs = @{ LicenseText = $text }
    if ($PublicCertB64) { $setArgs['PublicCertB64'] = $PublicCertB64 }
    [void](Set-PimLicense @setArgs)

    # 4. Read back what the containers will read, and verify THAT.
    $back = ''
    try { $back = ConvertTo-PimStoredLicenseText -Value (Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'License') }
    catch { throw "wrote the licence, but could not read it back: $($_.Exception.Message)" }
    if ("$back".Trim() -ne $text) { throw "read-back mismatch: pim.Settings['License'] does not hold the document that was written" }
    $verifyArgs['LicenseText'] = "$back"
    $post = Get-PimLicense @verifyArgs
    if ($post.Status -in @('Invalid','Missing')) { throw "the stored licence does not verify on read-back: $($post.Reason)" }
    $out.ok = $true; $out.stored = $true; $out.status = "$($post.Status)"; $out.reason = "$($post.Reason)"
    return [pscustomobject]$out
}

# Dot-sourced (the offline test): define the functions, run nothing.
if ($MyInvocation.InvocationName -eq '.') { return }

$result = [ordered]@{ ok = $false; reason = ''; whatIf = [bool]$WhatIfPreference }
function Write-ResultFile { if ("$OutFile".Trim()) { try { $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutFile -Encoding UTF8 } catch {} } }
function Fail($m) { $result.reason = $m; Write-ResultFile; Write-Host "RESULT: FAILED -- $m" -ForegroundColor Red; exit 1 }
function Note($m, $c = 'Gray') { Write-Host "  $m" -ForegroundColor $c }

Write-Host "=== PIM licence -> pim.Settings['License'] ===" -ForegroundColor Cyan

# --- the document (validated before any connection) ------------------------------------------
if ("$LicensePath".Trim() -and "$LicenseJson".Trim()) { Fail 'supply -LicensePath OR -LicenseJson, not both' }
$doc = ''
if ("$LicensePath".Trim()) {
    if (-not (Test-Path -LiteralPath $LicensePath)) { Fail "no licence file at '$LicensePath'" }
    $doc = Get-Content -LiteralPath $LicensePath -Raw -Encoding UTF8
} elseif ("$LicenseJson".Trim()) {
    $doc = "$LicenseJson"
} else { Fail 'supply -LicensePath (the issued licence file) or -LicenseJson (its content)' }

# --- the store ------------------------------------------------------------------------------
$cs = ''
if ("$ConnectionString".Trim()) {
    if ("$SqlServer".Trim()) { Fail 'supply -ConnectionString OR -SqlServer, not both' }
    $cs = "$ConnectionString"
} elseif ("$SqlServer".Trim()) {
    $global:PIM_SqlServer   = $SqlServer
    $global:PIM_SqlDatabase = $Database
    if ($SqlServer -match '(?i)database\.windows\.net') {
        if (-not "$TenantId".Trim()) { Fail 'an Azure SQL store needs -TenantId (token auth)' }
        if ($UseSignedInAccount) {
            if ("$AdminAppId".Trim() -or "$AdminCertThumbprint".Trim()) { Fail '-UseSignedInAccount cannot be combined with -AdminAppId/-AdminCertThumbprint' }
            . (Join-Path $here '_PimSignedIn.ps1')
            try { $who = Connect-PimSignedInSql -TenantId $TenantId; Note "store identity: signed-in user $($who.userName)" 'DarkGray' } catch { Fail "$($_.Exception.Message)" }
        } else {
            if (-not "$AdminAppId".Trim() -or -not "$AdminCertThumbprint".Trim()) { Fail 'supply -AdminAppId with -AdminCertThumbprint (certificate auth), or -UseSignedInAccount' }
            $global:PIM_TenantId       = $TenantId
            $global:PIM_ClientId       = $AdminAppId
            $global:PIM_CertThumbprint = $AdminCertThumbprint
        }
    }
    try { $cs = Get-PimSqlConnectionString -Server $SqlServer -Database $Database }
    catch { Fail "could not build a connection string: $($_.Exception.Message)" }
} else { Fail 'supply -SqlServer (with -Database) or -ConnectionString' }

# --- verify, store, read back ----------------------------------------------------------------
$whatIfOnly = [bool]$WhatIfPreference -or -not $PSCmdlet.ShouldProcess("pim.Settings['License']", 'store the verified licence')
try { $r = Import-PimLicenseToStore -ConnectionString $cs -LicenseText $doc -WhatIfOnly:$whatIfOnly }
catch { Fail "$($_.Exception.Message)" }

foreach ($k in $r.PSObject.Properties.Name) { $result[$k] = $r.$k }
Note ("licence : $($r.licenseId) -- $($r.customer), sku $($r.sku), valid to $($r.validTo)") 'Gray'
Note ("features: " + $(if (@($r.features).Count) { @($r.features) -join ', ' } else { '(none)' })) 'DarkGray'
if (@($r.tenantIds).Count) {
    Note ("bound to: " + (@($r.tenantIds) -join ', ')) 'DarkGray'
    if ("$TenantId".Trim() -and (@($r.tenantIds) -notcontains "$TenantId".Trim())) {
        Note "WARNING: this licence is NOT bound to tenant $TenantId -- Pro features will not unlock on it." 'Yellow'
    }
}
if ("$($r.previousLicenseId)".Trim()) { Note "replaces: $($r.previousLicenseId)" 'Yellow' }
if ($r.status -ne 'Valid') { Note "STATUS: $($r.status) -- $($r.reason)" 'Yellow' }

if ($r.whatIf) {
    $result.ok = $true; $result.reason = "what-if -- the licence verifies ($($r.status)); nothing written"
    Write-ResultFile; Write-Host "RESULT: WHAT-IF -- $($result.reason)" -ForegroundColor Yellow; exit 0
}
$result.ok = $true
$result.reason = "stored and read back: $($r.licenseId) ($($r.status): $($r.reason))"
Write-ResultFile
Write-Host "RESULT: OK -- $($result.reason)" -ForegroundColor Green
Write-Host "  NOTE: the containers cache the licence per process; it is picked up on the next start/roll." -ForegroundColor DarkGray
exit 0
