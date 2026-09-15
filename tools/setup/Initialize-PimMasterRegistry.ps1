#requires -Version 5.1
<#
.SYNOPSIS
    Apply the MSP MASTER registry schema (platform.Tenants / platform.TenantApps /
    pim.CentralAdmins / the fan-out view) to a master's store. Idempotent, and VERIFIED after it
    runs.

.DESCRIPTION
    🔴 WHY THIS SCRIPT EXISTS. The estate's step 4 creates the *pim* desired-store schema. It does
    NOT create the *platform* one -- the tables that make a tenant an MSP MASTER. Until now the
    only thing that applied `sql/platform-schema.sql` outside the engine was
    `tests/live/Seed-PimScenarioDataset.ps1`, a TEST script, which meant a freshly provisioned
    master had no `pim.CentralAdmins` and the first real command against it failed with

        Cannot find the object "pim.CentralAdmins" because it does not exist or you do not have
        permissions.

    -- measured on EFIF 2026-09-03, immediately after a clean rebuild. A prerequisite that only a
    test script installs is not installed.

    🪤 THE ERROR IS ACTIVELY MISLEADING. SQL words a missing object and a permissions problem the
    SAME WAY ("...does not exist or you do not have permissions"), so the natural reading of a
    fresh master is "my SPN lacks rights" -- and the estate has enough identity plumbing to make
    that plausible for a long time. It is neither: the table was simply never created.

    WHAT IT CREATES (all additive; the file is written to be re-runnable):
        platform.Tenants          the managed-tenant registry the downlink projects to
        platform.TenantApps       per-tenant app registrations
        pim.CentralAdmins         the MSP admins projected INTO managed tenants
        pim.TenantRoleProjection  the MSP-4 per-relationship projection policy
        + the MSP-4 targeting columns (CentralAdmins.Target, Tenants.Tags)

    🔒 GO BATCHES. `sql/platform-schema.sql` uses GO separators, which SqlClient cannot execute --
    it is a client directive, not T-SQL. The script is split on GO and each batch run separately.
    Running the file whole "works" right up until the first GO, then silently applies only the
    first batch, which is the worst possible partial state: some tables present, some absent.

.EXAMPLE
    ./Initialize-PimMasterRegistry.ps1 -SqlServer sql-ait-wa678.database.windows.net
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SqlServer,
    [string]$Database = 'PimPlatform',
    [string]$SchemaPath
)

$ErrorActionPreference = 'Stop'
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m){ Write-Host "    $m" -ForegroundColor DarkGray }

$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1')

if (-not "$SchemaPath".Trim()) { $SchemaPath = Join-Path $solRoot 'sql\platform-schema.sql' }
if (-not (Test-Path -LiteralPath $SchemaPath)) { throw "platform schema not found: $SchemaPath" }

Step "MSP master registry -> $SqlServer/$Database"
Note "schema: $SchemaPath"

$tok = Get-PimRestToken -Resource 'https://database.windows.net'
# 🔴 Decode before use (SEC-12): a fallback once returned a DIFFERENT COMPANY's token, and it
# surfaced far away as a permissions error.
$p = $tok.Split('.')[1].Replace('-','+').Replace('_','/'); while ($p.Length % 4) { $p += '=' }
$claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
if ("$($global:PIM_TenantId)".Trim() -and $claims.tid -ne $global:PIM_TenantId) {
    throw "token tenant '$($claims.tid)' != requested '$($global:PIM_TenantId)' -- refusing to apply DDL to $SqlServer."
}
Note "token verified: tid=$($claims.tid) appid=$($claims.appid)"
function Q($sql) { Invoke-Sqlcmd -ServerInstance $SqlServer -Database $Database -AccessToken $tok -Encrypt Mandatory -Query $sql -ErrorAction Stop }

# --- apply, batch by batch --------------------------------------------------------------
$text    = Get-Content -LiteralPath $SchemaPath -Raw
$batches = @([regex]::Split($text, "(?im)^\s*GO\s*$") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
Step "applying $($batches.Count) batch(es)"
if ($PSCmdlet.ShouldProcess("$SqlServer/$Database", "apply platform schema ($($batches.Count) batches)")) {
    $n = 0
    foreach ($b in $batches) {
        $n++
        try { Q $b | Out-Null }
        catch { throw "batch $n of $($batches.Count) failed: $($_.Exception.Message)" }
    }
    Note "applied $n batch(es)"
}

# --- VERIFY: the objects must actually be there -----------------------------------------
# A DDL script that reports its own success is exactly the pattern this solution keeps getting
# caught by, so the tables are read back rather than assumed.
Step 'verifying the registry objects exist'
$want = @('platform.Tenants','platform.TenantApps','pim.CentralAdmins','pim.TenantRoleProjection')
$missing = @()
foreach ($t in $want) {
    $ok = (Q "SELECT OBJECT_ID('$t') AS id").id
    if ($null -eq $ok -or $ok -eq [DBNull]::Value) { $missing += $t } else { Note "  $t present" }
}
if ($missing.Count) { throw "the schema applied but these objects are still missing: $($missing -join ', ')" }

# the MSP-4 targeting axis -- absent columns silently disable narrowing rather than failing
foreach ($c in @('pim.CentralAdmins|Target','platform.Tenants|Tags')) {
    $parts = $c.Split('|')
    $len = (Q "SELECT COL_LENGTH('$($parts[0])','$($parts[1])') AS n").n
    $state = if ($null -eq $len -or $len -eq [DBNull]::Value) { 'MISSING -- MSP-4 narrowing will be inert' } else { 'present' }
    Note "  $($parts[0]).$($parts[1]): $state"
}

Step 'Done.'
Note 'next: tools/setup/Add-PimCentralAdmin.ps1 to add the MSP admins, then setup/New-PimBaselineBundle.ps1 to publish.'
