<#
.SYNOPSIS
  Run the TEST-11 live functional matrix (Test-PimFunctionalMatrix.ps1) across SEVERAL estate
  tenants in one command, and report one table that says whether the product works.

.DESCRIPTION
  The matrix itself proves one tenant. This driver proves a SHAPE: the operator's question is not
  "does it work on a tenant" but "does it work on a STANDALONE tenant, on an MSP MASTER, and on a
  MANAGED SLAVE" -- three topologies that differ in how the store, the identities and the admin
  rows are arranged, and which have never been verified with one instrument.

  Everything each run needs is derived from the environment's own
  `C:\AutomateIT-TestRepo\<env>\bootstrap\platform-config.json` (tenant id, subscription id, vault
  name, bootstrap SPN + thumbprint), so a caller names environments and nothing else. The ENGINE
  identity is read from that tenant's own vault as `Modern-AppId` / `Modern-Thumbprint`.
  🪤 Those secret names are NOT the `PIM4EntraPS-*` pattern the repo-root CLAUDE.md documents --
  that pattern is myfamilynetwork's. Looking for it in an estate vault finds nothing.

  🔒 EACH ENVIRONMENT GETS ITS OWN SCRATCH STORE (`PimMatrixTest_<token>` on the local SQLEXPRESS).
  Sharing one would be a correctness bug, not a tidiness one: the matrix refuses to run unless the
  desired store holds only rows it owns, and tenant A's marked rows carry A's UPN domain. B would
  then plan against A's rows, and the first thing it did would be to reconcile them away.

  🔒 `PIM_TestTenantIds` is set to exactly the environments being run, and nothing else. The
  matrix's preflight refuses any tenant that does not classify as `test`, so this is the switch
  that makes a run possible -- which is precisely why it is set narrowly, per run, from the
  environments named on the command line, and never widened to "the estate".

.PARAMETER Environments
  Estate short names, e.g. test1comr2xx391 (standalone), test1mspmstintctrr2wa678 (master),
  test1mspslvintctrr3rq855 (slave).

.PARAMETER IncludeDestructive
  Pass through to the matrix: also run the "deliberately ON" half of the destructive family.
  Without it that half is SKIPPED, and a skip is not a pass.

.PARAMETER CleanupOnly
  Remove every marked object + harness row in each environment, then exit. Nothing is asserted.

.PARAMETER KeepObjects
  Do not clean up after a successful run (leaves the marked objects for inspection).

.NOTES
  Exit 0 only when every environment reports zero required failures AND zero required skips.
  A skipped required case is a failure here by design: the whole point is a green that means
  "verified", and "we did not look" is not that.
#>
[CmdletBinding()]
param(
    [string[]]$Environments = @('test1comr2xx391','test1mspmstintctrr2wa678','test1mspslvintctrr3rq855'),
    [switch]$IncludeDestructive,
    [switch]$CleanupOnly,
    [switch]$KeepObjects,
    [string]$RepoRoot = 'C:\AutomateIT-TestRepo',
    [string]$SqlServer = '.\SQLEXPRESS'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$matrix = Join-Path $here 'Test-PimFunctionalMatrix.ps1'
if (-not (Test-Path -LiteralPath $matrix)) { Write-Host "matrix not found: $matrix" -ForegroundColor Red; exit 2 }

function Head($t) { Write-Host ''; Write-Host ('=' * 100) -ForegroundColor Cyan; Write-Host " $t" -ForegroundColor Cyan; Write-Host ('=' * 100) -ForegroundColor Cyan }

# ---- resolve every environment FIRST -------------------------------------------------------
# All of it up front, before a single tenant is touched. A run that dies on environment 3 because
# its config was missing has already written to 1 and 2, and the operator now has a half-applied
# estate to reason about. Resolution is free; discovering a gap late is not.
$targets = @()
foreach ($e in $Environments) {
    $cfgPath = Join-Path $RepoRoot (Join-Path $e 'bootstrap\platform-config.json')
    if (-not (Test-Path -LiteralPath $cfgPath)) { Write-Host "NO CONFIG: $cfgPath" -ForegroundColor Red; exit 2 }
    $cfg = Get-Content -LiteralPath $cfgPath -Raw | ConvertFrom-Json
    $tok = $e.Substring($e.Length - 5)
    $targets += [pscustomobject]@{
        Env = $e; Token = $tok; TenantId = "$($cfg.TenantId)"; SubscriptionId = "$($cfg.SubscriptionId)"
        Vault = "$($cfg.KeyVaultName)"; BootAppId = "$($cfg.BootstrapAppId)"; BootThumb = "$($cfg.BootstrapThumbprint)"
        Db = "PimMatrixTest_$tok"
    }
}
Head "LIVE FUNCTIONAL MATRIX -- $($targets.Count) environment(s)"
foreach ($t in $targets) { Write-Host ("  {0,-26} tenant={1}  store={2}" -f $t.Env, $t.TenantId, $t.Db) }
# Narrow by construction: exactly the tenants named, so the matrix cannot be pointed anywhere else.
$env:PIM_TestTenantIds = ($targets.TenantId -join ',')
Write-Host "  PIM_TestTenantIds set to exactly these $($targets.Count) tenant(s)" -ForegroundColor DarkGray

$results = @()
foreach ($t in $targets) {
    Head "$($t.Env)  ($($t.Token))"
    $row = [pscustomobject]@{ Env=$t.Env; Pass=0; Fail=0; Skip=0; ReqFail=0; ReqSkip=0; Exit=$null; Detail='' }
    try {
        Connect-AzAccount -ServicePrincipal -ApplicationId $t.BootAppId -Tenant $t.TenantId `
            -CertificateThumbprint $t.BootThumb -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
        $cid = Get-AzKeyVaultSecret -VaultName $t.Vault -Name Modern-AppId      -AsPlainText -ErrorAction Stop
        $thb = Get-AzKeyVaultSecret -VaultName $t.Vault -Name Modern-Thumbprint -AsPlainText -ErrorAction Stop
        if (-not (Get-Item "Cert:\LocalMachine\My\$thb" -ErrorAction SilentlyContinue)) {
            throw "the engine cert $thb is not on this machine (LocalMachine\My) -- the matrix cannot authenticate"
        }
        $common = @{ TenantId = $t.TenantId; ClientId = $cid; CertThumbprint = $thb
                     SqlServer = $SqlServer; SqlDatabase = $t.Db }

        # Always start from a clean tenant. A previous run's marked objects would otherwise be read
        # as "already there" and the create cases would assert against someone else's leftovers.
        Write-Host '  -- cleanup (previous marked objects) --' -ForegroundColor DarkGray
        & $matrix @common -Cleanup 2>&1 | Out-Null

        if ($CleanupOnly) { $row.Exit = 0; $row.Detail = 'cleanup only'; $results += $row; continue }

        $mxArgs = @{} + $common
        if ($t.SubscriptionId) { $mxArgs['AzSubscriptionId'] = $t.SubscriptionId }   # else the AzRes cases self-skip
        if ($IncludeDestructive) { $mxArgs['IncludeDestructive'] = $true }
        $mxArgs['FailOnSkip'] = $true       # a required skip is not a pass

        # 🔴 `*>&1`, NOT `2>&1`. The matrix reports through Write-Host, which in PowerShell 5+ goes
        # to the INFORMATION stream (6) -- `2>&1` merges only stderr, so the first version of this
        # driver captured NOTHING, could not find the TOTAL line, and recorded 0 pass / 0 fail.
        $out = & $matrix @mxArgs *>&1
        $row.Exit = $LASTEXITCODE
        $out | ForEach-Object { Write-Host $_ }
        # Parse the harness's own TOTAL line rather than recomputing -- one source of truth.
        $tot = ($out | ForEach-Object { "$_" } | Select-String -Pattern 'TOTAL\s+pass=(\d+)\s+fail=(\d+)\s+skipped=(\d+)\s+\(required failures=(\d+), required skips=(\d+)\)' | Select-Object -Last 1)
        if ($tot) {
            $m = $tot.Matches[0].Groups
            $row.Pass=[int]$m[1].Value; $row.Fail=[int]$m[2].Value; $row.Skip=[int]$m[3].Value
            $row.ReqFail=[int]$m[4].Value; $row.ReqSkip=[int]$m[5].Value
        } else {
            # 🔴 FAIL CLOSED. This branch used to leave the row at 0/0/0 and fall through to the
            # green test -- which passes, because zero required failures and zero required skips is
            # exactly what a clean run looks like. The 2026-08-25 estate run really was 102/0/0 on
            # all three tenants, and the driver still printed "ALL 3 GREEN" for the wrong reason:
            # it had parsed nothing at all. **An unreadable result is not a passing result**, and a
            # verdict reached without evidence is the same defect as BUG-70 one layer up.
            $row.ReqFail = 1
            $row.Detail  = 'NO TOTAL LINE -- the run produced no parseable summary; treated as FAILED'
        }

        if (-not $KeepObjects -and $row.ReqFail -eq 0) {
            Write-Host '  -- cleanup (leave the tenant as we found it) --' -ForegroundColor DarkGray
            & $matrix @common -Cleanup 2>&1 | Out-Null
        } elseif ($row.ReqFail -gt 0) {
            Write-Host '  -- objects LEFT IN PLACE for diagnosis (required failures) --' -ForegroundColor Yellow
        }
    } catch {
        $row.Exit = 2; $row.Detail = $_.Exception.Message
        Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
    $results += $row
}

Head 'RESULT'
Write-Host ("  {0,-26} {1,6} {2,6} {3,6} {4,9} {5,9}  {6}" -f 'environment','pass','fail','skip','req-fail','req-skip','detail')
foreach ($r in $results) {
    $ok = ($r.ReqFail -eq 0 -and $r.ReqSkip -eq 0 -and $r.Exit -eq 0)
    Write-Host ("  {0,-26} {1,6} {2,6} {3,6} {4,9} {5,9}  {6}" -f $r.Env,$r.Pass,$r.Fail,$r.Skip,$r.ReqFail,$r.ReqSkip,$r.Detail) `
        -ForegroundColor $(if ($ok) { 'Green' } else { 'Red' })
}
$bad = @($results | Where-Object { $_.ReqFail -ne 0 -or $_.ReqSkip -ne 0 -or $_.Exit -ne 0 })
Write-Host ''
if ($bad.Count) {
    Write-Host ("  {0} of {1} environment(s) NOT green." -f $bad.Count, $results.Count) -ForegroundColor Red
    exit 1
}
Write-Host ("  ALL {0} environment(s) GREEN -- every required case verified against the live tenant." -f $results.Count) -ForegroundColor Green
exit 0
