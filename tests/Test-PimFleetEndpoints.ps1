#Requires -Version 5.1
<#
.SYNOPSIS
    Live boot test of the FLEET conformance endpoints (REQUIREMENTS.md s28 [H8]):
    GET /api/conformance/fleet (tenants x templates matrix, behind-by-N) and
    GET /api/conformance/ring-plan?template= (ring-wide rollout bands).

.DESCRIPTION
    Boots Open-PimManager.ps1 headless on a free loopback port (shared boot helper),
    then probes both new endpoints over real HTTP. Seeds the local instance's
    template-state stamp so the matrix has a non-trivial applied version for the
    single approved workload template under workloads/templates. Offline-safe: the
    fleet view never calls a tenant (it reads local state files), so no Graph/SQL.
    Rerunnable; restores the state file it touched.
#>
[CmdletBinding()] param([int]$Port = 0)
$ErrorActionPreference = 'Stop'
$pass=0; $fail=0
function T($n,$c){ if($c){Write-Host "  PASS $n" -ForegroundColor Green;$script:pass++}else{Write-Host "  FAIL $n" -ForegroundColor Red;$script:fail++} }

$solRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot '_shared\PimManagerBoot.ps1')
$mgr = Join-Path $solRoot 'tools\pim-manager\Open-PimManager.ps1'
$out = Join-Path $env:TEMP ("pim-fleet-ep-{0}.out" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))

# Seed the local instance's template-state with an applied version BEHIND the
# approved template (so the matrix shows a Behind/never-current local tenant).
$stateFile = Join-Path $solRoot 'output\state\template-state.json'
$stateDir  = Split-Path -Parent $stateFile
$backup    = $null
if (-not (Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
if (Test-Path $stateFile) { $backup = "$stateFile.fleettest.bak"; Copy-Item $stateFile $backup -Force }
# defender-xdr-roles is templateVersion 1 in-repo; stamp 0 to force NeverApplied for
# 'local' OR stamp the real version - we stamp 0 (delete the key) so it reads NeverApplied,
# which is the most common real-world fleet state (a tenant that never deployed it).
@{ } | ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding UTF8

$ctx = $null
try {
    $ctx = Start-PimManagerForTest -ManagerPath $mgr -StdoutPath $out -TimeoutSec 40
    T 'Manager booted (port + token)' ($ctx.Port -gt 0 -and $ctx.Token)
    if (-not ($ctx.Port -gt 0 -and $ctx.Token)) {
        Write-Host (Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue) -ForegroundColor DarkGray
        throw 'Manager did not report a port/token'
    }
    $base = $ctx.BaseUrl; $h = $ctx.Headers

    # --- 401 without the token (security model still holds on the new routes) ----
    $code = 0
    try { Invoke-WebRequest -Uri "$base/api/conformance/fleet" -UseBasicParsing | Out-Null }
    catch { $code = [int]$_.Exception.Response.StatusCode.value__ }
    T '/api/conformance/fleet 401 without token' ($code -eq 401)

    # --- fleet matrix -----------------------------------------------------------
    $fleet = Invoke-RestMethod -Uri "$base/api/conformance/fleet" -Headers $h -UseBasicParsing
    T 'fleet: returns activeInstance'    ([bool]$fleet.activeInstance)
    T 'fleet: has templates array'       ($null -ne $fleet.templates)
    T 'fleet: has tenants array'         ($null -ne $fleet.tenants)
    T 'fleet: includes the local tenant' (@($fleet.tenants | Where-Object { $_.tenantId -eq 'local' }).Count -ge 1)
    T 'fleet: totalTenants >= 1'         ($fleet.totalTenants -ge 1)
    # If there is an approved template, the local tenant (no applied version) is NeverApplied -> not current.
    $approvedCols = @($fleet.templates)
    if ($approvedCols.Count -ge 1) {
        $localRow = @($fleet.tenants | Where-Object { $_.tenantId -eq 'local' })[0]
        T 'fleet: local has a cell per template' (@($localRow.cells).Count -eq $approvedCols.Count)
        $cell0 = @($localRow.cells)[0]
        T 'fleet: never-applied cell status' ($cell0.status -eq 'NeverApplied')
        T 'fleet: never-applied not current' ($localRow.current -eq $false)
        T 'fleet: perTemplate rollup present' (@($fleet.perTemplate).Count -eq $approvedCols.Count)

        # --- ring-plan for that template ----------------------------------------
        $tid = $approvedCols[0].templateId
        $plan = Invoke-RestMethod -Uri "$base/api/conformance/ring-plan?template=$([uri]::EscapeDataString($tid))" -Headers $h -UseBasicParsing
        T 'ring-plan: echoes templateId' ($plan.templateId -eq $tid)
        T 'ring-plan: has bands'         ($null -ne $plan.bands)
        T 'ring-plan: totalTenants >= 1' ($plan.totalTenants -ge 1)
        T 'ring-plan: local is behind/never' ($plan.needsRolloutCount -ge 1)
    } else {
        Write-Host '  (no approved templates in repo; matrix structure still verified)' -ForegroundColor DarkYellow
        # ring-plan on a known template id should 400 cleanly when unknown.
        $rc = 0
        try { Invoke-WebRequest -Uri "$base/api/conformance/ring-plan?template=nope" -Headers $h -UseBasicParsing | Out-Null }
        catch { $rc = [int]$_.Exception.Response.StatusCode.value__ }
        T 'ring-plan: unknown template -> 400' ($rc -eq 400)
    }

    # --- ring-plan unknown template -> 400 -------------------------------------
    $rc2 = 0
    try { Invoke-WebRequest -Uri "$base/api/conformance/ring-plan?template=__does_not_exist__" -Headers $h -UseBasicParsing | Out-Null }
    catch { $rc2 = [int]$_.Exception.Response.StatusCode.value__ }
    T 'ring-plan: nonexistent template -> 400' ($rc2 -eq 400)

    try { Invoke-RestMethod -Uri "$base/api/heartbeat" -Method Post -Headers $h -UseBasicParsing | Out-Null } catch {}
}
finally {
    if ($ctx) { Stop-PimManagerForTest -Context $ctx }
    # Restore the state file we touched.
    if ($backup -and (Test-Path $backup)) { Move-Item $backup $stateFile -Force }
    elseif (-not $backup) { Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue }
}

Write-Host ""
Write-Host ("RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 } else { exit 0 }
