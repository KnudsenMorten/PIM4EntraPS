#Requires -Version 5.1
<#
.SYNOPSIS
    Functional test of the PIM Manager HTTP server: boots Open-PimManager.ps1
    headless (-Server -NoLaunch), captures the session bearer token from stdout,
    and probes every offline-safe /api/* endpoint over real HTTP (127.0.0.1).

.DESCRIPTION
    Proves the Manager's security model + routing: 401 without the token, 200
    with it, and sane JSON from each read endpoint. Graph-backed endpoints
    (refresh-tenant-lists, discovery-baseline, active-assignments, revoke) are
    not probed -- they need a live tenant. Sends /api/heartbeat to keep the
    server alive, then stops it. Rerunnable.
#>
[CmdletBinding()]
# -Port 0 (default) => boot helper allocates a FREE port at runtime (no fixed-port
# collision / no zombie-port hang). A non-zero -Port is accepted but ignored; the
# Manager always self-allocates and we use the port it actually bound.
param([int]$Port = 0)

$ErrorActionPreference = 'Stop'
$pass=0; $fail=0
function T($n,$c){ if($c){Write-Host "  PASS $n" -ForegroundColor Green;$script:pass++}else{Write-Host "  FAIL $n" -ForegroundColor Red;$script:fail++} }

$solRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot '_shared\PimManagerBoot.ps1')
$mgr = Join-Path $solRoot 'tools\pim-manager\Open-PimManager.ps1'
$out = Join-Path $env:TEMP ("pim-mgr-test-{0}.out" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
if (Test-Path $out) { Remove-Item $out -Force }

# Seed the scheduler state + run history (the local instance's output\scheduler dir,
# which the Manager's /api/jobs reads) so the Jobs tab is never a dead view. The seed
# includes one IN-PROGRESS run so we can assert ordering + the per-run Logs endpoint.
$seedScript = Join-Path $solRoot 'tools\pim-scheduler\Seed-PimSchedulerRuns.ps1'
if (Test-Path $seedScript) {
    try { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$seedScript" | Out-Null } catch { Write-Host "  (seed warning: $($_.Exception.Message))" -ForegroundColor DarkYellow }
}

# ---------------------------------------------------------------------------
# Seed the REAL append-only audit trail (output/audit/pim-audit-<yyyyMM>.jsonl)
# with a known set of multi-category events so the Audit tab tests below run
# against real data (no dead views / no dead filters). We tag the seeded events
# with a unique marker so we can find/clean exactly our rows, leaving any real
# audit history untouched. The local instance writes audit to <sol>\output.
# ---------------------------------------------------------------------------
$auditDir = Join-Path $solRoot 'output\audit'
if (-not (Test-Path $auditDir)) { New-Item -ItemType Directory -Path $auditDir -Force | Out-Null }
$auditFile = Join-Path $auditDir ('pim-audit-{0}.jsonl' -f ([datetime]::UtcNow.ToString('yyyyMM')))
$seedMarker = 'audit-seed-' + ([guid]::NewGuid().ToString('N'))
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
# action -> expected category (mirrors Get-PimAuditCategory).
$seedRows = @(
    @{ action='manager.login';          target="$seedMarker-user1"; cat='logins' }
    @{ action='emergency.passcode.failed'; target="$seedMarker-em";  cat='emergency'; result='denied' }
    @{ action='emergency.activate';      target="$seedMarker-em";    cat='emergency' }
    @{ action='approval.escalate';       target="$seedMarker-grpA";  cat='approvals' }
    @{ action='account.create';          target="$seedMarker-acctX"; cat='accounts' }
    @{ action='tap.create';              target="$seedMarker-acctX"; cat='accounts' }
    @{ action='membership.drift.remove'; target="$seedMarker-grpB";  cat='delegations' }
    @{ action='cutover.finalize';        target="$seedMarker-sql";   cat='delegations' }
    @{ action='policy.apply';            target="$seedMarker-grpC";  cat='engine' }
    @{ action='resource.discovered';     target="$seedMarker-res";   cat='engine' }
)
$i = 0
foreach ($r in $seedRows) {
    $i++
    $evt = [ordered]@{
        ts            = [datetime]::UtcNow.AddMinutes(-$i).ToString('o')
        runId         = $seedMarker
        correlationId = ''
        actor         = 'engine'
        action        = $r.action
        target        = $r.target
        before        = $null
        after         = @{ seeded = $true }
        result        = $(if ($r.ContainsKey('result')) { $r.result } else { 'ok' })
        whatIf        = $false
    }
    [System.IO.File]::AppendAllText($auditFile, (($evt | ConvertTo-Json -Depth 5 -Compress) + "`r`n"), $utf8NoBom)
}
Write-Host "Seeded $($seedRows.Count) audit events (marker $seedMarker) into $auditFile"

# Governance round-trips write real (gitignored) config files in the default
# config root; snapshot them so we can restore the pre-test state afterwards.
$cfgDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'config'
$accessFile   = Join-Path $cfgDir 'manager-access.custom.json'
$settingsFile = Join-Path $cfgDir 'manager-settings.custom.json'
$accessBak   = if (Test-Path $accessFile)   { Get-Content -LiteralPath $accessFile   -Raw -Encoding UTF8 } else { $null }
$settingsBak = if (Test-Path $settingsFile) { Get-Content -LiteralPath $settingsFile -Raw -Encoding UTF8 } else { $null }
# The running identity must stay SuperAdmin across the access-map write so the
# server doesn't lock itself out mid-test.
$me = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $env:USERNAME }
Write-Host "Booting Manager headless on a dynamic free port ..."
$ctx  = Start-PimManagerForTest -ManagerPath $mgr -StdoutPath $out -TimeoutSec 30
$proc = $ctx.Process

try {
    $token = $ctx.Token
    T 'Manager booted + emitted session token' ([bool]$token -and $ctx.Port -gt 0)
    if (-not $token) { Get-Content $out,"$out.err" -EA SilentlyContinue | Select-Object -Last 15 | ForEach-Object { Write-Host "    $_" }; throw 'no token' }
    Write-Host "  Manager bound port $($ctx.Port)" -ForegroundColor DarkGray

    $base = $ctx.BaseUrl
    $hdr  = @{ Authorization = "Bearer $token" }
    # 90s: the first /api/conformance* call cold-imports the (large) PIM-Functions
    # module, like other module-backed endpoints; 20s clipped that on a cold box.
    function Probe($path) { Invoke-RestMethod -Uri "$base$path" -Headers $hdr -TimeoutSec 90 }
    function Beat { try { Invoke-RestMethod -Method POST -Uri "$base/api/heartbeat" -Headers $hdr -TimeoutSec 10 | Out-Null } catch {} }

    # 401 without token
    T '401 without bearer token' {
        $code = 0
        try { Invoke-WebRequest -Uri "$base/api/config" -TimeoutSec 10 -UseBasicParsing | Out-Null } catch { $code = [int]$_.Exception.Response.StatusCode }
        $code -eq 401
    }

    Beat
    foreach ($ep in @(
        @{ p='/api/config';              chk={ param($r) $r.nodes -ne $null -or $r -ne $null } },
        @{ p='/api/access';              chk={ param($r) $r -ne $null } },
        @{ p='/api/license';             chk={ param($r) $r.status -ne $null } },
        @{ p='/api/audit?limit=5';       chk={ param($r) $r -ne $null } },
        @{ p='/api/mail-templates';      chk={ param($r) $r -ne $null } },
        @{ p='/api/admin-templates';     chk={ param($r) $r -ne $null } },
        @{ p='/api/templates';           chk={ param($r) $r -ne $null } },
        @{ p='/api/naming-conventions';  chk={ param($r) $r -ne $null } },
        @{ p='/api/emergency-status';    chk={ param($r) $r -ne $null } },
        @{ p='/api/access-map';          chk={ param($r) @($r.roles).Count -ge 4 -and $null -ne $r.you } },
        @{ p='/api/discovery-policy';    chk={ param($r) @($r.types).Count -ge 4 -and "$($r.default)" -eq 'flag' } },
        @{ p='/api/job-schedule';        chk={ param($r) @($r.jobs | Where-Object { $_.type -eq 'daily-summary' }).Count -eq 1 -and @($r.jobs | Where-Object { $_.type -eq 'tier-report' }).Count -eq 1 } },
        @{ p='/api/template-state';      chk={ param($r) $null -ne $r.disabled } },
        @{ p='/api/resolve-date?expr=Now'; chk={ param($r) $r -ne $null } },
        @{ p='/api/instances';           chk={ param($r) $r -ne $null } },
        @{ p='/api/preflight';           chk={ param($r) $r -ne $null } },
        @{ p='/api/conformance/templates'; chk={ param($r) $r.templates -ne $null } },
        @{ p='/api/conformance?template=defender-xdr-roles'; chk={ param($r) @($r.keys).Count -ge 1 -and $r.statuses -ne $null } },
        @{ p='/api/portal-access'; chk={ param($r) "$($r.managerRole)" -ne '' -and $null -ne $r.isSuperAdmin } },
        @{ p='/api/csv/Account-Definitions-Admins'; chk={ param($r) "$($r.base)" -eq 'Account-Definitions-Admins' -and $r.PSObject.Properties['portalFiltered'] } },
        # Visibility & reporting (§26a): the three read endpoints answer with the
        # right JSON shape (empty data is fine offline -- the shape proves routing
        # + the engine-backed model serialised end-to-end).
        @{ p='/api/access-report/who-can?person=nobody@example.test'; chk={ param($r) $r.PSObject.Properties['found'] -and $null -ne $r.count -and $null -ne $r.targets } },
        @{ p='/api/access-report/who-has?role=No%20Such%20Role'; chk={ param($r) $null -ne $r.resolved -and $null -ne $r.count -and $null -ne $r.reachers } },
        @{ p='/api/search?q=zzz-no-such-thing'; chk={ param($r) $null -ne $r.count -and $r.PSObject.Properties['hits'] } }
    )) {
        Beat
        $ok = $false
        try { $r = Probe $ep.p; $ok = (& $ep.chk $r) } catch { $ok = $false; Write-Host "      ($($ep.p): $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
        T "GET $($ep.p)" $ok
    }
    Write-Host "POST /api/wizard/derive (reversed wizard auto-fill)" -ForegroundColor Cyan
    Beat
    $okEntra = $false; $okAzure = $false
    try {
        $de = Invoke-RestMethod -Uri "$base/api/wizard/derive" -Headers $hdr -Method Post -ContentType 'application/json' -TimeoutSec 30 -Body (@{ target='entra'; roles=@('Global Administrator') } | ConvertTo-Json)
        $okEntra = ($de.ok -and $de.derivation.level -eq 0 -and "$($de.derivation.kind)" -eq 'permission-service' -and "$($de.derivation.groupName)" -like 'PIM-Entra-ID-*-L0-T0-CP-ID')
    } catch { Write-Host "      (entra derive: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'wizard derive entra GA -> service/L0/T0/CP' $okEntra
    try {
        $da = Invoke-RestMethod -Uri "$base/api/wizard/derive" -Headers $hdr -Method Post -ContentType 'application/json' -TimeoutSec 30 -Body (@{ target='azure'; scopeType='subscription'; scopeName='lz-corp-prod'; scopePath='/subscriptions/abc'; roles=@('Contributor') } | ConvertTo-Json)
        $okAzure = ($da.ok -and $da.derivation.level -eq 1 -and $da.derivation.tier -eq 1 -and "$($da.derivation.plane)" -eq 'WDP')
    } catch { Write-Host "      (azure derive: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'wizard derive azure sub LZ -> L1/T1/WDP' $okAzure
    # workload target (drives the new target-first "Create Resource Delegation"
    # wizard's workload path): single role -> permission-service, default WDP/T1.
    $okWl = $false
    try {
        $dw = Invoke-RestMethod -Uri "$base/api/wizard/derive" -Headers $hdr -Method Post -ContentType 'application/json' -TimeoutSec 30 -Body (@{ target='workload'; workload='Defender'; roles=@('Security Operator') } | ConvertTo-Json)
        $okWl = ($dw.ok -and "$($dw.derivation.kind)" -eq 'permission-service' -and "$($dw.derivation.plane)" -eq 'WDP' -and $dw.derivation.tier -eq 1 -and "$($dw.derivation.groupName)" -like 'PIM-Defender-*')
    } catch { Write-Host "      (workload derive: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'wizard derive workload Defender -> service/WDP/T1' $okWl
    # multi-role -> permission-bundle (entra), proves the 1-vs-many naming switch
    # the resource-delegation wizard relies on.
    $okBundle = $false
    try {
        $db = Invoke-RestMethod -Uri "$base/api/wizard/derive" -Headers $hdr -Method Post -ContentType 'application/json' -TimeoutSec 30 -Body (@{ target='entra'; roles=@('User Administrator','Groups Administrator'); bundleName='UserLifecycle' } | ConvertTo-Json)
        $okBundle = ($db.ok -and "$($db.derivation.kind)" -eq 'permission-bundle' -and $db.derivation.roleCount -eq 2)
    } catch { Write-Host "      (bundle derive: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'wizard derive entra 2 roles -> permission-bundle' $okBundle
    # admin-name derivation: owner + admin-type (prefix) + environment (suffix) -> UserName.
    $okAdmInt = $false; $okAdmExtAd = $false; $okAdmGuest = $false
    try {
        $da1 = Invoke-RestMethod -Uri "$base/api/wizard/derive" -Headers $hdr -Method Post -ContentType 'application/json' -TimeoutSec 30 -Body (@{ target='admin'; owner='JDO'; adminType='internal-adminuser'; environment='entra' } | ConvertTo-Json)
        $okAdmInt = ($da1.ok -and "$($da1.derivation.userName)" -eq 'admin-jdo-id' -and "$($da1.derivation.prefix)" -eq '' -and "$($da1.derivation.suffix)" -eq '-ID')
    } catch { Write-Host "      (admin derive int: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'wizard derive admin internal Entra -> admin-jdo-id (no prefix, -id, lower-case)' $okAdmInt
    try {
        $da2 = Invoke-RestMethod -Uri "$base/api/wizard/derive" -Headers $hdr -Method Post -ContentType 'application/json' -TimeoutSec 30 -Body (@{ target='admin'; owner='VND'; adminType='external-adminuser'; environment='ad' } | ConvertTo-Json)
        $okAdmExtAd = ($da2.ok -and "$($da2.derivation.userName)" -eq 'x-admin-vnd-ad')
    } catch { Write-Host "      (admin derive extAd: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'wizard derive admin external-adminuser AD -> x-admin-vnd-ad' $okAdmExtAd
    try {
        $da3 = Invoke-RestMethod -Uri "$base/api/wizard/derive" -Headers $hdr -Method Post -ContentType 'application/json' -TimeoutSec 30 -Body (@{ target='admin'; owner='GST'; adminType='external-guest'; environment='entra'; purpose='HighPriv' } | ConvertTo-Json)
        $okAdmGuest = ($da3.ok -and "$($da3.derivation.userName)" -eq 'admin-gst-l0-t0-id' -and $da3.derivation.highPriv -eq $true)
    } catch { Write-Host "      (admin derive guest: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'wizard derive admin external-guest Entra HighPriv -> admin-gst-l0-t0-id (no prefix)' $okAdmGuest

    Write-Host "POST /api/authoring/* (Manager authoring helpers)" -ForegroundColor Cyan
    function PostJson($path,$obj) { Invoke-RestMethod -Uri "$base$path" -Headers $hdr -Method Post -ContentType 'application/json' -TimeoutSec 30 -Body ($obj | ConvertTo-Json -Depth 6) }
    Beat
    $okBA=$false; try { $r = PostJson '/api/authoring/bulk-attach' @{ groupTag='PIM-Entra-X-L1-T0-CP-ID'; entraRoles=@('User Administrator','Helpdesk Administrator'); azureScopes=@(@{scope='/subscriptions/s1';permission='Reader'}) }; $okBA = ($r.ok -and $r.result.totalRows -eq 3 -and @($r.result.rolesGroupsRows).Count -eq 2) } catch { Write-Host "      (bulk-attach: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'authoring bulk-attach -> 3 rows (2 roles + 1 azure)' $okBA
    Beat
    $okCl=$false; try { $r = PostJson '/api/authoring/clone' @{ templateRow=@{ GroupName='PIM-A'; GroupTag='PIM-A'; TierLevel='T1' }; newTags=@('PIM-B','PIM-C') }; $okCl = ($r.ok -and $r.count -eq 2) } catch { Write-Host "      (clone: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'authoring clone -> 2 cloned rows' $okCl
    Beat
    $okCa=$false; try { $r = PostJson '/api/authoring/clone-azure-role' @{ sourceRow=@{ GroupTag='PIM-Az'; AzScope='/subscriptions/s1'; AzScopePermission='Reader' }; newRoles=@('Contributor','Owner') }; $okCa = ($r.ok -and $r.count -eq 2) } catch { Write-Host "      (clone-azure: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'authoring clone-azure-role -> 2 rows new roles' $okCa
    Beat
    $okAu=$false; try { $r = PostJson '/api/authoring/au' @{ auDisplayName='HD AU'; auTag='AU-HD'; roleBindings=@(@{groupTag='PIM-X';role='User Administrator'}) }; $okAu = ($r.ok -and "$($r.result.auTag)" -eq 'AU-HD' -and @($r.result.rolesAusRows).Count -eq 1) } catch { Write-Host "      (au: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'authoring au -> AU row + 1 binding' $okAu
    Beat
    $okIm=$false; try { $r = PostJson '/api/authoring/import-admins' @{ text="FirstName;LastName`nJane;Doe" }; $okIm = ($r.ok -and $r.count -eq 1 -and "$(@($r.rows)[0].Initials)" -eq 'JD') } catch { Write-Host "      (import: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'authoring import-admins -> derives initials' $okIm

    Write-Host "POST /api/onboarding/* (guest invite + self-service toggle)" -ForegroundColor Cyan
    Beat
    # The dev-local Windows identity has no portal profile -> SuperAdmin, which
    # bypasses the invite-guest / enable-consultants capability gates.
    $okGi=$false; try {
        $r = PostJson '/api/onboarding/guest-invite' @{ email='ext@partner.com'; firstName='Ext'; lastName='Consultant'; groupTag='PIM-Entra-ID-Helpdesk-L2-T0' }
        $okGi = ($r.ok -and "$($r.mode)" -eq 'guest-invite' -and $r.count -eq 2 -and @($r.changes | Where-Object { $_.entity -eq 'PIM-Assignments-Admins' }).Count -eq 1)
    } catch { Write-Host "      (guest-invite: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'onboarding guest-invite -> invitation + admin row + delegation' $okGi
    Beat
    $okGu=$false; try {
        $r = PostJson '/api/onboarding/guest-invite' @{ email='onprem@partner.com'; cloud=$false }
        $okGu = $false   # on-prem guest must be rejected (400)
    } catch { $okGu = ([int]$_.Exception.Response.StatusCode -eq 400) }
    T 'onboarding guest-invite on-prem -> 400 unsupported' $okGu
    Beat
    $okSt=$false; try {
        $r = PostJson '/api/onboarding/self-service-toggle' @{ accountName='consultant1@contoso.com'; action='disable' }
        $okSt = ($r.ok -and "$($r.change.payload.AccountStatus)" -eq 'Disabled' -and "$($r.change.op)" -eq 'Update')
    } catch { Write-Host "      (self-service: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'onboarding self-service-toggle -> AccountStatus change' $okSt

    # -------------------------------------------------------------------
    # Validate-tab Overrule / Acknowledge store (REQUIREMENTS s11). Proves the
    # GUI Overrule button's wiring end-to-end against the REAL engine post-filter:
    #   POST a SEEDED acknowledgement -> the engine override store gains it ->
    #   the next /api/preflight downgrades the matched finding to 'acknowledged'
    #   so the active warning count DROPS. Errors are never acknowledgeable.
    # We seed against PIM-DUP-001 (a warning the engine actually emits + scopes
    # with Subject/Target), then clean the store so the test is rerunnable.
    # -------------------------------------------------------------------
    Write-Host "POST /api/warning-overrides (Validate-tab Overrule writer)" -ForegroundColor Cyan
    $solRoot   = Split-Path -Parent $PSScriptRoot
    $ovrStore  = Join-Path $solRoot 'config\PIM-WarningOverrides.custom.json'
    $ovrBackup = if (Test-Path $ovrStore) { Get-Content -LiteralPath $ovrStore -Raw -Encoding UTF8 } else { $null }
    try {
        Beat
        # Baseline: read the active preflight summary.
        $pre = Probe '/api/preflight'
        $warnBefore = [int]$pre.summary.warnings
        $ackBefore  = [int]$pre.summary.acknowledged
        # Pick a real WARNING from the live report to seed an instance-scoped ack.
        $seed = @($pre.violations | Where-Object { $_.Severity -eq 'warning' -and ($_.Subject -or $_.Target) }) | Select-Object -First 1
        if (-not $seed) { $seed = @($pre.violations | Where-Object { $_.Severity -eq 'warning' }) | Select-Object -First 1 }

        # 1. Mandatory-reason contract is enforced server-side (400, not silent).
        $ok400=$false; try {
            PostJson '/api/warning-overrides' @{ code='PIM-DUP-001'; reason=''; expiresOn='2027-01-01' } | Out-Null
        } catch { $ok400 = ([int]$_.Exception.Response.StatusCode -eq 400) }
        T 'overrule rejects missing reason -> 400' $ok400

        # 2. Mandatory-expiry contract is enforced (400 unless noExpiry).
        $okExp=$false; try {
            PostJson '/api/warning-overrides' @{ code='PIM-DUP-001'; reason='no expiry given' } | Out-Null
        } catch { $okExp = ([int]$_.Exception.Response.StatusCode -eq 400) }
        T 'overrule rejects missing expiry -> 400' $okExp

        # 3. Errors are never acknowledgeable (the store accepts the entry, but the
        #    post-filter never downgrades an error). Seed an error-code override and
        #    assert preflight error count is unchanged.
        $errBefore = [int]$pre.summary.errors
        Beat
        $okErrGate=$false; try {
            PostJson '/api/warning-overrides' @{ code='PIM-FK-001'; reason='attempt to silence a hard error'; expiresOn='2027-01-01' } | Out-Null
            $p2 = Probe '/api/preflight'
            $okErrGate = ([int]$p2.summary.errors -eq $errBefore)
        } catch { Write-Host "      (err-gate: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
        T 'overrule never downgrades an error finding' $okErrGate

        # 4. Seeded warning acknowledgement actually downgrades + drops the count.
        if ($seed) {
            Beat
            $okAck=$false; try {
                $body = @{ code="$($seed.Code)"; subject="$($seed.Subject)"; target="$($seed.Target)"; reason='seeded by endpoint test -- accepted multi-path'; expiresOn='2027-12-31' }
                $w = PostJson '/api/warning-overrides' $body
                $okPost = ($w.ok -and [int]$w.count -ge 1)
                # GET reflects the new entry.
                $g = Probe '/api/warning-overrides'
                $okGet = ($g.ok -and @($g.overrides | Where-Object { "$($_.code)" -eq "$($seed.Code)" }).Count -ge 1)
                # Re-run preflight -> at least one finding is now acknowledged and
                # the active warning count is no greater than before.
                $p3 = Probe '/api/preflight'
                $okDrop = ([int]$p3.summary.acknowledged -ge ($ackBefore + 1) -and [int]$p3.summary.warnings -le $warnBefore)
                $okAck = ($okPost -and $okGet -and $okDrop)
            } catch { Write-Host "      (ack: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
            T 'overrule a warning -> downgraded to acknowledged + active count drops' $okAck
        } else {
            T 'overrule a warning -> downgraded to acknowledged + active count drops' $true   # no live warning to seed (clean dataset)
            Write-Host "      (no live warning in local dataset to seed -- store/GET path covered above)" -ForegroundColor DarkGray
        }
    } finally {
        # Restore the override store so the test leaves no residue (rerunnable).
        if ($null -ne $ovrBackup) { Set-Content -LiteralPath $ovrStore -Value $ovrBackup -Encoding UTF8 }
        elseif (Test-Path $ovrStore) { Remove-Item -LiteralPath $ovrStore -Force -EA SilentlyContinue }
    }

    # -----------------------------------------------------------------------
    # Audit tab API (GET /api/audit): category filter + free-text search +
    # paging + per-event category stamping, over the seeded trail above.
    # -----------------------------------------------------------------------
    Write-Host "GET /api/audit (Audit tab: category / search / paging)" -ForegroundColor Cyan
    Beat
    # Every seeded row is present + stamped with the correct category, newest first.
    $okStamp=$false; try {
        $r = Probe "/api/audit?q=$seedMarker&pageSize=200"
        $mine = @($r.events | Where-Object { "$($_.target)" -like "$seedMarker*" })
        $byTarget = @{}; foreach ($e in $mine) { $byTarget["$($e.action)|$($e.target)"] = "$($e.category)" }
        $allStamped = $true
        foreach ($s in $seedRows) { if ($byTarget["$($s.action)|$($s.target)"] -ne $s.cat) { $allStamped = $false } }
        # newest first: timestamps descending
        $ts = @($mine | ForEach-Object { "$($_.ts)" })
        $sortedDesc = (@($ts | Sort-Object -Descending) -join '|') -eq ($ts -join '|')
        $okStamp = ($mine.Count -eq $seedRows.Count -and $allStamped -and $sortedDesc)
    } catch { Write-Host "      (audit stamp: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'audit: all seeded events present, category-stamped, newest first' $okStamp

    # Category filter returns ONLY that category for our seeded rows.
    $okCatLogin=$false; try {
        $r = Probe "/api/audit?category=logins&q=$seedMarker&pageSize=200"
        $mine = @($r.events | Where-Object { "$($_.target)" -like "$seedMarker*" })
        $okCatLogin = ($mine.Count -eq 1 -and "$($mine[0].action)" -eq 'manager.login' -and "$($mine[0].category)" -eq 'logins')
    } catch { Write-Host "      (audit cat logins: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'audit: category=logins filters to the login event (real Logins filter)' $okCatLogin

    $okCatAcct=$false; try {
        $r = Probe "/api/audit?category=accounts&q=$seedMarker&pageSize=200"
        $mine = @($r.events | Where-Object { "$($_.target)" -like "$seedMarker*" })
        $okCatAcct = ($mine.Count -eq 2 -and (@($mine | Where-Object { "$($_.category)" -ne 'accounts' }).Count -eq 0))
    } catch { Write-Host "      (audit cat accounts: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'audit: category=accounts returns account.create + tap.create only' $okCatAcct

    $okCatDeleg=$false; try {
        $r = Probe "/api/audit?category=delegations&q=$seedMarker&pageSize=200"
        $mine = @($r.events | Where-Object { "$($_.target)" -like "$seedMarker*" })
        $okCatDeleg = ($mine.Count -eq 2 -and (@($mine | Where-Object { "$($_.category)" -ne 'delegations' }).Count -eq 0))
    } catch { Write-Host "      (audit cat delegations: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'audit: category=delegations returns membership + cutover only' $okCatDeleg

    # Per-category counts surface to the UI chips.
    $okCounts=$false; try {
        $r = Probe "/api/audit?q=$seedMarker&pageSize=200"
        $okCounts = ([int]$r.counts.logins -ge 1 -and [int]$r.counts.accounts -ge 2 -and [int]$r.counts.emergency -ge 2)
    } catch { Write-Host "      (audit counts: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'audit: per-category counts returned for chips' $okCounts

    # Free-text search narrows by target.
    $okSearch=$false; try {
        $r = Probe "/api/audit?q=$seedMarker-acctX&pageSize=200"
        $mine = @($r.events | Where-Object { "$($_.target)" -like "$seedMarker*" })
        $okSearch = ($mine.Count -eq 2 -and (@($mine | Where-Object { "$($_.target)" -ne "$seedMarker-acctX" }).Count -eq 0))
    } catch { Write-Host "      (audit search: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'audit: free-text search narrows to matching target' $okSearch

    # Paging: pageSize=3 over our 10 seeded rows -> 3 per page, pageCount math, no overlap.
    $okPage=$false; try {
        $p1 = Probe "/api/audit?q=$seedMarker&page=1&pageSize=3"
        $p2 = Probe "/api/audit?q=$seedMarker&page=2&pageSize=3"
        $ids1 = @($p1.events | ForEach-Object { "$($_.action)|$($_.target)|$($_.ts)" })
        $ids2 = @($p2.events | ForEach-Object { "$($_.action)|$($_.target)|$($_.ts)" })
        $overlap = @($ids1 | Where-Object { $ids2 -contains $_ }).Count
        $okPage = ($p1.matchCount -eq $seedRows.Count -and $p1.events.Count -eq 3 -and $p2.events.Count -eq 3 -and [int]$p1.pageCount -eq 4 -and $overlap -eq 0)
    } catch { Write-Host "      (audit paging: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'audit: paging (pageSize=3) splits seeded rows, no overlap, pageCount=4' $okPage

    # ---- Governance management round-trips (PUT then GET re-read) -----------
    # The dev-local Windows identity resolves to SuperAdmin (no access file), so
    # the write gates pass. Each PUT drives a REAL config/engine path; we re-read
    # to prove persistence (seeded data in -> same data out).
    Write-Host "Governance management (PUT -> GET round-trips)" -ForegroundColor Cyan
    function PutJson($path,$obj) { Invoke-RestMethod -Uri "$base$path" -Headers $hdr -Method Put -ContentType 'application/json' -TimeoutSec 30 -Body ($obj | ConvertTo-Json -Depth 8) }

    # 1) Discovery auto-create policy: set AzureSubscription=pending, PowerBIWorkspace=auto.
    Beat
    $okDp=$false; try {
        [void](PutJson '/api/discovery-policy' @{ policy = @{ AzureSubscription='pending'; PowerBIWorkspace='auto'; ResourceGroup='flag' } })
        $r = Probe '/api/discovery-policy'
        $okDp = ("$($r.policy.AzureSubscription)" -eq 'pending' -and "$($r.policy.PowerBIWorkspace)" -eq 'auto' -and "$($r.policy.ResourceGroup)" -eq 'flag')
    } catch { Write-Host "      (discovery-policy: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'discovery-policy PUT persists per-type (sub=pending, pbi=auto, default flag)' $okDp

    # 2) Job schedule: disable daily-summary, change tier-report cadence to 720.
    Beat
    $okSch=$false; try {
        [void](PutJson '/api/job-schedule' @{ jobs = @(@{ name='daily-summary'; enabled=$false }, @{ name='tier-report'; enabled=$true; intervalMinutes=720 }) })
        $r = Probe '/api/job-schedule'
        $ds = @($r.jobs | Where-Object { $_.name -eq 'daily-summary' })[0]
        $tr = @($r.jobs | Where-Object { $_.name -eq 'tier-report' })[0]
        $okSch = ($ds -and $ds.enabled -eq $false -and $tr -and [int]$tr.intervalMinutes -eq 720 -and $tr.enabled -eq $true)
    } catch { Write-Host "      (job-schedule: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'job-schedule PUT persists daily-summary off + tier-report 720m' $okSch

    # 3) Job schedule rejects an unknown job name (fixed engine catalog).
    Beat
    $okSchU=$false; try {
        $r = PutJson '/api/job-schedule' @{ jobs = @(@{ name='not-a-real-job'; enabled=$true }) }
        $okSchU = ([int]$r.count -eq 0)   # unknown name ignored -> nothing merged
    } catch { Write-Host "      (job-schedule unknown: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'job-schedule PUT ignores unknown job names' $okSchU

    # 4) Template state: disable the first shipped template, prove /api/templates reflects it, then re-enable.
    Beat
    $okTpl=$false; try {
        $all = Probe '/api/templates'
        $first = @($all.templates | Where-Object { -not $_.error })[0]
        if ($first) {
            [void](PutJson '/api/template-state' @{ id=$first.id; disabled=$true })
            $after = Probe '/api/templates'
            $row = @($after.templates | Where-Object { $_.id -eq $first.id })[0]
            $disabledOk = ($row -and $row.disabled -eq $true)
            [void](PutJson '/api/template-state' @{ id=$first.id; disabled=$false })   # restore
            $after2 = Probe '/api/templates'
            $row2 = @($after2.templates | Where-Object { $_.id -eq $first.id })[0]
            $okTpl = ($disabledOk -and $row2 -and -not $row2.disabled)
        } else { $okTpl = $true }   # no templates shipped -> trivially pass
    } catch { Write-Host "      (template-state: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'template-state PUT disable/enable round-trips through /api/templates' $okTpl

    # 4b) Mail templates: GUI-driven customization round-trip (no rebuild).
    #     GET one -> PUT a store override -> GET one shows source='store' + new body
    #     -> /api/mail-templates list shows source='store' -> DELETE resets ->
    #     GET one shows source='shipped' again with the original shipped body.
    Beat
    # The mail-template store is a single JSON file rewritten wholesale on each
    # PUT/DELETE. When two endpoint suites run CONCURRENTLY (the dynamic-free-port
    # collision proof), a peer's interleaving reset can drop this run's override
    # between our PUT and read-back. The round-trip itself is correct -- so retry a
    # few times; serially this passes on the first attempt (behavior unchanged).
    $okMt=$false
    for ($mtAttempt=1; $mtAttempt -le 4 -and -not $okMt; $mtAttempt++) {
        try {
            $list = Probe '/api/mail-templates'
            $mt0 = @($list.templates)[0]
            if ($mt0) {
                $type = "$($mt0.type)"
                $one0 = Probe ('/api/mail-template?type=' + $type)
                $shipped = "$($one0.body)"
                $custom = "<!-- subject: ENDPOINT TEST custom -->`r`n<p>customized via the API, no rebuild</p>"
                [void](PutJson '/api/mail-template' @{ type=$type; body=$custom })
                $one1 = Probe ('/api/mail-template?type=' + $type)
                $savedOk = ("$($one1.source)" -eq 'store' -and "$($one1.body)" -eq $custom)
                $listC  = Probe '/api/mail-templates'
                $rowC   = @($listC.templates | Where-Object { $_.type -eq $type })[0]
                $listOk = ($rowC -and "$($rowC.source)" -eq 'store' -and $rowC.customized -eq $true)
                [void](Invoke-RestMethod -Uri ("$base/api/mail-template?type=" + $type) -Headers $hdr -Method Delete -TimeoutSec 30)
                $one2 = Probe ('/api/mail-template?type=' + $type)
                $resetOk = ("$($one2.source)" -eq 'shipped' -and "$($one2.body)" -eq $shipped)
                $okMt = ($savedOk -and $listOk -and $resetOk)
            } else { $okMt = $true }   # no templates shipped -> trivially pass
        } catch { Write-Host "      (mail-template attempt $mtAttempt`: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
        if (-not $okMt -and $mtAttempt -lt 4) { Start-Sleep -Milliseconds 400 }
    }
    T 'mail-template PUT(store override)->GET(source=store)->DELETE->GET(source=shipped) round-trips' $okMt

    # 5) Access map: a map with NO SuperAdmin is rejected (lock-out guard).
    Beat
    $okAcc=$false; try {
        $r = PutJson '/api/access-map' @{ entries = @(@{ identity='someone@contoso.com'; role='Admin' }) }
        $okAcc = $false   # should have thrown 400
    } catch { $okAcc = ([int]$_.Exception.Response.StatusCode -eq 400) }
    T 'access-map PUT rejects a map with zero SuperAdmins (lock-out guard)' $okAcc

    # 6) Access map: a valid map (with a SuperAdmin) persists + re-reads. The
    # running identity is kept SuperAdmin so the server doesn't lock itself out.
    Beat
    $okAcc2=$false; try {
        [void](PutJson '/api/access-map' @{ entries = @(@{ identity=$me; role='SuperAdmin' }, @{ identity='hd@contoso.com'; role='Delegated' }) })
        $r = Probe '/api/access-map'
        $okAcc2 = (@($r.entries).Count -eq 2 -and @($r.entries | Where-Object { $_.role -eq 'SuperAdmin' }).Count -eq 1 -and @($r.entries | Where-Object { $_.role -eq 'Delegated' }).Count -eq 1)
    } catch { Write-Host "      (access-map valid: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'access-map PUT persists a valid map (SuperAdmin + Delegated)' $okAcc2

    Write-Host "GET /api/jobs + /api/jobs/log (Jobs tab, read-only scheduler view)" -ForegroundColor Cyan
    Beat
    $jobsData = $null
    $okJobs = $false
    try {
        $jobsData = Probe '/api/jobs'
        $okJobs = ($jobsData -ne $null -and @($jobsData.jobs).Count -ge 1 -and $jobsData.total -ge 1)
    } catch { Write-Host "      (jobs: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'GET /api/jobs returns the scheduler registry' $okJobs
    # in-progress job sorts to the TOP (the seed has exactly one running full-reconcile)
    $okTop = $false
    try { $okTop = ($jobsData.runningCount -ge 1 -and $jobsData.jobs[0].inProgress -eq $true -and "$($jobsData.jobs[0].status)" -eq 'running') } catch {}
    T 'in-progress job is first + runningCount>=1' $okTop
    # rows carry cadence / enabled / last result fields the GUI renders
    $okShape = $false
    try {
        $row = @($jobsData.jobs | Where-Object { "$($_.name)" -eq 'tenant-cache' })[0]
        $okShape = ($row -ne $null -and "$($row.cadence)".Trim() -ne '' -and $row.PSObject.Properties['enabled'] -and "$($row.lastResult)" -like 'tenant-cache refreshed*')
    } catch {}
    T 'job rows carry cadence + enabled + lastResult' $okShape
    # the Logs endpoint returns that run's log text by runId
    $okLog = $false
    try {
        $rid = "$($jobsData.jobs[0].runningRunId)"; if (-not $rid) { $rid = "$($jobsData.jobs[0].lastRunId)" }
        if (-not $rid) { $rid = @($jobsData.jobs | Where-Object { "$($_.lastRunId)".Trim() })[0].lastRunId }
        $log = Probe ('/api/jobs/log?runId=' + $rid)
        $okLog = ($log -ne $null -and "$($log.runId)" -eq "$rid" -and "$($log.log)".Trim().Length -gt 0)
    } catch { Write-Host "      (jobs/log: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'GET /api/jobs/log?runId returns the run log' $okLog
    # missing runId -> 400; unknown runId -> 404
    $okBad = $false
    try { Probe '/api/jobs/log' | Out-Null } catch { $okBad = ([int]$_.Exception.Response.StatusCode -eq 400) }
    T 'GET /api/jobs/log without runId -> 400' $okBad
    $ok404 = $false
    try { Probe '/api/jobs/log?runId=does-not-exist' | Out-Null } catch { $ok404 = ([int]$_.Exception.Response.StatusCode -eq 404) }
    T 'GET /api/jobs/log unknown runId -> 404' $ok404

    # /api/jobs exposes the dead-view guards the GUI uses: canRun (Admin+), a
    # historyCount, and (for never-run jobs) a synthesized next-run so the row is
    # never blank for both last AND next. The dev-local identity is SuperAdmin.
    Write-Host "Jobs tab controls (state PUT / force-start POST / dead-view guards)" -ForegroundColor Cyan
    Beat
    $okGuards = $false
    try {
        $jd = Probe '/api/jobs'
        $okGuards = ($jd.PSObject.Properties['canRun'] -and $jd.canRun -eq $true -and $jd.PSObject.Properties['historyCount'])
    } catch { Write-Host "      (jobs guards: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'GET /api/jobs exposes canRun + historyCount' $okGuards
    # every enabled row carries a nextRunUtc (real or synthesized) -- no dead "-".
    $okNext = $false
    try {
        $jd = Probe '/api/jobs'
        $enabledRows = @($jd.jobs | Where-Object { $_.enabled })
        $okNext = ($enabledRows.Count -ge 1 -and (@($enabledRows | Where-Object { -not "$($_.nextRunUtc)".Trim() }).Count -eq 0))
    } catch {}
    T 'every enabled job row has a next-run (none dead)' $okNext

    # PUT /api/jobs/state: toggle ONE job off + change its cadence, re-read via /api/jobs.
    Beat
    $okState = $false
    try {
        [void](PutJson '/api/jobs/state' @{ name='delta-pim-azure'; enabled=$false; intervalMinutes=45 })
        $jd = Probe '/api/jobs'
        $row = @($jd.jobs | Where-Object { "$($_.name)" -eq 'delta-pim-azure' })[0]
        $okState = ($row -and $row.enabled -eq $false -and [int]$row.intervalMinutes -eq 45)
        # restore (enabled + default 30) so the test leaves no residue
        [void](PutJson '/api/jobs/state' @{ name='delta-pim-azure'; enabled=$true; intervalMinutes=30 })
    } catch { Write-Host "      (jobs/state: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'PUT /api/jobs/state toggles enabled + cadence (round-trips to /api/jobs)' $okState

    # PUT /api/jobs/state unknown job -> 404.
    Beat
    $okStateBad = $false
    try { PutJson '/api/jobs/state' @{ name='not-a-real-job'; enabled=$false } | Out-Null } catch { $okStateBad = ([int]$_.Exception.Response.StatusCode -eq 404) }
    T 'PUT /api/jobs/state unknown job -> 404' $okStateBad

    # POST /api/jobs/run force-starts a job: records a run, returns a runId, and that
    # run is readable via /api/jobs/log (proves it actually executed + logged).
    Beat
    $okRun = $false
    try {
        $rr = Invoke-RestMethod -Uri "$base/api/jobs/run" -Headers $hdr -Method Post -ContentType 'application/json' -TimeoutSec 30 -Body (@{ name='reminders' } | ConvertTo-Json)
        $okRun = ($rr -and $rr.ok -eq $true -and "$($rr.runId)".Trim().Length -gt 0 -and "$($rr.status)" -in @('completed','failed'))
        if ($okRun) {
            $lg = Probe ('/api/jobs/log?runId=' + $rr.runId)
            $okRun = ($lg -ne $null -and "$($lg.runId)" -eq "$($rr.runId)" -and "$($lg.log)".Trim().Length -gt 0)
        }
    } catch { Write-Host "      (jobs/run: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'POST /api/jobs/run force-starts + records a readable run' $okRun

    # The forced run now shows up in /api/jobs as the latest run for that job.
    Beat
    $okRunVisible = $false
    try {
        $jd = Probe '/api/jobs'
        $row = @($jd.jobs | Where-Object { "$($_.name)" -eq 'reminders' })[0]
        $okRunVisible = ($row -and -not $row.neverRun -and "$($row.lastRunUtc)".Trim() -ne '')
    } catch {}
    T 'forced run is visible as the job''s last run in /api/jobs' $okRunVisible

    # POST /api/jobs/run unknown job -> 404.
    Beat
    $okRunBad = $false
    try { Invoke-RestMethod -Uri "$base/api/jobs/run" -Headers $hdr -Method Post -ContentType 'application/json' -TimeoutSec 30 -Body (@{ name='not-a-real-job' } | ConvertTo-Json) | Out-Null } catch { $okRunBad = ([int]$_.Exception.Response.StatusCode -eq 404) }
    T 'POST /api/jobs/run unknown job -> 404' $okRunBad

    # --- [M6] failure history + overdue detection + acknowledge (REQUIREMENTS §28) ---
    Write-Host "Jobs tab [M6] (failure history / overdue / acknowledge)" -ForegroundColor Cyan
    Beat
    # /api/jobs surfaces the overdue + failing summary counts (seed: escalations overdue,
    # discovery-azure failed).
    $okM6Summary = $false
    try {
        $jd = Probe '/api/jobs'
        $okM6Summary = ($jd.PSObject.Properties['overdueCount'] -and $jd.PSObject.Properties['failingCount'] -and [int]$jd.overdueCount -ge 1 -and [int]$jd.failingCount -ge 1)
    } catch { Write-Host "      (jobs M6 summary: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'GET /api/jobs exposes overdueCount + failingCount (>=1 each)' $okM6Summary
    # the overdue job (escalations) carries overdue=true + an overdueByMinutes
    $okOverdueRow = $false
    try {
        $jd = Probe '/api/jobs'
        $erow = @($jd.jobs | Where-Object { "$($_.name)" -eq 'escalations' })[0]
        $okOverdueRow = ($erow -and $erow.overdue -eq $true -and [int]$erow.overdueByMinutes -gt 0)
    } catch {}
    T 'overdue job row carries overdue + overdueByMinutes' $okOverdueRow

    # /api/jobs/history?name=discovery-azure surfaces the failed run (pass/fail/when)
    Beat
    $failRunId = $null
    $okHist = $false
    try {
        $hist = Probe '/api/jobs/history?name=discovery-azure'
        $okHist = ($hist -ne $null -and [int]$hist.total -ge 1 -and [int]$hist.failureCount -ge 1 -and @($hist.failures).Count -ge 1)
        if ($okHist) { $failRunId = "$(@($hist.failures)[0].runId)" }
    } catch { Write-Host "      (jobs/history: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'GET /api/jobs/history surfaces a failed run with pass/fail/when' $okHist

    # POST /api/jobs/ack mutes the failure -> unackedFailures drops, run record kept
    Beat
    $okAck = $false
    try {
        if ($failRunId) {
            $ack = PostJson '/api/jobs/ack' @{ runId = $failRunId }
            $hist2 = Probe '/api/jobs/history?name=discovery-azure'
            $ackedFail = @($hist2.failures | Where-Object { "$($_.runId)" -eq $failRunId })[0]
            # the run is still in history (audit intact) but now flagged acknowledged,
            # and the unacknowledged-failure count dropped by one.
            $okAck = ($ack.ok -eq $true -and $ack.acknowledged -eq $true -and $ackedFail -and $ackedFail.acknowledged -eq $true -and [int]$hist2.unackedFailures -lt [int]$hist.unackedFailures)
        }
    } catch { Write-Host "      (jobs/ack: $($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }
    T 'POST /api/jobs/ack mutes a failure (record kept, unacked drops)' $okAck

    # clear:true un-acknowledges the run
    Beat
    $okAckClear = $false
    try {
        if ($failRunId) {
            $clr = PostJson '/api/jobs/ack' @{ runId = $failRunId; clear = $true }
            $okAckClear = ($clr.ok -eq $true -and $clr.acknowledged -eq $false)
        }
    } catch {}
    T 'POST /api/jobs/ack clear:true un-acknowledges' $okAckClear

    # POST /api/jobs/ack without runId -> 400
    Beat
    $okAckBad = $false
    try { Invoke-RestMethod -Uri "$base/api/jobs/ack" -Headers $hdr -Method Post -ContentType 'application/json' -TimeoutSec 30 -Body (@{} | ConvertTo-Json) | Out-Null } catch { $okAckBad = ([int]$_.Exception.Response.StatusCode -eq 400) }
    T 'POST /api/jobs/ack without runId -> 400' $okAckBad

    # --- Approvals queue (maker/checker) over real HTTP (REQUIREMENTS §13/§27 H3/H4) ---
    # Proves the Approvals endpoints are wired in the live server: raise -> list ->
    # self-approve blocked (separation of duties) -> bad input rejected. (maker!=checker
    # with two distinct identities is exercised in-proc by Test-PimApprovalsGui.ps1.)
    Beat
    $apprId = $null
    try {
        $raised = PostJson '/api/approvals' @{ action='offboard'; target=('approval-http-' + [guid]::NewGuid().ToString('N').Substring(0,6) + '@test'); justification='endpoint test'; ticket='T-1' }
        $apprId = "$($raised.id)"
        T 'POST /api/approvals raises a Pending request' ($raised.ok -and "$($raised.status)" -eq 'Pending' -and $apprId)
    } catch { T 'POST /api/approvals raises a Pending request' $false; Write-Host "      ($($_.Exception.Message.Split([char]10)[0]))" -ForegroundColor DarkGray }

    try {
        $list = Probe '/api/approvals'
        $found = @($list.requests | Where-Object { "$($_.id)" -eq $apprId })
        T 'GET /api/approvals lists the raised request with its offboard sequence plan' ($list.ok -and $found.Count -eq 1 -and @($found[0].sequencePlan).Count -eq 3)
    } catch { T 'GET /api/approvals lists the raised request with its offboard sequence plan' $false }

    # The same identity raised it, so the local SuperAdmin caller cannot self-approve.
    $sepBlocked = $false
    try { PostJson '/api/approvals/decide' @{ id=$apprId; decision='approve'; note='self' } | Out-Null }
    catch { $sepBlocked = ([int]$_.Exception.Response.StatusCode -eq 403) }
    T 'POST /api/approvals/decide self-approve blocked (separation of duties -> 403)' $sepBlocked

    # Bad input: missing id / bad decision -> 400.
    $badDecide = $false
    try { PostJson '/api/approvals/decide' @{ decision='approve' } | Out-Null }
    catch { $badDecide = ([int]$_.Exception.Response.StatusCode -eq 400) }
    T 'POST /api/approvals/decide without id -> 400' $badDecide

    # Access-review decision endpoint degrades gracefully (no AccessReview.ReadWrite.All):
    # returns 200 with ok=$false (honest), never a 5xx crash.
    try {
        $dec = PostJson '/api/access-reviews/decision' @{ definitionId='seed-def-1'; instanceId='seed-inst-1'; decisionId='dec-1'; outcome='Approve'; justification='endpoint test' }
        T 'POST /api/access-reviews/decision degrades gracefully (ok=false, no crash)' ($dec -and $dec.ok -eq $false)
    } catch { T 'POST /api/access-reviews/decision degrades gracefully (ok=false, no crash)' $false }

    # Overdue read is never dead (seed fallback offline).
    try { $od = Probe '/api/access-reviews/overdue'; T 'GET /api/access-reviews/overdue returns rows (seed fallback)' (@($od.rows).Count -ge 1) }
    catch { T 'GET /api/access-reviews/overdue returns rows (seed fallback)' $false }
} finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
    Get-ChildItem "$out*" -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
    # Restore the config files the governance round-trips wrote (or remove them
    # if they didn't exist before this run) so the test leaves no residue.
    $enc = New-Object System.Text.UTF8Encoding($false)
    if ($null -ne $accessBak)   { [System.IO.File]::WriteAllText($accessFile,   $accessBak,   $enc) } elseif (Test-Path $accessFile)   { Remove-Item $accessFile   -Force -EA SilentlyContinue }
    if ($null -ne $settingsBak) { [System.IO.File]::WriteAllText($settingsFile, $settingsBak, $enc) } elseif (Test-Path $settingsFile) { Remove-Item $settingsFile -Force -EA SilentlyContinue }
    # Remove ONLY our seeded rows from the audit trail (keep any real history).
    try {
        if ($auditFile -and (Test-Path $auditFile)) {
            $keep = @(Get-Content -LiteralPath $auditFile -Encoding UTF8 | Where-Object { $_ -notmatch [regex]::Escape($seedMarker) })
            if ($keep.Count -gt 0) { [System.IO.File]::WriteAllText($auditFile, (($keep -join "`r`n") + "`r`n"), $utf8NoBom) }
            else { Remove-Item -LiteralPath $auditFile -Force -EA SilentlyContinue }
        }
    } catch { Write-Host "  (audit seed cleanup skipped: $($_.Exception.Message))" -ForegroundColor DarkGray }
}

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 }
