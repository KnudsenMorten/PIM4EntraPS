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
param([int]$Port = 8799)

$ErrorActionPreference = 'Stop'
$pass=0; $fail=0
function T($n,$c){ if($c){Write-Host "  PASS $n" -ForegroundColor Green;$script:pass++}else{Write-Host "  FAIL $n" -ForegroundColor Red;$script:fail++} }

$mgr = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\pim-manager\Open-PimManager.ps1'
$out = Join-Path $env:TEMP "pim-mgr-test-$Port.out"
if (Test-Path $out) { Remove-Item $out -Force }
Write-Host "Booting Manager headless on port $Port ..."
$proc = Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$mgr`"",'-Server','-NoLaunch','-Port',"$Port") -RedirectStandardOutput $out -RedirectStandardError "$out.err" -PassThru -WindowStyle Hidden

try {
    # wait for the token to appear in stdout
    $token = $null
    for ($i=0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 750
        if (Test-Path $out) {
            $m = Select-String -Path $out -Pattern 'session token:\s*([0-9a-fA-F\-]{16,})' -EA SilentlyContinue | Select-Object -First 1
            if ($m) { $token = $m.Matches[0].Groups[1].Value; break }
        }
        if ($proc.HasExited) { break }
    }
    T 'Manager booted + emitted session token' ([bool]$token)
    if (-not $token) { Get-Content $out,"$out.err" -EA SilentlyContinue | Select-Object -Last 15 | ForEach-Object { Write-Host "    $_" }; throw 'no token' }

    $base = "http://127.0.0.1:$Port"
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
        @{ p='/api/resolve-date?expr=Now'; chk={ param($r) $r -ne $null } },
        @{ p='/api/instances';           chk={ param($r) $r -ne $null } },
        @{ p='/api/preflight';           chk={ param($r) $r -ne $null } },
        @{ p='/api/conformance/templates'; chk={ param($r) $r.templates -ne $null } },
        @{ p='/api/conformance?template=defender-xdr-roles'; chk={ param($r) @($r.keys).Count -ge 1 -and $r.statuses -ne $null } },
        @{ p='/api/portal-access'; chk={ param($r) "$($r.managerRole)" -ne '' -and $null -ne $r.isSuperAdmin } }
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
} finally {
    if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
    Get-ChildItem "$out*" -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
}

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 }
