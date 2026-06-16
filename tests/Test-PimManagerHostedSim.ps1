#Requires -Version 5.1
<#
.SYNOPSIS
    HOSTED-MODE SIMULATION unit tests for the PIM Manager (offline, no tenant).

.DESCRIPTION
    Closes the test-coverage gap that let the hosted+SQL Manager ship "green" while
    its runtime was broken. The offline regression suite passed because NOTHING
    exercised hosted (PIM_HOSTED=1) + SQL-backend startup. These tests set the hosted
    + SQL signals WITHOUT a live tenant and assert the CORRECT hosted behavior -- the
    behavior the product fixes must produce:

      1. Startup resolves the SQL instance (sql:<db>) as the DEFAULT, NOT 'local'.
      2. The engine-SPN connect CONTEXT is resolved for the SQL instance (tenant/appId
         present on the instance -> Set-PimManagerInstance points the engine globals at
         it, so the tenant-connect block can run -- no '-ConnectPlatform' required).
      3. The '/' render path picks SQL render mode ('SQL: <db>'), NOT the
         static (read-only) viewer.
      4. The /api/active-assignments handler does NOT hard-require -ConnectPlatform
         (it resolves the connection lazily) and returns a server error (500) only on
         a genuine downstream failure, never 'static (read-only)'.
      5. The store backend selected under hosted is SQL-only (no CSV/static fallback).

    Two evidence layers:
      * SOURCE-CONTRACT assertions (always run, no SQL, no tenant) -- prove the code
        paths that MUST exist for the fixes (hosted forces SQL-required; render mode
        derives from PimStorageMode; the SQL instance is named 'sql:<db>'; the
        active-assignments handler has no -ConnectPlatform gate).
      * LIVE-BOOT assertions (skip cleanly if no SQL reachable) -- actually boot
        Open-PimManager.ps1 with PIM_HOSTED=1 + a throwaway local SQL DB and the SQL
        instance declared in instances.custom.json, then assert the boot log shows
        '[store] SQL mode', the active instance is the sql:<db> one (not 'local'),
        and the '/' page renders __PIM_MODE__ = 'SQL: <db>' (not static).

    THIS IS A TEST. It does not edit product code. Until the product fixes deploy in
    this worktree base, the live-boot block is the expected-after-fix gate: it will
    SKIP if no SQL is reachable, and FAIL (correctly) if a reachable SQL boot still
    defaults to 'local' / static / CSV -- which is exactly the regression we are
    encoding against.

        powershell -NoProfile -File .\tests\Test-PimManagerHostedSim.ps1 [-Server .\SQLEXPRESS]
    (The Manager binds a free loopback port at runtime -- no fixed port to collide on.)
#>
[CmdletBinding()] param([string]$Server = '.\SQLEXPRESS', [int]$Port = 0)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot '_shared\PimManagerBoot.ps1')   # -Port 0 => helper allocates a free port (no fixed-port collision)
$mgr  = Join-Path $root 'tools\pim-manager\Open-PimManager.ps1'

$pass=0; $fail=0; $skip=0
function T($n,$c){ if($c){Write-Host "  PASS $n" -ForegroundColor Green;$script:pass++}else{Write-Host "  FAIL $n" -ForegroundColor Red;$script:fail++} }
function S($n,$why){ Write-Host "  SKIP $n -- $why" -ForegroundColor Yellow; $script:skip++ }

Write-Host "=== PIM Manager HOSTED-MODE simulation (offline) ===" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Layer 1 -- SOURCE CONTRACT (always runs; no SQL, no tenant)
# These assert the code paths that the hosted fixes depend on. If a future
# refactor removes one, the hosted runtime silently regresses -- so guard them.
# ---------------------------------------------------------------------------
Write-Host "`n-- source contract --" -ForegroundColor Cyan
$src = [System.IO.File]::ReadAllText($mgr)

# (a) Hosted is always SQL-required: the store block must treat $script:PimHosted as a
#     trigger for the SQL-only path (no CSV fallback when hosted).
T 'hosted forces SQL-required store path (no CSV fallback)' `
    ($src -match '\$sqlRequired\s*=\s*\([^\r\n]*\$script:PimHosted')

# (b) PIM_HOSTED env (and -Hosted) sets $script:PimHosted.
T 'PIM_HOSTED / -Hosted sets $script:PimHosted' `
    ($src -match '\$script:PimHosted\s*=\s*\[bool\]\$Hosted[^\r\n]*PIM_HOSTED')

# (c) The SQL backend, once chosen, must set storage mode = 'sql' (drives render mode).
T 'SQL path sets $script:PimStorageMode = ''sql''' `
    ($src -match "PimStorageMode\s*=\s*'sql'")

# (d) The '/' render path derives the page mode label from PimStorageMode -> 'SQL: <db>'
#     (NOT a fixed 'static (read-only)').
T '/ render mode label derives from SQL storage mode' `
    ($src -match "modeLabel\s*=\s*if\s*\(\s*\`$script:PimStorageMode\s*-eq\s*'sql'\s*\)\s*\{\s*`"SQL:")

# (e) The SQL instance is enumerated as 'sql:<db>' so a hosted default can target it.
T 'SQL database surfaces as a selectable instance named sql:<db>' `
    ($src -match 'name\s*=\s*"sql:\$db"')

# (f) active-assignments handler resolves the connection lazily; it must NOT gate on
#     $ConnectPlatform. (Encodes: hosted GET /api/active-assignments works without
#     launching with -ConnectPlatform.)
$aaBlock = ''
$mAA = [regex]::Match($src, "/api/active-assignments\*'[\s\S]{0,800}")
if ($mAA.Success) { $aaBlock = $mAA.Value }
T 'active-assignments handler exists' ([bool]$aaBlock)
T 'active-assignments handler does NOT require -ConnectPlatform' `
    ($aaBlock -and ($aaBlock -notmatch 'ConnectPlatform') -and ($aaBlock -match 'Get-PimActiveAssignmentsCached'))

# (g) Lazy tenant connect lives in Get-PimActiveAssignmentsCached (calls
#     Initialize-PimManagerTenantConnection itself) -- so the handler never has to.
T 'active-assignments resolves the tenant connection lazily (no handler gate)' `
    ($src -match 'function Get-PimActiveAssignmentsCached[\s\S]{0,1400}Initialize-PimManagerTenantConnection')

# (h) The engine-SPN connect block runs when the instance carries tenantId (+appId/cert);
#     i.e. the SQL instance MUST be able to carry connection identity. This is the
#     hosted symptom "SQL instance config lacked tenant/appId/cert so the connect block
#     was skipped" -- the connect block is keyed on $inst.tenantId.
T 'engine-SPN connect block keyed on instance tenantId/appId/cert' `
    ($src -match 'if\s*\(\$inst\.tenantId\)[\s\S]{0,400}HighPriv_Modern_ApplicationID_Azure')

# (i) The tenant-connection assertion produces the exact "engine SPN context" error we
#     hit -- proving the missing-context detection exists (the fix makes hosted supply it).
$ts = [System.IO.File]::ReadAllText((Join-Path $root 'tools\pim-manager\_tenantSync.ps1'))
T 'tenant-context assertion emits the "engine SPN context" diagnostic' `
    ($ts -match 'engine SPN context')

# (j) ACTIVE-ASSIGNMENTS ERROR SURFACING (the v2.4.219 bug):
#     when every surface fetch FAILS (auth/missing app-role/no Azure scope) the
#     fetcher must NOT silently return ok=$true,total=0 (which rendered as the
#     misleading "Cache may be empty -- click Refresh"). It must collect per-surface
#     errors and report ok=$false + an actionable error. Guard each piece.
T 'active-assignments builds a per-surface error ledger ($surfaceErrors)' `
    ($src -match 'function Get-PimActiveAssignmentsCached[\s\S]{0,3000}\$surfaceErrors\s*=\s*New-Object')
T 'entra-role fetch failure is recorded, not swallowed' `
    ($src -match "entra-role assignment-schedules load failed[\s\S]{0,260}surface\s*=\s*'entra-role'")
T 'azure-rbac fetch/scope failure is recorded as a surface error' `
    ($src -match "surface\s*=\s*'azure-rbac'")
T 'pim-for-groups all-failed read is recorded as a surface error' `
    ($src -match "surface\s*=\s*'pim-for-groups'")
T 'payload reports ok=$false when nothing read AND a surface errored' `
    ($src -match '\$allFailedEmpty\s*=\s*\(\$rows\.Count\s*-eq\s*0\s*-and\s*\$errArr\.Count\s*-gt\s*0\)')
T 'payload carries surfaceErrors + an actionable top-level error' `
    (($src -match 'surfaceErrors\s*=\s*\$errArr') -and ($src -match '\$payload\.error\s*=\s*"Active PIM assignments could not be read'))
T 'cache-hit path also propagates surfaceErrors / ok' `
    (($src -match '\$cachedErrs\s*=\s*@\(\$script:PimActiveAssignmentsCache\.surfaceErrors\)') -and ($src -match 'surfaceErrors\s*=\s*\$cachedErrs'))

# (k) The surface-hint helper maps a 403/auth failure to the exact remediation
#     (Graph app-role + setup/Grant-PimGraphAppRoles.ps1 for Graph surfaces;
#     Reader for Azure RBAC). Test it IN-PROC by extracting the function body.
$hintFn = [regex]::Match($src, 'function Get-PimActiveAssignmentSurfaceHint[\s\S]*?\n\}\r?\n')
T 'Get-PimActiveAssignmentSurfaceHint function is present' ($hintFn.Success)
if ($hintFn.Success) {
    Invoke-Expression $hintFn.Value
    $hEntra = Get-PimActiveAssignmentSurfaceHint -Surface 'entra-role' -ErrorMessage 'GET ... -> HTTP 403 : Authorization_RequestDenied'
    T 'entra-role 403 hint names RoleManagement.Read.Directory + the grant script' `
        ($hEntra -match 'RoleManagement\.Read\.Directory' -and $hEntra -match 'Grant-PimGraphAppRoles\.ps1')
    $hGrp = Get-PimActiveAssignmentSurfaceHint -Surface 'pim-for-groups' -ErrorMessage 'HTTP 403 Forbidden'
    T 'pim-for-groups 403 hint names PrivilegedAccess.Read.AzureADGroup' `
        ($hGrp -match 'PrivilegedAccess\.Read\.AzureADGroup')
    $hAz = Get-PimActiveAssignmentSurfaceHint -Surface 'azure-rbac' -ErrorMessage 'AuthorizationFailed'
    T 'azure-rbac hint asks for Reader on the subscription (not a Graph role)' `
        ($hAz -match '(?i)Reader' -and $hAz -match '(?i)subscription')
    $hNone = Get-PimActiveAssignmentSurfaceHint -Surface 'entra-role' -ErrorMessage 'The remote name could not be resolved'
    T 'transient/transport entra-role failure yields NO permission hint' `
        ([string]::IsNullOrEmpty($hNone))
}

# ---------------------------------------------------------------------------
# Layer 1c -- SQL-MODE PATH SAFETY (always runs; no SQL, no tenant)
# Regression guards for the three SQL-mode Manager defects found by the scenario
# simulation. In SQL mode the synthetic instance name is 'sql:<db>' -- the ':' is
# illegal in a Windows path SEGMENT, so the CSV-era cache-folder path logic threw
# "The given path's format is not supported", 500-ing GET / and /api/preflight.
# Departments rows have no GroupTag, so the SQL natural key was blank and the row
# was silently dropped on save. These run in-proc against the real helpers.
# ---------------------------------------------------------------------------
Write-Host "`n-- SQL-mode path safety (offline) --" -ForegroundColor Cyan

# (1)+(2) Tenant-cache root must be a LEGAL filesystem path for a 'sql:<db>' instance.
#         Pre-fix, Get-PimTenantCacheRoot -> Join-Path .\cache 'sql:PimPlatform' and
#         New-Item/Test-Path throw "The given path's format is not supported", which
#         bubbles out of Read-PimTenantListCache (GET /) and Get-PimCacheFreshness
#         (/api/preflight) as a 500. The fix sanitizes the instance-name segment.
. (Join-Path $root 'tools\pim-manager\_tenantSync.ps1')
$cacheTestRoot = Join-Path $env:TEMP ("pim-cacheroot-" + [guid]::NewGuid().ToString('N').Substring(0,8))
$savedMgrRoot  = $script:PimManagerRoot
$savedInstName = $script:PimInstanceName
try {
    $script:PimManagerRoot  = $cacheTestRoot
    $script:PimInstanceName = 'sql:PimPlatform'   # the exact SQL-mode synthetic label
    $threw = $false; $resolvedRoot = $null
    try { $resolvedRoot = Get-PimTenantCacheRoot } catch { $threw = $true }
    T 'tenant-cache root resolves for a sql:<db> instance (no path-format throw)' (-not $threw)
    T 'tenant-cache root segment is filesystem-legal (no colon)' `
        ($resolvedRoot -and ((Split-Path -Leaf $resolvedRoot) -notmatch ':') -and (Test-Path -LiteralPath $resolvedRoot))
    # And the full read path that GET / uses must not throw either.
    $readThrew = $false
    try { [void](Read-PimTenantListCache) } catch { $readThrew = $true }
    T 'Read-PimTenantListCache succeeds in sql:<db> instance mode (GET / path)' (-not $readThrew)
} finally {
    $script:PimManagerRoot  = $savedMgrRoot
    $script:PimInstanceName = $savedInstName
    Remove-Item -LiteralPath $cacheTestRoot -Recurse -Force -EA SilentlyContinue
}

# (3) Departments natural key must derive from the Department name (not GroupTag).
#     The §11 Departments grid + the scenario seed write { Department; Owners; ... }
#     with NO GroupTag, so the old GroupTag-only key was '' -> Set-PimSqlEntityRows
#     skipped the row -> grid edits silently vanished. Fix keys on Department.
. (Join-Path $root 'engine\_shared\PIM-SqlStore.ps1')
$deptRow = [pscustomobject]@{ Department='IT'; Owners='owner@contoso.com'; Mode='Serial' }
T 'Departments row (no GroupTag) yields a non-empty SQL key' `
    ((Get-PimStoreRowKey -Base 'PIM-Definitions-Departments' -Row $deptRow) -eq 'IT')
T 'Departments key falls back to DepartmentName when Department is absent' `
    ((Get-PimStoreRowKey -Base 'PIM-Definitions-Departments' -Row ([pscustomobject]@{ DepartmentName='HR' })) -eq 'HR')
T 'Departments key still honours a GroupTag when the sample shape carries one' `
    ((Get-PimStoreRowKey -Base 'PIM-Definitions-Departments' -Row ([pscustomobject]@{ GroupTag='DEPT-Finance' })) -eq 'DEPT-Finance')
# Other PIM-Definitions-* entities must KEEP keying on GroupTag (no collateral change).
T 'other PIM-Definitions-* entities still key on GroupTag' `
    ((Get-PimStoreRowKey -Base 'PIM-Definitions-Services' -Row ([pscustomobject]@{ GroupTag='Svc-A'; Department='IT' })) -eq 'Svc-A')

# ---------------------------------------------------------------------------
# Layer 2 -- LIVE BOOT (skips cleanly if no SQL). Boots the REAL Manager against a
# throwaway SQL DB + a tenant-bound registry instance and asserts the SQL runtime
# behavior end to end: [store] SQL mode, SQL render mode (not static read-only),
# active instance != local, read-write role, and the active-assignments handler
# resolving its tenant connection lazily (no -ConnectPlatform gate).
#
# It boots in LOOPBACK (not -Hosted): hosted mode binds http://+:port (needs a URL-ACL
# / admin) and DOESN'T print the /api session token, so it can't be driven from a
# non-elevated test process. The hosted-SPECIFIC wiring (PIM_HOSTED -> SQL-required,
# fail-closed RBAC, static-vs-SQL render under Easy Auth) is asserted by Layer 1
# (source contract) and proven live by tests/live/Test-PimManagerHostedSmoke.ps1.
# What's deterministic offline -- the SQL store + SQL render + non-local instance +
# lazy-connect handler -- is proven here against a real running server.
# ---------------------------------------------------------------------------
Write-Host "`n-- live boot (SQL-backed loopback + throwaway SQL) --" -ForegroundColor Cyan

. (Join-Path $root 'engine\_shared\PIM-ChangeQueue.ps1')
. (Join-Path $root 'engine\_shared\PIM-SqlStore.ps1')

$masterCs = Get-PimSqlConnectionString -Server $Server -Database 'master'
if (-not (Test-PimSqlConnectivity -ConnectionString $masterCs)) {
    S 'hosted live boot' "SQL '$Server' not reachable (expected-after-fix gate; needs SQL to run)"
} else {
    $db   = "pimhosted_" + [guid]::NewGuid().ToString('N').Substring(0,12)
    $cs   = Get-PimSqlConnectionString -Server $Server -Database $db
    $cfgDir = Join-Path $root 'config'
    $outDir = Join-Path $root 'output'
    $instName = 'hostedsim'   # a real registry instance (the registry loader wraps {instances:[...]})
    # Declare a registry instance carrying tenant/appId identity so the engine-SPN
    # connect block has something to act on. SQL backend is driven by the hosted +
    # connection-string signals (the store block forces SQL-required when hosted).
    $instFile = Join-Path $root 'tools\pim-manager\instances.custom.json'
    $instBak  = "$instFile.hostedsimbak"
    $hadInst  = Test-Path -LiteralPath $instFile
    if ($hadInst) { Copy-Item $instFile $instBak -Force }
    $out = Join-Path $env:TEMP ("pim-hostedsim-{0}.out" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
    Get-ChildItem "$out*" -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
    $proc = $null
    $savedEnv = @{
        PIM_SqlServer = $env:PIM_SqlServer
        PIM_SqlDatabase = $env:PIM_SqlDatabase; PIM_SqlDatabases = $env:PIM_SqlDatabases
        PIM_SqlConnectionString = $env:PIM_SqlConnectionString
    }
    try {
        Initialize-PimSqlDatabase -Server $Server -Database $db
        # Instance registry (the loader expects { instances: [...] }). tenantId+appId mean
        # the connect block resolves the engine-SPN context for THIS instance.
        $fakeTid = '00000000-0000-0000-0000-0000000000aa'
        $fakeApp = '00000000-0000-0000-0000-0000000000bb'
        @{ instances = @(
            @{ name = $instName; configRoot = $cfgDir; outputRoot = $outDir; tenantId = $fakeTid; appId = $fakeApp }
        ) } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $instFile -Encoding UTF8

        # SQL backend signals (App Service app-settings shape). The connection-string
        # signal makes the store block treat SQL as REQUIRED (same gate hosted uses).
        $env:PIM_SqlConnectionString = $cs
        $env:PIM_SqlServer           = $Server
        $env:PIM_SqlDatabase         = $db
        $env:PIM_SqlDatabases        = $db

        Write-Host "Booting Manager (SQL-backed, loopback) on a dynamic free port (db $db, instance $instName) ..."
        # Target the SQL-bound registry instance; assert the store is SQL + the active
        # instance is NOT 'local' + the page renders SQL mode.
        $ctx  = Start-PimManagerForTest -ManagerPath $mgr -ExtraArgs @('-Instance',$instName) -StdoutPath $out -TimeoutSec 60
        $proc = $ctx.Process

        $token = $ctx.Token
        T 'Manager booted (SQL-backed)' ([bool]$token -and $ctx.Port -gt 0)
        if (-not $token) { Get-Content $out,"$out.err" -EA SilentlyContinue | Select-Object -Last 25 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray } }

        if ($token) {
            $bootLog = (Get-Content $out -Raw -EA SilentlyContinue)
            # store backend == SQL (no CSV / static fallback)
            T 'boot log: [store] SQL mode (SQL-only, no CSV fallback)' ($bootLog -match '\[store\]\s*SQL mode')
            T 'boot log: NOT defaulting to CSV store'                  ($bootLog -notmatch '\[store\]\s*CSV mode')
            # active instance is the SQL-bound instance, NOT 'local' (the startup-default symptom)
            T 'active instance is the SQL-bound instance (NOT local)'  ($bootLog -match ("instance:\s*" + [regex]::Escape($instName)))
            T 'boot did not silently fall back to local instance'      ($bootLog -notmatch 'instance:\s*local\b')

            $base = $ctx.BaseUrl; $hdr = @{ Authorization = "Bearer $token" }
            function Beat { try { Invoke-RestMethod -Method POST -Uri "$base/api/heartbeat" -Headers $hdr -TimeoutSec 10 | Out-Null } catch {} }
            Beat

            # '/' render path picks SQL mode (NOT static read-only). __PIM_MODE__ becomes
            # 'SQL: <db>'; the static viewer would render a read-only banner instead.
            $page = $null
            try { $page = Invoke-WebRequest -Uri "$base/" -Headers $hdr -TimeoutSec 60 -UseBasicParsing } catch {}
            T '/ served the dynamic (server) page' ([bool]$page -and $page.StatusCode -eq 200)
            if ($page) {
                $body = "$($page.Content)"
                # The render mode is carried in the <meta name="pim-mode" content="..."> tag
                # (__PIM_MODE__). Server-SQL -> "SQL: <db>"; the static viewer would inject a
                # static-mode label. Assert ON THE META, not raw text -- the page's client JS
                # contains the literal 'static (read-only)' string for its OWN fallback path,
                # so a raw-text search would false-positive on every served page.
                $metaMode = ''
                $mm = [regex]::Match($body, '<meta\s+name="pim-mode"\s+content="([^"]*)"')
                if ($mm.Success) { $metaMode = $mm.Groups[1].Value }
                T '/ render mode meta = SQL: <db> (NOT static read-only)' `
                    (($metaMode -match ("SQL:\s*" + [regex]::Escape($db))) -and ($metaMode -notmatch '(?i)static'))
            }

            # GUI is read-WRITE for an admin role: /api/portal-access reports a non-Reader
            # managerRole. (The hosted symptom is GUI read-only when the role fails closed;
            # here -- loopback, no manager-access file -- the operator is SuperAdmin, so a
            # Reader result would itself be a regression.)
            $pa = $null
            try { $pa = Invoke-RestMethod -Uri "$base/api/portal-access" -Headers $hdr -TimeoutSec 30 } catch {}
            T 'admin gets read-write role (managerRole != Reader)' `
                ($pa -and "$($pa.managerRole)" -ne '' -and "$($pa.managerRole)" -ne 'Reader')

            # The active-assignments handler must NOT 'static-read-only' nor crash with a
            # context message before even trying. Offline (no real tenant), the LAZY
            # connect will fail -> 500 with a tenant/connect error -- but that proves the
            # handler RAN the connect path (didn't hard-require -ConnectPlatform and didn't
            # serve a static page). A 200 would mean a tenant is actually reachable.
            $aaStatus = 0; $aaErr = ''
            try {
                $aa = Invoke-RestMethod -Uri "$base/api/active-assignments" -Headers $hdr -TimeoutSec 60
                $aaStatus = 200
            } catch {
                $errRec = $_
                $resp2 = $errRec.Exception.Response
                try { $aaStatus = [int]$resp2.StatusCode } catch { $aaStatus = -1 }
                # Pull the JSON error BODY the handler wrote (the message lives there, not in
                # the WebException text). The handler returns @{ ok=$false; error=... } on 500.
                #
                # Host-agnostic read -- the type of $resp2 differs by PowerShell edition:
                #   PS 7 (pwsh, the CI runner): Invoke-RestMethod is built on HttpClient, so
                #     $resp2 is a System.Net.Http.HttpResponseMessage -- it has NO
                #     GetResponseStream(); calling it throws MethodNotFound and the body is
                #     lost, which flaked this assertion intermittently (it passed under
                #     powershell.exe 5.1 but failed under pwsh 7).
                #   PS 5.1 (powershell.exe): built on HttpWebRequest, so $resp2 is a
                #     System.Net.HttpWebResponse -- the WebResponse API (GetResponseStream()).
                # On BOTH editions Invoke-RestMethod populates $_.ErrorDetails.Message with
                # the response body, so prefer that; fall back to the edition-correct stream
                # API only if it is empty. Never mix the two APIs.
                $aaErr = ''
                if ($errRec.ErrorDetails -and $errRec.ErrorDetails.Message) {
                    $aaErr = "$($errRec.ErrorDetails.Message)"
                }
                if ([string]::IsNullOrWhiteSpace($aaErr) -and $resp2) {
                    try {
                        if ($resp2 -is [System.Net.Http.HttpResponseMessage]) {
                            # PS 7 / HttpClient -- read via Content; GetAwaiter().GetResult()
                            # is the PS 5.1-safe sync form (harmless on PS 7).
                            $aaErr = $resp2.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                        } else {
                            # PS 5.1 / HttpWebResponse -- WebResponse.GetResponseStream().
                            $sr = New-Object System.IO.StreamReader($resp2.GetResponseStream())
                            try { $aaErr = $sr.ReadToEnd() } finally { $sr.Close() }
                        }
                    } catch { $aaErr = "$($errRec.Exception.Message)" }
                }
                if ([string]::IsNullOrWhiteSpace($aaErr)) { $aaErr = "$($errRec.Exception.Message)" }
            }
            Write-Host ("    (active-assignments: status=$aaStatus; err=" + (("$aaErr" -replace '\s+',' ').Substring(0, [Math]::Min(160, "$aaErr".Length))) + ")") -ForegroundColor DarkGray
            T 'active-assignments did not return static/read-only or 401' ($aaStatus -eq 200 -or $aaStatus -eq 500)
            # Offline (fake tenant), the LAZY connect attempt fails -> the handler's
            # try/catch around Get-PimActiveAssignmentsCached returns 500. There is NO other
            # path to a 500 here, so a 500 (or a 200 when a real tenant is reachable) proves
            # the handler RAN the connect path: it did NOT hard-require -ConnectPlatform (that
            # would never have produced this dynamic handler 500) and did NOT serve a static
            # page (that would be a 200 with HTML). When the JSON body is readable, it must
            # carry a connect/tenant/auth-shaped error, never a "static"/"read-only" string.
            $aaBodyOk = ([string]::IsNullOrWhiteSpace($aaErr)) -or `
                        (($aaErr -match '(?i)engine SPN context|connect|tenant|graph|token|certificate|app|auth|sign|credential|MSAL|AADSTS|"ok"\s*:\s*false') -and `
                         ($aaErr -notmatch '(?i)static \(read-only\)|read-only viewer'))
            T 'active-assignments attempted the lazy connect (no -ConnectPlatform gate)' `
                (($aaStatus -eq 200 -or $aaStatus -eq 500) -and $aaBodyOk)
        }
    } finally {
        if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -EA SilentlyContinue }
        foreach ($k in $savedEnv.Keys) { Set-Item -Path "Env:$k" -Value $savedEnv[$k] -EA SilentlyContinue; if ($null -eq $savedEnv[$k]) { Remove-Item "Env:$k" -EA SilentlyContinue } }
        Get-ChildItem "$out*" -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
        if ($hadInst) { Move-Item $instBak $instFile -Force -EA SilentlyContinue } else { Remove-Item $instFile -Force -EA SilentlyContinue }
        Remove-Item $instBak -Force -EA SilentlyContinue
        try { [void](Invoke-PimSqlNonQuery -ConnectionString $masterCs -Sql "IF DB_ID('$db') IS NOT NULL BEGIN ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]; END") } catch { Write-Warning "cleanup failed: $($_.Exception.Message)" }
    }
}

Write-Host ("`n RESULT: {0} pass, {1} fail, {2} skip" -f $pass, $fail, $skip) -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 }
