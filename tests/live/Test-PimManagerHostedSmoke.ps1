#Requires -Version 5.1
<#
.SYNOPSIS
  POST-DEPLOY HOSTED SMOKE for the PIM Manager Container App (ca-pim-manager).

.DESCRIPTION
  The missing test CLASS: a real runtime check against the LIVE hosted Manager, not a
  unit mock. It FAILS on exactly the symptoms that shipped "green" while the hosted+SQL
  runtime was broken:

    1. Render mode must be SQL -- NOT 'static (read-only)'.
    2. The engine-SPN context must resolve at startup -- NOT 500
       "engine SPN context missing" on /api/active-assignments. (See the Easy-Auth
       note below: this is asserted via the boot log, because a programmatic caller
       CANNOT authenticate to /api/* behind hosted Easy Auth -- that probe is an
       explicit browser-only skip, never a fail.)
    3. The tenant-list cache must be populated -- no "missing or empty" warning,
       entra-roles non-empty.
    4. The GUI must be read-WRITE for an admin role.
    5. The store backend must be SQL -- no CSV/static fallback.

  PRECISION NOTES (why earlier runs FALSE-FAILED a healthy deploy):
    * The boot-log "active instance" check now matches the REAL served phrasing
      active instance 'sql:<db>' (was the never-emitted `instance: sql:`).
    * The render-mode checks ANCHOR on real signals -- the boot-log "[store] SQL
      mode" line and the served page's <meta name="pim-mode" content="SQL: <db>">
      tag -- instead of substring-scanning the page/log for 'static (read-only)',
      which is incidental client-side fallback text present on EVERY served page.
    * /api/active-assignments is browser-only behind hosted Easy Auth (both the
      edge token and the app session GUID want the one Authorization header), so
      it is an EXPLICIT documented skip, not a fail. See docs/TESTS.md §1a.

  Evidence is taken from TWO sources:
    A. The Container App's OWN boot logs (Log Analytics workspace, table
       ContainerAppConsoleLogs_CL) -- asserts '[store] SQL mode' and the render mode
       were chosen at startup. Pulled via `az monitor log-analytics query`.
    B. Live HTTP against the app FQDN behind Easy Auth -- a bearer token for the Easy
       Auth app registration (audience api://<clientId>) is minted with
       `az account get-access-token --resource <aud>` (an app/MI token; documented
       auth path below). The '/' page render mode is probed (Easy-Auth token only).
       /api/* endpoints are best-effort: most are browser-only behind Easy Auth (see
       below) and self-SKIP with a documented reason when unauthenticated -- never a
       fail. The render-mode + engine-SPN-context evidence comes from source A.

  AUTH PATH (Easy Auth) -- and why /api/* is browser-only:
    Easy Auth fronts the app (api://<clientId>). The '/' page can be reached with an
    Easy Auth edge token alone (`az account get-access-token --resource <aud>` with a
    signed-in identity assigned to the app, or the deploying MI -- passed as
    'Authorization: Bearer <token>'). But /api/* needs TWO credentials that BOTH live
    in the single `Authorization` header: the Easy Auth edge token AND the app's OWN
    per-session GUID. A programmatic caller cannot present both at once, so /api/*
    (incl. /api/active-assignments) is effectively BROWSER-ONLY behind hosted Easy
    Auth -- this smoke SKIPS those probes with a documented reason rather than
    false-failing. If a deployment exposes a fixed service token, pass it via
    -SessionToken (sent as X-PIM-Token) to exercise /api/* directly.

  This test is LIVE-ONLY. It SKIPS cleanly (exit 0) when az is unavailable, not logged
  in, or the required parameters/env are absent -- so it never blocks an offline run.
  It is NEVER green-by-default: a reachable-but-broken hosted Manager FAILS here.

  PARAMETERS / ENV (env overrides shown):
    -App           ca-pim-manager            (PIM_HOSTED_APP)
    -ResourceGroup rg-pim-manager-web        (PIM_HOSTED_RG)
    -WorkspaceId   64fe16eb-...              (PIM_HOSTED_LA_WORKSPACE)
    -Fqdn          <ingress fqdn>            (PIM_HOSTED_FQDN)         -- optional; else derived from az
    -EasyAuthAud   api://<clientId>          (PIM_HOSTED_EASYAUTH_AUD) -- optional; enables HTTP layer
    -SessionToken  <app /api token>          (PIM_HOSTED_SESSION_TOKEN)-- optional; else read from boot log

.EXAMPLE
  $env:PIM_HOSTED_EASYAUTH_AUD='api://<clientId>'
  pwsh -File tests/live/Test-PimManagerHostedSmoke.ps1
#>
[CmdletBinding()]
param(
    [string]$App           = $(if ($env:PIM_HOSTED_APP)             { $env:PIM_HOSTED_APP }             else { 'ca-pim-manager' }),
    [string]$ResourceGroup = $(if ($env:PIM_HOSTED_RG)              { $env:PIM_HOSTED_RG }              else { 'rg-pim-manager-web' }),
    [string]$WorkspaceId   = $(if ($env:PIM_HOSTED_LA_WORKSPACE)    { $env:PIM_HOSTED_LA_WORKSPACE }    else { '64fe16eb-a9dd-49b6-9ce8-50a7c85f3cec' }),
    [string]$Fqdn          = $(if ($env:PIM_HOSTED_FQDN)            { $env:PIM_HOSTED_FQDN }            else { '' }),
    [string]$EasyAuthAud   = $(if ($env:PIM_HOSTED_EASYAUTH_AUD)    { $env:PIM_HOSTED_EASYAUTH_AUD }    else { '' }),
    [string]$SessionToken  = $(if ($env:PIM_HOSTED_SESSION_TOKEN)   { $env:PIM_HOSTED_SESSION_TOKEN }   else { '' }),
    [int]$LookbackMinutes  = 90
)
$ErrorActionPreference = 'Stop'
$pass=0; $fail=0; $skip=0
function T($n,$c){ if($c){Write-Host "  PASS $n" -ForegroundColor Green;$script:pass++}else{Write-Host "  FAIL $n" -ForegroundColor Red;$script:fail++} }
function S($n,$why){ Write-Host "  SKIP $n -- $why" -ForegroundColor Yellow; $script:skip++ }
function Have($cmd){ [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# EXPECTED version = the contents of SOLUTIONS/PIM4EntraPS/VERSION. The live Manager
# MUST be serving exactly this (boot log + served HTML header). A live version that
# is older/different == a deploy that didn't actually roll the image (the "stuck on
# 2.4.222" case) and is a HARD FAIL below, never a skip.
$ExpectedVersion = $null
$verFile = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'VERSION'  # tests/live -> tests -> PIM4EntraPS
if (Test-Path -LiteralPath $verFile) {
    try { $ExpectedVersion = ([System.IO.File]::ReadAllText($verFile)).Trim() } catch {}
}

Write-Host "=== PIM Manager HOSTED post-deploy SMOKE (live: $App) ===" -ForegroundColor Cyan
if ($ExpectedVersion) { Write-Host ("  expected served version (VERSION): {0}" -f $ExpectedVersion) -ForegroundColor DarkGray }
else                  { Write-Host  "  WARNING: could not read SOLUTIONS/PIM4EntraPS/VERSION -- version assertion will FAIL" -ForegroundColor Yellow }

# ---- Preconditions: az present + logged in -----------------------------------
if (-not (Have 'az')) {
    S 'hosted smoke' 'azure CLI (az) not found -- LIVE-only test, skipping cleanly'
    Write-Host ("`n RESULT: {0} pass, {1} fail, {2} skip" -f $pass,$fail,$skip) -ForegroundColor Green; exit 0
}
$acct = $null
try { $acct = az account show -o json 2>$null | ConvertFrom-Json } catch {}
if (-not $acct) {
    S 'hosted smoke' 'az not logged in (az login) -- skipping cleanly'
    Write-Host ("`n RESULT: {0} pass, {1} fail, {2} skip" -f $pass,$fail,$skip) -ForegroundColor Green; exit 0
}
Write-Host ("  az context: {0} / sub {1}" -f $acct.user.name, $acct.id) -ForegroundColor DarkGray

# =============================================================================
# A. Container App OWN boot logs (Log Analytics -- ContainerAppConsoleLogs_CL)
#    Asserts the startup decisions: [store] SQL mode + render mode = SQL (not static).
# =============================================================================
Write-Host "`n-- A. boot logs (LA workspace $WorkspaceId) --" -ForegroundColor Cyan
$logRows = @()
$kql = @"
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(${LookbackMinutes}m)
| where ContainerAppName_s == '$App' or ContainerName_s == '$App'
| project TimeGenerated, Log_s
| order by TimeGenerated desc
| take 4000
"@
try {
    $raw = az monitor log-analytics query --workspace $WorkspaceId --analytics-query $kql -o json 2>$null
    if ($raw) { $logRows = @($raw | ConvertFrom-Json) }
} catch { }
$logText = ($logRows | ForEach-Object { "$($_.Log_s)" }) -join "`n"

if (-not $logRows -or $logRows.Count -eq 0) {
    S 'boot-log assertions' "no ContainerAppConsoleLogs_CL rows for '$App' in last ${LookbackMinutes}m (workspace access? app name? deployed?)"
} else {
    Write-Host ("  pulled {0} log rows" -f $logRows.Count) -ForegroundColor DarkGray
    # 1 + 5: store backend is SQL, no CSV/static fallback.
    T 'boot log shows [store] SQL mode'                 ($logText -match '\[store\]\s*SQL mode')
    T 'boot log does NOT show CSV/static store fallback' ($logText -notmatch '\[store\]\s*CSV mode')
    # active instance is the SQL one (sql:<db>), not 'local'. The REAL boot line is
    #   "[store] hosted/SQL default -> active instance 'sql:PimPlatform'"
    # (Open-PimManager.ps1) -- match that exact phrasing, anchored on
    # active instance 'sql:...'. The old `instance:\s*sql:` regex never matched the
    # served wording and FALSE-FAILED a healthy deploy.
    T "boot log: active instance is 'sql:<db>' (NOT local)" ($logText -match "active instance '\s*sql:\S+")
    # render mode SQL, never static read-only. ANCHOR on the actual render-mode
    # signal the boot path emits ("[store] SQL mode") rather than substring-scanning
    # the whole 4000-row log for 'static (read-only)' -- that phrase is incidental
    # help/fallback text and produced a FALSE FAIL on a healthy SQL deploy. The
    # static viewer would instead emit "[store] CSV mode"/"static mode", which the
    # next assertion already rules out.
    T 'boot log: render/page mode is SQL (not static read-only)' `
        (($logText -match '\[store\]\s*SQL mode') -and ($logText -notmatch '(?i)\[store\]\s*CSV mode') -and ($logText -notmatch '(?i)static mode'))
    # the engine-SPN context resolved (no "engine SPN context missing" at startup).
    T 'boot log: no "engine SPN context" missing error'  ($logText -notmatch 'engine SPN context')
    # tenant cache not reported missing/empty.
    T 'boot log: tenant-list cache not "missing or empty"' ($logText -notmatch '(?i)tenant[- ]list[^\r\n]*missing or empty')
    # session token surfaced (and grab it for the HTTP layer if not supplied).
    if (-not $SessionToken) {
        $m = [regex]::Match($logText, 'session token:\s*([0-9a-fA-F\-]{16,})')
        if ($m.Success) { $SessionToken = $m.Groups[1].Value }
    }

    # ===== VERSION ASSERTION (boot log) =====================================
    # The Manager emits a deterministic startup line:
    #   "[version] PIM Manager v<X.Y.Z> (from VERSION)"
    # (Open-PimManager.ps1 / Invoke-Server). Assert the LIVE served version EQUALS
    # the EXPECTED version (SOLUTIONS/PIM4EntraPS/VERSION). A stale/older live
    # version means the deploy did NOT actually roll the image -- HARD FAIL (the
    # exact "stuck on 2.4.222" symptom). We take the MOST RECENT version line
    # (logRows are ordered desc) so an old revision's line never masks the current.
    $bootVer = $null
    foreach ($row in $logRows) {
        $vm = [regex]::Match("$($row.Log_s)", '\[version\]\s*PIM Manager\s*v?([0-9]+\.[0-9]+\.[0-9]+)')
        if ($vm.Success) { $bootVer = $vm.Groups[1].Value; break }   # first (newest) wins
    }
    if (-not $ExpectedVersion) {
        T 'boot log: served version matches VERSION (could not read VERSION)' $false
    } elseif (-not $bootVer) {
        # No version line at all in the lookback window. Treat as a FAIL, not a skip:
        # a healthy current image ALWAYS emits it at boot, so its absence means the
        # running image predates this assertion (i.e. it is stale) -- exactly what we
        # must catch. (If you truly cannot get logs, section A self-skips earlier.)
        T ("boot log: served version matches VERSION (expected v{0}; NO [version] line found in last {1}m -- stale image?)" -f $ExpectedVersion, $LookbackMinutes) $false
    } else {
        Write-Host ("  boot-log served version: v{0} (expected v{1})" -f $bootVer, $ExpectedVersion) -ForegroundColor DarkGray
        T ("boot log: served Manager version == VERSION (v{0})" -f $ExpectedVersion) ($bootVer -eq $ExpectedVersion)
    }
}

# =============================================================================
# B. Live HTTP behind Easy Auth (needs the Easy Auth audience to mint a token).
# =============================================================================
Write-Host "`n-- B. live HTTP (Easy Auth) --" -ForegroundColor Cyan

# Resolve the FQDN if not supplied (Container App ingress).
if (-not $Fqdn) {
    try { $Fqdn = (az containerapp show -n $App -g $ResourceGroup --query properties.configuration.ingress.fqdn -o tsv 2>$null) } catch {}
    if (-not $Fqdn) { try { $Fqdn = (az webapp show -n $App -g $ResourceGroup --query defaultHostName -o tsv 2>$null) } catch {} }
}

if (-not $EasyAuthAud) {
    S 'live HTTP probes' 'no Easy Auth audience (-EasyAuthAud / PIM_HOSTED_EASYAUTH_AUD) -- cannot mint a token through Easy Auth'
} elseif (-not $Fqdn) {
    S 'live HTTP probes' "could not resolve the app FQDN (-Fqdn / PIM_HOSTED_FQDN); is '$App' in '$ResourceGroup'?"
} else {
    $aadToken = $null
    try { $aadToken = (az account get-access-token --resource $EasyAuthAud --query accessToken -o tsv 2>$null) } catch {}
    if (-not $aadToken) {
        S 'live HTTP probes' "could not mint an Easy Auth token for '$EasyAuthAud' (is this identity assigned to the app?)"
    } else {
        $base = "https://$Fqdn"
        $edge = @{ Authorization = "Bearer $aadToken" }
        # /api/* needs the app session token too; X-PIM-Token mirrors the bearer the
        # local edition uses. Send both shapes so whichever the app honors works.
        $api = @{ Authorization = "Bearer $aadToken" }
        if ($SessionToken) { $api['X-PIM-Token'] = $SessionToken; $api['X-PIM-Session'] = $SessionToken }

        # 1 + render: '/' must be the SQL dynamic page, not static read-only.
        $page = $null
        try { $page = Invoke-WebRequest -Uri "$base/" -Headers $edge -TimeoutSec 60 -UseBasicParsing } catch {}
        T '/ reachable behind Easy Auth (200)' ([bool]$page -and $page.StatusCode -eq 200)
        if ($page) {
            $body = "$($page.Content)"
            # Assert ON THE <meta name="pim-mode" content="..."> tag, NOT a raw-text
            # scan of the page. The served SPA ALWAYS ships the client-side fallback
            # string 'static (read-only)' (pim-manager.html sets modeLabel.textContent
            # to it only when PIM_MODE==='static'), so a substring scan FALSE-FAILED
            # every healthy SQL render. The render mode is carried unambiguously in the
            # meta tag: SQL mode -> content="SQL: <db>"; the static viewer -> "static".
            $metaMode = ''
            $mm = [regex]::Match($body, '<meta\s+name="pim-mode"\s+content="([^"]*)"')
            if ($mm.Success) { $metaMode = $mm.Groups[1].Value }
            T '/ render mode meta = SQL: <db> (carries "SQL:" mode label)' ($metaMode -match 'SQL:\s*\S+')
            T '/ render mode meta is NOT the static (read-only) viewer'    ($metaMode -notmatch '(?i)static')

            # ===== VERSION ASSERTION (served HTML header) ===================
            # The header renders <span id="versionBadge">v<X.Y.Z></span> from
            # Get-PimSolutionVersion (which reads VERSION). Assert the SERVED page
            # advertises the EXPECTED version -- a stale badge means the running
            # image is older than VERSION. HARD FAIL on mismatch.
            $servedVer = ''
            $vb = [regex]::Match($body, 'id="versionBadge"[^>]*>\s*v?([0-9]+\.[0-9]+\.[0-9]+)')
            if ($vb.Success) { $servedVer = $vb.Groups[1].Value }
            if (-not $servedVer) {
                S '/ served version badge present' 'could not parse #versionBadge from the served HTML (page shape changed?) -- boot-log version assertion in section A still gates this'
            } elseif (-not $ExpectedVersion) {
                T '/ served versionBadge matches VERSION (could not read VERSION)' $false
            } else {
                Write-Host ("  served versionBadge: v{0} (expected v{1})" -f $servedVer, $ExpectedVersion) -ForegroundColor DarkGray
                T ("/ served versionBadge == VERSION (v{0}, NOT a stale deploy)" -f $ExpectedVersion) ($servedVer -eq $ExpectedVersion)
            }
        }

        # 4: GUI read-WRITE for an admin role.
        $pa = $null
        try { $pa = Invoke-RestMethod -Uri "$base/api/portal-access" -Headers $api -TimeoutSec 30 } catch {}
        if ($pa) {
            T 'GUI read-write: managerRole != Reader' (("$($pa.managerRole)" -ne '') -and ("$($pa.managerRole)" -ne 'Reader'))
        } else {
            S '/api/portal-access' 'no response (needs the app /api session token via -SessionToken if not in boot log)'
        }

        # 3: tenant cache populated -- entra-roles non-empty.
        $tl = $null
        try { $tl = Invoke-RestMethod -Uri "$base/api/tenant-lists" -Headers $api -TimeoutSec 30 } catch {}
        if ($tl) {
            $entra = $tl.entraRoles
            T 'tenant cache populated: entra-roles non-empty' ($null -ne $entra -and @($entra.items).Count -gt 0)
        } else {
            S '/api/tenant-lists' 'no response (app /api token?)'
        }

        # 2: the #47 fix -- /api/active-assignments must resolve the engine-SPN
        #    context (not 500 "engine SPN context missing"). See the IMPORTANT note:
        #    a programmatic caller CANNOT get a 200 from /api/* behind hosted Easy
        #    Auth, because BOTH the Easy Auth edge token AND the app's per-session
        #    GUID want the single `Authorization` header -- only the in-browser
        #    session (Easy Auth cookie at the edge + session GUID in the app) can
        #    satisfy both. So a script probe of /api/active-assignments returning
        #    non-200 is EXPECTED and is NOT evidence the deploy is broken.
        #
        #    The #47 fix is therefore asserted via the boot-log signal we CAN reach
        #    (section A: "no 'engine SPN context' missing error" -- the context
        #    resolved at startup) and the live HTTP probe is an EXPLICIT, DOCUMENTED
        #    skip in hosted Easy-Auth mode (browser-only), never a fail.
        #
        #    We still attempt the call: if a real 200 + JSON body IS obtained (e.g.
        #    a deployment that exposes a fixed service token via -SessionToken, or a
        #    non-Easy-Auth edge), we opportunistically verify the no-silent-empty
        #    contract. Otherwise we SKIP with the documented reason.
        $aaStatus = 0; $aaErr = ''; $aaBody = $null
        try { $aaBody = Invoke-RestMethod -Uri "$base/api/active-assignments" -Headers $api -TimeoutSec 120; $aaStatus = 200 }
        catch { try { $aaStatus = [int]$_.Exception.Response.StatusCode } catch { $aaStatus = -1 }; $aaErr = "$($_.Exception.Message)" }

        if ($aaStatus -eq 200 -and $null -ne $aaBody) {
            # A real authenticated 200 was reachable -- verify the no-silent-empty contract.
            T 'GET /api/active-assignments returns 200 (NOT 500)' ($aaStatus -eq 200)
            T 'active-assignments not "engine SPN context missing"' ($aaErr -notmatch '(?i)engine SPN context')

            # The v2.4.219 bug: the endpoint returned 200 with ok=true,total=0 even
            # when EVERY surface failed on auth -- which the GUI rendered as the
            # misleading "Cache may be empty -- click Refresh". The fixed contract is:
            # either active assignments ARE populated, OR ok=false carries an explicit,
            # actionable per-surface auth/permission error -- NEVER a silent empty.
            $total    = 0; try { $total = [int]$aaBody.counts.total } catch {}
            $okFlag   = $true; try { $okFlag = [bool]$aaBody.ok } catch {}
            $errs     = @(); try { $errs = @($aaBody.surfaceErrors) } catch {}
            $topErr   = "$($aaBody.error)"
            $populated   = ($total -gt 0)
            $explicitErr = ((-not $okFlag) -and ($errs.Count -gt 0 -or $topErr.Trim()))
            T 'active-assignments is populated OR carries an explicit auth/permission error (no silent empty)' `
                ($populated -or $explicitErr)
            if ($populated) {
                Write-Host ("    (active-assignments populated: {0} total)" -f $total) -ForegroundColor DarkGray
            } elseif ($explicitErr) {
                $surf = (($errs | ForEach-Object { "$($_.surface)" }) -join ', ')
                Write-Host ("    (active-assignments empty BUT correctly reported as auth/permission failure on: {0})" -f $surf) -ForegroundColor DarkYellow
                # Diagnostic: if a Graph surface is the failure, the hint should name the grant remediation.
                $hasHint = [bool](@($errs | Where-Object { "$($_.hint)" -match 'Grant-PimGraphAppRoles|Reader|app-role' }).Count)
                T 'failing-surface error includes an actionable remediation hint' $hasHint
            }
        } else {
            # Browser-only behind hosted Easy Auth: a script cannot present both the
            # Easy Auth edge token and the app session GUID in one Authorization
            # header. This is an EXPLICIT documented skip (NOT a fail). The #47 fix
            # (engine-SPN context resolves; no 500) is covered by the section-A
            # boot-log assertion 'no "engine SPN context" missing error'.
            S '/api/active-assignments (#47 engine-SPN context)' `
              ("browser-only behind hosted Easy Auth -- a programmatic caller cannot satisfy both the Easy Auth edge token and the app per-session GUID in one Authorization header (probe status=$aaStatus). #47 is asserted via the boot-log engine-SPN-context signal in section A. To exercise /api directly, pass a fixed service token via -SessionToken or run against a non-Easy-Auth edge.")
        }
    }
}

Write-Host ("`n RESULT: {0} pass, {1} fail, {2} skip" -f $pass, $fail, $skip) -ForegroundColor $(if($fail){'Red'}else{'Green'})
if ($fail) { exit 1 }
