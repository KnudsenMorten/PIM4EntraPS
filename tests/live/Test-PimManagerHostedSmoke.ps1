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
    [string]$ResourceGroup = $(if ($env:PIM_HOSTED_RG)              { $env:PIM_HOSTED_RG }              else { '' }),
    [string]$WorkspaceId   = $(if ($env:PIM_HOSTED_LA_WORKSPACE)    { $env:PIM_HOSTED_LA_WORKSPACE }    else { '' }),
    [string]$Fqdn          = $(if ($env:PIM_HOSTED_FQDN)            { $env:PIM_HOSTED_FQDN }            else { '' }),
    [string]$EasyAuthAud   = $(if ($env:PIM_HOSTED_EASYAUTH_AUD)    { $env:PIM_HOSTED_EASYAUTH_AUD }    else { '' }),
    # ðŸ”´ SCOPED. This gate reported its own context as sub 772440e1 -- ANOTHER COMPANY'S
    # subscription -- and then queried Log Analytics there, found no rows for ca-pim-manager, and
    # failed as "no boot logs". That reads like a broken Manager and is a wrong-tenant lookup.
    # Third tool in one session with this defect (SEC-12, the TEST-09 drift gate, the deploy
    # script): an ambient identity standing in for an explicit one. It matters most HERE, because
    # under 7a a gate that could not RUN blocks the release -- so an unscoped lookup does not just
    # mislead, it stops the deploy.
    [string]$SubscriptionId = $(if ($env:PIM_SUBSCRIPTION_ID) { $env:PIM_SUBSCRIPTION_ID } else { '' }),
    [string]$SessionToken  = $(if ($env:PIM_HOSTED_SESSION_TOKEN)   { $env:PIM_HOSTED_SESSION_TOKEN }   else { '' }),
    [int]$LookbackMinutes  = 90,
    # TEST-05: run as a RELEASE GATE, where a self-skip is a FAILURE.
    #
    # CLAUDE.md §7a says "a self-skip of the live smoke ... is a SKIP, not a pass -- it
    # means the gate didn't run, so the feature stays undelivered". The script did not
    # implement that: without an Easy Auth audience it skipped the entire live-HTTP layer
    # and still exited 0, so `GET /` = 200 and `GET /api/active-assignments` = 200 -- the
    # two assertions §7a names as the gate -- had NEVER been enforced on a deploy. The
    # gate reported green for a run in which it did nothing.
    #
    # Default OFF so an engineer can still run this ad-hoc on a laptop with no az and get
    # an honest "skipped". The DEPLOY path passes -AsReleaseGate, so a deploy cannot
    # inherit a skip as a pass. Env: PIM_HOSTED_SMOKE_REQUIRE=1.
    [switch]$AsReleaseGate = $([bool]("$($env:PIM_HOSTED_SMOKE_REQUIRE)".Trim() -in @('1','true','yes')))
)
$ErrorActionPreference = 'Stop'
# 🔴 THE GUARDED az SHADOW -- and this file needs it MORE than the deploy scripts do, because
# here the damage is silent. Under $ErrorActionPreference='Stop' PowerShell 5.1 makes any write to
# az's stderr terminating, and az writes ordinary WARNINGS there (see _PimAz.ps1). The very first
# az call below is `try { $acct = az account show ... } catch {}` -- so on a host whose az config
# dir has extensions installed, a warning would throw, be swallowed, leave $acct null, and this
# gate would report "az not logged in" and SKIP. 🪤 A SKIP is not a pass (CLAUDE.md §7a), but it is
# also not a failure, so the deploy would sail past the one check that proves the GUI still works.
# The internal-prod update runs on exactly such a profile.
. (Join-Path $PSScriptRoot '..\..\tools\setup\_PimAz.ps1')
# Spliced into every az invocation below. Empty => ambient, which the banner already prints, so a
# wrong-tenant run is at least visible rather than silent.
$smokeSub = @()
if ("$SubscriptionId".Trim()) { $smokeSub = @('--subscription', "$SubscriptionId".Trim()) }
$pass=0; $fail=0; $skip=0
$script:skipReasons = New-Object System.Collections.Generic.List[string]
$script:naReasons   = New-Object System.Collections.Generic.List[string]
$script:passedNames = New-Object System.Collections.Generic.HashSet[string]
function T($n,$c){
    if($c){ Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++; [void]$script:passedNames.Add("$n") }
    else  { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ }
}
function S($n,$why){
    $script:skipReasons.Add("$n -- $why")
    if ($script:AsReleaseGate) { Write-Host "  FAIL $n -- $why (RELEASE GATE: a skip is not a pass)" -ForegroundColor Red; $script:fail++ }
    else { Write-Host "  SKIP $n -- $why" -ForegroundColor Yellow; $script:skip++ }
}
function N($n, $why, [string[]]$CoveredBy) {
    <#
      TEST-10 -- "NOT APPLICABLE, and something else already proved it".

      Some probes cannot run BY CONSTRUCTION behind a hosted Easy Auth edge: the edge
      token and the app's per-session GUID both want the single Authorization header,
      so a programmatic caller can never get 200 from /api/*. That is not a missing
      input an operator can supply -- re-running with more flags will never help.

      Note the irony that makes this necessary: these probes used to work only because
      GET / handed the /api bearer token to any caller, which is precisely the hole
      SEC-01 closed. The gate's way in WAS the vulnerability.

      This is NOT a loophole back to "a skip is a pass" (TEST-05). The downgrade is
      CONDITIONAL: it applies only when every named compensating assertion actually RAN
      and PASSED in this same run. If a compensating assertion is missing or failed,
      this degrades to S() -- a hard failure in gate mode. So the condition is still
      proven on every run; only the *route* to proving it changes.

      Never use this for a probe that a flag/credential could make runnable -- that is
      what S() is for.
    #>
    $missing = @($CoveredBy | Where-Object { -not $script:passedNames.Contains("$_") })
    if ($missing.Count -gt 0) {
        S $n ("$why -- and its compensating assertion(s) did NOT pass: " + ($missing -join '; '))
        return
    }
    $script:naReasons.Add("$n -- $why (covered by: " + ($CoveredBy -join '; ') + ")")
    Write-Host ("  N/A  $n -- $why") -ForegroundColor DarkCyan
    Write-Host ("       covered by: " + ($CoveredBy -join '; ')) -ForegroundColor DarkGray
}
function Write-PimSmokeResult {
    Write-Host ("`n RESULT: {0} pass, {1} fail, {2} skip, {3} n/a" -f $script:pass, $script:fail, $script:skip, $script:naReasons.Count) -ForegroundColor $(if($script:fail){'Red'}else{'Green'})
    if ($script:naReasons.Count -gt 0) {
        # Never silent. An N/A is a probe that CANNOT run in this topology, and each one
        # names the assertion that proved its condition instead (TEST-10).
        Write-Host "`n NOT APPLICABLE in this topology -- each condition was proven by a passing assertion:" -ForegroundColor DarkCyan
        foreach ($r in $script:naReasons) { Write-Host "   - $r" -ForegroundColor DarkCyan }
    }
    if ($script:AsReleaseGate -and $script:skipReasons.Count -gt 0) {
        Write-Host "`n RELEASE GATE: the following did not run, and a gate that did not run is NOT a pass:" -ForegroundColor Red
        foreach ($r in $script:skipReasons) { Write-Host "   - $r" -ForegroundColor Red }
        Write-Host " Provide the missing inputs (az login / -EasyAuthAud / -Fqdn) and re-run. See CLAUDE.md §7a." -ForegroundColor Red
    }
}
function Have($cmd){ [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# PURE, offline-tested served-version helpers (parse + compare + retry decision).
# Injecting the log-fetcher keeps the version check unit-testable with NO live az
# (tests/Test-PimSmokeVersionCheck.ps1).
. (Join-Path $PSScriptRoot '..\_shared\PimSmokeVersion.ps1')

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
if ($AsReleaseGate) { Write-Host "  MODE: RELEASE GATE -- a self-skip counts as a FAILURE (CLAUDE.md §7a)" -ForegroundColor Yellow }
if (-not (Have 'az')) {
    S 'hosted smoke' 'azure CLI (az) not found -- LIVE-only test'
    Write-PimSmokeResult; if ($fail) { exit 1 } else { exit 0 }
}
$acct = $null
try { $acct = az account show -o json 2>$null | ConvertFrom-Json } catch {}
if (-not $acct) {
    S 'hosted smoke' 'az not logged in (az login)'
    Write-PimSmokeResult; if ($fail) { exit 1 } else { exit 0 }
}
# 🪤 REPORT THE SUBSCRIPTION THE QUERIES ACTUALLY USE, not the ambient one. After the queries were
# scoped, this banner still printed the AMBIENT context -- so a correct run advertised another
# company's subscription while quietly reading the right one. A status line that disagrees with
# what the tool did is worse than no status line: it is the evidence somebody will reason from.
$ctxSub = if ("$SubscriptionId".Trim()) { "$SubscriptionId".Trim() + ' (explicit)' } else { "$($acct.id) (ambient default)" }
Write-Host ("  az context: {0} / sub {1}" -f $acct.user.name, $ctxSub) -ForegroundColor DarkGray

# =============================================================================
# A. Container App OWN boot logs (Log Analytics -- ContainerAppConsoleLogs_CL)
#    Asserts the startup decisions: [store] SQL mode + render mode = SQL (not static).
# =============================================================================
# 🔴 TEST-16 -- THE WORKSPACE WAS AN UNCHECKED GUID, AND THE WRONG ONE READS AS HEALTHY.
# -WorkspaceId was whatever the caller (or PIM_HOSTED_LA_WORKSPACE) said, with nothing
# asserting it is the workspace THIS app writes to. Measured on the 2.4.259 roll: the GUID in
# use pointed at 'workspace-rgautomateitmfnpr…' while the Container Apps environment logs to
# 'law-pim-mfnpr'. The wrong workspace still returned ca-pim-manager rows -- from OLD revisions
# -- so all six boot-log assertions PASSED while describing a container that had not run for
# days, and the version read v2.4.245 on a 2.4.259 deploy.
# 🔑 THAT is what I first recorded as "Log Analytics lag". It was not lag; it was the wrong
#    source entirely, and lag was the innocent explanation that fit the symptom.
# Two consequences, both handled here:
#   1) DERIVE the workspace from the Container Apps environment when the caller did not pin
#      one -- the environment's own appLogsConfiguration is the only authority on where these
#      logs land, and it costs two read-only calls.
#   2) Judge FRESHNESS against the ACTIVE REVISION (below), so rows that predate this deploy
#      can never be asserted as if they described it.
if (-not "$WorkspaceId".Trim()) {
    try {
        $envId = az containerapp show @smokeSub -n $App -g $ResourceGroup --query properties.environmentId -o tsv 2>$null
        if ("$envId".Trim()) {
            $derivedWs = az containerapp env show --ids "$("$envId".Trim())" `
                --query properties.appLogsConfiguration.logAnalyticsConfiguration.customerId -o tsv 2>$null
            if ("$derivedWs".Trim()) {
                $WorkspaceId = "$derivedWs".Trim()
                Write-Host ("  workspace derived from the Container Apps environment (authoritative): {0}" -f $WorkspaceId) -ForegroundColor DarkGray
            }
        }
    } catch { }
}
# Resolve the ACTIVE revision + when it was created BEFORE reading logs: without it there is no
# way to tell "this deploy has not logged yet" (ingestion lag, innocent) from "these rows are a
# different revision's" (wrong workspace, not innocent).
$activeRev = $null; $activeRevCreated = $null
try {
    # 🪤 Filter on `properties.active` ONLY. The obvious-looking extra clause
    # `&& properties.runningState=='Running'` matches NOTHING on a healthy app: a scaled app
    # reports **RunningAtMaxScale**, not 'Running'. The version block below has carried that
    # same filter for months and has been silently living on its `[?properties.active]`
    # FALLBACK -- which is why nobody noticed. Written this way, my first cut of this guard
    # resolved no revision, so it never armed, and the wrong workspace still produced six green
    # ticks. Caught only by deliberately re-running the gate against the WRONG workspace.
    $revJson = az containerapp revision list @smokeSub -n $App -g $ResourceGroup `
        --query "sort_by([?properties.active], &properties.createdTime)[-1].{name:name,created:properties.createdTime}" `
        -o json 2>$null
    if ($revJson) {
        $rev = ($revJson | ConvertFrom-Json)
        if ($rev -and "$($rev.name)".Trim()) { $activeRev = "$($rev.name)".Trim() }
        if ($rev -and "$($rev.created)".Trim()) {
            # 🪤 DateTimeOffset -> .UtcDateTime, on BOTH sides of the later comparison. az returns
            # '…T18:34:08+00:00' and Log Analytics returns '…T18:48:…Z'; parsed with
            # [datetime]::Parse these land in DIFFERENT kinds, and on this UTC+2 machine that alone
            # made a fresh deploy look 106 minutes stale -- a timezone bug wearing the costume of
            # the very defect this guard was written to catch.
            try { $activeRevCreated = ([datetimeoffset]::Parse("$($rev.created)", [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime } catch { }
        }
    }
} catch { }
Write-Host "`n-- A. boot logs (LA workspace $WorkspaceId) --" -ForegroundColor Cyan
$logRows = @()
# 🔴 TEST-16 -- ONE LINE, DELIBERATELY. Do not "tidy" this back into a here-string.
# On Windows `az` is **az.cmd**, and cmd.exe TRUNCATES an argument at the first newline. A
# multi-line --analytics-query therefore reached the service as just `ContainerAppConsoleLogs_CL`
# and every stage after it -- the 90-minute window, the app filter, the projection, the row cap
# -- was silently DISCARDED. Measured on 2026-08-30: the "last 90 minutes of ca-pim-manager"
# read returned 119,894 rows spanning the full retention of EVERY app and job in the workspace,
# with all 24 columns present despite the `project`, and a `take 4000` that plainly did not cap.
# 🔑 It failed OPEN, not shut: a broader result set still answers, so six assertions went green
#    over logs that were never scoped to this app or this deploy. A filter that is silently
#    dropped is worse than one that errors -- nothing in the output looked wrong.
# The whole query on ONE line survives cmd.exe intact; KQL does not care.
$kql = ("ContainerAppConsoleLogs_CL" +
        " | where TimeGenerated > ago(${LookbackMinutes}m)" +
        " | where ContainerAppName_s == '$App' or ContainerName_s == '$App'" +
        " | project TimeGenerated, Log_s" +
        " | order by TimeGenerated desc" +
        " | take 4000")
try {
    $raw = az monitor log-analytics query @smokeSub --workspace $WorkspaceId --analytics-query $kql -o json 2>$null
    if ($raw) { $logRows = @($raw | ConvertFrom-Json) }
} catch { }
$logText = ($logRows | ForEach-Object { "$($_.Log_s)" }) -join "`n"

if (-not $logRows -or $logRows.Count -eq 0) {
    S 'boot-log assertions' "no ContainerAppConsoleLogs_CL rows for '$App' in last ${LookbackMinutes}m (workspace access? app name? deployed?)"
} else {
    Write-Host ("  pulled {0} log rows" -f $logRows.Count) -ForegroundColor DarkGray
    # TEST-16 -- do these rows describe THIS deploy, or an old one?
    # The separation is the 30-minute threshold: LA ingestion lag is MINUTES, so rows whose
    # NEWEST entry predates the active revision by more than half an hour are not late -- they
    # are somebody else's. Lag must stay innocent (failing a healthy deploy is the exact
    # anti-pattern TEST-15 was raised for), while a wrong workspace must never assert.
    $bootRowsStale = $false
    $newestRow = $null
    try {
        $newestRow = ($logRows | ForEach-Object {
            # 🪤 The TWO sources carry time DIFFERENTLY and each needs its own handling:
            #   az revision createdTime -> '2026-08-30T18:34:08+00:00'  (explicit offset)
            #   LA TimeGenerated        -> '08/30/2026 18:52:16'        (UTC, but UNZONED)
            # DateTimeOffset on the unzoned one assumes LOCAL, which on this UTC+2 machine moved
            # the logs two hours into the past and made a fresh deploy look stale. AssumeUniversal
            # is what says "this string is already UTC"; AdjustToUniversal keeps it that way.
            try { [datetime]::Parse("$($_.TimeGenerated)", [Globalization.CultureInfo]::InvariantCulture,
                    ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)) } catch { }
        } | Sort-Object -Descending | Select-Object -First 1)
    } catch { }
    if ($newestRow -and $activeRevCreated) {
        $behindMin = [math]::Round(($activeRevCreated - $newestRow).TotalMinutes, 1)
        Write-Host ("  newest row {0:yyyy-MM-dd HH:mm}Z; active revision '{1}' created {2:yyyy-MM-dd HH:mm}Z" -f $newestRow, $activeRev, $activeRevCreated) -ForegroundColor DarkGray
        if ($behindMin -gt 30) {
            $bootRowsStale = $true
            Write-Host ("  ! the newest row is {0} minutes OLDER than the running revision -- these logs are not this deploy's." -f $behindMin) -ForegroundColor Red
            Write-Host ("    Almost always the WRONG WORKSPACE: pass -WorkspaceId for the workspace this Container Apps") -ForegroundColor DarkGray
            Write-Host ("    environment writes to, or omit it and let the gate derive it from the environment.") -ForegroundColor DarkGray
        }
    }
}
if ($logRows -and $logRows.Count -gt 0 -and $bootRowsStale) {
    # Not a pass and not a silent skip: the layer did not run, and in -AsReleaseGate mode S()
    # already converts that into a failure. Asserting these six against another revision's logs
    # is how a stale source produces six green ticks about a container that is not running.
    S 'boot-log assertions' "the workspace's newest '$App' row predates the running revision by more than 30 minutes -- these are an older revision's logs (wrong workspace?), so the startup assertions would describe a container that is not running"
}
if ($logRows -and $logRows.Count -gt 0 -and -not $bootRowsStale) {
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

    # ===== VERSION ASSERTION (LA-lag-resilient) =============================
    # The Manager emits a deterministic startup line at boot:
    #   "[version] PIM Manager v<X.Y.Z> (from VERSION)"
    # (Open-PimManager.ps1). Assert the LIVE served version EQUALS the EXPECTED
    # version (SOLUTIONS/PIM4EntraPS/VERSION). A stale/older live version means the
    # deploy did NOT actually roll the image -- HARD FAIL (the "stuck on 2.4.222"
    # symptom).
    #
    # WHY THIS IS NOT JUST A LOG-ANALYTICS READ:
    #   LA ingestion LAGS. Right after a container roll the new revision is live +
    #   healthy, but its boot "[version]" line has NOT yet landed in
    #   ContainerAppConsoleLogs_CL -- so a single LA read returns the PRIOR
    #   revision's version and FALSE-FAILS a healthy deploy (this happened on the
    #   2.4.229 roll). The fix:
    #     1) PRIMARY source = the ACTIVE revision's LIVE console logs via
    #        `az containerapp logs show --revision <active> --format text` -- NO
    #        ingestion lag, reflects the ACTUAL running replica.
    #     2) RETRY WITH BACKOFF so a slow-booting replica that has not logged its
    #        boot line yet is not a false fail either.
    #     3) FALLBACK = the LA boot rows already pulled above (still with retry),
    #        used only when live-log retrieval is unavailable.
    #   Integrity is preserved: a live container genuinely running the WRONG version
    #   after all retries STILL FAILS (Resolve-PimSmokeVersionCheck.Ok=$false), and
    #   absence of any version line is a FAIL, never a silent pass.

    # The ACTIVE revision was already resolved before section A -- TEST-16's freshness guard
    # needs it there. Rediscover ONLY if that failed. This block used to carry its own copy of
    # the query, complete with the `runningState=='Running'` clause that matches nothing on a
    # scaled app (it reports RunningAtMaxScale); it has therefore been living on the fallback
    # below for months without anyone noticing, because the fallback works.
    if (-not $activeRev) {
        # Fallback discovery: any active revision (older az / different shape).
        try { $activeRev = (az containerapp revision list @smokeSub -n $App -g $ResourceGroup --query "[?properties.active].name | [0]" -o tsv 2>$null) } catch {}
        if ($activeRev) { $activeRev = "$activeRev".Trim() }
    }

    # PRIMARY fetcher: live console logs of the active revision (no ingestion lag).
    # Returns $null when az can't fetch (then we fall back to LA below).
    $getLiveLog = {
        param($attempt)
        if (-not $activeRev) { return $null }
        $txt = $null
        try { $txt = az containerapp logs show -n $App -g $ResourceGroup --revision $activeRev --tail 200 --format text 2>$null } catch {}
        if ($txt -is [array]) { $txt = ($txt -join "`n") }
        return $txt
    }
    # FALLBACK fetcher: the LA boot rows (re-query each attempt so a late-ingesting
    # line can still arrive within the retry window).
    $getLaLog = {
        param($attempt)
        if ($attempt -gt 1) {
            try {
                $r2 = az monitor log-analytics query @smokeSub --workspace $WorkspaceId --analytics-query $kql -o json 2>$null
                if ($r2) { $rows2 = @($r2 | ConvertFrom-Json); return (($rows2 | ForEach-Object { "$($_.Log_s)" }) -join "`n") }
            } catch {}
        }
        return $logText   # first attempt reuses rows already pulled in section A
    }

    # Decide which source to use: prefer live logs if we resolved an active revision
    # AND a first probe actually returns text; otherwise fall back to LA (with retry).
    $useLive = $false
    if ($activeRev) {
        $probe = $null
        try { $probe = & $getLiveLog 1 } catch {}
        if ($probe) { $useLive = $true }
    }

    if ($useLive) {
        Write-Host ("  version source: LIVE console logs of active revision '{0}' (no LA lag)" -f $activeRev) -ForegroundColor DarkGray
        $verRes = Resolve-PimSmokeVersionCheck -GetLogText $getLiveLog -ExpectedVersion $ExpectedVersion -MaxAttempts 5 -DelaySeconds 15
    } else {
        $why = if ($activeRev) { "live console logs for revision '$activeRev' unavailable" } else { "could not resolve the active revision" }
        Write-Host ("  version source: Log Analytics fallback ({0}) -- retrying to absorb ingestion lag" -f $why) -ForegroundColor DarkYellow
        $verRes = Resolve-PimSmokeVersionCheck -GetLogText $getLaLog -ExpectedVersion $ExpectedVersion -MaxAttempts 5 -DelaySeconds 15
    }

    if ($verRes.Found) { Write-Host ("  served version: v{0} (expected v{1})" -f $verRes.Found, $ExpectedVersion) -ForegroundColor DarkGray }
    # 🔴 TEST-15 -- DO NOT ASSERT HERE. This reading can come from the Log Analytics FALLBACK,
    # which lags ingestion and has repeatedly returned a version several releases old. On
    # 2026-08-30 it failed THREE healthy deploys in a row: it reported v2.4.253 while the live
    # HTTP probe in section B read v2.4.258 off the running app and passed.
    # 🔑 A STALE SOURCE MUST NOT OVERRULE A LIVE ONE. The verdict is deferred to the end, where
    # both readings exist, and the LIVE one wins when it was obtained. Section B has not run
    # yet at this point, so the assertion cannot be made here at all.
    $script:VerBoot = $verRes
}

# =============================================================================
# B. Live HTTP behind Easy Auth (needs the Easy Auth audience to mint a token).
# =============================================================================
Write-Host "`n-- B. live HTTP (Easy Auth) --" -ForegroundColor Cyan

# Resolve the FQDN if not supplied (Container App ingress).
if (-not $Fqdn) {
    # BUG-102: @smokeSub, like every other az call here. Resolving the FQDN from the ambient
    # context finds the app in whatever directory happens to be default -- or, worse, finds a
    # SIMILARLY NAMED app in another tenant and probes that instead.
    try { $Fqdn = (az containerapp show @smokeSub -n $App -g $ResourceGroup --query properties.configuration.ingress.fqdn -o tsv 2>$null) } catch {}
    if (-not $Fqdn) { try { $Fqdn = (az webapp show @smokeSub -n $App -g $ResourceGroup --query defaultHostName -o tsv 2>$null) } catch {} }
}

# 🔴 BUG-126 -- IS THIS DEPLOYMENT REACHABLE OVER HTTP FROM HERE *BY DESIGN*?
# PIM's required placement is its own VNet with NO public inbound. On that topology the Container
# Apps FQDN resolves only INSIDE the VNet, so from a deploy host outside it there is no HTTP probe
# to make -- and §7a's "a skip is not a pass" turned that into a FAILED nightly update, forever, on
# a healthy deployment. Measured 2026-09-04 on the master: 7 of 8 assertions passed and the run
# still exited 1, every night. A gate that cries wolf nightly is one nobody reads, which is the
# same "emailed and ignored" outcome rule 7b exists to prevent -- reintroduced by a gate.
#
# 🔒 THIS IS NOT "A SKIP IS A PASS". Two things are POSITIVELY VERIFIED before the layer is
# downgraded, and both come from Azure or the network -- never from a probe that merely failed:
#   1. the Container Apps environment really is vnetConfiguration.internal = true, and
#   2. the FQDN really does not resolve from this host.
# Only both together mean "no flag or credential can make this run", which is exactly the bar N()
# documents for NOT-APPLICABLE. If the environment is EXTERNAL, or the name resolves (i.e. the gate
# is being run from inside the VNet, which is the right way to run it), nothing changes and an
# unrunnable probe is still a hard failure below.
#
# 🪤 And the downgrade is still conditional: N() degrades to S() -- a hard gate failure -- unless
# every compensating assertion named here PASSED in this same run. So a genuinely broken Manager
# still fails the gate; only the ROUTE to proving it changes, never whether it is proven.
$smokeEnvInternal = $null
try {
    $smokeEnvId = (az containerapp show @smokeSub -n $App -g $ResourceGroup --query properties.environmentId -o tsv 2>$null)
    if ("$smokeEnvId".Trim()) {
        $smokeEnvInternal = (az containerapp env show @smokeSub --ids "$smokeEnvId" --query properties.vnetConfiguration.internal -o tsv 2>$null)
    }
} catch { }
$smokeFqdnResolves = $false
if ("$Fqdn".Trim()) {
    try { $smokeFqdnResolves = ([bool]@([System.Net.Dns]::GetHostAddresses("$Fqdn")).Count) } catch { $smokeFqdnResolves = $false }
}
$smokeUnreachableByDesign = (("$smokeEnvInternal".Trim() -ieq 'true') -and (-not $smokeFqdnResolves))

if ($smokeUnreachableByDesign) {
    N 'live HTTP probes' `
      "the Container Apps environment is VNet-INTERNAL and '$Fqdn' does not resolve from this host -- PIM's required placement is no public inbound, so no flag or credential can make an HTTP probe reach it from outside the VNet" `
      -CoveredBy @(
          'boot log shows [store] SQL mode',
          'boot log does NOT show CSV/static store fallback',
          'boot log: render/page mode is SQL (not static read-only)',
          'boot log: no "engine SPN context" missing error',
          'boot log: tenant-list cache not "missing or empty"'
      )
} elseif (-not $EasyAuthAud) {
    S 'live HTTP probes' 'no Easy Auth audience (-EasyAuthAud / PIM_HOSTED_EASYAUTH_AUD) -- cannot mint a token through Easy Auth'
} elseif (-not $Fqdn) {
    S 'live HTTP probes' "could not resolve the app FQDN (-Fqdn / PIM_HOSTED_FQDN); is '$App' in '$ResourceGroup'?"
} else {
    $aadToken = $null
    # BUG-102: @smokeSub, not the ambient context. A token minted from whatever directory az
    # happens to default to is a token for the WRONG TENANT -- on mgmt1 that is routinely a
    # different company's -- and it surfaces here as the misleading "is this identity assigned
    # to the app?", i.e. as an RBAC problem rather than as the targeting problem it is. Same
    # shape as SEC-12, where an unscoped fallback returned an ExpertsLiveDK token while we
    # asked for myfamilynetwork. Every other az call in this script was already scoped; this
    # one was not.
    try { $aadToken = (az account get-access-token @smokeSub --resource $EasyAuthAud --query accessToken -o tsv 2>$null) } catch {}
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
                # TEST-15: this reading came from the RUNNING APP over HTTP. It is the
                # authoritative answer to "what version is deployed", and the deferred
                # boot-log verdict below defers to it.
                $script:VerLive = [pscustomobject]@{ Found = $servedVer; Ok = ($servedVer -eq $ExpectedVersion) }
            }
        }

        # 4: GUI read-WRITE for an admin role.
        $pa = $null
        try { $pa = Invoke-RestMethod -Uri "$base/api/portal-access" -Headers $api -TimeoutSec 30 } catch {}
        if ($pa) {
            T 'GUI read-write: managerRole != Reader' (("$($pa.managerRole)" -ne '') -and ("$($pa.managerRole)" -ne 'Reader'))
        } elseif (-not $SessionToken) {
            # TEST-10: no session token exists to be had behind Easy Auth (SEC-01 stopped
            # GET / handing one out). Not an input the operator can supply -> N/A, but only
            # because the store/render assertions below prove the GUI is in read-write SQL
            # mode rather than the static read-only viewer.
            N '/api/portal-access (GUI read-write)' `
              'browser-only behind hosted Easy Auth: the edge token and the app per-session GUID both want the single Authorization header' `
              -CoveredBy @('boot log: render/page mode is SQL (not static read-only)', 'boot log shows [store] SQL mode')
        } else {
            S '/api/portal-access' 'a -SessionToken WAS supplied but the endpoint did not respond'
        }

        # 3: tenant cache populated -- entra-roles non-empty.
        $tl = $null
        try { $tl = Invoke-RestMethod -Uri "$base/api/tenant-lists" -Headers $api -TimeoutSec 30 } catch {}
        if ($tl) {
            $entra = $tl.entraRoles
            T 'tenant cache populated: entra-roles non-empty' ($null -ne $entra -and @($entra.items).Count -gt 0)
        } elseif (-not $SessionToken) {
            # TEST-10: same construction problem. The boot log already asserts the tenant
            # cache is not "missing or empty", which is the condition this probe tests.
            N '/api/tenant-lists (tenant cache populated)' `
              'browser-only behind hosted Easy Auth (see /api/portal-access)' `
              -CoveredBy @('boot log: tenant-list cache not "missing or empty"')
        } else {
            S '/api/tenant-lists' 'a -SessionToken WAS supplied but the endpoint did not respond'
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
        } elseif (-not $SessionToken) {
            # TEST-10: browser-only behind hosted Easy Auth -- a script cannot present both
            # the Easy Auth edge token and the app session GUID in one Authorization header.
            # This was an S() (a hard FAIL under -AsReleaseGate), which meant EVERY deploy
            # exited non-zero even when the deployment was perfect -- and an always-red gate
            # is one an operator learns to ignore, the exact failure mode TEST-05 existed to
            # prevent. It is now N/A, CONDITIONAL on the section-A boot-log assertion that
            # tests the same thing (#47: the engine-SPN context resolved at startup). If that
            # assertion did not pass, N() degrades this back to a hard failure.
            N '/api/active-assignments (#47 engine-SPN context)' `
              ("browser-only behind hosted Easy Auth -- a programmatic caller cannot satisfy both the Easy Auth edge token and the app per-session GUID in one Authorization header (probe status=$aaStatus). To exercise /api directly, pass a fixed service token via -SessionToken or run against a non-Easy-Auth edge.") `
              -CoveredBy @('boot log: no "engine SPN context" missing error')
        } else {
            S '/api/active-assignments (#47 engine-SPN context)' `
              ("a -SessionToken WAS supplied but the probe did not return 200 (status=$aaStatus) -- this is a real failure, not the Easy Auth construction problem")
        }
    }
}

# =============================================================================
# 🔴 TEST-15 -- THE DEFERRED VERSION VERDICT. Two sources, and the LIVE one wins.
# =============================================================================
# The boot-log reading (section A) can come from the Log Analytics FALLBACK, which lags
# ingestion. On 2026-08-30 it FAILED THREE HEALTHY DEPLOYS in a row -- reporting v2.4.253 while
# the live HTTP probe read v2.4.258 off the running app and passed. A version several releases
# old is not a deploy failure, it is a stale read, and the gate could not tell the difference.
# 🔑 A gate that fails a healthy deployment is worse than no gate: it trains the operator to
# ignore it, and then it cannot warn about the real thing either. That is TEST-09's lesson
# again, one layer up.
# Rules, in order:
#   1. LIVE HTTP reading exists  -> it decides. The boot log is corroboration; a disagreement
#                                   is reported as INFORMATION (a stale log), never a failure.
#   2. No live reading           -> fall back to the boot log, which then decides as before.
#   3. Neither                   -> FAIL. A gate that could not read the version did not run,
#                                   and a gate that did not run is not a pass (CLAUDE.md s7a).
if ($ExpectedVersion) {
    $live = $script:VerLive
    $boot = $script:VerBoot
    if ($live) {
        if ($boot -and $boot.Found -and ("$($boot.Found)" -ne "$($live.Found)")) {
            Write-Host ("  note: the boot-log/Log-Analytics reading (v{0}) disagrees with the LIVE served version (v{1}). The LIVE reading decides; the log is behind ingestion, which is expected right after a roll and is NOT a deploy failure (TEST-16 has already ruled out the other explanation -- an older revision's rows from the wrong workspace)." -f $boot.Found, $live.Found) -ForegroundColor DarkYellow
        }
        T ("deployed version == VERSION (live reading v{0} is authoritative)" -f $live.Found) ([bool]$live.Ok)
    } elseif ($boot) {
        Write-Host '  note: no LIVE reading was obtained -- falling back to the boot-log version, which now decides.' -ForegroundColor DarkYellow
        T ("deployed version == VERSION (boot-log reading, no live probe available: {0})" -f $boot.Reason) ([bool]$boot.Ok)
    } else {
        # 🪤 A SELF-SKIP, not a hard failure -- and the difference matters. An ad-hoc run against
        # an app that does not exist (an engineer poking at it locally) must still exit 0; only
        # -AsReleaseGate turns a skip into a failure, which is exactly the convention this script
        # already uses everywhere else. My first cut asserted $false here and broke TEST-05's
        # "engineers keep the honest skip" -- caught by the suite that guards this very logic.
        S 'deployed version == VERSION' 'neither a live nor a boot-log reading could be obtained (app unreachable / no workspace / no Easy Auth audience)'
    }
}

Write-PimSmokeResult
if ($fail) { exit 1 }
exit 0   # explicit: without this a green run leaves $LASTEXITCODE at whatever ran last
