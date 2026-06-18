#Requires -Version 5.1
<#
.SYNOPSIS
    GUI <-> engine alignment check for the PIM Manager (REQUIREMENTS.md s11/s20).
    Static analysis -- no live tenant, no server boot.

.DESCRIPTION
    Two assertions keep the Manager honest as it grows:

      1. NO DEAD GUI -- every '/api/*' path the GUI calls via api('METHOD','/api/...')
         in tools/pim-manager/pim-manager.html MUST have a matching route handler in
         tools/pim-manager/Open-PimManager.ps1. A button wired to a non-existent
         endpoint is a dead control; this fails the build.

      2. ORPHAN-ENGINE REPORT -- server '/api/*' handlers that NO GUI call reaches are
         listed (informational). Some are intentional (boot-injected GETs reachable at
         page load, tooling/test-only endpoints); those live in $KnownNonGui so the list
         stays meaningful. A NEW orphan that isn't whitelisted fails, forcing a conscious
         decision: wire it into the GUI, or whitelist it with a reason.

    Run standalone (exits 0 green / 1 red) or via Run-AllPimTests.ps1 / PIM.Tests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$mgrDir   = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\pim-manager'
$htmlPath = Join-Path $mgrDir 'pim-manager.html'
$srvPath  = Join-Path $mgrDir 'Open-PimManager.ps1'
T 'pim-manager.html present'   (Test-Path -LiteralPath $htmlPath)
T 'Open-PimManager.ps1 present' (Test-Path -LiteralPath $srvPath)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }

$html = [System.IO.File]::ReadAllText($htmlPath)
$srv  = [System.IO.File]::ReadAllText($srvPath)

# --- 1. Collect the GUI's /api/* calls -----------------------------------------
# Matches api('GET', '/api/foo' ...) -- captures method + the first path literal.
# Dynamic suffixes (?refresh=1, + encodeURIComponent(...)) are normalised to the
# base path; that's what the server routes on.
$guiCalls = New-Object System.Collections.Generic.HashSet[string]
foreach ($m in [regex]::Matches($html, "api\(\s*'(GET|POST|PUT|DELETE)'\s*,\s*[`'`"``](/api/[A-Za-z0-9_\-/]+)")) {
    $method = $m.Groups[1].Value
    $path   = $m.Groups[2].Value
    # A path literal ending in '/' is a base for string concatenation
    # ('/api/csv/' + encodeURIComponent(base)) -- normalise to a concrete segment
    # so it matches the server's parameterised route ^/api/csv/[\w.-]+$.
    if ($path.EndsWith('/')) { $path += 'X' }
    [void]$guiCalls.Add("$method $path")
}
# active-assignments is built as a variable ('/api/active-assignments' + qs) -- catch it.
if ($html -match "'/api/active-assignments'") { [void]$guiCalls.Add('GET /api/active-assignments') }
# Direct fetch('/api/...') calls are ALSO real GUI callers (some panels bypass the
# api() helper to read the raw {error,hint}+status body -- e.g. Role Lookup, which
# needs the 503 body to show a clean connect+retry panel instead of api()'s thrown
# string). Default method is GET unless a method:'POST'|... option is present. Treat
# them identically to api() calls so they neither look DEAD nor orphan their handler.
foreach ($m in [regex]::Matches($html, "fetch\(\s*[`'`"``](/api/[A-Za-z0-9_\-/]+)")) {
    $path = $m.Groups[1].Value
    if ($path.EndsWith('/')) { $path += 'X' }
    # Look just past the fetch() call for an options-object method; default GET.
    $tail = $html.Substring($m.Index, [Math]::Min(200, $html.Length - $m.Index))
    $method = if ($tail -match "method\s*:\s*[`'`"``](GET|POST|PUT|DELETE)") { $Matches[1] } else { 'GET' }
    [void]$guiCalls.Add("$method $path")
}
T 'GUI api()/fetch() calls discovered (>= 20)' ($guiCalls.Count -ge 20)

# --- 2. Collect the server's route handlers ------------------------------------
# Forms used in Open-PimManager.ps1:
#   if ($path -eq '/api/foo' -and $method -eq 'GET')
#   if ($path -like '/api/active-assignments*' -and $method -eq 'GET')
#   if ($path -match '^/api/diff/([\w\.-]+)$' -and $method -eq 'POST')
#   inside the conformance block: nested -eq handlers + a -like '/api/conformance*' gate
#   the csv handler is method-branched inside one -match block (GET/PUT)
$routes = New-Object System.Collections.Generic.List[object]
function Add-Route($method, $matcher) { $script:routes.Add([pscustomobject]@{ method = $method; matcher = $matcher }) }

foreach ($m in [regex]::Matches($srv, "\`$path\s+-eq\s+'(/api/[^']+)'\s+-and\s+\`$method\s+-eq\s+'(GET|POST|PUT|DELETE)'")) {
    Add-Route $m.Groups[2].Value ('^' + [regex]::Escape($m.Groups[1].Value) + '$')
}
foreach ($m in [regex]::Matches($srv, "\`$path\s+-like\s+'(/api/[^']+)'\s+-and\s+\`$method\s+-eq\s+'(GET|POST|PUT|DELETE)'")) {
    Add-Route $m.Groups[2].Value ('^' + [regex]::Escape($m.Groups[1].Value).Replace('\*', '.*') + '$')
}
foreach ($m in [regex]::Matches($srv, "\`$path\s+-match\s+'(\^/api/[^']+)'\s+-and\s+\`$method\s+-eq\s+'(GET|POST|PUT|DELETE)'")) {
    Add-Route $m.Groups[2].Value $m.Groups[1].Value
}
# The csv/data handler branches method INSIDE a single -match block (one regex,
# then `if ($method -eq 'GET')` / `if ($method -eq 'PUT')` inside): the per-verb
# loops above don't see it, so register both verbs explicitly when present.
if ($srv -match '/api/\(\?:csv\|data\)/\(\[\\w\\\.-\]\+\)') {
    $csvMatcher = '^/api/(csv|data)/[\w\.-]+$'
    Add-Route 'GET' $csvMatcher
    Add-Route 'PUT' $csvMatcher
}
T 'server route handlers discovered (>= 25)' ($routes.Count -ge 25)

# A GUI call to a templated/segment path (e.g. '/api/settings/' + section, which the
# collector normalises to '/api/settings/X') must match a server handler defined as a
# REGEX-ALTERNATION or CAPTURE-GROUP route (e.g. ^/api/settings/(naming|filters|...)$ or
# ^/api/csv/([\w.-]+)$). A literal '$path -match $matcher' fails because the placeholder
# 'X' is not one of the alternatives. Test-PathMatchesRoute first tries the exact matcher,
# then -- only when the GUI path carries the dynamic-segment placeholder -- relaxes the
# route's alternation/capture groups to a single-segment wildcard and retries, so the
# matcher understands alternation/segment routes instead of needing a whitelist entry.
function Get-RouteSegmentRegex($matcher) {
    # Turn ([...]+) capture groups and (a|b|c) alternations into a single-segment token.
    $m = $matcher
    $m = [regex]::Replace($m, '\((?:\?:)?\[[^\]]+\]\+\)', '[^/]+')      # ([\w.-]+) etc.
    $m = [regex]::Replace($m, '\((?:\?:)?[A-Za-z0-9_|\-]+\)', '[^/]+')  # (naming|filters|...) etc.
    return $m
}
function Test-PathMatchesRoute($path, $matcher) {
    if ($path -match $matcher) { return $true }
    # GUI templated segment: the collector marks a dynamic trailing segment with 'X'.
    if ($path -match '/X(/|$)') {
        $relaxed = Get-RouteSegmentRegex $matcher
        if ($relaxed -ne $matcher) {
            # Replace the GUI 'X' placeholder with a concrete probe segment, then test it
            # against the relaxed (alternation/capture -> single-segment) route regex.
            $guiProbe = ($path -replace '/X(?=/|$)', '/Zsegment')
            if ($guiProbe -match $relaxed) { return $true }
        }
    }
    return $false
}

function Test-RouteExists($method, $path) {
    foreach ($r in $routes) {
        if ($r.method -ne $method) { continue }
        if (Test-PathMatchesRoute $path $r.matcher) { return $true }
    }
    return $false
}

# --- 3. DEAD GUI: every GUI call must resolve to a handler ----------------------
$dead = New-Object System.Collections.Generic.List[string]
foreach ($call in $guiCalls) {
    $parts  = $call.Split(' ', 2)
    $method = $parts[0]; $path = $parts[1]
    if (-not (Test-RouteExists $method $path)) { $dead.Add($call) }
}
if ($dead.Count) { Write-Host "    DEAD GUI (no backing handler):" -ForegroundColor Red; $dead | ForEach-Object { Write-Host "      $_" -ForegroundColor Red } }
T 'NO DEAD GUI -- every api() call has a route handler' ($dead.Count -eq 0)

# --- 4. ORPHAN ENGINE: server handlers no GUI call reaches ----------------------
# Whitelisted non-GUI endpoints (with the reason they need no GUI call):
$KnownNonGui = @{
    'GET /api/heartbeat'           = 'liveness only (GUI POSTs it)'
    'GET /api/naming-conventions'  = 'boot-injected (PIM_NAMING_BOOT); tooling/test reads'
    'GET /api/access'              = 'boot-injected (PIM_ROLE_BOOT); tooling/test reads'
    'GET /api/instances'           = 'boot-injected (PIM_INSTANCES_BOOT); tooling/test reads'
    'GET /api/data'                = 'alias of /api/csv (GUI uses csv)'
    'PUT /api/data'                = 'alias of /api/csv (GUI uses csv)'
    # NOTE 2026-06-15: /api/wizard/derive is now WIRED into the GUI -- the new
    # target-first "Create Resource Delegation" wizard + the admin-name live
    # preview / Finish path call POST /api/wizard/derive (Get-PimWizardDerivation)
    # so GUI and engine derive identically. Removed from this allowlist; the
    # alignment check now proves it stays reachable from the front-end.
    # NOTE 2026-06-17: /api/conformance/promote is now WIRED into the GUI -- the
    # Template Rollout tab's per-entry matrix has a SuperAdmin ring <select> that
    # calls POST /api/conformance/promote (confPromote -> Set-PimEntryRing). Removed
    # from this allowlist; the alignment check now proves it stays reachable.
    # The Delegation Map renders CLIENT-SIDE from the baked engine model (PIM_DATA),
    # so its search + risk overlay compute in-page via the JS mirror of PIM-MapRisk.ps1
    # (computeMapRisk/mapSearchResults) for instant interactivity -- same pattern as the
    # rest of the map. These endpoints are the SERVER-AUTHORITATIVE parity API over the
    # same pure lib (engine-backed, used by tests); the GUI does not need to round-trip.
    'GET /api/map-risk'             = 'KNOWN ORPHAN: server-authoritative parity API for the map risk overlay; GUI computes in-page from baked engine data via the PIM-MapRisk JS mirror (REQUIREMENTS.md s28 [M8]).'
    'GET /api/map-search'           = 'KNOWN ORPHAN: server-authoritative parity API for the map search; GUI computes in-page from baked engine data via the PIM-MapRisk JS mirror (REQUIREMENTS.md s28 [M8]).'
    # Licensing is DELIBERATELY kept out of the customer-facing GUI (policy: every
    # feature is available to the customer -- no nag, no edition badge, no "upgrade to
    # Pro"). The endpoint exists for tooling/diagnostics only; intentionally GUI-less.
    'GET /api/license'             = 'INTENTIONAL GUI-LESS: licensing kept out of the customer GUI by policy (no nag/edition badge); tooling/diagnostics only.'
    # The Overrule WRITE (POST /api/warning-overrides) IS wired (Validate-tab
    # Overrule button -> overruleFinding). The GET is a read-only diagnostics/
    # tooling surface (lists current acknowledgements); the GUI reflects ack
    # state from the preflight report itself, so the GET has no GUI caller.
    'GET /api/warning-overrides'   = 'INTENTIONAL GUI-LESS: read-only ack-store listing for tooling/tests; GUI shows ack state from the preflight report. The WRITE (POST) is wired to the Validate-tab Overrule button.'
    # The Delegation Map workload-target chips badge their recon status from the
    # BAKED engine model (PIM_DATA, server-stamped reconStatus) -- same pattern as
    # map-risk/map-search. GET /api/workload-crawl is the server-authoritative
    # parity read of the raw crawl map for tooling/tests/scheduler; the GUI does
    # not round-trip it. The GUI DOES call GET /api/workload-recon (summary, wired
    # to the "Workload recon" map button) and POST /api/workload-crawl (admin
    # "Re-crawl now"), so those write/summary paths stay proven.
    'GET /api/workload-crawl'      = 'KNOWN ORPHAN: server-authoritative parity read of the raw workload crawl map; GUI badges from baked PIM_DATA + uses GET /api/workload-recon (summary) and POST /api/workload-crawl (re-crawl).'
    # The Governance "Permission templates" panel reads each pack''s disabled state
    # from the annotated GET /api/templates (which carries a `disabled` field); the
    # dedicated GET /api/template-state is for tooling/tests. The GUI DOES call
    # PUT /api/template-state (the active/disabled toggle), so the write path is wired.
    'GET /api/template-state'      = 'state surfaced via GET /api/templates (disabled field); GUI uses PUT to toggle. Tooling/test reads.'
    # Remaining pending-GUI orphan: handler exists + tested, no GUI surface YET.
    # Has a corresponding (BOX) item in REQUIREMENTS.md s11 to build its panel.
    # NOTE 2026-06-15: cutover (GET+POST), authoring/*, onboarding/*, and
    # role-permissions were WIRED into the GUI (Cutover / Authoring / Onboarding /
    # Role Lookup panels) and REMOVED from this allowlist -- the alignment check
    # now proves they stay reachable from the front-end.
}
# portal-access IS now reached by the GUI (Governance "Your access" panel). It is
# intentionally NOT whitelisted, so the alignment check proves it stays wired.

$orphans = New-Object System.Collections.Generic.List[string]
$seen    = New-Object System.Collections.Generic.HashSet[string]
foreach ($r in $routes) {
    # Build a representative concrete path for the matcher so we can compare to GUI calls.
    $sample = $r.matcher.TrimStart('^').TrimEnd('$')
    $sample = $sample -replace '\(\\\?\|&\).*$', ''           # strip optional query alternations
    $sample = $sample -replace '\.\*$', ''                     # -like '*' tail
    $sample = $sample -replace '\(csv\|data\)', 'csv'          # alias group
    $sample = $sample -replace '\(\[[^\]]+\]\+\)|\[[^\]]+\]\+', 'X'  # capture groups -> token
    $sample = $sample -replace '\((?:\?:)?[A-Za-z0-9_|\-]+\)', 'X'   # alternation groups -> token
    $sample = $sample -replace '\\', ''                        # unescape
    $key = "$($r.method) $sample"
    if (-not $seen.Add($key)) { continue }
    # Is this route reached by any GUI call?
    $reached = $false
    foreach ($call in $guiCalls) {
        $p = $call.Split(' ', 2); if ($p[0] -ne $r.method) { continue }
        if (Test-PathMatchesRoute $p[1] $r.matcher) { $reached = $true; break }
    }
    if (-not $reached) { $orphans.Add($key) }
}

Write-Host "`n  --- ORPHAN ENGINE report (server routes with no GUI caller) ---" -ForegroundColor Cyan
$unexpected = New-Object System.Collections.Generic.List[string]
foreach ($o in ($orphans | Sort-Object)) {
    # Normalise the csv-alias 'data' sample key for whitelist lookup.
    $look = $o
    if ($KnownNonGui.ContainsKey($look)) {
        Write-Host ("    [known] {0}  -- {1}" -f $look, $KnownNonGui[$look]) -ForegroundColor DarkGray
    } else {
        Write-Host ("    [NEW]   {0}" -f $look) -ForegroundColor Yellow
        $unexpected.Add($look)
    }
}
if (-not $orphans.Count) { Write-Host "    (none)" -ForegroundColor DarkGray }
T 'no UNEXPECTED orphan engine endpoints (whitelist or wire new ones)' ($unexpected.Count -eq 0)

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
