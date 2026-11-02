#Requires -Version 5.1
<#
.SYNOPSIS
  APIDOC-1 -- the PIM Manager's API + MCP reference, built from the code. Library: dot-sourced by
  tools/setup/New-PimApiReference.ps1 (the release hand-over) AND by the Manager itself (Settings > API and MCP reference,
  GET /api/api-reference -- the FULL reference of the running version, filtered to the signed-in person's role).

.DESCRIPTION
  Routes  every route the router serves, read from the code (never a hand-kept list):
          Handle-Request in Open-PimManager.ps1 (if / elseif clauses on $path, switch ($path) tables) and the router modules
          tools/pim-manager/_*.ps1 ('METHOD /path' switch tables, $Path conditions, switch ("$Path") tables).
          Per route: method, OpenAPI path, x-role = the role gate its body checks first (followed into the functions the body
          calls, e.g. the moved Invoke-PimManagerGetRoute* / Invoke-PimManagerPostRoute* bodies, and combined with the gate of
          an enclosing prefix block), the Pro feature it checks, and x-internal (page mechanics).
          A prefix handler ('/api/x*') that only dispatches to the routes inside it is NOT a route of its own.
  Profiles
          Full    every route + every MCP tool (the signed-in Manager page; never handed over).
          Public  the hand-over to invardia.com (owner 2026-11-01: "dont expose ways a hacker can gain access to customer";
                  framework APIDOC-1 item 6). DENY BY DEFAULT: a route is public ONLY when it is on the explicit allow-list
                  below AND matches none of the left-out classes AND its text carries none of Invardia's import words.
                  A new route is therefore left out until somebody classifies it public here.
  Summaries come ONLY from tools/pim-manager/api-descriptions.json (curated) -- never from code comments.
#>

$script:PimApiRefRank = @{ None = -1; Reader = 0; Delegated = 0; Demo = 0; Admin = 1; SuperAdmin = 2 }

# ======================================================================================================== PUBLIC PROFILE
# LOCKED: the classification is a REVIEWED list. Change it here, nowhere else; Test-PimApiReference fails on a public entry that
# is not a route, or that also matches a left-out class.
#
# Left-out classes ('METHOD glob', METHOD may be *). First matching class names the reason in the counts.
$script:PimApiRefLeftOutClasses = [ordered]@{
    'page-internal'      = @('* /api/heartbeat', '* /api/instance*', '* /api/list-layouts*', '* /api/get-started*', '* /api/wizard/*', '* /api/diff*',
                             '* /api/reports-overview*', '* /api/refresh-tenant-lists', '* /api/authoring*', '* /api/onboarding*', '* /api/demo-data*',
                             '* /api/resolve-date', '* /api/config', '* /api/csv/*', '* /api/data/*', '* /api/export*', '* /api/*{path}*',
                             '* /api/api-reference', 'POST /api/scheduler/kick')
    'emergency'          = @('* /api/emergency*', '* *break-glass*', '* *breakglass*', '* *restore*', '* /api/revoke', '* /api/admin-sessions*',
                             '* /api/admin-tap*', '* /api/reconcile/pause', '* /api/reconcile/resume')
    'backup'             = @('* *backup*', '* /api/settings/export', '* /api/settings/import')
    'support-diagnostics'= @('* /api/support*', '* *diagnostic*', '* *bundle*', '* *ticket*', '* /api/permissions-health*')   # what the engine identity can / cannot do = a map; signed-in only
    'credentials'        = @('* *api-key*', '* *apikey*', '* *token*', '* *secret*', '* *passphrase*', '* *certificate*', '* *credential*',
                             '* *sign-in*', '* *signin*', '* *login*', '* *auth*', '* /api/signed-requests*', '* /api/settings/mail*', '* /api/activator*')
    'security-settings'  = @('* /api/access', '* /api/access-map*', '* /api/portal-access*', '* /api/settings*', '* /api/license*', '* /api/rfa/settings',
                             '* /api/msp*', '* /api/downlink*', '* /api/update-ring*', '* /api/alerting*', '* /api/mail-notifications*', '* /api/mail-template*',
                             'PUT /api/job-schedule', '* /api/jobs/state', '* /api/drift/settings', 'PUT /api/discovery-policy', 'PUT /api/access-review-rules',
                             'PUT /api/policy-choices', '* /api/policy-templates/*', 'PUT /api/workload-exemptions', 'PUT /api/template-state',
                             'POST /api/warning-overrides', '* /api/reports/management/settings', '* /api/feature*', '* /api/security*',
                             'POST /api/access-reviews/reviewers', 'POST /api/coverage/ignore', 'PUT /api/drift/ignore', 'POST /api/custom-workloads',
                             'POST /api/hybrid-ad/discovery/preview')
    'destructive-tier0'  = @('DELETE *', '* /api/drift/remediate', '* /api/drift/group-delete', '* /api/hybrid-ad/cleanup*', '* /api/guards/*/release*',
                             '* /api/guards/*/approval*', '* /api/guards/strict/*', '* /api/guards/*/limit', '* /api/admin-accounts/*', 'POST /api/unmanaged-admins/*',
                             '* /api/unmanaged-admins/import', '* /api/custom-workloads/delete', '* /api/custom-workloads/import', '* /api/engine/*', '* /api/rfa/override',
                             '* /api/approvals/execute', '* /api/conformance/deploy', '* /api/conformance/promote', '* /api/conformance/approve',
                             'POST /api/conformance/exemptions*', '* /api/groups/adopt*', '* /api/hybrid-ad/server-groups/approve', '* /api/hybrid-ad/waiting/decide',
                             '* /api/discovery-baseline', '* *purge*', '* *wipe*', '* *reset*', '* *tier-0*', '* *tier0*')
}
# Routine routes the public reference carries (exact 'METHOD /path'). Everything else is left out.
$script:PimApiRefPublicRoutes = @(
    'GET /api/access-report/who-can', 'GET /api/access-report/who-has',
    'GET /api/access-review-campaigns', 'POST /api/access-review-campaigns/decide', 'GET /api/access-review-rules',
    'GET /api/access-reviews', 'POST /api/access-reviews/decision', 'GET /api/access-reviews/evidence', 'GET /api/access-reviews/overdue',
    'POST /api/access-reviews/reminders',
    'GET /api/account-states', 'GET /api/active-assignments', 'GET /api/admin-accounts', 'GET /api/admin-templates', 'GET /api/alerts',
    'GET /api/approvals', 'POST /api/approvals', 'POST /api/approvals/decide',
    'GET /api/asbuilt', 'GET /api/asbuilt/pdf', 'GET /api/attention', 'GET /api/audit', 'GET /api/audit/export',
    'POST /api/autoextend/decide', 'GET /api/autoextend/upcoming',
    'GET /api/commit-history', 'GET /api/commit-history/{p1}', 'GET /api/commit-status/{p1}', 'GET /api/commits',
    'GET /api/company-reviews', 'POST /api/company-review/answer',
    'GET /api/conformance', 'GET /api/conformance/exemptions', 'GET /api/conformance/fleet', 'GET /api/conformance/ring-plan', 'GET /api/conformance/templates',
    'GET /api/coverage', 'POST /api/coverage/check',
    'GET /api/custom-workloads', 'GET /api/custom-workloads/export', 'GET /api/directory/groups', 'GET /api/directory/people',
    'GET /api/discovered-resources', 'GET /api/discovery-inbox', 'POST /api/discovery-decisions', 'GET /api/discovery-policy',
    'GET /api/docs', 'GET /api/docs/page', 'GET /api/drift', 'GET /api/engine-failures', 'GET /api/environment-report',
    'GET /api/group-states', 'GET /api/guards', 'GET /api/home', 'GET /api/hybrid-ad/live', 'GET /api/hybrid-ad/server-groups/waiting', 'GET /api/hybrid-ad/waiting',
    'GET /api/impact', 'GET /api/job-schedule', 'POST /api/job-schedule/run-now',
    'GET /api/jobs', 'POST /api/jobs/run', 'POST /api/jobs/cancel', 'POST /api/jobs/ack', 'GET /api/jobs/history', 'GET /api/jobs/log',
    'GET /api/map-risk', 'GET /api/map-search', 'GET /api/naming-conventions',
    'POST /api/owner/extend', 'POST /api/owner/keep', 'POST /api/owner/remove', 'GET /api/owner/people',
    'GET /api/pending', 'PUT /api/pending/{p1}', 'POST /api/pending-discard', 'POST /api/pending-discard-all',
    'GET /api/policy-choices', 'GET /api/policy-templates', 'GET /api/preflight', 'POST /api/preflight',
    'GET /api/queue', 'POST /api/queue/commit', 'POST /api/queue/discard', 'GET /api/reconcile/state',
    'GET /api/reports/management', 'GET /api/reports/management/latest',
    'GET /api/rfa/requests', 'POST /api/rfa/decide', 'POST /api/rfa/end',
    'GET /api/role-lookup/compare', 'GET /api/role-lookup/reverse', 'GET /api/role-permissions', 'GET /api/role-permissions/by-action',
    'GET /api/search', 'GET /api/template-state', 'GET /api/templates', 'GET /api/tenant-lists', 'GET /api/tier-impact', 'GET /api/unmanaged-admins',
    'GET /api/warning-overrides', 'GET /api/workload-crawl', 'POST /api/workload-crawl', 'GET /api/workload-exemptions', 'GET /api/workload-prereqs',
    'POST /api/workload-prereqs/confirm', 'GET /api/workload-recon',
    'GET /api/workload-roles', 'GET /api/workloads'
)
# MCP tools the public reference carries (by name). Their route, when they name one, must be a public route too.
$script:PimApiRefPublicMcpTools = @(
    'whoami', 'who_can', 'who_has', 'search', 'role_lookup', 'tier_impact', 'coverage', 'drift', 'guards', 'problems',
    'approvals', 'approval_decide', 'access_reviews', 'access_review_decide', 'access_review_campaigns', 'access_review_campaign_decide',
    'autoextend_upcoming', 'autoextend_decide', 'owner_reviews', 'owner_review_extend', 'owner_review_keep', 'owner_review_remove',
    'jobs_status', 'job_history', 'job_log', 'job_run', 'job_cancel', 'job_run_now_scheduled',
    'active_assignments', 'environment_report', 'unmanaged_admins', 'access_requests', 'audit_search',
    'list_rows', 'pending_changes', 'stage_change', 'discard_staged', 'commit_staged', 'commit_status',
    # routine reads + the two access-request decisions (2026-11-01 review); NOT here on purpose: config_backups (backup),
    # permissions_health (the install's own permissions), managed_tenants / managed_tenant_reach (MSP), reconcile_pause /
    # reconcile_resume (engine control)
    'conformance_templates', 'conformance', 'conformance_exemptions', 'conformance_fleet', 'conformance_ring_plan',
    'role_permissions', 'role_permissions_by_action', 'role_compare', 'commit_history', 'commit_history_detail',
    'access_request_decide', 'access_request_end'
)
# Invardia's import guard (2026-11-01): a hand-over whose public path, summary, description, tool name or tool text carries
# one of these is refused. Applied on top of the classification: an operation or tool whose text matches is left out.
$script:PimApiRefForbiddenWords = '(?i)emergency|break-?glass|restore|backup|support|bundle|diagnostic|api-?key|secret|passphrase|certificate|credential|token|sign-?in|login|auth|security|tier[- ]?0|purge|wipe|reset'
$script:PimApiRefPublicSignInText = 'Sign in to your PIM Manager; your PIM Manager role decides what each route allows'
$script:PimApiRefInternal = @('/api/heartbeat', '/api/instance', '/api/list-layouts', '/api/get-started', '/api/wizard/', '/api/diff', '/api/reports-overview',
                              '/api/activator/build', '/api/activator/edge-policy', '/api/support/ticket/draft', '/api/refresh-tenant-lists')

function Get-PimApiRefPolicy {
    <# PURE. The public-profile lists, for the gate and the README. #>
    [ordered]@{ leftOutClasses = $script:PimApiRefLeftOutClasses; publicRoutes = @($script:PimApiRefPublicRoutes)
                publicMcpTools = @($script:PimApiRefPublicMcpTools); forbiddenWords = $script:PimApiRefForbiddenWords; signInText = $script:PimApiRefPublicSignInText }
}

function Get-PimApiRefLeftOutClass {
    <# PURE. The first left-out class 'METHOD /path' matches, or '' (no class). x-internal counts as page-internal. #>
    param([string]$Method, [string]$Path, [bool]$Internal = $false)
    if ($Internal) { return 'page-internal' }
    foreach ($cls in $script:PimApiRefLeftOutClasses.Keys) {
        foreach ($pat in @($script:PimApiRefLeftOutClasses[$cls])) {
            $pm, $pp = $pat -split ' ', 2
            if (($pm -eq '*' -or $pm -eq $Method) -and ($Path -like $pp)) { return $cls }
        }
    }
    return ''
}

function Test-PimApiRefForbiddenText {
    <# PURE. True when the text carries one of Invardia's import words. #>
    param([AllowEmptyString()][string]$Text)
    return [bool]("$Text" -match $script:PimApiRefForbiddenWords)
}

# ======================================================================================================== ROUTES FROM CODE
function Split-PimApiRefTopLevel {
    # split a regex at top-level '|' (outside groups and classes)
    param([string]$S)
    $parts = New-Object System.Collections.Generic.List[string]; $depth = 0; $inCls = $false; $cur = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $S.Length; $i++) {
        $c = $S[$i]
        if ($c -eq '\' -and $i + 1 -lt $S.Length) { [void]$cur.Append($c).Append($S[$i + 1]); $i++; continue }
        if ($inCls) { if ($c -eq ']') { $inCls = $false }; [void]$cur.Append($c); continue }
        if ($c -eq '[') { $inCls = $true } elseif ($c -eq '(') { $depth++ } elseif ($c -eq ')') { $depth-- }
        elseif ($c -eq '|' -and $depth -eq 0) { $parts.Add($cur.ToString()); [void]$cur.Clear(); continue }
        [void]$cur.Append($c)
    }
    $parts.Add($cur.ToString())
    return , $parts.ToArray()
}

function Expand-PimApiRefRegex {
    # a route regex -> the plain paths it serves (an optional part = both variants; a class / capture of a class = one
    # parameter, written as the marker char 1 and numbered later). $null when it is not a plain path.
    param([string]$S)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($part in (Split-PimApiRefTopLevel -S $S)) {
        $tokens = New-Object System.Collections.Generic.List[object]
        $i = 0
        while ($i -lt $part.Length) {
            $c = $part[$i]
            if ($c -eq '^' -or $c -eq '$') { $i++; continue }
            if ($c -eq '\') {
                $n = $part[$i + 1]
                if ("$n" -cmatch '^[dDwWsS]$') { $tokens.Add(@([string][char]1)) } else { $tokens.Add(@([string]$n)) }
                $i += 2; continue
            }
            if ($c -eq '[') {
                $j = $i + 1; if ($j -lt $part.Length -and $part[$j] -eq ']') { $j++ }
                while ($j -lt $part.Length -and $part[$j] -ne ']') { if ($part[$j] -eq '\') { $j++ }; $j++ }
                $tokens.Add(@([string][char]1)); $i = $j + 1; continue
            }
            if ($c -eq '(') {
                $depth = 0; $j = $i; $inCls = $false
                for (; $j -lt $part.Length; $j++) {
                    $d = $part[$j]
                    if ($d -eq '\') { $j++; continue }
                    if ($inCls) { if ($d -eq ']') { $inCls = $false }; continue }
                    if ($d -eq '[') { $inCls = $true } elseif ($d -eq '(') { $depth++ } elseif ($d -eq ')') { $depth--; if ($depth -eq 0) { break } }
                }
                $inner = $part.Substring($i + 1, $j - $i - 1)
                if ($inner.StartsWith('?:')) { $inner = $inner.Substring(2) } elseif ($inner.StartsWith('?')) { return $null }
                $sub = Expand-PimApiRefRegex -S $inner
                if ($null -eq $sub) { return $null }
                $tokens.Add(@($sub)); $i = $j + 1; continue
            }
            if ($c -eq '.') { $tokens.Add(@([string][char]1)); $i++; continue }
            if ($c -eq '*' -or $c -eq '+' -or $c -eq '{') {
                # a count on a parameter is still one parameter; on a literal it is a pattern, not a path
                $last = if ($tokens.Count) { $tokens[$tokens.Count - 1] } else { $null }
                if (-not $last -or @($last).Count -ne 1 -or "$(@($last)[0])" -ne [string][char]1) { return $null }
                if ($c -eq '{') { $j = $part.IndexOf('}', $i); if ($j -lt 0) { return $null }; $i = $j + 1 } else { $i++ }
                continue
            }
            if ($c -eq '?') {
                if (-not $tokens.Count) { return $null }
                $tokens[$tokens.Count - 1] = @(@($tokens[$tokens.Count - 1]) + '')
                $i++; continue
            }
            if ($c -eq ')' -or $c -eq '|') { return $null }
            $tokens.Add(@([string]$c)); $i++
        }
        $acc = @('')
        foreach ($t in $tokens) { $next = New-Object System.Collections.Generic.List[string]; foreach ($a in $acc) { foreach ($v in @($t)) { $next.Add("$a$v") } }; $acc = $next.ToArray() }
        foreach ($a in $acc) { $out.Add($a) }
    }
    return , $out.ToArray()
}

function ConvertTo-PimApiRefPaths {
    <# A route condition's path -> OpenAPI paths. -Op eq | like | match. A 'like' prefix answers @{ prefix = base; sub = $true when
       it ends in '/*' }. #>
    param([string]$Op, [string]$Value)
    if ($Op -eq 'eq' -or $Op -eq 'in') { return @{ paths = @($Value); prefix = $null } }
    if ($Op -eq 'like') {
        if ($Value -eq '/api/*') { return @{ paths = @(); prefix = $null } }
        $b = (($Value -replace '\*$', '') -replace '/$', '')
        return @{ paths = @(); prefix = @{ base = $b; sub = [bool]($Value -match '/\*$') } }
    }
    if ($Op -eq 'match') {
        $ex = Expand-PimApiRefRegex -S $Value
        if ($null -eq $ex) { return @{ paths = @(); prefix = $null } }
        $res = @()
        foreach ($p in $ex) {
            # adjacent parameter parts ([a-z0-9][a-z0-9.-]{0,99}) are ONE parameter; each path numbers its own from 1
            $p = [regex]::Replace($p, "$([char]1)+", [string][char]1)
            $sb = New-Object System.Text.StringBuilder; $n = 0
            foreach ($ch in $p.ToCharArray()) { if ($ch -eq [char]1) { $n++; [void]$sb.Append('{p' + $n + '}') } else { [void]$sb.Append($ch) } }
            $res += $sb.ToString()
        }
        return @{ paths = @($res | Where-Object { $_ -like '/api/*' -and $_ -notmatch '[\\\[\]\(\)\*\+\|\^\$]' } | Select-Object -Unique); prefix = $null }
    }
    return @{ paths = @(); prefix = $null }
}

function Get-PimApiRefRoleFromText {
    # the role a gate expression names: @{ role; unresolved }
    param([string]$Text, [hashtable]$VarMap)
    $m = [regex]::Match($Text, "Test-PimManagerRoleAtLeast\s+(-Minimum\s+)?'(\w+)'")
    if ($m.Success) { return @{ role = $m.Groups[2].Value; unresolved = $false } }
    if ($Text -match 'Test-PimManagerRoleAtLeast') { return @{ role = ''; unresolved = $true } }
    $t = $Text.Trim().TrimStart('(').TrimEnd(')').Trim()
    if ($t -match '^\$(\w+)\.(super|isSuper|superAdmin)$') { return @{ role = 'SuperAdmin'; unresolved = $false } }
    if ($t -match '^\$(\w+)\.(admin|isAdmin)$') { return @{ role = 'Admin'; unresolved = $false } }
    if ($t -match '^\$(\w+)$' -and $VarMap.ContainsKey($Matches[1].ToLowerInvariant())) {
        $r = $VarMap[$Matches[1].ToLowerInvariant()]; if ($r) { return @{ role = $r; unresolved = $false } } else { return @{ role = ''; unresolved = $true } }
    }
    return $null
}

function Get-PimApiRefCondBranchText {
    # the branch text of the nearest if-clause whose CONDITION holds this node ('' when none)
    param($Node)
    $p = $Node.Parent
    while ($p) {
        if ($p -is [System.Management.Automation.Language.IfStatementAst]) {
            foreach ($cl in $p.Clauses) {
                if ($Node.Extent.StartOffset -ge $cl.Item1.Extent.StartOffset -and $Node.Extent.EndOffset -le $cl.Item1.Extent.EndOffset) { return $cl.Item2.Extent.Text }
            }
            return ''
        }
        if ($p -is [System.Management.Automation.Language.StatementBlockAst]) { return '' }
        $p = $p.Parent
    }
    return ''
}

function Get-PimApiRefGateFromRefusal {
    # a condition that is ONLY '-not <x>' and whose branch answers 403 "<Role> role required" -> that role
    param($Unary)
    $p = $Unary.Parent
    while ($p -and ($p -is [System.Management.Automation.Language.CommandExpressionAst] -or $p -is [System.Management.Automation.Language.PipelineAst] -or $p -is [System.Management.Automation.Language.ParenExpressionAst])) {
        $q = $p.Parent
        if ($q -is [System.Management.Automation.Language.IfStatementAst]) {
            foreach ($cl in $q.Clauses) {
                if ($cl.Item1 -eq $p) {
                    $bt = $cl.Item2.Extent.Text
                    if ($bt -match '403' -and $bt -match '\b(SuperAdmin|Admin)\s+(role\s+)?(is\s+)?required') { return @{ role = $Matches[1]; unresolved = $false } }
                    return $null
                }
            }
            return $null
        }
        $p = $q
    }
    return $null
}

function Test-PimApiRefMethodAllowed {
    # does an enclosing condition let this method through? (no method in it = yes)
    param([string]$Cond, [string]$Method)
    $eq = @([regex]::Matches($Cond, "(?i)\`$(method|m)\s+-eq\s+'(\w+)'") | ForEach-Object { $_.Groups[2].Value.ToUpperInvariant() })
    $in = @([regex]::Matches($Cond, "(?i)\`$(method|m)\s+-in\s+@\(([^)]*)\)") | ForEach-Object { [regex]::Matches($_.Groups[2].Value, "'(\w+)'") | ForEach-Object { $_.Groups[1].Value.ToUpperInvariant() } })
    $ne = @([regex]::Matches($Cond, "(?i)\`$(method|m)\s+-ne\s+'(\w+)'") | ForEach-Object { $_.Groups[2].Value.ToUpperInvariant() })
    $pos = @($eq + $in)
    if ($pos.Count -and $pos -notcontains $Method) { return $false }
    if (-not $pos.Count -and $ne.Count -and $ne -contains $Method -and $Cond -notmatch '-or') { return $false }
    return $true
}

function Test-PimApiRefRoutingCond {
    # a condition that only picks the method / path (or checks that a function is loaded) -- a gate behind it still applies
    param([string]$Cond)
    $r = $Cond
    $r = [regex]::Replace($r, "(?i)\`$(method|m)\s+-(eq|ne)\s+'\w+'", '')
    $r = [regex]::Replace($r, "(?i)\`$(method|m)\s+-(in|notin)\s+@\([^)]*\)", '')
    $r = [regex]::Replace($r, "(?i)\`$path\s+-(eq|ne|like|match)\s+'[^']*'", '')
    $r = [regex]::Replace($r, "(?i)\`$path\s+-in\s+@\([^)]*\)", '')
    $r = [regex]::Replace($r, "(?i)\(?Get-Command\s+[\w-]+(\s+-ErrorAction\s+SilentlyContinue)?\)?", '')
    $r = [regex]::Replace($r, '(?i)\$true\b', '')
    $r = [regex]::Replace($r, '(?i)-and|-or|[()\s]', '')
    return ($r -eq '')
}

function Test-PimApiRefPathAllowed {
    # does an enclosing condition name other exact paths only?
    param([string]$Cond, [string]$Path)
    $ex = @([regex]::Matches($Cond, "(?i)\`$path\s+-eq\s+'(/api/[^']+)'") | ForEach-Object { $_.Groups[1].Value })
    if (-not $ex.Count -or $Cond -match "(?i)\`$path\s+-(like|match|in)\b") { return $true }
    return ($ex -contains $Path)
}

function Find-PimApiRefGate {
    <# The first role gate in $Node for this method + path: @{ role; unresolved } or $null. Skips the regions of other routes
       (-Skip: list of @(start, end)), gates behind a condition for another method / path, and (with -Before) gates after it.
       With nothing found it follows the functions the node calls (depth 3). #>
    param($Node, [string]$Method, [string]$Path, [object[]]$Skip = @(), [int]$Before = [int]::MaxValue, [hashtable]$Fns, [hashtable]$VarMap,
          [int]$Depth = 0, [hashtable]$Seen = $null)
    if (-not $Seen) { $Seen = @{} }
    $inSkip = { param($a) foreach ($r in $Skip) { if ($a.Extent.StartOffset -ge $r[0] -and $a.Extent.EndOffset -le $r[1]) { return $true } }; return $false }
    $nodeStart = $Node.Extent.StartOffset; $nodeEnd = $Node.Extent.EndOffset
    $allowed = {
        param($a)
        $p = $a.Parent; $child = $a; $inIfCond = $false
        while ($p -and $p.Extent.StartOffset -ge $nodeStart -and $p.Extent.EndOffset -le $nodeEnd) {
            if ($p -is [System.Management.Automation.Language.IfStatementAst]) {
                $k = 0
                foreach ($cl in $p.Clauses) {
                    $inCond = ($a.Extent.StartOffset -ge $cl.Item1.Extent.StartOffset -and $a.Extent.EndOffset -le $cl.Item1.Extent.EndOffset)
                    $inBody = ($a.Extent.StartOffset -ge $cl.Item2.Extent.StartOffset -and $a.Extent.EndOffset -le $cl.Item2.Extent.EndOffset)
                    if ($inCond) { $inIfCond = $true; break }
                    if ($inBody) {
                        $ct = $cl.Item1.Extent.Text
                        if (-not (Test-PimApiRefMethodAllowed -Cond $ct -Method $Method)) { return $false }
                        if (-not (Test-PimApiRefPathAllowed -Cond $ct -Path $Path)) { return $false }
                        # a gate behind any other condition ('if ($body.source -eq "restore") { SuperAdmin }') is no minimum
                        if (-not $relax -and -not (Test-PimApiRefRoutingCond -Cond $ct)) { return $false }
                        break
                    }
                    $k++
                }
                if (-not $relax -and $p.ElseClause -and $a.Extent.StartOffset -ge $p.ElseClause.Extent.StartOffset -and $a.Extent.EndOffset -le $p.ElseClause.Extent.EndOffset) {
                    foreach ($cl in $p.Clauses) { if (-not (Test-PimApiRefRoutingCond -Cond $cl.Item1.Extent.Text)) { return $false } }
                }
            } elseif ($p -is [System.Management.Automation.Language.SwitchStatementAst] -and $p.Condition.Extent.Text -match '(?i)\$path') {
                foreach ($cl in $p.Clauses) {
                    if ($a.Extent.StartOffset -ge $cl.Item2.Extent.StartOffset -and $a.Extent.EndOffset -le $cl.Item2.Extent.EndOffset) {
                        $lbl = "$($cl.Item1.Extent.Text)".Trim("'", '"')
                        if ($lbl -match '^/api/' -and $lbl -ne $Path) { return $false }
                        if ($lbl -match '^(GET|POST|PUT|DELETE|PATCH) (/api/\S+)$' -and ($Matches[1] -ne $Method -or $Matches[2] -ne $Path)) { return $false }
                    }
                }
            }
            $p = $p.Parent
        }
        return $inIfCond
    }
    # the role checks + calls of a node, found once per node (FindAll walks in document order)
    if (-not $script:PimApiRefNodeCache) { $script:PimApiRefNodeCache = @{} }
    $nc = $script:PimApiRefNodeCache[$Node]
    if (-not $nc) {
        $un = @($Node.FindAll({ param($n) $n -is [System.Management.Automation.Language.UnaryExpressionAst] -and
            ($n.TokenKind -eq [System.Management.Automation.Language.TokenKind]::Not -or $n.TokenKind -eq [System.Management.Automation.Language.TokenKind]::Exclaim) -and
            $n.Child.Extent.Text -match '(?i)Test-PimManagerRoleAtLeast|^\(?\$\w+(\.\w+)?\)?$' }, $true))
        $cm = @($Node.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $Fns.ContainsKey("$($n.GetCommandName())") }, $true))
        $nc = @{ unary = $un; calls = $cm }
        $script:PimApiRefNodeCache[$Node] = $nc
    }
    $unary = $nc.unary
    $unres = $false; $cond = $false; $relax = $false
    foreach ($u in $unary) {
        if ($u.Extent.StartOffset -ge $Before) { break }
        if (& $inSkip $u) { continue }
        $g = Get-PimApiRefRoleFromText -Text $u.Child.Extent.Text -VarMap $VarMap
        if (-not $g) {
            # 'if (-not $access.list) { ... 403 "Admin role required ..." }': a gate on a computed right, named by its own refusal
            $g = Get-PimApiRefGateFromRefusal -Unary $u
            if (-not $g) { continue }
        }
        # a gate REFUSES: 'if (-not $isSuper) { <filter the rows> }' only shapes the answer and is no minimum
        if ("$(Get-PimApiRefCondBranchText -Node $u)" -notmatch '\b403\b') { continue }
        if (-not (& $allowed $u)) {
            # behind another condition: a role check that applies only sometimes (said so: 'conditional')
            $relax = $true; if (& $allowed $u) { $cond = $true }; $relax = $false
            continue
        }
        # 'if (-not <gate> -and <something else>)': a gate that something else lifts (an owner, a flag) is no minimum --
        # except when the something else is the method (a gate for that method only)
        if ($u.Parent -is [System.Management.Automation.Language.BinaryExpressionAst] -and "$($u.Parent.Operator)" -eq 'And') {
            $sib = if ($u.Parent.Left -eq $u) { $u.Parent.Right } else { $u.Parent.Left }
            $st = $sib.Extent.Text
            if ($st -match '(?i)^\(?\s*\$(method|m)\s+-(eq|ne|in)\b') { if (-not (Test-PimApiRefMethodAllowed -Cond $st -Method $Method)) { continue } }
            else { $cond = $true; continue }
        }
        if ($g.unresolved) { $unres = $true; continue }
        $g['line'] = $u.Extent.StartLineNumber
        return $g
    }
    if ($Depth -lt 3) {
        foreach ($c in $nc.calls) {
            if ($c.Extent.StartOffset -ge $Before) { break }
            $cn = $c.GetCommandName()
            if (-not $cn -or -not $Fns.ContainsKey($cn) -or $Seen.ContainsKey($cn)) { continue }
            if ($cn -in @('Test-PimManagerRoleAtLeast', 'Get-PimManagerRole', 'Handle-Request')) { continue }
            if (& $inSkip $c) { continue }
            if (-not (Test-PimApiRefCallReachable -Call $c -Method $Method -Path $Path -NodeStart $nodeStart -NodeEnd $nodeEnd)) { continue }
            $Seen[$cn] = $true
            $r = Find-PimApiRefGate -Node $Fns[$cn].Body -Method $Method -Path $Path -Fns $Fns -VarMap $VarMap -Depth ($Depth + 1) -Seen $Seen
            if ($r) { if ($r.unresolved) { $unres = $true; continue }; if ($r.conditional) { $cond = $true; continue }; return $r }
        }
    }
    if ($unres) { return @{ role = ''; unresolved = $true } }
    if ($cond) { return @{ role = ''; unresolved = $false; conditional = $true } }
    return $null
}

function Test-PimApiRefCallReachable {
    # a call (not a condition) is reachable for this method + path when no enclosing condition sends it elsewhere
    param($Call, [string]$Method, [string]$Path, [int]$NodeStart, [int]$NodeEnd)
    $p = $Call.Parent
    while ($p -and $p.Extent.StartOffset -ge $NodeStart -and $p.Extent.EndOffset -le $NodeEnd) {
        if ($p -is [System.Management.Automation.Language.IfStatementAst]) {
            foreach ($cl in $p.Clauses) {
                if ($Call.Extent.StartOffset -ge $cl.Item2.Extent.StartOffset -and $Call.Extent.EndOffset -le $cl.Item2.Extent.EndOffset) {
                    if (-not (Test-PimApiRefMethodAllowed -Cond $cl.Item1.Extent.Text -Method $Method)) { return $false }
                    if (-not (Test-PimApiRefPathAllowed -Cond $cl.Item1.Extent.Text -Path $Path)) { return $false }
                    if (-not (Test-PimApiRefRoutingCond -Cond $cl.Item1.Extent.Text)) { return $false }
                }
            }
            if ($p.ElseClause -and $Call.Extent.StartOffset -ge $p.ElseClause.Extent.StartOffset -and $Call.Extent.EndOffset -le $p.ElseClause.Extent.EndOffset) {
                foreach ($cl in $p.Clauses) { if (-not (Test-PimApiRefRoutingCond -Cond $cl.Item1.Extent.Text)) { return $false } }
            }
        } elseif ($p -is [System.Management.Automation.Language.SwitchStatementAst] -and $p.Condition.Extent.Text -match '(?i)\$path') {
            foreach ($cl in $p.Clauses) {
                if ($Call.Extent.StartOffset -ge $cl.Item2.Extent.StartOffset -and $Call.Extent.EndOffset -le $cl.Item2.Extent.EndOffset) {
                    $lbl = "$($cl.Item1.Extent.Text)".Trim("'", '"')
                    if ($lbl -match '^/api/' -and $lbl -ne $Path) { return $false }
                    if ($lbl -match '^(GET|POST|PUT|DELETE|PATCH) (/api/\S+)$' -and ($Matches[1] -ne $Method -or $Matches[2] -ne $Path)) { return $false }
                }
            }
        }
        $p = $p.Parent
    }
    return $true
}

function Find-PimApiRefProFeature {
    # the first Pro feature the node (or a function it calls, depth 3) checks
    param($Node, [hashtable]$Fns, [int]$Depth = 0, [hashtable]$Seen = $null)
    if (-not $Seen) { $Seen = @{} }
    $txt = $Node.Extent.Text
    $m = [regex]::Match($txt, "Test-PimManagerProFeature\s+-Key\s+'([\w\.]+)'")
    if ($m.Success) { return $m.Groups[1].Value }
    if ($Depth -ge 3) { return '' }
    foreach ($cm in [regex]::Matches($txt, '\b(Invoke-PimManager\w*Route\w*)\b')) {
        $cn = $cm.Groups[1].Value
        if (-not $Fns.ContainsKey($cn) -or $Seen.ContainsKey($cn)) { continue }
        $Seen[$cn] = $true
        $r = Find-PimApiRefProFeature -Node $Fns[$cn].Body -Fns $Fns -Depth ($Depth + 1) -Seen $Seen
        if ($r) { return $r }
    }
    return ''
}

function Get-PimApiRefMethodsInBody {
    # the methods a body branches on ($method -eq / -in / -ne 'X'), outside the given regions
    param($Node, [object[]]$Skip = @(), [switch]$Condition)
    $res = @()
    $ops = if ($Condition) { @('Ieq', 'Ceq', 'Iin', 'Cin') } else { @('Ieq', 'Ceq', 'Ine', 'Cne', 'Iin', 'Cin') }   # in a body, '-ne POST -> 405' names POST
    foreach ($b in @($Node.FindAll({ param($n) $n -is [System.Management.Automation.Language.BinaryExpressionAst] -and $n.Left.Extent.Text -match '(?i)^\$(method|m)$' }, $true))) {
        $in = $false; foreach ($r in $Skip) { if ($b.Extent.StartOffset -ge $r[0] -and $b.Extent.EndOffset -le $r[1]) { $in = $true; break } }
        if ($in) { continue }
        $op = "$($b.Operator)"
        # 'if ($method -eq 'POST' ...) { 405 }' names a method the route does NOT serve
        if (-not $Condition -and $op -notin @('Ine', 'Cne') -and "$(Get-PimApiRefCondBranchText -Node $b)" -match '\b405\b') { continue }
        if ($op -in $ops) { $res += @([regex]::Matches($b.Right.Extent.Text, "'(\w+)'") | ForEach-Object { $_.Groups[1].Value.ToUpperInvariant() }) }
    }
    return @($res | Where-Object { $_ -in @('GET', 'POST', 'PUT', 'DELETE', 'PATCH') } | Select-Object -Unique)
}

function Get-PimApiRefDisjuncts {
    # a condition -> its top-level -or parts (each its own path + method pairing)
    param($Ast)
    $a = $Ast
    while ($a -is [System.Management.Automation.Language.PipelineAst] -and $a.PipelineElements.Count -eq 1 -and $a.PipelineElements[0] -is [System.Management.Automation.Language.CommandExpressionAst]) { $a = $a.PipelineElements[0].Expression }
    while ($a -is [System.Management.Automation.Language.ParenExpressionAst]) { $a = $a.Pipeline; while ($a -is [System.Management.Automation.Language.PipelineAst] -and $a.PipelineElements.Count -eq 1 -and $a.PipelineElements[0] -is [System.Management.Automation.Language.CommandExpressionAst]) { $a = $a.PipelineElements[0].Expression } }
    if ($a -is [System.Management.Automation.Language.BinaryExpressionAst] -and "$($a.Operator)" -eq 'Or') { return @(Get-PimApiRefDisjuncts -Ast $a.Left) + @(Get-PimApiRefDisjuncts -Ast $a.Right) }
    return @($Ast.Extent.Text)
}

function Get-PimApiRefFileRoutes {
    <# The route clauses of one parsed file (or of one function in it): if / elseif clauses with a $path condition, switch ($path)
       tables and 'METHOD /path' switch tables. Returns the list of clause objects, parents linked. #>
    param($Root)
    $clauses = New-Object System.Collections.Generic.List[object]
    foreach ($ifs in @($Root.FindAll({ param($n) $n -is [System.Management.Automation.Language.IfStatementAst] }, $true))) {
        $prevEnd = $null
        foreach ($cl in $ifs.Clauses) {
            $ct = $cl.Item1.Extent.Text
            if ($ct -notmatch "(?i)\`$path\s+-(eq|like|match|in)\s+@?\(?\s*'\^?/api/") { continue }
            $parts = New-Object System.Collections.Generic.List[object]; $prefixes = @()
            foreach ($dj in (Get-PimApiRefDisjuncts -Ast $cl.Item1)) {
                $paths = @()
                foreach ($m in [regex]::Matches($dj, "(?i)\`$path\s+-(eq|like|match)\s+'(\^?/api/[^']+)'")) {
                    $cv = ConvertTo-PimApiRefPaths -Op $m.Groups[1].Value.ToLowerInvariant() -Value $m.Groups[2].Value
                    $paths += @($cv.paths); if ($cv.prefix) { $prefixes += $cv.prefix }
                }
                foreach ($m in [regex]::Matches($dj, "(?i)\`$path\s+-in\s+@\(([^)]*)\)")) { foreach ($q in [regex]::Matches($m.Groups[1].Value, "'(/api/[^']+)'")) { $paths += $q.Groups[1].Value } }
                $methods = @(@([regex]::Matches($dj, "(?i)\`$method\s+-eq\s+'(\w+)'") | ForEach-Object { $_.Groups[1].Value.ToUpperInvariant() }) +
                             @([regex]::Matches($dj, "(?i)\`$method\s+-in\s+@\(([^)]*)\)") | ForEach-Object { [regex]::Matches($_.Groups[1].Value, "'(\w+)'") | ForEach-Object { $_.Groups[1].Value.ToUpperInvariant() } }) |
                             Where-Object { $_ -in @('GET', 'POST', 'PUT', 'DELETE', 'PATCH') } | Select-Object -Unique)
                $parts.Add(@{ paths = @($paths | Select-Object -Unique); methods = $methods })
            }
            # '/api/*' (the gate in front of every route) is no route clause
            if (-not @($parts | Where-Object { @($_.paths).Count }).Count -and -not @($prefixes).Count) { continue }
            $clauses.Add([pscustomobject]@{ kind = 'if'; cond = $ct; condAst = $cl.Item1; body = $cl.Item2; start = $cl.Item1.Extent.StartOffset; end = $cl.Item2.Extent.EndOffset
                                            parts = $parts.ToArray(); prefixes = $prefixes; parent = $null; children = (New-Object System.Collections.Generic.List[object]) })
        }
    }
    foreach ($sw in @($Root.FindAll({ param($n) $n -is [System.Management.Automation.Language.SwitchStatementAst] }, $true))) {
        $isPath = $sw.Condition.Extent.Text -match '(?i)\$path'
        foreach ($cl in $sw.Clauses) {
            $lbl = "$($cl.Item1.Extent.Text)".Trim("'", '"')
            if ($lbl -match '^(GET|POST|PUT|DELETE|PATCH) (/api/\S+)$') {
                $clauses.Add([pscustomobject]@{ kind = 'table'; cond = ''; condAst = $null; body = $cl.Item2; start = $cl.Item1.Extent.StartOffset; end = $cl.Item2.Extent.EndOffset
                                                parts = @(@{ paths = @($Matches[2]); methods = @($Matches[1]) }); prefixes = @(); parent = $null; children = (New-Object System.Collections.Generic.List[object]) })
            } elseif ($isPath -and $lbl -match '^/api/\S+$') {
                $clauses.Add([pscustomobject]@{ kind = 'switch'; cond = ''; condAst = $null; body = $cl.Item2; start = $cl.Item1.Extent.StartOffset; end = $cl.Item2.Extent.EndOffset
                                                parts = @(@{ paths = @($lbl); methods = @() }); prefixes = @(); parent = $null; children = (New-Object System.Collections.Generic.List[object]) })
            }
        }
    }
    # parents: the innermost clause whose BODY holds this clause
    $sorted = @($clauses | Sort-Object start)
    $stack = New-Object System.Collections.Generic.List[object]
    foreach ($c in $sorted) {
        while ($stack.Count -and -not ($c.start -ge $stack[$stack.Count - 1].body.Extent.StartOffset -and $c.end -le $stack[$stack.Count - 1].body.Extent.EndOffset)) { $stack.RemoveAt($stack.Count - 1) }
        if ($stack.Count) { $c.parent = $stack[$stack.Count - 1]; $c.parent.children.Add($c) }
        $stack.Add($c)
    }
    return , $sorted
}

function Get-PimApiReferenceRoutes {
    <#
      Every route the Manager serves, from the code of -SolutionRoot. Returns objects
      { method; path; role; roleBasis ('gate' = the body checks it | 'none' = no role check: any signed-in role |
        'unresolved' = a check the reader cannot name); pro; internal }.
    #>
    param([Parameter(Mandatory)][string]$SolutionRoot)
    $script:PimApiRefNodeCache = @{}
    try { return (Get-PimApiReferenceRoutesCore -SolutionRoot $SolutionRoot) } finally { $script:PimApiRefNodeCache = $null }
}

function Get-PimApiReferenceRoutesCore {
    param([Parameter(Mandatory)][string]$SolutionRoot)
    $pm = Join-Path $SolutionRoot 'tools\pim-manager'
    $files = @(@{ path = (Join-Path $pm 'Open-PimManager.ps1'); main = $true }) + @(Get-ChildItem -LiteralPath $pm -Filter '_*.ps1' -File | Sort-Object Name | ForEach-Object { @{ path = $_.FullName; main = $false } })
    $parsed = @()
    $fns = @{}; $varMap = @{}
    foreach ($f in $files) {
        $src = [IO.File]::ReadAllText($f.path)
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
        foreach ($fd in @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))) { if (-not $fns.ContainsKey($fd.Name)) { $fns[$fd.Name] = $fd } }
        foreach ($m in [regex]::Matches($src, "\`$(\w+)\s*=\s*\[bool\]\(Test-PimManagerRoleAtLeast\s+-Minimum\s+'(\w+)'\)")) {
            $k = $m.Groups[1].Value.ToLowerInvariant()
            if ($varMap.ContainsKey($k) -and $varMap[$k] -ne $m.Groups[2].Value) { $varMap[$k] = '' } else { $varMap[$k] = $m.Groups[2].Value }
        }
        $parsed += @{ file = $f; ast = $ast; src = $src }
    }
    # a module router: a module function that serves routes of its own ('METHOD /path' labels or $Path conditions)
    $routerFns = @{}
    foreach ($p in $parsed) {
        if ($p.file.main) { continue }
        foreach ($fd in @($p.ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))) {
            if ($fd.Body.Extent.Text -match "'(GET|POST|PUT|DELETE|PATCH) /api/|(?i)\`$path\s+-eq\s+'/api/|switch\s*\(\s*""?\`$Path") { $routerFns[$fd.Name] = $true }
        }
    }
    $ops = New-Object System.Collections.Generic.List[object]
    foreach ($p in $parsed) {
        $root = if ($p.file.main) { $p.ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Handle-Request' }, $true) } else { $p.ast }
        if (-not $root) { continue }
        $clauses = Get-PimApiRefFileRoutes -Root $root
        foreach ($c in $clauses) {
            # what the clause dispatches to: routes inside it, or a module router -- then the prefix is not a route of its own
            $callsRouter = $false
            if ($p.file.main) { foreach ($cmd in @($c.body.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))) { if ($routerFns.ContainsKey("$($cmd.GetCommandName())")) { $callsRouter = $true; break } } }
            if ($callsRouter) { continue }
            # a clause that only answers 405 ('did you mean ...') names a method the route does not serve
            $bt = $c.body.Extent.Text
            if ($bt -match '\b405\b' -and $bt -notmatch '\b20[0-4]\b|return \(') { continue }
            $hasInner = ($c.children.Count -gt 0)
            $skip = @($c.children | ForEach-Object { , @($_.start, $_.end) })
            foreach ($part in $c.parts) {
                $paths = @($part.paths)
                if (-not $hasInner) { foreach ($px in @($c.prefixes)) { if ($px.sub) { $paths += ($px.base + '/{path}') } else { $paths += $px.base } } }
                $paths = @($paths | Where-Object { $_ } | Select-Object -Unique)
                if (-not $paths.Count) { continue }
                foreach ($path in $paths) {
                    $methods = @($part.methods)
                    if (-not $methods.Count) {
                        $a = $c.parent
                        while ($a -and -not $methods.Count) {
                            $hit = @($a.parts | Where-Object { @($_.paths) -contains $path -and @($_.methods).Count })
                            $methods = if ($hit.Count) { @($hit | ForEach-Object { $_.methods }) } else { @($a.parts | ForEach-Object { $_.methods }) }
                            $methods = @($methods | Where-Object { $_ } | Select-Object -Unique)
                            $a = $a.parent
                        }
                    }
                    if (-not $methods.Count) { $methods = @(Get-PimApiRefMethodsInBody -Node $c.body -Skip $skip) }
                    if (-not $methods.Count) { $methods = @('GET') }   # no method anywhere: the page reads it
                    foreach ($me in $methods) {
                        $rank = -1; $role = ''; $unres = $false; $gline = 0; $condl = $false
                        $g = Find-PimApiRefGate -Node $c.body -Method $me -Path $path -Skip $skip -Fns $fns -VarMap $varMap
                        if ($g) { if ($g.unresolved) { $unres = $true } elseif ($g.conditional) { $condl = $true } else { $role = $g.role; $rank = $script:PimApiRefRank[$role]; $gline = [int]$g.line } }
                        # the gate of an enclosing block, before this route, applies too (the higher one wins)
                        $child = $c; $a = $c.parent
                        while ($a) {
                            $askip = @($a.children | ForEach-Object { , @($_.start, $_.end) })
                            $ga = Find-PimApiRefGate -Node $a.body -Method $me -Path $path -Skip $askip -Before $child.start -Fns $fns -VarMap $varMap -Depth 3
                            if ($ga -and -not $ga.unresolved -and -not $ga.conditional -and $script:PimApiRefRank[$ga.role] -gt $rank) { $role = $ga.role; $rank = $script:PimApiRefRank[$role]; $gline = [int]$ga.line }
                            $child = $a; $a = $a.parent
                        }
                        $basis = if ($role) { 'gate' } elseif ($unres) { 'unresolved' } elseif ($condl) { 'conditional' } else { 'none' }
                        $pro = Find-PimApiRefProFeature -Node $c.body -Fns $fns
                        if (-not $pro) { $a = $c.parent; while ($a -and -not $pro) { $mpro = [regex]::Match($a.body.Extent.Text.Substring(0, [Math]::Max(0, [Math]::Min($a.body.Extent.Text.Length, $c.start - $a.body.Extent.StartOffset))), "Test-PimManagerProFeature\s+-Key\s+'([\w\.]+)'"); if ($mpro.Success) { $pro = $mpro.Groups[1].Value }; $a = $a.parent } }
                        $isInt = [bool]@($script:PimApiRefInternal | Where-Object { $path.StartsWith($_) }).Count
                        $ops.Add([pscustomobject]@{ method = $me; path = $path; role = $(if ($role) { $role } elseif ($unres) { '' } else { 'Reader' }); roleBasis = $basis; pro = $pro; internal = $isInt; gateLine = $gline; file = (Split-Path $p.file.path -Leaf) })
                    }
                }
            }
        }
        # a module's 'METHOD /path' list that has no switch label of its own (rare) still counts
        if (-not $p.file.main) {
            foreach ($m in [regex]::Matches($p.src, "'(GET|POST|PUT|DELETE|PATCH) (/api/[^'\s]+)'")) {
                $k = "$($m.Groups[1].Value) $($m.Groups[2].Value)"
                if (-not @($ops | Where-Object { "$($_.method) $($_.path)" -eq $k }).Count) {
                    $ops.Add([pscustomobject]@{ method = $m.Groups[1].Value; path = $m.Groups[2].Value; role = ''; roleBasis = 'unresolved'; pro = ''; internal = $false })
                }
            }
        }
    }
    # one entry per method + path: the strongest resolved gate wins (a route served by an outer and an inner clause)
    $out = foreach ($grp in ($ops | Group-Object { "$($_.method) $($_.path)" })) {
        $score = { param($o) if ($o.roleBasis -eq 'unresolved') { -3 } elseif ($o.roleBasis -eq 'gate') { 10 + $script:PimApiRefRank[$o.role] } elseif ($o.roleBasis -eq 'conditional') { 1 } else { 0 } }
        $best = @($grp.Group | Sort-Object { & $score $_ } -Descending)[0]
        if (-not $best.pro) { $best.pro = "$(@($grp.Group | Where-Object { $_.pro } | Select-Object -First 1).pro)" }
        $best
    }
    return , @($out | Sort-Object path, method)
}

# ======================================================================================================== THE DOCUMENTS
function Get-PimApiRefDescriptions {
    param([Parameter(Mandatory)][string]$SolutionRoot)
    $desc = @{}
    $f = Join-Path $SolutionRoot 'tools\pim-manager\api-descriptions.json'
    if (Test-Path -LiteralPath $f) { $dj = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json; foreach ($p in $dj.PSObject.Properties) { if ($p.Name -ne '_comment') { $desc[$p.Name] = "$($p.Value)" } } }
    return $desc
}

function ConvertTo-PimApiRefToolRow {
    # an MCP tool definition -> its reference row (no handler)
    param($Tool)
    [ordered]@{ name = "$($Tool.name)"; description = "$($Tool.description)"; inputSchema = $Tool.inputSchema
                output = 'JSON text: the same answer the PIM Manager page gets for this action (an error says why)'
                readOnly = ("$($Tool.kind)" -eq 'read'); kind = "$($Tool.kind)"; route = $(if ("$($Tool.route)") { "$($Tool.route)" } else { $null }); requires = "$($Tool.minRole)" }
}

function New-PimApiReferenceDocument {
    <#
      -Profile Full: every route + tool. -Profile Public: the deny-by-default public profile (see the lists at the top).
      Returns @{ api; mcp; summary; leftOut (per class counts); leftOutRoutes; conflicts } -- conflicts = a public-listed route or tool
      that is not there or that also matches a left-out class (the gate fails on them).
    #>
    param([Parameter(Mandatory)][object[]]$Routes, [object[]]$Tools = @(), [Parameter(Mandatory)][string]$Version, [hashtable]$Descriptions = @{},
          [ValidateSet('Full', 'Public')][string]$Profile = 'Full')
    $pub = ($Profile -eq 'Public')
    $pubSet = @{}; foreach ($k in $script:PimApiRefPublicRoutes) { $pubSet[$k] = $true }
    $have = @{}; foreach ($o in $Routes) { $have["$($o.method) $($o.path)"] = $o }
    $conflicts = New-Object System.Collections.Generic.List[string]
    if ($pub) { foreach ($k in $script:PimApiRefPublicRoutes) { if (-not $have.ContainsKey($k)) { $conflicts.Add("public route '$k' is not a route of this version") } } }
    $leftOut = [ordered]@{}; $leftOutRoutes = New-Object System.Collections.Generic.List[object]
    $pathsObj = [ordered]@{}; $kept = New-Object System.Collections.Generic.List[object]
    foreach ($o in $Routes) {
        $key = "$($o.method) $($o.path)"
        $summary = if ($Descriptions.ContainsKey($key)) { $Descriptions[$key] } else { $key }
        $roleTxt = if ($o.roleBasis -eq 'unresolved') { 'the route checks the role itself' } elseif ($o.roleBasis -eq 'none') { 'any signed-in PIM Manager role' }
                   elseif ($o.roleBasis -eq 'conditional') { 'any signed-in PIM Manager role; the route checks more for some requests (who you are for the item, or what you ask for)' } else { "$($o.role) or higher" }
        $description = if ($pub) { "Requires: $(if ($o.roleBasis -eq 'gate') { "$($o.role) or higher" } else { 'Reader or higher' })." }
                       else { "Requires: $roleTxt.$(if ($o.pro) { " Pro feature: $($o.pro)." })$(if ($o.internal) { ' Internal: a mechanic of the PIM Manager page -- not a supported integration point.' })" }
        if ($pub) {
            $cls = Get-PimApiRefLeftOutClass -Method $o.method -Path $o.path -Internal ([bool]$o.internal)
            $why = ''
            if (-not $pubSet.ContainsKey($key)) { $why = $(if ($cls) { $cls } else { 'unclassified' }) }
            elseif ($cls) { $why = $cls; $conflicts.Add("public route '$key' also matches the left-out class '$cls'") }
            elseif ((Test-PimApiRefForbiddenText -Text $o.path) -or (Test-PimApiRefForbiddenText -Text $summary) -or (Test-PimApiRefForbiddenText -Text $description)) { $why = 'import-word' }
            elseif ($o.roleBasis -eq 'unresolved') { $why = 'role-unresolved' }
            if ($why) { $leftOut[$why] = 1 + [int]$leftOut[$why]; $leftOutRoutes.Add([pscustomobject]@{ route = $key; class = $why }); continue }
        }
        $kept.Add($o)
        if (-not $pathsObj.Contains($o.path)) { $pathsObj[$o.path] = [ordered]@{} }
        $params = @([regex]::Matches($o.path, '\{(\w+)\}') | ForEach-Object { [ordered]@{ name = $_.Groups[1].Value; in = 'path'; required = $true; schema = @{ type = 'string' } } })
        $op = [ordered]@{
            operationId = (($o.method.ToLowerInvariant()) + '_' + (($o.path -replace '^/api/', '' -replace '[{}]', '' -replace '[^A-Za-z0-9]+', '_').Trim('_')))
            summary     = $summary
            description = $description
            'x-role'    = "$($o.role)"
            'x-pim-role' = "$($o.role)"
            'x-pim-pro-feature' = $(if ($o.pro) { $o.pro } else { $null })
        }
        if (-not $pub) { $op['x-role-basis'] = "$($o.roleBasis)"; $op['x-internal'] = [bool]$o.internal }
        $op['security'] = @(@{ manager = @() })
        $op['responses'] = [ordered]@{ '200' = @{ description = 'OK' }; '400' = @{ description = 'The request is not valid (the answer says why)' }
                                       '401' = @{ description = 'Not signed in' }; '403' = @{ description = 'Your role or licence does not allow it (the answer says which)' } }
        if ($params.Count) { $op['parameters'] = $params }
        if ($o.method -in 'POST', 'PUT', 'PATCH') { $op['requestBody'] = @{ required = $false; content = @{ 'application/json' = @{ schema = @{ type = 'object' } } } } }
        $pathsObj[$o.path][$o.method.ToLowerInvariant()] = $op
    }
    $info = if ($pub) {
        [ordered]@{ title = 'PIM Manager API'; version = $Version
                    description = 'The routine routes of the PIM Manager API. Paths are relative to your own PIM Manager address. Generated from the code of this version. The complete reference, filtered to your role, is in your PIM Manager: Settings > API and MCP reference.' }
    } else {
        [ordered]@{ title = 'PIM Manager API (complete)'; version = $Version
                    description = 'Every route the PIM Manager page uses: every action of the page is a route here. Paths are relative to this PIM Manager. Generated from the code of this version.' }
    }
    $schemeText = if ($pub) { $script:PimApiRefPublicSignInText } else { 'Microsoft Entra sign-in at the PIM Manager. Your PIM Manager role (Reader, Admin, SuperAdmin) decides what each route allows.' }
    $api = [ordered]@{
        openapi = '3.1.0'; info = $info
        servers = @(@{ url = '/'; description = 'your PIM Manager' })
        components = @{ securitySchemes = @{ manager = @{ type = 'http'; scheme = 'bearer'; description = $schemeText } } }
        paths = $pathsObj
    }
    # ---- MCP
    $pubTools = @{}; foreach ($n in $script:PimApiRefPublicMcpTools) { $pubTools[$n] = $true }
    $pubRouteKeys = @{}; foreach ($o in $kept) { $pubRouteKeys["$($o.method) $($o.path)"] = $true }
    $toolRows = New-Object System.Collections.Generic.List[object]; $toolsOut = 0
    $toolNames = @($Tools | ForEach-Object { "$($_.name)" })
    if ($pub) { foreach ($n in $script:PimApiRefPublicMcpTools) { if ($Tools.Count -and $toolNames -notcontains $n) { $conflicts.Add("public MCP tool '$n' is not a tool of this version") } } }
    # A tool names a path parameter by its own argument ('/{commitId}'); the router's form is positional ('/{p1}'). The row
    # carries the reference's OWN key for that route, so a tool always names an operation of api.json exactly.
    $routeByShape = @{}; foreach ($k in $have.Keys) { $routeByShape[($k -replace '\{\w+\}', '{}')] = $k }
    foreach ($t in @($Tools | Sort-Object name)) {
        $row = ConvertTo-PimApiRefToolRow -Tool $t
        if ($row.route -and -not $have.ContainsKey($row.route)) { $shape = $row.route -replace '\{\w+\}', '{}'; if ($routeByShape.ContainsKey($shape)) { $row.route = $routeByShape[$shape] } }
        if ($pub) {
            $schemaTxt = ($row.inputSchema | ConvertTo-Json -Depth 20 -Compress)
            $ok = $pubTools.ContainsKey($row.name) -and -not (Test-PimApiRefForbiddenText -Text $row.name) -and -not (Test-PimApiRefForbiddenText -Text $row.description) -and -not (Test-PimApiRefForbiddenText -Text $schemaTxt)
            if ($ok -and $row.route -and -not $pubRouteKeys.ContainsKey($row.route)) {
                if ($pubTools.ContainsKey($row.name)) { $conflicts.Add("public MCP tool '$($row.name)' runs '$($row.route)', which is not public") }
                $ok = $false
            }
            if (-not $ok) { $toolsOut++; continue }
        }
        $toolRows.Add($row)
    }
    $mcp = [ordered]@{ product = 'pim-manager'; version = $Version; generatedAt = [datetime]::UtcNow.ToString('o'); endpoint = 'POST /mcp (JSON-RPC 2.0, streamable HTTP, JSON answers)' }
    if ($pub) { $mcp['access'] = 'Sign in to your PIM Manager; your PIM Manager role decides which tools you see and may call.' }
    else {
        $mcp['signIn'] = 'A person signs in with Microsoft Entra: a delegated token for api://<your PIM Manager app>/mcp.access. App-only tokens are refused. Your PIM Manager role decides which tools you see and may call; every call is audited.'
        $mcp['guiOnly'] = 'By design NOT in the MCP (the PIM Manager page only): emergency / break-glass / restore, revoke, drift remediation and group delete, hybrid-AD delete approvals, guard release, and changes to settings, licence and managed tenants (the MCP reads them).'
    }
    $mcp['tools'] = $toolRows.ToArray()
    $summary = [ordered]@{ version = $Version; profile = $Profile; routes = $kept.Count; paths = $pathsObj.Count
                           internalRoutes = @($kept | Where-Object { $_.internal }).Count
                           roleUnresolved = @($kept | Where-Object { $_.roleBasis -eq 'unresolved' }).Count
                           mcpTools = $toolRows.Count; mcpRead = @($toolRows | Where-Object { $_.readOnly }).Count; mcpWrite = @($toolRows | Where-Object { -not $_.readOnly }).Count
                           routesLeftOut = $leftOutRoutes.Count; mcpToolsLeftOut = $toolsOut }
    return @{ api = $api; mcp = $mcp; summary = $summary; leftOut = $leftOut; leftOutRoutes = $leftOutRoutes.ToArray(); conflicts = $conflicts.ToArray() }
}

function Test-PimApiReferenceClean {
    <# PURE. Problems in a generated text: host names, GUIDs, e-mail addresses, secret-like text. Empty = clean. #>
    param([string]$Name, [AllowEmptyString()][string]$Text)
    $bad = @()
    if ($Text -match '(?i)[a-z0-9-]+\.(azurecontainerapps\.io|database\.windows\.net|blob\.core\.windows\.net|vault\.azure\.net|onmicrosoft\.com|azurewebsites\.net)') { $bad += "${Name}: a host name ($($Matches[0]))" }
    if ($Text -match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') { $bad += "${Name}: a GUID ($($Matches[0]))" }
    if ($Text -match '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}' -and $Matches[0] -notmatch '@example\.(test|com)$') { $bad += "${Name}: an e-mail address ($($Matches[0]))" }
    if ($Text -match '(?i)(sig=|AccountKey=|client_secret|password\s*[:=])') { $bad += "${Name}: secret-like text ($($Matches[0]))" }
    return , $bad
}

function Get-PimApiReferenceAnswer {
    <#
      The Manager page's answer (GET /api/api-reference) -> @{ status; body }.
      WHY AT RUNTIME, ONCE PER PROCESS: the reference is read from the code THIS process runs (tools\pim-manager under
      -SolutionRoot), so it can never be the reference of another version -- no generated file to ship, nothing to keep in step.
      Reading the code takes seconds and the Manager answers one request at a time, so the read runs ONCE, in a background
      runspace started by the first request; until it is ready the answer is 202 { preparing } and the page asks again.
      The MCP tools come from -Tools (the running Manager's own Get-PimManagerMcpTools) when the reference is built.
      The full reference is checked (no host names, GUIDs, e-mail addresses, secrets) before anything is answered.
    #>
    param([Parameter(Mandatory)][string]$SolutionRoot, [string]$Version = '', [string]$Role = 'Reader', [scriptblock]$Tools = $null)
    $st = $script:PimApiRefRuntime
    if (-not $st) {
        $lib = Join-Path $SolutionRoot 'tools\setup\_PimApiReference.ps1'
        $ps = [powershell]::Create()
        [void]$ps.AddScript({ param($lib, $root) . $lib; Get-PimApiReferenceRoutes -SolutionRoot $root }).AddArgument($lib).AddArgument($SolutionRoot)
        $script:PimApiRefRuntime = @{ ps = $ps; handle = $ps.BeginInvoke(); doc = $null; error = ''; version = "$Version" }
        return @{ status = 202; body = [ordered]@{ ok = $false; preparing = $true; message = 'The reference of this version is being prepared -- ask again in a few seconds.' } }
    }
    if (-not $st.doc -and -not $st.error) {
        if (-not $st.handle.IsCompleted) { return @{ status = 202; body = [ordered]@{ ok = $false; preparing = $true; message = 'The reference of this version is being prepared -- ask again in a few seconds.' } } }
        try {
            $res = $st.ps.EndInvoke($st.handle)
            $routes = @($res | ForEach-Object { $_ })
            if (-not $routes.Count) { throw "no route was read ($(@($st.ps.Streams.Error | Select-Object -First 1)))" }
            $tl = @(); if ($Tools) { try { $tl = @(& $Tools) } catch { $tl = @() } }
            $doc = New-PimApiReferenceDocument -Routes $routes -Tools $tl -Version $st.version -Descriptions (Get-PimApiRefDescriptions -SolutionRoot $SolutionRoot) -Profile Full
            $bad = @(Test-PimApiReferenceClean -Name 'api' -Text ($doc.api | ConvertTo-Json -Depth 30)) + @(Test-PimApiReferenceClean -Name 'mcp' -Text ($doc.mcp | ConvertTo-Json -Depth 30))
            $bad = @($bad | Where-Object { $_ })
            if ($bad.Count) { throw "the reference did not pass its own check: $($bad -join '; ')" }
            $st.doc = $doc
        } catch {
            $st.error = "$($_.Exception.Message)"
            Write-Warning "  [apiref] the API and MCP reference could not be built: $($st.error)"
        } finally { try { $st.ps.Dispose() } catch { } }
    }
    if ($st.error) { return @{ status = 500; body = [ordered]@{ ok = $false; error = 'The API and MCP reference could not be built for this version. The published routine reference is on invardia.com.' } } }
    return @{ status = 200; body = (Get-PimApiReferenceForRole -Reference $st.doc -Role $Role) }
}

function Get-PimApiReferenceForRole {
    <#
      PURE. The page's view of the FULL reference for one signed-in role: the routes and MCP tools that role may call
      (x-role at or below the role; a route whose role check cannot be named is shown to a SuperAdmin only -- fail closed).
      -Reference = New-PimApiReferenceDocument -Profile Full output; -Role = the caller's Manager role.
    #>
    param([Parameter(Mandatory)]$Reference, [string]$Role = 'Reader')
    $rank = if ($script:PimApiRefRank.ContainsKey("$Role")) { $script:PimApiRefRank["$Role"] } else { -1 }
    $routes = New-Object System.Collections.Generic.List[object]; $hidden = 0
    foreach ($pk in $Reference.api.paths.Keys) {
        $pv = $Reference.api.paths[$pk]
        foreach ($mk in $pv.Keys) {
            $op = $pv[$mk]
            $need = if ("$($op['x-role-basis'])" -eq 'unresolved') { 2 } elseif ($script:PimApiRefRank.ContainsKey("$($op['x-role'])")) { $script:PimApiRefRank["$($op['x-role'])"] } else { 2 }
            if ($need -gt $rank) { $hidden++; continue }
            $routes.Add([ordered]@{ method = $mk.ToUpperInvariant(); path = $pk; summary = "$($op.summary)"; role = "$($op['x-role'])"; roleBasis = "$($op['x-role-basis'])"
                                    pro = "$($op['x-pim-pro-feature'])"; internal = [bool]$op['x-internal'] })
        }
    }
    $tools = New-Object System.Collections.Generic.List[object]; $toolsHidden = 0
    foreach ($t in @($Reference.mcp.tools)) {
        $need = if ($script:PimApiRefRank.ContainsKey("$($t.requires)")) { $script:PimApiRefRank["$($t.requires)"] } else { 2 }
        if ($need -gt $rank) { $toolsHidden++; continue }
        $tools.Add([ordered]@{ name = "$($t.name)"; kind = "$($t.kind)"; requires = "$($t.requires)"; route = $(if ($t.route) { "$($t.route)" } else { '' }); description = "$($t.description)"; inputSchema = $t.inputSchema })
    }
    return [ordered]@{ ok = $true; version = "$($Reference.summary.version)"; role = "$Role"; endpoint = "$($Reference.mcp.endpoint)"
                       routes = $routes.ToArray(); hiddenRoutes = $hidden; tools = $tools.ToArray(); hiddenTools = $toolsHidden
                       totalRoutes = $routes.Count + $hidden; totalTools = $tools.Count + $toolsHidden }
}
