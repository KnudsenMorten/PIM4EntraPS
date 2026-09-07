#Requires -Version 5.1
<#
.SYNOPSIS
    §35.1 -- the delegation wizard's pickers. Offline static asserts over the shipped GUI +
    server. No tenant, no network, no writes.

    The operator's emphasis: "it is important that the delegation wizard shows all available
    entra roles, all azure roles, all azure resource levels on mg and sub level + workload
    roles." Entra and Azure RBAC roles already came from the tenant cache. Three did not:

      * WORKLOAD was a free-text box with an "e.g. Defender / PowerBI / Intune" placeholder,
        even though GET /api/workloads has shipped the connector catalog all along.
      * WORKLOAD ROLES fell through to a comma-separated free-text box -- for the one field
        where the exact platform spelling matters most -- even though
        GET /api/workload-roles?id= existed.
      * The AZURE ARM PATH was free text with an example placeholder. A typed ARM path is a
        SILENT-failure surface: a typo yields a syntactically valid scope that grants nothing
        and nothing tells you.

    And one loose end this session created: the §35.2 grid emits PIM_WIZARD_PREFILL and, until
    now, nothing consumed it -- which would have made §35.6's "two surfaces, one workflow"
    decoration rather than a workflow.

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$root = Split-Path -Parent $PSScriptRoot
$guiP = Join-Path $root 'tools\pim-manager\pim-manager.html'
$srvP = Join-Path $root 'tools\pim-manager\Open-PimManager.ps1'
T 'pim-manager.html present'    (Test-Path -LiteralPath $guiP)
T 'Open-PimManager.ps1 present' (Test-Path -LiteralPath $srvP)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }

# Comments stripped -- a source-scan must read CODE. This file and the GUI both NAME the
# placeholders they removed, so a naive scan would match the prose explaining the fix.
$guiRaw = Get-Content -LiteralPath $guiP -Raw
$gui = $guiRaw -replace '(?m)^\s*//.*$', ''
$srv = (Get-Content -LiteralPath $srvP -Raw) -replace '(?m)^\s*#.*$', ''
T 'the comment-stripper actually removed prose' ($guiRaw.Length -gt $gui.Length)

# === the endpoints the wizard now uses ======================================
Write-Host "`n-- the endpoints (both pre-existing; nothing was reading them) --" -ForegroundColor Cyan
T 'GET /api/workloads exists'       ($srv -match "'/api/workloads'")
T 'GET /api/workload-roles exists'  ($srv -match "'/api/workload-roles'")
T 'the wizard loads the connector catalog' ($gui -match "api\('GET', '/api/workloads'\)")
T 'the wizard loads workload roles'        ($gui -match "/api/workload-roles\?id=")

# === workload picker ========================================================
Write-Host "`n-- workload is a picker, not a placeholder --" -ForegroundColor Cyan
T 'a workload catalog cache exists'  ($gui -match 'function loadWorkloadCatalog')
T 'the workload field gets a combo'  ($gui -match 'pimAttachCombo\(wlIn')
# §35.6's one-shared-helper rule + BUG-88: do not invent another picker style.
T 'it REUSES pimAttachCombo'         ($gui -match 'pimAttachCombo\(wlIn, \(\) => wlCatalog\.items\)')
T 'the misleading e.g. placeholder is gone' ($gui -notmatch "example:'e\.g\. Defender / PowerBI / Intune'")
T 'a catalog read failure is surfaced'      ($gui -match 'Could not read the connector catalog')

# === workload roles =========================================================
Write-Host "`n-- workload ROLES come from the connector --" -ForegroundColor Cyan
T 'a per-workload role cache exists'        ($gui -match 'wlRoleCache')
T 'roles are sourced when target=workload'  ($gui -match "s\.target === 'workload' && s\.workload")
# The load-bearing one, same rule as the people-picker: a failed live read must not look like
# an empty catalog. Reading workload roles needs the tenant connection AND that connector's
# permission, so failing is legitimate -- "no roles exist" is a different claim.
T 'a failed role read is NOT rendered as "no roles"' ($gui -match 'This is <b>not</b> &ldquo;no roles exist&rdquo;')
T '   ...and says the lookup failed'                 ($gui -match 'the lookup failed')
T 'changing workload clears the chosen roles'        ($gui -match 's\.workload=v; s\.roles=\[\]')

# === azure scope ============================================================
Write-Host "`n-- the ARM path is browsable, and honest about the cache --" -ForegroundColor Cyan
T 'the ARM path field gets a combo'   ($gui -match 'pimAttachCombo\(scIn')
T 'sourced from the cached scopes'    ($gui -match 'const scopeItems = \(tlScopes\.items')
T 'the old ARM example placeholder is gone from that field' ($gui -notmatch "example:'/subscriptions/abc-123 or /providers/Microsoft\.Management/managementGroups/X',\s*\r?\n\s*hint:'Optional")
# 🔑 The enumerator reads BOTH management groups and subscriptions and swallows a failure to a
# warning, so a SHORT list is most often a rights problem, not a small tenant. Presenting a
# short list as complete is the silent-degradation defect this whole chapter is about.
T 'an EMPTY scope cache names the likely cause'  ($gui -match 'no ARM read rights at management-group / subscription level')
T 'a SHORT list is not presented as complete'    ($gui -match 'It is not proof the tenant has only these')

# === the §35.6 handoff ======================================================
Write-Host "`n-- §35.6: two surfaces, ONE workflow --" -ForegroundColor Cyan
T 'the grid emits the handoff'        ($gui -match 'PIM_WIZARD_PREFILL = \{ admin:')
T 'the wizard CONSUMES it'            ($gui -match 'window\.PIM_WIZARD_PREFILL && window\.PIM_WIZARD_PREFILL\.admin')
T '   ...into wizard state'           ($gui -match 's\._forAdmin' -or $gui -match 'state\._forAdmin')
# Consumed once and cleared, or re-opening the wizard later is silently still about whoever was
# selected twenty minutes ago -- a stale-context bug that looks like the operator's own mistake.
T 'it is CLEARED after being read'    ($gui -match 'window\.PIM_WIZARD_PREFILL = null')
T 'the wizard SHOWS who it is for'    ($gui -match 'Delegating access for')
T '   ...and says where that came from' ($gui -match 'carried over from the Admin accounts grid')
T '   ...and that nothing is written yet' ($gui -match 'nothing is written until')

# === v1 step 6: assignment type + duration ==================================
Write-Host "`n-- the operator's v1 step 6, which the wizard did not have --" -ForegroundColor Cyan
# The desired-state schema has carried AssignmentType / NumOfDaysWhenExpire / Permanent all
# along; the wizard HARDCODED Eligible + 365 into every staged row and never asked.
T 'an Assignment step exists'            ($gui -match "label: 'Assignment'")
# v1 pairs type WITH duration as ONE control -- "Eligible for 90 days" is a single decision.
T 'type and duration are ONE paired choice' ($gui -match "value:'Eligible\|365'" -and $gui -match "value:'Active\|90'")
T 'the v1 durations are offered (365/180/90)' ($gui -match "Eligible\|180" -and $gui -match "Eligible\|90")
T 'a permanent option exists'            ($gui -match "value:'Eligible\|0'")
T 'the choice is threaded into staging'  ($gui -match 'const ASG_TYPE' -and $gui -match 'AssignmentType: ASG_TYPE')
T 'duration is threaded too'             ($gui -match 'NumOfDaysWhenExpire: ASG_DAYS')
T 'permanent flips the Permanent flag'   ($gui -match "ASG_PERM = \(ASG_DAYS === '0'\) \? 'TRUE' : 'FALSE'")
T 'no delegation row still hardcodes Eligible/365' ($gui -notmatch "AssignmentType: 'Eligible', UpdateExisting:'FALSE'")
# The NESTING row is a different edge (permission group INTO role group) and keeps Active by
# design -- threading the delegation's choice into it would change an unrelated semantic.
T 'the nesting row deliberately stays Active' ($gui -match "AssignmentType:'Active', Action:'Assign'")
# Standing access is the exposure PIM exists to remove; choosing it should not be an unremarked
# dropdown value.
T 'choosing Active warns it is standing access' ($gui -match 'Active is standing access')
T 'choosing permanent warns it never expires'   ($gui -match 'never expires')

# === §35.3 level narrowing in the wizard ====================================
Write-Host "`n-- §35.3: the pickers NARROW to the caller's level --" -ForegroundColor Cyan
T 'the wizard loads the caller''s access'   ($gui -match 'function loadPimAccess' -and $gui -match "api\('GET', '/api/portal-access'\)")
# The role->level classification is served from the ENGINE's own functions. A second copy in JS
# would drift, and it would drift toward showing Global Administrator to someone without it.
T 'the endpoint serves the role-level model' ($srv -match 'roleLevels' -and $srv -match 'Get-PimPrivilegedEntraRoles' -and $srv -match 'Get-PimAuScopableRoles')
T 'the GUI does NOT hard-code the privileged list' ($gui -notmatch "'Global Administrator'\s*,\s*'Privileged Role Administrator'")
T 'the engine rule is applied (priv=L0, AU=L2, else L1)' ($gui -match 'function pimEntraRoleLevel')
T 'entra roles are narrowed by the ceiling' ($gui -match 'pimNarrowEntraRoles')
T 'targets are narrowed by service'         ($gui -match 'function pimAllowedServices')

# Narrowing must NEVER be silent: a short list is indistinguishable from a small catalog, and
# the operator would not know to ask for more rights.
T 'a narrowed role list SAYS it is narrowed'  ($gui -match 'are hidden because they are above your')
T '   ...and says it is a ceiling, not the catalog' ($gui -match 'This is your ceiling, not the whole catalog')
T 'a narrowed target list explains itself'    ($gui -match 'Some targets are hidden because your profile covers only')
# Narrowing to NOTHING would teach the operator the tool is broken rather than that they lack a
# right, so an empty result falls back to the full list.
T 'target narrowing never yields an empty list' ($gui -match 'if \(allowed\.length\)')

# 🔒 It is a usability layer, not the control -- SuperAdmin and an unknown profile skip it, and
# the server-side [SS2] gate is untouched.
T 'SuperAdmin is not narrowed'            ($gui -match 'if \(pimAccess\.isSuper \|\| !pimAccess\.profile\) return null')
T 'an unloaded profile means NO narrowing (fail-open on USABILITY only)' ($gui -match 'leave unloaded -> no narrowing, enforcement still applies' -or $guiRaw -match 'enforcement still applies')

# === item 3: the Manager must not pretend to run an engine job ==============
Write-Host "`n-- 'Run now' refuses engine jobs the Manager cannot run --" -ForegroundColor Cyan
# Invoke-PimJobForceStart honours handlers registered in THIS process, and the Manager registers
# none for the engine types -- the real handler is wired by Start-PimScheduler.ps1. So the button
# could only ever write a run that did nothing.
T 'the run endpoint refuses engine types'   ($srv -match "\`$_engineTypes = @\('engine-delta','engine-full','msp-pull'\)")
T '   ...only when no engine is present'    ($srv -match "-not \(Get-Command Invoke-PimEngine -ErrorAction SilentlyContinue\)")
T '   ...with 409, not a fake run'          ($srv -match "(?s)not-runnable-here")
T '   ...and records NOTHING'               ($srv -match 'Nothing was started and no run was recorded')
T '   ...and says where it DOES run'        ($srv -match 'ca-pim-tick / VisualCron')
T 'the refusal is audited'                  ($srv -match "schedule\.job\.run\.refused")

Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
