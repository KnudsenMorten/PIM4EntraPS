#Requires -Version 5.1
<#
.SYNOPSIS
    AutomateIT RING-1 adoption test -- PIM's deploy contract (solution.deploy.json)
    and PIM's vendored copy of the platform ring decision core (PIM-RingGate.ps1).
    The GATE for "PIM consumes the AutomateIT framework design instead of its own".

.DESCRIPTION
    All OFFLINE (no live tenant, no network, no server boot). Layers:

      1. CONTRACT SHAPE  -- solution.deploy.json parses and carries every key the
                            framework's spine requires; capabilities are well-formed;
                            deploy.appliesTo names only DECLARED capabilities.
      2. VERIFIED FACTS  -- needsSchema is checked against REALITY (the shipped DDL +
                            the DeployAll 'schema' step), so the flag cannot drift
                            from the code. The RING-1 runbook demands this be
                            verified, not assumed.
      3. PLATFORM PARITY -- PIM's VENDORED core returns byte-identical verdicts to
                            the real sync/_AitRings.ps1 across every branch.
                            🔒 When the platform file is NOT reachable (a published
                            customer tree -- sync/ is not part of any solution's
                            payload) this REPORTS and SKIPS rather than failing:
                            PIM's CLAUDE.md forbids failing PIM's suite on a shared
                            file PIM does not own.
      4. CO-REQUISITES   -- the 'code implies schema' invariant fires on the exact
                            promotion shape the shipped sample map uses.
      5. NON-BREAKING    -- an unassigned target is track-current, an assigned target
                            with nothing promoted HOLDS (never silently falls back),
                            and a customer's block on a REQUIRED capability is
                            REFUSED rather than obeyed.

    Run standalone (exits 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0; $skip = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }
function S($n, $why) { Write-Host "  SKIP $n -- $why" -ForegroundColor DarkYellow; $script:skip++ }
# NB: named 'Report', NOT 'R' -- 'R' is a built-in ALIAS for Invoke-History, and in
# PowerShell an alias OUTRANKS a function, so `R "..."` silently called Invoke-History
# and threw. Never use a single letter that Get-Alias already resolves.
function Report($m) { Write-Host "  REPORT $m" -ForegroundColor Yellow }

$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $root 'engine\_shared\PIM-RingGate.ps1')

# NB: assign FIRST, then wrap -- never @(pipeline). Under PS 5.1 ConvertFrom-Json
# emits an array as ONE object, so @(Get-Content ... | ConvertFrom-Json) yields a
# 1-element array containing the whole Object[]. That is BUG-26, and this suite
# must not reproduce the defect it exists alongside.
$contractPath = Join-Path $root 'solution.deploy.json'
$contractRaw  = Get-Content -LiteralPath $contractPath -Raw
$contract     = $contractRaw | ConvertFrom-Json
$declared     = @($contract.capabilities)

Write-Host ''
Write-Host '== 1. CONTRACT SHAPE ==' -ForegroundColor Cyan

T 'solution.deploy.json exists and parses'            ($null -ne $contract)
T "schema is 1 (got '$($contract.schema)')"           ([int]$contract.schema -eq 1)
T "solution is PIM4EntraPS"                           ("$($contract.solution)" -eq 'PIM4EntraPS')
T 'declares at least one capability'                  ($declared.Count -ge 1)

$badCap = @($declared | Where-Object {
    -not "$($_.name)".Trim() -or
    ($_.PSObject.Properties.Name -notcontains 'optional') -or
    -not "$($_.description)".Trim()
})
T 'every capability has name + optional + description' ($badCap.Count -eq 0)

$names = @($declared | ForEach-Object { "$($_.name)" })
$dupes = @($names | Group-Object | Where-Object { $_.Count -gt 1 })
T 'capability names are unique'                        ($dupes.Count -eq 0)

$required = @($declared | Where-Object { -not $_.optional } | ForEach-Object { "$($_.name)" })
T "at least one REQUIRED capability (got: $($required -join ', '))" ($required.Count -ge 1)
T "'code' is declared and REQUIRED"                    ($required -contains 'code')

# appliesTo must not name a capability that does not exist -- a typo here silently
# means "this deploy step covers nothing".
$appliesTo = @($contract.deploy.appliesTo)
$unknown   = @($appliesTo | Where-Object { $names -notcontains $_ })
T 'deploy.appliesTo names only DECLARED capabilities'  ($unknown.Count -eq 0)
if ($unknown.Count) { Report "appliesTo names undeclared capabilities: $($unknown -join ', ')" }

T 'deploy.script is set'                               ("$($contract.deploy.script)".Trim() -ne '')
$deployScript = Join-Path $root ("$($contract.deploy.script)" -replace '/', '\')
T "deploy.script EXISTS on disk ($($contract.deploy.script))" (Test-Path -LiteralPath $deployScript)

T 'declares the platform dependency'                   (@($contract.dependencies) -contains 'PlatformConfiguration')

Write-Host ''
Write-Host '== 2. VERIFIED FACTS (needsSchema must match reality) ==' -ForegroundColor Cyan

# The runbook: "needsSchema must be VERIFIED, not assumed." So verify it against the
# tree rather than trusting the flag -- if PIM ever loses its DDL, this must fail.
$ddl = @(Get-ChildItem -LiteralPath (Join-Path $root 'sql') -Filter '*schema*.sql' -ErrorAction SilentlyContinue)
$deployAll = Join-Path $root 'engine\_shared\PIM-DeployAll.ps1'
$hasSchemaStep = $false
if (Test-Path -LiteralPath $deployAll) {
    $daRaw = Get-Content -LiteralPath $deployAll -Raw
    $hasSchemaStep = ($daRaw -match "key\s*=\s*'schema'")
}

T "PIM ships schema DDL ($($ddl.Count) file(s) under sql/)"       ($ddl.Count -ge 1)
T 'the whole-solution orchestrator has a schema step'             ($hasSchemaStep)
T 'needsSchema is TRUE, and matches both facts above'             ([bool]$contract.needsSchema -eq $true -and $ddl.Count -ge 1 -and $hasSchemaStep)

Write-Host ''
Write-Host '== 3. PLATFORM PARITY (vendored core vs sync/_AitRings.ps1) ==' -ForegroundColor Cyan

# sync/ is NOT part of any solution's published payload, so on a customer tree this
# file is absent BY DESIGN. Report + skip; never fail PIM's suite on it.
$platformCore = Join-Path (Split-Path -Parent (Split-Path -Parent $root)) 'sync\_AitRings.ps1'
if (-not (Test-Path -LiteralPath $platformCore)) {
    S 'platform parity' "sync\_AitRings.ps1 not reachable from this tree (expected in a published/customer tree -- sync/ is not part of the solution payload). PIM's vendored core CANNOT be diffed here."
    Report 'Parity is unverified in this tree. Run this suite in the monorepo dev tree before releasing a change to PIM-RingGate.ps1.'
} else {
    . $platformCore

    $cases = @(
        @{ n='unrestricted ring ($null allow)';       allow=$null;                                                  block=$null }
        @{ n='EMPTY allow (nothing approved)';        allow=@();                                                    block=$null }
        @{ n='allow code only (the skew case)';       allow=@('code');                                              block=$null }
        @{ n='allow everything declared';             allow=$names;                                                 block=$null }
        @{ n='customer blocks an OPTIONAL';           allow=$null;                                                  block=@('infra') }
        @{ n='customer blocks a REQUIRED';            allow=$null;                                                  block=@('schema') }
        @{ n='blocked + held mixture';                allow=@('code');                                              block=@('schema','appreg') }
        @{ n='block a capability that is not declared'; allow=$null;                                                block=@('does-not-exist') }
    )

    foreach ($c in $cases) {
        $a = Get-AitRingCapabilityDecision -Declared $declared -RingAllow $c.allow -CustomerBlocked $c.block
        $p = Get-PimRingCapabilityDecision -Declared $declared -RingAllow $c.allow -CustomerBlocked $c.block
        $same = $true
        foreach ($k in 'Run','Held','Blocked','Refused') {
            if ((@($a.$k) -join '|') -ne (@($p.$k) -join '|')) { $same = $false }
        }
        T "parity: $($c.n)" $same
        if (-not $same) {
            Report "platform Run=[$($a.Run -join ',')] Held=[$($a.Held -join ',')] Blocked=[$($a.Blocked -join ',')] Refused=[$($a.Refused -join ',')]"
            Report "pim      Run=[$($p.Run -join ',')] Held=[$($p.Held -join ',')] Blocked=[$($p.Blocked -join ',')] Refused=[$($p.Refused -join ',')]"
        }
    }
}

Write-Host ''
Write-Host '== 3b. SELF-STANDING CORE INVARIANTS (no platform file needed) ==' -ForegroundColor Cyan

# 🔒 WHY THIS SECTION EXISTS -- found by negative verification 2026-08-07.
# Section 3 can only catch a fork when sync/_AitRings.ps1 is REACHABLE. In a
# published customer tree it never is, so a forked vendored core would be
# completely invisible there. Sabotaging 'Held collapsed into Blocked' and
# '$null allow treated as empty' both left the suite GREEN for exactly that
# reason. These assertions check the framework's load-bearing invariants against
# PIM's core ALONE, so a fork is caught with or without the platform file.

$invAll  = Get-PimRingCapabilityDecision -Declared $declared -RingAllow $null
$invNone = Get-PimRingCapabilityDecision -Declared $declared -RingAllow @()
T '$null allow (unrestricted) runs EVERY declared capability' (@($invAll.Run).Count -eq $names.Count)
T 'EMPTY allow runs NOTHING and holds everything'             (@($invNone.Run).Count -eq 0 -and @($invNone.Held).Count -eq $names.Count)
T 'RULE: $null allow and EMPTY allow are NOT the same thing'      ((@($invAll.Run) -join '|') -ne (@($invNone.Run) -join '|'))

# Held (operator has not promoted) must never be reported as Blocked (customer
# opted out). Collapsing them makes a stalled rollout look like a healthy opt-out.
$invHeld = Get-PimRingCapabilityDecision -Declared $declared -RingAllow @('code')
T 'RULE: a ring-held capability lands in Held, NOT in Blocked'    (@($invHeld.Held) -contains 'schema' -and @($invHeld.Blocked) -notcontains 'schema')
T '  ...and with no customer block, Blocked is empty'          (@($invHeld.Blocked).Count -eq 0)

# An optional block is obeyed; a required block is refused. Both, from PIM's core.
$invOpt = Get-PimRingCapabilityDecision -Declared $declared -RingAllow $null -CustomerBlocked @('infra')
$invReq = Get-PimRingCapabilityDecision -Declared $declared -RingAllow $null -CustomerBlocked @('code')
T 'an OPTIONAL block is obeyed (Blocked, not Run)'             (@($invOpt.Blocked) -contains 'infra' -and @($invOpt.Run) -notcontains 'infra')
T 'a REQUIRED block is refused (Refused AND still Run)'        (@($invReq.Refused) -contains 'code' -and @($invReq.Run) -contains 'code')

Write-Host ''
Write-Host '== 4. CO-REQUISITE INVARIANT (code implies schema) ==' -ForegroundColor Cyan

$co = @($contract.coRequisiteCapabilities)
T 'contract declares at least one co-requisite rule' ($co.Count -ge 1)

# The shipped sample map promotes PIM with allow:['code'] -- the exact shape that
# deploys new code against an un-upgraded database. The invariant must catch it.
$skew = Get-PimRingCapabilityDecision -Declared $declared -RingAllow @('code')
$v = Test-PimCoRequisiteCapabilities -Decision $skew -CoRequisites $co
T "allow:['code'] alone is reported as a co-requisite VIOLATION" (-not $v.ok)
T '  ...and the violation names the missing co-requisite'        (@($v.violations) -join ' ' -match 'schema')

# ...and the corrected promotion must be clean, or the check is just noise.
$ok = Get-PimRingCapabilityDecision -Declared $declared -RingAllow @('code','schema')
$v2 = Test-PimCoRequisiteCapabilities -Decision $ok -CoRequisites $co
T "allow:['code','schema'] is CLEAN (the rule is not vacuous)"   ($v2.ok)

# A capability that is not running cannot violate its own co-requisite.
$none = Get-PimRingCapabilityDecision -Declared $declared -RingAllow @()
$v3 = Test-PimCoRequisiteCapabilities -Decision $none -CoRequisites $co
T 'nothing approved => no co-requisite violation (not a false alarm)' ($v3.ok)

# Report the real shipped maps, so a bad promotion is visible without failing on a
# shared file PIM does not own.
foreach ($mapName in 'release-map.json','release-map.sample.json') {
    $mapPath = Join-Path (Split-Path -Parent (Split-Path -Parent $root)) "sync\$mapName"
    if (-not (Test-Path -LiteralPath $mapPath)) { continue }
    $mapRaw = Get-Content -LiteralPath $mapPath -Raw
    $map = $mapRaw | ConvertFrom-Json
    $pimPromo = $null
    if ($map.promotions) {
        foreach ($pp in $map.promotions.PSObject.Properties) {
            if ("$($pp.Name)" -ieq 'PIM4EntraPS') { $pimPromo = $pp.Value; break }
        }
    }
    if (-not $pimPromo) { continue }
    foreach ($chan in $pimPromo.PSObject.Properties) {
        foreach ($ringSlot in $chan.Value.PSObject.Properties) {
            $slot = $ringSlot.Value
            $allow = $null
            if ($slot -isnot [string] -and $slot.PSObject.Properties.Name -contains 'allow') { $allow = @($slot.allow) }
            $d = Get-PimRingCapabilityDecision -Declared $declared -RingAllow $allow
            $chk = Test-PimCoRequisiteCapabilities -Decision $d -CoRequisites $co
            if (-not $chk.ok) {
                Report "$mapName -> PIM4EntraPS/$($chan.Name)/ring $($ringSlot.Name): $($chk.violations -join '; ')"
            }
        }
    }
}

Write-Host ''
Write-Host '== 5. NON-BREAKING RULE + the two gates ==' -ForegroundColor Cyan

$assign = [pscustomobject]@{ 'tenant-a' = [pscustomobject]@{ 'Baseline' = [pscustomobject]@{ ring = 2 } } }
$promoted   = [pscustomobject]@{ 'Baseline' = [pscustomobject]@{ 'managed' = [pscustomobject]@{ '2' = [pscustomobject]@{ version='v1'; allow=@('code','schema') } } } }
$unpromoted = [pscustomobject]@{ 'Baseline' = [pscustomobject]@{ 'managed' = [pscustomobject]@{ } } }

$planUnassigned = Get-PimTemplateRingPlan -Template 'Baseline' -TenantId 'nobody' -Assignments $assign -Promotions $promoted -Declared $declared
T 'RULE: UNASSIGNED target => track-current (today''s behaviour)'  ($planUnassigned.Action -eq 'track-current')

$planHold = Get-PimTemplateRingPlan -Template 'Baseline' -TenantId 'tenant-a' -Assignments $assign -Promotions $unpromoted -Declared $declared
T 'assigned + nothing promoted => HOLD, never a silent fallback' ($planHold.Action -eq 'hold')

$planUpdate = Get-PimTemplateRingPlan -Template 'Baseline' -TenantId 'tenant-a' -Assignments $assign -Promotions $promoted -Declared $declared
T 'assigned + promoted => update, carrying the approved version' ($planUpdate.Action -eq 'update' -and "$($planUpdate.Version)" -eq 'v1')

$planBlocked = Get-PimTemplateRingPlan -Template 'Baseline' -TenantId 'tenant-a' -Assignments $assign -Promotions $promoted -Declared $declared -CustomerBlocked @('schema')
T 'a block on a REQUIRED capability is REFUSED, not obeyed'      (@($planBlocked.Capabilities.Refused) -contains 'schema')
T '  ...and it still RUNS (refusing the block means running it)' (@($planBlocked.Capabilities.Run) -contains 'schema')

# Held and Blocked must stay distinguishable, or the uplink cannot tell a stalled
# rollout from a healthy opt-out.
$planMixed = Get-PimTemplateRingPlan -Template 'Baseline' -TenantId 'tenant-a' -Assignments $assign `
                -Promotions ([pscustomobject]@{ 'Baseline' = [pscustomobject]@{ 'managed' = [pscustomobject]@{ '2' = [pscustomobject]@{ version='v1'; allow=@('code','schema','infra') } } } }) `
                -Declared $declared -CustomerBlocked @('infra')
T 'Held and Blocked are DISTINCT outcomes'  (@($planMixed.Capabilities.Blocked) -contains 'infra' -and @($planMixed.Capabilities.Held) -notcontains 'infra')

Write-Host ''
Write-Host '== 5b. BUG-28: the declared entry point carries NO operator infrastructure ==' -ForegroundColor Cyan
# The contract names tools/setup/Invoke-PimUpdate.ps1 as the deploy entry point, and that
# file SHIPS TO CUSTOMERS. Its -ResourceGroup / -AcrName / -Recipient used to default to
# the operator's own resource group, container registry and mailbox, so a customer running
# the sync-driven deploy without supplying them would have aimed at the operator's estate.
# Assert on the PARAMETER BLOCK, which is where a default can be reintroduced.
$entry = Join-Path $root ([string]$contract.deploy.script).Replace('/', '\')
T 'the contract entry point exists on disk' (Test-Path -LiteralPath $entry)
if (Test-Path -LiteralPath $entry) {
    $entryRaw = Get-Content -Raw -LiteralPath $entry
    $paramBlock = ''
    $mParam = [regex]::Match($entryRaw, '(?s)^param\s*\(.*?\n\)', 'Multiline')
    if (-not $mParam.Success) { $mParam = [regex]::Match($entryRaw, '(?s)\nparam\s*\(.*?\n\)') }
    if ($mParam.Success) { $paramBlock = $mParam.Value }
    T '  ...and its param block is readable' ([bool]$paramBlock)
    # Scan CODE only -- the comments there quote the old values to explain the fix, and a
    # comment explaining a bug must not fail the test that prevents it (the same rule the
    # registry-sweep asserts in Test-PimScenarioCleanup.ps1 already follow).
    $paramCode = (($paramBlock -split "`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    T '  ...no default resource group'   ($paramCode -notmatch "ResourceGroup\s*=\s*'[^']+'")
    T '  ...no default registry name'    ($paramCode -notmatch "AcrName\s*=\s*'[^']+'")
    T '  ...no default mail recipient'   ($paramCode -notmatch "Recipient\s*=\s*'[^']+'")
    # ...and they come from the environment instead, per the SEC-02 pattern.
    T '  ...ResourceGroup reads $env:'   ($paramCode -match 'ResourceGroup\s*=\s*"\$\(\$env:')
    T '  ...AcrName reads $env:'         ($paramCode -match 'AcrName\s*=\s*"\$\(\$env:')
    T '  ...Recipient reads $env:'       ($paramCode -match 'Recipient\s*=\s*"\$\(\$env:')
    # A missing target must FAIL the hosted deploy, not silently proceed.
    T 'a hosted deploy REFUSES an unconfigured target' ($entryRaw -match 'hosted deploy target not configured')
    T '  ...and a missing recipient SKIPS notify instead of failing the deploy' ($entryRaw -match 'notify SKIPPED -- no recipient')
    # 🪤 The real risk is a literal that LOOKS like infrastructure sneaking back into any
    # default. Catch the shapes, not just the three names that were wrong this time.
    $suspect = @()
    foreach ($m in [regex]::Matches($paramCode, "=\s*'([^']*)'")) {
        $v = $m.Groups[1].Value
        if ($v -match '^(rg|acr|kv|st|sql)-?[a-z0-9]' -and $v -notmatch '^(pim-manager|ca-pim)') { $suspect += $v }
        if ($v -match '@' -and $v -match '\.') { $suspect += $v }   # an email address
    }
    T '  ...no infrastructure-shaped or email default anywhere in the param block' (@($suspect).Count -eq 0)
    if (@($suspect).Count) { Report ("suspect defaults: " + (@($suspect) -join ', ')) }
}

Write-Host ''
Write-Host '== 6. SCENARIO DIMENSION CONTRACT (PLAT-07) ==' -ForegroundColor Cyan
# RING-1 phase 1 item 3: the dimension contract is a PLATFORM primitive that PIM
# CONSUMES. PIM owns only its CATALOG and its BINDINGS.
. (Join-Path $root 'engine\_shared\PIM-ScenarioProfile.ps1')
$pimDims = Get-PimGenericScenarioDimensions

# --- self-standing invariants: these hold with NO platform file present ---------
# Learned on the ring core: parity that can only be checked where the platform file
# is reachable is not parity everywhere, and two deliberate forks went undetected
# until an invariant layer was added. A customer tree has no sync/ at all.
T 'PIM exposes the generic dimension contract'   ($pimDims -and $pimDims.Keys.Count -ge 8)
T '  ...and every dimension declares values + a description' (@($pimDims.Keys | Where-Object { -not @($pimDims[$_].values).Count -or -not "$($pimDims[$_].description)".Trim() }).Count -eq 0)
# ⚠️ The fork this guards against: a PIM-specific dimension smuggled into a contract
# that is supposed to describe ANY solution's install shape.
$pimOnlyWords = @('pim', 'entra', 'admin', 'ring')
$leaky = @($pimDims.Keys | Where-Object { $k = "$_".ToLowerInvariant(); @($pimOnlyWords | Where-Object { $k -like "*$_*" }).Count -gt 0 })
T '  ...and NO dimension name carries a PIM specific' (@($leaky).Count -eq 0)
# Every catalog entry must satisfy the contract -- a missing dimension is not a default.
$catalog = @(Get-PimScenarioCatalog)
T "PIM ships a scenario catalog ($($catalog.Count) descriptors)" ($catalog.Count -ge 6)
$badDescriptors = New-Object System.Collections.Generic.List[string]
foreach ($d in $catalog) {
    foreach ($dim in $pimDims.Keys) {
        $v = "$($d.$dim)".Trim()
        if (-not $v) { [void]$badDescriptors.Add("$($d.id): missing '$dim'"); continue }
        if (@($pimDims[$dim].values) -notcontains $v) { [void]$badDescriptors.Add("$($d.id): '$dim'='$v' not permitted") }
    }
}
T 'every catalog descriptor obeys the dimension contract' (@($badDescriptors).Count -eq 0)
if (@($badDescriptors).Count) { Report ("descriptor problems: " + (@($badDescriptors) -join '; ')) }
T 'every descriptor keeps its PIM bindings separate' (@($catalog | Where-Object { -not $_.bindings }).Count -eq 0)

# --- parity against the real platform primitive, when reachable -----------------
$platformScenarios = Join-Path (Split-Path -Parent (Split-Path -Parent $root)) 'sync\_AitScenarios.ps1'
if (-not (Test-Path -LiteralPath $platformScenarios)) {
    S 'scenario dimension parity' "sync\_AitScenarios.ps1 not reachable from this tree (expected on a customer tree -- sync/ is not part of the solution payload). PIM's vendored dimensions CANNOT be diffed here."
    Report 'Dimension parity is unverified in this tree. Run this suite in the monorepo dev tree before releasing a change to Get-PimGenericScenarioDimensions.'
} else {
    . $platformScenarios
    $aitDims = Get-AitGenericScenarioDimensions
    T 'dimension NAMES match the platform exactly'  ((@($pimDims.Keys) -join ',') -eq (@($aitDims.Keys) -join ','))
    $valueDrift = New-Object System.Collections.Generic.List[string]
    foreach ($k in $aitDims.Keys) {
        $a = @($aitDims[$k].values) -join ','
        $p = @($pimDims[$k].values) -join ','
        if ($a -ne $p) { [void]$valueDrift.Add("$k : platform[$a] vs PIM[$p]") }
    }
    T '  ...and every dimension VALUE SET matches'  (@($valueDrift).Count -eq 0)
    if (@($valueDrift).Count) { Report ("dimension drift: " + (@($valueDrift) -join '; ')) }
    # The platform validator must agree with the loop above -- two implementations
    # of "is this descriptor valid" that disagree would be the fork all over again.
    $viaPlatform = @($catalog | ForEach-Object { Test-AitScenarioDescriptor -Descriptor $_ -Dimensions $aitDims } | Where-Object { -not $_.ok })
    T '  ...and the platform validator agrees PIM catalog is valid' (@($viaPlatform).Count -eq 0)
}

Write-Host ''
if ($skip) { Write-Host "==== Deploy-contract test: $pass passed, $fail failed, $skip skipped ====" -ForegroundColor $(if ($fail) { 'Red' } else { 'Yellow' }) }
else       { Write-Host "==== Deploy-contract test: $pass passed, $fail failed ====" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' }) }
if ($fail) { exit 1 }
exit 0
