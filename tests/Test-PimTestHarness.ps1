#Requires -Version 5.1
<#
  TEST-28 -- THE RUNNER'S OWN INVARIANTS.

  The suite runner has an anti-rot check for every test file on disk (TEST-01/02/07), but
  nothing checked the RUNNER ITSELF. That gap shipped a red suite that nobody could see:

    `Run-AllPimTests.ps1` launched every child suite with `powershell.exe` (Windows
    PowerShell 5.1). Two suites added by the DEPLOY-2 / BUG-67 work declare
    `#Requires -Version 7`, so 5.1 refused them at line 1 -- ScriptRequiresUnmatchedPSVersion
    -- and the runner counted them as FAILED suites. Measured 2026-08-17: the full suite had
    been RED since 1c042e6d/075fbb01, and NEITHER new suite had ever actually EXECUTED inside
    it. Test-PimDeployDescriptor.ps1 is 13 pass / 0 fail under pwsh 7.

  🪤 The lesson is the one this runner keeps re-learning: a suite that cannot RUN reads
  exactly like a suite that FAILS, and both read like "someone else's problem". So the
  interpreter rule is derived from each suite's own `#Requires` (never a hand-kept list of
  "the PS7 ones"), and this file asserts that it stays that way.

  PS 5.1-compatible on purpose: it runs under powershell.exe like most of the suite.
#>
param()
$ErrorActionPreference = 'Stop'

$here   = $PSScriptRoot
$sol    = Split-Path -Parent $here
$runner = Join-Path $here 'Run-AllPimTests.ps1'

$script:pass = 0; $script:fail = 0
function T { param([string]$Name, [bool]$Cond, [string]$Detail = '')
    if ($Cond) { $script:pass++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:fail++; Write-Host "  FAIL  $Name$(if ($Detail) { " -- $Detail" })" -ForegroundColor Red } }

Write-Host "`n== 1. THE RUNNER EXISTS AND PARSES ==" -ForegroundColor Cyan
T 'Run-AllPimTests.ps1 exists' (Test-Path -LiteralPath $runner)
$perr = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($runner, [ref]$null, [ref]$perr)
T 'the runner parses under 5.1 (it is the 5.1 entry point)' (@($perr).Count -eq 0) ("$(@($perr).Count) parse error(s)")

$src = Get-Content -LiteralPath $runner -Raw

Write-Host "`n== 2. NO CHILD SUITE IS LAUNCHED ON A HARD-CODED INTERPRETER ==" -ForegroundColor Cyan
# The defect, stated as an assertion: `& powershell.exe ... -File` to run a SUITE is what
# made a PS7 suite unrunnable. All three call sites must go through the single helper.
$hardCoded = [regex]::Matches($src, '(?im)^\s*&\s*powershell\.exe[^\r\n]*-File')
T 'no `& powershell.exe -File` child-suite launch remains in the runner' ($hardCoded.Count -eq 0) `
    ("$($hardCoded.Count) site(s) still hard-code the interpreter")
T 'the runner defines the derived interpreter helper Get-PimSuiteHost' ($src -match 'function\s+Get-PimSuiteHost')
T 'the runner funnels child suites through ONE launcher (Invoke-PimSuiteChild)' ($src -match 'function\s+Invoke-PimSuiteChild')
foreach ($fn in 'Invoke-PimStandaloneGates','Invoke-PimFunctionalSuites','Invoke-PimOutOfTreeSuites',
                'Invoke-PimScenarioSuites') {
    $def = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                                   $n.Name -eq $fn }, $true) | Select-Object -First 1
    T "$fn launches via Invoke-PimSuiteChild" ($null -ne $def -and $def.Extent.Text -match 'Invoke-PimSuiteChild')
}
# The -Gui path cannot use the launcher (it passes an extra -Install), so assert it at least
# derives the interpreter rather than hard-coding one.
T 'the -Gui path derives its interpreter too' ($src -match '\$guiExe\s*=\s*Get-PimSuiteHost')

Write-Host "`n== 2b. NO SUITE RUNNER RETURNS A COUNT (the output-stream capture trap) ==" -ForegroundColor Cyan
# 🔴 `& <exe>` inside a function writes the child's stdout into the FUNCTION'S OUTPUT STREAM.
# So `$n = Invoke-...Suites` captures every line the children printed PLUS the count -- a
# non-empty ARRAY, which is always truthy. That silently forced exit 1 on a fully green run.
# The runner documents this as fixed, but Invoke-PimScenarioSuites still did it: `-Scenario`
# could not pass. Every child-suite runner must record BY NAME and return nothing.
foreach ($fn in 'Invoke-PimStandaloneGates','Invoke-PimFunctionalSuites','Invoke-PimOutOfTreeSuites',
                'Invoke-PimScenarioSuites') {
    $def = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                                   $n.Name -eq $fn }, $true) | Select-Object -First 1
    $rets = @()
    if ($def) {
        $rets = @($def.FindAll({ param($n) $n -is [System.Management.Automation.Language.ReturnStatementAst] -and
                                           $null -ne $n.Pipeline }, $true))
    }
    T "$fn returns no value (records by name instead)" ($null -ne $def -and $rets.Count -eq 0) `
        ("$($rets.Count) value-returning `return` statement(s)")
}
# Checked via the AST, NOT the text: the runner deliberately KEEPS a comment quoting the old
# `$scnFail = Invoke-PimScenarioSuites ...` line to explain the trap, and a text match flags
# that comment as the defect it documents. Assert on real assignments only.
# Match a real COMMAND INVOCATION on the right-hand side -- not merely the name appearing in
# the text. The $OutOfTreeExcluded reasons legitimately mention "(Invoke-PimScenarioSuites)",
# and a substring match calls that hashtable a defect.
$badAssign = @($ast.FindAll({ param($n)
        if ($n -isnot [System.Management.Automation.Language.AssignmentStatementAst]) { return $false }
        $cmds = $n.Right.FindAll({ param($c)
                    $c -is [System.Management.Automation.Language.CommandAst] }, $true)
        foreach ($c in $cmds) {
            $cn = $c.GetCommandName()
            if ($cn -and $cn -match '^Invoke-Pim\w*Suites$') { return $true }
        }
        return $false
    }, $true))
T 'no suite runner''s result is ASSIGNED to a variable (AST-checked, comments ignored)' `
    ($badAssign.Count -eq 0) `
    (($badAssign | ForEach-Object { $_.Extent.Text }) -join ' | ')

Write-Host "`n== 3. THE HELPER'S BEHAVIOUR (exercised, not just present) ==" -ForegroundColor Cyan
# Define the real helper here by lifting its own source out of the runner -- dot-sourcing the
# runner would RUN the entire test suite. The AST extent is the function verbatim.
$helperAst = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                                      $n.Name -eq 'Get-PimSuiteHost' }, $true) | Select-Object -First 1
if (-not $helperAst) { T 'Get-PimSuiteHost is liftable from the runner' $false 'function not found'; }
else {
    . ([scriptblock]::Create($helperAst.Extent.Text))
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pimharness-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force $tmp | Out-Null
    try {
        $f7   = Join-Path $tmp 'seven.ps1';    Set-Content $f7   "#Requires -Version 7`r`n'x'"   -Encoding ASCII
        $f70  = Join-Path $tmp 'sevendot.ps1'; Set-Content $f70  "#Requires -Version 7.0`r`n'x'" -Encoding ASCII
        $f51  = Join-Path $tmp 'five.ps1';     Set-Content $f51  "#Requires -Version 5.1`r`n'x'" -Encoding ASCII
        $fnone= Join-Path $tmp 'none.ps1';     Set-Content $fnone "'x'"                          -Encoding ASCII
        $fcase= Join-Path $tmp 'case.ps1';     Set-Content $fcase "#requires  -version   7`r`n'x'" -Encoding ASCII

        T 'a #Requires -Version 7 suite routes to pwsh'        ((Get-PimSuiteHost -Path $f7)    -match 'pwsh')
        T 'a #Requires -Version 7.0 suite routes to pwsh'      ((Get-PimSuiteHost -Path $f70)   -match 'pwsh')
        T 'lower-case / spaced #requires is honoured too'      ((Get-PimSuiteHost -Path $fcase) -match 'pwsh')
        T 'a #Requires -Version 5.1 suite stays on powershell.exe' ((Get-PimSuiteHost -Path $f51)   -eq 'powershell.exe')
        T 'a suite with NO #Requires stays on powershell.exe'       ((Get-PimSuiteHost -Path $fnone) -eq 'powershell.exe')

        # 🔴 The regression that started this: the helper must NOT read the requirement via the
        # AST, because under 5.1 a PS7-only file fails to parse and ScriptRequirements can come
        # back null -- which would silently route it to 5.1 again. Prove it on real PS7 syntax.
        $fternary = Join-Path $tmp 'ternary.ps1'
        Set-Content $fternary "#Requires -Version 7`r`n`$a = 1`r`n`$b = (`$a -eq 1) ? 'y' : 'n'`r`n`$b" -Encoding ASCII
        $tern = [System.Management.Automation.Language.Parser]::ParseFile($fternary, [ref]$null, [ref]([ref]$null).Value)
        T 'a PS7-only suite routes to pwsh even though 5.1 CANNOT parse it' `
            ((Get-PimSuiteHost -Path $fternary) -match 'pwsh')
    } finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
}

Write-Host "`n== 4. EVERY PS7 SUITE ON DISK IS REACHABLE (the anti-rot half) ==" -ForegroundColor Cyan
# Derived from disk, like the runner's own inventory: if pwsh is absent, these CANNOT run --
# and that must be a loud failure, never a silent pass. Assert the runner says so.
$ps7Suites = @(Get-ChildItem $here -File -Filter 'Test-Pim*.ps1' | Where-Object {
                  (Get-Content -LiteralPath $_.FullName -Raw) -match '(?im)^\s*#requires\s+-version\s+[6-9]' })
Write-Host ("   {0} suite(s) in tests\ declare PS7: {1}" -f $ps7Suites.Count,
            (($ps7Suites | ForEach-Object { $_.Name }) -join ', ')) -ForegroundColor DarkGray
T 'a missing pwsh is recorded as a FAILURE, not skipped silently' ($src -match 'needs pwsh 7')
T 'pwsh is resolved as an Application (never a function/alias shadow)' ($src -match "Get-Command\s+'pwsh\.exe'\s+-CommandType\s+Application")

Write-Host "`n== 5. THE READINESS PROBE IS NOT RUN AS A TEST SUITE ==" -ForegroundColor Cyan
# tools\setup\Test-PimTenantReady.ps1 is the DEPLOY-TIME probe (framework DEPLOY-2), named
# Test-Pim* because it answers "is this tenant ready". Run as a suite it reports NOT READY
# (0/7) against a tenant it was never pointed at -- correct behaviour, meaningless verdict.
$probeRel = 'tools\setup\Test-PimTenantReady.ps1'
T 'the probe exists where the exclusion claims' (Test-Path -LiteralPath (Join-Path $sol $probeRel))
T 'the probe is DECLARED in the out-of-tree EXCLUDED table (so the anti-rot scan is satisfied)' `
    ($src -match [regex]::Escape($probeRel))
# It must be in the EXCLUDED table, not the table of out-of-tree suites that DO run.
$runTable = [regex]::Match($src, '(?s)\$OutOfTreeSuites\s*=\s*\[ordered\]@\{(.*?)\n\}')
T 'the probe is NOT in $OutOfTreeSuites (it must never be executed as a suite)' `
    (-not ($runTable.Success -and $runTable.Groups[1].Value -match [regex]::Escape($probeRel)))
T 'its OFFLINE cover is in the run path (tests\Test-PimTenantReady.ps1)' `
    (Test-Path -LiteralPath (Join-Path $here 'Test-PimTenantReady.ps1'))

Write-Host ("`n==== test harness (TEST-28): {0} passed, {1} failed ====" -f $script:pass, $script:fail) `
    -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
if ($script:fail) { exit 1 }
exit 0
