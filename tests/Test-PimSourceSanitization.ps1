#Requires -Version 5.1
<#
.SYNOPSIS
    SEC-02 -- PIM-OWNED scan of PIM's own SOURCE for real identifiers that must never ship.

    The shared gate TOOLS/Test-PublicDocSanitization.ps1 scans DOCUMENTS only
    (README / RELEASENOTES / FEATURES / DESIGN). `.ps1` / `.psm1` / `.json` source is never
    scanned by it -- which is how two real tenant GUIDs, a real subscription id and a real
    management-group id sat in shipped source while every publish gate reported clean.

    🔒 This test deliberately DUPLICATES a little scanning logic instead of widening the shared
    tool. TOOLS/* is shared by all four solutions and widening it has already taken another
    solution from a passing publish gate to a blocked one. Isolation beats DRY here
    (CLAUDE.md "Scope -- PIM4EntraPS is its own project").

    Approach: a DENYLIST of the known-real values, kept in `internal/REAL-IDENTIFIERS.md`
    (internal/ is stripped at publish). A denylist, not a heuristic: PIM's source legitimately
    contains ~147 GUIDs -- Entra role template ids, sample ids, placeholder ids -- so a
    "flag every GUID" rule would be all false positives and would be switched off within a week.
    This asks the only question that matters: has one of the values we removed come back?

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function Assert($n, $c) { if ($c) { Write-Host "  PASS  $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL  $n" -ForegroundColor Red; $script:fail++ } }

$solRoot   = Split-Path -Parent $PSScriptRoot
$denyFile  = Join-Path $solRoot 'internal\REAL-IDENTIFIERS.md'

Write-Host "=== PIM source sanitization (SEC-02) ===" -ForegroundColor Cyan

# The denylist is the whole gate. If it cannot be read, this test must go RED rather than
# report a green it did not earn -- a security gate that silently finds nothing to check is
# worse than no gate (CLAUDE.md: a self-skip is a SKIP, not a pass).
Assert "denylist present: internal/REAL-IDENTIFIERS.md" (Test-Path -LiteralPath $denyFile)
if (-not (Test-Path -LiteralPath $denyFile)) {
    Write-Host "`n=== RESULT: $pass passed, $fail failed ===" -ForegroundColor Red; exit 1
}

$deny = @()
$inBlock = $false
foreach ($line in (Get-Content -LiteralPath $denyFile -Encoding UTF8)) {
    if ($line -match '^##\s*DENYLIST-BEGIN') { $inBlock = $true; continue }
    if ($line -match '^##\s*DENYLIST-END')   { $inBlock = $false; continue }
    if (-not $inBlock) { continue }
    if ($line -match '^\s*<!--') { continue }

    # SEC-05: TWO accepted forms. The original parser matched a GUID and NOTHING else,
    # so any non-GUID entry in the denylist was silently ignored -- the scan could not
    # find a UPN, a domain, a server name or a phone number even if one was listed.
    # That is why real admin UPNs and a phone number shipped publicly while this gate
    # reported green: the gate was not weak, it was structurally incapable.
    #   1. a bare GUID          -> 4ff34194-...  # label
    #   2. value: <literal>     -> value: admin@real.example  # label
    $label = "$(($line -split '#', 2)[1])".Trim()
    $lit = [regex]::Match($line, '^\s*value:\s*(?<v>.+?)\s*(?:#.*)?$')
    if ($lit.Success) {
        $v = "$($lit.Groups['v'].Value)".Trim().Trim('"',"'")
        # A too-short literal would match half the tree and make the gate useless noise.
        if ($v.Length -lt 5) { throw "denylist literal '$v' is too short to scan for -- use at least 5 characters" }
        $deny += [pscustomobject]@{ value = $v.ToLowerInvariant(); label = $label; kind = 'literal' }
        continue
    }
    $m = [regex]::Match($line, '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
    if ($m.Success) {
        $deny += [pscustomobject]@{ value = $m.Value.ToLowerInvariant(); label = $label; kind = 'guid' }
    }
}
$denyGuids    = @($deny | Where-Object { $_.kind -eq 'guid' })
$denyLiterals = @($deny | Where-Object { $_.kind -eq 'literal' })
Assert "denylist carries GUID entries ($($denyGuids.Count))"     ($denyGuids.Count -gt 0)
Assert "denylist carries LITERAL entries ($($denyLiterals.Count)) -- SEC-05" ($denyLiterals.Count -gt 0)
Assert "denylist parsed and non-empty ($($deny.Count) value(s))" ($deny.Count -gt 0)
if ($deny.Count -eq 0) { Write-Host "`n=== RESULT: $pass passed, $fail failed ===" -ForegroundColor Red; exit 1 }

# The SHIPPED tree -- everything the public mirror carries. internal/, tests/, docs/ and logs/
# are excluded: internal/ and tests/ are stripped at publish, and the docs are already covered
# by the shared document gate.
# NOTE `legacy` IS in this list. The publish strip removes internal/logs/staging/demo/
# output -- it does NOT remove legacy/, so a retired component still publishes. Retiring
# a file must not quietly move it out of this gate's view (IMP-05 moved one here).
$shippedDirs = @('engine', 'config', 'tools', 'workloads', 'launcher', 'setup', 'sql', 'templates', 'legacy')

# SEC-05: an UNTRACKED file cannot ship -- the publish takes what git has. Scanning it
# produces a finding nobody can fix by editing published content, which is the kind of
# false positive that trains the operator to ignore the gate. Tracked-ness is the exact
# criterion the gate cares about, so ask git. If git is unavailable the set is EMPTY and
# nothing is skipped -- the gate must never become MORE permissive because a tool is
# missing (that is how SEC-02 shipped a green on an unscannable class in the first place).
$untracked = @()
try {
    $u = & git -C $solRoot ls-files --others --exclude-standard 2>$null
    if ($LASTEXITCODE -eq 0 -and $u) {
        $untracked = @($u | ForEach-Object { (Join-Path $solRoot ("$_".Replace('/','\'))).ToLowerInvariant() })
    }
} catch { $untracked = @() }

$files = New-Object System.Collections.Generic.List[object]
$skippedUntracked = 0
foreach ($d in $shippedDirs) {
    $p = Join-Path $solRoot $d
    if (-not (Test-Path -LiteralPath $p)) { continue }
    foreach ($f in Get-ChildItem -LiteralPath $p -Recurse -File -Include '*.ps1','*.psm1','*.psd1','*.json','*.js','*.html','*.md','*.yml','*.yaml','*.sql','*.xml','*.csv' -EA SilentlyContinue) {
        # `*.custom.*` is where real environment values are SUPPOSED to live: it is
        # gitignored (SOLUTIONS/PIM4EntraPS/.gitignore) so it neither commits nor
        # publishes. Flagging it would be a false positive that trains the operator to
        # ignore this gate -- the one outcome that would make it useless.
        if ($f.Name -match '\.custom\.[^.]+$') { continue }
        # SEC-05: untracked -> cannot be published -> not this gate's business.
        if ($untracked -contains $f.FullName.ToLowerInvariant()) { $skippedUntracked++; continue }
        $files.Add($f)
    }
}
Assert "found shipped source to scan ($($files.Count) files)" ($files.Count -gt 0)
if ($skippedUntracked -gt 0) {
    Write-Host ("    (skipped $skippedUntracked untracked file(s) -- untracked cannot publish)") -ForegroundColor DarkGray
}

$hits = New-Object System.Collections.Generic.List[string]
foreach ($f in $files) {
    $text = ''
    try { $text = [System.IO.File]::ReadAllText($f.FullName) } catch { continue }
    if (-not $text) { continue }
    $lower = $text.ToLowerInvariant()
    foreach ($d in $deny) {
        if ($lower.Contains($d.value)) {
            $rel = $f.FullName.Substring($solRoot.Length).TrimStart('\', '/')
            # name the LINE so the fix is obvious, not a hunt
            $ln = 0; $where = ''
            foreach ($line in ($text -split "`n")) {
                $ln++
                if ($line.ToLowerInvariant().Contains($d.value)) { $where = ":$ln"; break }
            }
            $hits.Add("$rel$where -> $($d.label)")
        }
    }
}

foreach ($h in $hits) { Write-Host "    LEAK: $h" -ForegroundColor Red }
Assert "no real identifier from the denylist appears in shipped source" ($hits.Count -eq 0)

# Guard the guard: the scan must actually be capable of finding something. A denylist scan
# that silently matches nothing because of an encoding/path mistake would report the same
# green as a clean tree. Prove it fires on a synthetic file containing a denied value.
# SEC-05: prove it for BOTH kinds. Proving only the GUID kind is what let the literal
# path ship broken -- a decoy that only exercises the half that works proves nothing
# about the half that doesn't.
foreach ($kind in @($denyGuids, $denyLiterals)) {
    if (-not $kind -or $kind.Count -eq 0) { continue }
    $probe = $kind[0]
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pim-sec02-decoy-{0}.ps1" -f ([guid]::NewGuid().ToString('N')))
    try {
        Set-Content -LiteralPath $tmp -Value ("`$x = '{0}'" -f $probe.value) -Encoding UTF8
        $decoyText = ([System.IO.File]::ReadAllText($tmp)).ToLowerInvariant()
        Assert "the scan detects a planted $($probe.kind) value (gate is not a tautology)" ($decoyText.Contains($probe.value))
    } finally { Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue }
}

# SEC-02 fail-safe: with no test-tenant list configured, NOTHING may classify as a test
# tenant. Shipped source must not carry a default list -- that default decided where
# destructive features turn ON.
$guard = Join-Path $solRoot 'engine\_shared\PIM-DisableGuard.ps1'
if (Test-Path -LiteralPath $guard) {
    . $guard
    $prevG = $global:PIM_TestTenantIds; $prevE = $env:PIM_TestTenantIds
    try {
        $global:PIM_TestTenantIds = $null; $env:PIM_TestTenantIds = $null
        Assert "SEC-02: with nothing configured the test-tenant list is EMPTY" (@(Get-PimTestTenantIds).Count -eq 0)
        Assert "SEC-02: an unknown tenant therefore classifies as protected" ((Resolve-PimEnvironmentClass -TenantId '12345678-1234-1234-1234-123456789abc') -eq 'protected')
        $global:PIM_TestTenantIds = '22222222-2222-2222-2222-222222222222'
        Assert "SEC-02: a configured tenant still classifies as test" ((Resolve-PimEnvironmentClass -TenantId '22222222-2222-2222-2222-222222222222') -eq 'test')
    } finally { $global:PIM_TestTenantIds = $prevG; $env:PIM_TestTenantIds = $prevE }
}

# === SEC-03: no SQL path may put the session on the wire in clear text ==========
# The local/on-prem builders used Encrypt=False, so privileged desired-state data and the
# SQL session travelled unencrypted. Encrypt=True;TrustServerCertificate=True keeps the wire
# encrypted while still tolerating a self-signed cert -- which is what the §31 hybrid note
# actually intended. This asserts on the SOURCE so the concession cannot quietly widen again.
Write-Host "`n-- SEC-03: SQL transport encryption --" -ForegroundColor Cyan
$sqlStore = Join-Path $solRoot 'engine\_shared\PIM-SqlStore.ps1'
if (Test-Path -LiteralPath $sqlStore) {
    $sqlText = [System.IO.File]::ReadAllText($sqlStore)
    $connLines = @(($sqlText -split "`n") | Where-Object { $_ -match 'Server=.*Database=' -and $_ -match 'Encrypt=' })
    Assert "SEC-03: found the SQL connection-string builders ($($connLines.Count))" ($connLines.Count -ge 3)
    $clear = @($connLines | Where-Object { $_ -match 'Encrypt\s*=\s*False' })
    foreach ($c in $clear) { Write-Host "    CLEAR-TEXT: $($c.Trim())" -ForegroundColor Red }
    Assert "SEC-03: no connection string uses Encrypt=False" ($clear.Count -eq 0)
    # the Azure SQL path must stay FULLY strict -- encryption AND certificate validation
    Assert "SEC-03: the Azure SQL path still validates the certificate" ($sqlText -match 'Encrypt=True;TrustServerCertificate=False')
}

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
exit 0
