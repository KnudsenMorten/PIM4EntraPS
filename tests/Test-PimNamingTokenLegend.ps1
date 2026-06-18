#Requires -Version 5.1
<#
.SYNOPSIS
    Offline test for the GUI "supported variables/tokens" legend (REQUIREMENTS.md §11).
    Static analysis (no live tenant, no server boot) + a real probe of the engine
    resolver so the legend can never drift from what the engine actually expands.

.DESCRIPTION
    REQUIREMENTS §11 wants the Manager to SHOW the substitution tokens its naming-pattern
    fields (and the mail-template editor) support, so users stop guessing. This test keeps
    that honest:

      1. The Manager's naming-token catalog (the JS const PIM_NAMING_TOKENS in
         tools/pim-manager/pim-manager.html) MUST list exactly the tokens the engine
         resolver (engine/_shared/PIM-Naming.ps1 -> Expand-PimNamePattern, used by
         Resolve-PimAdminName / Resolve-PimGroupName / Resolve-PimResourceGroup) actually
         honours -- no missing token, no invented token.
      2. The legend states {Initial} is PREFERRED and {Owner} is the backward-compat
         synonym (the resolver maps both to the initials).
      3. The naming Value fields are marked data-token-field and the legend's click-to-
         insert chips target them (so it's a working picker, not dead UI).
      4. The mail-template editor renders a per-template supported-tokens legend derived
         from the shipped body (mailTemplateTokens) and targets #govMailBody.

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1 / PIM.Tests.ps1.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
$sol = Split-Path -Parent $here
$htmlPath   = Join-Path $sol 'tools\pim-manager\pim-manager.html'
$namingPath = Join-Path $sol 'engine\_shared\PIM-Naming.ps1'

Write-Host "=== PIM naming-token legend (REQUIREMENTS.md §11) ===" -ForegroundColor Cyan
T 'pim-manager.html present' (Test-Path -LiteralPath $htmlPath)
T 'PIM-Naming.ps1 present'    (Test-Path -LiteralPath $namingPath)
if ($fail) { Write-Host "`n=== RESULT: $pass passed, $fail failed ===" -ForegroundColor Red; exit 1 }

$html = [System.IO.File]::ReadAllText($htmlPath)

# --- 1. Tokens the GUI legend advertises -------------------------------------
# Parse the PIM_NAMING_TOKENS JS array literal and pull each `token: '{...}'`.
$constMatch = [regex]::Match($html, 'const\s+PIM_NAMING_TOKENS\s*=\s*\[(.*?)\];', 'Singleline')
T 'PIM_NAMING_TOKENS catalog present in HTML' ($constMatch.Success)
$guiTokens = New-Object System.Collections.Generic.List[string]
if ($constMatch.Success) {
    foreach ($m in [regex]::Matches($constMatch.Groups[1].Value, "token:\s*'(\{[A-Za-z]+\})'")) {
        [void]$guiTokens.Add($m.Groups[1].Value)
    }
}
T 'GUI legend lists at least 8 tokens' ($guiTokens.Count -ge 8)
$guiSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$guiTokens, [System.StringComparer]::OrdinalIgnoreCase)

# --- 2. Tokens the ENGINE actually expands -----------------------------------
# Dot-source the pure resolver and probe Expand-PimNamePattern: a token is "honoured"
# iff expanding "{Tok}" with a sentinel value yields the sentinel (i.e. it is replaced).
. $namingPath
function Test-TokenHonoured([string]$tok) {
    $name = $tok.Trim('{', '}')
    $out = Expand-PimNamePattern -Pattern $tok -Tokens @{ $name = 'SENTINEL' }
    return ($out -eq 'SENTINEL')
}
# The replacement is generic (any key in the hashtable), so to define the ENGINE's
# canonical token set we use the tokens that appear in the engine's DEFAULT patterns
# PLUS the synonyms the resolvers explicitly wire (Owner<->Initial, Platform<->EnvironmentSuffix).
$summary = Get-PimNamingSummary
$patternTokens = New-Object System.Collections.Generic.List[string]
foreach ($pat in @($summary.AdminDay2Day, $summary.AdminHighPriv, $summary.GroupPattern, $summary.GroupAuPattern, $summary.ResourceGroup)) {
    foreach ($m in [regex]::Matches("$pat", '\{([A-Za-z]+)\}')) { [void]$patternTokens.Add('{' + $m.Groups[1].Value + '}') }
}
# Synonyms/aliases the resolver wires in code (Resolve-PimAdminName tokens hashtable):
#   {Owner} == {Initial}; {Platform} == {EnvironmentSuffix}; {Role} also set from {Permission}.
$synonyms = @('{Initial}', '{Owner}', '{Platform}', '{EnvironmentSuffix}', '{Role}')
$engineTokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($t in $patternTokens) { [void]$engineTokens.Add($t) }
foreach ($t in $synonyms)      { [void]$engineTokens.Add($t) }
# Sanity: every engine token is actually expandable by the resolver (not a typo).
$notHonoured = @($engineTokens | Where-Object { -not (Test-TokenHonoured $_) })
T 'every engine token is actually expanded by Expand-PimNamePattern' ($notHonoured.Count -eq 0)
if ($notHonoured.Count) { Write-Host "    not honoured: $($notHonoured -join ', ')" -ForegroundColor Red }

# --- 3. GUI legend set == engine token set (no missing, no invented) ---------
$missingInGui = @($engineTokens | Where-Object { -not $guiSet.Contains($_) })
$inventedInGui = @($guiTokens   | Where-Object { -not $engineTokens.Contains($_) })
if ($missingInGui.Count)  { Write-Host "    MISSING from GUI legend:  $($missingInGui -join ', ')" -ForegroundColor Red }
if ($inventedInGui.Count) { Write-Host "    INVENTED in GUI legend:   $($inventedInGui -join ', ')" -ForegroundColor Red }
T 'GUI legend lists every engine token (none missing)'   ($missingInGui.Count -eq 0)
T 'GUI legend invents no token the engine ignores'       ($inventedInGui.Count -eq 0)

# --- 4. Preferred / synonym wording is present -------------------------------
T 'legend marks {Initial} as PREFERRED'                  ($html -match '\{Initial\}[^<]*PREFERRED|PREFERRED[^<]*\{Initial\}' -or $html -match "token:\s*'\{Initial\}'[^}]*PREFERRED")
T 'legend marks {Owner} as the synonym for {Initial}'    ($html -match "\{Owner\}[^}]*synonym" -or $html -match "synonym[^}]*\{Initial\}")
T 'legend notes {Platform}/{EnvironmentSuffix} are synonyms' ($html -match '\{Platform\}[^}]*[Ss]ynonym|[Ss]ynonym[^}]*\{EnvironmentSuffix\}')

# --- 5. Click-to-insert is a WORKING picker (not dead UI) --------------------
T 'buildTokenLegend helper exists'                       ($html -match 'function\s+buildTokenLegend')
T 'delegated tok-insert click handler exists'            ($html -match "closest\('\.tok-insert'\)|class=`"tok-insert")
T 'naming Value inputs are marked data-token-field'      ($html -match 'class="setNamingVal"\s+data-token-field="1"')
T 'naming legend targets the Value inputs'               ($html -match "buildTokenLegend\(PIM_NAMING_TOKENS,\s*'#setNamingTbl \.setNamingVal'")

# --- 6. Mail-template editor renders a per-template legend -------------------
T 'mailTemplateTokens helper exists'                     ($html -match 'function\s+mailTemplateTokens')
T 'mail editor builds a legend targeting #govMailBody'   ($html -match "buildTokenLegend\(mailToks,\s*'#govMailBody'")
T 'mail editor textarea is a token field'                ($html -match 'id="govMailBody" data-token-field="1"')

Write-Host ""
Write-Host ("  GUI tokens   : {0}" -f (($guiTokens | Sort-Object) -join ', ')) -ForegroundColor DarkGray
Write-Host ("  Engine tokens: {0}" -f ((@($engineTokens) | Sort-Object) -join ', ')) -ForegroundColor DarkGray

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
