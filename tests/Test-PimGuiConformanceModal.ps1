#Requires -Version 5.1
<#
.SYNOPSIS
    Static assertions for two GUI items (REQUIREMENTS.md s11):

      [L2] Conformance grant / approve / deploy / revoke no longer use the raw
           browser confirm()/prompt(): the Template Rollout tab drives them
           through the in-app reusable modals (pimConfirm / pimFormModal). The
           exemption GRANT collects reason + a mandatory expiry in a form modal.

      s29  Feature-customization dependency cross-references PROMPT/BLOCK at
           toggle time: enabling a feature whose prerequisite is off prompts to
           also enable the prerequisite; disabling a feature an enabled feature
           depends on warns and reverts the toggle on cancel.

    Static analysis only -- no live tenant, no server boot. The hosted/SQL
    Manager GUI smoke (CLAUDE.md s7a) is the live gate for both. Run standalone
    (exits 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$mgrDir   = Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\pim-manager'
$htmlPath = Join-Path $mgrDir 'pim-manager.html'
T 'pim-manager.html present' (Test-Path -LiteralPath $htmlPath)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }
$html = [System.IO.File]::ReadAllText($htmlPath)

Write-Host "`n--- Reusable modal helpers ([L2]) ---" -ForegroundColor Cyan
T "pimConfirm helper defined"                ($html -match 'function pimConfirm\(')
T "pimFormModal helper defined"              ($html -match 'function pimFormModal\(')
T "pimConfirm returns a Promise"             ($html -match 'function pimConfirm[\s\S]{0,200}return new Promise')
T "pimFormModal returns a Promise"           ($html -match 'function pimFormModal[\s\S]{0,200}return new Promise')
T "pimFormModal validates required fields"   ($html -match 'f\.required && !val')
T "pimFormModal cancels on Escape (null)"    ($html -match "e\.key === 'Escape'\) done\(null\)")
T "pimConfirm supports a danger style"        ($html -match "danger \? 'danger' : 'primary'")

Write-Host "`n--- Conformance actions use modals, not raw confirm/prompt ([L2]) ---" -ForegroundColor Cyan
# The four conformance interactions are wired to the in-app modals.
T "approve draft uses pimConfirm"            ($html -match "Approve draft template[\s\S]{0,200}/api/conformance/approve")
T "deploy live uses pimConfirm (danger)"     ($html -match "title: 'Deploy live'[\s\S]{0,260}danger: true")
T "exempt GRANT uses pimFormModal"           ($html -match "async function confExempt[\s\S]{0,300}pimFormModal\(")
T "exempt modal collects a reason field"     ($html -match "name: 'reason'[\s\S]{0,120}required: true")
T "exempt modal collects a mandatory expiry" ($html -match "name: 'expiry'[\s\S]{0,160}required: true")
T "exempt expiry defaults to +90d"           ($html -match 'function confDefaultExemptExpiry\(')
T "exempt still POSTs /api/conformance/exemptions" ($html -match "async function confExempt[\s\S]{0,1200}api\('POST',\s*'/api/conformance/exemptions'")
T "revoke exemption uses pimConfirm (danger)" ($html -match "async function confRevoke[\s\S]{0,260}pimConfirm\([\s\S]{0,200}danger: true")

# Guard: no raw confirm()/prompt() remain in the conformance functions.
$confBlock = ''
$mStart = [regex]::Match($html, 'async function renderConformance\(')
if ($mStart.Success) {
    $mEnd = [regex]::Match($html.Substring($mStart.Index), 'async function confDeploy\(')
    if ($mEnd.Success) { $confBlock = $html.Substring($mStart.Index, $mEnd.Index) }
}
T "conformance block captured for raw-dialog scan" ($confBlock.Length -gt 0)
T "no raw confirm() in conformance block"   (-not ($confBlock -match '[^A-Za-z]confirm\('))
T "no raw prompt() in conformance block"    (-not ($confBlock -match '[^A-Za-z]prompt\('))
T "no raw alert() in conformance block"     (-not ($confBlock -match '[^A-Za-z]alert\('))

Write-Host "`n--- Feature-gate dependency cross-references (s29) ---" -ForegroundColor Cyan
# The catalog (with dependsOn) is consumed and the toggle has a change handler
# that prompts/blocks based on the dependency graph.
T "builds a dependents (reverse-dependency) map"  ($html -match 'const dependents = \{\}')
T "feature toggle wires an onchange handler"       ($html -match "\.featGateToggle:not\(:disabled\)'\)\.forEach\(cb => \{[\s\S]{0,80}cb\.onchange")
T "enabling prompts to enable a missing prerequisite" ($html -match 'Enable a prerequisite\?')
T "auto-enables the prerequisite toggle on confirm"  ($html -match "depToggle\.checked = true")
T "warns when a prerequisite cannot be enabled here" ($html -match 'Prerequisite unavailable')
T "disabling warns when an enabled feature depends on it" ($html -match 'Other features depend on this')
T "disable cancel reverts the toggle (re-checks)"   ($html -match "if \(!go\) \{ cb\.checked = true; return; \}")
T "uses the catalog's dependsOn data"               ($html -match 'f\.dependsOn \|\| \[\]')

Write-Host ("`n RESULT: {0} pass, {1} fail" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
