#Requires -Version 5.1
<#
.SYNOPSIS
    Offline tests for GUI-driven, store-backed mail-template customization
    (no image rebuild). Proves the engine's effective-body resolver
    (engine/_shared/PIM-Notify.ps1 -> Get-PimNotifyTemplateText) honours the
    precedence:  persistent-store override  ->  file .custom.html  ->  shipped.
    Save (store override) wins and is read by the renderer/sender; reset (clear
    the store key) falls back to the file/shipped default. PURE -- no network,
    no SQL: the "store" is simulated via the same global the SQL settings hydrate
    into ($global:PIM_NamingConventions['MailTemplateOverrides']).

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1 / PIM.Tests.ps1.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
$sol = Split-Path -Parent $here
. "$here\..\engine\_shared\PIM-Notify.ps1"

Write-Host "=== PIM mail-template customization (store override, no rebuild) ===" -ForegroundColor Cyan

# Point the template dir at the shipped templates and pick a real type.
$global:PIM_MailTemplateDir = Join-Path $sol 'templates\mail'
$type = 'daily-summary'
T "shipped template '$type' exists" (Test-Path -LiteralPath (Join-Path $global:PIM_MailTemplateDir "$type.mailtemplate.html"))

# Clean slate.
$global:PIM_NamingConventions = @{}
$global:PIM_MailTemplateOverrides = $null

# 1. No override -> shipped default is the effective body.
$r = Get-PimNotifyTemplateText -Type $type
T "no override -> source 'shipped'"        ($r.source -eq 'shipped')
T "shipped body is non-empty"              ($r.text.Trim().Length -gt 0)
$shippedBody = $r.text

# 2. Save a store override (simulates the GUI PUT -> SQL pim.Settings hydration).
$customBody = "<!-- subject: CUSTOM daily summary -->`r`n<p>Hello {{TenantLabel}} -- customized in the GUI, no rebuild.</p>"
$global:PIM_NamingConventions['MailTemplateOverrides'] = @{ $type = $customBody }
$r2 = Get-PimNotifyTemplateText -Type $type
T "store override wins -> source 'store'"  ($r2.source -eq 'store')
T "store override body is returned"        ($r2.text -eq $customBody)
T "store override differs from shipped"    ($r2.text -ne $shippedBody)

# 3. The SENDER/renderer reads the override (subject comes from the override).
$render = ConvertTo-PimNotifyRendering -TemplateText $r2.text -Tokens @{ TenantLabel = 'contoso' }
T "rendered subject uses the override"     ($render.Subject -eq 'CUSTOM daily summary')
T "rendered body filled the token"         ($render.BodyHtml -match 'contoso')

# 3b. Send (WhatIf -> renders, never sends) proves Send-PimNotifyMail uses the resolver.
$global:WhatIfMode = $true
$send = Send-PimNotifyMail -Type $type -Tokens @{ TenantLabel = 'contoso' } -Recipient 'a@b.com'
$global:WhatIfMode = $false
T "Send-PimNotifyMail renders the override subject" ($send.subject -eq 'CUSTOM daily summary')

# 4. Override accepted as a JSON STRING too (SQL keeps scalars as text).
$global:PIM_NamingConventions['MailTemplateOverrides'] = (@{ $type = $customBody } | ConvertTo-Json)
$r3 = Get-PimNotifyTemplateText -Type $type
T "json-string store override is parsed"   ($r3.source -eq 'store' -and $r3.text -eq $customBody)

# 5. RESET: clearing the store key falls back to the shipped default again.
$global:PIM_NamingConventions['MailTemplateOverrides'] = @{}
$r4 = Get-PimNotifyTemplateText -Type $type
T "reset -> back to shipped default"       ($r4.source -eq 'shipped' -and $r4.text -eq $shippedBody)

# 6. File-based .custom.html remains a FALLBACK (used only when no store override).
$customFile = Join-Path $global:PIM_MailTemplateDir "$type.mailtemplate.custom.html"
$createdFile = $false
try {
    if (-not (Test-Path -LiteralPath $customFile)) {
        $fileBody = "<!-- subject: FILE fallback -->`r`n<p>from the .custom.html file</p>"
        [System.IO.File]::WriteAllText($customFile, $fileBody, (New-Object System.Text.UTF8Encoding($false)))
        $createdFile = $true
        # no store override -> file wins
        $rf = Get-PimNotifyTemplateText -Type $type
        T "file .custom.html is the fallback (source 'file')" ($rf.source -eq 'file' -and $rf.text -eq $fileBody)
        # store override STILL wins over the file
        $global:PIM_NamingConventions['MailTemplateOverrides'] = @{ $type = $customBody }
        $rfo = Get-PimNotifyTemplateText -Type $type
        T "store override beats the .custom.html file" ($rfo.source -eq 'store')
    } else {
        Write-Host "  (skip file-fallback create: $type.mailtemplate.custom.html already exists)" -ForegroundColor DarkYellow
    }
} finally {
    if ($createdFile -and (Test-Path -LiteralPath $customFile)) { Remove-Item -LiteralPath $customFile -Force }
    $global:PIM_NamingConventions = @{}; $global:PIM_MailTemplateOverrides = $null; Remove-Variable -Name PIM_MailTemplateDir -Scope Global -ErrorAction SilentlyContinue
}

Write-Host ("`n=== RESULT: {0} passed, {1} failed ===" -f $pass, $fail) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
if ($fail) { exit 1 }
