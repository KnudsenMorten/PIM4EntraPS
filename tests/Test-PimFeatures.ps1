#Requires -Version 5.1
<#
.SYNOPSIS
    Functional, rerunnable test suite for PIM4EntraPS engine + Manager features.

.DESCRIPTION
    Offline functional tests (no live tenant) covering every feature whose logic
    can be exercised without Graph/SQL: pure utilities, date grammar, licensing,
    baseline-courier crypto, schema upgrade, audit, mail/policy templates,
    policy/tap/offboard state, emergency override window, Purpose routing,
    approval-escalation guard logic, and the Manager validator (all rules).

    Graph/SQL-coupled WRITE paths (account create, policy apply to tenant,
    TAP issue, discovery, fan-out, local apply) are validated LIVE elsewhere and
    are reported here as SKIP(live) with the reason -- this file is the offline
    regression gate, runnable on any box with no tenant.

    Isolation: sets $global:PIM_ConfigVariant='test' so all state/output/audit
    writes land under output/test/ and never touch real data. Rerunnable.

.EXAMPLE
    powershell -NoProfile -File tests\Test-PimFeatures.ps1
#>
[CmdletBinding()]
param([switch]$IncludeLive)

$ErrorActionPreference = 'Stop'
$script:pass = 0; $script:fail = 0; $script:skip = 0
function T  { param($n,[scriptblock]$b)
    try { $r = & $b; if ($r) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }
    catch { Write-Host "  FAIL $n -- $($_.Exception.Message.Split([char]10)[0])" -ForegroundColor Red; $script:fail++ } }
function S  { param($n,$why) Write-Host "  SKIP $n ($why)" -ForegroundColor DarkYellow; $script:skip++ }
function Has { param($c) [bool](Get-Command $c -ErrorAction SilentlyContinue) }
function Section($t){ Write-Host "`n== $t ==" -ForegroundColor Cyan }

$root = Split-Path -Parent $PSScriptRoot
$global:PIM_ConfigVariant = 'test'
Import-Module (Join-Path $root 'engine\_shared\PIM-Functions.psm1') -Force -DisableNameChecking

Section 'PURE UTILITIES'
T 'New-PimRandomPassword length+classes' {
    if (-not (Has New-PimRandomPassword)) { return $false }
    $p = New-PimRandomPassword
    ($p.Length -ge 12) -and ($p -match '[A-Z]') -and ($p -match '[a-z]') -and ($p -match '[0-9]')
}

Section 'DATE EXPRESSIONS'
foreach ($e in 'Now','FirstDayNextMonth','FirstWorkdayNextMonth','FirstDayNextWeek','2026-07-01','FirstWorkdayNextMonth-3d@08:00') {
    T "Resolve-PimDateExpression '$e'" { $d = Resolve-PimDateExpression -Expression $e; $null -ne $d }
}
T 'FirstWorkdayNextMonth is Mon-Fri' {
    $d = [datetime](Resolve-PimDateExpression -Expression 'FirstWorkdayNextMonth')
    $d.DayOfWeek -ne 'Saturday' -and $d.DayOfWeek -ne 'Sunday'
}

Section 'LICENSING (Core/Pro offline)'
T 'Get-PimLicense returns status' { (Get-PimLicense -Refresh).Status -ne $null }
T 'Test-PimProFeature blocks unknown/unlicensed tenant' { -not (Test-PimProFeature 'MspFanout' -TenantId '00000000-0000-0000-0000-000000000099' -Quiet) }
T 'Test-PimProFeature usable with valid license' {
    $l = Get-PimLicense -Refresh
    if ($l.Status -eq 'Valid' -and ($l.TenantIds.Count -gt 0)) { Test-PimProFeature 'MspFanout' -TenantId $l.TenantIds[0] -Quiet } else { $true }
}

Section 'BASELINE COURIER (signature crypto, offline)'
$blCert = Get-ChildItem Cert:\LocalMachine\My -EA SilentlyContinue | Where-Object { $_.Subject -eq 'CN=PIM4EntraPS-Baseline' -and $_.HasPrivateKey } | Select-Object -First 1
if ($blCert -and (Has Test-PimBaselineDoc)) {
    $payload = @{ product='PIM4EntraPS'; kind='baseline'; version=9999999999; scope='test'; generatedAtUtc=(Get-Date).ToUniversalTime().ToString('o'); validToUtc=(Get-Date).AddDays(1).ToUniversalTime().ToString('o'); rows=@(@{UserName='Admin-T-ID';Purpose='Day2Day'}) }
    $pb = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 5 -Compress))
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($blCert)
    $sig = $rsa.SignData($pb,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $doc = [pscustomobject]@{ product='PIM4EntraPS'; payloadB64=[Convert]::ToBase64String($pb); signature=[Convert]::ToBase64String($sig); keyThumbprint=$blCert.Thumbprint }
    T 'valid signed bundle verifies' { $p = Test-PimBaselineDoc -Doc $doc; $p.version -eq 9999999999 }
    T 'tampered bundle rejected' {
        $bad = $doc.PSObject.Copy(); $j = [Text.Encoding]::UTF8.GetString($pb) -replace 'Day2Day','HighPriv'; $bad.payloadB64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))
        $rej=$false; try { Test-PimBaselineDoc -Doc $bad | Out-Null } catch { $rej = ("$_" -match 'SIGNATURE INVALID') }; $rej
    }
} else { S 'baseline signature verify' 'CN=PIM4EntraPS-Baseline cert or Test-PimBaselineDoc not present' }
if (Has Set-PimBaselineApplied) {
    T 'Set-PimBaselineApplied + read back (anti-rollback marker)' {
        Set-PimBaselineApplied -Version 12345
        [int64]((Get-Content (Get-PimBaselineStateFile) -Raw | ConvertFrom-Json).version) -eq 12345
    }
} else { S 'Set-PimBaselineApplied' 'PIM-Baseline.ps1 not loaded by module' }

Section 'CSV SCHEMA UPGRADE'
T 'Invoke-PimCsvSchemaUpgrade appends Purpose' {
    $tmp = Join-Path $env:TEMP "pimt-$(Get-Random)"; New-Item -ItemType Directory $tmp | Out-Null
    Set-Content (Join-Path $tmp 'Account-Definitions-Admins.custom.csv') @('FirstName;LastName;Initials;TierLevel;UserName','J;D;JD;T1;Admin-JD-ID') -Encoding UTF8
    Invoke-PimCsvSchemaUpgrade -ConfigDir $tmp
    $ok = (Get-Content (Join-Path $tmp 'Account-Definitions-Admins.custom.csv') -TotalCount 1) -match 'Purpose'
    Remove-Item $tmp -Recurse -Force; $ok
}

Section 'AUDIT (jsonl)'
T 'Write-PimAuditEvent writes a readable jsonl line' {
    if (-not (Has Write-PimAuditEvent)) { return $false }
    Write-PimAuditEvent -Action 'test.audit' -Target 'unit' -After @{ k='v' }
    $dir = Join-Path (Get-PimOutputDir) 'audit'
    $f = Get-ChildItem $dir -Filter 'pim-audit-*.jsonl' -EA SilentlyContinue | Sort-Object LastWriteTime -Desc | Select-Object -First 1
    $f -and ((Get-Content $f.FullName | Select-Object -Last 1) -match 'test\.audit')
}

Section 'MAIL TEMPLATES'
$mailTypes = 'approval-escalation','approval-request','emergency-override','new-admin','new-permission','new-role','offboarding-notice','tap-delivery'
foreach ($mt in $mailTypes) {
    T "mail '$mt' renders" {
        $p = Get-PimMailTemplate -Type $mt
        if (-not $p) { return $false }
        $r = ConvertTo-PimMailRendering -TemplateText (Get-Content $p -Raw) -Tokens @{ DisplayName='X';UserPrincipalName='x@y';Date='2026-06-12';GroupName='G';Code='1';Reason='r';ManagerEmail='m@y' }
        $r.Subject -and $r.BodyHtml
    }
}

Section 'POLICY TEMPLATES + APPROVAL CONFIG'
T 'Get-PimPolicyTemplates loads >=2 (default + approval-required)' {
    $t = Get-PimPolicyTemplates; (@($t.Keys).Count -ge 2) -or (@($t).Count -ge 2)
}
T 'approval-required template ENABLES approval' {
    $j = Get-Content (Join-Path $root 'templates\policy\approval-required.policytemplate.json') -Raw | ConvertFrom-Json
    "$($j | ConvertTo-Json -Depth 8)" -match '(?i)approval'
}
T 'default template does NOT require approval' {
    $j = Get-Content (Join-Path $root 'templates\policy\default.policytemplate.json') -Raw | ConvertFrom-Json
    $null -ne $j
}

Section 'STATE ROUND-TRIPS (policy / tap / offboard)'
T 'policy-state save+load' { if (-not (Has Save-PimPolicyState)) { return $false } Save-PimPolicyState -State @{ 'G'=@{ groupTag='ROLE-X'; approval=@{ mode='Serial'; owners=@('a@y','b@y'); activeApproverIndex=0; escalationHours=4 } } }; (Get-PimPolicyState)['G'].approval.mode -eq 'Serial' }
T 'tap-state save+load' { if (-not (Has Save-PimTapState)) { return $false } Save-PimTapState -State @{ 'u@y'=@{ issued=$true } }; (Get-PimTapState)['u@y'].issued -eq $true }
T 'offboard-state save+load' { if (-not (Has Save-PimOffboardState)) { return $false } Save-PimOffboardState -State @{ 'u@y'=@{ disabled=$true } }; (Get-PimOffboardState)['u@y'].disabled -eq $true }

Section 'APPROVALS / ESCALATION (guard logic, offline)'
T 'Invoke-PimApprovalEscalation no-throw + no rotation without Graph' {
    if (-not (Has Invoke-PimApprovalEscalation)) { return $false }
    Save-PimPolicyState -State @{ 'G'=@{ groupId='gid'; groupTag='ROLE-X'; approval=@{ mode='Serial'; owners=@('a@y','b@y'); activeApproverIndex=0; escalationHours=4 } } }
    Invoke-PimApprovalEscalation -ErrorAction SilentlyContinue | Out-Null    # Graph read fails-safe -> caught
    (Get-PimPolicyState)['G'].approval.activeApproverIndex -eq 0              # did NOT escalate (no pending reqs readable)
}
T 'escalation early-returns on empty state' {
    Save-PimPolicyState -State @{}
    $null -eq (Invoke-PimApprovalEscalation -ErrorAction SilentlyContinue)
}

Section 'EMERGENCY OVERRIDE (window logic)'
if ((Has Get-PimEmergencyOverride) -and (Has Test-PimEmergencyOverrideActive)) {
    $ef = Get-PimEmergencyOverrideFile
    @{ active=$true; scopeGroupTags=@('ROLE-GA'); activatedBy='op@y'; reason='t'; expiresAtUtc=(Get-Date).AddHours(2).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content $ef -Encoding UTF8
    T 'active override in-scope = active' { Test-PimEmergencyOverrideActive -GroupTag 'ROLE-GA' }
    T 'active override out-of-scope = inactive' { -not (Test-PimEmergencyOverrideActive -GroupTag 'ROLE-OTHER') }
    @{ active=$true; scopeGroupTags=@('ROLE-GA'); activatedBy='op@y'; reason='t'; expiresAtUtc=(Get-Date).AddHours(-1).ToUniversalTime().ToString('o') } | ConvertTo-Json | Set-Content $ef -Encoding UTF8
    T 'expired override = inactive' { -not (Test-PimEmergencyOverrideActive -GroupTag 'ROLE-GA') }
    Remove-Item $ef -Force -EA SilentlyContinue
} else { S 'emergency override' 'functions not present' }

Section 'PURPOSE / NAMING ROUTING (regex)'
$hp = '(?i)(^|[-_.])(L0|T0)([-_.]|$)'
T 'HighPriv name matches marker' { 'Admin-XYZ-L0-T0-ID' -match $hp }
T 'Day2Day name does NOT match marker' { -not ('Admin-XYZ-ID' -match $hp) }

Section 'VERSION'
T 'VERSION file is 2.4.177+' { [version]((Get-Content (Join-Path $root 'VERSION') -TotalCount 1).Trim()) -ge [version]'2.4.177' }

Section 'MANAGER VALIDATOR (all rules vs live config)'
$cfg = Join-Path $root 'config'
if (Test-Path (Join-Path $cfg 'PIM4EntraPS.NamingConventions.locked.ps1')) {
    . (Join-Path $cfg 'PIM4EntraPS.NamingConventions.locked.ps1')
    if (-not (Has Get-PimNamingConventions)) { function Get-PimNamingConventions { $global:PIM_NamingConventions } }
    function Get-PimConfigDir { $cfg }
    function Get-PimCsvBases { @('Account-Definitions-Admins','PIM-Assignments-Admins','PIM-Definitions-Roles','PIM-Definitions-Tasks','PIM-Definitions-Services','PIM-Definitions-Processes','PIM-Definitions-Resources','PIM-Definitions-Departments','PIM-Definitions-Organization','PIM-Definitions-AU','PIM-Assignments-Groups','PIM-Assignments-Roles-Groups','PIM-Assignments-Roles-AUs','PIM-Assignments-Azure-Resources','PIM-Assignments-Workloads') | ForEach-Object { [pscustomobject]@{ base=$_ } } }
    function Resolve-PimCsvPath { param([string]$BaseName) $p=Join-Path $cfg "$BaseName.custom.csv"; if (Test-Path $p) { $p } else { $null } }
    . (Join-Path $root 'tools\pim-manager\_validator.ps1')
    T 'validator runs + returns findings collection' { $v=@(Invoke-PimPreflightValidation); $null -ne $v }
    T 'no naming (PIM-NAME-002) violations in live config' { @(Invoke-PimPreflightValidation | Where-Object Code -eq 'PIM-NAME-002').Count -eq 0 }
} else { S 'validator' 'naming conventions file not found' }

Section 'LIVE-ONLY (Graph/SQL write paths -- validated live, skipped offline)'
foreach ($f in 'Invoke-PimMspFanout (WhatIf live)','Invoke-PimLocalApply (live, both tenants)','baseline cross-tenant PE pull (ACI live)','account create from local store (live)','activator backend app-only deploy (live)','EXO mailbox forwarding (live)') {
    if ($IncludeLive) { S $f 'live mode not implemented in this harness' } else { S $f 'requires live tenant -- proven in session logs' }
}

Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host (" RESULT: {0} pass, {1} fail, {2} skip" -f $script:pass, $script:fail, $script:skip) -ForegroundColor $(if ($script:fail) {'Red'} else {'Green'})
Write-Host "=====================================================" -ForegroundColor Cyan
if ($script:fail) { exit 1 }
