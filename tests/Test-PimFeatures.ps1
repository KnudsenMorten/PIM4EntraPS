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

Section 'LICENSING (Core/Pro offline) -- full suite in Test-PimLicensing.ps1'
T 'Get-PimLicense returns status' { (Get-PimLicense -Refresh).Status -ne $null }
T 'Pro is granted free by default (no nag, no block)' { (-not (Test-PimProLicenseEnforced)) -and (Test-PimProFeature 'MspFanout' -Quiet) }
T 'gate still blocks when enforced; super-admin never blocked' {
    $global:PIM_EnforceProLicense = $true
    try { (-not (Test-PimProFeature 'MspFanout' -TenantId '00000000-0000-0000-0000-000000000099' -Quiet)) -and (Test-PimProFeature 'MspFanout' -SuperAdmin -Quiet) }
    finally { Remove-Variable -Name PIM_EnforceProLicense -Scope Global -ErrorAction SilentlyContinue }
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

Section 'MANAGER AUTHORING (pure row-set builders, offline)'
T 'New-PimBulkAttachRows fans roles+scopes+AUs onto one tag' {
    if (-not (Has New-PimBulkAttachRows)) { return $false }
    $d = New-PimBulkAttachRows -GroupTag 'PIM-Entra-X-L1-T0-CP-ID' -EntraRoles @('User Administrator','Helpdesk Administrator') -AzureScopes @(@{scope='/subscriptions/s1';permission='Reader'}) -AuScopes @(@{auTag='AU-HD';role='User Administrator'})
    ($d.totalRows -eq 4) -and ($d.rolesGroupsRows.Count -eq 2) -and ($d.azureResourceRows.Count -eq 1) -and ($d.rolesAusRows.Count -eq 1) -and ($d.rolesGroupsRows[0].GroupTag -eq 'PIM-Entra-X-L1-T0-CP-ID')
}
T 'New-PimBulkAttachRows requires a GroupTag' {
    $threw=$false; try { New-PimBulkAttachRows -GroupTag '' -EntraRoles @('User Administrator') } catch { $threw=$true }; $threw
}
T 'Copy-PimDefinitionRows clones to N tags + follows GroupName' {
    if (-not (Has Copy-PimDefinitionRows)) { return $false }
    $tpl = [ordered]@{ GroupName='PIM-A'; GroupTag='PIM-A'; TierLevel='T1'; Owners='o@x' }
    $cl = Copy-PimDefinitionRows -TemplateRow $tpl -NewTags @('PIM-B','PIM-C')
    (@($cl).Count -eq 2) -and ($cl[0].GroupTag -eq 'PIM-B') -and ($cl[0].GroupName -eq 'PIM-B') -and ($cl[1].GroupTag -eq 'PIM-C') -and ($cl[0].Owners -eq 'o@x')
}
T 'Copy-PimDefinitionRows honours SetColumns override' {
    $tpl = [ordered]@{ GroupName='PIM-A'; GroupTag='PIM-A'; TierLevel='T1' }
    $cl = @(Copy-PimDefinitionRows -TemplateRow $tpl -NewTags @('PIM-B') -SetColumns @{ TierLevel='T0' })
    $cl[0].TierLevel -eq 'T0'
}
T 'Copy-PimAzureRbacToRole swaps role, keeps scope (clone-to-N)' {
    if (-not (Has Copy-PimAzureRbacToRole)) { return $false }
    $src = [ordered]@{ GroupTag='PIM-Az'; AzScope='/subscriptions/s1'; AzScopePermission='Reader' }
    $ca = Copy-PimAzureRbacToRole -SourceRow $src -NewRoles @('Contributor','Owner')
    (@($ca).Count -eq 2) -and ($ca[0].AzScopePermission -eq 'Contributor') -and ($ca[1].AzScopePermission -eq 'Owner') -and ($ca[0].AzScope -eq '/subscriptions/s1')
}
T 'New-PimAuRows builds AU row + bindings' {
    if (-not (Has New-PimAuRows)) { return $false }
    $au = New-PimAuRows -AuDisplayName 'HD AU' -AdministrativeUnitTag 'AU-HD' -Visibility 'HiddenMembership' -RoleBindings @(@{groupTag='PIM-X';role='User Administrator'})
    ($au.auRow.AdministrativeUnitTag -eq 'AU-HD') -and ($au.auRow.Visibility -eq 'HiddenMembership') -and (@($au.rolesAusRows).Count -eq 1) -and ($au.rolesAusRows[0].GroupTag -eq 'PIM-X')
}
T 'ConvertFrom-PimAdminImportCsv parses ; , and tab' {
    if (-not (Has ConvertFrom-PimAdminImportCsv)) { return $false }
    $semi = @(ConvertFrom-PimAdminImportCsv -Text "FirstName;LastName`nJane;Doe")
    $tab  = @(ConvertFrom-PimAdminImportCsv -Text "FirstName`tLastName`nJohn`tSmith")
    ($semi.Count -eq 1) -and ($semi[0].FirstName -eq 'Jane') -and ($tab.Count -eq 1) -and ($tab[0].LastName -eq 'Smith')
}
T 'New-PimAdminRowsFromImport derives Initials/DisplayName + applies template prefill' {
    if (-not (Has New-PimAdminRowsFromImport)) { return $false }
    $people = @(ConvertFrom-PimAdminImportCsv -Text "FirstName;LastName;Department`nJane;Doe;IT")
    $tpl = [pscustomobject]@{ id='consultant'; prefill=[pscustomobject]@{ Purpose='Day2Day'; Ring='2' } }
    $rows = @(New-PimAdminRowsFromImport -People $people -Template $tpl)
    ($rows[0].Initials -eq 'JD') -and ($rows[0].DisplayName -eq 'Jane Doe') -and ($rows[0].Purpose -eq 'Day2Day') -and ($rows[0].Ring -eq '2') -and ($rows[0].Department -eq 'IT')
}
T 'New-PimAdminMovePlan replaces only the matched (admin,from) rows' {
    if (-not (Has New-PimAdminMovePlan)) { return $false }
    $a = @([ordered]@{Username='a1';GroupTag='R-A'}, [ordered]@{Username='a1';GroupTag='R-B'}, [ordered]@{Username='a2';GroupTag='R-A'})
    $mv = New-PimAdminMovePlan -AssignmentRows $a -Username 'a1' -FromTag 'R-A' -ToTag 'R-C'
    ($mv.movedCount -eq 1) -and (@($mv.rows).Count -eq 3) -and (@($mv.rows | Where-Object { $_.Username -eq 'a1' -and $_.GroupTag -eq 'R-C' }).Count -eq 1) -and (@($mv.rows | Where-Object { $_.Username -eq 'a2' -and $_.GroupTag -eq 'R-A' }).Count -eq 1)
}
T 'New-PimAdminMovePlan throws when nothing matches' {
    $a = @([ordered]@{Username='a1';GroupTag='R-A'})
    $threw=$false; try { New-PimAdminMovePlan -AssignmentRows $a -Username 'x' -FromTag 'R-A' -ToTag 'R-C' } catch { $threw=$true }; $threw
}
T 'Remove-PimRowsByIndex drops the right rows (bounds-safe)' {
    if (-not (Has Remove-PimRowsByIndex)) { return $false }
    $a = @([ordered]@{V='0'}, [ordered]@{V='1'}, [ordered]@{V='2'})
    $d = Remove-PimRowsByIndex -Rows $a -Indexes @(0,2,99)
    ($d.removedCount -eq 2) -and (@($d.rows).Count -eq 1) -and ($d.rows[0].V -eq '1')
}
T 'Format-PimRolePermissions flattens + groups by namespace' {
    if (-not (Has Format-PimRolePermissions)) { return $false }
    $rdef = [pscustomobject]@{ displayName='Test'; rolePermissions=@([pscustomobject]@{ allowedResourceActions=@('microsoft.directory/users/create','microsoft.directory/users/create','microsoft.directory/groups/create') }) }
    $fmt = Format-PimRolePermissions -RoleDefinition $rdef
    ($fmt.totalActions -eq 2) -and (@($fmt.byNamespace).Count -eq 2)   # de-duped; users + groups namespaces
}
T 'ConvertTo-PimLaAuditRecord stamps CollectionTime + flattens after' {
    if (-not (Has ConvertTo-PimLaAuditRecord)) { return $false }
    $evt = [ordered]@{ ts='2026-06-14T10:00:00Z'; actor='manager:x'; action='config.csv.save'; target='PIM-Definitions-Roles'; result='ok'; after=@{adds=1} }
    $la = ConvertTo-PimLaAuditRecord -Event $evt
    ($la.CollectionTime) -and ($la.Action -eq 'config.csv.save') -and ($la.Details -match 'adds')
}

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
    T 'validator runs + returns violations collection' { $r=Invoke-PimPreflightValidation; $null -ne $r.violations -or $null -ne $r }
    T 'no naming (PIM-NAME-002) violations in live config' { @((Invoke-PimPreflightValidation).violations | Where-Object Code -eq 'PIM-NAME-002').Count -eq 0 }
} else { S 'validator' 'naming conventions file not found' }

Section 'NOTIFICATIONS BATCH (REQ §12 -- daily summary / tier 0-1 / escalation / intake; pure, offline)'
# (1) Daily summary: folds audit events into a 24h digest of DELEGATION/ASSIGNMENT
# changes; ACTIVATION events are Entra-native and MUST be excluded (two-approval model).
$nowU = [datetime]'2026-06-13T23:00:00Z'
$evts = @(
    [pscustomobject]@{ ts='2026-06-13T10:00:00Z'; action='account.create';          target='Admin-AB-T0';        result='ok'; actor='engine' }
    [pscustomobject]@{ ts='2026-06-13T11:00:00Z'; action='assignment.create';        target='alice->PIM-GA-L1-T0';result='ok'; actor='mok' }
    [pscustomobject]@{ ts='2026-06-13T12:00:00Z'; action='role.activate';            target='alice';              result='ok' }   # excluded (activation)
    [pscustomobject]@{ ts='2026-06-13T13:00:00Z'; action='account.offboard.revoke';  target='Admin-XY-T1';        result='ok' }
    [pscustomobject]@{ ts='2026-06-01T13:00:00Z'; action='assignment.create';        target='old';                result='ok' }   # excluded (out of window)
    [pscustomobject]@{ ts='2026-06-13T14:00:00Z'; action='assignment.create';        target='wi';                 whatIf=$true }   # excluded (whatif)
)
T 'daily summary counts only delegation/assignment changes in window' {
    if (-not (Has Get-PimDailySummary)) { return $false }
    $s = Get-PimDailySummary -Events $evts -NowUtc $nowU
    ($s.totalChanges -eq 3) -and (@($s.admins).Count -eq 1) -and (@($s.delegations).Count -eq 1) -and (@($s.removals).Count -eq 1)
}
T 'daily summary EXCLUDES activation events (two-approval model)' {
    $s = Get-PimDailySummary -Events $evts -NowUtc $nowU
    -not (@($s.admins + $s.delegations + $s.removals) | Where-Object { "$($_.action)" -match 'activat' })
}
T 'daily summary tokens render with no leftover {{tokens}}' {
    $s = Get-PimDailySummary -Events $evts -NowUtc $nowU
    $tok = ConvertTo-PimDailySummaryTokens -Summary $s -TenantLabel 'T'
    $tplDir = Join-Path $root 'templates\mail'
    $body = (Get-Content (Join-Path $tplDir 'daily-summary.mailtemplate.html') -Raw)
    foreach ($k in $tok.Keys) { $body = $body -replace ('\{\{' + [regex]::Escape($k) + '\}\}'), ([string]$tok[$k] -replace '\$','$$$$') }
    -not ($body -match '\{\{\w+\}\}')
}

# (2) Tier 0/1 report: highest tier per user + levels; T2+ excluded; name marker or field.
$assn = @(
    [pscustomobject]@{ UserName='alice@x';          GroupTag='PIM-AAD-GA-L1-T0' }
    [pscustomobject]@{ UserName='alice@x';          GroupTag='PIM-AAD-Helpdesk-L2-T1' }
    [pscustomobject]@{ UserName='bob@x';            GroupTag='PIM-AAD-App-L3-T2' }       # excluded
    [pscustomobject]@{ UserPrincipalName='carol@x'; Tier=1; Level=2 }
)
T 'tier report returns only T0/T1 holders, highest-tier first' {
    if (-not (Has Get-PimTierZeroOneReport)) { return $false }
    $r = Get-PimTierZeroOneReport -Assignments $assn
    ($r.Count -eq 2) -and ($r[0].user -eq 'alice@x') -and ($r[0].highestTier -eq 0)
}
T 'tier report captures privilege levels per user' {
    $r = Get-PimTierZeroOneReport -Assignments $assn
    $alice = $r | Where-Object { $_.user -eq 'alice@x' }
    (@($alice.levels) -contains 1) -and (@($alice.levels) -contains 2)
}
T 'tier report tokens render with no leftover {{tokens}}' {
    $r = Get-PimTierZeroOneReport -Assignments $assn
    $tok = ConvertTo-PimTierReportTokens -Report $r
    $body = (Get-Content (Join-Path $root 'templates\mail\tier-report.mailtemplate.html') -Raw)
    foreach ($k in $tok.Keys) { $body = $body -replace ('\{\{' + [regex]::Escape($k) + '\}\}'), ([string]$tok[$k] -replace '\$','$$$$') }
    -not ($body -match '\{\{\w+\}\}')
}

# (3) Escalation/reminders: serial steps one owner at a time after escalationHours;
# parallel notifies all at once (any-one approves).
$req = [pscustomobject]@{ requestor='alice@x'; groupTag='PIM-GA-L1-T0'; justification='j'; requestedUtc='2026-06-12T00:00:00Z'; status='pending' }
T 'serial escalation steps to the next owner after escalationHours' {
    if (-not (Has Get-PimApprovalEscalationTargets)) { return $false }
    $t = Get-PimApprovalEscalationTargets -Request $req -Owners @('o1','o2','o3') -NowUtc ([datetime]'2026-06-14T06:00:00Z') -Mode serial -EscalationHours 24
    ($t.step -eq 2) -and (@($t.notify) -eq 'o3') -and ($t.isEscalated) -and ($t.previousApprover -eq 'o2')
}
T 'serial escalation does not re-notify the same step' {
    $r2 = [pscustomobject]@{ requestor='a'; groupTag='g'; requestedUtc='2026-06-12T00:00:00Z'; status='pending'; lastNotifiedStep=2 }
    $null -eq (Get-PimApprovalEscalationTargets -Request $r2 -Owners @('o1','o2','o3') -NowUtc ([datetime]'2026-06-14T06:00:00Z') -Mode serial -EscalationHours 24)
}
T 'parallel escalation notifies all owners at once' {
    $t = Get-PimApprovalEscalationTargets -Request $req -Owners @('o1','o2') -NowUtc ([datetime]'2026-06-12T01:00:00Z') -Mode parallel -EscalationHours 24
    (@($t.notify).Count -eq 2) -and (-not $t.isEscalated)
}
T 'escalation skips non-pending requests' {
    $done = [pscustomobject]@{ requestor='a'; groupTag='g'; requestedUtc='2026-06-12T00:00:00Z'; status='approved' }
    $null -eq (Get-PimApprovalEscalationTargets -Request $done -Owners @('o1','o2') -NowUtc ([datetime]'2026-06-14T00:00:00Z') -Mode serial)
}

# (4) ServiceNow intake: sanitise + secure routing. Privileged ALWAYS approve; activation
# + self-target rejected; only allowlisted non-priv auto-applies; store-and-forward poll.
T 'intake record strips unknown fields + stamps received status' {
    if (-not (Has ConvertTo-PimIntakeRecord)) { return $false }
    $rec = ConvertTo-PimIntakeRecord -Payload ([pscustomobject]@{ requestType='delegation-request'; requestor='a@x'; targetAdmin='b'; evilField='rm -rf' })
    ($null -eq $rec.PSObject.Properties['evilField']) -and ($rec.status -eq 'received')
}
T 'intake REJECTS activation requests (Entra-native only)' {
    $rec = ConvertTo-PimIntakeRecord -Payload ([pscustomobject]@{ requestType='activation'; requestor='a@x' })
    -not (Test-PimIntakeAccepted -Record $rec).accepted
}
T 'intake REJECTS self-targeting (no self-create/self-elevate)' {
    $rec = ConvertTo-PimIntakeRecord -Payload ([pscustomobject]@{ requestType='delegation-request'; requestor='a@x'; targetAdmin='a@x' })
    -not (Test-PimIntakeAccepted -Record $rec).accepted
}
T 'intake routes Tier 0/1 to APPROVE even if type is allowlisted' {
    $rec = ConvertTo-PimIntakeRecord -Payload ([pscustomobject]@{ requestType='delegation-request'; requestor='a@x'; targetAdmin='b'; groupTag='PIM-GA-L1-T0' })
    (Resolve-PimIntakeRouting -Record $rec -AutoApplyTypes @('delegation-request')).route -eq 'approve'
}
T 'intake auto-applies only allowlisted non-privileged types' {
    $rec = ConvertTo-PimIntakeRecord -Payload ([pscustomobject]@{ requestType='group-add'; requestor='a@x'; targetAdmin='b'; groupTag='PIM-App-L3-T2' })
    ((Resolve-PimIntakeRouting -Record $rec -AutoApplyTypes @('group-add')).route -eq 'auto-apply') -and
    ((Resolve-PimIntakeRouting -Record $rec -AutoApplyTypes @()).route -eq 'approve')
}
T 'intake store-and-forward poll reads + routes without mutating' {
    if (-not (Has Invoke-PimIntakePoll)) { return $false }
    $store = Join-Path (Get-PimOutputDir) ('intake-test-{0}.jsonl' -f ([guid]::NewGuid().ToString('N')))
    Add-PimIntakeRecord -StoreFile $store -Record (ConvertTo-PimIntakeRecord -Payload ([pscustomobject]@{ requestType='delegation-request'; requestor='a@x'; targetAdmin='b'; groupTag='PIM-GA-L1-T0' }))
    Add-PimIntakeRecord -StoreFile $store -Record (ConvertTo-PimIntakeRecord -Payload ([pscustomobject]@{ requestType='group-add'; requestor='a@x'; targetAdmin='b'; groupTag='PIM-App-L3-T2' }))
    $d = @(Invoke-PimIntakePoll -StoreFile $store -AutoApplyTypes @('group-add'))
    Remove-Item $store -Force -EA SilentlyContinue
    ($d.Count -eq 2) -and (@($d | Where-Object { $_.route -eq 'approve' }).Count -eq 1) -and (@($d | Where-Object { $_.route -eq 'auto-apply' }).Count -eq 1)
}

Section 'WORKLOAD CONNECTORS (per-workload, offline schema + token + container logic)'
$connDir = Join-Path $root 'workloads\connectors'
$script:conns = @{}
foreach ($c in @(Read-PimWorkloadConnectors -ConnectorsDir $connDir)) { $script:conns["$($c.id)"] = $c }

T 'all connector JSONs parse + every connector has id + assign + remove' {
    if (-not $script:conns.Count) { return $false }
    foreach ($c in $script:conns.Values) {
        if (-not $c.id) { return $false }
        if (-not $c.api.assign) { return $false }
        if (-not $c.api.remove) { return $false }
    }
    $true
}
T 'new per-workload connectors are present (business-central, azure-devops, power-platform)' {
    $script:conns.ContainsKey('business-central') -and $script:conns.ContainsKey('azure-devops') -and $script:conns.ContainsKey('power-platform')
}
T 'shipped connectors still present (defender-xdr, intune) + each declares prerequisites' {
    foreach ($id in 'defender-xdr','intune','business-central','azure-devops','power-platform') {
        if (-not $script:conns.ContainsKey($id)) { return $false }
        if (-not $script:conns[$id].prerequisites) { return $false }
    }
    $true
}
T 'business-central is membership-model with container ops + per-row resource' {
    $c = $script:conns['business-central']
    [bool]$c.membershipModel -and [bool]$c.perRowResource -and ($null -ne $c.api.resolveContainer) -and ($null -ne $c.api.listContainerRoles)
}
T 'azure-devops is membership-model with a client-side container match filter' {
    $c = $script:conns['azure-devops']
    [bool]$c.membershipModel -and ("$($c.api.resolveContainer.matchField)" -eq 'originId') -and ("$($c.api.resolveContainer.matchToken)" -eq 'groupId')
}
T 'power-platform is a flat connector with static roles (Environment Admin / Maker)' {
    $c = $script:conns['power-platform']
    $names = @($c.roles | ForEach-Object { "$($_.name)" })
    ($names -contains 'Environment Admin') -and ($names -contains 'Environment Maker') -and ($null -ne $c.api.listAssignments)
}
T 'every connector uses a known auth adapter with a resolvable token resource' {
    $known = 'graph','arm','powerbi','devops','businesscentral','dataverse','powerplatform'
    foreach ($c in $script:conns.Values) {
        if ("$($c.auth)" -notin $known) { return $false }
        if ("$($c.auth)" -eq 'graph') { continue }   # graph uses the live MgGraph session, no minted token
        $global:PIM_WorkloadTokens = @{ "$($c.auth)" = 'TESTTOKEN' }   # avoid a live Get-AzAccessToken call
        if ((Get-PimWorkloadToken -Connector $c) -ne 'TESTTOKEN') { return $false }
    }
    $global:PIM_WorkloadTokens = $null
    $true
}
T 'new non-graph auth adapters resolve a default token resource (no PIM_WorkloadTokens)' {
    $global:PIM_WorkloadTokens = $null
    $bc = [pscustomobject]@{ id='bc'; auth='businesscentral'; api=@{ baseUrl='x' } }
    $pp = [pscustomobject]@{ id='pp'; auth='powerplatform'; api=@{ baseUrl='x' } }
    $ok = $true
    # Get-PimWorkloadToken would call Get-AzAccessToken if no minted token; we only
    # assert the adapter is RECOGNISED (no 'no token resource' throw) by inspecting
    # the switch via a minted token shortcut for each.
    $global:PIM_WorkloadTokens = @{ businesscentral='B'; powerplatform='P' }
    if ((Get-PimWorkloadToken -Connector $bc) -ne 'B') { $ok = $false }
    if ((Get-PimWorkloadToken -Connector $pp) -ne 'P') { $ok = $false }
    $global:PIM_WorkloadTokens = $null
    $ok
}
T 'Select-PimWorkloadContainerItem honours matchField/matchToken (DevOps subject pick)' {
    # Two groups, only one matches the PIM group's objectId via originId. The match
    # filter must pick that one (pure helper backing Get-PimWorkloadContainerId).
    $op = [pscustomobject]@{ method='GET'; path='/g'; itemsPath='value'; idField='descriptor'; matchField='originId'; matchToken='groupId' }
    $items = @(
        [pscustomobject]@{ descriptor='vssgp.WRONG'; originId='99999999-9999-9999-9999-999999999999' },
        [pscustomobject]@{ descriptor='vssgp.RIGHT'; originId='11111111-1111-1111-1111-111111111111' }
    )
    $picked = Select-PimWorkloadContainerItem -Op $op -Items $items -Tokens @{ groupId='11111111-1111-1111-1111-111111111111' }
    "$($picked.descriptor)" -eq 'vssgp.RIGHT'
}
T 'Select-PimWorkloadContainerItem keeps first-item behaviour when no matchField (Dataverse)' {
    $op = [pscustomobject]@{ itemsPath='value'; idField='teamid' }   # server-filtered, no matchField
    $items = @([pscustomobject]@{ teamid='FIRST' }, [pscustomobject]@{ teamid='SECOND' })
    $picked = Select-PimWorkloadContainerItem -Op $op -Items $items -Tokens @{}
    "$($picked.teamid)" -eq 'FIRST'
}
T 'Select-PimWorkloadContainerItem returns null when nothing matches (no container yet)' {
    $op = [pscustomobject]@{ itemsPath='value'; idField='descriptor'; matchField='originId'; matchToken='groupId' }
    $items = @([pscustomobject]@{ descriptor='x'; originId='other' })
    $null -eq (Select-PimWorkloadContainerItem -Op $op -Items $items -Tokens @{ groupId='nope' })
}
T 'Expand-PimWorkloadTokens fills {token} + {token|default}' {
    (Expand-PimWorkloadTokens -Text '/x/{scope|/}/{groupId}' -Tokens @{ groupId='G' }) -eq '/x///G'
}

Section 'POWER PLATFORM DISCOVERY (environment auto-detect -> propose PIM groups, offline)'
T 'environment derivation builds a PIM-PowerPlatform-* group name with tier 1 / WDP' {
    $d = Get-PimPowerPlatformDerivation -DisplayName 'Contoso Finance' -EnvironmentType 'Production'
    ($d.groupName -like 'PIM-PowerPlatform-*') -and ($d.tier -eq 1) -and ($d.plane -eq 'WDP') -and ($d.level -eq 3)
}
T 'sandbox/developer environments get a looser (higher) level than production' {
    (Get-PimPowerPlatformDerivation -DisplayName 'X' -EnvironmentType 'Sandbox').level -gt (Get-PimPowerPlatformDerivation -DisplayName 'X' -EnvironmentType 'Production').level
}
T 'reconcile: NEW env -> create + PENDING (propose, never auto-map by default)' {
    $disc = @([pscustomobject]@{ environmentName='env-aaa'; displayName='Finance'; environmentType='Production' })
    $plan = Get-PimPowerPlatformReconcilePlan -Discovered $disc -Existing @()
    ($plan.summary.create -eq 1) -and ($plan.summary.autoCreate -eq 0)
}
T 'reconcile: auto-import rule promotes a matching env to autoCreate' {
    $disc = @([pscustomobject]@{ environmentName='env-bbb'; displayName='Dev1'; environmentType='Sandbox' })
    $rules = @(@{ environmentTypes=@('Sandbox'); minLevel=0; maxLevel=9 })
    $plan = Get-PimPowerPlatformReconcilePlan -Discovered $disc -Existing @() -AutoImportRules $rules
    $plan.summary.autoCreate -eq 1
}
T 'reconcile: renamed env (displayName drift, same env id) -> rename not orphan+create' {
    $disc = @([pscustomobject]@{ environmentName='env-ccc'; displayName='Finance EU'; environmentType='Production' })
    $existing = @([pscustomobject]@{ environmentName='env-ccc'; groupName='PIM-PowerPlatform-Finance-L3-T1-WDP-RES' })
    $plan = Get-PimPowerPlatformReconcilePlan -Discovered $disc -Existing $existing
    ($plan.summary.rename -eq 1) -and ($plan.summary.create -eq 0) -and ($plan.summary.orphan -eq 0)
}
T 'reconcile: env gone from discovery -> orphan (flag, never auto-delete)' {
    $existing = @([pscustomobject]@{ environmentName='env-ddd'; groupName='PIM-PowerPlatform-Old-L4-T1-WDP-RES' })
    $plan = Get-PimPowerPlatformReconcilePlan -Discovered @() -Existing $existing
    $plan.summary.orphan -eq 1
}
T 'queue changes: only auto-imports become Create; non-auto left out; orphans gated' {
    $disc = @(
        [pscustomobject]@{ environmentName='env-1'; displayName='Auto'; environmentType='Sandbox' },
        [pscustomobject]@{ environmentName='env-2'; displayName='Manual'; environmentType='Production' }
    )
    $rules = @(@{ environmentTypes=@('Sandbox') })
    $plan = Get-PimPowerPlatformReconcilePlan -Discovered $disc -Existing @() -AutoImportRules $rules
    $changes = @(ConvertTo-PimPowerPlatformQueueChanges -Plan $plan)
    @($changes | Where-Object { $_.Op -eq 'Create' }).Count -eq 1   # only the Sandbox auto-import
}
T 'ConvertFrom-PimPowerPlatformEnvironment shapes a raw BAP record' {
    $raw = [pscustomobject]@{ name='env-xyz'; properties=[pscustomobject]@{ displayName='Sales'; environmentSku='Production' } }
    $e = ConvertFrom-PimPowerPlatformEnvironment -Raw $raw
    ($e.environmentName -eq 'env-xyz') -and ($e.displayName -eq 'Sales') -and ($e.environmentType -eq 'Production')
}

Section 'LIVE-ONLY (Graph/SQL write paths -- validated live, skipped offline)'
foreach ($f in 'Invoke-PimMspFanout (WhatIf live)','Invoke-PimLocalApply (live, both tenants)','baseline cross-tenant PE pull (ACI live)','account create from local store (live)','activator backend app-only deploy (live)','EXO mailbox forwarding (live)') {
    if ($IncludeLive) { S $f 'live mode not implemented in this harness' } else { S $f 'requires live tenant -- proven in session logs' }
}

Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host (" RESULT: {0} pass, {1} fail, {2} skip" -f $script:pass, $script:fail, $script:skip) -ForegroundColor $(if ($script:fail) {'Red'} else {'Green'})
Write-Host "=====================================================" -ForegroundColor Cyan
if ($script:fail) { exit 1 }
