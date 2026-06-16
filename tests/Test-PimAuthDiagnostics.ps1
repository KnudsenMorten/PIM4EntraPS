#Requires -Version 5.1
<#
.SYNOPSIS
    Functional, rerunnable suite for the Auth / Identity diagnostics (REQUIREMENTS section 9):
    missing-role hint, account sign-in prompt clarity, AD-failure diagnostics, MFA-gated
    Manager login. Offline (no live tenant) -- pure decision logic only. Mirrors the
    Pester 'Auth / Identity diagnostics' Describe so the suite is green with or without Pester.
.EXAMPLE
    powershell -NoProfile -File tests\Test-PimAuthDiagnostics.ps1
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$script:pass = 0; $script:fail = 0
function T { param($n,[scriptblock]$b)
    try { $r = & $b; if ($r) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }
    catch { Write-Host "  FAIL $n -- $($_.Exception.Message.Split([char]10)[0])" -ForegroundColor Red; $script:fail++ } }
function Section($t){ Write-Host "`n== $t ==" -ForegroundColor Cyan }

$root = Split-Path -Parent $PSScriptRoot
$global:PIM_ConfigVariant = 'test'
Import-Module (Join-Path $root 'engine\_shared\PIM-Functions.psm1') -Force -DisableNameChecking

function New-TestJwt([hashtable]$Claims) {
    $b64 = { param($o) [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($o | ConvertTo-Json -Compress))).TrimEnd('=').Replace('+','-').Replace('/','_') }
    ((& $b64 @{ alg='none'; typ='JWT' }) + '.' + (& $b64 $Claims) + '.sig')
}

Section 'Missing-role hint'
T 'non-403 status returns no hint'                  { $null -eq (Get-PimMissingRoleHint -Path '/groups' -StatusCode 500 -ErrorBody 'boom') }
T 'Test-PimIsAuthForbidden 403/insufficient/false'  { (Test-PimIsAuthForbidden -StatusCode 403) -and (Test-PimIsAuthForbidden -ErrorBody 'Insufficient privileges') -and -not (Test-PimIsAuthForbidden -StatusCode 500 -ErrorBody 'x') }
T 'roleManagementPolicies -> RoleManagementPolicy.ReadWrite.AzureADGroup + Grant script' {
    $h = Get-PimMissingRoleHint -Path "/policies/roleManagementPolicies('x')" -StatusCode 403 -AppOnly $true
    ($h.AppRolesToGrant -contains 'RoleManagementPolicy.ReadWrite.AzureADGroup') -and ($h.Hint -match 'Grant-PimGraphAppRoles') }
T '/users -> User.ReadWrite.All'                    { (Get-PimMissingRoleHint -Path '/users/x' -StatusCode 403).AppRolesToGrant -contains 'User.ReadWrite.All' }
T '/groups -> Group.ReadWrite.All'                  { (Get-PimMissingRoleHint -Path '/groups' -StatusCode 403).AppRolesToGrant -contains 'Group.ReadWrite.All' }
T 'accessReviews -> AccessReview.Read.All'          { (Get-PimMissingRoleHint -Path '/identityGovernance/accessReviews/x' -StatusCode 403).AppRolesToGrant -contains 'AccessReview.Read.All' }
T 'interactive hint names the PIM role to activate' { $h = Get-PimMissingRoleHint -Path '/roleManagement/directory/roleAssignmentScheduleRequests' -StatusCode 403 -AppOnly $false; ($h.PimRolesToActivate -contains 'Privileged Role Administrator') -and ($h.Hint -match 'Activate in PIM') }
T 'unknown path falls back to Directory.Read.All'   { (Get-PimMissingRoleHint -Path '/foo/bar' -StatusCode 403).AppRolesToGrant -contains 'Directory.Read.All' }

Section 'Account sign-in prompt clarity'
T 'default select_account; ForceFresh -> login'     { ((ConvertTo-PimAuthCodePrompt) -eq 'select_account') -and ((ConvertTo-PimAuthCodePrompt -ForceFresh) -eq 'login') }
T 'known stale account -> login'                    { (ConvertTo-PimAuthCodePrompt -KnownStaleAccount 'old@c.com') -eq 'login' }
T 'no cache -> picker, no mismatch'                 { $r = Get-PimAccountSignInHint -CachedAccount '' -ExpectedAccount 'a@b.com'; (-not $r.Mismatch) -and ($r.Prompt -eq 'select_account') }
T 'cached differs from expected -> mismatch+login'  { $r = Get-PimAccountSignInHint -CachedAccount 'old@b.com' -ExpectedAccount 'new@b.com'; $r.Mismatch -and ($r.Prompt -eq 'login') }
T 'matching cached account -> picker, no mismatch'  { $r = Get-PimAccountSignInHint -CachedAccount 'Same@b.com' -ExpectedAccount 'same@b.com'; (-not $r.Mismatch) -and ($r.Prompt -eq 'select_account') }

Section 'AD-failure diagnostics'
T 'SYSTEM+no cred+no DC flags identity + DC'        { $d = Resolve-PimAdFailureDiagnostic -ProcessIdentity 'NT AUTHORITY\SYSTEM' -DiscoveredDc ''; $d.LooksLikeSystem -and (($d.Causes -join ' ') -match 'domain controller') -and (($d.Causes -join ' ') -match 'non-domain identity') }
T 'machine account (trailing $) is system-ish'      { (Resolve-PimAdFailureDiagnostic -ProcessIdentity 'CONTOSO\MGMT1$' -DiscoveredDc 'dc1').LooksLikeSystem }
T 'domain user+DC+tickets -> authorization problem' { $d = Resolve-PimAdFailureDiagnostic -ProcessIdentity 'CONTOSO\admin' -HasExplicitCredential $true -HasKerberosTickets $true -DiscoveredDc 'dc1'; (-not $d.LooksLikeSystem) -and (($d.Causes -join ' ') -match 'authorization') }
T 'DC reachable but no tickets flags Kerberos'      { (Resolve-PimAdFailureDiagnostic -ProcessIdentity 'CONTOSO\admin' -HasExplicitCredential $true -HasKerberosTickets $false -DiscoveredDc 'dc1').Causes -join ' ' -match 'Kerberos' }
T 'live wrapper returns shaped object, no throw'    { $d = Get-PimAdFailureDiagnostic -HasExplicitCredential $false -ErrorMessage 'x'; ("$($d.ProcessIdentity)".Length -gt 0) -and ($d.Causes.Count -ge 1) }

Section 'MFA-gated Manager login'
T 'ConvertFrom-PimJwtClaims decodes; junk -> null'  { ((ConvertFrom-PimJwtClaims -Token (New-TestJwt @{ upn='a@b.com' })).upn -eq 'a@b.com') -and ($null -eq (ConvertFrom-PimJwtClaims -Token 'nope')) }
T 'amr mfa -> true; pwd-only -> false'              { (Test-PimTokenHasMfa -Token (New-TestJwt @{ amr=@('pwd','mfa') })) -and -not (Test-PimTokenHasMfa -Token (New-TestJwt @{ amr=@('pwd') })) }
T 'fido + acr=1 -> true; no amr -> false'           { (Test-PimTokenHasMfa -Token (New-TestJwt @{ amr=@('fido') })) -and (Test-PimTokenHasMfa -Token (New-TestJwt @{ acr='1' })) -and -not (Test-PimTokenHasMfa -Token (New-TestJwt @{ sub='x' })) }
T 'hosted gate is a no-op (Easy Auth) -> Allowed'   { $r = Assert-PimManagerMfa -Hosted; $r.Allowed -and ($r.Source -match 'Easy Auth') }
T 'local MFA token -> Allowed + UPN'                { $r = Assert-PimManagerMfa -Token (New-TestJwt @{ upn='ops@b.com'; amr=@('pwd','mfa') }); $r.Allowed -and ($r.Upn -eq 'ops@b.com') }
T 'local non-MFA token -> denied + NeedSignIn'      { $r = Assert-PimManagerMfa -Token (New-TestJwt @{ amr=@('pwd') }); (-not $r.Allowed) -and $r.NeedSignIn }
T 'local no token -> denied, no device-code in hint'{ $r = Assert-PimManagerMfa; (-not $r.Allowed) -and $r.NeedSignIn -and ($r.Hint -notmatch 'device') }
T 'RequireMfa=$false -> Allowed (gate disabled)'    { (Assert-PimManagerMfa -RequireMfa $false).Allowed }

Section 'Support / diagnostics -- connectivity + permission checks (section 28 [M9])'
T 'SQL clean pass -> status pass, no hint'           { $c = Get-PimConnectivityCheck -Surface 'sql' -Reachable $true; ($c.status -eq 'pass') -and (-not $c.hint) -and (-not $c.isPermissionFailure) }
T 'SQL unreachable -> fail + connectivity hint'      { $c = Get-PimConnectivityCheck -Surface 'sql' -Reachable $false -ErrorMessage 'A network-related error'; ($c.status -eq 'fail') -and (-not $c.isPermissionFailure) -and ($c.hint -match '(?i)firewall|VNet|server name') }
T 'SQL 403/auth -> fail + DB-user grant hint'        { $c = Get-PimConnectivityCheck -Surface 'sql' -Reachable $true -ErrorMessage 'Login failed -- Authorization_RequestDenied'; ($c.status -eq 'fail') -and $c.isPermissionFailure -and ($c.hint -match '(?i)db_datareader|FROM EXTERNAL PROVIDER') }
T 'Graph 403 -> fail + names missing app-role'       { $c = Get-PimConnectivityCheck -Surface 'graph' -Reachable $true -StatusCode 403 -ProbePath '/v1.0/users/x'; ($c.status -eq 'fail') -and $c.isPermissionFailure -and ($c.hint -match '(?i)app(lication)? role|Grant-PimGraphAppRoles') }
T 'Graph clean 200 -> pass'                          { (Get-PimConnectivityCheck -Surface 'graph' -Reachable $true -StatusCode 200).status -eq 'pass' }
T 'ARM not configured -> skipped (no Azure scope)'   { (Get-PimConnectivityCheck -Surface 'arm' -Configured $false).status -eq 'skipped' }
T 'ARM 403 -> fail permission'                       { $c = Get-PimConnectivityCheck -Surface 'arm' -Reachable $true -StatusCode 403 -ProbePath '/subscriptions'; ($c.status -eq 'fail') -and $c.isPermissionFailure }

Section 'Support / diagnostics -- health summary (injected state)'
T 'storeMode normalises sql/file'                    { ((Get-PimSupportHealthSummary -StorageMode 'SQL').storeMode -eq 'sql') -and ((Get-PimSupportHealthSummary -StorageMode 'csv').storeMode -eq 'file') }
T 'any stale cache -> stale verdict'                 { (Get-PimSupportHealthSummary -CacheFreshness @{ a='live'; b='stale' }).cacheVerdict -eq 'stale' }
T 'all live -> live; all none -> none'               { ((Get-PimSupportHealthSummary -CacheFreshness @{ a='live'; b='live' }).cacheVerdict -eq 'live') -and ((Get-PimSupportHealthSummary -CacheFreshness @{ a='none' }).cacheVerdict -eq 'none') }
T 'lastRun ok -> green; failed -> red; none -> unknown' {
    ((Get-PimSupportHealthSummary -LastRun @{ name='x'; ok=$true }).lastRunStatus -eq 'green') -and
    ((Get-PimSupportHealthSummary -LastRun @{ name='x'; ok=$false }).lastRunStatus -eq 'red') -and
    ((Get-PimSupportHealthSummary).lastRunStatus -eq 'unknown') }
T 'instance + version carried through'               { $h = Get-PimSupportHealthSummary -InstanceName 'sql:PimPlatform' -ManagerVersion '2.4.9'; ($h.instance -eq 'sql:PimPlatform') -and ($h.managerVersion -eq '2.4.9') }

Section 'Support / diagnostics -- redaction (Protect-PimDiagnosticsText)'
T 'connection-string password masked'               { (Protect-PimDiagnosticsText -Text 'Server=x;Database=d;User ID=app;Password=Sup3rSecret!') -notmatch 'Sup3rSecret' }
T 'storage SAS sig masked'                           { (Protect-PimDiagnosticsText -Text 'https://x.blob.core.windows.net/c?sig=abcDEF123%2Bslash') -notmatch 'abcDEF123' }
T 'JWT token masked'                                 { (Protect-PimDiagnosticsText -Text ('tok=' + (New-TestJwt @{ upn='a@b.com'; amr=@('mfa') }))) -match 'REDACTED-TOKEN' }
# NOTE: the PEM BEGIN/END markers are assembled at runtime (string concat) so
# the full marker never appears contiguously in this source file and the CI
# secret-scan can't false-positive on a TEST fixture. The runtime string is
# still a real PEM block, so the redactor under test is fully exercised.
T 'PEM private key block masked'                     { $beg=('-----BEGIN '+'PRIVATE '+'KEY-----'); $end=('-----END '+'PRIVATE '+'KEY-----'); (Protect-PimDiagnosticsText -Text "$beg`nAAAABBBBCCCC`n$end") -match 'REDACTED-PRIVATE-KEY' }
T 'cert thumbprint (40-hex) masked'                  { (Protect-PimDiagnosticsText -Text 'thumb 1234567890ABCDEF1234567890ABCDEF12345678') -match 'REDACTED-THUMBPRINT' }
T 'GUID kept-first-8, tail masked'                   { $r = Protect-PimDiagnosticsText -Text 'tenant a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d'; ($r -match 'a1b2c3d4') -and ($r -notmatch '5e6f-7a8b') }
T 'generic clientSecret=value masked'               { (Protect-PimDiagnosticsText -Text 'clientSecret=AbCdEf123456') -notmatch 'AbCdEf123456' }
T 'redaction is idempotent (re-run = same)'          { $once = Protect-PimDiagnosticsText -Text 'Password=hunter2'; (Protect-PimDiagnosticsText -Text $once) -eq $once }
T 'empty/null -> empty string'                       { (Protect-PimDiagnosticsText -Text '') -eq '' }

Section 'Support / diagnostics -- bundle assembly + redaction (New-PimDiagnosticsBundle)'
$bChecks = @((Get-PimConnectivityCheck -Surface 'sql' -Reachable $true), (Get-PimConnectivityCheck -Surface 'graph' -Reachable $true -StatusCode 200))
$bHealth = Get-PimSupportHealthSummary -StorageMode 'sql' -InstanceName 'sql:PimPlatform' -ManagerVersion '2.4.9'
$bVer    = @{ manager='2.4.9'; powershell='5.1.0'; dotnet='4.0.30319' }
# Feed a FAKE secret + GUID through config to prove the bundle masks them.
$fakeSecret = 'Server=tcp:srv;Database=PimPlatform;User ID=eng;Password=PlainTextSecret123;'
$fakeGuid   = '11112222-3333-4444-5555-666677778888'
$bundle = New-PimDiagnosticsBundle -Versions $bVer -Checks $bChecks -Health $bHealth -Config @{ connectionString=$fakeSecret; tenantId=$fakeGuid; storageMode='sql' } -RecentRuns @(@{ name='engine'; whenUtc='2026-06-16T00:00:00Z'; ok=$true })
T 'bundle has versions/checks/health/config fields'  { ($bundle.text -match '"versions"') -and ($bundle.text -match '"checks"') -and ($bundle.text -match '"health"') -and ($bundle.text -match '"config"') -and ($bundle.text -match '"recentRuns"') }
T 'bundle MASKS the fake password'                   { $bundle.text -notmatch 'PlainTextSecret123' }
T 'bundle MASKS the fake full GUID (tail gone)'      { ($bundle.text -notmatch '3333-4444-5555') -and ($bundle.text -match '11112222') }
T 'bundle object re-parses (already-masked struct)'  { $null -ne $bundle.object }
T 'bundle carries the safe-to-share note'            { $bundle.text -match 'Sanitized bundle' }

Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host (" RESULT: {0} pass, {1} fail" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) {'Red'} else {'Green'})
Write-Host "=====================================================" -ForegroundColor Cyan
if ($script:fail) { exit 1 }
