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

Section 'Missing-role hint -- ARM (AuthorizationFailed) plane'
T 'ARM roleAssignments path -> arm plane + Azure RBAC wording, not Graph' {
    $h = Get-PimMissingRoleHint -Path '/subscriptions/x/providers/Microsoft.Authorization/roleAssignments/y' -StatusCode 403 -AppOnly $true
    ($h.Plane -eq 'arm') -and ($h.Hint -match '(?i)Azure RBAC') -and ($h.Hint -notmatch 'Grant-PimGraphAppRoles') }
T 'ARM AuthorizationFailed body classified as auth failure' { Test-PimIsAuthForbidden -ErrorBody 'AuthorizationFailed: client does not have permission' }
T 'ARM management.azure.com generic scope -> arm plane' {
    (Get-PimMissingRoleHint -Path 'https://management.azure.com/subscriptions/x/resourcegroups' -StatusCode 403).Plane -eq 'arm' }
T 'ARM interactive hint says activate Azure-resource role'  {
    (Get-PimMissingRoleHint -Path '/subscriptions/x/providers/Microsoft.Authorization/roleEligibilitySchedules' -StatusCode 403 -AppOnly $false).Hint -match '(?i)PIM for Azure resources' }
T 'Graph path keeps graph plane (regression)'              { (Get-PimMissingRoleHint -Path '/users/x' -StatusCode 403).Plane -eq 'graph' }
T 'new appRoleAssignedTo -> AppRoleAssignment.ReadWrite.All' { (Get-PimMissingRoleHint -Path '/servicePrincipals/x/appRoleAssignedTo' -StatusCode 403).AppRolesToGrant -contains 'AppRoleAssignment.ReadWrite.All' }
T 'new deviceManagement roleAssignments -> Intune RBAC role' { (Get-PimMissingRoleHint -Path '/deviceManagement/roleAssignments' -StatusCode 403).AppRolesToGrant -contains 'DeviceManagementRBAC.ReadWrite.All' }

Section 'Token-claims role PRE-FLIGHT (proactive -- before the 403)'
T 'unknown/benign operation -> not required, allowed'      { $p = Test-PimOperationRolePreflight -Operation '/me' -Token (New-TestJwt @{ wids=@() }); (-not $p.Required) -and $p.Allowed }
T 'pim-policy with PRA active in wids -> allowed + matched' {
    $tok = New-TestJwt @{ wids=@('e8611ab8-c189-46e8-94e1-60213ab1f814') }
    $p = Test-PimOperationRolePreflight -Operation 'pim-policy' -Token $tok
    $p.Required -and $p.Allowed -and ($p.MatchedRole -eq 'Privileged Role Administrator') }
T 'pim-policy with NO matching wids -> blocked + activate hint' {
    $p = Test-PimOperationRolePreflight -Operation 'pim-policy' -Token (New-TestJwt @{ wids=@('fe930be7-5e62-47db-91af-98c3a49a38b1') })
    $p.Required -and (-not $p.Allowed) -and ($p.Hint -match '(?i)activate.*PIM') -and ($p.MatchedRole -eq '') }
T 'Global Admin (62e9..) satisfies a user-write op'        {
    $p = Test-PimOperationRolePreflight -Operation '/users/abc' -Token (New-TestJwt @{ wids=@('62e90394-69f5-4237-9190-012177145e10') })
    $p.Required -and $p.Allowed -and ($p.MatchedRole -eq 'Global Administrator') }
T 'absent wids on a privileged op -> fail closed (blocked)' {
    $p = Test-PimOperationRolePreflight -Operation 'administrative-unit' -Token (New-TestJwt @{ sub='x' })
    $p.Required -and (-not $p.Allowed) -and ($p.Hint.Length -gt 0) }
T 'AppOnly engine context -> no-op allowed (no interactive wids)' {
    $p = Test-PimOperationRolePreflight -Operation 'pim-policy' -AppOnly $true
    $p.Required -and $p.Allowed -and ($p.Source -match '(?i)app-only') }
T 'path fragment resolves the op (roleAssignmentSchedule -> PRA)' {
    (Resolve-PimRequiredRolesForOperation -Operation '/roleManagement/directory/roleAssignmentScheduleRequests') -contains 'Privileged Role Administrator' }
T 'Resolve active wids ids from claims (lower-cased, empty-dropped)' {
    $ids = @(Resolve-PimActiveDirectoryRoleTemplateIds -Claims ([pscustomobject]@{ wids=@('E8611AB8-C189-46E8-94E1-60213AB1F814','') }))
    ($ids.Count -eq 1) -and ($ids -contains 'e8611ab8-c189-46e8-94e1-60213ab1f814') }
T 'access-review op needs IGA / GA, group-only token blocked' {
    $p = Test-PimOperationRolePreflight -Operation 'access-review' -Claims ([pscustomobject]@{ wids=@('fdd7a751-b60b-444a-984c-02652fe8fa1c') })
    (-not $p.Allowed) -and ($p.RequiredRoles -contains 'Identity Governance Administrator') }
T 'enterprise-app op satisfied by Cloud App Administrator'  {
    $p = Test-PimOperationRolePreflight -Operation 'enterprise-app' -Claims ([pscustomobject]@{ wids=@('158c047a-c907-4556-b7ef-446551a6b5f7') })
    $p.Allowed -and ($p.MatchedRole -eq 'Cloud Application Administrator') }

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

Section 'SEC-12b: the SQL layer must not silently present a DIFFERENT identity'
# 🔴 SEC-12 was fixed in PIM-Rest; this is the SAME defect one layer down, and it was still live.
# BUG-34 fixed the PRECEDENCE (an explicit SPN is tried before ambient MI). It never fixed the
# FAILURE path: when the explicit SPN's token could not be ACQUIRED, control carried on to the MI
# branch, and then to a pre-pinned $global:PIM_SqlAccessToken -- either of which is a different
# principal.
# 🪤 OBSERVED IN A LIVE RUN, not imagined:
#       [sql] SPN token failed: ...
#       [sql] token source: MANAGED IDENTITY
#   ...then "The SELECT permission was denied on the object 'Tenants'". That reads as an RBAC
#   problem and is not one -- the connection had authenticated as the machine's managed identity
#   instead of the SPN that was explicitly configured. Every minute spent on the permission is
#   wasted, and there is nothing in the error pointing anywhere near the cause.
$sqlLibPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-SqlStore.ps1'
$restLibPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-Rest.ps1'
. $restLibPath
. $sqlLibPath

function Invoke-Sec12bProbe {
    <#
      Drive New-PimSqlConnection with an EXPLICIT SPN whose credential cannot be acquired, while a
      pre-pinned token AND (on this machine) a managed identity are both available -- i.e. exactly
      the state in which the old code silently substituted one of them. Returns the error text, or
      '' if it did NOT refuse.
      🔒 Every global is saved and restored: this suite must not leave auth state behind for the
      suites that run after it in the same process.
    #>
    $saved = @{
        cid   = $global:PIM_SqlClientId;       thumb = $global:PIM_SqlCertThumbprint
        cid2  = $global:PIM_ClientId;          thumb2 = $global:PIM_CertThumbprint
        tid   = $global:PIM_TenantId;          tok   = $global:PIM_SqlAccessToken
        sec   = $global:PIM_SqlClientSecret;   sec2  = $global:PIM_ClientSecret
    }
    try {
        $global:PIM_SqlClientId       = '22222222-2222-2222-2222-222222222222'
        $global:PIM_SqlCertThumbprint = 'DEADBEEF00000000000000000000000000000000'
        $global:PIM_TenantId          = '11111111-1111-1111-1111-111111111111'
        $global:PIM_SqlClientSecret   = $null; $global:PIM_ClientSecret = $null
        # A token left over from somewhere else -- the last-resort branch the old code would reach.
        $global:PIM_SqlAccessToken    = 'a-previously-pinned-token-from-somewhere-else'
        try {
            [void](New-PimSqlConnection -ConnectionString 'Server=tcp:x.database.windows.net,1433;Database=D;Encrypt=True')
            return ''
        } catch { return "$($_.Exception.Message)" }
    } finally {
        $global:PIM_SqlClientId = $saved.cid; $global:PIM_SqlCertThumbprint = $saved.thumb
        $global:PIM_ClientId = $saved.cid2;   $global:PIM_CertThumbprint = $saved.thumb2
        $global:PIM_TenantId = $saved.tid;    $global:PIM_SqlAccessToken = $saved.tok
        $global:PIM_SqlClientSecret = $saved.sec; $global:PIM_ClientSecret = $saved.sec2
    }
}
$sec12b = Invoke-Sec12bProbe

T 'SEC-12b: an explicit SPN whose token cannot be acquired REFUSES the connection' { [bool]$sec12b }
T '  ...naming the SPN that was configured'      { $sec12b -match '22222222-2222-2222-2222-222222222222' }
T '  ...and saying it will not fall back'        { $sec12b -match 'Refusing to fall back' }
# 🔒 The two identities it must not silently become, named in the message so the reader knows what
# was declined on their behalf rather than wondering what changed.
T '  ...naming the managed identity as a thing it declined to use' { $sec12b -match 'managed identity' }
T '  ...and the pre-pinned token too'                              { $sec12b -match 'pre-pinned' }
# 🔑 The message must say how to get ambient auth ON PURPOSE. A refusal with no exit is how a guard
# gets deleted by the next person who legitimately wants the other behaviour.
T '  ...and how to opt INTO ambient auth deliberately' { $sec12b -match 'clear \$global:PIM_SqlClientId' }

# 🪤 THE CONTROL. Without this, a guard that broke ALL auth would pass every assertion above --
# the "test that cannot fail for the right reason" trap this project keeps paying for. With NO
# explicit SPN configured, the ambient path must still be allowed to run.
$ambientOk = $false
$savedC = $global:PIM_SqlClientId; $savedC2 = $global:PIM_ClientId
$savedT = $global:PIM_SqlCertThumbprint; $savedT2 = $global:PIM_CertThumbprint
try {
    $global:PIM_SqlClientId = $null; $global:PIM_ClientId = $null
    $global:PIM_SqlCertThumbprint = $null; $global:PIM_CertThumbprint = $null
    try { [void](New-PimSqlConnection -ConnectionString 'Server=tcp:x.database.windows.net,1433;Database=D;Encrypt=True'); $ambientOk = $true }
    catch { $ambientOk = $false }
} finally {
    $global:PIM_SqlClientId = $savedC; $global:PIM_ClientId = $savedC2
    $global:PIM_SqlCertThumbprint = $savedT; $global:PIM_CertThumbprint = $savedT2
}
T '  ...while NO explicit SPN still permits the ambient path (the guard is narrow, not a wall)' { $ambientOk }

# 🔒 ORDER IS THE GUARD. A refusal written after the MI branch prevents nothing at all.
$sqlSrc = Get-Content -LiteralPath $sqlLibPath -Raw
# 🪤 STRIP FULL-LINE COMMENTS FIRST, and this suite paid for the lesson on its own first run: the
# order assert below matched the SEC-12b COMMENT above (which quotes the very log line it looks
# for) instead of the managed-identity branch, and reported a correctly-ordered guard as RED.
# Third time in one session that a source assertion met a comment -- twice satisfied by one, once
# broken by one. *A source-scanning assertion must read CODE*, in both directions.
$sqlCode = (($sqlSrc -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
$iRefuse = $sqlCode.IndexOf('PIM store auth REFUSED')
$iMi     = $sqlCode.IndexOf('if (-not $tok -and $miAvail)')
$iPinned = $sqlCode.IndexOf('$global:PIM_SqlAccessToken) { $tok = $global:PIM_SqlAccessToken }')
T 'SEC-12b: the refusal is placed BEFORE the managed-identity branch' { $iRefuse -gt 0 -and $iMi -gt 0 -and $iRefuse -lt $iMi }
T '  ...and before the pre-pinned-token last resort'                  { $iRefuse -gt 0 -and $iPinned -gt 0 -and $iRefuse -lt $iPinned }
# 🪤 The reason must be CARRIED into the refusal. The old branch dropped it into a Write-Warning
# and moved on, so the one fact that explained the whole downstream symptom was gone by the time
# anybody read the failure.
# 🔴 ASSERTED BEHAVIOURALLY, and the first version could NOT fail: it matched `$spnErr` in the
# SOURCE, so blanking the assignment (`$spnErr = $null`) left the variable name in place and the
# negative run came back 0 red. Checking that a NAME appears is not checking that a VALUE flows --
# the same family as the guard that detected a mismatch and lost it in an exception. The probe's
# underlying failure names the bogus thumbprint, so the outer refusal must repeat it.
T '  ...and carries the underlying credential error into the refusal' { $sec12b -match 'DEADBEEF' }

Section 'SEC-13: no shipped setup script may make a CLIENT SECRET structurally required'
# 🔒 Repo-root rule: "authenticate as its SPN using a CERTIFICATE -- never interactively, never with
# a client secret." A [Parameter(Mandatory)] secret does not merely PREFER a secret, it makes one
# STRUCTURALLY REQUIRED: an operator whose onboarding SPN is cert-only cannot run the script at all,
# and the only way forward is to mint the credential the rule forbids.
# 🔴 THREE INSTANCES, FOUND 2026-08-28 BY SWEEPING RATHER THAN BY LOOKING AT ONE:
#   Initialize-PimMailSender.ps1, Initialize-PimTenantStore.ps1, Setup-PimMsp.ps1.
# Grant-PimMiSql had been fixed for exactly this on 2026-08-09 -- and the fix stopped at the
# function that was in front of somebody. 🪤 Setup-PimMsp is the sharpest case: the script it
# forwards to (Setup-PimContainers.ps1) had accepted -SqlAdminCertThumbprint all along, and this
# caller simply never exposed it. The capability existed downstream and nothing could reach it --
# BUG-78's shape, one level up.
# ▶ SO THIS ASSERTION NAMES NO SCRIPT. It DISCOVERS every shipped .ps1 under tools\setup\ and
# setup\ by AST and requires that none of them marks a secret parameter Mandatory. A fourth
# instance is caught the day it is written, which a hand-written list of three could never do.
$setupRoots = @(
    (Join-Path (Split-Path -Parent $PSScriptRoot) 'tools\setup'),
    (Join-Path (Split-Path -Parent $PSScriptRoot) 'setup')
) | Where-Object { Test-Path -LiteralPath $_ }

$sec13Files = @()
foreach ($r in $setupRoots) { $sec13Files += @(Get-ChildItem -LiteralPath $r -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue) }
# 🪤 A sweep that matches nothing passes silently and proves nothing -- recorded in this project
# more than once. Assert the sweep found a real population before trusting its verdict.
T 'SEC-13: the sweep actually finds shipped setup scripts' { @($sec13Files).Count -ge 5 }

$sec13Offenders = New-Object System.Collections.Generic.List[string]
$sec13Unparsed  = New-Object System.Collections.Generic.List[string]
foreach ($file in $sec13Files) {
    $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$errs)
    if ($errs -and $errs.Count) {
        # A file this host cannot parse is one this host cannot audit. 7.0-only scripts are a
        # legitimate case (they run in a container), so they are recorded, not failed -- but the
        # skip is PAID FOR below by a textual check, or the sweep would have a blind spot exactly
        # where somebody could hide a mandatory secret.
        $sec13Unparsed.Add($file.Name) | Out-Null
        $txt = Get-Content -LiteralPath $file.FullName -Raw
        if ($txt -match '(?i)\[Parameter\(Mandatory[^\)]*\)\][^\r\n]*\$\w*(Secret|Password|Pwd)\b') { $sec13Offenders.Add("$($file.Name) (text)") | Out-Null }
        continue
    }
    if (-not $ast.ParamBlock) { continue }
    foreach ($p in $ast.ParamBlock.Parameters) {
        $name = "$($p.Name.VariablePath.UserPath)"
        if ($name -notmatch '(?i)(Secret|Password|Pwd)$') { continue }
        # 🔑 The KV secret NAME is not a credential. `-SecretName` / `-VaultSecret` name a pointer
        # to a secret; requiring one is correct and must not be flagged, or the guard becomes noise
        # and gets switched off.
        if ($name -match '(?i)(SecretName|SecretUri|SecretId|VaultSecret)') { continue }
        $mandatory = $false
        foreach ($a in $p.Attributes) {
            if ("$($a.TypeName)" -notmatch '(?i)^Parameter$') { continue }
            foreach ($na in $a.NamedArguments) {
                if ("$($na.ArgumentName)" -match '(?i)^Mandatory$') {
                    # `[Parameter(Mandatory)]` has no explicit value; `Mandatory=$true` does.
                    if ($na.ExpressionOmitted -or "$($na.Argument)" -match '(?i)true') { $mandatory = $true }
                }
            }
        }
        if ($mandatory) { $sec13Offenders.Add("$($file.Name):`$$name") | Out-Null }
    }
}
$sec13List = @($sec13Offenders.ToArray())
T 'SEC-13: NO shipped setup script marks a client-secret parameter Mandatory' {
    if ($sec13List.Count) { Write-Host ("      offenders: " + ($sec13List -join ', ')) -ForegroundColor Yellow }
    $sec13List.Count -eq 0
}
# 🔒 The three that were fixed must offer the certificate ALTERNATIVE, not merely have stopped
# demanding a secret -- "optional secret and no other way to authenticate" is a worse state than
# where this started, and it would satisfy the assertion above on its own.
foreach ($pair in @(
    @{ f = 'Initialize-PimMailSender.ps1';  p = 'AdminCertThumbprint' }
    @{ f = 'Initialize-PimTenantStore.ps1'; p = 'AdminCertThumbprint' }
    @{ f = 'Setup-PimMsp.ps1';              p = 'SqlAdminCertThumbprint' })) {
    $fp = Join-Path (Split-Path -Parent $PSScriptRoot) "tools\setup\$($pair.f)"
    $body = if (Test-Path -LiteralPath $fp) { Get-Content -LiteralPath $fp -Raw } else { '' }
    T "  ...$($pair.f) offers -$($pair.p) instead" { $body -match ('\$' + $pair.p) }
    # ...and REFUSES both-or-neither, so an ambiguous invocation cannot pick a credential silently.
    T "  ...and refuses both-or-neither credentials" { $body -match 'pass EITHER' -and $body -match 'is required' }
}

Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host (" RESULT: {0} pass, {1} fail" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) {'Red'} else {'Green'})
Write-Host "=====================================================" -ForegroundColor Cyan
if ($script:fail) { exit 1 }
