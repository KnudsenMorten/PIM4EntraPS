#Requires -Version 5.1
<#
.SYNOPSIS
    Offline, rerunnable tests for the PIM4EntraPS setup/deploy + hosting family
    (tools/setup/*). No live tenant, no Azure -- pure assertions over the shared
    helpers + static contract checks on the deploy scripts.

.DESCRIPTION
    Covers REQUIREMENTS S1 (hosting) + S3 (setup):
      * _PimSetupShared helpers: region guard (West Europe / Denmark East only, France
        refused), SID-from-appId, Graph app-role map, GSA/private-link guidance text,
        version reader, banner runs without throwing.
      * Static contract on the deploy scripts: every tool/setup/*.ps1 parses; the
        container script uses --ingress external + --yaml (NOT multi-token --command);
        the engine app-reg installer is REST/cert (no Microsoft.Graph #Requires);
        no real tenant/subscription/customer values are baked into the published
        scripts (public-safety).

.EXAMPLE
    powershell -NoProfile -File tests\Test-PimSetupHosting.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:pass = 0; $script:fail = 0
function T { param($n,[scriptblock]$b)
    try { $r = & $b; if ($r) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }
    catch { Write-Host "  FAIL $n -- $($_.Exception.Message.Split([char]10)[0])" -ForegroundColor Red; $script:fail++ } }
function Section($t){ Write-Host "`n== $t ==" -ForegroundColor Cyan }

$root    = Split-Path -Parent $PSScriptRoot          # ...\PIM4EntraPS
$setpDir = Join-Path $root 'tools\setup'
. (Join-Path $setpDir '_PimSetupShared.ps1')

Section 'SHARED HELPERS -- region guard'
T 'westeurope allowed (normalised)'        { (Assert-PimSetupRegion -Location 'West Europe') -eq 'westeurope' }
T 'denmarkeast allowed'                     { (Assert-PimSetupRegion -Location 'denmarkeast') -eq 'denmarkeast' }
T 'francecentral REFUSED'                   { $threw=$false; try { Assert-PimSetupRegion -Location 'francecentral' } catch { $threw=$true }; $threw }
T 'francesouth REFUSED'                     { $threw=$false; try { Assert-PimSetupRegion -Location 'francesouth' } catch { $threw=$true }; $threw }
T 'eastus (non-approved) REFUSED'           { $threw=$false; try { Assert-PimSetupRegion -Location 'eastus' } catch { $threw=$true }; $threw }

Section 'SHARED HELPERS -- SID-from-appId + app-role map'
T 'SID is 0x + 32 hex chars'                { $s = ConvertTo-PimSqlSidFromAppId -AppId '11111111-2222-3333-4444-555555555555'; $s -match '^0x[0-9A-F]{32}$' }
T 'Graph app-role map has the engine roles' {
    $m = Get-PimGraphAppRoleMap
    $m.ContainsKey('RoleManagement.ReadWrite.Directory') -and $m.ContainsKey('PrivilegedAccess.ReadWrite.AzureADGroup') `
        -and $m.ContainsKey('Group.ReadWrite.All') -and $m.ContainsKey('User.ReadWrite.All') -and ($m.Count -ge 6)
}
T 'Get-PimGraphAppRoleMap returns a copy (caller cannot mutate module table)' {
    $a = Get-PimGraphAppRoleMap; $a['__probe__'] = 'x'
    -not (Get-PimGraphAppRoleMap).ContainsKey('__probe__')
}

Section 'SHARED HELPERS -- GSA / private-link guidance + version + banner'
T 'GSA guidance names every required private-link zone' {
    $g = Get-PimGsaPrivateLinkGuidance -ManagerFqdn 'app.example.io'
    ($g -match 'privatelink\.database\.windows\.net') -and ($g -match 'privatelink\.azurewebsites\.net') `
        -and ($g -match 'privatelink\.blob\.core\.windows\.net') -and ($g -match 'Global Secure Access') -and ($g -match '168\.63\.129\.16')
}
T 'GSA guidance embeds the manager fqdn when supplied'  { (Get-PimGsaPrivateLinkGuidance -ManagerFqdn 'mgr.contoso.io') -match 'mgr\.contoso\.io' }
T 'Get-PimSetupSolutionVersion reads VERSION'           { (Get-PimSetupSolutionVersion -SolutionRoot $root) -eq ((Get-Content (Join-Path $root 'VERSION') -Raw).Trim()) }
T 'Show-PimSetupBanner runs without throwing'           { Show-PimSetupBanner -ScriptName 'Test' -SolutionRoot $root; $true }

Section 'DEPLOY SCRIPTS -- parse + structural contract'
$scripts = 'Setup-PimContainers.ps1','Setup-PimVM.ps1','Setup-PimMsp.ps1','Update-PimContainers.ps1','Install-PimEngineAppRegistration.ps1','_PimSetupShared.ps1'
foreach ($s in $scripts) {
    T "parses (PS 5.1 AST): $s" {
        $p = Join-Path $setpDir $s; $t=$null; $e=$null
        [System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$t,[ref]$e) | Out-Null
        -not ($e -and $e.Count)
    }
}

$containers = Get-Content (Join-Path $setpDir 'Setup-PimContainers.ps1') -Raw
T 'container manager uses --ingress external (internal env reachability fix)' { $containers -match '--ingress external' }
T 'container workers deploy via --yaml (NOT multi-token --command)'           { ($containers -match '--yaml') -and ($containers -notmatch '--command\b') }
T 'container env is internal-only (--internal-only true)'                     { $containers -match '--internal-only true' }
T 'container script dot-sources the shared lib'                               { $containers -match '_PimSetupShared\.ps1' }
T 'container script enforces region guard'                                    { $containers -match 'Assert-PimSetupRegion' }
T 'container script enforces persistent SQL (Set-PimSqlNoAutoPause)'          { $containers -match 'Set-PimSqlNoAutoPause' }
T 'container script prints GSA/private-link guidance'                         { $containers -match 'Show-PimGsaPrivateLinkGuidance' }

$msp = Get-Content (Join-Path $setpDir 'Setup-PimMsp.ps1') -Raw
T 'MSP script has the az acr import step (build-once / import-per-customer)'  { $msp -match 'az acr import|acr.*import' -and $msp -match 'acr' }
T 'MSP script wires template-pull (pull-not-push)'                           { $msp -match 'PIM_MspTemplateConn' -and $msp -match 'template-pull' }

$vm = Get-Content (Join-Path $setpDir 'Setup-PimVM.ps1') -Raw
T 'VM script registers PIM-Manager + PIM-Scheduler scheduled tasks'          { ($vm -match "TaskName 'PIM-Manager'") -and ($vm -match "TaskName 'PIM-Scheduler'") }
T 'VM script grants the VM-MI via the shared Grant-PimMiSql'                 { $vm -match 'Grant-PimMiSql' }

$install = Get-Content (Join-Path $setpDir 'Install-PimEngineAppRegistration.ps1') -Raw
T 'engine app-reg installer is REST/cert (no Microsoft.Graph #Requires)'     { $install -notmatch '#Requires -Modules .*Microsoft\.Graph' }
T 'engine app-reg installer self-signs into LocalMachine\My by default'      { ($install -match 'New-SelfSignedCertificate') -and ($install -match 'LocalMachine\\My') }
T 'engine app-reg installer requests Exchange.ManageAsApp'                    { $install -match 'Exchange\.ManageAsApp' }
T 'engine app-reg installer assigns Azure UAA (skippable)'                    { ($install -match 'User Access Administrator') -and ($install -match 'SkipAzureRbac') }
T 'engine app-reg installer has -GrantConsent'                               { $install -match '\$GrantConsent' }
T 'engine app-reg installer writes LauncherConfig globals'                    { ($install -match 'HighPriv_Modern_ApplicationID_Azure') -and ($install -match 'LauncherConfig\.custom\.ps1') }

Section 'PUBLIC-SAFETY -- no real tenant/subscription/customer values in published deploy scripts'
# Known real values that must NOT be baked into the public-facing setup scripts.
$forbidden = @(
    'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e',   # internal tenant id
    '54468121-98ba-48ba-ba59-ba10a9711ed3',   # internal subscription id
    '2linkit.local',                          # internal AD domain
    'sql-pimplatform-we484',                  # real SQL server name
    'acrsecurityinsight',                     # real ACR name
    'rg-platform-connectivity'                # real RG name
)
foreach ($s in $scripts) {
    T "no baked-in real env values: $s" {
        $c = Get-Content (Join-Path $setpDir $s) -Raw
        $hit = $forbidden | Where-Object { $c -match [regex]::Escape($_) }
        -not $hit
    }
}
T 'no France region VALUE (francecentral/francesouth) used as a default in any setup script' {
    # The word "France" may appear in a comment ("never France"); what must never
    # appear is an actual France region value used as a parameter default / az arg.
    $bad = $false
    foreach ($s in $scripts) {
        if ($s -eq '_PimSetupShared.ps1') { continue }   # the guard's deny-list legitimately names the values
        if ((Get-Content (Join-Path $setpDir $s) -Raw) -match 'francecentral|francesouth') { $bad = $true }
    }
    -not $bad
}

Write-Host ""
Write-Host ("SETUP/HOSTING TESTS: {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) {'Red'} else {'Green'})
if ($script:fail) { exit 1 }
