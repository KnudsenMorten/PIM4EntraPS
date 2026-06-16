#Requires -Version 5.1
<#
.SYNOPSIS
    Offline, rerunnable tests for the REST migration of the EXO runtime path + the
    legacy SDK setup scripts (REQUIREMENTS.md §19). No live tenant, no modules.

.DESCRIPTION
    Covers:
      * PIM-Rest EXO data plane: the 'exo' audience is registered; Invoke-PimExoCmdlet
        builds the correct InvokeCommand body + URL; Set-PimMailboxForwarding maps
        Set-Mailbox params (incl. clear-forwarding -> null); org segment resolution.
      * Setup-script reconciliation: setup/Install-PimEngineAppRegistration.ps1 and
        setup/Grant-PimEngineAdminConsent.ps1 are now thin REST redirects (no
        Microsoft.Graph #Requires, no Connect-MgGraph, no -UseDeviceCode).
      * Invoke-PimMspFanout.ps1 + Invoke-PimLocalApply.ps1 authenticate, read AND
        WRITE over pure REST (PIM-Rest + PIM-AccountRest) -- no Connect-MgGraph /
        Get-MgDomain; the legacy Graph-SDK engine call is opt-in (PIM_UseGraphSdk).
      * PIM-AccountRest writer (New-PimRestAdminAccount / Invoke-PimRestAccountApply):
        create (POST /users + passwordPolicies PATCH), update, WhatIf, manager link,
        companyName, AD-row skip, password generator -- mocked Invoke-PimGraph.
      * New-PimBaselineBundle.ps1 drops Az.Storage / Az.Accounts (Send-PimRestBlob +
        Get-PimRestToken). Migrate-PimToSql.ps1 confirmed REST-clean (SQL plane only).
      * Every touched script parses under the PS 5.1 AST.
      * No device-code anywhere in setup/.

.EXAMPLE
    powershell -NoProfile -File tests\Test-PimRestExoSetup.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:pass = 0; $script:fail = 0
function T { param($n,[scriptblock]$b)
    try { $r = & $b; if ($r) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }
    catch { Write-Host "  FAIL $n -- $($_.Exception.Message.Split([char]10)[0])" -ForegroundColor Red; $script:fail++ } }
function Section($t){ Write-Host "`n== $t ==" -ForegroundColor Cyan }

$root      = Split-Path -Parent $PSScriptRoot          # ...\PIM4EntraPS
$sharedDir = Join-Path $root 'engine\_shared'
$setupDir  = Join-Path $root 'setup'

. (Join-Path $sharedDir 'PIM-Rest.ps1')

# ---------------------------------------------------------------------------
Section 'PIM-Rest -- EXO audience + helpers present'
T 'exo resource resolves to outlook.office365.com' {
    (Resolve-PimRestResource -Resource 'exo') -eq 'https://outlook.office365.com'
}
T 'Invoke-PimExoCmdlet is defined'      { [bool](Get-Command Invoke-PimExoCmdlet -ErrorAction SilentlyContinue) }
T 'Set-PimMailboxForwarding is defined' { [bool](Get-Command Set-PimMailboxForwarding -ErrorAction SilentlyContinue) }

# ---------------------------------------------------------------------------
Section 'PIM-Rest -- EXO InvokeCommand body shape (mock Invoke-PimRest)'

# Capture what Invoke-PimExoCmdlet would POST by shadowing Invoke-PimRest.
$script:exoCapture = $null
function Invoke-PimRest {
    param([string]$Method='GET',[string]$Url,[object]$Body,[string]$Resource='graph',[hashtable]$Headers=@{},[switch]$All,[int]$MaxRetry=5)
    $script:exoCapture = [pscustomobject]@{ Method=$Method; Url=$Url; Body=$Body; Resource=$Resource }
    # mimic an EXO InvokeCommand response envelope
    return [pscustomobject]@{ value = @([pscustomobject]@{ ok = $true }) }
}

T 'Invoke-PimExoCmdlet POSTs to the InvokeCommand endpoint with tenant segment' {
    $script:exoCapture = $null
    Invoke-PimExoCmdlet -CmdletName 'Get-Mailbox' -Parameters @{ Identity='u@x.com' } -Organization 'contoso.onmicrosoft.com' | Out-Null
    ($script:exoCapture.Method -eq 'POST') -and
    ($script:exoCapture.Resource -eq 'exo') -and
    ($script:exoCapture.Url -eq 'https://outlook.office365.com/adminapi/beta/contoso.onmicrosoft.com/InvokeCommand')
}
T 'Invoke-PimExoCmdlet wraps CmdletInput { CmdletName; Parameters }' {
    $script:exoCapture = $null
    Invoke-PimExoCmdlet -CmdletName 'Set-Mailbox' -Parameters @{ Identity='u@x.com'; DeliverToMailboxAndForward=$false } -Organization 'c.onmicrosoft.com' | Out-Null
    $ci = $script:exoCapture.Body.CmdletInput
    ($ci.CmdletName -eq 'Set-Mailbox') -and ($ci.Parameters.Identity -eq 'u@x.com') -and ($ci.Parameters.DeliverToMailboxAndForward -eq $false)
}
T 'Invoke-PimExoCmdlet returns the .value payload (unwrapped)' {
    $r = Invoke-PimExoCmdlet -CmdletName 'Get-Mailbox' -Parameters @{} -Organization 'c.onmicrosoft.com'
    @($r)[0].ok -eq $true
}

Section 'PIM-Rest -- Set-PimMailboxForwarding param mapping'
T 'sets ForwardingSmtpAddress + DeliverToMailboxAndForward=false' {
    $script:exoCapture = $null
    Set-PimMailboxForwarding -Identity 'admin@x.com' -ForwardingSmtpAddress 'real@x.com' -Organization 'c.onmicrosoft.com'
    $p = $script:exoCapture.Body.CmdletInput.Parameters
    ($script:exoCapture.Body.CmdletInput.CmdletName -eq 'Set-Mailbox') -and
    ($p.Identity -eq 'admin@x.com') -and ($p.ForwardingSmtpAddress -eq 'real@x.com') -and ($p.DeliverToMailboxAndForward -eq $false)
}
T 'empty forwarding address CLEARS (maps to $null, not empty string)' {
    $script:exoCapture = $null
    Set-PimMailboxForwarding -Identity 'admin@x.com' -ForwardingSmtpAddress '' -Organization 'c.onmicrosoft.com'
    $p = $script:exoCapture.Body.CmdletInput.Parameters
    ($p.ContainsKey('ForwardingSmtpAddress')) -and ($null -eq $p.ForwardingSmtpAddress)
}
T 'organization segment falls back to $global:PIM_ExoOrganization' {
    $script:exoCapture = $null
    $global:PIM_ExoOrganization = 'fallback.onmicrosoft.com'
    try { Invoke-PimExoCmdlet -CmdletName 'Get-Mailbox' -Parameters @{} | Out-Null }
    finally { $global:PIM_ExoOrganization = $null }
    $script:exoCapture.Url -eq 'https://outlook.office365.com/adminapi/beta/fallback.onmicrosoft.com/InvokeCommand'
}

# restore the real Invoke-PimRest for any later use
Remove-Item Function:\Invoke-PimRest -ErrorAction SilentlyContinue
. (Join-Path $sharedDir 'PIM-Rest.ps1')

# ---------------------------------------------------------------------------
# Helper: strip comments + here-string doc blocks so we test EXECUTABLE code,
# not explanatory prose (a redirect shim legitimately NAMES the retired
# mechanisms in its docstring). Tokenize with the AST and drop Comment tokens.
function Get-PimCodeOnly {
    param([string]$Path)
    $tk=$null; $er=$null
    [System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tk,[ref]$er) | Out-Null
    ($tk | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' '
}

Section 'SETUP SCRIPTS -- legacy SDK duplicates are now REST redirects'
$instTxt   = Get-Content (Join-Path $setupDir 'Install-PimEngineAppRegistration.ps1') -Raw
$grantTxt  = Get-Content (Join-Path $setupDir 'Grant-PimEngineAdminConsent.ps1') -Raw
$instCode  = Get-PimCodeOnly (Join-Path $setupDir 'Install-PimEngineAppRegistration.ps1')
$grantCode = Get-PimCodeOnly (Join-Path $setupDir 'Grant-PimEngineAdminConsent.ps1')

T 'Install redirect: NO Microsoft.Graph #Requires'  { $instTxt -notmatch '(?im)^#Requires -Modules.*Microsoft\.Graph' }
T 'Install redirect: NO Mg* cmdlet CALLS in code'   { ($instCode -notmatch 'Connect-MgGraph') -and ($instCode -notmatch 'New-MgApplication') -and ($instCode -notmatch 'Get-MgServicePrincipal') }
T 'Install redirect: points at tools\setup REST installer' { $instTxt -match 'tools\\setup\\Install-PimEngineAppRegistration\.ps1' }

T 'Grant redirect: NO Microsoft.Graph #Requires'    { $grantTxt -notmatch '(?im)^#Requires -Modules.*Microsoft\.Graph' }
T 'Grant redirect: NO device-code FLAG in code'     { $grantCode -notmatch '-UseDeviceCode' }
T 'Grant redirect: NO Connect-MgGraph CALL in code' { $grantCode -notmatch 'Connect-MgGraph' }
T 'Grant redirect: points at Grant-PimGraphAppRoles.ps1' { $grantTxt -match 'Grant-PimGraphAppRoles\.ps1' }

# ---------------------------------------------------------------------------
Section 'MSP FAN-OUT -- pure-REST auth + reads'
$fanTxt  = Get-Content (Join-Path $setupDir 'Invoke-PimMspFanout.ps1') -Raw
$fanCode = Get-PimCodeOnly (Join-Path $setupDir 'Invoke-PimMspFanout.ps1')
T 'fanout dot-sources PIM-Rest'                     { $fanTxt -match 'PIM-Rest\.ps1' }
T 'fanout auth uses Get-PimRestToken (no Connect-MgGraph CALL)' { ($fanCode -match 'Get-PimRestToken') -and ($fanCode -notmatch 'Connect-MgGraph') }
T 'fanout default-domain via REST (Get-PimRestDefaultDomain/Invoke-PimGraph; no Get-MgDomain CALL)' { (($fanCode -match 'Get-PimRestDefaultDomain') -or ($fanCode -match 'Invoke-PimGraph')) -and ($fanCode -notmatch 'Get-MgDomain') }
T 'fanout has NO Get-MgContext CALL' { $fanCode -notmatch 'Get-MgContext' }
T 'fanout LIVE write defaults to the REST writer (Invoke-PimRestAccountApply)' { $fanCode -match 'Invoke-PimRestAccountApply' }
T 'fanout dot-sources PIM-AccountRest' { $fanTxt -match 'PIM-AccountRest\.ps1' }
T 'fanout legacy engine call is now opt-in (guarded by PIM_UseGraphSdk)' {
    # the CreateUpdate-Accounts-From-file-CSV call must sit under an if ($global:PIM_UseGraphSdk) branch
    $fanCode -match 'PIM_UseGraphSdk' -and $fanCode -match 'CreateUpdate-Accounts-From-file-CSV'
}

# ---------------------------------------------------------------------------
Section 'LOCAL APPLY -- pure-REST auth + write'
$laTxt  = Get-Content (Join-Path $setupDir 'Invoke-PimLocalApply.ps1') -Raw
$laCode = Get-PimCodeOnly (Join-Path $setupDir 'Invoke-PimLocalApply.ps1')
T 'local-apply dot-sources PIM-Rest + PIM-AccountRest' { ($laTxt -match 'PIM-Rest\.ps1') -and ($laTxt -match 'PIM-AccountRest\.ps1') }
T 'local-apply auth via Get-PimRestToken (no Connect-MgGraph CALL)' { ($laCode -match 'Get-PimRestToken') -and ($laCode -notmatch 'Connect-MgGraph') }
T 'local-apply default-domain via Get-PimRestDefaultDomain (no Get-MgDomain CALL)' { ($laCode -match 'Get-PimRestDefaultDomain') -and ($laCode -notmatch 'Get-MgDomain') }
T 'local-apply LIVE write defaults to the REST writer' { $laCode -match 'Invoke-PimRestAccountApply' }
T 'local-apply legacy engine call is opt-in (PIM_UseGraphSdk)' { $laCode -match 'PIM_UseGraphSdk' }

# ---------------------------------------------------------------------------
Section 'BASELINE BUNDLE -- Az.Storage / Az.Accounts dropped (REST blob + token)'
$bbTxt  = Get-Content (Join-Path $setupDir 'New-PimBaselineBundle.ps1') -Raw
$bbCode = Get-PimCodeOnly (Join-Path $setupDir 'New-PimBaselineBundle.ps1')
T 'baseline bundle NO Import-Module Az.Storage'           { $bbCode -notmatch 'Import-Module\s+Az\.Storage' }
T 'baseline bundle NO New-AzStorageContext / Set-AzStorageBlobContent' { ($bbCode -notmatch 'New-AzStorageContext') -and ($bbCode -notmatch 'Set-AzStorageBlobContent') }
T 'baseline bundle NO Get-AzAccessToken CALL'             { $bbCode -notmatch 'Get-AzAccessToken' }
T 'baseline bundle uploads via Send-PimRestBlob'          { $bbCode -match 'Send-PimRestBlob' }
T 'baseline bundle mints SQL token via Get-PimRestToken'  { $bbCode -match 'Get-PimRestToken' }

# ---------------------------------------------------------------------------
Section 'MIGRATE-TO-SQL -- confirmed REST-clean (SQL data plane only)'
$mtCode = Get-PimCodeOnly (Join-Path $setupDir 'Migrate-PimToSql.ps1')
T 'migrate has NO Microsoft.Graph cmdlet CALLS' { ($mtCode -notmatch 'Connect-MgGraph') -and ($mtCode -notmatch 'New-MgUser') -and ($mtCode -notmatch 'Update-MgUser') }
T 'migrate has NO Az.Storage / Connect-AzAccount CALLS'  { ($mtCode -notmatch 'New-AzStorageContext') -and ($mtCode -notmatch 'Connect-AzAccount') }

# ---------------------------------------------------------------------------
Section 'PIM-AccountRest -- ID create/update over REST (mock Invoke-PimGraph)'
. (Join-Path $sharedDir 'PIM-AccountRest.ps1')
T 'New-PimRestAdminAccount is defined'  { [bool](Get-Command New-PimRestAdminAccount -ErrorAction SilentlyContinue) }
T 'Invoke-PimRestAccountApply is defined'{ [bool](Get-Command Invoke-PimRestAccountApply -ErrorAction SilentlyContinue) }
T 'Get-PimRestDefaultDomain is defined' { [bool](Get-Command Get-PimRestDefaultDomain -ErrorAction SilentlyContinue) }
T 'Send-PimRestBlob is defined'         { [bool](Get-Command Send-PimRestBlob -ErrorAction SilentlyContinue) }

# Mock the Graph data plane so the writer can be exercised offline.
$script:graphCalls = @()
function Invoke-PimGraph {
    param([string]$Method='GET',[string]$Path,[object]$Body,[switch]$All,[switch]$Beta,[hashtable]$Headers=@{})
    $script:graphCalls += [pscustomobject]@{ Method=$Method; Path=$Path; Body=$Body }
    # GET /users/<upn>?... -> existence probe. Default: 404 (create). For a UPN
    # containing 'exists' return an object so the update branch is exercised.
    if ($Method -eq 'GET' -and $Path -match '^/users/') {
        if ($Path -match 'exists') { return [pscustomobject]@{ id='00000000-0000-0000-0000-000000000001'; userPrincipalName='x' } }
        throw "GET $Path -> HTTP 404 : Request_ResourceNotFound"
    }
    if ($Method -eq 'POST' -and $Path -eq '/users') { return [pscustomobject]@{ id='11111111-1111-1111-1111-111111111111' } }
    return $null
}

T 'CREATE: new user POSTs /users then PATCHes passwordPolicies; returns created+password' {
    $script:graphCalls = @()
    $row = [pscustomobject]@{ TargetPlatform='ID'; UserName='newadm'; FirstName='New'; LastName='Adm'; DisplayName='New Adm'; UserPrincipalName='newadm@contoso.com'; UsageLocation='DK' }
    $r = New-PimRestAdminAccount -Row $row
    $post  = @($script:graphCalls | Where-Object { $_.Method -eq 'POST' -and $_.Path -eq '/users' })
    $patch = @($script:graphCalls | Where-Object { $_.Method -eq 'PATCH' -and $_.Path -match '^/users/' })
    ($r.Action -eq 'created') -and ($r.Password) -and ($post.Count -eq 1) -and ($patch.Count -ge 1) -and
    ($post[0].Body.userPrincipalName -eq 'newadm@contoso.com') -and ($post[0].Body.accountEnabled -eq $true) -and ($post[0].Body.passwordProfile.password)
}
T 'CREATE: company name flows to companyName on the create body' {
    $script:graphCalls = @()
    $row = [pscustomobject]@{ TargetPlatform='ID'; UserName='c'; UserPrincipalName='c@contoso.com'; Company='ACME' }
    New-PimRestAdminAccount -Row $row | Out-Null
    (@($script:graphCalls | Where-Object { $_.Method -eq 'POST' })[0]).Body.companyName -eq 'ACME'
}
T 'UPDATE: existing user PATCHes (no POST /users); returns updated, no password' {
    $script:graphCalls = @()
    $row = [pscustomobject]@{ TargetPlatform='ID'; UserName='e'; DisplayName='E'; UserPrincipalName='exists@contoso.com'; UsageLocation='DK' }
    $r = New-PimRestAdminAccount -Row $row
    $post  = @($script:graphCalls | Where-Object { $_.Method -eq 'POST' -and $_.Path -eq '/users' })
    $patch = @($script:graphCalls | Where-Object { $_.Method -eq 'PATCH' })
    ($r.Action -eq 'updated') -and (-not $r.Password) -and ($post.Count -eq 0) -and ($patch.Count -eq 1) -and
    ($patch[0].Body.displayName -eq 'E') -and ($patch[0].Body.passwordPolicies -eq 'DisablePasswordExpiration')
}
T 'WhatIf: no POST/PATCH at all; returns whatif' {
    $script:graphCalls = @()
    $row = [pscustomobject]@{ TargetPlatform='ID'; UserName='w'; UserPrincipalName='wnew@contoso.com' }
    $r = New-PimRestAdminAccount -Row $row -WhatIf
    $writes = @($script:graphCalls | Where-Object { $_.Method -in 'POST','PATCH','PUT' })
    ($r.Action -eq 'whatif') -and ($writes.Count -eq 0)
}
T 'MANAGER: ManagerEmail resolves + PUT /manager/$ref' {
    $script:graphCalls = @()
    $row = [pscustomobject]@{ TargetPlatform='ID'; UserName='m'; UserPrincipalName='mnew@contoso.com'; ManagerEmail='exists.boss@contoso.com' }
    New-PimRestAdminAccount -Row $row | Out-Null
    @($script:graphCalls | Where-Object { $_.Method -eq 'PUT' -and $_.Path -match '/manager/\$ref' }).Count -eq 1
}
T 'Invoke-PimRestAccountApply SKIPS non-ID rows (AD/hybrid out of REST scope)' {
    $script:graphCalls = @()
    $rows = @(
        [pscustomobject]@{ TargetPlatform='AD'; UserName='adusr'; UserPrincipalName='adusr@contoso.com' },
        [pscustomobject]@{ TargetPlatform='ID'; UserName='idusr'; UserPrincipalName='idusr@contoso.com' }
    )
    $res = @(Invoke-PimRestAccountApply -Rows $rows)
    # only the ID row should have produced Graph writes; result count = ID rows handled
    ($res.Count -eq 1) -and ($res[0].Upn -eq 'idusr@contoso.com') -and (@($script:graphCalls | Where-Object { $_.Method -eq 'POST' }).Count -eq 1)
}
T 'New-PimRestPassword: length + at least one of each class' {
    $pw = New-PimRestPassword -Length 24
    ($pw.Length -eq 24) -and ($pw -cmatch '[A-Z]') -and ($pw -cmatch '[a-z]') -and ($pw -match '[0-9]') -and ($pw -match '[!@#\$%\^&\*\-_=\+\?]')
}

# restore the real Invoke-PimGraph
Remove-Item Function:\Invoke-PimGraph -ErrorAction SilentlyContinue
. (Join-Path $sharedDir 'PIM-Rest.ps1')

# ---------------------------------------------------------------------------
Section 'NO device-code FLAG anywhere in setup/ (executable code)'
$allSetup = Get-ChildItem (Join-Path $setupDir '*.ps1') -File
foreach ($f in $allSetup) {
    T "no -UseDeviceCode flag in $($f.Name)" { (Get-PimCodeOnly $f.FullName) -notmatch '-UseDeviceCode' }
}

# ---------------------------------------------------------------------------
Section 'PARSE (PS 5.1 AST) -- touched scripts'
$touched = @(
    (Join-Path $sharedDir 'PIM-Rest.ps1'),
    (Join-Path $sharedDir 'PIM-AccountRest.ps1'),
    (Join-Path $sharedDir 'PIM-Functions.psm1'),
    (Join-Path $setupDir 'Install-PimEngineAppRegistration.ps1'),
    (Join-Path $setupDir 'Grant-PimEngineAdminConsent.ps1'),
    (Join-Path $setupDir 'Invoke-PimMspFanout.ps1'),
    (Join-Path $setupDir 'Invoke-PimLocalApply.ps1'),
    (Join-Path $setupDir 'New-PimBaselineBundle.ps1'),
    (Join-Path $setupDir 'Migrate-PimToSql.ps1')
)
foreach ($p in $touched) {
    T "parses: $(Split-Path -Leaf $p)" {
        $tk=$null; $er=$null
        [System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$tk,[ref]$er) | Out-Null
        @($er).Count -eq 0
    }
}

# ---------------------------------------------------------------------------
Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) {'Red'} else {'Green'})
if ($script:fail) { exit 1 }
