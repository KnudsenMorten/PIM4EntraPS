#Requires -Version 5.1

<#
.SYNOPSIS
  Gives the Invardia Support app its standing access to the database of an existing PIM Manager installation: membership of the SQL admin group, and its own database user (created from the application's client id) in the database owner role. Run once per installation; -WhatIf shows it first.

.DESCRIPTION
  PIM REQUIREMENTS 100.116 (framework 4.1b). A new installation does this by itself when a Support app is named. This
  script brings an EXISTING installation to the same state. It changes nothing else, and it leaves the SQL server's
  administrator and its firewall exactly as it found them.

  What it does, in order:
    1. Reads and keeps the SQL server's Microsoft Entra administrator and its Entra-only setting, and reads the
       setup firewall rule 'AllowSetupHost'. Prints them ("before").
    2. Adds the Invardia Support app to the SQL admin group (grp-pim-sql-admins). A refusal -- the group is
       role-assignable, so this needs a Privileged Role Administrator -- is a WARNING with the next step, not a stop.
    3. Opens the firewall rule 'AllowSetupHost' for this machine's public address, when it is not there. A rule that
       is already there for another address stops the run (another setup may be using it); nothing is changed.
    4. Signs in to the database as you. When the database refuses AND this window is the Invardia Support app's
       session, the Support app is made the server's administrator FOR THIS STEP, and the script waits until a
       database sign-in answers.
    5. Creates the database user from the Support app's client id when no user has that id (an existing user of the
       Support app is reused whatever its name) and adds it to db_owner. Reads it back.
    6. ALWAYS, also after a failed step: puts the server's administrator back exactly as read and reads it back;
       removes the firewall rule it opened and reads that back.
    7. Proof: in a Support session, a new database sign-in as the Support app. Otherwise it says "not checked" and
       why; the evidence is then the user and its role, read back.
  Prints "before" and "after", and what it restored.

  Why db_owner: PIM Manager's own setup scripts create database users for the product's identities and add them to
  fixed database roles, apply the schema and write settings. Adding a member to a fixed database role needs db_owner;
  no smaller fixed role covers it.

  Sign-in: the Invardia Support app's session open in this window, otherwise your own browser sign-in. No Azure CLI,
  no PowerShell module, no secret on the command line. Every token is pinned to -TenantId.

  Exit codes: 0 done (warnings allowed); 1 not done (the reason and the next step are printed); 2 the server's
  administrator could NOT be put back -- the exact values to set by hand are printed.

.EXAMPLE
  .\Grant-PimSupportSqlAccess.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -ResourceGroup rg-pim -SqlServerName sql-pim-contoso -SupportAppId <Invardia Support app client id> -WhatIf
  Preview: reads everything and prints what it would do. Then the same command without -WhatIf.

.LINK
  https://invardia.com/docs/pim/scripts/Grant-PimSupportSqlAccess/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$TenantId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$SubscriptionId,
    # the resource group of the SQL server
    [Parameter(Mandatory)][string]$ResourceGroup,
    # the SQL server name or its FQDN (sql-x or sql-x.database.windows.net)
    [Parameter(Mandatory)][string]$SqlServerName,
    [string]$SqlDatabase = 'PimPlatform',
    # the Invardia Support app's application (client) id. In the Support app's own session it may be left out.
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$SupportAppId = '',
    [string]$DbUserName = 'invardia-support',
    [string]$SqlAdminGroupName = 'grp-pim-sql-admins',
    # this machine's public address for the firewall rule; without it the address is read from api.ipify.org
    [ValidatePattern('^$|^\d{1,3}(\.\d{1,3}){3}$')][string]$SetupHostIp = '',
    [ValidateRange(20, 1800)][int]$SignInWaitSeconds = 300,
    # --- test seams (tests/Test-PimSupportSqlAccess.ps1); omit them for a real run ---
    [scriptblock]$Arm,
    [scriptblock]$Graph,
    [scriptblock]$Sql,
    [scriptblock]$Sleep
)
$ErrorActionPreference = 'Stop'
# Published as ONE standalone file (https://invardia.com/support/pim/Grant-PimSupportSqlAccess.ps1): every helper is
# dot-sourced by a literal path relative to this script's folder, so Build-PimSupportScripts.ps1 inlines it. The next line
# tells the build to leave out the OPTIONAL loads the engine libraries end with and to fail on any load left.
# BUILD-NO-OPTIONAL-LOADS
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Rest.ps1')       # the ONE token client (framework 12.17)
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-SqlStore.ps1')   # Resolve-PimSqlClientType (.NET SqlClient, no module)
. (Join-Path $PSScriptRoot '_PimSignedIn.ps1')                        # the sign-in rule: the Support session, else the browser
. (Join-Path $PSScriptRoot '_PimSupportSqlAccess.ps1')
$null = Start-PimScriptRun -Script 'Grant-PimSupportSqlAccess'
$script:gssRc = 1
try {
$srv = ("$SqlServerName".Trim() -replace '^tcp:', '' -replace ',\d+$', '').Split('.')[0].ToLowerInvariant()
if ($srv -notmatch '^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$') { throw "Grant-PimSupportSqlAccess: not a SQL server name: $SqlServerName" }
if ($SqlDatabase -notmatch '^[^<>*%&:\\/?\[\]'';]{1,128}$') { throw "Grant-PimSupportSqlAccess: not a database name: $SqlDatabase" }
$tid = "$TenantId".Trim().ToLowerInvariant(); $sub = "$SubscriptionId".Trim().ToLowerInvariant()

Write-Host ('=' * 78) -ForegroundColor Cyan
Write-Host " PIM MANAGER -- INVARDIA SUPPORT: STANDING DATABASE ACCESS  ($srv / $SqlDatabase)$(if ($WhatIfPreference) { '   PREVIEW' })" -ForegroundColor Cyan
Write-Host ('=' * 78) -ForegroundColor Cyan

# ---- sign-in: the Support app's session in this window, else the person's browser (asserted: this tenant, this subscription)
$sessionApp = ''
if (-not ($Arm -and $Graph)) {
    $who = Get-PimSignedInIdentity -TenantId $tid -SubscriptionId $sub
    if (-not $who.ok) { throw "Grant-PimSupportSqlAccess: REFUSED (nothing was touched) -- $($who.reason)" }
    $sessionApp = "$($who.supportAppId)".Trim().ToLowerInvariant()
    Write-Host "  $($who.reason)" -ForegroundColor DarkGray
}
$app = "$SupportAppId".Trim().ToLowerInvariant()
if (-not $app) { $app = $sessionApp }
if (-not $app) { throw 'Grant-PimSupportSqlAccess: pass -SupportAppId <the Invardia Support app''s client id> (it is only known by itself in the Support app''s own session). Nothing was touched.' }
if ($sessionApp -and $sessionApp -ne $app) { throw "Grant-PimSupportSqlAccess: this window is the session of the Support app $sessionApp, but -SupportAppId names $app -- REFUSED (the right would go to another application). Nothing was touched." }
$isSupportSession = [bool]($sessionApp -and $sessionApp -eq $app)
Write-Host "  Invardia Support app: $app$(if ($isSupportSession) { ' (this window is its session)' })" -ForegroundColor DarkGray

# ---- the callers (REST / .NET only) ---------------------------------------------------------------------------------
# PLAIN scriptblocks over script-level functions, never a bound closure: a closure runs in its own module scope and
# cannot see the functions this script loaded (the token client, the SQL client type).
$script:gssTenant = $tid
$script:gssConn = "Server=tcp:$srv.database.windows.net,1433;Database=$SqlDatabase;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;Pooling=False"
function Invoke-GssRest {
    param([string]$Base, [string]$Resource, [string]$Method = 'GET', [string]$Path, $Body)
    $WhatIfPreference = $false   # the reads of a preview are real; every write is gated before it gets here
    $tok = "$(Get-PimRestToken -Resource $Resource -TenantId $script:gssTenant)".Trim()
    if (-not $tok) { throw "no token for $Resource in tenant $($script:gssTenant)" }
    $a = @{ Method = $Method; Uri = $(if ($Path -match '^https://') { $Path } else { "$Base$Path" }); Headers = @{ Authorization = "Bearer $tok" } }
    if ($null -ne $Body) { $a['Body'] = ($Body | ConvertTo-Json -Depth 8 -Compress); $a['ContentType'] = 'application/json' }
    try { return (Invoke-RestMethod @a) }
    catch {
        $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { $code = 0 }
        throw "$Method $Path -> HTTP $code : $((("$($_.ErrorDetails.Message) $($_.Exception.Message)") -replace '\s+', ' ').Trim())"
    }
}
function Invoke-GssSqlScalar {
    param([string]$Query)
    # a NEW token and a NEW connection each call: a right given a moment ago is not in an older token
    $tok = "$(Get-PimRestToken -Resource 'https://database.windows.net' -TenantId $script:gssTenant -Force)".Trim()
    if (-not $tok) { throw "no database token in tenant $($script:gssTenant)" }
    $c = New-Object (Resolve-PimSqlClientType).FullName $script:gssConn
    $c.AccessToken = $tok; $c.Open()
    try { $cmd = $c.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 60; return $cmd.ExecuteScalar() } finally { $c.Close() }
}
if (-not $Arm) { $Arm = { param([string]$Method = 'GET', [string]$Path, $Body) Invoke-GssRest -Base 'https://management.azure.com' -Resource 'https://management.azure.com' -Method $Method -Path $Path -Body $Body } }
if (-not $Graph) { $Graph = { param([string]$Method = 'GET', [string]$Path, $Body) Invoke-GssRest -Base 'https://graph.microsoft.com/v1.0' -Resource 'https://graph.microsoft.com' -Method $Method -Path $Path -Body $Body } }
if (-not $Sql) { $Sql = { param([string]$Query) Invoke-GssSqlScalar -Query $Query } }

$whatIfOnly = -not $PSCmdlet.ShouldProcess("SQL server $srv, database $SqlDatabase", "give the Invardia Support app $app its standing database access (database user in db_owner, member of '$SqlAdminGroupName')")
$ip = "$SetupHostIp".Trim()
if (-not $ip -and -not $whatIfOnly) {
    try { $ip = "$(Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 20)".Trim(); Write-Host "  this machine's public address (read from api.ipify.org): $ip" -ForegroundColor DarkGray }
    catch { $ip = '' }
}
$ga = @{ Arm = $Arm; Graph = $Graph; Sql = $Sql; TenantId = $tid; SubscriptionId = $sub; ResourceGroup = $ResourceGroup; SqlServerName = $srv; SqlDatabase = $SqlDatabase
         SupportAppId = $app; SessionIsSupportApp = $isSupportSession; DbUserName = $DbUserName; SqlAdminGroupName = $SqlAdminGroupName; HostIp = $ip
         SignInWaitSeconds = $SignInWaitSeconds; WhatIfOnly = $whatIfOnly }
if ($Sleep) { $ga['Sleep'] = $Sleep }
$r = Invoke-PimSupportSqlAccessGrant @ga

foreach ($w in @($r.warnings)) { Write-Host "  WARNING: $w" -ForegroundColor Yellow }
foreach ($p in @($r.problems)) { Write-Host "  NOT DONE: $p" -ForegroundColor Red }
Write-Host ''
if ($r.whatIf) { Write-Host "RESULT: preview only -- nothing was changed$(if (@($r.problems).Count) { ' (see NOT DONE above)' })." -ForegroundColor DarkYellow }
elseif ($r.exit -eq 2) { Write-Host 'RESULT: THE ADMINISTRATOR WAS NOT PUT BACK -- set it by hand now (the values are above).' -ForegroundColor Red }
elseif ($r.exit -ne 0) { Write-Host "RESULT: NOT DONE$(if ($r.swapped) { ' -- the administrator is back exactly as read' })." -ForegroundColor Red }
else {
    $proof = if ("$($r.proof.state)" -eq 'proven') { 'proven by a database sign-in as the Support app' } else { "the user and its role were read back; a sign-in as the Support app was not checked ($($r.proof.detail))" }
    Write-Host "RESULT: done$(if (@($r.warnings).Count) { " with $(@($r.warnings).Count) warning(s)" }) -- database user [$($r.user.userName)] in db_owner; $proof.$(if ($r.swapped) { ' The administrator is back exactly as read.' })" -ForegroundColor Green
    Write-Host '  The customer ends this access by switching the Invardia Support app off in Microsoft Entra ID (or Grant-PimSupportAccess.ps1 -Remove).' -ForegroundColor DarkGray
}
$script:gssRc = [int]$r.exit
if ($r.whatIf -and -not @($r.problems).Count) { $script:gssRc = 0 }
} finally { Stop-PimScriptRun -Script 'Grant-PimSupportSqlAccess' }
exit $script:gssRc
