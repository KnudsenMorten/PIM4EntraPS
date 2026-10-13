#Requires -Version 5.1

<#
.SYNOPSIS
  Gives the Invardia Support app its database user on a PIM Manager installation whose database is private (public network access off), from inside: a one-time job in the installation's own environment creates the user from the application's client id and adds it to the database owner role, the result is read back, and the job is removed. Nothing is opened; -WhatIf shows it first.

.DESCRIPTION
  PIM REQUIREMENTS 100.116 (framework 4.1b). On an installation with a public database, Grant-PimSupportSqlAccess.ps1
  does this from the machine it runs on. A PRIVATE database has no route from outside, and none is made for this: no
  firewall rule, no public access, no jump host. The grant runs inside the installation's own network instead, and
  you -- the customer -- start it.

  What it does, in order:
    1. Reads the installation's own database setup job (ca-pim-dbinit): its environment, its image, the SQL server and
       database it names, and the user-assigned identity it signs in to the database with. That identity is the SQL
       server's administrator (or a member of the SQL admin group); it is used as it is. No role, no group membership
       and no permission is given to any identity. When the installation has no such job or identity, the script
       STOPS, changes nothing, and prints the options.
    2. Reads whether a job of the one-time name is already there (a leftover of a killed run of this script is removed
       first; any other job of that name is not touched and stops the run), and that the Invardia Support app exists
       in this tenant.
    3. Creates the one-time job (caj-pim-supportsql) in the same environment, with that identity and a tag that says
       what it is.
    4. Starts it once. In the database, the job creates the user from the Support app's client id when no user has
       that id (an existing user of the Support app is reused whatever its name) and adds it to db_owner, then reads
       both back. When the user is already there with the role, the job sends one read and changes nothing.
    5. Waits for the execution, reads its result and its log lines, and prints PASS or FAIL with them.
    6. ALWAYS, also after a failed step: removes the one-time job and reads back that it is gone.

  The statement the job runs is the one Grant-PimSupportSqlAccess.ps1 runs: the job's script is built from the same
  functions. The membership of the SQL admin group is not part of this script (it is given from outside the network).

  Why db_owner: PIM Manager's own setup scripts create database users for the product's identities and add them to
  fixed database roles, apply the schema and write settings. Adding a member to a fixed database role needs db_owner;
  no smaller fixed role covers it.

  Sign-in: your own browser sign-in (or the Invardia Support app's session open in this window). No Azure CLI, no
  PowerShell module, no secret on the command line. Every token is pinned to -TenantId.

  Exit codes: 0 PASS (or a preview with nothing in the way); 1 FAIL -- the reason and the next step are printed.

.EXAMPLE
  .\Invoke-PimSupportSqlAccessJob.ps1 -TenantId <tenant id> -SubscriptionId <subscription id> -ResourceGroup rg-pim -SupportAppId <Invardia Support app client id> -WhatIf
  Preview: reads everything, prints what it would do and the script the job would run. Then the same command without -WhatIf.

.LINK
  https://invardia.com/docs/pim/scripts/Invoke-PimSupportSqlAccessJob/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$TenantId,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$SubscriptionId,
    # the resource group of the PIM Manager installation (its Container Apps environment and jobs)
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.()-]{1,90}$')][string]$ResourceGroup,
    # the Invardia Support app's application (client) id. In the Support app's own session it may be left out.
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$SupportAppId = '',
    [string]$DbUserName = 'invardia-support',
    # the installation's own job the identity, the image and the database are read from
    [ValidatePattern('^[a-z][a-z0-9-]{0,30}[a-z0-9]$')][string]$TemplateJobName = 'ca-pim-dbinit',
    # the name of the one-time job (created, run once, removed)
    [ValidatePattern('^[a-z][a-z0-9-]{0,30}[a-z0-9]$')][string]$JobName = 'caj-pim-supportsql',
    # only when the template job does not name its database identity itself: the client id of a user-assigned identity it already carries
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$SqlIdentityClientId = '',
    [ValidateRange(60, 3600)][int]$TimeoutSeconds = 600,
    # --- test seams (tests/Test-PimSupportSqlJob.ps1); omit them for a real run ---
    [scriptblock]$Arm,
    [scriptblock]$Graph,
    [scriptblock]$Logs,
    [scriptblock]$Sleep,
    [int]$PollSeconds = 10,
    [int]$LogWaitSeconds = 180
)
$ErrorActionPreference = 'Stop'
# Published as ONE standalone file (https://invardia.com/support/pim/Invoke-PimSupportSqlAccessJob.ps1): every helper is
# dot-sourced by a literal path relative to this script's folder, so Build-PimSupportScripts.ps1 inlines it.
. (Join-Path $PSScriptRoot '_PimScriptDoc.ps1')
. (Join-Path $PSScriptRoot '..\..\engine\_shared\PIM-Rest.ps1')       # the ONE token client (framework 12.17)
. (Join-Path $PSScriptRoot '_PimSignedIn.ps1')                        # the sign-in rule: the Support session, else the browser
. (Join-Path $PSScriptRoot '_PimSupportSqlAccess.ps1')                # the grant itself: the SID, the statement, the read-back
. (Join-Path $PSScriptRoot '_PimSupportSqlJob.ps1')                   # the one-time job around it
$null = Start-PimScriptRun -Script 'Invoke-PimSupportSqlAccessJob'
$script:ssjRc = 1
try {
$tid = "$TenantId".Trim().ToLowerInvariant(); $sub = "$SubscriptionId".Trim().ToLowerInvariant()
if ($JobName -ieq $TemplateJobName) { throw "Invoke-PimSupportSqlAccessJob: -JobName and -TemplateJobName are the same ('$JobName') -- the one-time job is created and removed, the installation's own job is only read. Nothing was touched." }

Write-Host ('=' * 78) -ForegroundColor Cyan
Write-Host " PIM MANAGER -- INVARDIA SUPPORT: DATABASE ACCESS FROM INSIDE (PRIVATE DATABASE)  ($ResourceGroup)$(if ($WhatIfPreference) { '   PREVIEW' })" -ForegroundColor Cyan
Write-Host ('=' * 78) -ForegroundColor Cyan

# ---- sign-in: the Support app's session in this window, else the person's browser (asserted: this tenant, this subscription)
$sessionApp = ''
if (-not ($Arm -and $Graph)) {
    $who = Get-PimSignedInIdentity -TenantId $tid -SubscriptionId $sub
    if (-not $who.ok) { throw "Invoke-PimSupportSqlAccessJob: REFUSED (nothing was touched) -- $($who.reason)" }
    $sessionApp = "$($who.supportAppId)".Trim().ToLowerInvariant()
    Write-Host "  $($who.reason)" -ForegroundColor DarkGray
}
$app = "$SupportAppId".Trim().ToLowerInvariant()
if (-not $app) { $app = $sessionApp }
if (-not $app) { throw 'Invoke-PimSupportSqlAccessJob: pass -SupportAppId <the Invardia Support app''s client id> (it is only known by itself in the Support app''s own session). Nothing was touched.' }
if ($sessionApp -and $sessionApp -ne $app) { throw "Invoke-PimSupportSqlAccessJob: this window is the session of the Support app $sessionApp, but -SupportAppId names $app -- REFUSED (the right would go to another application). Nothing was touched." }
Write-Host "  Invardia Support app: $app" -ForegroundColor DarkGray

# ---- the callers (REST only) ------------------------------------------------------------------------------------------
# PLAIN scriptblocks over script-level functions, never a bound closure: a closure runs in its own module scope and
# cannot see the functions this script loaded (the token client).
$script:ssjTenant = $tid
function Invoke-SsjRest {
    param([string]$Base, [string]$Resource, [string]$Method = 'GET', [string]$Path, $Body)
    $WhatIfPreference = $false   # the reads of a preview are real; every write is gated before it gets here
    $tok = "$(Get-PimRestToken -Resource $Resource -TenantId $script:ssjTenant)".Trim()
    if (-not $tok) { throw "no token for $Resource in tenant $($script:ssjTenant)" }
    $a = @{ Method = $Method; Uri = $(if ($Path -match '^https://') { $Path } else { "$Base$Path" }); Headers = @{ Authorization = "Bearer $tok" } }
    if ($null -ne $Body) { $a['Body'] = ($Body | ConvertTo-Json -Depth 12 -Compress); $a['ContentType'] = 'application/json' }
    try { return (Invoke-RestMethod @a) }
    catch {
        $code = 0; try { $code = [int]$_.Exception.Response.StatusCode } catch { $code = 0 }
        throw "$Method $Path -> HTTP $code : $((("$($_.ErrorDetails.Message) $($_.Exception.Message)") -replace '\s+', ' ').Trim())"
    }
}
function Get-SsjLogLines {
    # The console lines of one execution, from the environment's Log Analytics workspace. A read; never part of the verdict.
    param([string]$WorkspaceId, [string]$Execution)
    $q = Get-PimSupportSqlJobLogQuery -Execution $Execution
    $r = Invoke-SsjRest -Base 'https://api.loganalytics.io' -Resource 'https://api.loganalytics.io' -Method 'POST' -Path "/v1/workspaces/$WorkspaceId/query" -Body @{ query = $q; timespan = 'P1D' }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($t in @(@($r.tables) | Select-Object -First 1)) {
        $at = 0; $cols = @($t.columns)
        for ($i = 0; $i -lt $cols.Count; $i++) { if ("$($cols[$i].name)" -eq 'Log_s') { $at = $i } }
        foreach ($row in @($t.rows)) { $out.Add("$(@($row)[$at])") }
    }
    return @($out.ToArray())
}
if (-not $Arm) { $Arm = { param([string]$Method = 'GET', [string]$Path, $Body) Invoke-SsjRest -Base 'https://management.azure.com' -Resource 'https://management.azure.com' -Method $Method -Path $Path -Body $Body } }
if (-not $Graph) { $Graph = { param([string]$Method = 'GET', [string]$Path, $Body) Invoke-SsjRest -Base 'https://graph.microsoft.com/v1.0' -Resource 'https://graph.microsoft.com' -Method $Method -Path $Path -Body $Body } }
if (-not $Logs) { $Logs = { param([string]$WorkspaceId, [string]$Execution) Get-SsjLogLines -WorkspaceId $WorkspaceId -Execution $Execution } }

$whatIfOnly = -not $PSCmdlet.ShouldProcess("resource group $ResourceGroup", "create, run once and remove the job '$JobName', which gives the Invardia Support app $app its database user in db_owner from inside the installation")
$ja = @{ Arm = $Arm; Graph = $Graph; Logs = $Logs; SubscriptionId = $sub; ResourceGroup = $ResourceGroup; SupportAppId = $app; TemplateJobName = $TemplateJobName; JobName = $JobName
         DbUserName = $DbUserName; SqlIdentityClientId = $SqlIdentityClientId; TimeoutSeconds = $TimeoutSeconds; PollSeconds = $PollSeconds; LogWaitSeconds = $LogWaitSeconds; WhatIfOnly = $whatIfOnly }
if ($Sleep) { $ja['Sleep'] = $Sleep }
$r = Invoke-PimSupportSqlJobGrant @ja

foreach ($w in @($r.warnings)) { Write-Host "  WARNING: $w" -ForegroundColor Yellow }
foreach ($p in @($r.problems)) { Write-Host "  NOT DONE: $p" -ForegroundColor Red }
Write-Host ''
if ($r.whatIf) { Write-Host "RESULT: preview only -- nothing was changed$(if (@($r.problems).Count) { ' (see NOT DONE above)' })." -ForegroundColor DarkYellow }
elseif ($r.exit -ne 0) {
    $tail = if ($r.jobCreated -and $r.jobRemoved) { ' The one-time job was removed.' } elseif ($r.jobCreated) { ' THE ONE-TIME JOB IS STILL THERE (see above).' } else { ' No job was created.' }
    $done = if ("$($r.status)" -eq 'Succeeded' -and -not ($r.result -and -not [bool]$r.result.ok)) { ' The database user is in place (the job read it back); what failed is above.' } else { '' }
    Write-Host "RESULT: FAIL.$done$tail" -ForegroundColor Red
} else {
    $what = if ($r.result) { "database user [$($r.result.userName)] in db_owner ($(switch ("$($r.result.state)") { 'created' { 'created' } 'role-added' { 'was there, added to db_owner' } 'unchanged' { 'was already there, nothing was changed' } default { 'in place' } })), read back by the job" }
            else { 'the job ended Succeeded, which it does only after reading the user and its role back' }
    Write-Host "RESULT: PASS$(if (@($r.warnings).Count) { " with $(@($r.warnings).Count) warning(s)" }) -- $what. The one-time job was removed; no firewall rule and no network path was opened." -ForegroundColor Green
    Write-Host '  The customer ends this access by switching the Invardia Support app off in Microsoft Entra ID (or Grant-PimSupportAccess.ps1 -Remove).' -ForegroundColor DarkGray
}
$script:ssjRc = [int]$r.exit
if ($r.whatIf -and -not @($r.problems).Count) { $script:ssjRc = 0 }
} finally { Stop-PimScriptRun -Script 'Invoke-PimSupportSqlAccessJob' }
exit $script:ssjRc
