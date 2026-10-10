<#
.SYNOPSIS
  Run a PIM deployment (or just collect state) and produce ONE redacted report file that is safe to
  send back to the vendor from a CUSTOMER tenant.

.DESCRIPTION
  Why this exists: a deploy that fails in a customer environment is diagnosed from whatever the
  operator can paste, which is usually the last screenful -- the part that says a step failed and
  not the part that says why. This captures the WHOLE run plus the surrounding state, in one file,
  and REDACTS it so sending it does not leak credentials.

  🔒 REDACTION IS THE POINT, and it is deny-by-default on VALUES, not on keywords. Anything that
  looks like a secret is masked wherever it appears -- bearer tokens, connection strings, SAS
  tokens, client secrets, certificate blobs, passwords -- because a transcript captures command
  lines, and command lines are where secrets actually leak. What is deliberately KEPT is everything
  needed to diagnose: resource names, revision names, image digests, error codes, timings.

  🪤 IDENTIFIERS ARE A SEPARATE DECISION FROM SECRETS. Tenant/subscription ids and domain names are
  not credentials, and diagnosis is much harder without them -- but in an MSP setting they identify
  a third party. They are kept by default and masked with -RedactIdentifiers, which is a choice the
  operator makes per customer rather than a default someone has to remember to override.

  WHAT IT COLLECTS
    1. Run context      -- versions (PowerShell/.NET), OS, UTC timestamp, PIM version, who is signed in (REST).
    2. The deploy run   -- full transcript of Invoke-PimDeployAll (unless -CollectOnly).
    3. Resource state   -- the RG inventory, ACA env, every app + its image + revision + replicas,
                           the SQL database and its SKU/status.
    4. Container logs   -- the last N lines from each container app (the actual failure, usually).
    5. Verdict          -- the step table, what failed, and whether a rollback fired.

.PARAMETER DeployArgs
  Hashtable of parameters forwarded verbatim to Invoke-PimDeployAll.ps1.

.PARAMETER CollectOnly
  Do NOT deploy. Only gather state + logs. Use this to report on an environment that is already
  broken, without changing it.

.PARAMETER RedactIdentifiers
  Also mask tenant ids, subscription ids and *.onmicrosoft.com / customer domains.

.PARAMETER TailLines
  Container log lines per app (default 200).

.EXAMPLE
  # Deploy and produce a report to send back
  .\New-PimDeployReport.ps1 -DeployArgs @{ TenantId='...'; SubscriptionId='...'; ResourceGroup='rg-...'
      VnetName='vnet-...'; VnetResourceGroup='rg-...'; AcrName='acr...'; EnvName='cae-...'
      SqlServerFqdn='...'; Apply=$true } -RedactIdentifiers

.EXAMPLE
  # Just report on what is there now, change nothing
  .\New-PimDeployReport.ps1 -CollectOnly -DeployArgs @{ SubscriptionId='...'; ResourceGroup='rg-...' }
#>
[CmdletBinding()]
param(
    [hashtable]$DeployArgs = @{},
    [switch]$CollectOnly,
    [switch]$RedactIdentifiers,
    [int]$TailLines = 200,
    [string]$OutDir = (Join-Path ([IO.Path]::GetTempPath()) 'pim-deploy-reports')
)
$ErrorActionPreference = 'Continue'
Set-StrictMode -Off
$here = $PSScriptRoot

# ---------------------------------------------------------------------------
. (Join-Path (Split-Path (Split-Path $here -Parent) -Parent) 'engine\_shared\PIM-DeployReport.ps1')

function Add-Section {
    param([System.Text.StringBuilder]$Sb, [string]$Title, [scriptblock]$Body)
    [void]$Sb.AppendLine(''); [void]$Sb.AppendLine('=' * 96)
    [void]$Sb.AppendLine(" $Title"); [void]$Sb.AppendLine('=' * 96)
    try   { $out = & $Body 2>&1 | Out-String; [void]$Sb.AppendLine($out.TrimEnd()) }
    catch { [void]$Sb.AppendLine("  <collection failed: $($_.Exception.Message)>") }
}

New-Item -ItemType Directory -Force $OutDir | Out-Null
$stamp     = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$reportRaw = Join-Path $OutDir "pim-deploy-$stamp.raw.log"
$reportOut = Join-Path $OutDir "pim-deploy-$stamp.report.log"
$sb = [System.Text.StringBuilder]::new()

[void]$sb.AppendLine("PIM4EntraPS DEPLOY REPORT")
[void]$sb.AppendLine("generated (UTC) : $((Get-Date).ToUniversalTime().ToString('u'))")
[void]$sb.AppendLine("mode            : $(if ($CollectOnly) { 'COLLECT-ONLY (nothing deployed)' } else { 'DEPLOY + COLLECT' })")
[void]$sb.AppendLine("identifiers     : $(if ($RedactIdentifiers) { 'REDACTED' } else { 'kept (resource + tenant ids visible)' })")
[void]$sb.AppendLine("secrets         : ALWAYS REDACTED")

$rg     = $DeployArgs['ResourceGroup']
$sub    = $DeployArgs['SubscriptionId']
$envN   = $DeployArgs['EnvName']
# 100.41 (framework 12.17 NO-AZ): every read below is ARM / Log Analytics REST through PIM-Rest's one token client
# (engine/_shared/PIM-ArmSetup.ps1) -- a calling run's REST session as it is; standalone, the Invardia Support app's session
# or the person signed in. No az, no module.
$solRoot = Split-Path (Split-Path $here -Parent) -Parent
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRoot 'engine\_shared\PIM-ArmSetup.ps1') }
$restReady = $false
if ($sub) {
    try {
        if (-not "$($global:PIM_SetupRestMode)".Trim()) {
            $cn = @{ SubscriptionId = $sub }
            if ("$($DeployArgs['TenantId'])".Trim()) { $cn.TenantId = "$($DeployArgs['TenantId'])".Trim() }
            [void](Connect-PimSetupRest @cn)
        }
        $restReady = $true
    } catch { Write-Host "    sign-in for the state reads failed: $($_.Exception.Message)" -ForegroundColor Yellow }
}
function Get-ReportArmList([string]$Path, [string]$Kind) {
    # One ARM list (paged) under the report's subscription; @() when unreadable (the reason is reported by the caller).
    @(Invoke-PimSetupArm -Path "/subscriptions/$sub/resourceGroups/$rg$Path" -ApiVersion (Get-PimSetupApiVersion $Kind) -All -ErrorAsNull | Where-Object { $_ })
}

Add-Section $sb '1. RUN CONTEXT' {
    "PowerShell : $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
    "OS         : $([System.Environment]::OSVersion.VersionString)"
    "az CLI     : not used (REST, framework 12.17)"
    # IMP-49 c: VERSION is at the SOLUTION root (tools\setup -> tools -> PIM4EntraPS). This read it from
    # tools\, where it never exists, so every report said "unknown".
    $vf = Join-Path (Split-Path (Split-Path $here -Parent) -Parent) 'VERSION'
    "PIM version: $(if (Test-Path $vf) { (Get-Content $vf -Raw).Trim() } else { 'unknown' })"
    # BUG-215: report the subscription this report is ABOUT (never a "default" context -- REST has none), and who reads it.
    if ($sub) {
        $sa = if ($restReady) { Get-PimArmSubscription -SubscriptionId $sub -ErrorAsNull } else { $null }
        "subscription: $(if ($sa) { ([ordered]@{ name = "$($sa.displayName)"; tenant = "$($sa.tenantId)"; id = "$($sa.subscriptionId)" } | ConvertTo-Json -Compress) } else { 'not visible to this sign-in' })"
        $who = if ($restReady) { Get-PimSetupAccount -SubscriptionId $sub } else { $null }
        "signed in  : $(if ($who) { "$($who.user.type) $($who.user.name) (tenant $($who.tenantId), mode $($global:PIM_SetupRestMode))" } else { 'not signed in' })"
    }
}

if (-not $CollectOnly) {
    Start-Transcript -Path $reportRaw -Force | Out-Null
    try {
        $deploy = Join-Path $here 'Invoke-PimDeployAll.ps1'
        Write-Host "==> running Invoke-PimDeployAll ..." -ForegroundColor Cyan
        & $deploy @DeployArgs
    } catch {
        Write-Host "DEPLOY THREW: $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        Stop-Transcript | Out-Null
    }
    Add-Section $sb '2. DEPLOY RUN (full transcript)' {
        if (Test-Path $reportRaw) { Get-Content $reportRaw -Raw } else { '<no transcript captured>' }
    }
} else {
    Add-Section $sb '2. DEPLOY RUN' { '<skipped: -CollectOnly>' }
}

Add-Section $sb '3. RESOURCE STATE' {
    if (-not $rg) { '<no -ResourceGroup in DeployArgs; skipping>' ; return }
    # BUG-215: never read a resource group out of whatever the DEFAULT subscription is.
    if (-not $sub) { '<no -SubscriptionId in DeployArgs; skipping -- a resource group is never read from a guessed subscription>' ; return }
    if (-not $restReady) { '<not signed in; skipping>' ; return }
    "--- resource group inventory ---"
    $inv = Get-ReportArmList '/resources' 'resources'
    if (-not $inv.Count -and $global:PimSetupRestLastError) { "<unreadable: $($global:PimSetupRestLastError)>" }
    $inv | ForEach-Object { [pscustomobject]@{ name = $_.name; type = $_.type; location = $_.location } } | Format-Table -AutoSize | Out-String -Width 250
    "`n--- container apps env ---"
    Get-ReportArmList '/providers/Microsoft.App/managedEnvironments' 'aca' | ForEach-Object { [pscustomobject]@{ name = $_.name; state = $_.properties.provisioningState } } | Format-Table -AutoSize | Out-String -Width 250
    "`n--- container apps (image + revision + replicas) ---"
    Get-ReportArmList '/providers/Microsoft.App/containerApps' 'aca' | ForEach-Object {
        [pscustomobject]@{ name = $_.name; image = @($_.properties.template.containers)[0].image; minReplicas = $_.properties.template.scale.minReplicas
                           revision = $_.properties.latestRevisionName; fqdn = $_.properties.configuration.ingress.fqdn }
    } | Format-Table -AutoSize | Out-String -Width 250
    "`n--- container app JOBS (cron tick) ---"
    Get-PimArmAcaJobList -SubscriptionId $sub -ResourceGroup $rg -ErrorAsNull | ForEach-Object {
        [pscustomobject]@{ name = $_.name; cron = $_.properties.configuration.scheduleTriggerConfig.cronExpression; image = @($_.properties.template.containers)[0].image }
    } | Format-Table -AutoSize | Out-String -Width 250
    "`n--- sql ---"
    $dbs = foreach ($srv in @(Get-ReportArmList '/providers/Microsoft.Sql/servers' 'sql')) {
        foreach ($db in @(Get-ReportArmList "/providers/Microsoft.Sql/servers/$($srv.name)/databases" 'sql')) {
            [pscustomobject]@{ server = $srv.name; name = $db.name; sku = $db.properties.currentServiceObjectiveName; status = $db.properties.status }
        }
    }
    @($dbs) | Format-Table -AutoSize | Out-String -Width 250
}

# 🪤 NOT `'a ' + $x + ' b'` in argument position: PowerShell treats each `+` as another ARGUMENT,
# so the scriptblock lands on the wrong parameter and Body gets "+". Interpolate instead.
Add-Section $sb "4. CONTAINER LOGS (last $TailLines lines per app)" {
    if (-not $rg) { '<no -ResourceGroup; skipping>' ; return }
    if (-not $sub) { '<no -SubscriptionId; skipping -- a resource group is never read from a guessed subscription>' ; return }
    if (-not $restReady) { '<not signed in; skipping>' ; return }
    # The CLI's `logs show` streamed the replica console; over REST the same lines are the environment's Log Analytics
    # table ContainerAppConsoleLogs_CL (the workspace the environment sends to -- appLogsConfiguration).
    $apps = @(Get-ReportArmList '/providers/Microsoft.App/containerApps' 'aca')
    if (-not $apps.Count) { '<no container apps found>'; return }
    $wsByEnv = @{}
    foreach ($a in $apps) {
        "`n########## $($a.name) ##########"
        $envId = "$($a.properties.managedEnvironmentId)"
        if (-not $wsByEnv.ContainsKey($envId)) {
            $e = if ($envId) { Get-PimArmAcaEnv -ResourceId $envId -ErrorAsNull } else { $null }
            $wsByEnv[$envId] = "$($e.properties.appLogsConfiguration.logAnalyticsConfiguration.customerId)".Trim()
        }
        $ws = $wsByEnv[$envId]
        if (-not $ws) { '<the environment sends no logs to Log Analytics -- read the console log in the Azure portal: the app > Monitoring > Log stream>'; continue }
        $q = "ContainerAppConsoleLogs_CL | where ContainerAppName_s == '$($a.name)' | top $TailLines by TimeGenerated desc | sort by TimeGenerated asc | project TimeGenerated, RevisionName_s, Log_s"
        $rows = @(Invoke-PimLogAnalyticsQuery -WorkspaceCustomerId $ws -Query $q -Timespan 'P1D')
        if (-not $rows.Count) { "<no log lines in the last 24 h readable by this sign-in (needs Log Analytics Reader on the workspace) -- or read them in the Azure portal: the app > Monitoring > Log stream>"; continue }
        foreach ($r in $rows) { "$($r.TimeGenerated) [$($r.RevisionName_s)] $($r.Log_s)" }
    }
}

Add-Section $sb '5. WHAT TO SEND BACK' {
    "Send THIS file: $reportOut"
    "Secrets are redacted. Identifiers are $(if ($RedactIdentifiers) { 'redacted' } else { 'PRESENT -- re-run with -RedactIdentifiers if that is not acceptable' })."
    "If the deploy failed, the useful part is section 2 (the step table + the first error) and"
    "section 4 (the container's own log). Section 3 shows whether the shape is right:"
    "  minReplicas 0 on ca-pim-manager and a ca-pim-tick JOB = the on-demand shape."
    "  minReplicas 1 on six apps = the always-on matrix, which costs materially more."
}

$final = Get-PimRedactedText -Text $sb.ToString() -Identifiers:$RedactIdentifiers
Set-Content -LiteralPath $reportOut -Value $final -Encoding utf8
if (Test-Path $reportRaw) { Remove-Item $reportRaw -Force -ErrorAction SilentlyContinue }  # raw is UNREDACTED

Write-Host ''
Write-Host "REPORT: $reportOut" -ForegroundColor Green
Write-Host "  secrets redacted; identifiers $(if ($RedactIdentifiers) { 'redacted' } else { 'kept' }). Raw transcript deleted (it was unredacted)." -ForegroundColor DarkGray
return $reportOut

