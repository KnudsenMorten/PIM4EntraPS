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
    1. Run context      -- versions (PowerShell/.NET/az/module), OS, UTC timestamp, PIM version.
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
$subArg = if ($sub) { @('--subscription', $sub) } else { @() }

Add-Section $sb '1. RUN CONTEXT' {
    "PowerShell : $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
    "OS         : $([System.Environment]::OSVersion.VersionString)"
    "az CLI     : $(try { (az version --output json 2>$null | ConvertFrom-Json).'azure-cli' } catch { 'n/a' })"
    $vf = Join-Path (Split-Path $here -Parent) 'VERSION'
    "PIM version: $(if (Test-Path $vf) { (Get-Content $vf -Raw).Trim() } else { 'unknown' })"
    "az context : $(try { az account show --query '{name:name,tenant:tenantId,id:id}' -o json 2>$null } catch { 'not logged in' })"
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
    "--- resource group inventory ---"
    az resource list -g $rg @subArg --query "[].{name:name,type:type,location:location}" -o table --only-show-errors 2>&1
    "`n--- container apps env ---"
    az containerapp env list -g $rg @subArg --query "[].{name:name,state:properties.provisioningState}" -o table --only-show-errors 2>&1
    "`n--- container apps (image + revision + replicas) ---"
    az containerapp list -g $rg @subArg --query "[].{name:name,image:properties.template.containers[0].image,minReplicas:properties.template.scale.minReplicas,revision:properties.latestRevisionName,fqdn:properties.configuration.ingress.fqdn}" -o table --only-show-errors 2>&1
    "`n--- container app JOBS (cron tick) ---"
    az containerapp job list -g $rg @subArg --query "[].{name:name,cron:properties.configuration.scheduleTriggerConfig.cronExpression,image:properties.template.containers[0].image}" -o table --only-show-errors 2>&1
    "`n--- sql ---"
    az sql db list -g $rg @subArg --query "[].{server:location,name:name,sku:currentServiceObjectiveName,status:status}" -o table --only-show-errors 2>&1
}

# 🪤 NOT `'a ' + $x + ' b'` in argument position: PowerShell treats each `+` as another ARGUMENT,
# so the scriptblock lands on the wrong parameter and Body gets "+". Interpolate instead.
Add-Section $sb "4. CONTAINER LOGS (last $TailLines lines per app)" {
    if (-not $rg) { '<no -ResourceGroup; skipping>' ; return }
    $apps = @()
    try { $apps = az containerapp list -g $rg @subArg --query "[].name" -o tsv --only-show-errors 2>$null } catch { }
    if (-not $apps) { '<no container apps found>'; return }
    foreach ($a in @($apps | Where-Object { $_ })) {
        "`n########## $a ##########"
        az containerapp logs show -n $a -g $rg @subArg --tail $TailLines --only-show-errors 2>&1
    }
}

Add-Section $sb '5. WHAT TO SEND BACK' {
    "Send THIS file: $reportOut"
    "Secrets are redacted. Identifiers are $(if ($RedactIdentifiers) { 'redacted' } else { 'PRESENT -- re-run with -RedactIdentifiers if that is not acceptable' })."
    "If the deploy failed, the useful part is section 2 (the step table + the first error) and"
    "section 4 (the container's own log). Section 3 shows whether the shape is right:"
    "  minReplicas 0 on ca-pim-manager and a ca-pim-tick JOB = the on-demand shape."
    "  minReplicas 1 on six apps = the always-on matrix, which is ~`$205-230/environment/month."
}

$final = Get-PimRedactedText -Text $sb.ToString() -Identifiers:$RedactIdentifiers
Set-Content -LiteralPath $reportOut -Value $final -Encoding utf8
if (Test-Path $reportRaw) { Remove-Item $reportRaw -Force -ErrorAction SilentlyContinue }  # raw is UNREDACTED

Write-Host ''
Write-Host "REPORT: $reportOut" -ForegroundColor Green
Write-Host "  secrets redacted; identifiers $(if ($RedactIdentifiers) { 'redacted' } else { 'kept' }). Raw transcript deleted (it was unredacted)." -ForegroundColor DarkGray
return $reportOut

