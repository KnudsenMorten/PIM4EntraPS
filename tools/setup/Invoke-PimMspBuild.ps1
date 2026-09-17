#Requires -Version 5.1
<#
.SYNOPSIS
    71.18 -- THE ONE-SHOT MSP BUILD: an MSP MASTER (S3) or a MANAGED tenant (S6, locally hosted pull), end to end, from a
    machine-local config of ids and names. Signed-in administrator OR certificate identity; the environments it builds
    run as managed identities. Plan by default; -Apply to build.

.DESCRIPTION
    Operator 2026-09-15: "on friday we must use it to build efif and ride in prod". Runs, in order and idempotently, every
    step that made the EFIF -> RIDE test pair work (engine/_shared/PIM-MspBuild.ps1 decides the plan):

      both   keyvault (when keyVaultName + bootstrapAppId are set) -> hosting (Invoke-PimDeployAll -Scenario S3|S6: identity,
             prerequisites incl. SQL admin group, image, containers, schema, mail sender, Easy Auth, code, updater, access,
             smoke gate) -> sqlgroup (tick + Manager + troubleshooting identity) -> access (tick Engine Graph set, Manager
             read-only set, Container Apps Jobs Operator on the tick, SchedulerTickJobId) -> scenario
      master registry -> publishnetwork (storage service endpoint on the master's own subnet) -> storage (public-but-signed:
             anonymous blob read; the master's subnet allowed, THEN firewall Deny) -> register-<n> + network-<n> (each managed
             tenant: ring + tags, and a storage network rule for its subnet) -> signingkey (non-exportable Key Vault key; PRINTS
             the key id managed tenants pin) -> publishjob (ca-pim-publish: daily Container Apps job, system identity) ->
             publish (start it, wait for Succeeded)   [71.35: no signing host, no certificate, no scheduled task]
      slave  pullnetwork (storage service endpoint on this environment's subnet; PRINTS the subnet id for the master) ->
             downlink (pull job: plain blob URL, signature-verified, system identity)

    THE PULL IS PUBLIC-BUT-SIGNED (71.34, DESIGN 13.7). No SAS, no read link, no rotation task, no master credential on the
    managed tenant's side, and nothing in the access path that expires. Trust is the bundle's RSA signature (a pull
    REFUSES a bundle that does not verify); access is the master storage firewall, which names each managed tenant's
    subnet. Order: build the MASTER, build the managed tenant (it prints its subnet id), then on the master set
    slaves[<n>].subnetResourceId and re-run -From network-<n>.

    Then it PRINTS the operator steps (Get-PimMspOperatorSteps) -- the first-run policy mass-change approval is deliberately
    not automated.

    WHO THE BUILD RUNS AS (71.33) -- decided by the config alone:
      * no 'deployIdentity'  -> SIGNED-IN mode: the administrator signed in with `az login`. Before anything is touched the
        build REFUSES unless the az account for config.subscriptionId is a USER in config.tenantId (a service principal,
        another tenant or another subscription is refused; with no sign-in it runs `az login --tenant <tenantId>`), and
        unless no AZURE_CLIENT_SECRET / PIM_CERT_THUMBPRINT / managed-identity variable would make a step authenticate as
        somebody else. The signed-in user is made a member of grp-pim-sql-admins (the store steps connect as that user).
        (71.35: the daily publish is a Container Apps job on the master's managed identity, so a signed-in master build has
        no step it cannot run.)
        Roles the signed-in user needs: Owner (or Contributor + User Access Administrator) on the subscription; in Entra,
        Privileged Role Administrator (to grant the managed identities their Microsoft Graph app roles), Application
        Administrator (Easy Auth registration) and Groups Administrator (the SQL admin group). Exchange Administrator only
        if the mail sender is to be provisioned by this build.
      * 'deployIdentity' { clientId, certThumbprint } -> CERTIFICATE mode (the MSP management host): az logs in as that
        application by certificate (LocalMachine\My) into a per-run directory that only SYSTEM, Administrators and the
        running account can read; that directory -- PEM and step argument files -- is deleted when the run ends.

    SECRETS: none, in either mode. The config is refused if any key or value looks like a credential; no token is ever
    printed or written by the build.
    Exit codes: 0 complete; 1 refused or a step failed (the resume command is printed); 2 INCOMPLETE -- every runnable step
    succeeded, but a step that cannot run under this identity (or is waiting for a managed tenant's subnet id) did not.

.PARAMETER Role / ConfigPath
    Master | Slave, and the JSON config (see internal/FRIDAY-MSP-GO-LIVE.md for both shapes).

.PARAMETER Apply
    Build. Without it the plan and the operator steps are printed and nothing is touched.

.PARAMETER From
    Resume at this step id (every step converges, so re-running earlier ones is also safe).

.PARAMETER UpdateSourceUrl / UpdateSourceUrlFile
    WHERE THE RELEASE FEED URL COMES FROM. Operator 2026-09-17: "include in a secret file or something i can
    distribute with the url + sas token". -UpdateSourceUrlFile is that file: ONE line holding the feed template
    (URL + its stored-access-policy SAS) and nothing else, so it is trivial to hand over and trivial to replace.
    Order: -UpdateSourceUrl, then the feed file (-UpdateSourceUrlFile / $env:PIM_UPDATE_SOURCE_URL_FILE), then
    $env:PIM_UPDATE_SOURCE_URL, then the actionable refusal below. No other sources.
    The value is a credential: it is NEVER printed, logged or written to a build config -- only its ORIGIN is shown.

.PARAMETER StepRunner
    TEST seam: a scriptblock param($step, $resolvedArgs) returning @{ ok; output }. Replaces process launch, az login and
    placeholder resolution by az (placeholders are then resolved from -Resolved).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Master','Slave')][string]$Role,
    [Parameter(Mandatory)][string]$ConfigPath,
    [switch]$Apply,
    [string]$From,
    [string]$UpdateSourceUrl,
    [string]$UpdateSourceUrlFile = "$($env:PIM_UPDATE_SOURCE_URL_FILE)",
    [scriptblock]$StepRunner,
    [hashtable]$Resolved = @{}
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $solRoot 'engine\_shared\PIM-MspBuild.ps1')
. (Join-Path $here '_PimSasCertLogin.ps1')

if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "config not found: $ConfigPath" }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$chk = Test-PimMspBuildConfig -Role $Role -Config $config
foreach ($w in $chk.warnings) { Write-Host "  [warn] $w" -ForegroundColor Yellow }
if (-not $chk.ok) {
    foreach ($e in $chk.errors) { Write-Host "  [x] $e" -ForegroundColor Red }
    Write-Host 'REFUSED: fix the config; nothing was touched.' -ForegroundColor Red
    exit 1
}
$plan = @(Get-PimMspBuildPlan -Role $Role -Config $config)
$ops = @(Get-PimMspOperatorSteps -Role $Role -Config $config)
$authMode = Get-PimMspBuildAuthMode -Config $config
$startAt = 0
if ("$From".Trim()) {
    $startAt = [array]::FindIndex([object[]]$plan, [Predicate[object]]{ param($s) $s.id -eq "$From".Trim() })
    if ($startAt -lt 0) { throw "-From '$From' is not a step of the $Role plan: $(($plan | ForEach-Object { $_.id }) -join ', ')" }
}

Write-Host ("=== PIM4EntraPS one-shot MSP build: {0} ({1}) tenant {2} -- {3} ===" -f $Role, $(if ($Role -eq 'Master') { 'S3' } else { 'S6' }), $config.tenantId, $(if ($Apply) { 'APPLY' } else { 'PLAN ONLY' })) -ForegroundColor Cyan
Write-Host ("    identity: {0}" -f $(if ($authMode -eq 'SignedIn') { 'the SIGNED-IN az user (no deployIdentity in the config)' } else { "certificate identity $($config.deployIdentity.clientId)" })) -ForegroundColor DarkGray
for ($i = 0; $i -lt $plan.Count; $i++) {
    $s = $plan[$i]
    $mark = if ($i -lt $startAt) { 'skip' } elseif ("$($s.blocked)".Trim()) { 'N/A ' } else { '    ' }
    Write-Host ("  {0} [{1,2}] {2,-17} {3}" -f $mark, ($i + 1), $s.id, $s.title)
    Write-Host ("               {0} {1}{2}" -f $s.host, $s.script, $(if (@($s.switches).Count) { ' -' + (@($s.switches) -join ' -') } else { '' })) -ForegroundColor DarkGray
}
$printOps = {
    Write-Host "`n--- operator steps (need a human or a decision; NOT automated) ---" -ForegroundColor Yellow
    foreach ($o in $ops) { Write-Host ("  [{0}] {1}  (when: {2})`n        {3}" -f $o.id, $o.title, $o.when, $o.command) }
}
if (-not $Apply) { & $printOps; Write-Host "`nPLAN ONLY -- re-run with -Apply to build." -ForegroundColor Cyan; exit 0 }
# The release feed URL carries its SAS, so it lives in this session's environment only (Invoke-PimDeployAll reads it) --
# never in the config file. Without it the updater cannot be deployed, so refuse before touching anything.
# THE RELEASE FEED. Three sources, in this order and no others: -UpdateSourceUrl, the distributable FEED FILE, then
# this session's $env:PIM_UPDATE_SOURCE_URL. The value is a credential (URL + SAS): only its ORIGIN is ever printed.
if (-not $StepRunner -and ($startAt -le [array]::FindIndex([object[]]$plan, [Predicate[object]]{ param($s) $s.id -eq 'hosting' }))) {
    $feedOrigin = ''
    if ("$UpdateSourceUrl".Trim()) {
        $env:PIM_UPDATE_SOURCE_URL = "$UpdateSourceUrl".Trim(); $feedOrigin = '-UpdateSourceUrl'
    } elseif ("$UpdateSourceUrlFile".Trim() -and (Test-Path -LiteralPath "$UpdateSourceUrlFile".Trim())) {
        # One line, nothing else -- a file with more than the feed in it is a paste accident, not a feed.
        $line = @((Get-Content -LiteralPath "$UpdateSourceUrlFile".Trim()) | Where-Object { "$_".Trim() }) | Select-Object -First 1
        if ("$line".Trim()) { $env:PIM_UPDATE_SOURCE_URL = "$line".Trim().Trim('"').Trim("'"); $feedOrigin = 'feed file' }
    } elseif ("$env:PIM_UPDATE_SOURCE_URL".Trim()) {
        $feedOrigin = 'session $env:PIM_UPDATE_SOURCE_URL'
    }
    if ($feedOrigin) { Write-Host "    release feed resolved from: $feedOrigin" -ForegroundColor DarkGray }
}
if (-not $StepRunner -and ($startAt -le [array]::FindIndex([object[]]$plan, [Predicate[object]]{ param($s) $s.id -eq 'hosting' })) -and -not "$env:PIM_UPDATE_SOURCE_URL".Trim()) {
    # 🔴 REHEARSAL FINDING 2026-09-17: this refusal fires BEFORE anything is touched -- correct -- but it only
    # named a document, and that document only said "the same value the internal updater uses". An operator who
    # does not already have the link in hand is then stopped at step zero of a go-live with no command to run.
    # The whole build is gated on ONE value, so the refusal now carries the exact way to produce it.
    Write-Host "REFUSED: `$env:PIM_UPDATE_SOURCE_URL is not set in this session (the release feed URL + its stored-access-policy SAS). Nothing was touched." -ForegroundColor Red
    Write-Host '' -ForegroundColor Red
    Write-Host '  Supply it as -UpdateSourceUrl, or as a one-line feed file (-UpdateSourceUrlFile / $env:PIM_UPDATE_SOURCE_URL_FILE).' -ForegroundColor Yellow
    Write-Host '  To mint one, if you hold rights on the source storage account (the SAS is policy-backed, so it carries no expiry of its own):' -ForegroundColor Yellow
    Write-Host '    $acct = ''<source storage account>''; $cont = ''pim-src''; $pol = ''srcread''' -ForegroundColor Gray
    Write-Host '    $key  = az storage account keys list --account-name $acct --subscription <sub> --query "[0].value" -o tsv' -ForegroundColor Gray
    Write-Host '    $sas  = az storage container generate-sas --account-name $acct --name $cont --policy-name $pol --https-only --account-key $key -o tsv' -ForegroundColor Gray
    Write-Host '    $env:PIM_UPDATE_SOURCE_URL = "https://$acct.blob.core.windows.net/$cont/pim-src-{version}.tar.gz?$($sas.Trim(''"''))"' -ForegroundColor Gray
    Write-Host '  (a CONTAINER SAS, never a blob SAS -- the URL is a TEMPLATE and {version} is substituted at run time.)' -ForegroundColor DarkGray
    Write-Host '  The concrete account, subscription and full procedure are in the internal runbook (internal\FRIDAY-MSP-GO-LIVE.md section 1 step 4).' -ForegroundColor DarkGray
    exit 1
}

$runDir = Join-Path ([IO.Path]::GetTempPath()) ('pim-msp-build-' + [guid]::NewGuid().ToString('N'))
$exitCode = 0
$notRun = New-Object System.Collections.Generic.List[string]
# Rehearsal blocker #3: az finds its extensions under AZURE_CONFIG_DIR unless AZURE_EXTENSION_DIR says otherwise, and the
# certificate login's per-run directory has none -- so the hosted smoke gate (az containerapp) could not run. Point az at
# the invoking user's installed extensions for this run only (an explicit AZURE_EXTENSION_DIR is left alone).
$prevExtDirSet = [bool]$env:AZURE_EXTENSION_DIR
$extDir = Get-PimMspBuildAzExtensionDir -Current "$env:AZURE_EXTENSION_DIR" -UserProfile "$env:USERPROFILE"
$prevSubscription = ''
try {
    if (-not $StepRunner) {
        $null = New-PimRestrictedProfileDir -Path $runDir
        if ($extDir) { $env:AZURE_EXTENSION_DIR = $extDir; Write-Host "    az extensions for this run: $extDir" -ForegroundColor DarkGray }
        if ($authMode -eq 'Certificate') {
            Write-Host "`n==> az certificate login as the deploy identity $($config.deployIdentity.clientId)" -ForegroundColor Cyan
            $login = Invoke-PimCertAzLogin -TenantId $config.tenantId -ClientId $config.deployIdentity.clientId -CertThumbprint $config.deployIdentity.certThumbprint `
                        -SubscriptionId $config.subscriptionId -ProfileDir $runDir -Name 'deploy'
            if (-not $login.ok) { throw "certificate login failed: $($login.reason)" }
            Write-Host "    $($login.reason)" -ForegroundColor DarkGray
            $Resolved['{{pem:deploy}}'] = $login.pemPath
        } else {
            # 71.33 -- SIGNED-IN. The caller's own az profile (no per-run login, no PEM). Asserted before anything is touched.
            . (Join-Path $here '_PimSignedIn.ps1')
            Write-Host "`n==> signed-in identity for tenant $($config.tenantId) / subscription $($config.subscriptionId)" -ForegroundColor Cyan
            $who = Get-PimSignedInIdentity -TenantId $config.tenantId -SubscriptionId $config.subscriptionId
            if (-not $who.ok -and $who.reason -match 'no az sign-in covers') {
                Write-Host "    not signed in for this subscription -- starting: az login --tenant $($config.tenantId)" -ForegroundColor Yellow
                $ErrorActionPreference = 'Continue'; az login --tenant $config.tenantId -o none; $ErrorActionPreference = 'Stop'
                $who = Get-PimSignedInIdentity -TenantId $config.tenantId -SubscriptionId $config.subscriptionId
            }
            if (-not $who.ok) { throw "REFUSED (nothing was touched): $($who.reason)" }
            Write-Host "    $($who.reason) -- object id $($who.objectId)" -ForegroundColor DarkGray
            $Resolved['{{signed-in-user}}'] = $who.objectId
            # Some steps judge the az DEFAULT subscription; pin it for the run and put the caller's back afterwards.
            $ErrorActionPreference = 'Continue'
            $prevSubscription = "$(az account show --query id -o tsv 2>$null)".Trim()
            az account set --subscription $config.subscriptionId -o none 2>$null
            $ErrorActionPreference = 'Stop'
        }
    }
    if ($authMode -eq 'Certificate') {
        $globals = @{ PIM_TenantId = "$($config.tenantId)"; PIM_ClientId = "$($config.deployIdentity.clientId)"; PIM_CertThumbprint = "$($config.deployIdentity.certThumbprint)"
                      PIM_SqlClientId = "$($config.deployIdentity.clientId)"; PIM_SqlCertThumbprint = "$($config.deployIdentity.certThumbprint)" }
    } else {
        $globals = @{ PIM_TenantId = "$($config.tenantId)" }   # NO application identity reaches a step
    }

    # 71.36: a -From resume INSIDE a private store's build window re-opens the window first (the step that failed may be a
    # store step, and a previous run may have closed it). Get-PimMspBuildRunOrder is pure and offline-tested.
    $order = @(Get-PimMspBuildRunOrder -StepIds @($plan | ForEach-Object { $_.id }) -StartAt $startAt)
    if ($order.Count -and $startAt -lt $plan.Count -and $order[0] -ne $startAt) { Write-Host "    resume inside the SQL build window: running 'sqlopen' first" -ForegroundColor DarkGray }
    foreach ($i in $order) {
        $s = $plan[$i]
        Write-Host ("`n==> [{0}/{1}] {2}: {3}" -f ($i + 1), $plan.Count, $s.id, $s.title) -ForegroundColor Cyan
        if ("$($s.blocked)".Trim()) {
            # Never executed, never resolved -- and never reported as done.
            Write-Host "    NOT RUN: $($s.blocked)" -ForegroundColor Yellow
            $notRun.Add($s.id)
            continue
        }
        if ($s.why) { Write-Host "    why: $($s.why)" -ForegroundColor DarkGray }
        # resolve run-time placeholders (managed identity object ids are read from ARM at the moment they are needed)
        $argsOut = @{}
        foreach ($k in $s.args.Keys) {
            $val = $s.args[$k]
            if (-not $StepRunner) {
                foreach ($m in [regex]::Matches((@($val) -join ' '), '\{\{mi-(job|app):([^}]+)\}\}')) {
                    if ($Resolved.ContainsKey($m.Value)) { continue }
                    # 🔴 71.31 (rehearsal 2026-09-17) -- [string[]] IS LOAD-BEARING, NOT DECORATION.
                    # PowerShell UNWRAPS a single-element array returned from an if-expression to a SCALAR STRING.
                    # `@('containerapp','job')` stayed an Object[] and splatted correctly, but `@('containerapp')`
                    # became the String 'containerapp' -- and splatting a STRING splats it ONE CHARACTER PER
                    # ARGUMENT, so the build actually ran:
                    #     az c o n t a i n e r a p p show --subscription ... -n ca-pim-manager ...
                    # az rejected it, the error was swallowed by `2>$null`, $oid came back empty, and the build died
                    # with "unresolved {{mi-app:ca-pim-manager}} ... (an earlier step did not produce it)" -- which
                    # blames the WRONG step. {{mi-job:...}} worked by luck (two elements), {{mi-app:...}} NEVER did,
                    # so EVERY MSP build failed at step 3 of 10 (sqlgroup) on any machine. Measured on dp998+du660.
                    # Same unwrapping trap the $members line in PIM-MspBuild.ps1 already carries a comment about.
                    $kind = [string[]]$(if ($m.Groups[1].Value -eq 'job') { @('containerapp', 'job') } else { @('containerapp') })
                    $ErrorActionPreference = 'Continue'
                    $oid = az @kind show --subscription $config.subscriptionId -g $config.resourceGroup -n $m.Groups[2].Value --query identity.principalId -o tsv --only-show-errors 2>$null
                    $ErrorActionPreference = 'Stop'
                    if ("$oid".Trim()) { $Resolved[$m.Value] = "$oid".Trim() }
                }
            }
            $r = Resolve-PimMspBuildArgument -Value $val -Resolved $Resolved
            if (-not $r.ok) { throw "step '$($s.id)': unresolved $($r.missing -join ', ') for -$k (an earlier step did not produce it)" }
            $argsOut[$k] = $r.value
        }
        $scriptPath = [IO.Path]::GetFullPath((Join-Path $solRoot $s.script))
        if ($StepRunner) {
            $res = & $StepRunner $s $argsOut
            $ok = [bool]$res.ok; $output = "$($res.output)"
        } else {
            if (-not (Test-Path -LiteralPath $scriptPath)) { throw "step '$($s.id)': script not found: $scriptPath" }
            $argsFile = Join-Path $runDir "$($s.id).args.json"; $outFile = Join-Path $runDir "$($s.id).out"
            $spec = [ordered]@{ args = $argsOut; switches = @($s.switches); globals = $globals }
            if ($authMode -eq 'SignedIn') {
                $spec['signedIn'] = @{ tenantId = "$($config.tenantId)" }
                if ($s.azPowerShell) { $spec['azPowerShell'] = @{ mode = 'signedIn'; tenantId = "$($config.tenantId)"; subscriptionId = "$($config.subscriptionId)" } }
            }
            elseif ($s.azPowerShell) { $spec['azPowerShell'] = @{ tenantId = "$($config.tenantId)"; clientId = "$($config.deployIdentity.clientId)"; certThumbprint = "$($config.deployIdentity.certThumbprint)"; subscriptionId = "$($config.subscriptionId)" } }
            $spec | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $argsFile -Encoding UTF8
            $exe = if ($s.host -eq 'powershell') { "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" } else { (Get-Process -Id $PID).Path }
            $launcher = Join-Path $here '_PimInvokeStep.ps1'
            $childArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $launcher, '-Script', $scriptPath, '-ArgsFile', $argsFile)
            if ($s.capturesOutput) { $childArgs += @('-OutFile', $outFile) }
            & $exe @childArgs
            $ok = ($LASTEXITCODE -eq 0)
            Remove-Item -LiteralPath $argsFile -Force -ErrorAction SilentlyContinue   # it may carry a resolved read link
            $output = if ($s.capturesOutput -and (Test-Path -LiteralPath $outFile)) { (Get-Content -LiteralPath $outFile -Raw).Trim() } else { '' }
            Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
        }
        if (-not $ok) {
            Write-Host "`nSTEP FAILED: $($s.id). Fix the cause above, then resume: Invoke-PimMspBuild.ps1 -Role $Role -ConfigPath '$ConfigPath' -Apply -From $($s.id)" -ForegroundColor Red
            $exitCode = 1
            break
        }
        if ($s.capturesOutput) {
            if (-not "$output".Trim()) { Write-Host "`nSTEP FAILED: $($s.id) produced no output for the next step." -ForegroundColor Red; $exitCode = 1; break }
            $Resolved["{{step:$($s.id)}}"] = "$output".Trim()
            Write-Host "    (output captured for the next step; not printed)" -ForegroundColor DarkGray
        }
        Write-Host "    [OK] $($s.id)" -ForegroundColor Green
    }
} finally {
    if (Test-Path -LiteralPath $runDir) {
        foreach ($w in 0, 2, 5) { if ($w) { Start-Sleep -Seconds $w }; Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction SilentlyContinue; if (-not (Test-Path -LiteralPath $runDir)) { break } }
        if (Test-Path -LiteralPath $runDir) { Write-Warning "could not remove the per-run directory $runDir (it holds a certificate PEM) -- delete it." }
    }
    if ($extDir -and -not $prevExtDirSet -and -not $StepRunner) { Remove-Item Env:\AZURE_EXTENSION_DIR -ErrorAction SilentlyContinue }
    if ($prevSubscription -and $prevSubscription -ne "$($config.subscriptionId)") {
        $ErrorActionPreference = 'Continue'; az account set --subscription $prevSubscription -o none 2>$null; $ErrorActionPreference = 'Stop'
    }
}
& $printOps
if ($exitCode) { exit $exitCode }
if ($notRun.Count) {
    Write-Host "`nBUILD INCOMPLETE ($Role): every runnable step succeeded, but these did NOT run: $($notRun -join ', '). See NOT RUN above and the operator steps." -ForegroundColor Yellow
    exit 2
}
Write-Host "`nBUILD COMPLETE ($Role). Work through the operator steps above." -ForegroundColor Green
exit 0
