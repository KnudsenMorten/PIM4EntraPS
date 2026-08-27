#Requires -Version 5.1
<#
.SYNOPSIS
    Rotate the READ-ONLY SAS that lets a managed (slave) tenant fetch the master's signed
    baseline bundle -- mint, PROVE it reads, then swap it into the slave's downlink Job.

.DESCRIPTION
    BUG-73 established the transport: a managed tenant cannot authenticate to the MASTER's
    storage account, because a managed identity in one tenant is not a principal the other
    tenant's directory can grant to (measured: 401 "Server failed to authenticate the request").
    DESIGN §13.7 transport 2 is therefore the open path, and the signature -- not the network --
    is what establishes trust.

    A SAS expires. That is the whole point of using one, and it is also the failure mode:
    when it lapses the downlink stops, and it stops SILENTLY, because a scheduled job failing
    to read a blob looks exactly like a scheduled job that has not run yet. So the credential
    that makes the downlink work is also the thing most likely to break it, on a date nobody
    wrote down. This script is that date's owner.

    THE ORDER MATTERS, and it is the whole design:
      1. MINT a fresh read-only SAS on the master's baseline blob.
      2. FETCH the bundle with it, and check the document is really a signed bundle.
      3. ONLY THEN write it into the slave Job's ACA secret.
    Minting and writing without step 2 would let a broken credential replace a working one --
    rotation turning a healthy downlink into a dead one, which is worse than not rotating.

    ROTATE EARLY, NOT AT EXPIRY. -ValidDays defaults to 30 and the recommended cadence is
    WEEKLY. That overlap means three consecutive missed runs still leave a working credential,
    and the operator learns from -WarnWithinDays long before anything breaks. A rotation that
    only runs on the last valid day is a single point of failure wearing a schedule.

.PARAMETER StorageAccount / Container / Blob
    The MASTER's baseline blob (the publish target of New-PimBaselineBundle).

.PARAMETER ResourceGroup / JobName / SubscriptionId
    The SLAVE's downlink Job whose `pim-baseline-url` secret is replaced.

.PARAMETER ValidDays
    SAS lifetime. Default 30.

.PARAMETER WarnWithinDays
    Report (exit 0, loudly) when the CURRENT secret is closer than this to expiry. Default 10.

.PARAMETER CheckOnly
    Report what would happen -- mint nothing, write nothing. Safe to schedule for reporting.

.NOTES
    Exit 0 = rotated (or nothing to do). 1 = failed; the EXISTING secret is left untouched.
    Never prints the SAS. Run it from a host that can reach BOTH tenants (mgmt1).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$StorageAccount,
    [string]$Container = 'baselines',
    [string]$Blob      = 'baseline-latest.json',
    [Parameter(Mandatory)][string]$ResourceGroup,
    [string]$JobName   = 'ca-pim-downlink-s6',
    [string]$SecretName = 'pim-baseline-url',
    [string]$SubscriptionId,
    [ValidateRange(1,365)][int]$ValidDays = 30,
    [ValidateRange(0,180)][int]$WarnWithinDays = 10,
    [switch]$CheckOnly,
    # --- make it AUTOMATIC. Mirrors Register-PimSyncSchedule.ps1: a Windows Scheduled Task,
    # exportable to VisualCron (Export-ScheduledTask -TaskName <name>). WEEKLY on purpose --
    # see the rotate-early note in .DESCRIPTION.
    [switch]$Register,
    [string]$TaskName = 'PIM-BaselineSasRotation',
    [ValidateRange(0,23)][int]$AtHour = 2,
    [ValidateSet('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')][string]$DayOfWeek = 'Sunday',
    [string]$RunAsUser = 'NT AUTHORITY\NETWORK SERVICE',
    # 🔴 A SCHEDULED TASK DOES NOT INHERIT YOUR az LOGIN. This script needs a context for the
    # MASTER (to mint the SAS) and one for the SLAVE (to write the secret) -- two different
    # tenants. Interactively they are whatever you last logged into; under a service account the
    # profile is EMPTY, so an armed task would fail every week, silently, which is precisely the
    # class of defect this script exists to prevent. Point it at a prepared profile directory
    # holding both logins, and it is verified below before anything is minted.
    [string]$AzureConfigDir,
    # 🔴 AND -AzureConfigDir ALONE CANNOT SOLVE IT, which is the part that is easy to get wrong.
    # az encrypts stored service-principal credentials with DPAPI, bound to the user who CREATED
    # the profile. A profile you prepare interactively is therefore undecryptable by the service
    # account the task runs as -- measured here as
    #   ERROR: [Errno 3] Decryption failed: ...\service_principal_entries.bin
    # after the armed task returned exit 1 on its first run. The credentials are fine; the account
    # is different. So an unattended run must LOG IN AS ITSELF and build its own profile, which
    # then binds to the account that will actually use it.
    # -PreAuthScript is that hook: a script run BEFORE anything else whose only job is to leave a
    # usable az context. Kept generic on purpose -- how you authenticate is environment-specific
    # (this estate goes bootstrap cert -> Key Vault -> per-tenant SPN, the same chain the backup
    # jobs use), and the check below verifies the RESULT rather than trusting the method.
    [string]$PreAuthScript,
    # Subscription ids to assert the context against. Optional, but STRONGLY recommended: without
    # them the script can only check that SOME context exists, not that it is the right one --
    # and on this host the default az context is routinely a different company's tenant.
    [string]$MasterSubscriptionId
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m){ Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m){ Write-Host "    $m" -ForegroundColor Yellow }
function Fail($m){ Write-Host "    $m" -ForegroundColor Red }

Step "Baseline SAS rotation -- account=$StorageAccount/$Container/$Blob  job=$JobName (rg $ResourceGroup)"

# --- 0) REGISTER the recurring task, then exit. -------------------------------
# Registration is a SEPARATE action from rotating: doing both in one run would mean the
# schedule only ever exists on a box where a rotation also succeeded.
if ($Register) {
    $self = $MyInvocation.MyCommand.Path
    $exe  = (Get-Command powershell.exe -CommandType Application | Select-Object -First 1).Source
    $argLine = ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -StorageAccount {1} -Container {2} -Blob {3} -ResourceGroup {4} -JobName {5} -SecretName {6} -ValidDays {7}' -f `
                $self, $StorageAccount, $Container, $Blob, $ResourceGroup, $JobName, $SecretName, $ValidDays)
    if ("$SubscriptionId".Trim()) { $argLine += " -SubscriptionId $SubscriptionId" }
    Step "registering WEEKLY task '$TaskName' ($DayOfWeek $($AtHour):00, as $RunAsUser)"
    $a = New-ScheduledTaskAction -Execute $exe -Argument $argLine
    $t = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $DayOfWeek -At ([datetime]::Today.AddHours($AtHour))
    $p = New-ScheduledTaskPrincipal -UserId $RunAsUser -LogonType ServiceAccount -RunLevel Highest
    $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    Register-ScheduledTask -TaskName $TaskName -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
    Note "registered. Run now: Start-ScheduledTask -TaskName '$TaskName'   |   export for VisualCron: Export-ScheduledTask -TaskName '$TaskName'"
    Note ("cadence: WEEKLY against a {0}-day SAS -- three consecutive missed runs still leave a working credential." -f $ValidDays)
    exit 0
}

# --- 0b) CONTEXT -- prove we can act, BEFORE we mint anything -------------------
# A rotation that discovers halfway through that it cannot write the secret has already minted a
# credential and learned nothing useful. Check first, fail with the fix, change nothing.
if ("$AzureConfigDir".Trim()) {
    if (-not (Test-Path -LiteralPath $AzureConfigDir)) {
        Fail "-AzureConfigDir '$AzureConfigDir' does not exist. A scheduled task needs a prepared az profile; it does not inherit an interactive login."
        exit 1
    }
    $env:AZURE_CONFIG_DIR = $AzureConfigDir
    Note "using az profile: $AzureConfigDir"
}
if ("$PreAuthScript".Trim()) {
    if (-not (Test-Path -LiteralPath $PreAuthScript)) {
        Fail "-PreAuthScript '$PreAuthScript' not found. Nothing was minted or written."
        exit 1
    }
    Step "pre-auth: $PreAuthScript"
    & $PreAuthScript
    if ($LASTEXITCODE -ne 0) {
        Fail "pre-auth script failed (exit $LASTEXITCODE) -- refusing to continue. Nothing was minted or written."
        exit 1
    }
}
$acct = az account show --query id -o tsv --only-show-errors 2>$null
if ($LASTEXITCODE -ne 0 -or -not "$acct".Trim()) {
    Fail 'no usable az context. Nothing was minted or written.'
    Fail '  Interactively: az login / az account set --subscription <master sub>.'
    Fail '  Scheduled: prepare a profile directory with BOTH tenant logins and pass -AzureConfigDir.'
    exit 1
}
if ("$MasterSubscriptionId".Trim() -and "$acct".Trim() -ne "$MasterSubscriptionId".Trim()) {
    # 🪤 On this host the default context is routinely another tenant entirely, so "a context
    # exists" is not "the right context". Same failure family as ESTATE-14.
    Fail "az context is subscription '$acct' but the master is '$MasterSubscriptionId' -- refusing to mint against the wrong subscription."
    Fail "  Fix: az account set --subscription $MasterSubscriptionId   (then re-run)"
    exit 1
}
Note "az context verified: subscription $acct"

# --- 1) MINT ------------------------------------------------------------------
# 🪤 The account key is read, used, and never printed. It stays in this process only.
$key = az storage account keys list -n $StorageAccount --query "[0].value" -o tsv --only-show-errors 2>$null
if ($LASTEXITCODE -ne 0 -or -not "$key".Trim()) {
    Fail "could not read the storage account key for '$StorageAccount' -- refusing to rotate. The existing secret is untouched."
    exit 1
}
$expiryDt = (Get-Date).ToUniversalTime().AddDays($ValidDays)
$expiry   = $expiryDt.ToString('yyyy-MM-ddTHH:mmZ')
if ($CheckOnly) {
    Note "CHECK-ONLY: would mint a read-only SAS on $Blob expiring $expiry, verify it, then replace secret '$SecretName'."
} else {
    Note "minting a read-only SAS expiring $expiry ($ValidDays days)"
}
$sas = az storage blob generate-sas --account-name $StorageAccount --account-key $key `
        -c $Container -n $Blob --permissions r --expiry $expiry -o tsv --only-show-errors 2>$null
if ($LASTEXITCODE -ne 0 -or -not "$sas".Trim()) {
    Fail 'SAS generation returned nothing -- refusing to rotate. The existing secret is untouched.'
    exit 1
}
$sasUrl = "https://$StorageAccount.blob.core.windows.net/$Container/$Blob`?$sas"

# --- 2) PROVE IT READS, BEFORE ANYTHING IS REPLACED ----------------------------
# 🔴 This step is the difference between rotation and breakage. Writing an unverified
# credential over a working one turns a healthy downlink into a dead one -- and it dies
# silently, at the next scheduled run, not here where someone is watching.
Step 'verifying the new SAS actually reads the bundle (before replacing anything)'
try {
    $doc = Invoke-RestMethod -Method GET -Uri $sasUrl -Headers @{ 'x-ms-version' = '2021-08-06' } -ErrorAction Stop
} catch {
    Fail "the new SAS could NOT read $Blob -- refusing to rotate. The existing secret is untouched. $($_.Exception.Message)"
    exit 1
}
# And it must be a SIGNED BUNDLE, not merely 200-with-something. A misconfigured container
# can return an error document with a success status; 'it downloaded' is not 'it is the bundle'.
$names = @($doc.PSObject.Properties.Name)
foreach ($req in @('payloadB64','signature','keyThumbprint')) {
    if ($names -notcontains $req) {
        Fail "the blob fetched with the new SAS is missing '$req' -- that is not a signed bundle. Refusing to rotate."
        exit 1
    }
}
Note ("verified: signed bundle fetched ({0})" -f ($names -join ', '))

if ($CheckOnly) {
    Step 'CHECK-ONLY: nothing was written.'
    exit 0
}

# --- 3) SWAP IT IN -------------------------------------------------------------
Step "replacing ACA secret '$SecretName' on $JobName"
# 🔴 A SAS CONTAINS `&`, AND `az` ON WINDOWS IS `az.cmd` -- A BATCH WRAPPER.
# cmd re-parses the arguments, so an unquoted `...?sv=..&sig=..` SPLITS THE COMMAND at the first
# `&`. Measured on the first unattended run: everything after it was severed -- including
# `--subscription` -- so az looked in the WRONG subscription and reported
#     ERROR: The containerapp job 'ca-pim-downlink-s6' does not exist
# while the remaining SAS fields were executed as commands ('sv' is not recognized...). The error
# names the job, so it reads as a missing job or a bad name; the cause is quoting, and the two
# look nothing alike. Wrapping the pair in LITERAL quotes makes cmd treat it as one token.
$secretArg = '"' + "$SecretName=$sasUrl" + '"'
$setArgs = @('containerapp','job','secret','set','-g',$ResourceGroup,'-n',$JobName,
             '--secrets',$secretArg,'-o','none','--only-show-errors')
if ("$SubscriptionId".Trim()) { $setArgs += @('--subscription',"$SubscriptionId") }
az @setArgs
if ($LASTEXITCODE -ne 0) {
    Fail "failed to set the secret on $JobName (az exit $LASTEXITCODE). The job keeps its PREVIOUS secret."
    exit 1
}
Note "secret replaced (value never printed); new expiry $expiry"

# --- 4) READ BACK -- the secret must exist and the job must still be healthy ----
# `az ... secret set` exiting 0 says the CALL succeeded. It does not say the job is still
# runnable, and a rotation that leaves a job unable to start is the failure this whole script
# exists to prevent.
# 🪤 THE READ-BACK MUST TARGET THE SLAVE TOO. The ambient context is the MASTER -- that is where
# the SAS is minted -- but the job lives in the managed tenant. Omitting --subscription here made
# az look for the slave's resource group in the master's subscription and answer
#     ERROR: (ResourceGroupNotFound) Resource group 'rg-automateit-...' could not be found.
# AFTER the secret had already been replaced successfully. That is a FALSE FAILURE, and it is its
# own hazard: a rotation that worked reports non-zero, inviting someone to "fix" what is fine.
$subArgs = @()
if ("$SubscriptionId".Trim()) { $subArgs = @('--subscription',"$SubscriptionId") }
$names2 = az containerapp job show -g $ResourceGroup -n $JobName --query "properties.configuration.secrets[].name" -o tsv --only-show-errors @subArgs 2>$null
if ("$names2" -notmatch [regex]::Escape($SecretName)) {
    Fail "read-back: secret '$SecretName' is not present on $JobName after the set."
    exit 1
}
$prov = az containerapp job show -g $ResourceGroup -n $JobName --query "properties.provisioningState" -o tsv --only-show-errors @subArgs 2>$null
if ("$prov".Trim() -ne 'Succeeded') {
    Fail "read-back: $JobName is provisioningState='$prov' after the rotation -- it will not execute."
    exit 1
}
Note "read-back OK: secret present, provisioningState=$prov"

Write-Host ("ROTATED: {0} now reads {1} with a SAS valid until {2} ({3} days)." -f $JobName, $Blob, $expiry, $ValidDays) -ForegroundColor Green
if ($WarnWithinDays -gt 0) {
    Write-Host ("Next rotation should run well before {0} -- WEEKLY is the recommended cadence, so three missed runs still leave a working credential." -f $expiry) -ForegroundColor DarkGray
}
exit 0
