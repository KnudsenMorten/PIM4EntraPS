#Requires -Version 5.1
<#
  BUG-73b -- automatic rotation of the baseline SAS (tools/setup/Update-PimBaselineSas.ps1).

  WHY THESE ASSERTIONS AND NOT OTHERS. A SAS expires by design, so the credential that makes the
  downlink work is also the thing most likely to break it -- and it breaks SILENTLY, because a
  scheduled job that cannot read a blob looks exactly like one that has not run yet. The risk in a
  rotation script is therefore not "does it mint a SAS"; it is that rotation itself REPLACES a
  working credential with a broken one. So what is asserted here is the ORDER (verify before
  write) and the FAIL-SAFE (on any failure, leave the existing secret alone).

  OFFLINE: source + parse only. No az, no Azure, no network -- same contract as the other
  deploy-tooling suites.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Off

$here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$sol  = Split-Path -Parent $here
$script:Path = Join-Path $sol 'tools\setup\Update-PimBaselineSas.ps1'

$script:pass = 0; $script:fail = 0
function T([string]$Name, [scriptblock]$Body) {
    $ok = $false
    try { $ok = [bool](& $Body) } catch { $ok = $false }
    if ($ok) { $script:pass++; Write-Host "  PASS $Name" -ForegroundColor Green }
    else     { $script:fail++; Write-Host "  FAIL $Name" -ForegroundColor Red }
}

Write-Host '== BUG-73b -- baseline SAS rotation ==' -ForegroundColor Cyan

T 'the script exists' { Test-Path -LiteralPath $script:Path }

$errs = $null
[System.Management.Automation.Language.Parser]::ParseFile($script:Path, [ref]$null, [ref]$errs) | Out-Null
T 'parses clean' { @($errs).Count -eq 0 }

# CODE-ONLY view: the comments here explain the very defects being asserted, so a raw-text scan
# would pass on the documentation instead of the code (the recorded trap).
$tokens = $null; $e2 = $null
[System.Management.Automation.Language.Parser]::ParseFile($script:Path, [ref]$tokens, [ref]$e2) | Out-Null
$code = ((@($tokens) | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' ')
T 'the comment-stripper dropped comments (mechanism, proven before it is relied on)' {
    ($code -notmatch 'silently, because a scheduled job') -and ($code -match 'generate-sas')
}

# --- THE ORDER IS THE DESIGN -------------------------------------------------
$posMint   = $code.IndexOf('generate-sas')
$posVerify = $code.IndexOf('Invoke-RestMethod')
$posWrite  = $code.IndexOf('secret')
T 'it MINTS before it verifies' { $posMint -ge 0 -and $posVerify -gt $posMint }
T 'it VERIFIES the fetch BEFORE writing the secret' {
    $posSet = $code.IndexOf("'set'")
    $posSet -gt $posVerify -and $posVerify -gt 0
}
T 'it checks the fetched document IS a signed bundle, not merely a 200' {
    ($code -match 'payloadB64') -and ($code -match 'signature') -and ($code -match 'keyThumbprint')
}

# --- FAIL-SAFE: a failure must never leave the job worse off -----------------
T 'a failed mint refuses to rotate and says the secret is untouched' {
    $code -match 'refusing to rotate'
}
T 'a failed VERIFY refuses to rotate (the credential is not written)' {
    # the verify catch block must exit non-zero rather than continue to the write
    $code -match '(?s)could NOT read.*?exit 1'
}
T 'a failed secret-set reports that the PREVIOUS secret is still in place' {
    $code -match 'keeps its PREVIOUS secret'
}

# --- READ-BACK: "az exited 0" is not "the job still runs" --------------------
T 'it reads back that the secret is present after the set' {
    $code -match 'properties\.configuration\.secrets'
}
T 'it reads back provisioningState, because a rotation must not leave a dead job' {
    ($code -match 'properties\.provisioningState') -and ($code -match "-ne 'Succeeded'")
}

# --- SECRECY -----------------------------------------------------------------
T 'the SAS is never written to output' {
    # no Write-Host/Note of $sasUrl or $sas; the account key likewise
    ($code -notmatch 'Write-Host[^\r\n]*\$sasUrl') -and ($code -notmatch 'Note[^\r\n]*\$sasUrl') -and
    ($code -notmatch 'Write-Host[^\r\n]*\$key\b')
}

# --- AUTOMATIC ---------------------------------------------------------------
T 'it can REGISTER itself as a recurring task (that is what "automatic" means)' {
    ($code -match 'Register-ScheduledTask') -and ($code -match 'New-ScheduledTaskTrigger')
}
T 'the cadence is WEEKLY against a longer-lived SAS, so a missed run is survivable' {
    # rotate-early: weekly trigger, and a default validity well beyond one week
    ($code -match '-Weekly') -and ($code -match '\$ValidDays\s*=\s*30')
}
T 'registration EXITS instead of also rotating in the same run' {
    $code -match '(?s)\$Register.*?exit 0'
}
T '-CheckOnly writes nothing' {
    $code -match '(?s)CheckOnly.*?nothing was written'
}

# --- CONTEXT: an armed task does NOT inherit an interactive az login ---------
# The whole point of arming this is that it runs unattended. If it cannot establish the right
# context it must say so and change nothing -- an armed task that fails silently every week is
# worse than no rotation, because the expiry date then has an owner who is not doing the job.
T 'it verifies an az context EXISTS before minting anything' {
    ($code -match 'az account show') -and ($code -match 'no usable az context')
}
T 'it verifies the context is the RIGHT subscription, not merely present' {
    ($code -match '\$MasterSubscriptionId') -and ($code -match 'refusing to mint against the wrong subscription')
}
T 'the context check happens BEFORE the mint (nothing is created to then be abandoned)' {
    $code.IndexOf('az account show') -lt $code.IndexOf('generate-sas')
}
T 'it accepts a prepared profile dir for unattended runs, and fails if it is absent' {
    ($code -match '\$AzureConfigDir') -and ($code -match 'AZURE_CONFIG_DIR') -and ($code -match 'does not exist')
}

# Whitespace-removed view: the tokenizer re-spaces source, so a literal regex over its output
# would test the tokenizer's formatting rather than the code.
$flat = $code -replace '\s',''
T 'the secret argument is LITERALLY QUOTED (a SAS contains & and az is a .cmd wrapper)' {
    # Unquoted, cmd splits the command at the first `&`: --subscription is severed, az looks in
    # the wrong subscription and says the JOB DOES NOT EXIST -- an error that names the job while
    # the cause is quoting. Measured on the first unattended run.
    $flat -match '\$secretArg=''"''\+'
}
T 'the quoted pair is what is passed to --secrets (not the raw value)' {
    $flat -match '''--secrets'',\$secretArg'
}
T 'the READ-BACK calls target the slave subscription explicitly' {
    # The ambient context is the MASTER (that is where the SAS is minted), but the job lives in
    # the SLAVE. Read-backs that omit --subscription reported ResourceGroupNotFound and turned a
    # SUCCESSFUL rotation into a non-zero exit -- a false failure, which is its own hazard: it
    # invites someone to "fix" a rotation that actually worked.
    # both read-backs must carry the subscription splat, not just one of them
    ($flat -match '\$subArgs=@\(''--subscription''') -and
    ([regex]::Matches($flat,'@subArgs')).Count -ge 2
}

Write-Host ''
Write-Host ("BASELINE SAS ROTATION TESTS: {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor Cyan
if ($script:fail) { exit 1 }
exit 0
