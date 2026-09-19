#Requires -Version 5.1
<#
.SYNOPSIS
  The OUT-OF-BAND operator route for the break-glass ACCOUNT list (pim.Settings['BreakGlassAccounts']).

.DESCRIPTION
  In the Manager a change to the break-glass list is MAKER/CHECKER (operator 2026-09-19): one SuperAdmin
  raises a request, a SECOND SuperAdmin approves it, and only then does it apply
  (engine/_shared/PIM-BreakGlassChange.ps1). That is the normal route.

  This script is the documented EMERGENCY / BOOTSTRAP route, for when the Manager route cannot work:
    * an environment with only ONE SuperAdmin (nobody can approve);
    * a Manager that is down while an emergency account has to be protected now.
  It needs what the Manager cannot give a single person: direct write access to the store (the SQL admin
  app's certificate, or a signed-in member of the SQL admin group). Every write is AUDITED
  (pim.AuditEvents, action 'breakglass.accounts.set', ActorSource 'setup') with the justification.

  SAME SAFETY RULES AS THE OTHER STORE-WRITING SETUP SCRIPTS (Set-PimManagerAccess.ps1, Set-PimLicense.ps1):
    * Input is validated BEFORE the store is contacted (each entry a UPN or an object id; an empty list
      only with -ConfirmEmpty -- it removes the protection from every emergency account).
    * A store that cannot be read is not written.
    * -WhatIf shows the diff and writes nothing.
    * It reads back and compares. A write that is not verified is a hope.
    * The write is a compare-and-set against the list it read, so a change made in between is refused.
  An OPEN Manager request is reported: after this write its snapshot no longer matches, so the Manager
  will refuse to approve it ("the list changed since the request was made -- raise a new request").

.PARAMETER Accounts
  The COMPLETE new list (UPNs and/or object ids). It replaces the stored list.
.PARAMETER Justification
  Why. Required -- recorded on the audit event.
.PARAMETER ConfirmEmpty
  Required to store an EMPTY list.
.PARAMETER ConnectionString
  A ready connection string to the store (e.g. a local SQL Server with Integrated security).
.PARAMETER SqlServer
  The store's server instead of -ConnectionString. An Azure SQL FQDN connects with a token -- as the admin
  app (-TenantId -AdminAppId -AdminCertThumbprint) or as the signed-in az user (-UseSignedInAccount).

.EXAMPLE
  pwsh -File Set-PimBreakGlassAccounts.ps1 -SqlServer sql-x.database.windows.net -TenantId <t> `
       -AdminAppId <appid> -AdminCertThumbprint <thumb> `
       -Accounts 'breakglass01@contoso.onmicrosoft.com','breakglass02@contoso.onmicrosoft.com' `
       -Justification 'only one SuperAdmin in this environment' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [AllowEmptyCollection()][string[]]$Accounts = @(),
    [string]$Justification,
    [switch]$ConfirmEmpty,
    [string]$ConnectionString,
    [Alias('SqlServerFqdn')][string]$SqlServer,
    [Alias('SqlDatabase')][string]$Database = 'PimPlatform',
    [string]$TenantId,
    [string]$AdminAppId,
    [string]$AdminCertThumbprint,
    [switch]$UseSignedInAccount,
    [string]$OutFile
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $PSCommandPath
$sol  = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $sol 'engine\_shared\PIM-Rest.ps1')
. (Join-Path $sol 'engine\_shared\PIM-SqlStore.ps1')
. (Join-Path $sol 'engine\_shared\PIM-BreakGlassAccounts.ps1')
. (Join-Path $sol 'engine\_shared\PIM-BreakGlassChange.ps1')

function Invoke-PimBreakGlassAccountsSetup {
    <#
      Validate, read, diff, (write with compare-and-set, audited as 'setup'), read back. Returns the outcome;
      THROWS on any failure (invalid input, an unreadable store, a refused write, a read-back mismatch).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConnectionString,
        [AllowEmptyCollection()][string[]]$Accounts = @(),
        [string]$Justification = '',
        [Parameter(Mandatory)][string]$Actor,
        [switch]$ConfirmEmpty,
        [switch]$WhatIfOnly
    )
    # 1. Validate BEFORE the store is contacted.
    if (-not "$Justification".Trim()) { throw 'a -Justification is required -- this list exempts accounts from every disable, revoke and offboard guard' }
    $bad = @(@($Accounts) | Where-Object { "$_".Trim() -and -not (Test-PimBreakGlassAccountEntry -Value "$_") })
    if ($bad.Count) { throw ("invalid break-glass entr{0}: {1} -- each entry must be a UPN or an object id" -f $(if ($bad.Count -eq 1) { 'y' } else { 'ies' }), ($bad -join ', ')) }
    $new = @(ConvertTo-PimBreakGlassList -Value @($Accounts))
    if ($new.Count -eq 0 -and -not $ConfirmEmpty) { throw 'an EMPTY list removes the protection from every emergency account -- pass -ConfirmEmpty if that is really the intent' }

    # 2. Read what is there (a store that cannot be read is not written).
    $state = $null
    try { $state = Get-PimBreakGlassStoredListState -ConnectionString $ConnectionString }
    catch { throw "could not read the stored list ($($_.Exception.Message)) -- nothing was written" }
    $diff = Get-PimBreakGlassListDiff -Current $state.accounts -Proposed $new
    $openNote = ''
    try {
        $rq = Get-PimBreakGlassChangeRequest -ConnectionString $ConnectionString
        if ($rq.open) { $openNote = "an open Manager request raised by $($rq.request.maker) (expires $($rq.request.expiresUtc)) -- after this write it will be refused as stale" }
    } catch { $openNote = "the Manager's change request could not be read: $($_.Exception.Message)" }
    $out = [ordered]@{ ok = $false; stored = $false; whatIf = [bool]$WhatIfOnly; before = @($state.accounts); accounts = @($new)
                       added = @($diff.added); removed = @($diff.removed); changed = [bool]$diff.changed; openRequest = $openNote }
    if ($WhatIfOnly) { $out.ok = $true; return [pscustomobject]$out }
    if (-not $diff.changed) { $out.ok = $true; return [pscustomobject]$out }

    # 3. Write -- compare-and-set against the list just read, audited as 'setup'.
    [void](Set-PimBreakGlassAccountList -ConnectionString $ConnectionString -Accounts $new -ExpectedSnapshotHash $state.hash `
            -Actor $Actor -ActorSource 'setup' -AuditDetail @{ justification = "$Justification".Trim(); route = 'tools/setup/Set-PimBreakGlassAccounts.ps1'; added = @($diff.added); removed = @($diff.removed) })

    # 4. Read back.
    $back = Get-PimBreakGlassStoredListState -ConnectionString $ConnectionString
    if ($back.hash -ne (Get-PimBreakGlassListHash -Accounts $new)) { throw "read-back mismatch: the store holds '$(@($back.accounts) -join ', ')', not the list that was written" }
    $out.ok = $true; $out.stored = $true; $out.accounts = @($back.accounts)
    return [pscustomobject]$out
}

# Dot-sourced (the offline test): define the functions, run nothing.
if ($MyInvocation.InvocationName -eq '.') { return }

$result = [ordered]@{ ok = $false; reason = ''; whatIf = [bool]$WhatIfPreference }
function Write-ResultFile { if ("$OutFile".Trim()) { try { $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutFile -Encoding UTF8 } catch {} } }
function Fail($m) { $result.reason = $m; Write-ResultFile; Write-Host "RESULT: FAILED -- $m" -ForegroundColor Red; exit 1 }
function Note($m, $c = 'Gray') { Write-Host "  $m" -ForegroundColor $c }

Write-Host "=== PIM break-glass accounts -> pim.Settings['BreakGlassAccounts'] (operator route, audited as 'setup') ===" -ForegroundColor Cyan

# --- the store ------------------------------------------------------------------------------
$cs = ''
$actor = ''
if ("$ConnectionString".Trim()) {
    if ("$SqlServer".Trim()) { Fail 'supply -ConnectionString OR -SqlServer, not both' }
    $cs = "$ConnectionString"
    try { $actor = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $actor = "$env:USERNAME" }
} elseif ("$SqlServer".Trim()) {
    $global:PIM_SqlServer   = $SqlServer
    $global:PIM_SqlDatabase = $Database
    if ($SqlServer -match '(?i)database\.windows\.net') {
        if (-not "$TenantId".Trim()) { Fail 'an Azure SQL store needs -TenantId (token auth)' }
        if ($UseSignedInAccount) {
            if ("$AdminAppId".Trim() -or "$AdminCertThumbprint".Trim()) { Fail '-UseSignedInAccount cannot be combined with -AdminAppId/-AdminCertThumbprint' }
            . (Join-Path $here '_PimSignedIn.ps1')
            try { $who = Connect-PimSignedInSql -TenantId $TenantId; $actor = "$($who.userName)"; Note "store identity: signed-in user $actor" 'DarkGray' } catch { Fail "$($_.Exception.Message)" }
        } else {
            if (-not "$AdminAppId".Trim() -or -not "$AdminCertThumbprint".Trim()) { Fail 'supply -AdminAppId with -AdminCertThumbprint (certificate auth), or -UseSignedInAccount' }
            $global:PIM_TenantId       = $TenantId
            $global:PIM_ClientId       = $AdminAppId
            $global:PIM_CertThumbprint = $AdminCertThumbprint
            $actor = "app:$AdminAppId"
        }
    } else {
        try { $actor = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { $actor = "$env:USERNAME" }
    }
    try { $cs = Get-PimSqlConnectionString -Server $SqlServer -Database $Database }
    catch { Fail "could not build a connection string: $($_.Exception.Message)" }
} else { Fail 'supply -SqlServer (with -Database) or -ConnectionString' }
if (-not "$actor".Trim()) { $actor = 'setup' }

# --- validate, read, write, read back --------------------------------------------------------
$whatIfOnly = [bool]$WhatIfPreference -or -not $PSCmdlet.ShouldProcess("pim.Settings['BreakGlassAccounts']", 'replace the break-glass account list')
try { $r = Invoke-PimBreakGlassAccountsSetup -ConnectionString $cs -Accounts $Accounts -Justification $Justification -Actor $actor -ConfirmEmpty:$ConfirmEmpty -WhatIfOnly:$whatIfOnly }
catch { Fail "$($_.Exception.Message)" }

foreach ($k in $r.PSObject.Properties.Name) { $result[$k] = $r.$k }
Note ("stored now : " + $(if (@($r.before).Count) { @($r.before) -join ', ' } else { '(none)' })) 'DarkGray'
Note ("add        : " + $(if (@($r.added).Count) { @($r.added) -join ', ' } else { '-' })) 'Gray'
Note ("remove     : " + $(if (@($r.removed).Count) { @($r.removed) -join ', ' } else { '-' })) $(if (@($r.removed).Count) { 'Yellow' } else { 'Gray' })
if ("$($r.openRequest)".Trim()) { Note "NOTE: $($r.openRequest)" 'Yellow' }
if ($r.whatIf) {
    $result.ok = $true; $result.reason = 'what-if -- nothing written'
    Write-ResultFile; Write-Host "RESULT: WHAT-IF -- nothing written" -ForegroundColor Yellow; exit 0
}
if (-not $r.changed) {
    $result.ok = $true; $result.reason = 'the stored list already matches -- nothing written'
    Write-ResultFile; Write-Host "RESULT: OK -- $($result.reason)" -ForegroundColor Green; exit 0
}
$result.ok = $true
$result.reason = "stored and read back: $(@($r.accounts).Count) account(s); audited as '$actor' (ActorSource setup)"
Write-ResultFile
Write-Host "RESULT: OK -- $($result.reason)" -ForegroundColor Green
Write-Host "  NOTE: the Manager and the engine read the list on their next check (within a minute)." -ForegroundColor DarkGray
exit 0
