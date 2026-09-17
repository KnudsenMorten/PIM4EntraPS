#Requires -Version 5.1
<#
.SYNOPSIS
    71.18 -- one way for the MSP build's store-writing setup scripts (Set-PimScenario, Register-PimManagedTenant,
    Initialize-PimHostingAccess) to reach a deployed PIM store AS A CERTIFICATE IDENTITY, verified before use.

.DESCRIPTION
    The identity must be a member of the store's SQL admin group (grp-pim-sql-admins) -- the build's sqlgroup step adds
    the troubleshooting/deploy identity. The token is DECODED and its tenant and app asserted before any statement runs:
    a token for the wrong directory surfaces far away as "permission denied" (SEC-12). Run under Windows PowerShell 5.1
    (System.Data.SqlClient): the same code under pwsh 7 was measured failing login with "connection forcibly closed".
#>

# 🔴 71.32 (rehearsal 2026-09-17) -- THESE DOT-SOURCES MUST BE AT FILE SCOPE, AND THEY WERE INSIDE THE FUNCTION.
# Dot-sourcing INSIDE a function loads the definitions into that function's LOCAL scope, and they are discarded the
# moment it returns. So every caller that did
#     Connect-PimSetupStore ...        # succeeded
#     Get-PimSqlSetting ...            # "The term 'Get-PimSqlSetting' is not recognized"
# failed on the NEXT line, with an error that names a missing cmdlet rather than a scoping mistake. Measured live on
# dp998: the build's `access` step granted all 27 Engine app-roles, all 15 Manager roles and the Jobs Operator
# assignment, then died writing SchedulerTickJobId. The same break is latent in every other store-writing setup
# script -- Set-PimScenario, Register-PimManagedTenant, Set-PimManagerAccess, Set-PimPortalAdmins -- i.e. build steps
# 4, 5 and 8. Dot-sourced here at file scope, the definitions land in the CALLER's script scope, where they are used.
$script:PimSetupSqlRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
foreach ($f in 'PIM-Rest.ps1', 'PIM-ChangeQueue.ps1', 'PIM-SqlStore.ps1') { . (Join-Path $script:PimSetupSqlRoot "engine\_shared\$f") }

function Connect-PimSetupStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SqlServerFqdn,
        [string]$SqlDatabase = 'PimPlatform',
        [Parameter(Mandatory)][string]$TenantId,
        [string]$ClientId,
        [string]$CertThumbprint,
        # 71.33 -- the SIGNED-IN az user instead of a certificate identity (a customer deploying interactively). The
        # user must be a member of the store's SQL admin group; the token's tenant AND user-ness are asserted.
        [switch]$UseSignedInAccount
    )
    if ($UseSignedInAccount) {
        if ("$ClientId".Trim() -or "$CertThumbprint".Trim()) { throw 'Connect-PimSetupStore: -UseSignedInAccount cannot be combined with -ClientId/-CertThumbprint -- pick ONE identity.' }
        if (-not (Get-Command Connect-PimSignedInSql -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '_PimSignedIn.ps1') }
        $who = Connect-PimSignedInSql -TenantId $TenantId
        Write-Host "    store identity: signed-in user $($who.userName) ($($who.objectId))" -ForegroundColor DarkGray
        $global:PIM_SqlServer = "$SqlServerFqdn".Trim(); $global:PIM_SqlDatabase = "$SqlDatabase".Trim()
        return (Get-PimSqlConnectionString -Server $global:PIM_SqlServer -Database $global:PIM_SqlDatabase)
    }
    if (-not "$ClientId".Trim() -or -not "$CertThumbprint".Trim()) {
        throw 'Connect-PimSetupStore: give -ClientId and -CertThumbprint (certificate identity), or -UseSignedInAccount (the signed-in az user).'
    }
    if (-not (Get-Item -LiteralPath "Cert:\LocalMachine\My\$CertThumbprint" -ErrorAction SilentlyContinue)) {
        throw "certificate $CertThumbprint is not in Cert:\LocalMachine\My on this host -- the store cannot be reached by certificate."
    }
    $global:PIM_UseGraphSdk = $false
    $global:PIM_TenantId = "$TenantId".Trim(); $global:PIM_ClientId = "$ClientId".Trim(); $global:PIM_CertThumbprint = "$CertThumbprint".Trim()
    $global:PIM_SqlClientId = $global:PIM_ClientId; $global:PIM_SqlCertThumbprint = $global:PIM_CertThumbprint
    $global:PIM_SqlServer = "$SqlServerFqdn".Trim(); $global:PIM_SqlDatabase = "$SqlDatabase".Trim()
    $tok = Get-PimRestToken -Resource 'https://database.windows.net'
    $seg = "$tok".Split('.')[1].Replace('-', '+').Replace('_', '/'); while ($seg.Length % 4) { $seg += '=' }
    $claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($seg)) | ConvertFrom-Json
    if ("$($claims.tid)" -ne $global:PIM_TenantId -or "$($claims.appid)" -ne $global:PIM_ClientId) {
        throw "REFUSING: the SQL token is for tenant '$($claims.tid)' app '$($claims.appid)', expected '$TenantId' / '$ClientId'."
    }
    return (Get-PimSqlConnectionString -Server $global:PIM_SqlServer -Database $global:PIM_SqlDatabase)
}

function Write-PimSetupAudit {
    # Record a setup write in pim.AuditEvents (the store's own writer). A failed audit WARNS -- the write itself is done
    # and read back; losing the trail must be visible, but must not undo a converged step.
    param([Parameter(Mandatory)][string]$ConnectionString, [Parameter(Mandatory)][string]$Action, [Parameter(Mandatory)][string]$Target, [object]$Before = $null, [object]$After = $null)
    try {
        $actor = if ("$($global:PIM_ClientId)".Trim()) { "$($global:PIM_ClientId)" } else { "$($global:PIM_SetupActor)" }   # 71.33: the signed-in user
        Write-PimSqlAuditEvent -ConnectionString $ConnectionString -Actor $actor -ActorSource 'setup' -Action $Action -Target $Target -Before $Before -After $After
    } catch { Write-Warning "audit '$Action' on '$Target' could not be written: $($_.Exception.Message)" }
}
