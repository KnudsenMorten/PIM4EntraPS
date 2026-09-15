#requires -Version 5.1
<#
.SYNOPSIS
    Add (or update) an MSP admin in the MASTER's pim.CentralAdmins -- the people the downlink
    projects into every managed tenant. Idempotent, and it names the account using the SOLUTION'S
    OWN naming convention rather than a string you typed.

.DESCRIPTION
    🔴 WHY THIS SCRIPT EXISTS. There was no shipped way to add a real MSP admin. `Set-PimPortalAdmins.ps1`
    seeds the PORTAL authorization model (who may use the Manager), which is a different thing, and
    `tests/live/Seed-PimScenarioDataset.ps1` creates SYNTHETIC `PIMSCEN-` admins for the offline
    matrix. So the one step an MSP actually performs -- "add Thomas, Kasper and Morten, and have
    them appear in every customer tenant" -- was a hand-written SQL INSERT. That is the shape of
    step that quietly diverges between tenants and between people.

    🔒 THE NAME IS RESOLVED, NOT TYPED, and that is the point. `Resolve-PimAdminName` renders the
    locked convention (`admin-<initials>-id`, or `admin-<initials>-l0-t0-id` for high-priv). The
    slave's Admins provider builds its live set with `startswith(userPrincipalName, <prefix>)`, so
    an account whose name does not match the convention is INVISIBLE to it -- never in the live
    set, therefore recreated on every tick and left unmanaged in the customer's directory. That is
    IMP-13, and the operator ruling of 2026-09-03 made the prefix mandatory. Typing the name by
    hand is precisely how it gets violated.

    📌 IT ALSO ADDS THE OPTIONAL COLUMNS THE BUNDLE ALREADY EXPECTS. `New-PimBaselineBundle.ps1`
    selects `Target, CreateTap, TapLifetimeHours, ManagerEmail` and falls back with
    "(no CreateTap/TapLifetimeHours/ManagerEmail in pim.CentralAdmins -- the downlink will apply
    its own default)" when they are absent. Absent ManagerEmail means every synced admin relies on
    a single -DefaultManagerEmail, and without even that the engine refuses to mint their TAP
    ("REFUSING to issue a TAP that cannot be delivered"). Per-admin delivery needs the column, so
    this creates it when missing -- additive only, never destructive.

.PARAMETER Initials
    The owner token the convention renders (e.g. 'thpo'). The account name is derived from it.

.PARAMETER ManagerEmail
    Where this admin's TAP is delivered. 🔑 The account itself needs no mailbox: notification and
    TAP mail is SENT FROM the shared sender mailbox TO this address. An empty value means the
    engine will refuse to mint a TAP for them rather than mint one nobody receives.

.PARAMETER Ring
    0 broad / 1 pilot / 2 test. Drives WHICH managed tenants receive this admin.

.PARAMETER HighPriv
    Render the L0/T0 high-privilege name instead of the day-to-day one.

.EXAMPLE
    ./Add-PimCentralAdmin.ps1 -SqlServer sql-ait-wa678.database.windows.net `
        -FirstName Thomas -LastName Poulsen -Initials thpo -Ring 0 -ManagerEmail thomas@efif.dk
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SqlServer,
    [string]$Database = 'PimPlatform',
    [Parameter(Mandatory)][string]$FirstName,
    [Parameter(Mandatory)][string]$LastName,
    [Parameter(Mandatory)][string]$Initials,
    [Parameter(Mandatory)][string]$ManagerEmail,
    [ValidateRange(0,2)][int]$Ring = 2,
    [switch]$HighPriv,
    [ValidateSet('Day2Day','HighPriv')][string]$Purpose,
    [string]$Template,
    [string]$UsageLocation = 'DK',
    [string]$Environment = 'entra',
    [string]$AdminType = 'internal-adminuser',
    [bool]$CreateTap = $true,
    [int]$TapLifetimeHours = 8,
    [string]$Target,                       # MSP-4 targeting axis; empty = every managed tenant
    [string]$MasterUpnDomain,              # for the Upn column; defaults to the initials@server-derived form
    [switch]$List
)

$ErrorActionPreference = 'Stop'
function Step($m){ Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m){ Write-Host "    $m" -ForegroundColor DarkGray }
function Warn($m){ Write-Host "    $m" -ForegroundColor Yellow }

$here    = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$solRoot = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $solRoot 'engine\_shared\PIM-Rest.ps1')
# 🔴 LOAD THE NAMING CONFIG BEFORE THE RESOLVER, LOCKED THEN CUSTOM.
# Resolve-PimAdminName renders from $global:PIM_NamingConventions, which the CONFIG files set --
# not PIM-Naming.ps1 itself. Dot-sourcing only the resolver silently falls back to its built-in
# defaults, and the defaults have no organisation token: MEASURED 2026-09-03, that produced
# 'admin-khrs-id' where this deployment's convention is 'admin-efif-khrs-id'.
# 🪤 It fails in the worst direction: a plausible-looking name that is WRONG. The account is still
# created, still syncs, and is still invisible to any provider scoped to the real convention --
# which is IMP-13's silent tick-loop, introduced by the very script meant to prevent it.
# The custom file OVERRIDES the locked one and is loaded second, exactly as the locked file's own
# header instructs.
foreach ($__cfg in @('config\PIM4EntraPS.NamingConventions.locked.ps1',
                     'config\PIM4EntraPS.NamingConventions.custom.ps1')) {
    $__p = Join-Path $solRoot $__cfg
    if (Test-Path -LiteralPath $__p) { . $__p }
}
. (Join-Path $solRoot 'engine\_shared\PIM-Naming.ps1')

# --- identity: the caller sets the standard PIM globals; we only VERIFY the token ------
$tok = Get-PimRestToken -Resource 'https://database.windows.net'
# 🔴 DECODE BEFORE USE (SEC-12). A fallback once returned a DIFFERENT COMPANY's token, and it
# surfaced far away as "SELECT permission was denied" -- i.e. as an RBAC problem.
$p = $tok.Split('.')[1].Replace('-','+').Replace('_','/'); while ($p.Length % 4) { $p += '=' }
$claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
if ("$($global:PIM_TenantId)".Trim() -and $claims.tid -ne $global:PIM_TenantId) {
    throw "token tenant '$($claims.tid)' != requested '$($global:PIM_TenantId)' -- refusing to write to $SqlServer."
}
Note "token verified: tid=$($claims.tid) appid=$($claims.appid)"
function Q($sql) { Invoke-Sqlcmd -ServerInstance $SqlServer -Database $Database -AccessToken $tok -Encrypt Mandatory -Query $sql -ErrorAction Stop }

if ($List) {
    Step "pim.CentralAdmins on $SqlServer/$Database"
    Q "SELECT UserName, DisplayName, Ring, ISNULL(ManagerEmail,'(none)') AS ManagerEmail FROM pim.CentralAdmins ORDER BY Ring, UserName" |
        Format-Table -AutoSize | Out-String | Write-Host
    return
}

# --- 1) additive columns the bundle already selects -------------------------------------
Step 'ensuring the optional CentralAdmins columns exist (additive only)'
$want = @{
    'Target'           = 'NVARCHAR(400) NULL'
    'CreateTap'        = 'BIT NULL'
    'TapLifetimeHours' = 'INT NULL'
    'ManagerEmail'     = 'NVARCHAR(320) NULL'
    'Owner'            = "NVARCHAR(20) NULL"
}
foreach ($c in $want.Keys) {
    $has = (Q "SELECT COL_LENGTH('pim.CentralAdmins','$c') AS n").n
    if ($null -eq $has -or $has -eq [DBNull]::Value) {
        if ($PSCmdlet.ShouldProcess("pim.CentralAdmins.$c", 'add column')) {
            Q "ALTER TABLE pim.CentralAdmins ADD [$c] $($want[$c])" | Out-Null
            Note "added column $c"
        }
    } else { Note "column $c present" }
}

# --- 2) the NAME comes from the convention ----------------------------------------------
$userName = Resolve-PimAdminName -Owner $Initials -AdminType $AdminType -Environment $Environment -HighPriv:$HighPriv
if (-not "$userName".Trim()) { throw "the naming convention rendered an empty name for initials '$Initials'." }
if (-not $Purpose) { $Purpose = if ($HighPriv) { 'HighPriv' } else { 'Day2Day' } }
$display = "$FirstName $LastName" + $(if ($HighPriv) { ' (L0/T0)' } else { '' })
$upn = if ("$MasterUpnDomain".Trim()) { "$userName@$MasterUpnDomain" } else { $userName }
Step "admin '$userName'  ring=$Ring  purpose=$Purpose  tap->$ManagerEmail"
if (-not "$ManagerEmail".Trim()) {
    Warn 'no -ManagerEmail: the engine will REFUSE to mint this admin a TAP rather than mint one nobody receives.'
}

# --- 3) upsert ---------------------------------------------------------------------------
function Esc($s) { "$s".Replace("'","''") }
$sql = @"
MERGE pim.CentralAdmins AS t
USING (SELECT '$(Esc $userName)' AS UserName) AS s ON t.UserName = s.UserName
WHEN MATCHED THEN UPDATE SET
    DisplayName='$(Esc $display)', Upn='$(Esc $upn)', Ring=$Ring, Enabled=1,
    FirstName='$(Esc $FirstName)', LastName='$(Esc $LastName)', Initials='$(Esc $Initials)',
    UsageLocation='$(Esc $UsageLocation)', Purpose='$(Esc $Purpose)',
    Template=$(if ("$Template".Trim()) { "'$(Esc $Template)'" } else { 'NULL' }),
    Target=$(if ("$Target".Trim()) { "'$(Esc $Target)'" } else { 'NULL' }),
    CreateTap=$(if ($CreateTap) { 1 } else { 0 }), TapLifetimeHours=$TapLifetimeHours,
    ManagerEmail='$(Esc $ManagerEmail)', Owner='MSP', UpdatedAtUtc=SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT
    (UserName, DisplayName, Upn, Ring, Enabled, FirstName, LastName, Initials, UsageLocation,
     Purpose, Template, Target, CreateTap, TapLifetimeHours, ManagerEmail, Owner)
    VALUES ('$(Esc $userName)','$(Esc $display)','$(Esc $upn)',$Ring,1,'$(Esc $FirstName)','$(Esc $LastName)',
            '$(Esc $Initials)','$(Esc $UsageLocation)','$(Esc $Purpose)',
            $(if ("$Template".Trim()) { "'$(Esc $Template)'" } else { 'NULL' }),
            $(if ("$Target".Trim()) { "'$(Esc $Target)'" } else { 'NULL' }),
            $(if ($CreateTap) { 1 } else { 0 }), $TapLifetimeHours, '$(Esc $ManagerEmail)', 'MSP');
"@
if ($PSCmdlet.ShouldProcess($userName, 'upsert central admin')) {
    Q $sql | Out-Null
    $back = Q "SELECT UserName, DisplayName, Ring, Purpose, ManagerEmail, Owner FROM pim.CentralAdmins WHERE UserName='$(Esc $userName)'"
    if (-not $back) { throw "wrote '$userName' but could not read it back." }
    Note "upserted + read back: $($back.UserName) ring=$($back.Ring) purpose=$($back.Purpose) tap->$($back.ManagerEmail) owner=$($back.Owner)"
}
Step 'Done.'
Note 'next: republish the baseline so managed tenants receive this admin --'
Note "  setup/New-PimBaselineBundle.ps1 -CentralServer $SqlServer -Database $Database -StorageAccount <master storage> -Container baselines -Scope fleet"
