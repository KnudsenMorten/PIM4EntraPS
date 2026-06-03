#Requires -Version 5.1
<#
.SYNOPSIS
    CSV-driven Intune Remediation deployer for PIM Activator multi-tenant
    rollout. One source of truth (tenants.csv), three modes:

      -GenerateScripts         Emit Detection.ps1 + Remediation.ps1 to disk so
                               you can upload them via the Intune UI yourself.

      -CreateIntuneRemediation Push a brand-new Intune Remediation containing
                               both scripts, schedule it hourly, assign to a
                               security group. Prints the remediation id (save
                               it for later -UpdateIntuneRemediation runs).

      -UpdateIntuneRemediation Re-read tenants.csv and overwrite an EXISTING
                               Intune Remediation's scripts in place. This is
                               the "add a tenant" command: edit CSV, run this,
                               done. Clients self-heal on the next check
                               (hourly by default).

.DESCRIPTION
    The remediation pair (Detection + Remediation) writes / repairs the
    Chromium policy registry keys that drive the PIM Activator extension's
    forcelist install + multi-tenant Tenants array:

      HKCU\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist\<slot>
      HKCU\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\<id>\policy\Tenants
      HKCU\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist\<slot>
      HKCU\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\<id>\policy\Tenants

    Detection script compares the on-disk Tenants JSON against the desired
    JSON (baked in from tenants.csv at generation time). Drift -> exit 1 ->
    Intune fires the remediation, which rewrites every key from scratch.

    Schedule: every 1 hour by default (-IntervalHours overrides). Faster than
    the 8-hour MDM sync because Remediations run on their own scheduler.

.PARAMETER TenantsCsv
    CSV file with columns: Name,TenantId,ClientId. One row per tenant.
    Friendly name shows in the popup picker; tenant + client are the auth
    target. Required by every mode.

.PARAMETER ExtensionId
    32-char Chromium extension id (lowercase a-p). Default is the deterministic
    id derived from this repo's signing key.

.PARAMETER UpdateUrl
    The update.xml URL the extension auto-updates from. Default is the
    canonical gh-pages URL for this repo.

.PARAMETER OutputDir
    For -GenerateScripts: where to write Detection.ps1 + Remediation.ps1.
    Default: .\out-remediation

.PARAMETER GroupId
    Microsoft Entra security group id. -CreateIntuneRemediation assigns the
    new remediation to this group. Required for -CreateIntuneRemediation.

.PARAMETER RemediationId
    Existing remediation id (from a prior -CreateIntuneRemediation run, also
    visible in Intune Admin Center -> Devices -> Scripts and remediations).
    Required for -UpdateIntuneRemediation.

.PARAMETER IntervalHours
    Remediation schedule interval, hours. Default 1 (hourly check). Range 1-24.

.PARAMETER DisplayName
    Friendly name shown in Intune Admin Center for the remediation. Default
    'PIM Activator -- forcelist + Tenants policy'.

.PARAMETER Description
    Description in Intune Admin Center. Default summarises behaviour + the
    tenant list count.

.PARAMETER RunAsAccount
    'user' (default, HKCU) or 'system' (HKLM). Recommended 'user' so that
    HKCU policy survives roaming profiles and works under non-admin accounts.

.PARAMETER GroupNameFilter
    Regex limiting which eligible groups appear. Default ^PIM-.

.PARAMETER DefaultDurationHours
    Default duration shown in the popup. Default 1.

.PARAMETER DefaultJustification
    Default justification text. Default 'Daily ops'.

.EXAMPLE
    # First time: generate the script pair to inspect before uploading.
    .\Deploy-PimActivatorIntune.ps1 -GenerateScripts -TenantsCsv .\tenants.csv

.EXAMPLE
    # First time on Intune: create + assign in one shot.
    .\Deploy-PimActivatorIntune.ps1 -CreateIntuneRemediation `
        -TenantsCsv .\tenants.csv `
        -GroupId 11111111-2222-3333-4444-555555555555
    # ...prints: Remediation id: <guid> -- save this for future -UpdateIntuneRemediation

.EXAMPLE
    # Add a tenant: edit tenants.csv, then push the change to Intune. Hourly
    # check means clients converge within ~1h without any user action.
    .\Deploy-PimActivatorIntune.ps1 -UpdateIntuneRemediation `
        -TenantsCsv .\tenants.csv `
        -RemediationId <existing-remediation-guid>

.NOTES
    Uses Microsoft.Graph.Beta.DeviceManagement (deviceHealthScripts /
    deviceHealthScriptAssignments live on the beta endpoint). Authenticates
    with Connect-MgGraph -- the signed-in user needs DeviceManagementScripts
    .ReadWrite.All consent. Install:
        Install-Module Microsoft.Graph.Beta.DeviceManagement -Scope CurrentUser
#>
[CmdletBinding(DefaultParameterSetName='GenerateScripts')]
param(
    [Parameter(Mandatory)]
    [string]$TenantsCsv,

    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId = 'hkdglhgahonnjbfindmgplekkcngmcck',

    [string]$UpdateUrl = 'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml',

    [Parameter(ParameterSetName='GenerateScripts')]
    [switch]$GenerateScripts,

    [Parameter(ParameterSetName='GenerateScripts')]
    [string]$OutputDir = (Join-Path (Get-Location) 'out-remediation'),

    [Parameter(Mandatory, ParameterSetName='CreateIntuneRemediation')]
    [switch]$CreateIntuneRemediation,

    # Optional. When supplied, the remediation is auto-assigned to this group.
    # When omitted, the remediation is created unassigned -- you assign it
    # manually in the Intune UI (Devices -> Scripts and remediations -> open
    # the new remediation -> Assignments -> Add groups).
    [Parameter(ParameterSetName='CreateIntuneRemediation')]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$GroupId,

    [Parameter(Mandatory, ParameterSetName='UpdateIntuneRemediation')]
    [switch]$UpdateIntuneRemediation,

    # Self-contained installer for file-share / AD GPO / SCCM rollouts.
    # Emits ONE Install-PimActivator.ps1 (and matching Uninstall) with the
    # tenant JSON baked in -- no params, no CSV dependency. Drop on a share,
    # users (or GPO Startup Script) run it.
    [Parameter(Mandatory, ParameterSetName='GenerateLocalInstaller')]
    [switch]$GenerateLocalInstaller,

    [Parameter(ParameterSetName='GenerateLocalInstaller')]
    [string]$LocalInstallerOutputDir = (Join-Path (Get-Location) 'out-localinstaller'),

    [Parameter(ParameterSetName='GenerateLocalInstaller')]
    [ValidateSet('Machine','User')]
    [string]$LocalInstallerScope = 'User',

    [Parameter(Mandatory, ParameterSetName='UpdateIntuneRemediation')]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$RemediationId,

    [Parameter(ParameterSetName='CreateIntuneRemediation')]
    [Parameter(ParameterSetName='UpdateIntuneRemediation')]
    [ValidateRange(1, 24)]
    [int]$IntervalHours = 1,

    [Parameter(ParameterSetName='CreateIntuneRemediation')]
    [Parameter(ParameterSetName='UpdateIntuneRemediation')]
    [string]$DisplayName = 'PIM Activator -- forcelist + Tenants policy',

    [Parameter(ParameterSetName='CreateIntuneRemediation')]
    [Parameter(ParameterSetName='UpdateIntuneRemediation')]
    [string]$Description,

    [Parameter(ParameterSetName='CreateIntuneRemediation')]
    [Parameter(ParameterSetName='UpdateIntuneRemediation')]
    [ValidateSet('user','system')]
    [string]$RunAsAccount = 'user',

    [string]$GroupNameFilter = '^PIM-',

    [ValidateRange(0.5, 24)]
    [double]$DefaultDurationHours = 1,

    [string]$DefaultJustification = 'Daily ops'
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$Msg) Write-Host "`n>> $Msg" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Msg) Write-Host "   $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "   $Msg" -ForegroundColor Yellow }

# ----------------------------------------------------------------------------
# Load tenants.csv -> JSON string
# ----------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $TenantsCsv)) { throw "TenantsCsv not found: $TenantsCsv" }
$rows = Import-Csv -LiteralPath $TenantsCsv
if (-not $rows) { throw "TenantsCsv is empty: $TenantsCsv" }
$required = 'Name','TenantId','ClientId'
foreach ($col in $required) {
    if ($rows[0].PSObject.Properties.Name -notcontains $col) {
        throw "TenantsCsv must have columns: $($required -join ', '). Missing: $col"
    }
}
# Wrap in @() so a single CSV row stays an ARRAY (otherwise PowerShell collapses
# it to a lone [ordered] hashtable whose .Count reports 3 = key count, not 1 row).
$tenantList = @(foreach ($r in $rows) {
    if (-not $r.Name -or -not $r.TenantId -or -not $r.ClientId) {
        Write-Warn "Skipping row with empty field: $($r | ConvertTo-Json -Compress)"
        continue
    }
    [ordered]@{ Name = $r.Name; TenantId = $r.TenantId; ClientId = $r.ClientId }
})
if (-not $tenantList.Count) { throw "No valid tenant rows found in $TenantsCsv" }
$tenantsJson = ConvertTo-Json -InputObject $tenantList -Depth 4 -Compress
# ConvertTo-Json renders a single-element array as an OBJECT, not "[ {...} ]".
# Force the array form so the popup parses Tenants as an array of one entry.
if ($tenantList.Count -eq 1 -and $tenantsJson.StartsWith('{')) { $tenantsJson = "[$tenantsJson]" }

Write-Step "Loaded $($tenantList.Count) tenant(s) from $TenantsCsv"
$tenantList | ForEach-Object { Write-Host "   $($_.Name) -- $($_.TenantId)" -ForegroundColor DarkGray }

if (-not $Description) {
    $Description = "Force-installs the PIM Activator browser extension into Edge + Chrome and configures the multi-tenant Tenants array ($($tenantList.Count) tenant(s)). Self-heals on every check (every $IntervalHours h). Source CSV: $(Split-Path -Leaf $TenantsCsv)."
}

# ----------------------------------------------------------------------------
# Build Detection + Remediation script bodies. Both scripts must be
# stand-alone (no module imports, no params): Intune runs them verbatim on
# every assigned device.
# ----------------------------------------------------------------------------

$tenantsJsonEscaped = $tenantsJson.Replace("'", "''")    # safe for single-quoted PS string literal

$detectionScript = @"
# ============================================================================
# PIM Activator -- Intune Remediation DETECTION script (auto-generated)
# Source CSV : $(Split-Path -Leaf $TenantsCsv)
# Tenants    : $($tenantList.Count) entry/entries
# Generated  : $(Get-Date -Format 'u')
# ============================================================================
# Exits 0 if every required policy key matches the expected value. Exits 1 if
# ANY key is missing or drifted -- Intune then runs the remediation script
# which rewrites all keys.

`$ErrorActionPreference = 'Stop'
`$EXT_ID       = '$ExtensionId'
`$UPDATE_URL   = '$UpdateUrl'
`$EXPECTED_JSON = '$tenantsJsonEscaped'

`$browsers = @(
    @{ Name='Edge';   Root='HKCU:\SOFTWARE\Policies\Microsoft\Edge' }
    @{ Name='Chrome'; Root='HKCU:\SOFTWARE\Policies\Google\Chrome'  }
)

`$drift = `$false
foreach (`$b in `$browsers) {
    `$forcelistPath = Join-Path `$b.Root 'ExtensionInstallForcelist'
    `$managedPath   = Join-Path `$b.Root "3rdparty\extensions\`$EXT_ID\policy"

    if (-not (Test-Path -LiteralPath `$forcelistPath)) { Write-Host "DRIFT: missing `$forcelistPath"; `$drift = `$true; continue }
    `$flProps = Get-ItemProperty -LiteralPath `$forcelistPath
    `$expectedFl = "`$EXT_ID;`$UPDATE_URL"
    `$haveFl = `$false
    foreach (`$p in `$flProps.PSObject.Properties) {
        if (`$p.Value -eq `$expectedFl) { `$haveFl = `$true; break }
    }
    if (-not `$haveFl) { Write-Host "DRIFT: forcelist missing entry for `$EXT_ID under `$forcelistPath"; `$drift = `$true }

    if (-not (Test-Path -LiteralPath `$managedPath)) { Write-Host "DRIFT: missing `$managedPath"; `$drift = `$true; continue }
    `$got = (Get-ItemProperty -LiteralPath `$managedPath -Name Tenants -ErrorAction SilentlyContinue).Tenants
    if (`$got -ne `$EXPECTED_JSON) { Write-Host "DRIFT: Tenants value differs at `$managedPath"; `$drift = `$true }
}

if (`$drift) { Write-Host 'PIM Activator policy DRIFT detected'; exit 1 }
Write-Host 'PIM Activator policy OK'
exit 0
"@

$remediationScript = @"
# ============================================================================
# PIM Activator -- Intune Remediation REMEDIATION script (auto-generated)
# Source CSV : $(Split-Path -Leaf $TenantsCsv)
# Tenants    : $($tenantList.Count) entry/entries
# Generated  : $(Get-Date -Format 'u')
# ============================================================================
# Writes / repairs every Chromium policy key needed to force-install the PIM
# Activator extension and push the multi-tenant Tenants array. Idempotent.

`$ErrorActionPreference = 'Stop'
`$EXT_ID                = '$ExtensionId'
`$UPDATE_URL            = '$UpdateUrl'
`$TENANTS_JSON          = '$tenantsJsonEscaped'
`$GROUP_NAME_FILTER     = '$GroupNameFilter'
`$DEFAULT_JUSTIFICATION = '$DefaultJustification'
`$DEFAULT_DURATION      = '$DefaultDurationHours'

`$browsers = @(
    @{ Name='Edge';   Root='HKCU:\SOFTWARE\Policies\Microsoft\Edge' }
    @{ Name='Chrome'; Root='HKCU:\SOFTWARE\Policies\Google\Chrome'  }
)

foreach (`$b in `$browsers) {
    `$forcelistPath = Join-Path `$b.Root 'ExtensionInstallForcelist'
    `$managedPath   = Join-Path `$b.Root "3rdparty\extensions\`$EXT_ID\policy"

    foreach (`$p in @(`$forcelistPath, `$managedPath)) {
        if (-not (Test-Path -LiteralPath `$p)) { New-Item -Path `$p -Force | Out-Null }
    }

    # Idempotent forcelist slot derived from EXT_ID hash (so re-runs always
    # overwrite the same slot without colliding with other extensions).
    `$slot = ([System.Math]::Abs(`$EXT_ID.GetHashCode()) % 9000) + 1000
    New-ItemProperty -Path `$forcelistPath -Name "`$slot" -Value "`$EXT_ID;`$UPDATE_URL" -PropertyType String -Force | Out-Null

    # Clear singleton tenantId/clientId if a previous v1.0 install left them
    # behind (Tenants array supersedes singleton mode).
    foreach (`$n in 'tenantId','clientId') {
        if (Get-ItemProperty -Path `$managedPath -Name `$n -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path `$managedPath -Name `$n -ErrorAction SilentlyContinue
        }
    }
    New-ItemProperty -Path `$managedPath -Name 'Tenants'             -Value `$TENANTS_JSON          -PropertyType String -Force | Out-Null
    New-ItemProperty -Path `$managedPath -Name 'groupNameFilter'     -Value `$GROUP_NAME_FILTER     -PropertyType String -Force | Out-Null
    New-ItemProperty -Path `$managedPath -Name 'defaultJustification' -Value `$DEFAULT_JUSTIFICATION -PropertyType String -Force | Out-Null
    New-ItemProperty -Path `$managedPath -Name 'defaultDurationHours' -Value `$DEFAULT_DURATION     -PropertyType String -Force | Out-Null

    Write-Host "[`$(`$b.Name)] policy applied at `$managedPath"
}

Write-Host "PIM Activator policy converged (Tenants count: $($tenantList.Count))."
exit 0
"@

# ----------------------------------------------------------------------------
# Mode: GenerateScripts
# ----------------------------------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'GenerateScripts') {
    if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir | Out-Null }
    $detPath = Join-Path $OutputDir 'Detection.ps1'
    $remPath = Join-Path $OutputDir 'Remediation.ps1'
    Set-Content -LiteralPath $detPath -Value $detectionScript -Encoding UTF8
    Set-Content -LiteralPath $remPath -Value $remediationScript -Encoding UTF8
    Write-Step 'Scripts generated -- upload via Intune Admin Center'
    Write-Ok "Detection   : $detPath"
    Write-Ok "Remediation : $remPath"
    Write-Host ''
    Write-Host '  Intune steps:' -ForegroundColor Cyan
    Write-Host '   1. Devices -> Scripts and remediations -> Platform scripts'
    Write-Host '   2. Create -> Windows. Upload Detection.ps1 + Remediation.ps1'
    Write-Host '   3. Run as: Logged-on credentials. 64-bit: Yes. Signature: No'
    Write-Host '   4. Schedule: Daily 1 hour (or hourly via XML overrides)'
    Write-Host '   5. Assign to your target user/device group.'
    return
}

# ----------------------------------------------------------------------------
# Mode: GenerateLocalInstaller -- self-contained installer for file share /
# AD Group Policy / SCCM / manual install. No CSV dependency at run time;
# the tenants JSON is baked into the emitted script.
# ----------------------------------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'GenerateLocalInstaller') {
    if (-not (Test-Path -LiteralPath $LocalInstallerOutputDir)) {
        New-Item -ItemType Directory -Path $LocalInstallerOutputDir | Out-Null
    }
    $hive = if ($LocalInstallerScope -eq 'Machine') { 'HKLM' } else { 'HKCU' }

    $installer = @"
#Requires -Version 5.1
# ============================================================================
# Install-PimActivator.ps1  --  self-contained (auto-generated)
# Generated  : $(Get-Date -Format 'u')
# Source CSV : $(Split-Path -Leaf $TenantsCsv)
# Tenants    : $($tenantList.Count) entry/entries
# Scope      : $LocalInstallerScope ($hive)
# ============================================================================
# Drop on a file share, run from AD GPO Startup Script ($LocalInstallerScope=Machine),
# Logon Script ($LocalInstallerScope=User), SCCM application, or have an end
# user double-click to install. No parameters, no module dependencies, no CSV
# dependency. Re-runnable / idempotent.
#
# Writes the Chromium policy keys for Edge + Chrome that:
#   1. Force-install the PIM Activator extension from the gh-pages CRX host
#   2. Configure the multi-tenant Tenants array (popup picker fires when N>=2)
# ============================================================================

`$ErrorActionPreference = 'Stop'
`$EXT_ID                = '$ExtensionId'
`$UPDATE_URL            = '$UpdateUrl'
`$TENANTS_JSON          = '$tenantsJsonEscaped'
`$GROUP_NAME_FILTER     = '$GroupNameFilter'
`$DEFAULT_JUSTIFICATION = '$DefaultJustification'
`$DEFAULT_DURATION      = '$DefaultDurationHours'
`$HIVE                  = '${hive}:'

if (`$HIVE -eq 'HKLM:') {
    # HKLM requires admin. Fail loud if invoker can't write it.
    `$id = [Security.Principal.WindowsIdentity]::GetCurrent()
    `$pr = New-Object Security.Principal.WindowsPrincipal(`$id)
    if (-not `$pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'HKLM scope requires administrator. Run elevated, or regenerate the installer with -LocalInstallerScope User.'
    }
}

`$browsers = @(
    @{ Name='Edge';   Root="`$HIVE\SOFTWARE\Policies\Microsoft\Edge" }
    @{ Name='Chrome'; Root="`$HIVE\SOFTWARE\Policies\Google\Chrome"  }
)

foreach (`$b in `$browsers) {
    `$forcelistPath = Join-Path `$b.Root 'ExtensionInstallForcelist'
    `$managedPath   = Join-Path `$b.Root "3rdparty\extensions\`$EXT_ID\policy"

    foreach (`$p in @(`$forcelistPath, `$managedPath)) {
        if (-not (Test-Path -LiteralPath `$p)) { New-Item -Path `$p -Force | Out-Null }
    }

    # Idempotent slot derived from extension id hash.
    `$slot = ([System.Math]::Abs(`$EXT_ID.GetHashCode()) % 9000) + 1000
    New-ItemProperty -Path `$forcelistPath -Name "`$slot" -Value "`$EXT_ID;`$UPDATE_URL" -PropertyType String -Force | Out-Null

    # Clear legacy singleton values if a prior v1.0 install left them behind.
    foreach (`$n in 'tenantId','clientId') {
        if (Get-ItemProperty -Path `$managedPath -Name `$n -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path `$managedPath -Name `$n -ErrorAction SilentlyContinue
        }
    }
    New-ItemProperty -Path `$managedPath -Name 'Tenants'              -Value `$TENANTS_JSON          -PropertyType String -Force | Out-Null
    New-ItemProperty -Path `$managedPath -Name 'groupNameFilter'      -Value `$GROUP_NAME_FILTER     -PropertyType String -Force | Out-Null
    New-ItemProperty -Path `$managedPath -Name 'defaultJustification' -Value `$DEFAULT_JUSTIFICATION -PropertyType String -Force | Out-Null
    New-ItemProperty -Path `$managedPath -Name 'defaultDurationHours' -Value `$DEFAULT_DURATION     -PropertyType String -Force | Out-Null

    Write-Host "[`$(`$b.Name)] PIM Activator policy written at `$managedPath"
}

Write-Host ''
Write-Host 'PIM Activator policy installed. Restart Edge + Chrome to pick it up.'
Write-Host 'Tenants in this install: $($tenantList.Count) (popup will show picker when N >= 2).'
exit 0
"@

    $uninstaller = @"
#Requires -Version 5.1
# ============================================================================
# Uninstall-PimActivator.ps1  --  removes everything Install-PimActivator.ps1 wrote
# Generated : $(Get-Date -Format 'u')
# Scope     : $LocalInstallerScope ($hive)
# ============================================================================

`$ErrorActionPreference = 'Stop'
`$EXT_ID = '$ExtensionId'
`$HIVE   = '${hive}:'

if (`$HIVE -eq 'HKLM:') {
    `$id = [Security.Principal.WindowsIdentity]::GetCurrent()
    `$pr = New-Object Security.Principal.WindowsPrincipal(`$id)
    if (-not `$pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'HKLM scope requires administrator.'
    }
}

`$browsers = @(
    @{ Name='Edge';   Root="`$HIVE\SOFTWARE\Policies\Microsoft\Edge" }
    @{ Name='Chrome'; Root="`$HIVE\SOFTWARE\Policies\Google\Chrome"  }
)

foreach (`$b in `$browsers) {
    `$forcelistPath = Join-Path `$b.Root 'ExtensionInstallForcelist'
    if (Test-Path -LiteralPath `$forcelistPath) {
        Get-ItemProperty -LiteralPath `$forcelistPath | ForEach-Object {
            foreach (`$p in `$_.PSObject.Properties) {
                if (`$p.Value -like "`$EXT_ID;*") {
                    Remove-ItemProperty -LiteralPath `$forcelistPath -Name `$p.Name -ErrorAction SilentlyContinue
                    Write-Host "[`$(`$b.Name)] removed forcelist slot `$(`$p.Name)"
                }
            }
        }
    }
    `$managedPath = Join-Path `$b.Root "3rdparty\extensions\`$EXT_ID\policy"
    if (Test-Path -LiteralPath `$managedPath) {
        Remove-Item -LiteralPath `$managedPath -Recurse -Force
        Write-Host "[`$(`$b.Name)] removed managed config at `$managedPath"
    }
}

Write-Host 'PIM Activator policy removed. Restart Edge + Chrome to drop the extension.'
exit 0
"@

    $tenantsCsvCopy = Join-Path $LocalInstallerOutputDir 'tenants.csv'
    Copy-Item -LiteralPath $TenantsCsv -Destination $tenantsCsvCopy -Force

    $readme = @"
# PIM Activator -- self-contained installer

Generated: $(Get-Date -Format 'u')
Source CSV: $(Split-Path -Leaf $TenantsCsv) ($($tenantList.Count) tenant(s))
Scope: $LocalInstallerScope ($hive)

## What's in this folder

- ``Install-PimActivator.ps1``    Idempotent installer. No params. Run from
                                 anywhere. Writes Chromium policy keys.
- ``Uninstall-PimActivator.ps1``  Removes everything Install wrote.
- ``tenants.csv``                 Reference copy of the source tenant list
                                 (NOT read at install time -- the JSON is
                                 baked into Install-PimActivator.ps1).

## Deployment options

### A) Manual / file share
Drop this folder on a share (e.g. ``\\srv\sw\PimActivator\``). End users (or
your support team) run:
```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\srv\sw\PimActivator\Install-PimActivator.ps1
```
$(if ($LocalInstallerScope -eq 'Machine') { '(Requires elevated/admin shell because scope is Machine/HKLM.)' } else { '(No admin needed because scope is User/HKCU.)' })

### B) AD Group Policy -- $LocalInstallerScope scope
$(if ($LocalInstallerScope -eq 'Machine') {
@'
Computer Configuration -> Policies -> Windows Settings -> Scripts -> Startup
- Add this Install-PimActivator.ps1 (PowerShell tab)
- Runs as SYSTEM at boot, writes HKLM policy. All users on the machine get it.

Uninstall: replace the startup script with Uninstall-PimActivator.ps1 (one-shot),
or remove the GPO assignment + run Uninstall on each box.
'@
} else {
@'
User Configuration -> Policies -> Windows Settings -> Scripts -> Logon
- Add this Install-PimActivator.ps1 (PowerShell tab)
- Runs as the user at sign-in, writes HKCU policy. Only the policy-target user gets it.

Uninstall: replace the logon script with Uninstall-PimActivator.ps1.
'@
})

### C) SCCM / Configuration Manager
Package the Install-PimActivator.ps1 as an Application (Script installer):
- Install command : ``powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-PimActivator.ps1``
- Uninstall command: ``powershell.exe -NoProfile -ExecutionPolicy Bypass -File Uninstall-PimActivator.ps1``
- Detection rule: registry key ``$hive\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\$ExtensionId\policy`` value ``Tenants`` exists

### D) Intune (use the Remediation path instead)
This static installer is for environments WITHOUT Intune. For Intune, run
``Deploy-PimActivatorIntune.ps1 -CreateIntuneRemediation`` instead -- you get
the self-heal scheduler for free.

## Updating the tenant list

This installer has the tenant list BAKED IN at generation time. To add /
remove tenants:
1. Edit your source CSV (the original you fed to -TenantsCsv)
2. Re-run ``Deploy-PimActivatorIntune.ps1 -GenerateLocalInstaller`` to emit
   a fresh Install-PimActivator.ps1
3. Re-deploy via your chosen rollout path (file share refresh / GPO Logoff
   first then Logon / SCCM application update)
"@

    Set-Content -LiteralPath (Join-Path $LocalInstallerOutputDir 'Install-PimActivator.ps1')   -Value $installer   -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $LocalInstallerOutputDir 'Uninstall-PimActivator.ps1') -Value $uninstaller -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $LocalInstallerOutputDir 'README.md')                  -Value $readme      -Encoding UTF8

    Write-Step "Local installer generated in $LocalInstallerOutputDir"
    Write-Ok "Install-PimActivator.ps1   ($LocalInstallerScope scope)"
    Write-Ok "Uninstall-PimActivator.ps1 ($LocalInstallerScope scope)"
    Write-Ok "tenants.csv (reference copy)"
    Write-Ok "README.md (deployment-path guide)"
    Write-Host ''
    Write-Host '  Drop the folder on a file share, or wire into AD GPO / SCCM. See README.md.' -ForegroundColor Cyan
    return
}

# ----------------------------------------------------------------------------
# Modes: CreateIntuneRemediation / UpdateIntuneRemediation
# Microsoft Graph beta endpoint -- deviceHealthScripts is THE Remediations API.
# ----------------------------------------------------------------------------
Write-Step 'Connecting to Microsoft Graph (beta) -- DeviceManagementScripts.ReadWrite.All'
$mods = 'Microsoft.Graph.Authentication','Microsoft.Graph.Beta.DeviceManagement'
foreach ($m in $mods) {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        throw "Required module '$m' not installed. Run: Install-Module $m -Scope CurrentUser"
    }
    Import-Module $m -ErrorAction Stop | Out-Null
}
Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All','DeviceManagementManagedDevices.ReadWrite.All','Group.Read.All' -NoWelcome | Out-Null

$detB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($detectionScript))
$remB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($remediationScript))

$body = [ordered]@{
    displayName                = $DisplayName
    description                = $Description
    publisher                  = '2linkit / Morten Knudsen'
    runAs32Bit                 = $false
    runAsAccount               = $RunAsAccount        # 'user' or 'system'
    enforceSignatureCheck      = $false
    detectionScriptContent     = $detB64
    remediationScriptContent   = $remB64
    roleScopeTagIds            = @('0')
}

if ($PSCmdlet.ParameterSetName -eq 'CreateIntuneRemediation') {
    Write-Step "Creating Intune Remediation '$DisplayName'"
    $created = Invoke-MgGraphRequest -Method POST `
        -Uri 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts' `
        -Body ($body | ConvertTo-Json -Depth 10) `
        -ContentType 'application/json'
    $remId = $created.id
    Write-Ok "Remediation created. Id: $remId"

    if ($GroupId) {
        # Auto-assign to the supplied group with an hourly schedule.
        Write-Step "Assigning remediation to group $GroupId (interval: every $IntervalHours hour(s))"
        $assignment = @{
            deviceHealthScriptAssignments = @(
                @{
                    target = @{
                        '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                        groupId        = $GroupId
                    }
                    runRemediationScript = $true
                    runSchedule = @{
                        '@odata.type' = '#microsoft.graph.deviceHealthScriptHourlySchedule'
                        interval       = $IntervalHours
                    }
                }
            )
        } | ConvertTo-Json -Depth 10
        Invoke-MgGraphRequest -Method POST `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$remId/assign" `
            -Body $assignment `
            -ContentType 'application/json' | Out-Null
        Write-Ok 'Assignment created.'
    } else {
        Write-Warn 'No -GroupId provided -- remediation created UNASSIGNED.'
        Write-Host '   Assign manually: Intune Admin Center -> Devices -> Scripts and remediations' -ForegroundColor DarkGray
        Write-Host "   -> open '$DisplayName' -> Assignments -> Add groups (set schedule: hourly)" -ForegroundColor DarkGray
    }

    Write-Host ''
    Write-Host "==========================================================" -ForegroundColor Green
    Write-Host " Save this Remediation Id for future -UpdateIntuneRemediation:" -ForegroundColor Green
    Write-Host "   $remId" -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Green
    if ($GroupId) {
        Write-Host ''
        Write-Host " Clients in group $GroupId will receive the policy on next sync." -ForegroundColor Cyan
        Write-Host " Detection + remediation will then run every $IntervalHours hour(s)." -ForegroundColor Cyan
    }
    return
}

if ($PSCmdlet.ParameterSetName -eq 'UpdateIntuneRemediation') {
    Write-Step "Updating Intune Remediation $RemediationId"
    Invoke-MgGraphRequest -Method PATCH `
        -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$RemediationId" `
        -Body ($body | ConvertTo-Json -Depth 10) `
        -ContentType 'application/json' | Out-Null
    Write-Ok "Remediation updated. Clients re-converge within ~$IntervalHours h."
    return
}
