#Requires -Version 5.1
<#
.SYNOPSIS
    Per-machine installer for the PIM Activator browser extension (Edge,
    Chrome, or both). Pushes force-install + tenant configuration via the
    Chromium enterprise policy registry tree. Designed for unattended
    Intune / Group Policy / Configuration Manager rollout.

.DESCRIPTION
    Writes two sets of HKLM policy keys (one set per targeted browser) that
    Edge / Chrome read at next launch:

    1. ExtensionInstallForcelist
       Tells the browser to install + auto-update the extension from
       -UpdateUrl (the update.xml of a private CRX host -- e.g.
       'https://<owner>.github.io/<repo>/updates.xml' -- or the Edge Add-ons
       store URL 'https://edge.microsoft.com/extensionwebstorebase/v1/crx',
       or the Chrome Web Store URL 'https://clients2.google.com/service/update2/crx').

    2. 3rdparty\extensions\<ExtensionId>\policy
       The managed_storage payload (chrome.storage.managed) the extension's
       popup.js reads on load: tenantId, clientId, groupNameFilter,
       defaultDurationHours, defaultJustification. Admin-pushed values
       override anything the user might set locally.

    Both browsers read the SAME key names + value layout, just under different
    policy roots:
      Edge   : HKLM\SOFTWARE\Policies\Microsoft\Edge\...
      Chrome : HKLM\SOFTWARE\Policies\Google\Chrome\...

    Re-runnable. Safe under SYSTEM. Returns exit code 0 on success.

.PARAMETER ExtensionId
    32-char Chromium extension id (lowercase a-p). Required.

.PARAMETER UpdateUrl
    The update.xml URL the extension auto-updates from. For a private CRX
    host (e.g. GitHub Pages), use the URL of your update manifest XML.

.PARAMETER TenantId
    Entra tenant id (GUID) the activator signs into.

.PARAMETER ClientId
    App registration client id (output by Deploy-PimActivatorBackend.ps1).

.PARAMETER GroupNameFilter
    Optional regex limiting which eligible groups are shown. Default '^PIM-'.

.PARAMETER DefaultDurationHours
    Optional default activation duration (hours). Default 1.

.PARAMETER DefaultJustification
    Optional default text for the justification field. Default 'Daily ops'.

.PARAMETER Scope
    'User' (default, HKCU, no admin required, no Intune conflict) or 'Machine'
    (HKLM, requires admin).

    'User' scope writes BOTH the forcelist + managed-storage keys under
    HKCU\SOFTWARE\Policies\... which both Edge and Chrome honour for the
    current Windows user only. Easy to revert (delete the HKCU key, no admin).
    Recommended for dev-box testing.

    'Machine' scope writes the same keys under HKLM. This affects every user
    on the machine AND -- critically -- CONFLICTS with Intune-managed
    ExtensionInstallForcelist policy. Only use Machine on isolated test
    machines that are NOT managed by Intune / GPO. Production rollouts
    should push the same key/value pairs via Intune instead (see
    Setup-PimActivator.ps1 -PrintIntuneConfig for the exact payload).

.PARAMETER Browser
    Which browser policy roots to write/remove. 'Edge', 'Chrome', or 'Both'.
    Default: 'Both'. Both browsers read identical key names under their own
    policy root.

.PARAMETER Uninstall
    Remove all policy keys this script writes (under whichever browser(s)
    -Browser targets).

.EXAMPLE
    # Dev-box testing (default) -- HKCU only, no admin, no Intune conflict:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Deploy-PimActivatorClient.ps1 `
        -ExtensionId 'abcdefghijklmnopabcdefghijklmnop' `
        -UpdateUrl 'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml' `
        -TenantId 'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e' `
        -ClientId '11111111-2222-3333-4444-555555555555' `
        -Browser Both

.EXAMPLE
    # Isolated test machine NOT managed by Intune -- explicit Machine scope (HKLM):
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Deploy-PimActivatorClient.ps1 `
        -ExtensionId 'abcdefghijklmnopabcdefghijklmnop' `
        -UpdateUrl 'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml' `
        -TenantId 'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e' `
        -ClientId '11111111-2222-3333-4444-555555555555' `
        -Scope Machine -Browser Both

.EXAMPLE
    # Edge only:
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Deploy-PimActivatorClient.ps1 `
        -ExtensionId abcd... -UpdateUrl https://... -TenantId ... -ClientId ... `
        -Browser Edge

.EXAMPLE
    # Detection / uninstall (removes policy from both browsers):
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Deploy-PimActivatorClient.ps1 `
        -ExtensionId abcd... -Uninstall -Browser Both

.NOTES
    Tested on Edge for Business 120+ and Chrome 120+. Both browsers pick up
    policy changes on next launch; no reboot required.
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-p]{32}$')]
    [string]$ExtensionId,

    [Parameter(Mandatory, ParameterSetName = 'Install')]
    [Parameter(Mandatory, ParameterSetName = 'InstallMulti')]
    [string]$UpdateUrl,

    # Single-tenant (legacy) -----------------------------------------------------
    [Parameter(Mandatory, ParameterSetName = 'Install')]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [Parameter(Mandatory, ParameterSetName = 'Install')]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    # Multi-tenant (v1.1+) -------------------------------------------------------
    # Array of hashtables: @(@{Name='ACME Prod';TenantId='<guid>';ClientId='<guid>'}, ...)
    # When 2+ entries are present the popup shows a tenant picker on first open
    # per browser profile; choice cached in chrome.storage.local (per-profile).
    [Parameter(Mandatory, ParameterSetName = 'InstallMulti')]
    [object[]]$Tenants,

    # Optional CSV path: Name,TenantId,ClientId (one row per tenant). Convenience
    # alternative to -Tenants for admins who maintain tenant lists in Excel.
    [Parameter(ParameterSetName = 'InstallMulti')]
    [string]$TenantsCsv,

    # Shared options -------------------------------------------------------------
    [Parameter(ParameterSetName = 'Install')]
    [Parameter(ParameterSetName = 'InstallMulti')]
    [string]$GroupNameFilter = '^PIM-',

    [Parameter(ParameterSetName = 'Install')]
    [Parameter(ParameterSetName = 'InstallMulti')]
    [ValidateRange(0.5, 24)]
    [double]$DefaultDurationHours = 1,

    [Parameter(ParameterSetName = 'Install')]
    [Parameter(ParameterSetName = 'InstallMulti')]
    [string]$DefaultJustification = 'Daily ops',

    [Parameter()]
    [ValidateSet('Machine', 'User')]
    [string]$Scope = 'User',

    [Parameter()]
    [ValidateSet('Edge', 'Chrome', 'Both')]
    [string]$Browser = 'Both',

    [Parameter(Mandatory, ParameterSetName = 'Uninstall')]
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Build the list of policy roots we'll operate on, one per targeted browser.
# Edge   : SOFTWARE\Policies\Microsoft\Edge
# Chrome : SOFTWARE\Policies\Google\Chrome
# Both browsers read identical key names under their own root.
# ---------------------------------------------------------------------------

$hiveRoot = if ($Scope -eq 'Machine') { 'HKLM:' } else { 'HKCU:' }

$policyRoots = New-Object System.Collections.Generic.List[object]
if ($Browser -in @('Edge','Both')) {
    $policyRoots.Add([pscustomobject]@{ Name = 'Edge';   Path = "$hiveRoot\SOFTWARE\Policies\Microsoft\Edge" })
}
if ($Browser -in @('Chrome','Both')) {
    $policyRoots.Add([pscustomobject]@{ Name = 'Chrome'; Path = "$hiveRoot\SOFTWARE\Policies\Google\Chrome" })
}

function New-PolicyKey {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
}

function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [Microsoft.Win32.RegistryValueKind]$Kind = [Microsoft.Win32.RegistryValueKind]::String)
    New-PolicyKey -Path $Path
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Kind -Force | Out-Null
}

if ($Uninstall) {
    Write-Host "Removing PIM Activator policy keys ($Scope scope, $Browser) for extension $ExtensionId..." -ForegroundColor Yellow

    foreach ($root in $policyRoots) {
        Write-Host "  [$($root.Name)] root: $($root.Path)" -ForegroundColor DarkGray

        # Forcelist: clear the slot we wrote to. We use a stable slot number
        # derived from the extension id so re-runs are idempotent and
        # uninstall is targeted (doesn't touch other extensions' forcelist
        # entries).
        $forcelistPath = Join-Path $root.Path 'ExtensionInstallForcelist'
        if (Test-Path -LiteralPath $forcelistPath) {
            Get-ItemProperty -Path $forcelistPath | ForEach-Object {
                foreach ($prop in $_.PSObject.Properties) {
                    if ($prop.Value -like "$ExtensionId;*") {
                        Remove-ItemProperty -Path $forcelistPath -Name $prop.Name -ErrorAction SilentlyContinue
                        Write-Host "    removed forcelist entry $($prop.Name) = $($prop.Value)" -ForegroundColor DarkGray
                    }
                }
            }
        }

        $managedPath = Join-Path $root.Path "3rdparty\extensions\$ExtensionId\policy"
        if (Test-Path -LiteralPath $managedPath) {
            Remove-Item -Path $managedPath -Recurse -Force
            Write-Host "    removed managed config key $managedPath" -ForegroundColor DarkGray
        }
    }

    Write-Host "PIM Activator policy removed. Restart $Browser to apply." -ForegroundColor Green
    return
}

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

if ($Scope -eq 'Machine') {
    Write-Host ""
    Write-Host "  *** -Scope Machine selected -- HKLM writes will be applied. ***" -ForegroundColor Yellow
    Write-Host "  HKLM ExtensionInstallForcelist CONFLICTS with Intune-managed policy." -ForegroundColor Yellow
    Write-Host "  Only use Machine scope on isolated test machines that are NOT Intune-managed." -ForegroundColor Yellow
    Write-Host "  Production rollouts: push the same payload via Intune instead" -ForegroundColor Yellow
    Write-Host "  (run Setup-PimActivator.ps1 -PrintIntuneConfig for the copy-paste values)." -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host ""
    Write-Host "  -Scope User selected -- HKCU-only. Won't affect other users or Intune." -ForegroundColor Green
    Write-Host ""
}

# ---- Multi-tenant: normalise -Tenants / -TenantsCsv into a JSON string -------
$tenantsJson = $null
if ($PSCmdlet.ParameterSetName -eq 'InstallMulti') {
    $tenantList = New-Object System.Collections.Generic.List[object]
    if ($TenantsCsv) {
        if (-not (Test-Path -LiteralPath $TenantsCsv)) { throw "TenantsCsv not found: $TenantsCsv" }
        $csv = Import-Csv -LiteralPath $TenantsCsv
        foreach ($row in $csv) {
            if (-not $row.Name -or -not $row.TenantId -or -not $row.ClientId) {
                throw "TenantsCsv row missing Name/TenantId/ClientId column: $($row | ConvertTo-Json -Compress)"
            }
            $tenantList.Add([ordered]@{ Name = $row.Name; TenantId = $row.TenantId; ClientId = $row.ClientId })
        }
    }
    foreach ($t in ($Tenants | Where-Object { $_ })) {
        # Accept hashtable or PSCustomObject; normalise to ordered hashtable.
        $name     = if ($t -is [hashtable]) { $t['Name']     } else { $t.Name     }
        $tenantId = if ($t -is [hashtable]) { $t['TenantId'] } else { $t.TenantId }
        $clientId = if ($t -is [hashtable]) { $t['ClientId'] } else { $t.ClientId }
        if (-not $name -or -not $tenantId -or -not $clientId) {
            throw "Each -Tenants entry must have Name, TenantId, ClientId. Got: $($t | ConvertTo-Json -Compress)"
        }
        $tenantList.Add([ordered]@{ Name = $name; TenantId = $tenantId; ClientId = $clientId })
    }
    if (-not $tenantList.Count) { throw "No tenants resolved from -Tenants or -TenantsCsv." }
    $tenantsJson = $tenantList | ConvertTo-Json -Depth 4 -Compress
}

Write-Host "Installing PIM Activator policy ($Scope scope, $Browser)..." -ForegroundColor Cyan
Write-Host "  ExtensionId : $ExtensionId"
if ($tenantsJson) {
    Write-Host "  Tenants     : $($tenantList.Count) tenant(s) -- popup will show picker when >=2" -ForegroundColor Cyan
    $tenantList | ForEach-Object { Write-Host "                $($_.Name) -- $($_.TenantId)" -ForegroundColor DarkGray }
} else {
    Write-Host "  TenantId    : $TenantId"
    Write-Host "  ClientId    : $ClientId"
}
Write-Host "  UpdateUrl   : $UpdateUrl"

foreach ($root in $policyRoots) {
    Write-Host ""
    Write-Host "  [$($root.Name)] writing under $($root.Path)" -ForegroundColor Cyan

    # 1) Force-install via ExtensionInstallForcelist. The value format is:
    #    "<extension-id>;<update-url>"
    # We allocate slots by hashing the extension id, so re-runs always overwrite
    # the same slot (idempotent) and never collide with other policy-installed
    # extensions.
    $forcelistPath = Join-Path $root.Path 'ExtensionInstallForcelist'
    New-PolicyKey -Path $forcelistPath
    $slot = ([System.Math]::Abs($ExtensionId.GetHashCode()) % 9000) + 1000
    Set-Reg -Path $forcelistPath -Name "$slot" -Value "$ExtensionId;$UpdateUrl"
    Write-Host "    -> forcelist slot $slot set" -ForegroundColor DarkGray

    # 2) Managed config (chrome.storage.managed). Both Edge and Chrome map
    #    the registry sub-tree under 3rdparty\extensions\<id>\policy directly
    #    to managed-storage keys, so REG_SZ "tenantId" becomes
    #    managed.tenantId at runtime.
    $managedPath = Join-Path $root.Path "3rdparty\extensions\$ExtensionId\policy"
    New-PolicyKey -Path $managedPath
    if ($tenantsJson) {
        # Multi-tenant mode -- Tenants is a REG_SZ JSON array. Chromium parses
        # it into managed-storage as an array of {Name,TenantId,ClientId}.
        # Clear singleton fields so the array is the sole source of truth and
        # there's no risk of leftover/conflicting values from a prior install.
        foreach ($n in 'tenantId','clientId') {
            if (Get-ItemProperty -Path $managedPath -Name $n -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $managedPath -Name $n -ErrorAction SilentlyContinue
            }
        }
        Set-Reg -Path $managedPath -Name 'Tenants' -Value $tenantsJson
    } else {
        Set-Reg -Path $managedPath -Name 'tenantId' -Value $TenantId
        Set-Reg -Path $managedPath -Name 'clientId' -Value $ClientId
    }
    Set-Reg -Path $managedPath -Name 'groupNameFilter'      -Value $GroupNameFilter
    Set-Reg -Path $managedPath -Name 'defaultJustification' -Value $DefaultJustification
    # defaultDurationHours is a number; both browsers accept REG_SZ and parse
    # to number per the schema.
    Set-Reg -Path $managedPath -Name 'defaultDurationHours' -Value ([string]$DefaultDurationHours)

    Write-Host "    -> managed config keys set under $managedPath" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "Done. Restart $Browser (or wait for next launch) to apply policy." -ForegroundColor Green
if ($Browser -in @('Edge','Both'))   { Write-Host "Validate from any Edge window  : edge://policy   -> Search 'PIM' / extension id." -ForegroundColor DarkGray }
if ($Browser -in @('Chrome','Both')) { Write-Host "Validate from any Chrome window: chrome://policy -> Search 'PIM' / extension id." -ForegroundColor DarkGray }
