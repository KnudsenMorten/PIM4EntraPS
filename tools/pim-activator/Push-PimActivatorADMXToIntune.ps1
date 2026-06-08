#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Upload the PIM Activator custom ADMX/ADML pair to Intune so the policies
    appear in Settings Catalog under "Templates -> Imported Administrative
    templates -> PIM Activator". After upload, an admin creates a
    Configuration Profile that pastes the tenant catalog JSON into the
    new policy's textbox -- Intune writes via Group Policy CSP (which
    Microsoft trusts), bypassing the Registry CSP restriction that
    failed v2.4.90 (error 0x87d1fde8).

.DESCRIPTION
    Wraps the manual "Devices -> Configuration -> Import Custom ADMX"
    portal flow into one re-runnable script. Idempotent: if a definition
    file with the same fileName already exists, the script DELETES it
    first, then re-uploads (Intune's groupPolicyUploadedDefinitionFile
    resource doesn't support PATCH, so delete+recreate is the documented
    update pattern).

    File layout expected next to this script:
        intune\PIM4EntraPS.PimActivator.admx
        intune\en-US\PIM4EntraPS.PimActivator.adml

.PARAMETER AdmxPath
    Path to the .admx file. Default: sibling intune\ folder.

.PARAMETER AdmlPath
    Path to the en-US .adml file. Default: sibling intune\en-US\ folder.

.PARAMETER Remove
    Delete the ingested ADMX from Intune (idempotent).

.EXAMPLE
    .\Push-PimActivatorADMXToIntune.ps1

.EXAMPLE
    .\Push-PimActivatorADMXToIntune.ps1 -Remove

.NOTES
    Required Graph scopes (delegated):
      - DeviceManagementConfiguration.ReadWrite.All
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter()]
    [string]$AdmxPath = (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'intune\PIM4EntraPS.PimActivator.admx'),

    [Parameter()]
    [string]$AdmlPath = (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'intune\en-US\PIM4EntraPS.PimActivator.adml'),

    [Parameter(Mandatory, ParameterSetName = 'Uninstall')]
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

# ---- 1. Graph context -----------------------------------------------------
$_requiredScopes = @('DeviceManagementConfiguration.ReadWrite.All')
$ctx = Get-MgContext -ErrorAction SilentlyContinue
if (-not $ctx) {
    Write-Host "Not connected to Microsoft Graph. Launching interactive sign-in (scopes: $($_requiredScopes -join ', '))..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes $_requiredScopes -NoWelcome -ErrorAction Stop
    $ctx = Get-MgContext
}
$missingScopes = $_requiredScopes | Where-Object { $_ -notin $ctx.Scopes }
if ($missingScopes) {
    Write-Host "Re-connecting Graph to include missing scope(s): $($missingScopes -join ', ')" -ForegroundColor Yellow
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Connect-MgGraph -Scopes $_requiredScopes -NoWelcome -ErrorAction Stop
    $ctx = Get-MgContext
}
Write-Host "Connected to tenant $($ctx.TenantId) as $($ctx.Account)" -ForegroundColor Gray

# ---- 2. Lookup existing upload by fileName --------------------------------
$admxFileName = Split-Path -Leaf $AdmxPath
$listUri      = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles?`$filter=fileName eq '$admxFileName'"
$existing     = $null
try {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $listUri -ErrorAction Stop
    if ($resp.value -and $resp.value.Count -gt 0) {
        $existing = $resp.value[0]
    }
} catch {
    Write-Warning "Lookup failed (will attempt POST): $($_.Exception.Message)"
}

if ($Remove) {
    if ($existing) {
        Write-Host "Removing existing ADMX upload '$admxFileName' (id $($existing.id))..." -ForegroundColor Yellow
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($existing.id)/remove" -ErrorAction Stop | Out-Null
        Write-Host "[OK] Removed." -ForegroundColor Green
    } else {
        Write-Host "Nothing to remove -- no upload named '$admxFileName' in tenant $($ctx.TenantId)." -ForegroundColor Gray
    }
    return
}

# ---- 3. Read + base64-encode the ADMX / ADML pair ------------------------
if (-not (Test-Path -LiteralPath $AdmxPath)) { throw "ADMX file not found: $AdmxPath" }
if (-not (Test-Path -LiteralPath $AdmlPath)) { throw "ADML file not found: $AdmlPath" }

$admxBytes  = [System.IO.File]::ReadAllBytes($AdmxPath)
$admlBytes  = [System.IO.File]::ReadAllBytes($AdmlPath)
$admxBase64 = [Convert]::ToBase64String($admxBytes)
$admlBase64 = [Convert]::ToBase64String($admlBytes)
$admlFileName = Split-Path -Leaf $AdmlPath

Write-Host "ADMX: $AdmxPath ($($admxBytes.Length) bytes)" -ForegroundColor Cyan
Write-Host "ADML: $AdmlPath ($($admlBytes.Length) bytes)" -ForegroundColor Cyan

# ---- 4. (Intune groupPolicyUploadedDefinitionFile is POST-only) ----------
# To update, delete first then POST anew. Microsoft's documented pattern.
if ($existing) {
    # State-aware handling. Intune's groupPolicyUploadedDefinitionFile goes
    # through asynchronous transient states (uploadInProgress, removalInProgress)
    # before reaching a terminal one (available, uploadFailed, removed). Calling
    # /remove on a transient row returns 400 "OperationInProgress".
    #
    # Strategy:
    #   uploadInProgress    -> wait until terminal; if it becomes 'available',
    #                          this IS our upload (it's the right content) -> exit success
    #   available           -> /remove + wait for 404 -> re-upload
    #   removalInProgress   -> wait for 404 -> re-upload
    #   uploadFailed        -> /remove + wait for 404 -> re-upload
    #   anything else       -> /remove + wait for 404 -> re-upload (best effort)
    if ($existing.status -in @('uploadInProgress','removalInProgress')) {
        Write-Host "Existing upload (id $($existing.id)) is in transient state '$($existing.status)'. Waiting for it to settle..." -ForegroundColor Yellow
    } elseif ($existing.status -in @('available')) {
        Write-Host "Existing upload (id $($existing.id), status $($existing.status)). Calling /remove action..." -ForegroundColor Yellow
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($existing.id)/remove" -ErrorAction Stop | Out-Null
    } else {
        Write-Host "Existing upload (id $($existing.id), status $($existing.status)). Attempting /remove..." -ForegroundColor Yellow
        try {
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($existing.id)/remove" -ErrorAction Stop | Out-Null
        } catch {
            Write-Warning "/remove failed ($($_.Exception.Message)). Will still wait + retry."
        }
    }
    Write-Host "Polling until terminal state..." -ForegroundColor Cyan
    $deadline2 = (Get-Date).AddMinutes(3)
    $skipReupload = $false
    do {
        Start-Sleep -Seconds 3
        try {
            $check = Invoke-MgGraphRequest -Method GET `
                -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$($existing.id)" `
                -ErrorAction Stop
            Write-Host "  status: $($check.status)" -ForegroundColor Gray
            if ($check.status -eq 'available') {
                # Upload completed successfully. If this row was already 'available'
                # at script entry, we /remove'd it and will re-upload (so the next
                # poll will eventually 404). If it was 'uploadInProgress' at entry,
                # this IS our content from a prior run -- success, exit early.
                if ($existing.status -eq 'uploadInProgress') {
                    Write-Host "[OK] Prior upload completed successfully (status='available'). Nothing more to do." -ForegroundColor Green
                    Write-Host ""
                    Write-Host "Upload id: $($existing.id)" -ForegroundColor Gray
                    $skipReupload = $true
                    break
                }
                # else: just-/remove'd, but state hasn't moved yet -- keep polling.
            }
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match '404|NotFound|does not exist') {
                Write-Host "  status: removed (404 -- ready to re-upload)" -ForegroundColor Green
                break
            }
            Write-Warning "Poll failed: $msg"
            break
        }
    } while ((Get-Date) -lt $deadline2)
    if ($skipReupload) { return }
}

$bodyHashtable = @{
    fileName                          = $admxFileName
    languageCodes                     = @('en-US')
    targetPrefix                      = 'pimactivator'
    targetNamespace                   = 'MortenKnudsen.PIM4EntraPS.PimActivator'
    policyType                        = 'admxIngested'
    revision                          = '1.0'
    content                           = $admxBase64
    groupPolicyUploadedLanguageFiles  = @(
        @{
            fileName     = $admlFileName
            languageCode = 'en-US'
            content      = $admlBase64
        }
    )
}
$body = $bodyHashtable | ConvertTo-Json -Depth 20

Write-Host "Uploading ADMX + ADML..." -ForegroundColor Cyan
$created = Invoke-MgGraphRequest -Method POST `
    -Uri 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles' `
    -Body $body -ContentType 'application/json' -ErrorAction Stop
$uploadId = $created.id
Write-Host "[OK] Uploaded. id=$uploadId  status=$($created.status)" -ForegroundColor Green

# Intune processes the ADMX asynchronously. Poll status briefly.
Write-Host "Waiting for Intune to process the ADMX (status -> uploadCompleted)..." -ForegroundColor Cyan
$deadline = (Get-Date).AddMinutes(2)
do {
    Start-Sleep -Seconds 3
    try {
        $check = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyUploadedDefinitionFiles/$uploadId" `
            -ErrorAction Stop
        Write-Host "  status: $($check.status)" -ForegroundColor Gray
        if ($check.status -in @('available','uploadCompleted')) { break }
        if ($check.status -in @('uploadFailed','removalFailed')) {
            throw "Intune rejected the ADMX. status=$($check.status). uploadInfo: $($check.uploadInfo | ConvertTo-Json -Compress)"
        }
    } catch {
        Write-Warning "Status poll failed: $($_.Exception.Message)"
        break
    }
} while ((Get-Date) -lt $deadline)

Write-Host ""
Write-Host "NEXT STEPS (in Intune admin center):" -ForegroundColor Yellow
Write-Host "  1. Devices -> Configuration -> Create -> New Policy" -ForegroundColor Yellow
Write-Host "  2. Platform: 'Windows 10 and later'  Profile type: 'Templates -> Imported Administrative templates'" -ForegroundColor Yellow
Write-Host "  3. Pick 'PIM Activator (PIM4EntraPS)' -> 'PIM Activator' category -> enable" -ForegroundColor Yellow
Write-Host "     'Tenant catalog -- Microsoft Edge' (and Chrome if you use it)" -ForegroundColor Yellow
Write-Host "  4. Paste your JSON catalog into the textbox (single-line, see sample-tenant-catalog.json)" -ForegroundColor Yellow
Write-Host "  5. Assign to your MSP-admin device group" -ForegroundColor Yellow
Write-Host "  6. Verify on a target device (as admin):" -ForegroundColor Yellow
Write-Host "       Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\eheocihmlppcophaeakmdenhgcookkab\policy' -Name tenantCatalog" -ForegroundColor Gray
Write-Host ""
Write-Host "Done." -ForegroundColor Green
