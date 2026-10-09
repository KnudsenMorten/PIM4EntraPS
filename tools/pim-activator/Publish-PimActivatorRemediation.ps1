#Requires -Version 5.1

<#
.SYNOPSIS
    Builds the PIM Activator Intune Remediation (Detect + Remediate) for your tenant and uploads it to Intune -- creates it, or updates it in place when a Remediation with the same name exists -- and assigns it to the one group you name (nobody otherwise).

.DESCRIPTION
    Documentation (purpose, who may run it, every change and permission, -WhatIf, undo):
    https://invardia.com/docs/pim/scripts/Publish-PimActivatorRemediation/
    -WhatIf signs in, reads Intune and prints every change it would make; it uploads, assigns and writes nothing (the
    pair it would upload is built in the temp folder so you can read it).

    ONE file, ONE command: nothing else to download.
    97.2 (owner 2026-10-08: "this guide is wrong as it refers to 3 files, but the cmdlets show is missing 2 of them"):
    the script builds Detect-PimActivator.ps1 + Remediate-PimActivator.ps1 ITSELF from the parameters (the same text
    the PIM Manager's Operations > PIM Activator page builds for the same settings), writes them next to itself
    (-OutDir), then uploads them. Always: run as SYSTEM, 64-bit PowerShell, no signature check.
    -DetectScript / -RemediateScript upload your own pair instead (an override).

    WHO GETS IT (owner 2026-10-08: "customer must define who (group) to deploy to - not everyone" / "confirm that the
    cmdlets doesn't add an assignment by default"): -AssignToGroupId assigns the Remediation to THAT group (it replaces
    the Remediation's assignments) and reads the assignment back. Without it NOTHING is assigned -- a new Remediation
    reaches nobody until you assign a group; an existing one keeps the assignments it has. There is no "all users" /
    "all devices" option.

    NO MODULES (owner 2026-10-07: "neither pim, si or invardia must have dependencies"): plain REST. You sign in in the
    browser (Edge) as an Intune administrator; the script asks Microsoft Graph for DeviceManagementScripts.ReadWrite.All
    only. -AccessToken takes a token you already have instead (automation).

.EXAMPLE
    # PROD, assigned to the group of admins who use the Activator (the command the PIM Manager page shows):
    .\Publish-PimActivatorRemediation.ps1 -TenantId <tenant id> -Channel Released -ClientId <PIM Activator app id> `
        -CatalogName 'Contoso' -AssignToGroupId <group object id>
.EXAMPLE
    # Upload a pair you edited yourself, no assignment yet:
    .\Publish-PimActivatorRemediation.ps1 -TenantId <tenant id> -Name 'PIM Activator settings (TEST)' `
        -DetectScript .\Detect-PimActivator.ps1 -RemediateScript .\Remediate-PimActivator.ps1
.EXAMPLE
    # Preview: what it would upload and assign -- changes nothing:
    .\Publish-PimActivatorRemediation.ps1 -TenantId <tenant id> -ClientId <PIM Activator app id> -AssignToGroupId <group object id> -WhatIf
.NOTES
    A transcript of the run is written to <temp>\pim-manager-logs\ (its path is printed).
.LINK
    https://invardia.com/docs/pim/scripts/Publish-PimActivatorRemediation/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # The tenant to sign in to and to write into the extension's catalog (its id).
    [string]$TenantId = 'organizations',
    # Released (PROD) or Test -- which extension the Remediation configures.
    [ValidateSet('Released', 'Test')][string]$Channel = 'Released',
    # The PIM Activator app registration of that channel (its Application (client) id) -- step 1 of the page.
    [string]$ClientId,
    # The settings step of the page: the name admins see, the activation defaults, the optional filters and limits.
    [string]$CatalogName = 'PIM',
    [string]$DefaultJustification = 'Change in infrastructure',
    [ValidateRange(1, 24)][int]$DefaultDurationHours = 8,
    [string]$Prefix = '',
    [string]$EntraPrefix = '',
    [string]$AzurePrefix = '',
    [ValidateRange(0, 100)][int]$AutoActivateMaxGroups = -1,
    [ValidateRange(0, 100)][int]$BulkActivateConfirmThreshold = -1,
    [string[]]$Browsers = @('Edge', 'Chrome'),
    # Optional: more tenants for the popup's tenant switcher (multi-tenant), a JSON array of
    # { name, tenantId, clientId, ... } -- this tenant stays the first entry. Empty = this tenant only.
    [string]$AdditionalTenantsJson = '',
    # The Remediation's name in Intune. Default 'PIM Activator settings (PROD)' / '(TEST)'.
    [string]$Name,
    # Overrides: upload these two files instead of building them.
    [string]$DetectScript,
    [string]$RemediateScript,
    # Where the built pair is written (default: next to this script).
    [string]$OutDir,
    # A Microsoft Graph access token with DeviceManagementScripts.ReadWrite.All -- skips the browser sign-in.
    [string]$AccessToken,
    [string]$Description = '',
    # Assign to this Entra group (user or device group). REPLACES the Remediation's assignments. Not given = NOTHING is
    # assigned (nobody gets it until you assign a group).
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')][string]$AssignToGroupId,
    [ValidatePattern('^\d{2}:\d{2}$')][string]$DailyTime = '09:00',
    # With an assignment: run every N hours instead of daily (e.g. 1 = every hour).
    [ValidateRange(1, 23)][int]$EveryHours
)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
# The pure builder (catalog + the filled pair) and the shipped Detect / Remediate text. Loaded with the literal form below
# so Build-PimSupportScripts inlines it (with the two scripts embedded) into the standalone download.
. (Join-Path $PSScriptRoot '_PimActivatorBuild.ps1')
# 12.7 run frame: "Documentation: <page>" as the first line + a transcript in the temp folder (its path printed at the end).
. (Join-Path $PSScriptRoot '..\setup\_PimScriptDoc.ps1')
$null = Start-PimScriptRun -Script 'Publish-PimActivatorRemediation'
try {
$_preview = [bool]$WhatIfPreference
if ($_preview) { Write-Host 'PREVIEW (-WhatIf): signs in and reads; every change is listed as "What if:" and none is made.' -ForegroundColor Yellow }

$label =if ($Channel -eq 'Test') { 'TEST' } else { 'PROD' }
if (-not "$Name".Trim()) { $Name = "PIM Activator settings ($label)" }
$here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if (-not "$OutDir".Trim()) { $OutDir = $here }

# ---- the pair: built from the parameters, or the two files given -------------------------------------------------------
if ($DetectScript -or $RemediateScript) {
    if (-not ($DetectScript -and $RemediateScript)) { throw 'Pass BOTH -DetectScript and -RemediateScript (or neither, and the script builds them).' }
    foreach ($f in $DetectScript, $RemediateScript) { if (-not (Test-Path -LiteralPath $f)) { throw "Script not found: $f" } }
    $detPath = (Resolve-Path -LiteralPath $DetectScript).Path; $remPath = (Resolve-Path -LiteralPath $RemediateScript).Path
    Write-Host "Using your own pair: $detPath + $remPath" -ForegroundColor Cyan
} else {
    $guid = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    if ("$TenantId" -notmatch $guid) { throw '-TenantId <tenant id> is required to build the Remediation (it goes into the extension''s catalog). Copy the command from the PIM Manager (Operations > PIM Activator > Intune remediation).' }
    if ("$ClientId" -notmatch $guid) { throw "-ClientId <PIM Activator app id> is required to build the Remediation -- create the app first (Deploy-PimActivatorBackend.ps1) and use its client id." }
    $br = @(@($Browsers) | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $pair = New-PimActivatorRemediationPair -TenantId $TenantId -ClientId $ClientId -Name $CatalogName -Channel $Channel -Browsers $br `
        -DefaultJustification $DefaultJustification -DefaultDurationHours $DefaultDurationHours -Prefix $Prefix -EntraPrefix $EntraPrefix -AzurePrefix $AzurePrefix `
        -AutoActivateMaxGroups $(if ($AutoActivateMaxGroups -ge 0) { $AutoActivateMaxGroups } else { $null }) -BulkActivateConfirmThreshold $(if ($BulkActivateConfirmThreshold -ge 0) { $BulkActivateConfirmThreshold } else { $null }) `
        -AdditionalTenantsJson $AdditionalTenantsJson
    $writeDir = $OutDir
    if (-not $PSCmdlet.ShouldProcess($OutDir, 'Write Detect-PimActivator.ps1 + Remediate-PimActivator.ps1 (the pair it uploads)')) {
        # preview: the pair goes to the temp folder instead, so it can still be read (and is what would be uploaded)
        $writeDir = Join-Path ([IO.Path]::GetTempPath()) ('pim-activator-preview-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    }
    if (-not (Test-Path -LiteralPath $writeDir)) { New-Item -ItemType Directory -Force -Path $writeDir -WhatIf:$false | Out-Null }
    $detPath = Join-Path $writeDir 'Detect-PimActivator.ps1'; $remPath = Join-Path $writeDir 'Remediate-PimActivator.ps1'
    # UTF-8 WITH a BOM, so Windows PowerShell 5.1 on the device reads non-ASCII characters right (same bytes as the page).
    $enc = New-Object Text.UTF8Encoding($true)
    [IO.File]::WriteAllText($detPath, $pair.detect, $enc); [IO.File]::WriteAllText($remPath, $pair.remediate, $enc)
    Write-Host "Built the Remediation for $label (tenant $TenantId, app $ClientId, '$CatalogName'): $detPath + $remPath$(if ($writeDir -ne $OutDir) { ' (preview copy in the temp folder)' })" -ForegroundColor Cyan
}
$who = if ($AssignToGroupId) { "group $AssignToGroupId" } else { 'NOBODY yet (no -AssignToGroupId)' }
Write-Host "Deploys to: $who" -ForegroundColor Cyan

function ConvertTo-PaB64Url([byte[]]$Bytes) { [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') }

function Get-PaGraphToken {
    <# Browser sign-in, auth code + PKCE on a localhost loopback (the Microsoft Graph Command Line Tools public client). #>
    param([string]$Tenant)
    $cid = '14d82eec-204b-4c2f-b7e8-296a70dab67e'
    $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    $verifier = ConvertTo-PaB64Url $b
    $challenge = ConvertTo-PaB64Url ([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::ASCII.GetBytes($verifier)))
    $state = [guid]::NewGuid().ToString('N')
    $tcp = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0); $tcp.Start()
    $redirect = "http://localhost:$(([Net.IPEndPoint]$tcp.LocalEndpoint).Port)/"
    $scope = 'https://graph.microsoft.com/DeviceManagementScripts.ReadWrite.All offline_access openid profile'
    $url = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/authorize?client_id=$cid&response_type=code&response_mode=query" +
           "&redirect_uri=$([uri]::EscapeDataString($redirect))&scope=$([uri]::EscapeDataString($scope))&state=$state" +
           "&code_challenge=$challenge&code_challenge_method=S256&prompt=select_account"
    $edge = @((Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'), (Join-Path $env:ProgramFiles 'Microsoft\Edge\Application\msedge.exe')) |
            Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    Write-Host 'Sign in in the browser window as an Intune administrator ...' -ForegroundColor Yellow
    if ($edge) { Start-Process -FilePath $edge -ArgumentList @('--new-window', $url) -WhatIf:$false } else { Start-Process $url -WhatIf:$false }   # -WhatIf still signs in
    $query = $null
    try {
        $deadline = (Get-Date).AddMinutes(5)
        while (-not $query) {
            if ((Get-Date) -gt $deadline) { throw 'Timed out (5 min) waiting for the sign-in.' }
            if (-not $tcp.Pending()) { Start-Sleep -Milliseconds 200; continue }
            $c = $tcp.AcceptTcpClient()
            try {
                $s = $c.GetStream(); $line = (New-Object IO.StreamReader($s)).ReadLine()
                $html = '<html><body style="font-family:sans-serif"><h3>Signed in.</h3>You can close this tab.</body></html>'
                $w = New-Object IO.StreamWriter($s); $w.Write("HTTP/1.1 200 OK`r`nContent-Type: text/html`r`nContent-Length: $($html.Length)`r`nConnection: close`r`n`r`n$html"); $w.Flush()
                if ($line -match '^GET /\?(\S+) HTTP') { $query = $Matches[1] }
            } finally { $c.Close() }
        }
    } finally { $tcp.Stop() }
    $kv = @{}; foreach ($p in ($query -split '&')) { $k, $v = $p -split '=', 2; $kv[$k] = [uri]::UnescapeDataString(("$v" -replace '\+', ' ')) }   # (( )): inside a method call the -replace comma is an argument separator
    if ($kv['error']) { throw "Sign-in failed: $($kv['error']) -- $($kv['error_description'])" }
    if ($kv['state'] -ne $state) { throw 'Sign-in answer did not match (state) -- close all browser windows and run again.' }
    $r = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
        client_id = $cid; grant_type = 'authorization_code'; code = $kv['code']; redirect_uri = $redirect; code_verifier = $verifier; scope = $scope }
    return "$($r.access_token)"
}

$token = if ($AccessToken) { $AccessToken } else { Get-PaGraphToken -Tenant $TenantId }
function Invoke-PaGraph([string]$Method, [string]$Uri, $Body) {
    $p = @{ Method = $Method; Uri = $Uri; Headers = @{ Authorization = "Bearer $token" } }
    if ($null -ne $Body) { $p.Body = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 8)); $p.ContentType = 'application/json' }
    Invoke-RestMethod @p
}
$base = 'https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts'

# find an existing Remediation with this exact name
$all = @(); $resp = Invoke-PaGraph GET "$base`?`$select=id,displayName"
$all += @($resp.value); while ($resp.'@odata.nextLink') { $resp = Invoke-PaGraph GET $resp.'@odata.nextLink'; $all += @($resp.value) }
$match = @($all | Where-Object { "$($_.displayName)" -eq $Name })
if ($match.Count -gt 1) { throw "More than one Remediation is named '$Name' -- rename or delete the extras first (refusing to guess which to update)." }

$body = [ordered]@{
    displayName              = $Name
    description              = $(if ($Description) { $Description } else { "PIM Activator -- uploaded by Publish-PimActivatorRemediation.ps1 $((Get-Date).ToString('yyyy-MM-dd HH:mm'))" })
    publisher                = 'PIM Manager'
    runAsAccount             = 'system'
    runAs32Bit               = $false
    enforceSignatureCheck    = $false
    detectionScriptContent   = [Convert]::ToBase64String([IO.File]::ReadAllBytes($detPath))
    remediationScriptContent = [Convert]::ToBase64String([IO.File]::ReadAllBytes($remPath))
}
$_what = "Detect + Remediate scripts (sha256 $((Get-FileHash -LiteralPath $detPath -Algorithm SHA256).Hash.Substring(0, 12))... / $((Get-FileHash -LiteralPath $remPath -Algorithm SHA256).Hash.Substring(0, 12))...), run as SYSTEM, 64-bit, no signature check"
$_scheduleText = if ($EveryHours) { "every $EveryHours hour(s)" } else { "daily at $DailyTime" }
if ($match) {
    $id = "$($match[0].id)"
    if (-not $PSCmdlet.ShouldProcess("Intune Remediation '$Name' ($id)", "Update (PATCH deviceHealthScripts): $_what")) {
        if ($AssignToGroupId) { [void]$PSCmdlet.ShouldProcess("Intune Remediation '$Name' ($id)", "Assign to group $AssignToGroupId ONLY (replaces its assignments), $_scheduleText") }
        Write-Host 'PREVIEW (-WhatIf) complete: nothing was uploaded, assigned or changed. Run the same command without -WhatIf to apply.' -ForegroundColor Yellow
        return
    }
    [void](Invoke-PaGraph PATCH "$base/$id" $body)
    Write-Host "[OK] Updated '$Name' ($id)." -ForegroundColor Green
} else {
    if (-not $PSCmdlet.ShouldProcess("Intune Remediation '$Name'", "Create (POST deviceHealthScripts): $_what")) {
        $asgText = if ($AssignToGroupId) { "group $AssignToGroupId ONLY, $_scheduleText" } else { 'NOBODY (no -AssignToGroupId)' }
        if ($AssignToGroupId) { [void]$PSCmdlet.ShouldProcess("Intune Remediation '$Name'", "Assign to $asgText") }
        Write-Host 'PREVIEW (-WhatIf) complete: nothing was uploaded, assigned or changed. Run the same command without -WhatIf to apply.' -ForegroundColor Yellow
        return
    }
    $body['roleScopeTagIds'] = @('0')
    $id = "$((Invoke-PaGraph POST $base $body).id)"
    Write-Host "[OK] Created '$Name' ($id)." -ForegroundColor Green
}

# read it back -- Intune must hold exactly what was uploaded
$back = Invoke-PaGraph GET "$base/$id"
if ("$($back.detectionScriptContent)" -ne $body.detectionScriptContent -or "$($back.remediationScriptContent)" -ne $body.remediationScriptContent -or "$($back.runAsAccount)" -ne 'system' -or [bool]$back.runAs32Bit) {
    throw "'$Name' ($id) did not read back as uploaded -- check it in Intune."
}
Write-Host '     read back OK: same scripts, runs as SYSTEM, 64-bit.' -ForegroundColor DarkGray

if ($AssignToGroupId) {
    $schedule = if ($EveryHours) { @{ '@odata.type' = '#microsoft.graph.deviceHealthScriptHourlySchedule'; interval = $EveryHours } }
                else { @{ '@odata.type' = '#microsoft.graph.deviceHealthScriptDailySchedule'; interval = 1; useUtc = $false; time = "$DailyTime`:00" } }
    $asg = @{ deviceHealthScriptAssignments = @(@{
        target               = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $AssignToGroupId }
        runRemediationScript = $true
        runSchedule          = $schedule
    }) }
    if (-not $PSCmdlet.ShouldProcess("Intune Remediation '$Name' ($id)", "Assign to group $AssignToGroupId ONLY (replaces its assignments), $_scheduleText")) { return }
    [void](Invoke-PaGraph POST "$base/$id/assign" $asg)
    # read the assignment back: exactly this group, nothing wider
    $got = @((Invoke-PaGraph GET "$base/$id/assignments").value)
    $hit = @($got | Where-Object { "$($_.target.groupId)" -ieq $AssignToGroupId -and "$($_.target.'@odata.type')" -match 'groupAssignmentTarget' })
    if ($got.Count -ne 1 -or $hit.Count -ne 1) { throw "'$Name' ($id): the assignment did not read back as ONLY group $AssignToGroupId ($($got.Count) assignment(s)) -- check it in Intune > Devices > Scripts and remediations." }
    Write-Host ("[OK] Assigned to group $AssignToGroupId only, {0} (read back)." -f $(if ($EveryHours) { "every $EveryHours hour(s)" } else { "daily at $DailyTime" })) -ForegroundColor Green
} else {
    $n = @((Invoke-PaGraph GET "$base/$id/assignments").value).Count
    if ($n) { Write-Host "     assignments: $n (unchanged -- this run assigned nothing)" -ForegroundColor DarkGray }
    else {
        Write-Host "     NOT ASSIGNED to anyone yet -- nobody gets it. Assign it to a group: re-run with -AssignToGroupId <group object id>," -ForegroundColor Yellow
        Write-Host "     or in Intune > Devices > Scripts and remediations > '$Name' > Properties > Assignments (a group, never all users / all devices)." -ForegroundColor Yellow
    }
}
} finally { Stop-PimScriptRun -Script 'Publish-PimActivatorRemediation' }
