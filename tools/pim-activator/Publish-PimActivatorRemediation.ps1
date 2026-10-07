#Requires -Version 5.1
<#
.SYNOPSIS
    Uploads a Detect + Remediate script pair to Intune as a Remediation -- creates it, or updates it in place when a
    Remediation with the same name exists (its assignments are kept). Optional: assign it to a group, all devices or
    all users.

.DESCRIPTION
    For Detect-PimActivator.ps1 + Remediate-PimActivator.ps1 in .\intune-remediation (after you have edited their
    SETTINGS block -- identically in both), or the pair the PIM Manager builds under Operations > PIM Activator.
    Always uploaded as: run as SYSTEM, 64-bit PowerShell, no signature check.

    NO MODULES (owner 2026-10-07: "neither pim, si or invardia must have dependencies"): plain REST. You sign in in the
    browser (Edge) as an Intune administrator; the script asks Microsoft Graph for DeviceManagementScripts.ReadWrite.All
    only. -AccessToken takes a token you already have instead (automation).

.EXAMPLE
    .\Publish-PimActivatorRemediation.ps1 -TenantId <tenant id> -Name 'PIM Activator settings (TEST)' `
        -DetectScript .\Detect-PimActivator.ps1 -RemediateScript .\Remediate-PimActivator.ps1
.EXAMPLE
    .\Publish-PimActivatorRemediation.ps1 -TenantId <tenant id> -Name 'PIM Activator settings (PROD)' `
        -DetectScript .\Detect-PimActivator.ps1 -RemediateScript .\Remediate-PimActivator.ps1 -AssignAllDevices -EveryHours 1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$DetectScript,
    [Parameter(Mandatory)][string]$RemediateScript,
    # The tenant to sign in to (its id or a verified domain). Not given = your home tenant.
    [string]$TenantId = 'organizations',
    # A Microsoft Graph access token with DeviceManagementScripts.ReadWrite.All -- skips the browser sign-in.
    [string]$AccessToken,
    [string]$Description = '',
    # Assign to this Entra group (user or device group). REPLACES the Remediation's assignments. Not given = unchanged.
    [ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$AssignToGroupId,
    # 97.2 (operator 2026-10-07: "make it optional to which group or all devices or all users"): instead of a group,
    # every device or every (licensed) user. Exactly one of -AssignToGroupId / -AssignAllDevices / -AssignAllUsers.
    [switch]$AssignAllDevices,
    [switch]$AssignAllUsers,
    [ValidatePattern('^\d{2}:\d{2}$')][string]$DailyTime = '09:00',
    # With an assignment: run every N hours instead of daily (e.g. 1 = every hour).
    [ValidateRange(1, 23)][int]$EveryHours
)
$ErrorActionPreference = 'Stop'
if (@(@([bool]$AssignToGroupId, [bool]$AssignAllDevices, [bool]$AssignAllUsers) | Where-Object { $_ }).Count -gt 1) { throw 'Pass ONE of -AssignToGroupId, -AssignAllDevices or -AssignAllUsers.' }
foreach ($f in $DetectScript, $RemediateScript) { if (-not (Test-Path -LiteralPath $f)) { throw "Script not found: $f" } }
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

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
    if ($edge) { Start-Process -FilePath $edge -ArgumentList @('--new-window', $url) } else { Start-Process $url }
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
    $kv = @{}; foreach ($p in ($query -split '&')) { $k, $v = $p -split '=', 2; $kv[$k] = [uri]::UnescapeDataString("$v" -replace '\+', ' ') }
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
    detectionScriptContent   = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $DetectScript)))
    remediationScriptContent = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $RemediateScript)))
}
if ($match) {
    $id = "$($match[0].id)"
    [void](Invoke-PaGraph PATCH "$base/$id" $body)
    Write-Host "[OK] Updated '$Name' ($id) -- assignments unchanged." -ForegroundColor Green
} else {
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

if ($AssignToGroupId -or $AssignAllDevices -or $AssignAllUsers) {
    $schedule = if ($EveryHours) { @{ '@odata.type' = '#microsoft.graph.deviceHealthScriptHourlySchedule'; interval = $EveryHours } }
                else { @{ '@odata.type' = '#microsoft.graph.deviceHealthScriptDailySchedule'; interval = 1; useUtc = $false; time = "$DailyTime`:00" } }
    $target = if ($AssignAllDevices) { @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }
              elseif ($AssignAllUsers) { @{ '@odata.type' = '#microsoft.graph.allLicensedUsersAssignmentTarget' } }
              else { @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $AssignToGroupId } }
    $who = if ($AssignAllDevices) { 'all devices' } elseif ($AssignAllUsers) { 'all users' } else { "group $AssignToGroupId" }
    $asg = @{ deviceHealthScriptAssignments = @(@{
        target               = $target
        runRemediationScript = $true
        runSchedule          = $schedule
    }) }
    [void](Invoke-PaGraph POST "$base/$id/assign" $asg)
    Write-Host ("[OK] Assigned to $who, {0}." -f $(if ($EveryHours) { "every $EveryHours hour(s)" } else { "daily at $DailyTime" })) -ForegroundColor Green
} else {
    $n = @((Invoke-PaGraph GET "$base/$id/assignments").value).Count
    Write-Host ("     assignments: {0}" -f $(if ($n) { "$n (unchanged)" } else { 'none yet -- assign it in Intune or re-run with -AssignToGroupId / -AssignAllDevices / -AssignAllUsers' })) -ForegroundColor $(if ($n) { 'DarkGray' } else { 'Yellow' })
}
