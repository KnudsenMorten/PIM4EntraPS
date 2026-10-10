#Requires -Version 5.1
<#
.SYNOPSIS
    REQ 93 -- let an AI client reach the Manager's MCP endpoint (/mcp) with the person's OWN Entra sign-in. PLANS by
    default; changes nothing without -Apply.

.DESCRIPTION
    The Manager's Easy Auth signs people in to the PAGE. An MCP client instead sends an ACCESS TOKEN for the Manager's
    own API, which Easy Auth only accepts once the application exposes one and the audience is allowed. This script,
    on the Manager's existing Easy Auth application (found from the container app -- never created here):

      1. identifier URI  api://<app id>                     (merged -- existing URIs kept)
      2. one delegated scope  'mcp.access'                  (merged -- existing scopes kept, never disabled or removed)
      3. Azure CLI pre-authorised for that scope            (so a person who uses the CLI as their MCP token source gets
                                                              api://<id>/mcp.access without a consent prompt)
      4. Easy Auth allowed audiences += api://<app id>, <app id>   (the page sign-in is untouched)
      5. the Manager's env PIM_MCP_AUDIENCE = api://<app id>,<app id> -- what /mcp pins a token to (BUG-283: the Manager
         verifies the bearer itself; without this it refuses every MCP call). Setting it rolls a new revision.
      6. Easy Auth excludedPaths += /mcp + /.well-known/oauth-protected-resource[/mcp] -- so an MCP client without a
         token gets 401 + WWW-Authenticate (sign-in discovery) instead of a 302 to the login page. ONLY when the
         Manager image is 2.4.483 or newer: an older Manager trusts the edge headers, which outside Easy Auth are
         the caller's own words.

    It grants NOTHING by itself: a token only proves who the person is -- the Manager's role for that person (Reader /
    Admin / SuperAdmin) decides what the MCP tools may do, exactly as on the page.

    Connect (example -- the token is the PERSON's own, from whatever client they already use; the Azure CLI is
    pre-authorised above only so that a person who has it gets the token without a consent prompt. This script itself
    never runs the CLI):
      claude mcp add --transport http pim https://<manager host>/mcp --header "Authorization: Bearer <access token for api://<app id>/mcp.access>"
      e.g. the token from: az account get-access-token --scope api://<app id>/mcp.access --query accessToken -o tsv

    100.41 (framework 12.17 NO-AZ): every call is ARM / Graph REST through PIM-Rest's ONE token client
    (engine/_shared/PIM-ArmSetup.ps1): a calling deploy's REST session as it is, else the Invardia Support app's session,
    else the person signed in in the browser. -AzureConfigDir is OBSOLETE and ignored (kept so existing callers still bind).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$TenantId,
    [string]$ManagerApp = 'ca-pim-manager',
    [string]$AzureConfigDir,   # OBSOLETE (100.41): ignored -- no az profile is used any more
    [switch]$Apply
)
$ErrorActionPreference = 'Stop'
if ("$AzureConfigDir".Trim()) { Write-Warning "-AzureConfigDir '$AzureConfigDir' is ignored: this script no longer uses an az profile (100.41) -- it signs in through PIM-Rest." }
$solRootMcp = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
if (-not (Get-Command Get-PimRestToken -ErrorAction SilentlyContinue)) { . (Join-Path $solRootMcp 'engine\_shared\PIM-Rest.ps1') }
if (-not (Get-Command Invoke-PimSetupArm -ErrorAction SilentlyContinue)) { . (Join-Path $solRootMcp 'engine\_shared\PIM-ArmSetup.ps1') }
$script:AzCliAppId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'   # Microsoft Azure CLI (first-party, the same in every tenant)

function Get-PimManagerMcpAuthPlan {
    <#
      PURE. From the Manager's application (Graph object: appId, identifierUris, api.oauth2PermissionScopes,
      api.preAuthorizedApplications) and its Easy Auth config -> @{ steps; patch; audiences; scopeId; reason }.
      -NewScopeId is the id a NEW scope gets (passed in so the plan stays pure). The patch body MERGES: every existing
      identifier URI, scope and pre-authorisation is kept.
    #>
    param([Parameter(Mandatory)][object]$App, [AllowNull()][object]$Auth, [Parameter(Mandatory)][string]$NewScopeId,
          [object[]]$EnvVars = @(), [string]$ManagerImage = '')
    $appId = "$($App.appId)"; $uri = "api://$appId"
    $steps = New-Object System.Collections.Generic.List[string]
    $uris = @(@($App.identifierUris) | Where-Object { "$_".Trim() })
    if ($uris -notcontains $uri) { $steps.Add('identifier-uri') | Out-Null; $uris = @($uris) + $uri }
    $api = $App.api
    $scopes = @(if ($api -and $api.oauth2PermissionScopes) { @($api.oauth2PermissionScopes) })
    $sc = @($scopes | Where-Object { "$($_.value)" -eq 'mcp.access' })[0]
    $scopeId = if ($sc) { "$($sc.id)" } else { $NewScopeId }
    if (-not $sc) {
        $steps.Add('scope') | Out-Null
        $scopes = @($scopes) + [pscustomobject][ordered]@{ id = $NewScopeId; value = 'mcp.access'; type = 'User'; isEnabled = $true
            adminConsentDisplayName = 'Use the PIM Manager through an AI assistant (MCP)'; adminConsentDescription = 'Lets an MCP client act as the signed-in person on the PIM Manager. What it may do is decided by that person''s role in the Manager.'
            userConsentDisplayName = 'Use the PIM Manager through an AI assistant (MCP)'; userConsentDescription = 'Lets an MCP client act as you on the PIM Manager, within your Manager role.' }
    }
    $pre = @(if ($api -and $api.preAuthorizedApplications) { @($api.preAuthorizedApplications) })
    $cli = @($pre | Where-Object { "$($_.appId)" -eq $script:AzCliAppId })[0]
    if (-not $cli) { $steps.Add('preauthorize-azure-cli') | Out-Null; $pre = @($pre) + [pscustomobject]@{ appId = $script:AzCliAppId; delegatedPermissionIds = @($scopeId) } }
    elseif (@($cli.delegatedPermissionIds) -notcontains $scopeId) {
        $steps.Add('preauthorize-azure-cli') | Out-Null
        $pre = @($pre | ForEach-Object { if ("$($_.appId)" -eq $script:AzCliAppId) { [pscustomobject]@{ appId = $_.appId; delegatedPermissionIds = @(@($_.delegatedPermissionIds) + $scopeId | Select-Object -Unique) } } else { $_ } })
    }
    $aad = if ($Auth -and $Auth.PSObject.Properties['identityProviders'] -and $Auth.identityProviders) { $Auth.identityProviders.azureActiveDirectory } else { $null }
    $have = @(if ($aad -and $aad.validation -and $aad.validation.allowedAudiences) { @($aad.validation.allowedAudiences) })
    $aud = @(@($have) + @($uri, $appId) | Where-Object { "$_".Trim() } | Select-Object -Unique)
    if (@($uri, $appId | Where-Object { $have -notcontains $_ }).Count) { $steps.Add('audiences') | Out-Null }
    $envValue = "$uri,$appId"
    $envHave = "$((@($EnvVars) | Where-Object { "$($_.name)" -eq 'PIM_MCP_AUDIENCE' } | Select-Object -First 1).value)"
    if ($envHave -ne $envValue) { $steps.Add('mcp-audience-env') | Out-Null }
    # BUG-283: excluding /mcp from Easy Auth is safe ONLY on a Manager that verifies the bearer itself (2.4.483+)
    $exclNeed = @('/mcp', '/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp')
    $gv = if ($Auth -and $Auth.PSObject.Properties['globalValidation']) { $Auth.globalValidation } else { $null }
    $exclHave = @(if ($gv -and $gv.PSObject.Properties['excludedPaths'] -and $gv.excludedPaths) { @($gv.excludedPaths) })
    $excl = @(@($exclHave) + $exclNeed | Where-Object { "$_".Trim() } | Select-Object -Unique)
    $ver = if ("$ManagerImage" -match ':v?(\d+)\.(\d+)\.(\d+)$') { [version]"$($Matches[1]).$($Matches[2]).$($Matches[3])" } else { $null }
    $exclSafe = ($null -ne $ver -and $ver -ge [version]'2.4.483')
    $deferred = ''
    if (@($exclNeed | Where-Object { $exclHave -notcontains $_ }).Count) {
        if ($exclSafe) { $steps.Add('exclude-paths') | Out-Null }
        else { $deferred = " (excludedPaths deferred: the Manager image '$ManagerImage' is not 2.4.483+ -- it would trust edge headers on /mcp; re-run after the roll)" }
    }
    $boundId = if ($aad -and $aad.registration) { "$($aad.registration.clientId)" } else { '' }
    $why = if ($boundId -and $boundId -ne $appId) { "Easy Auth is bound to $boundId, not $appId -- refusing" } elseif ($steps.Count) { "to do: $($steps -join ', ')$deferred" } elseif ($deferred) { "nothing to do now$deferred" } else { 'nothing to do -- MCP clients can sign in' }
    return [pscustomobject]@{ steps = @($steps); scopeId = $scopeId; audiences = $aud; ok = (-not $boundId -or $boundId -eq $appId)
        envValue = $envValue; excludedPaths = $excl; deferred = [bool]$deferred
        patch = [ordered]@{ identifierUris = @($uris); api = [ordered]@{ oauth2PermissionScopes = @($scopes); preAuthorizedApplications = @($pre) } }; reason = $why }
}

function Invoke-PimMcpRetry([scriptblock]$Call, [int]$Tries = 8) {
    # Graph replication: pre-authorising a scope seconds after it was created fails (seen live on internal 2026-10-02)
    for ($i = 1; $i -le $Tries; $i++) {
        try { return (& $Call) } catch { if ($i -eq $Tries) { throw }; Start-Sleep -Seconds (5 * $i) }
    }
}
function Get-PimMcpAuthNode($Node, [string[]]$Path) {
    # the child object at -Path under -Node, created (empty) where it is missing -- for the authConfigs read-modify-write
    $cur = $Node
    foreach ($p in $Path) {
        if ($null -eq $cur.$p) { $cur | Add-Member -NotePropertyName $p -NotePropertyValue ([pscustomobject]@{}) -Force }
        $cur = $cur.$p
    }
    return $cur
}
function Get-PimMcpAuthState {
    # authConfigs/current's PROPERTIES (identityProviders, globalValidation ... -- the shape `az containerapp auth show` printed)
    $r = Get-PimArmAcaAuthConfig -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp
    if ($r -and $r.properties) { return $r.properties }
    return $null
}

function Resolve-PimManagerImageVersion {
    <#
      PURE. The deploy pins the Manager by DIGEST (registry/pim-manager@sha256:...), which carries no version, so the
      2.4.483+ gate on excludedPaths deferred forever (live, r1-pro 2026-10-03). Given the registry's tags for the repo
      (@{ name; digest }), return 'registry/repo:<version>' for the highest version tag pointing at that digest; an image
      already tagged is returned as is; no matching version tag = the input (the gate then defers, fail closed).
    #>
    param([string]$Image, [object[]]$Tags = @())
    if ("$Image" -notmatch '^(?<repo>[^@]+)@(?<dig>sha256:[0-9a-f]+)$') { return "$Image" }
    $repo = $Matches['repo']; $dig = $Matches['dig']
    $vers = @(@($Tags) | Where-Object { "$($_.digest)" -eq $dig -and "$($_.name)" -match '^v?\d+\.\d+\.\d+$' } |
              ForEach-Object { [version]("$($_.name)" -replace '^v', '') } | Sort-Object -Descending)
    if (-not $vers.Count) { return "$Image" }
    return "${repo}:$($vers[0])"
}
function Get-PimManagerImageForGate([string]$Image) {
    # the registry's tags for a digest-pinned image, with their digests (ACR data plane /acr/v1/<repo>/_tags, paged with `last`)
    if ("$Image" -notmatch '^(?<reg>[^/.]+)\.azurecr\.io/(?<repo>[^@:]+)@sha256:') { return "$Image" }
    $ls = "$($Matches['reg'].ToLowerInvariant()).azurecr.io"; $repo = $Matches['repo']
    $tags = New-Object System.Collections.Generic.List[object]
    try {
        $last = ''
        for ($page = 0; $page -lt 100; $page++) {
            $r = Invoke-PimAcrData -LoginServer $ls -Repository $repo -Path ("/acr/v1/$repo/_tags?n=1000" + $(if ($last) { "&last=$([uri]::EscapeDataString($last))" } else { '' }))
            $pageTags = @(@($r.tags) | Where-Object { $_ -and "$($_.name)".Trim() })
            foreach ($t in $pageTags) { $tags.Add($t) }
            if ($pageTags.Count -lt 1000) { break }
            $last = "$($pageTags[-1].name)"
        }
    } catch { $tags.Clear() }   # unreadable = no tags (the gate then defers -- fail closed), as before
    return (Resolve-PimManagerImageVersion -Image $Image -Tags @($tags | ForEach-Object { [pscustomobject]@{ name = "$($_.name)"; digest = "$($_.digest)" } }))
}

if ($MyInvocation.InvocationName -eq '.') { return }

# WHO: a calling deploy's REST session is used as it is (it must be for -TenantId); standalone, Connect-PimSetupRest pins
# -TenantId (the Invardia Support app's session when one covers it, else the person signs in in the browser).
if (-not "$($global:PIM_SetupRestMode)".Trim()) { [void](Connect-PimSetupRest -SubscriptionId $SubscriptionId -TenantId $TenantId) }
elseif ("$($global:PIM_TenantId)".Trim() -and "$($global:PIM_TenantId)".Trim().ToLowerInvariant() -ne "$TenantId".Trim().ToLowerInvariant()) {
    throw "the REST session in this shell is for tenant '$($global:PIM_TenantId)', not '$TenantId' -- refusing."
}
$auth = Get-PimMcpAuthState
$appId = "$($auth.identityProviders.azureActiveDirectory.registration.clientId)".Trim()
if (-not $appId) { throw "$ManagerApp has no Easy Auth application -- run Set-PimManagerEasyAuth.ps1 first (the page sign-in comes before MCP)" }
$app = Get-PimGraphApplication -Id $appId
if (-not $app) { throw "the Easy Auth application $appId was not found in tenant $TenantId" }
$ca = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp
if (-not $ca) { throw "container app $ManagerApp not found in $ResourceGroup" }
$c0 = @($ca.properties.template.containers)[0]
$plan = Get-PimManagerMcpAuthPlan -App $app -Auth $auth -NewScopeId ([guid]::NewGuid().ToString()) -EnvVars @($c0.env) -ManagerImage (Get-PimManagerImageForGate "$($c0.image)")
Write-Host "==> $ManagerApp / application $appId : $($plan.reason)" -ForegroundColor Cyan
if (-not $plan.ok) { throw $plan.reason }
if (-not $plan.steps.Count) { return $plan }
if (-not $Apply) { Write-Host '    PLAN ONLY -- re-run with -Apply.' -ForegroundColor Yellow; return $plan }

if (@($plan.steps | Where-Object { $_ -in @('identifier-uri', 'scope', 'preauthorize-azure-cli') }).Count) {
    # a scope must exist BEFORE it is pre-authorised: write URIs + scopes first, then the pre-authorisation
    # Graph PATCH /applications/{object id} -- the body goes straight to Graph (no temp file, no az.cmd quoting)
    $patchUrl = "/applications/$($app.id)"
    [void](Invoke-PimSetupGraph -Method PATCH -Path $patchUrl -Body ([ordered]@{ identifierUris = @($plan.patch.identifierUris); api = [ordered]@{ oauth2PermissionScopes = @($plan.patch.api.oauth2PermissionScopes) } }))
    [void](Invoke-PimMcpRetry { Invoke-PimSetupGraph -Method PATCH -Path $patchUrl -Body ([ordered]@{ api = [ordered]@{ preAuthorizedApplications = @($plan.patch.api.preAuthorizedApplications) } }) })
}
if ($plan.steps -contains 'audiences') {
    # az containerapp auth microsoft update --allowed-audiences: read-modify-write of authConfigs/current (all else kept)
    [void](Set-PimArmAcaAuthConfig -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -Mutate {
        param($p)
        $val = Get-PimMcpAuthNode $p @('identityProviders', 'azureActiveDirectory', 'validation')
        $val | Add-Member -NotePropertyName allowedAudiences -NotePropertyValue @($plan.audiences) -Force
    })
}
if ($plan.steps -contains 'mcp-audience-env') {
    # the env var BEFORE the exclusion: a Manager without it refuses /mcp (503), never trusts anything
    [void](Set-PimArmAcaAppEnvVars -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -Env @{ PIM_MCP_AUDIENCE = "$($plan.envValue)" })
}
if ($plan.steps -contains 'exclude-paths') {
    # az containerapp auth update --excluded-paths: the merged list (the plan keeps every existing path)
    [void](Set-PimArmAcaAuthConfig -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp -Mutate {
        param($p)
        $gv = Get-PimMcpAuthNode $p @('globalValidation')
        $gv | Add-Member -NotePropertyName excludedPaths -NotePropertyValue @($plan.excludedPaths) -Force
    })
}
$app2 = Get-PimGraphApplication -Id $appId
$auth2 = Get-PimMcpAuthState
$ca2 = Get-PimArmAcaApp -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Name $ManagerApp
$c2 = @($ca2.properties.template.containers)[0]
$after = Get-PimManagerMcpAuthPlan -App $app2 -Auth $auth2 -NewScopeId ([guid]::NewGuid().ToString()) -EnvVars @($c2.env) -ManagerImage (Get-PimManagerImageForGate "$($c2.image)")
if ($after.steps.Count) { throw "read-back: still $($after.reason)" }
Write-Host "==> done. Scope api://$appId/mcp.access; the person's Manager role decides what the MCP tools may do." -ForegroundColor Green
return $after
