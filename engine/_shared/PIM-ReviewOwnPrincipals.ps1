#Requires -Version 5.1
<#
  PIM-ReviewOwnPrincipals.ps1 -- Review active assignments: which rows are PIM Manager's OWN access, the Invardia
  Support app's, or a break-glass account's (owner 2026-10-08: "default it must not show permissions related to pim
  manager + invardia support app + emergency accounts delegations (defined in PIM manager). make option to tick them on").

  The page hides those three groups by default, each behind its own tick. This file decides WHICH principals they are.
  It never guesses from a display name first -- every rule below is a fact the directory or the store states:

    PIM MANAGER (product)  * the service principal this Manager runs as (its app id: PIM_RuntimeAppId / AZURE_CLIENT_ID /
                             the appid in its own Graph token), and every app id the install configured for itself
                             (engine app of a non-hosted install, the SQL identities, the managed identity client ids);
                           * every MANAGED IDENTITY whose resource id (alternativeNames) lies in the SAME resource group as
                             this Manager's own managed identity -- ca-pim-tick, ca-pim-manager and the publish / update /
                             downlink jobs all live there;
                           * every service principal that is a member of PIM's own SQL admin group (grp-pim-sql-admins):
                             the setup scripts put exactly the tick, Manager, deploy and updater identities there.
    SUPPORT APP            * a service principal carrying the tag 'InvardiaSupport' -- Invardia's New-InvardiaSupportApp
                             tags everything it creates with it;
                           * the app id of the contained SQL user Grant-PimSupportAccess creates FROM THE APP'S SID
                             (default name 'invardia-support') -- read from the store, never configured by hand;
                           * FALLBACK ONLY (support apps made before the tag existed): a service principal whose display
                             name starts with 'Invardia Support'.
                           A support app is never also counted as product, even when it sits in the SQL admin group.
    BREAK-GLASS            the accounts DEFINED in PIM Manager (Settings > Break-glass: pim.Settings 'BreakGlassAccounts'
                           unioned with the legacy setting) -- matched by object id or UPN, like the revoke guard.
                           An UNREADABLE list marks nothing here (the revoke guard still protects every row server-side);
                           the page says the list could not be read.

  Pure: Graph and SQL come in as scriptblocks (tests/Test-PimReviewOwnPrincipals.ps1 drives it offline). Never throws.
#>

function Get-PimReviewSupportTag { 'InvardiaSupport' }

function ConvertFrom-PimSqlSidToGuid {
    # An Entra application's contained user (CREATE USER ... WITH SID = <appId bytes>, TYPE = E) carries the app id as its
    # 16-byte SID. Accepts a byte[] or a 0x-hex string; returns the app id GUID string, or '' when it is not one.
    param($Sid)
    try {
        $bytes = $null
        if ($Sid -is [byte[]]) { $bytes = $Sid }
        # PowerShell unrolls a byte[] returned from a function / scriptblock into object[] -- take it back as bytes.
        elseif ($Sid -is [array] -and @($Sid).Count -eq 16 -and -not (@($Sid) | Where-Object { $_ -isnot [byte] -and $_ -isnot [int] })) { $bytes = [byte[]]@($Sid) }
        elseif ("$Sid" -match '^(0x)?([0-9a-fA-F]{32})$') {
            $hex = $Matches[2]; $bytes = New-Object byte[] 16
            for ($i = 0; $i -lt 16; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
        }
        if (-not $bytes -or $bytes.Length -ne 16) { return '' }
        return ([guid]::new([byte[]]$bytes)).ToString()
    } catch { return '' }
}

function Get-PimReviewOwnPrincipals {
    <#
      -ServicePrincipalIds  the service-principal ids seen in the review rows (looked up in ONE getByIds call)
      -SelfAppId            the app id this Manager runs as
      -ProductAppIds        further app ids the install configured for itself
      -Graph                { param($Method, $Path, $Body) } -> the parsed Graph answer
      -SqlSupportSid        { } -> the SID (byte[] / 0x hex) of the support contained user, or $null (optional)
      Returns { product[]; support[]; productKnown; supportKnown; errors[]; fallbackNameMatches[] } -- ids lower-case.
    #>
    [CmdletBinding()]
    param(
        [string[]]$ServicePrincipalIds = @(),
        [string]$SelfAppId = '',
        [string[]]$ProductAppIds = @(),
        [Parameter(Mandatory)][scriptblock]$Graph,
        [scriptblock]$SqlSupportSid,
        [string]$SqlAdminGroupName = 'grp-pim-sql-admins'
    )
    $tag = Get-PimReviewSupportTag
    $errors = New-Object System.Collections.Generic.List[string]
    $objs = @{}                                        # id -> service principal object (every one we learn about)
    $sqlGroupMembers = New-Object 'System.Collections.Generic.HashSet[string]'
    $productApp = New-Object 'System.Collections.Generic.HashSet[string]'
    $supportApp = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($a in (@($SelfAppId) + @($ProductAppIds))) { if ("$a".Trim()) { [void]$productApp.Add("$a".Trim().ToLowerInvariant()) } }
    $add = { param($o) if ($o -and "$($o.id)") { $objs["$($o.id)".ToLowerInvariant()] = $o } }
    $selfId = ''; $rgPrefix = ''; $productKnown = $false; $supportKnown = $false

    # 1. who am I -- and, for a managed identity, which resource group the product lives in
    if ("$SelfAppId".Trim()) {
        try {
            $r = & $Graph 'GET' ("/servicePrincipals?`$filter=appId eq '{0}'&`$select=id,appId,displayName,servicePrincipalType,alternativeNames,tags" -f "$SelfAppId".Trim()) $null
            $self = @($r.value) | Select-Object -First 1
            if ($self) {
                & $add $self; $selfId = "$($self.id)".ToLowerInvariant(); $productKnown = $true
                $rid = @(@($self.alternativeNames) | Where-Object { "$_" -match '^/subscriptions/' }) | Select-Object -First 1
                if ("$($self.servicePrincipalType)" -eq 'ManagedIdentity' -and $rid) {
                    $rgPrefix = ("$rid" -replace '(?i)^(/subscriptions/[^/]+/resourcegroups/[^/]+/).*$', '$1').ToLowerInvariant()
                }
            } else { $errors.Add("no service principal for this Manager's app id") }
        } catch { $errors.Add("this Manager's own identity could not be read: $($_.Exception.Message)") }
    } else { $errors.Add('the identity this Manager runs as could not be resolved') }

    # 2. PIM's own SQL admin group: its service-principal members are the product's identities (and the support app)
    if ("$SqlAdminGroupName".Trim()) {
        try {
            $f = [uri]::EscapeDataString("displayName eq '$("$SqlAdminGroupName".Replace("'", "''"))'")
            $gs = @((& $Graph 'GET' "/groups?`$filter=$f&`$select=id,displayName" $null).value)
            foreach ($g in $gs) {
                $m = & $Graph 'GET' "/groups/$($g.id)/members/microsoft.graph.servicePrincipal?`$select=id,appId,displayName,servicePrincipalType,alternativeNames,tags&`$top=999" $null
                foreach ($o in @($m.value)) { if ($o -and "$($o.id)") { & $add $o; [void]$sqlGroupMembers.Add("$($o.id)".ToLowerInvariant()) } }
            }
            $productKnown = $true
        } catch { $errors.Add("PIM's SQL admin group could not be read: $($_.Exception.Message)") }
    }

    # 3. the support app: by its tag (the directory says so)
    try {
        $f = [uri]::EscapeDataString("tags/any(t:t eq '$tag')")
        foreach ($o in @((& $Graph 'GET' "/servicePrincipals?`$filter=$f&`$select=id,appId,displayName,servicePrincipalType,alternativeNames,tags" $null).value)) { & $add $o }
        $supportKnown = $true
    } catch { $errors.Add("the Invardia Support app could not be looked up by its tag: $($_.Exception.Message)") }
    # ... and by the SQL user Grant-PimSupportAccess made from its SID (the store says so)
    if ($SqlSupportSid) {
        try {
            $sid = & $SqlSupportSid
            $sAppId = ConvertFrom-PimSqlSidToGuid -Sid $sid
            if ($sAppId) { [void]$supportApp.Add($sAppId.ToLowerInvariant()) }
        } catch { $errors.Add("the support SQL user could not be read: $($_.Exception.Message)") }
    }

    # 4. the service principals in the rows, in one call
    $need = @($ServicePrincipalIds | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Select-Object -Unique | Where-Object { -not $objs.ContainsKey($_) })
    for ($i = 0; $i -lt $need.Count; $i += 1000) {
        $chunk = @($need[$i..([Math]::Min($i + 999, $need.Count - 1))])
        try {
            $r = & $Graph 'POST' '/directoryObjects/getByIds' (@{ ids = $chunk; types = @('servicePrincipal') } | ConvertTo-Json -Depth 4 -Compress)
            foreach ($o in @($r.value)) { & $add $o }
        } catch { $errors.Add("the service principals in the list could not be read: $($_.Exception.Message)") }
    }

    # 5. classify
    $product = New-Object System.Collections.Generic.List[string]
    $support = New-Object System.Collections.Generic.List[string]
    $fallback = New-Object System.Collections.Generic.List[string]
    foreach ($id in $objs.Keys) {
        $o = $objs[$id]
        $appId = "$($o.appId)".ToLowerInvariant()
        $isSupport = (@($o.tags) -contains $tag) -or ($appId -and $supportApp.Contains($appId))
        if (-not $isSupport -and "$($o.displayName)" -match '^(?i)Invardia Support') { $isSupport = $true; $fallback.Add($id) }
        if ($isSupport) { $support.Add($id); continue }
        $inRg = $false
        if ($rgPrefix -and "$($o.servicePrincipalType)" -eq 'ManagedIdentity') {
            $inRg = [bool](@($o.alternativeNames) | Where-Object { "$_".ToLowerInvariant().StartsWith($rgPrefix) })
        }
        if ($id -eq $selfId -or ($appId -and $productApp.Contains($appId)) -or $inRg -or $sqlGroupMembers.Contains($id)) { $product.Add($id) }
    }
    return [pscustomobject]@{
        product             = @($product | Sort-Object)
        support             = @($support | Sort-Object)
        productKnown        = [bool]$productKnown
        supportKnown        = [bool]$supportKnown
        fallbackNameMatches = @($fallback)
        resourceGroupPrefix = $rgPrefix
        errors              = @($errors)
    }
}

function Get-PimReviewRowField {
    param($Row, [string]$Name)
    if ($null -eq $Row) { return '' }
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { return "$($Row[$Name])" } else { return '' } }
    $p = $Row.PSObject.Properties[$Name]; if ($p) { return "$($p.Value)" } else { return '' }
}

function Set-PimReviewRowOwnKind {
    <#
      Marks each row 'ownKind' = breakglass | support | product | '' (in that order of precedence) and returns the counts.
      -BreakGlass are the identifiers (UPNs / object ids) from Get-PimBreakGlassAccountStatus; -Product / -Support ids.
    #>
    param([object[]]$Rows = @(), [string[]]$Product = @(), [string[]]$Support = @(), [string[]]$BreakGlass = @())
    $p = New-Object 'System.Collections.Generic.HashSet[string]'; foreach ($x in $Product) { if ("$x") { [void]$p.Add("$x".ToLowerInvariant()) } }
    $s = New-Object 'System.Collections.Generic.HashSet[string]'; foreach ($x in $Support) { if ("$x") { [void]$s.Add("$x".ToLowerInvariant()) } }
    $b = New-Object 'System.Collections.Generic.HashSet[string]'; foreach ($x in $BreakGlass) { if ("$x".Trim() -and "$x" -notmatch '^<') { [void]$b.Add("$x".Trim().ToLowerInvariant()) } }
    $n = [ordered]@{ product = 0; support = 0; breakglass = 0 }
    foreach ($row in @($Rows)) {
        if ($null -eq $row) { continue }
        $pid_ = (Get-PimReviewRowField $row 'principalId').Trim().ToLowerInvariant()
        $lbl  = (Get-PimReviewRowField $row 'principal').Trim().ToLowerInvariant()
        $upn  = (Get-PimReviewRowField $row 'principalUpn').Trim().ToLowerInvariant()
        $k = ''
        if (($pid_ -and $b.Contains($pid_)) -or ($lbl -and $b.Contains($lbl)) -or ($upn -and $b.Contains($upn))) { $k = 'breakglass' }
        elseif ($pid_ -and $s.Contains($pid_)) { $k = 'support' }
        elseif ($pid_ -and $p.Contains($pid_)) { $k = 'product' }
        if ($k) { $n[$k]++ }
        if ($row -is [System.Collections.IDictionary]) { $row['ownKind'] = $k } else { $row | Add-Member -NotePropertyName ownKind -NotePropertyValue $k -Force }
    }
    return $n
}
