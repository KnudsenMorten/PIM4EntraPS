#Requires -Version 5.1
<#
.SYNOPSIS
    PIM REQUIREMENTS 95.2i -- after a roll, the in-cloud updater CHECKS the engine identity's rights against what THIS
    version needs, and reports what is missing with the exact fix command. It never grants anything.

.DESCRIPTION
    WHY (found 2026-10-07, 2.4.419 -> 2.4.519): the updater rolled code + schema, the new version expected one more
    Microsoft Graph application permission (AccessReview.ReadWrite.All), and nothing said so until a person opened the
    Manager and read "Core functionality is BLOCKED". Every upgrade from an older version can hit this.

    WHAT (owner-approved 2026-10-29):
      1. one plain line in the updater's own log (and the fix command under it),
      2. the same verdict recorded in the update run's record (pim.Settings 'UpdateState' -> 'enginePermissions'), which
         the Manager's update panel and its permission banner read,
      3. NEVER fails the roll and NEVER grants: the updater's identity holds no Graph app roles and no role-assignment
         write, and it may not get them (PIM-ConvergeDefaults.ps1: "the updater may not grant roles"). The fix is the
         product's own Grant-PimEnginePermissions command, run by a Privileged Role Administrator.

    ONE PERMISSION MAP. What the engine needs is Get-PimRequiredGraphCapabilities and the verdict is Get-PimPermissionHealth
    (PIM-PermissionHealth.ps1) -- the same functions the Manager's banner uses. Nothing here lists a permission.

    WHERE THE FACTS COME FROM (every read may fail; a failed read is "not checked", never "all present"):
      Graph   1. live: the engine identity's appRoleAssignments (works where this identity may read service principals);
              2. else the Manager's last REAL check (pim.Settings 'PermissionSnapshot': the granted list, recorded by the
                 Manager each time it reads the engine identity) -- compared against THIS version's list;
              3. else an older snapshot's missingIds (what the Manager last saw missing; roles new in this version are then
                 not confirmed and it says so).
      Azure   the engine identity's role assignments listed at THIS resource group with assignedTo() -- ARM returns the
              ones inherited from the subscription, management groups and the tenant root too (Reader on the group is
              enough to list them). Reader + User Access Administrator at the tenant root, as the banner judges them.

    Every decision is PURE and offline-tested (tests/Test-PimUpdaterPermissionCheck.ps1); the I/O step takes seams.
    PS 5.1 + 7, no modules, no az, ASCII only.
#>

Set-StrictMode -Off
. (Join-Path $PSScriptRoot 'PIM-PermissionHealth.ps1')

$script:PimUpdPermGraphAppId = '00000003-0000-0000-c000-000000000000'
$script:PimUpdPermAuthzApi   = '2022-04-01'
$script:PimUpdPermAcaApi     = '2024-03-01'
# Owner, User Access Administrator, Role Based Access Control Administrator -- the roles that can write role assignments
# (the same three the Manager's check counts as an Azure role-management scope).
$script:PimUpdPermRbacWriters = @('8e3af657-a8ff-443c-a75c-2fe8c4bcb635', '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9', 'f58310d9-a9f6-439a-9e8d-f62e7b41a168')

function Get-PimUpdPermFirstLine {
    # PURE. The first line of an error text, trimmed and bounded (a log line, never a stack).
    param([AllowNull()][string]$Text)
    $t = ((("$Text") -split "`n")[0]).Trim()
    if ($t.Length -gt 240) { $t = $t.Substring(0, 240) + '...' }
    return $t
}

function Get-PimUpdPermItems {
    # PURE. A Graph / ARM answer as a list: an array (Invoke-PimGraph -All) or an object with .value.
    param([AllowNull()][object]$Answer)
    if ($null -eq $Answer) { return @() }
    if ($Answer -is [array]) { return @($Answer | Where-Object { $null -ne $_ }) }
    if ($Answer.PSObject -and $Answer.PSObject.Properties['value']) { return @(@($Answer.value) | Where-Object { $null -ne $_ }) }
    return @($Answer)
}

function ConvertTo-PimUpdaterGraphRoleNames {
    <#
      PURE. appRoleAssignments rows -> the Microsoft Graph app-role VALUES held (for example Group.ReadWrite.All).
      -GraphSpId: Microsoft Graph's service principal id in this tenant; -AppRoles: its appRoles (id, value).
      Rows on another API, and role ids Graph does not name, are not Graph permissions and are left out.
    #>
    param([object[]]$Assignments = @(), [string]$GraphSpId = '', [object[]]$AppRoles = @())
    $byId = @{}
    foreach ($r in @($AppRoles | Where-Object { $_ })) { if ("$($r.id)".Trim()) { $byId["$($r.id)".Trim().ToLowerInvariant()] = "$($r.value)".Trim() } }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($a in @($Assignments | Where-Object { $_ })) {
        if ("$GraphSpId".Trim() -and "$($a.resourceId)".Trim() -ine "$GraphSpId".Trim()) { continue }
        $v = $byId["$($a.appRoleId)".Trim().ToLowerInvariant()]
        if ($v -and -not $out.Contains($v)) { $out.Add($v) }
    }
    return @($out.ToArray())
}

function Get-PimUpdaterAzureWriterScopes {
    # PURE. The scopes where the identity may write role assignments (Owner / User Access Administrator / RBAC Administrator).
    param([object[]]$Assignments = @())
    $s = New-Object System.Collections.Generic.List[string]
    foreach ($a in @($Assignments | Where-Object { $_ })) {
        $p = if ($a.PSObject.Properties['properties'] -and $a.properties) { $a.properties } else { $a }
        $g = ((("$($p.roleDefinitionId)").Trim().TrimEnd('/')) -split '/')[-1].ToLowerInvariant()
        if ($script:PimUpdPermRbacWriters -contains $g) { $sc = "$($p.scope)".Trim(); if ($sc -and -not $s.Contains($sc)) { $s.Add($sc) } }
    }
    return @($s.ToArray())
}

function Get-PimUpdaterEnginePermissionVerdict {
    <#
      PURE. The updater's verdict on the engine identity's rights for THIS version.
        -GraphReadable / -GrantedGraphRoles  the Graph app roles held ($false = not known)
        -GraphSource                         'live' | 'snapshot' (the Manager's last real check) | ''
        -GraphCheckedUtc                     when the snapshot was taken ('' for live)
        -SnapshotMissingIds                  an OLD snapshot without the granted list: what the Manager last saw missing
        -GraphReason                         why Graph is not known
        -AzureAssignments                    the identity's role assignments as ARM lists them; $null = not readable
        -AzureReason / -AzureDelegationCount / -TenantId / -EngineObjectId / -EngineName / -Version / -NowUtc
      Returns @{ state = ok | missing | unknown; graphState; azureState; missingGraph[]; missingAzure[]; source; headline;
                 lines[] (@{ level = info | warn; text }); fix; record }.
      Graph and Azure are judged by Get-PimPermissionHealth, one dimension at a time (the other held), so a gap in one
      is never hidden by an unknown in the other. Mail is not this check's business (the Manager checks it).
    #>
    param(
        [bool]$GraphReadable = $false,
        [string[]]$GrantedGraphRoles = @(),
        [string]$GraphSource = '',
        [string]$GraphCheckedUtc = '',
        [string[]]$SnapshotMissingIds = @(),
        [string]$GraphReason = '',
        [AllowNull()][object[]]$AzureAssignments = $null,
        [string]$AzureReason = '',
        [int]$AzureDelegationCount = -1,
        [string]$TenantId = '',
        [string]$EngineObjectId = '',
        [string]$EngineName = 'the engine identity',
        [string]$Version = '',
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $allRoles = @(Get-PimRequiredGraphCapabilities | ForEach-Object { "$($_.role)" })
    $ver = "$Version".Trim()
    $forVer = if ($ver) { "version $ver" } else { 'this version' }

    # ---- Graph -------------------------------------------------------------------------------------------------------
    $graphState = 'unknown'; $missingGraph = @(); $graphNote = ''
    if ($GraphReadable) {
        $hg = Get-PimPermissionHealth -GrantedGraphRoles @($GrantedGraphRoles) -AzureRoleScopes @('/') -IdentityName $EngineName `
                  -GraphReadable $true -MailSender 'not-checked-here' -MailSendOk $true -AzureDelegationCount 0
        $missingGraph = @(@($hg.missingRequired) | Where-Object { $_ } | ForEach-Object { "$($_.role)" } | Where-Object { $_ } | Select-Object -Unique)
        $graphState = if ($missingGraph.Count) { 'missing' } else { 'ok' }
        if ("$GraphSource" -eq 'snapshot') { $graphNote = "from the PIM Manager's last check of the engine identity$(if ("$GraphCheckedUtc".Trim()) { " ($("$GraphCheckedUtc".Trim()))" })" }
    } else {
        $old = @(@($SnapshotMissingIds) | ForEach-Object { "$_".Trim() } | Where-Object { $_ -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$' } | Select-Object -Unique)
        if ($old.Count) {
            $graphState = 'missing'; $missingGraph = $old
            $graphNote = "as the PIM Manager last saw them$(if ("$GraphCheckedUtc".Trim()) { " ($("$GraphCheckedUtc".Trim()))" }); permissions new in $forVer could not be confirmed"
        }
    }

    # ---- Azure -------------------------------------------------------------------------------------------------------
    $azureState = 'unknown'; $missingAzure = @(); $azNeedUaa = $false; $azNeedReader = $false
    if ($null -ne $AzureAssignments) {
        $asg = @($AzureAssignments | Where-Object { $_ })
        $hold = Get-PimRootAzureHoldings -Assignments $asg -TenantId $TenantId -Readable $true
        $ha = Get-PimPermissionHealth -GrantedGraphRoles $allRoles -AzureRoleScopes @(Get-PimUpdaterAzureWriterScopes -Assignments $asg) -IdentityName $EngineName `
                  -GraphReadable $true -MailSender 'not-checked-here' -MailSendOk $true -AzureDelegationCount $AzureDelegationCount `
                  -RootReaderHeld $hold.reader -RootUaaHeld $hold.userAccessAdmin -TenantId $TenantId -EngineObjectId $EngineObjectId
        # The same two conditions the Manager's fix block uses (pim-manager.html permFixScript): Reader at the root when it
        # is missing; User Access Administrator at the root when no Azure role-management scope is held where one is needed.
        $azNeedReader = ("$($ha.azureRoot.reader)" -eq 'missing')
        $azNeedUaa    = ($ha.azureOk -eq $false) -or ("$($ha.azureRoot.userAccessAdmin)" -eq 'missing' -and [bool]$ha.azureRoot.userAccessAdminNeeded)
        if ($azNeedReader) { $missingAzure += 'Reader at the tenant root management group' }
        if ($azNeedUaa)    { $missingAzure += 'User Access Administrator at the tenant root management group (Azure resource delegations are defined)' }
        if (-not "$TenantId".Trim() -and -not $missingAzure.Count) { $azureState = 'unknown'; $AzureReason = 'the tenant id is not known here' }
        else { $azureState = if ($missingAzure.Count) { 'missing' } else { 'ok' } }
    }

    # ---- one verdict, lines, the fix -------------------------------------------------------------------------------
    $state = if ($graphState -eq 'missing' -or $azureState -eq 'missing') { 'missing' } elseif ($graphState -eq 'unknown' -or $azureState -eq 'unknown') { 'unknown' } else { 'ok' }
    $azRoles = @(); if ($azNeedReader) { $azRoles += 'Reader' }; if ($azNeedUaa) { $azRoles += 'User Access Administrator' }
    $fix = ''
    if ($state -eq 'missing') { $fix = Get-PimEnginePermissionFixCommand -TenantId $TenantId -EngineObjectId $EngineObjectId -GraphPermissions $missingGraph -AzureRootRoles $azRoles }

    $lines = New-Object System.Collections.Generic.List[object]
    $add = { param($lvl, $txt) $lines.Add([pscustomobject]@{ level = $lvl; text = $txt }) }
    switch ($graphState) {
        'ok'      { & $add 'info' ("engine permissions: every Microsoft Graph permission $forVer needs is held by $EngineName" + $(if ($graphNote) { " ($graphNote)" } else { '' })) }
        'missing' { & $add 'warn' ("engine permissions: MISSING $($missingGraph.Count) Microsoft Graph permission(s) $forVer needs: $($missingGraph -join ', ')" + $(if ($graphNote) { " ($graphNote)" } else { '' }) + " -- the engine cannot do that work until they are granted") }
        default   { & $add 'warn' ("engine permissions: Microsoft Graph not checked ($(if ("$GraphReason".Trim()) { "$GraphReason".Trim() } else { 'the engine identity''s permissions could not be read' })) -- PIM Manager > Home > Verify permissions checks them") }
    }
    switch ($azureState) {
        'ok'      { & $add 'info' 'engine permissions: the Azure rights at the tenant root are as needed' }
        'missing' { & $add 'warn' ("engine permissions: MISSING Azure right(s): $($missingAzure -join '; ')") }
        default   { & $add 'warn' ("engine permissions: Azure rights not checked ($(if ("$AzureReason".Trim()) { "$AzureReason".Trim() } else { 'the role assignments could not be read' }))") }
    }
    if ($state -eq 'missing') { & $add 'warn' 'engine permissions: the updater may not grant roles -- a Privileged Role Administrator runs the command below (browser sign-in, no modules); a new grant reaches the engine within ~30 minutes' }

    $nMiss = $missingGraph.Count + $missingAzure.Count
    $headline = switch ($state) {
        'missing' { "The engine is missing $nMiss permission(s) $forVer needs" }
        'unknown' { 'The updater could not check every engine permission' }
        default   { "The engine holds every permission $forVer needs" }
    }
    $record = [ordered]@{
        checkedUtc   = $NowUtc.ToUniversalTime().ToString('o')
        version      = $ver
        state        = $state
        graphState   = $graphState
        azureState   = $azureState
        source       = "$GraphSource"
        identity     = "$EngineName"
        objectId     = "$EngineObjectId"
        missingGraph = @($missingGraph)
        missingAzure = @($missingAzure)
        headline     = $headline
        fix          = "$fix"
        reason       = (@(@("$GraphReason".Trim(), "$AzureReason".Trim()) | Where-Object { $_ }) -join '; ')
    }
    return [pscustomobject]@{
        state = $state; graphState = $graphState; azureState = $azureState
        missingGraph = @($missingGraph); missingAzure = @($missingAzure); source = "$GraphSource"
        headline = $headline; lines = @($lines.ToArray()); fix = "$fix"; record = $record
    }
}

function Invoke-PimUpdaterEnginePermissionCheck {
    <#
      The updater's step (update-job-entry, after the roll and on the 'ahead' exit). READ ONLY. NEVER throws.
        -Arm   { param($method, $path, $body) }  -- called with 'GET' only
        -Graph { param($path) }                   -- Microsoft Graph GET (relative to v1.0, no leading '/'); all pages
        -Store { param($op, $name, $value) }      -- called with 'get' only ($null = no store)
      Returns the verdict of Get-PimUpdaterEnginePermissionVerdict (with .record for the update run's record).
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [string]$TickJob = 'ca-pim-tick', [string]$TenantId = '', [string]$Version = '',
          [Parameter(Mandatory)][scriptblock]$Arm, [scriptblock]$Graph, [scriptblock]$Store,
          [int]$AzureDelegationCount = -1, [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        $rgScope = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup"
        # ---- who is the engine -------------------------------------------------------------------------------------
        $oid = ''; $oidWhy = ''
        try { $j = & $Arm 'GET' "$rgScope/providers/Microsoft.App/jobs/$TickJob`?api-version=$($script:PimUpdPermAcaApi)" $null; $oid = "$($j.identity.principalId)".Trim() }
        catch { $oidWhy = Get-PimUpdPermFirstLine $_.Exception.Message }
        if (-not $oid) {
            $why = "the engine job $TickJob's identity could not be read$(if ($oidWhy) { ": $oidWhy" })"
            return (Get-PimUpdaterEnginePermissionVerdict -GraphReason $why -AzureReason $why -TenantId $TenantId -EngineName $TickJob -Version $Version -NowUtc $NowUtc)
        }

        # ---- Graph: live, else the Manager's last real check ---------------------------------------------------------
        $graphOk = $false; $granted = @(); $src = ''; $at = ''; $oldMissing = @(); $gWhy = ''
        if ($Graph) {
            try {
                $gsp = @(Get-PimUpdPermItems (& $Graph ("servicePrincipals?`$filter=appId eq '{0}'&`$select=id,appRoles" -f $script:PimUpdPermGraphAppId))) | Select-Object -First 1
                if (-not $gsp) { throw 'Microsoft Graph''s service principal was not found' }
                $asg = @(Get-PimUpdPermItems (& $Graph "servicePrincipals/$oid/appRoleAssignments"))
                $granted = @(ConvertTo-PimUpdaterGraphRoleNames -Assignments $asg -GraphSpId "$($gsp.id)" -AppRoles @($gsp.appRoles))
                $graphOk = $true; $src = 'live'
            } catch { $gWhy = "this updater may not read it ($(Get-PimUpdPermFirstLine $_.Exception.Message))" }
        } else { $gWhy = 'no Microsoft Graph access here' }
        if (-not $graphOk) {
            $snap = $null
            if ($Store) { try { $snap = & $Store 'get' 'PermissionSnapshot' $null } catch { $snap = $null } }
            if ($snap -is [string]) { try { $snap = $snap | ConvertFrom-Json } catch { $snap = $null } }
            if ($snap -is [System.Collections.IDictionary]) { $snap = [pscustomobject]$snap }
            if ($snap -and $snap.PSObject) {
                $sOid = "$($snap.engineObjectId)".Trim()
                $sAt = $snap.checkedUtc; if ($sAt -is [datetime]) { $sAt = $sAt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
                if ($sOid -and $sOid -ine $oid) { $gWhy += '; the PIM Manager''s last check was of another identity' }
                elseif ([bool]$snap.readable -and $snap.PSObject.Properties['granted']) {
                    $granted = @(@($snap.granted) | ForEach-Object { "$_".Trim() } | Where-Object { $_ }); $graphOk = $true; $src = 'snapshot'; $at = "$sAt"
                } elseif ([bool]$snap.readable) { $oldMissing = @(@($snap.missingIds) | Where-Object { "$_".Trim() }); $at = "$sAt"; if (-not $oldMissing.Count) { $gWhy += '; the PIM Manager''s last check is from a version that did not record the granted list' } }
            } else { $gWhy += '; the PIM Manager has not recorded a check of the engine identity yet' }
        }

        # ---- Azure: the engine's assignments as seen from THIS resource group (incl. inherited) ----------------------
        $azList = $null; $aWhy = ''
        try {
            $r = & $Arm 'GET' ("$rgScope/providers/Microsoft.Authorization/roleAssignments?`$filter=assignedTo('{0}')&api-version={1}" -f $oid, $script:PimUpdPermAuthzApi) $null
            $azList = @(Get-PimUpdPermItems $r)
        } catch { $aWhy = Get-PimUpdPermFirstLine $_.Exception.Message }

        return (Get-PimUpdaterEnginePermissionVerdict -GraphReadable $graphOk -GrantedGraphRoles $granted -GraphSource $src -GraphCheckedUtc $at `
                    -SnapshotMissingIds $oldMissing -GraphReason $(if ($graphOk) { '' } else { $gWhy.TrimStart('; ') }) `
                    -AzureAssignments $azList -AzureReason $aWhy -AzureDelegationCount $AzureDelegationCount `
                    -TenantId $TenantId -EngineObjectId $oid -EngineName "$TickJob (engine job)" -Version $Version -NowUtc $NowUtc)
    } catch {
        $why = "the check itself failed: $(Get-PimUpdPermFirstLine $_.Exception.Message)"
        return (Get-PimUpdaterEnginePermissionVerdict -GraphReason $why -AzureReason $why -TenantId $TenantId -EngineName $TickJob -Version $Version -NowUtc $NowUtc)
    }
}

function Merge-PimUpdaterPermissionRecord {
    <#
      PURE. The Manager's permission banner + the updater's recorded check (UpdateState.enginePermissions).
      The Manager's OWN live check wins whenever it could read the engine identity (it is newer and complete). When it
      could NOT read it, and the updater recorded missing permissions, the banner says so -- red, with the updater's fix
      command and the missing roles in the shape the page's fix block takes. Otherwise the banner is unchanged.
      -Live: @{ ok; severity; headline; detail; readable; objectId; missingRequired }. Returns the same shape + fromUpdater.
    #>
    param([Parameter(Mandatory)][object]$Live, [AllowNull()][object]$Record)
    $o = [ordered]@{ ok = $Live.ok; severity = "$($Live.severity)"; headline = "$($Live.headline)"; detail = "$($Live.detail)"
                     objectId = "$($Live.objectId)"; missingRequired = @(@($Live.missingRequired) | Where-Object { $null -ne $_ }); fromUpdater = $false }
    if ([bool]$Live.readable -or $null -eq $Record) { return [pscustomobject]$o }
    $fld = { param($k) if ($Record -is [System.Collections.IDictionary]) { $Record[$k] } elseif ($Record.PSObject.Properties[$k]) { $Record.PSObject.Properties[$k].Value } else { $null } }
    if ("$(& $fld 'state')" -ne 'missing') { return [pscustomobject]$o }
    $mg = @(@(& $fld 'missingGraph') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $ma = @(@(& $fld 'missingAzure') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    $caps = @{}; foreach ($c in @(Get-PimRequiredGraphCapabilities)) { $caps["$($c.role)"] = $c }
    $o.ok = $false; $o.severity = 'error'; $o.fromUpdater = $true
    $at = & $fld 'checkedUtc'; if ($at -is [datetime]) { $at = $at.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    $o.headline = "Core functionality is BLOCKED -- $(& $fld 'headline') (found by the update run on $at)"
    $bits = @("The update run checked the engine identity after the roll.")
    if ($mg.Count) { $bits += "Missing Microsoft Graph permission(s): $($mg -join ', ')." }
    if ($ma.Count) { $bits += "Missing Azure right(s): $($ma -join '; ')." }
    $fix = "$(& $fld 'fix')".Trim()
    $d = ($bits -join ' ')
    if ($fix) { $d += "  A Privileged Role Administrator runs (browser sign-in, no modules; the updater may not grant roles):`n" + (Add-PimSupportScriptDocLines -Text $fix) + "`n" }
    $o.detail = "$d  This Manager's own check: $($Live.headline) $($Live.detail)".Trim()
    if (-not $o.objectId) { $o.objectId = "$(& $fld 'objectId')" }
    $o.missingRequired = @($mg | ForEach-Object {
        $c = $caps[$_]
        [pscustomobject]@{ role = $_; capability = $(if ($c) { "$($c.capability)" } else { '' }); tier = $(if ($c) { "$($c.tier)" } else { 'mandatory' }); connector = $(if ($c) { "$($c.connector)" } else { '' }) } })
    return [pscustomobject]$o
}
