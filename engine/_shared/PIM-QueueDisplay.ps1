#Requires -Version 5.1
<#
  PIM4EntraPS -- human-readable change-queue entries (section 65.7 review surface).

  Operator, 2026-09-12, looking at Pending changes: "need real names". The queue's "What" column
  showed only the addressing key, e.g.
      faf09d54-...|pim-for-groups|ad898bc9-...
  which nobody can review. A review surface a human cannot read is not a review surface.

  Two halves, both PURE (no Graph, no SQL) so they are testable offline:
    * New-PimQueueActionNames      -- at ENQUEUE: the readable fields stored on the payload
                                      (principalName, targetName, targetKind, assignmentType),
                                      taken from the row the GUI already sent.
    * Format-PimQueueEntryDisplay  -- at READ: one sentence per entry. Uses the stored names
                                      first; for OLD entries without them it takes names from a
                                      caller-supplied id->name map (the Manager fills that map
                                      from its tenant caches and ONE batched Graph call).
    * Get-PimQueueEntryLookupIds   -- which ids an entry still needs resolved (so the caller
                                      batches every entry's ids into a single lookup, never
                                      one call per row -- section 67 N+1).
  An id that cannot be named is shown as the id plus "(name not found)" -- never blank, and
  never guessed.
#>

Set-StrictMode -Off

function Get-PimQueuePayloadValue {
    param($Payload, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Payload) { return '' }
    if ($Payload -is [System.Collections.IDictionary]) { if ($Payload.Contains($Name)) { return "$($Payload[$Name])" }; return '' }
    $p = $Payload.PSObject.Properties[$Name]
    if ($p -and $null -ne $p.Value) { return "$($p.Value)" }
    return ''
}

function Test-PimQueueLooksLikeId {
    # A bare GUID (or an ARM resource id) is an identifier, not a name. The old enqueue path stored
    # the principal LABEL, which falls back to the id when the name cache missed -- so a stored
    # value is only trusted as a name when it is not simply the id again.
    param([AllowEmptyString()][string]$Value)
    $v = "$Value".Trim()
    if (-not $v) { return $true }
    if ($v -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { return $true }
    return $false
}

function Format-PimQueuePrincipalName {
    # "Display Name (upn)" when both are known and differ; otherwise whichever exists.
    param([AllowEmptyString()][string]$DisplayName, [AllowEmptyString()][string]$Upn)
    $d = "$DisplayName".Trim(); $u = "$Upn".Trim()
    if ($d -and $u -and ($d -ne $u)) { return "$d ($u)" }
    if ($u) { return $u }
    return $d
}

function Get-PimQueueTargetKindLabel {
    param([AllowEmptyString()][string]$ActionType, [AllowEmptyString()][string]$AccessId)
    switch ("$ActionType") {
        'entra-role-revoke'       { return 'Entra role' }
        'azure-rbac-revoke'       { return 'Azure RBAC' }
        'group-assignment-revoke' { $a = "$AccessId".Trim(); if (-not $a) { $a = 'member' }; return "PIM for Groups, $a" }
        default                   { return '' }
    }
}

function New-PimQueueActionNames {
    <#
      Readable fields for a revoke queue entry, from the active-assignment ROW the GUI sent
      (principal / role / scope / accessId), optionally enriched with the principal's display name
      and UPN from the Manager's user cache. Never throws: a missing name is stored as '' and the
      read side falls back to id resolution.
    #>
    param(
        [Parameter(Mandatory)]$Row,
        [Parameter(Mandatory)][string]$ActionType,
        [AllowEmptyString()][string]$PrincipalDisplayName = '',
        [AllowEmptyString()][string]$PrincipalUpn = ''
    )
    $g = { param($n) Get-PimQueuePayloadValue -Payload $Row -Name $n }
    $label = & $g 'principal'
    $upn   = "$PrincipalUpn".Trim()
    if (-not $upn -and "$label" -match '@') { $upn = "$label".Trim() }
    $disp  = "$PrincipalDisplayName".Trim()
    if (-not $disp -and $label -and ($label -notmatch '@') -and -not (Test-PimQueueLooksLikeId $label)) { $disp = "$label".Trim() }
    $principalName = Format-PimQueuePrincipalName -DisplayName $disp -Upn $upn

    $access = & $g 'accessId'
    $targetName = ''
    switch ("$ActionType") {
        'entra-role-revoke' {
            $targetName = & $g 'role'
            $scope = & $g 'scope'
            $dsid  = & $g 'directoryScopeId'
            if ($scope -and $dsid -and $dsid -ne '/' -and $scope -ne '/' -and $scope -ne $targetName) { $targetName = "$targetName at $scope" }
        }
        'group-assignment-revoke' {
            # The row's `scope` is the group's display name; `role` is "<group> (<access>)".
            $targetName = & $g 'scope'
            if (-not $targetName) { $targetName = ((& $g 'role') -replace '\s*\((member|owner)\)\s*$', '') }
        }
        'azure-rbac-revoke' {
            $role  = & $g 'role'
            $scope = & $g 'scope'
            $targetName = if ($role -and $scope) { "$role at $scope" } elseif ($role) { $role } else { '' }
        }
    }
    if (Test-PimQueueLooksLikeId $targetName) { $targetName = '' }
    return [ordered]@{
        principalName  = "$principalName"
        targetName     = "$targetName"
        targetKind     = (Get-PimQueueTargetKindLabel -ActionType $ActionType -AccessId $access)
        assignmentType = "$(& $g 'assignmentType')"
    }
}

function Get-PimQueueEntryLookupIds {
    <#
      The ids an entry still needs NAMED: only those whose readable field is missing. Returns
      @{ objects = @(principal/group ids for /directoryObjects/getByIds); roles = @(entra role
      definition ids) }. A caller unions these across every entry and resolves them in ONE call.
    #>
    param([Parameter(Mandatory)]$Entry)
    $objects = New-Object System.Collections.Generic.List[string]
    $roles   = New-Object System.Collections.Generic.List[string]
    $p = $Entry.payload
    $type = Get-PimQueuePayloadValue -Payload $p -Name 'type'
    if ("$($Entry.entity)" -eq 'PIM-Action-Revoke' -or $type -like '*-revoke') {
        $pn = Get-PimQueuePayloadValue -Payload $p -Name 'principalName'
        $pl = Get-PimQueuePayloadValue -Payload $p -Name 'principal'
        # (not $pid -- that is PowerShell's read-only automatic process-id variable)
        $prinId = Get-PimQueuePayloadValue -Payload $p -Name 'principalId'
        if (-not $pn -and (Test-PimQueueLooksLikeId $pl) -and $prinId) { $objects.Add($prinId) }
        if (-not (Get-PimQueuePayloadValue -Payload $p -Name 'targetName')) {
            $gid = Get-PimQueuePayloadValue -Payload $p -Name 'groupId'
            $rid = Get-PimQueuePayloadValue -Payload $p -Name 'roleDefinitionId'
            if ($type -eq 'group-assignment-revoke' -and $gid) { $objects.Add($gid) }
            if ($type -eq 'entra-role-revoke' -and $rid) { $roles.Add($rid) }
        }
    }
    return @{ objects = @($objects.ToArray()); roles = @($roles.ToArray()) }
}

function Get-PimQueueFriendlyName {
    <#
      PURE. The human name an entry's payload already carries, if any. Producers name the field
      differently (roleName / displayName / GroupName / Username ...), and a display that only
      understood one of them is how a whole queue page ended up reading as GUIDs.
    #>
    param($Payload)
    foreach ($n in @('roleName', 'displayName', 'DisplayName', 'name', 'Name',
                     'GroupName', 'groupName', 'GroupTag', 'groupTag',
                     'UserPrincipalName', 'Username', 'userPrincipalName')) {
        $v = Get-PimQueuePayloadValue -Payload $Payload -Name $n
        if ("$v".Trim()) { return "$v".Trim() }
    }
    return ''
}

function Get-PimQueueServiceLabel {
    # PURE. The product name a human uses for a connector id. Unknown ids are returned as given --
    # a wrong friendly name is worse than the id itself.
    param([AllowEmptyString()][string]$Service)
    switch ("$Service".Trim().ToLowerInvariant()) {
        'entra'         { return 'Entra ID' }
        'entraid'       { return 'Entra ID' }
        'defender'      { return 'Defender XDR' }
        'defender-xdr'  { return 'Defender XDR' }
        'intune'        { return 'Intune' }
        'powerbi'       { return 'Power BI' }
        'powerplatform' { return 'Power Platform' }
        'azuredevops'   { return 'Azure DevOps' }
        'dataverse'     { return 'Dataverse' }
        'businesscentral' { return 'Business Central' }
        default         { return $(if ("$Service".Trim()) { "$Service".Trim() } else { 'service' }) }
    }
}

function Resolve-PimQueueName {
    param([hashtable]$Names, [AllowEmptyString()][string]$Id)
    if (-not "$Id".Trim()) { return '' }
    if ($Names -and $Names.ContainsKey("$Id") -and "$($Names["$Id"])".Trim()) { return "$($Names["$Id"])" }
    return "$Id (name not found)"
}

function Format-PimQueueEntryDisplay {
    <#
      One readable sentence for a queue entry:
        Remove Morten Knudsen (admin-mok-id@x) from PIM-ROLE-HelpdeskL2 (PIM for Groups, member)
        Remove Morten Knudsen (admin-mok-id@x) from Groups Administrator (Entra role)
        Re-issue TAP for Admin-Helpdesk-ID@x
      $Names: id -> readable name, used only for fields the payload does not already carry.
    #>
    param([Parameter(Mandatory)]$Entry, [hashtable]$Names = @{})
    $p = $Entry.payload
    $type   = Get-PimQueuePayloadValue -Payload $p -Name 'type'
    $entity = "$($Entry.entity)"
    $op     = "$($Entry.op)"
    $key    = "$($Entry.key)"

    if ($type -like '*-revoke' -and $type -ne 'session-revoke') {
        $who = Get-PimQueuePayloadValue -Payload $p -Name 'principalName'
        if (-not $who) {
            $pl = Get-PimQueuePayloadValue -Payload $p -Name 'principal'
            if ($pl -and -not (Test-PimQueueLooksLikeId $pl)) { $who = $pl }
            else { $who = Resolve-PimQueueName -Names $Names -Id (Get-PimQueuePayloadValue -Payload $p -Name 'principalId') }
        }
        if (-not $who) { $who = '(unknown principal)' }
        $target = Get-PimQueuePayloadValue -Payload $p -Name 'targetName'
        if (-not $target) {
            switch ($type) {
                'group-assignment-revoke' { $target = Resolve-PimQueueName -Names $Names -Id (Get-PimQueuePayloadValue -Payload $p -Name 'groupId') }
                'entra-role-revoke'       { $target = Resolve-PimQueueName -Names $Names -Id (Get-PimQueuePayloadValue -Payload $p -Name 'roleDefinitionId') }
                'azure-rbac-revoke'       {
                    $ra = Get-PimQueuePayloadValue -Payload $p -Name 'roleAssignmentId'
                    $sc = Get-PimQueuePayloadValue -Payload $p -Name 'scope'
                    $raName = if ($ra) { ($ra -split '/')[-1] } else { '' }
                    $target = if ($raName -and $sc) { "role assignment $raName at $sc (name not found)" } elseif ($raName) { "role assignment $raName (name not found)" } else { '(unknown assignment)' }
                }
            }
        }
        $kind = Get-PimQueuePayloadValue -Payload $p -Name 'targetKind'
        if (-not $kind) { $kind = Get-PimQueueTargetKindLabel -ActionType $type -AccessId (Get-PimQueuePayloadValue -Payload $p -Name 'accessId') }
        $at = Get-PimQueuePayloadValue -Payload $p -Name 'assignmentType'
        $tail = @($kind, $at) | Where-Object { "$_".Trim() }
        return ("Remove {0} from {1}{2}" -f $who, $target, $(if ($tail) { ' (' + ($tail -join ', ') + ')' } else { '' }))
    }
    if ($type -eq 'tap-reset') {
        $u = Get-PimQueuePayloadValue -Payload $p -Name 'userPrincipalName'; if (-not $u) { $u = $key }
        $rcpt = Get-PimQueuePayloadValue -Payload $p -Name 'recipient'
        return ("Re-issue TAP for {0}{1}" -f $u, $(if ($rcpt) { " (mailed to $rcpt)" } else { '' }))
    }
    if ($type -eq 'session-revoke') {
        $u = Get-PimQueuePayloadValue -Payload $p -Name 'userPrincipalName'; if (-not $u) { $u = $key }
        return "Revoke sign-in sessions for $u"
    }
    # 🔴 A KEY THAT IS AN ID SAYS NOTHING (operator, 2026-09-22, on a queue full of
    # "Add PIM-Catalog-ServiceRoles row entra|124577f8-48ed-456a-839f-13b419002e33": *"what is this,
    # it is hard to understand, i need displayname - context, i dont assume it is new entra roles"*).
    # The producer HAD the name all along -- Invoke-PimServiceRoleSweep puts roleName in the payload --
    # and the display threw it away because the fallback assumed every key is a natural key
    # (GroupTag / UserName), which is true of every OTHER producer and false of this one.
    # So: the name leads, the id stays underneath (the GUI renders the raw key in grey), and the
    # sentence says WHAT the row is and what it does NOT do -- cataloguing a role grants nobody
    # anything, which is the reassurance the question was really asking for.
    if ($entity -like 'PIM-Catalog-*') {
        $svc = Get-PimQueuePayloadValue -Payload $p -Name 'service'
        if (-not $svc -and $key -match '^([^|]+)\|') { $svc = $Matches[1] }
        $nm = Get-PimQueueFriendlyName -Payload $p
        if (-not $nm) { $nm = if ($key -match '\|(.+)$') { $Matches[1] } else { $key } }
        $svcLabel = Get-PimQueueServiceLabel -Service $svc
        $verbTxt = switch ($op) { 'Create' { 'Catalogue' } 'Remove' { 'Remove from the catalogue' } default { 'Update in the catalogue' } }
        return ("{0} the {1} role '{2}' -- found in the tenant and not yet in PIM's catalogue (cataloguing it grants nobody access)" -f $verbTxt, $svcLabel, $nm)
    }
    # Desired-state rows and any other action: the entity plus its natural key is usually readable
    # (GroupTag / UserName / ...), so say what happens to which row -- but if the key is an ID and
    # the payload carries a name, LEAD WITH THE NAME. Same defect class as above, one level up.
    $verb = switch ($op) { 'Create' { 'Add' } 'Update' { 'Change' } 'Remove' { 'Remove' } default { $op } }
    $friendly = Get-PimQueueFriendlyName -Payload $p
    $keyIsId = (Test-PimQueueLooksLikeId $key) -or ($key -match '^[^|]+\|[0-9a-fA-F-]{36}$')
    $what = if ($key -and $keyIsId -and $friendly) { "$friendly in $entity" }
            elseif ($key) { "$entity row $key" }
            else { $entity }
    if ($type) { return ("{0}: {1} ({2})" -f $verb, $what, $type) }
    return ("{0} {1}" -f $verb, $what)
}
