# PIM-ManagerAccessIdentity.ps1 -- SEC-90 (PIM REQUIREMENTS, SECAUDIT-1, from SI #995).
#
# A Manager access entry (pim.Settings['ManagerAccess'].managerAccess[]) used to be matched on its NAME only (the UPN /
# preferred_username). A renamed or re-used UPN therefore inherited an old entry's role. From here on an entry may also
# hold the person's Entra OBJECT ID ('objectId'), and when it does, the object id decides:
#   * entry WITH objectId + a request that carries a verified oid -> match on the oid ONLY (a different person who now
#     holds the same UPN gets nothing from it; the same person after a UPN rename keeps the role);
#   * entry WITH objectId + a request with NO oid (the local / break-glass console, an edge that sent no oid claim)
#     -> match on the name, exactly as before (nobody is locked out by this change);
#   * entry WITHOUT objectId -> match on the name, exactly as before. Ids are filled in by the Manager from the directory
#     (Invoke-PimManagerAccessObjectIdBackfill), never typed by a person and never taken from a browser.
# Every function here is PURE (no I/O) so Test-PimManagerAccessObjectId tests them directly.

function Test-PimGuidText {
    [CmdletBinding()] param([string]$Value = '')
    return ("$Value".Trim() -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')
}

function Get-PimAccessEntryField {
    # One field of an entry that may be a PSCustomObject (parsed JSON) or a dictionary (written in this process).
    [CmdletBinding()] param([object]$Entry, [string]$Name)
    if ($null -eq $Entry) { return $null }
    if ($Entry -is [System.Collections.IDictionary]) { if ($Entry.Contains($Name)) { return $Entry[$Name] }; return $null }
    $p = $Entry.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-PimAccessEntryObjectId {
    # The entry's stored object id, lower-case, or '' when it has none (or holds something that is not a GUID).
    [CmdletBinding()] param([object]$Entry)
    $v = "$(Get-PimAccessEntryField -Entry $Entry -Name 'objectId')".Trim()
    if (Test-PimGuidText $v) { return $v.ToLowerInvariant() }
    return ''
}

function Test-PimManagerAccessEntryMatch {
    <#
      PURE. Does this ManagerAccess entry belong to the signed-in caller?
      -Identity = the verified sign-in name (UPN); -ObjectId = the verified oid of THIS request ('' when none).
      Returns @{ match; via ('objectId' | 'identity' | ''); conflict } -- conflict = the NAME matches but the entry is bound
      to a DIFFERENT object id (a re-used UPN): no match, and the caller says so in its log.
    #>
    # -RequireObjectId (FIRST-SUPERADMIN-1 binding): a BOUND entry matches on the oid ONLY -- a request with no verified oid
    # gets nothing from it (no name fallback). The hosted Manager passes it for the installer-seeded first SuperAdmin.
    [CmdletBinding()] param([object]$Entry, [string]$Identity = '', [string]$ObjectId = '', [switch]$RequireObjectId)
    $eid  = "$(Get-PimAccessEntryField -Entry $Entry -Name 'identity')".Trim().ToLowerInvariant()
    $eoid = Get-PimAccessEntryObjectId -Entry $Entry
    $who  = "$Identity".Trim().ToLowerInvariant()
    $oid  = if (Test-PimGuidText $ObjectId) { "$ObjectId".Trim().ToLowerInvariant() } else { '' }
    $nameHit = [bool]($eid -and $who -and $eid -eq $who)
    if ($eoid -and $oid) {
        if ($eoid -eq $oid) { return @{ match = $true; via = 'objectId'; conflict = $false } }
        return @{ match = $false; via = ''; conflict = $nameHit }
    }
    if ($eoid -and $RequireObjectId) { return @{ match = $false; via = ''; conflict = $false; needsObjectId = $nameHit } }
    if ($nameHit) { return @{ match = $true; via = 'identity'; conflict = $false } }
    return @{ match = $false; via = ''; conflict = $false }
}

function Test-PimAccessEntryRequiresObjectId {
    <#
      PURE. FIRST-SUPERADMIN-1 (C): the entry the INSTALLER seeded (seededBy 'first-install', bound to the installing person's
      object id) is matched on the token's oid only -- never on the sign-in name alone.
    #>
    [CmdletBinding()] param([object]$Entry)
    return ([bool](Get-PimAccessEntryObjectId -Entry $Entry) -and "$(Get-PimAccessEntryField -Entry $Entry -Name 'seededBy')".Trim() -ceq 'first-install')
}

function ConvertTo-PimAccessEntryObject {
    # A copy of the entry as an ordered dictionary (every field it had), so a field can be added without touching the input.
    [CmdletBinding()] param([object]$Entry)
    $o = [ordered]@{}
    if ($null -eq $Entry) { return $o }
    if ($Entry -is [System.Collections.IDictionary]) { foreach ($k in @($Entry.Keys)) { $o["$k"] = $Entry[$k] } }
    else { foreach ($p in $Entry.PSObject.Properties) { $o[$p.Name] = $p.Value } }
    return $o
}

function Copy-PimManagerAccessObjectIds {
    <#
      PURE. A writer that rebuilds the map from { identity, role } (the Settings page, Set-PimManagerAccess.ps1, the deploy's
      dbinit step) must not DROP the object ids the Manager already bound. For every -After entry with no objectId, the
      objectId of the -Before entry with the SAME identity (case-insensitive) is carried over. A client-supplied objectId on
      an -After entry is never trusted: it is replaced by the stored one, or removed when there is none (-DropUnknown).
      Returns the -After entries (ordered dictionaries), same order.
    #>
    [CmdletBinding()] param([object[]]$Before = @(), [object[]]$After = @(), [switch]$DropUnknown)
    $byId = @{}; $seedOf = @{}
    foreach ($b in @($Before)) {
        $k = "$(Get-PimAccessEntryField -Entry $b -Name 'identity')".Trim().ToLowerInvariant()
        $o = Get-PimAccessEntryObjectId -Entry $b
        if ($k -and $o -and -not $byId.ContainsKey($k)) {
            $byId[$k] = $o
            # FIRST-SUPERADMIN-1: the installer-seeded marker travels with the bound id (the oid-only match stays)
            if (Test-PimAccessEntryRequiresObjectId -Entry $b) { $seedOf[$k] = @{ seededBy = 'first-install'; seededUtc = "$(Get-PimAccessEntryField -Entry $b -Name 'seededUtc')" } }
        }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($a in @($After)) {
        if ($null -eq $a) { continue }
        $e = ConvertTo-PimAccessEntryObject -Entry $a
        $k = "$($e['identity'])".Trim().ToLowerInvariant()
        if ($e.Contains('seededBy')) { $e.Remove('seededBy') }; if ($e.Contains('seededUtc')) { $e.Remove('seededUtc') }   # never from outside
        if ($k -and $byId.ContainsKey($k)) {
            $e['objectId'] = $byId[$k]
            if ($seedOf.ContainsKey($k)) { $e['seededBy'] = $seedOf[$k].seededBy; if ("$($seedOf[$k].seededUtc)".Trim()) { $e['seededUtc'] = $seedOf[$k].seededUtc } }
        }
        elseif ($DropUnknown -and $e.Contains('objectId')) { $e.Remove('objectId') }
        $out.Add($e)
    }
    return @($out.ToArray())
}

function Get-PimManagerAccessBackfillTargets {
    <#
      PURE. The identities whose entry has no object id yet and that look like a sign-in name (name@domain) -- the only
      ones the directory can resolve to one user. Distinct, lower-case.
    #>
    [CmdletBinding()] param([object[]]$Entries = @())
    $seen = @{}
    foreach ($e in @($Entries)) {
        $id = "$(Get-PimAccessEntryField -Entry $e -Name 'identity')".Trim()
        if (-not $id -or (Get-PimAccessEntryObjectId -Entry $e)) { continue }
        if ($id -notmatch '^[^@\s;,'']+@[^@\s;,'']+\.[^@\s;,'']+$') { continue }
        $seen[$id.ToLowerInvariant()] = $true
    }
    return @($seen.Keys | Sort-Object)
}

function Set-PimManagerAccessObjectIds {
    <#
      PURE. Write the directory's answers into the entries. -Found: identity (lower-case) -> @{ id; upn }. An id is bound
      ONLY when the directory's userPrincipalName is the entry's identity (case-insensitive) and the id is a GUID -- the
      Manager signs people in by UPN, so anything else is a different person or a mail alias. Entries that already hold an
      object id are never changed. Returns @{ entries (ordered dictionaries); bound = @(identities) }.
    #>
    [CmdletBinding()] param([object[]]$Entries = @(), [hashtable]$Found = @{})
    $out = New-Object System.Collections.Generic.List[object]
    $bound = New-Object System.Collections.Generic.List[string]
    foreach ($en in @($Entries)) {
        if ($null -eq $en) { continue }
        $e = ConvertTo-PimAccessEntryObject -Entry $en
        $id = "$($e['identity'])".Trim(); $k = $id.ToLowerInvariant()
        if ($k -and -not (Get-PimAccessEntryObjectId -Entry $e) -and $Found -and $Found.ContainsKey($k)) {
            $f = $Found[$k]
            $fid = "$(Get-PimAccessEntryField -Entry $f -Name 'id')".Trim()
            $fupn = "$(Get-PimAccessEntryField -Entry $f -Name 'upn')".Trim().ToLowerInvariant()
            if ((Test-PimGuidText $fid) -and $fupn -eq $k) { $e['objectId'] = $fid.ToLowerInvariant(); $bound.Add($id) }
        }
        $out.Add($e)
    }
    return @{ entries = @($out.ToArray()); bound = @($bound.ToArray()) }
}
