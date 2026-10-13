<#
  PIM-AdminDeletePins.ps1 -- CODE REVIEW 1 FIXES 2026-10-13 (lane review1), owner decisions (51) and (54):
  "Yes, once and pinned" -- an admin account delete acts ONCE on the exact account (object id) the operator chose, in
  THIS tenant, and then the row is closed.

  THE PIN. Every account delete PIM Manager may carry out is a record in pim.Settings 'AdminDeletePins' of THIS tenant:
    { pins: [ { id; key (the account-name part, lower); upn; objectId (lower, '' = pinned on first sight, central only);
                source = 'local' | 'central'; status; requestId; requestedBy; approvedBy; approvedUtc; doneUtc; note } ] }
  status:  approved  -> the engine may delete the account whose object id IS objectId, once
           claimed   -> the engine started the delete (written BEFORE the DELETE call); never acted on again
           deleted   -> TOMBSTONE: deleted (or found gone); never acted on again, whatever account carries the name later
           failed    -> the DELETE call failed; the next run may try again (same object id only)
  A row marked AccountStatus = Deleted WITHOUT an approved pin (every row an older version marked) is NOT deleted: the
  engine reports that an operator must confirm the delete again.
  local   = the Manager wrote it (Delete account / a commit that passed the delete rule) with the live object id it read.
  central = a managed tenant wrote it from the managing tenant's SIGNED 'delete-account' intent, approved there by a
            SuperAdmin (PIM-DownlinkIntents.ps1). objectId is '' until the engine first sees the account; the engine then
            pins THIS tenant's own object id and deletes that account only.
  The pins are never copied by a backup, an environment import or a settings copy (the three exclusion lists name
  'AdminDeletePins'): another environment's decision to delete is not this one's.
  Store access: -ConnectionString (the downlink, which writes a managed tenant's store) or the guard store
  (Get-PimGuardStoreText / Set-PimGuardStoreText, PIM-GuardRelease.ps1; $global:PIM_GuardReleaseStore is the test seam).
  Reads that fail return $null (the caller refuses: never "no pin" on a read that failed). ASCII only; PS 5.1 + 7.
#>
Set-StrictMode -Off

function Get-PimAdminDeletePinSettingName { 'AdminDeletePins' }

function ConvertTo-PimAdminDeletePinKey {
    # PURE. The account-name part of a UPN / user name, lower-case (the Admins scope's own key).
    param([AllowNull()][string]$Name)
    $s = "$Name".Trim(); $i = $s.IndexOf('@'); if ($i -ge 0) { $s = $s.Substring(0, $i) }
    return $s.ToLowerInvariant()
}

function Get-PimAdminDeletePinKeyOfRow {
    # PURE. The pin key of an admin row: the account-name part of its UserPrincipalName, else its UserName.
    param([AllowNull()][object]$Row)
    if ($null -eq $Row) { return '' }
    $v = { param($n) if ($Row -is [System.Collections.IDictionary]) { "$($Row[$n])" } elseif ($Row.PSObject.Properties[$n]) { "$($Row.PSObject.Properties[$n].Value)" } else { '' } }
    $u = (& $v 'UserPrincipalName').Trim(); if (-not $u) { $u = (& $v 'userPrincipalName').Trim() }
    if (-not $u) { $u = (& $v 'UserName').Trim() }
    return (ConvertTo-PimAdminDeletePinKey -Name $u)
}

function Get-PimAdminDeletePinText {
    # The stored JSON text, or $null when nothing is stored. THROWS when the store cannot be read.
    param([string]$ConnectionString = '')
    $n = Get-PimAdminDeletePinSettingName
    if ("$ConnectionString".Trim() -and -not ($global:PIM_GuardReleaseStore -is [hashtable])) {
        if (-not (Get-Command Get-PimSqlSettingRaw -ErrorAction SilentlyContinue)) { throw 'the settings reader is not loaded' }
        $t = Get-PimSqlSettingRaw -ConnectionString $ConnectionString -Name $n
        if ($null -eq $t -or "$t".Trim() -eq '') { return $null }
        return "$t"
    }
    if (-not (Get-Command Get-PimGuardStoreText -ErrorAction SilentlyContinue)) { throw 'the settings store library (PIM-GuardRelease.ps1) is not loaded' }
    return (Get-PimGuardStoreText -Name $n)
}

function Set-PimAdminDeletePinText {
    # Compare-and-set write. Returns 1 written / 0 lost (the caller reads again). THROWS when there is no store.
    param([Parameter(Mandatory)][string]$Json, [AllowNull()][string]$Expected, [string]$ConnectionString = '')
    $n = Get-PimAdminDeletePinSettingName
    if ("$ConnectionString".Trim() -and -not ($global:PIM_GuardReleaseStore -is [hashtable])) {
        if (-not (Get-Command Set-PimSqlSettingIfUnchanged -ErrorAction SilentlyContinue)) { throw 'the settings writer is not loaded' }
        return [int](Set-PimSqlSettingIfUnchanged -ConnectionString $ConnectionString -Name $n -NewValueJson $Json -ExpectedValueJson $Expected)
    }
    if (-not (Get-Command Set-PimGuardStoreText -ErrorAction SilentlyContinue)) { throw 'the settings store library (PIM-GuardRelease.ps1) is not loaded' }
    return [int](Set-PimGuardStoreText -Name $n -Json $Json -Expected $Expected -Cas)
}

function ConvertFrom-PimAdminDeletePinText {
    # PURE. JSON text -> the pin array. Text that is not readable THROWS (never "no pins" on a broken record).
    param([AllowNull()][string]$Text)
    if ($null -eq $Text -or "$Text".Trim() -eq '') { return @() }
    $o = $Text | ConvertFrom-Json
    if ($null -eq $o -or -not $o.PSObject.Properties['pins']) { throw "the stored '$(Get-PimAdminDeletePinSettingName)' record has no pins list" }
    return @(@($o.pins) | Where-Object { $null -ne $_ })
}

function Get-PimAdminDeletePins {
    # Every pin, or $null when the store could not be read (the caller then deletes NOTHING).
    param([string]$ConnectionString = '')
    try { return ,@(ConvertFrom-PimAdminDeletePinText -Text (Get-PimAdminDeletePinText -ConnectionString $ConnectionString)) }
    catch { Write-Warning "[admin-delete] the delete pins could not be read ($($_.Exception.Message)) -- no account is deleted on a read that failed"; return $null }
}

function Find-PimAdminDeletePin {
    # PURE. The LATEST pin for an account name (by approvedUtc, then position), or $null. -Source narrows to local / central.
    param([AllowNull()][object[]]$Pins = @(), [Parameter(Mandatory)][string]$Key, [string]$Source = '')
    $k = ConvertTo-PimAdminDeletePinKey -Name $Key
    $hit = $null
    foreach ($p in @($Pins)) {
        if ($null -eq $p -or "$($p.key)".Trim().ToLowerInvariant() -ne $k) { continue }
        if ($Source -and "$($p.source)" -ine $Source) { continue }
        $hit = $p   # stored in time order: the last one is the latest
    }
    return $hit
}

function New-PimAdminDeletePin {
    # PURE. One pin record (status approved). '' objectId only for a central pin (pinned on first sight by the engine).
    param([Parameter(Mandatory)][string]$Key, [string]$Upn = '', [string]$ObjectId = '', [ValidateSet('local', 'central')][string]$Source = 'local',
          [string]$RequestId = '', [string]$RequestedBy = '', [string]$ApprovedBy = '', [string]$Note = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $oid = "$ObjectId".Trim().ToLowerInvariant()
    if ($Source -eq 'local' -and $oid -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { throw "a local delete pin needs the account's object id (got '$ObjectId') -- nothing was pinned" }
    if ($oid -and $oid -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { throw "'$ObjectId' is not an object id -- nothing was pinned" }
    if (-not "$ApprovedBy".Trim()) { throw 'a delete pin needs the person who approved it -- nothing was pinned' }
    return [pscustomobject][ordered]@{
        id = [guid]::NewGuid().ToString('N'); key = (ConvertTo-PimAdminDeletePinKey -Name $Key); upn = "$Upn".Trim(); objectId = $oid
        source = $Source; status = 'approved'; requestId = "$RequestId"; requestedBy = "$RequestedBy"; approvedBy = "$ApprovedBy".Trim()
        approvedUtc = $NowUtc.ToUniversalTime().ToString('o'); doneUtc = ''; note = "$Note"
    }
}

function Update-PimAdminDeletePins {
    # Read -> change -> compare-and-set write, three tries. -Change { param($pins) -> new pins array }. Returns the new
    # pins, or THROWS (nothing written) when the store cannot be read or keeps changing.
    param([Parameter(Mandatory)][scriptblock]$Change, [string]$ConnectionString = '')
    for ($try = 0; $try -lt 3; $try++) {
        $text = Get-PimAdminDeletePinText -ConnectionString $ConnectionString
        $pins = @(ConvertFrom-PimAdminDeletePinText -Text $text)
        $new = @(& $Change $pins)
        $json = ConvertTo-Json -InputObject ([ordered]@{ pins = @($new | Select-Object -Last 2000) }) -Depth 6 -Compress
        if ([int](Set-PimAdminDeletePinText -Json $json -Expected $text -ConnectionString $ConnectionString) -eq 1) { return ,@($new) }
    }
    throw 'the delete pins kept changing while they were written -- nothing was written'
}

function Add-PimAdminDeletePin {
    # Store one new pin (THROWS on failure: the caller then requests / deletes nothing). A newer pin for the same account
    # replaces an older APPROVED one (never a claimed / deleted one: those stay as the record).
    # The SAME decision (same requestId) is never pinned twice: once it acted (tombstone) it can never pin a later account.
    param([Parameter(Mandatory)][object]$Pin, [string]$ConnectionString = '')
    $rid = "$($Pin.requestId)".Trim()
    [void](Update-PimAdminDeletePins -ConnectionString $ConnectionString -Change {
        param($pins)
        if ($rid -and @($pins | Where-Object { "$($_.requestId)".Trim() -ieq $rid -and "$($_.key)" -eq "$($Pin.key)" }).Count) { return @($pins) }
        @(@($pins | Where-Object { -not ("$($_.key)" -eq "$($Pin.key)" -and "$($_.source)" -eq "$($Pin.source)" -and "$($_.status)" -in @('approved', 'failed')) }) + @($Pin))
    }.GetNewClosure())
    return $Pin
}

function Set-PimAdminDeletePinState {
    # Move ONE pin (by id) to -Status, with -ObjectId (a central pin pinned on first sight) and a note. THROWS on failure.
    param([Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][ValidateSet('claimed', 'deleted', 'failed', 'approved')][string]$Status,
          [string]$ObjectId = '', [string]$Note = '', [string]$ConnectionString = '', [datetime]$NowUtc = [datetime]::UtcNow)
    $stamp = $NowUtc.ToUniversalTime().ToString('o')
    [void](Update-PimAdminDeletePins -ConnectionString $ConnectionString -Change {
        param($pins)
        foreach ($p in @($pins)) {
            if ("$($p.id)" -ne $Id) { $p; continue }
            $c = [ordered]@{}; foreach ($pp in $p.PSObject.Properties) { $c[$pp.Name] = $pp.Value }
            $c['status'] = $Status
            if ("$ObjectId".Trim()) { $c['objectId'] = "$ObjectId".Trim().ToLowerInvariant() }
            if ($Status -in @('deleted', 'claimed', 'failed')) { $c['doneUtc'] = $stamp }
            if ("$Note".Trim()) { $c['note'] = "$Note" }
            [pscustomobject]$c
        }
    }.GetNewClosure())
}

function Get-PimAdminDeletePinDecision {
    <#
      PURE. May the engine delete THIS live account (-LiveObjectId) for the account name -Key now?
        -Pins   every pin ($null = the pins could not be read: refused)
        -Source 'local' | 'central' -- a central row is deleted only on a central pin, a local row only on a local pin
      Returns @{ act; code; reason; pin; pinObjectId } -- pinObjectId is what to pin for a central pin seen the first time.
      Codes: pins-unreadable | no-pin | tombstoned | claimed | other-object | no-object | ok
    #>
    param([AllowNull()][object[]]$Pins, [Parameter(Mandatory)][string]$Key, [AllowNull()][string]$LiveObjectId, [ValidateSet('local', 'central')][string]$Source = 'local')
    $o = [ordered]@{ act = $false; code = ''; reason = ''; pin = $null; pinObjectId = '' }
    if ($null -eq $Pins) { $o.code = 'pins-unreadable'; $o.reason = 'the delete pins could not be read -- nothing is deleted on a read that failed'; return [pscustomobject]$o }
    $live = "$LiveObjectId".Trim().ToLowerInvariant()
    $p = Find-PimAdminDeletePin -Pins $Pins -Key $Key -Source $Source
    $o.pin = $p
    if ($null -eq $p) {
        $o.code = 'no-pin'
        $o.reason = $(if ($Source -eq 'central') { "the central row says Deleted, but no SuperAdmin approval of the managing tenant (a signed 'delete-account' decision) reached this tenant -- the account is DISABLED, never deleted" }
                      else { "marked Deleted, but no operator pinned the account to delete (marked by an older version, or not through Delete account) -- NOT deleted: an operator must confirm the delete again (Delete account)" })
        return [pscustomobject]$o
    }
    $st = "$($p.status)".Trim().ToLowerInvariant()
    if ($st -eq 'deleted') { $o.code = 'tombstoned'; $o.reason = ("the delete was done once ({0}, object id {1}) -- the row is closed and acts on no account again (this account: object id {2})" -f "$($p.doneUtc)", "$($p.objectId)", $(if ($live) { $live } else { 'none' })); return [pscustomobject]$o }
    if ($st -eq 'claimed') { $o.code = 'claimed'; $o.reason = ("a delete of object id {0} was started ({1}) and never confirmed -- nothing more is done; an operator confirms the delete again" -f "$($p.objectId)", "$($p.doneUtc)"); return [pscustomobject]$o }
    if ($st -notin @('approved', 'failed')) { $o.code = 'no-pin'; $o.reason = "the delete pin is in state '$st' -- NOT deleted"; return [pscustomobject]$o }
    if (-not $live) { $o.code = 'no-object'; $o.reason = 'the account was not found'; return [pscustomobject]$o }
    $want = "$($p.objectId)".Trim().ToLowerInvariant()
    if (-not $want) {
        if ($Source -ne 'central') { $o.code = 'no-pin'; $o.reason = 'the delete pin carries no object id -- NOT deleted'; return [pscustomobject]$o }
        $o.act = $true; $o.code = 'ok'; $o.pinObjectId = $live; $o.reason = "the managing tenant's SuperAdmin approved this delete; this tenant's account (object id $live) is pinned now"
        return [pscustomobject]$o
    }
    if ($want -ne $live) { $o.code = 'other-object'; $o.reason = "the account now carrying this name has object id $live, not the pinned $want -- NOT deleted (a restored or a new account is never deleted by an old decision)"; return [pscustomobject]$o }
    $o.act = $true; $o.code = 'ok'; $o.reason = "pinned delete of object id $want"
    return [pscustomobject]$o
}
