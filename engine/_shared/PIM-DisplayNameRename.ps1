#Requires -Version 5.1
<#
  PIM-DisplayNameRename.ps1 -- framework DOCS/REQUIREMENTS.md §12.11c NAMING (CR5) item 5, PIM REQUIREMENTS 100.149:
  "Short code in Azure, full name where people read" -- at EXISTING installs too, by the update. The product is
  "PIM Manager", never "PIM4EntraPS", in every display name a person reads.

  🔒 OFF BY DEFAULT (PIM_Update_RenameDisplayNames, Test-PimRenameDisplayNamesSwitch in PIM-InstallNames.ps1) until the
  owner switches it on. With it off nothing is read and nothing is written.

  What is renamed (only an object whose display name is EXACTLY the name PIM gave it in an earlier release -- a name a
  customer chose is never touched; KEPT: the mailbox ADDRESS, mailNickname, the Exchange scope name, identifier uris):
    managerApp     application  'PIM4EntraPS Manager'                              -> 'PIM Manager'
    engineApp      application  'PIM4EntraPS Engine'                               -> 'PIM Manager Engine'
    deployApp      application  'PIM4EntraPS Deploy'                               -> 'PIM Manager Deploy'
    membersGroup   group        'PIM4EntraPS Manager users (members, no guests)'   -> 'PIM Manager users (members, no guests)'
    senderMailbox  user         'PIM4EntraPS Engine (notifications)'               -> 'PIM Manager (notifications)'
  Every finder in setup looks for both forms (Get-PimDisplayNameForms), and no setup script renames one back
  (Test-PimDisplayNameIsNewerForm), so a renamed object is never forked into a second one.

  WHO CAN DO IT: the update runs as the updater's own identity (Contributor on its resource group + its database user).
  It holds NO Microsoft Graph application permission, so today every rename here is reported as "cannot" with the
  permission it would need (Get-PimDisplayNameRenameTargets .permission) -- read, never guessed: a refused read or write
  is classified, never thrown. Idempotent (an object already on its new name is 'current'), read back after each write,
  audited (install.displayname.rename, before/after), and it NEVER fails an update.
  Seams: -Graph { param($Method, $Path, $Body) }, -Audit { param($Target, $Before, $After) }. PS 5.1-safe; no modules.
#>
Set-StrictMode -Off

function Get-PimDisplayNameRenameTargets {
    <#
      PURE. The display names the update may rename. -SenderMailbox: the sender's address (pim.Settings MailSender) -- the
      mailbox is found by it (never by name); without one the mailbox target is left out.
    #>
    param([AllowEmptyString()][string]$SenderMailbox = '')
    $appPerm = 'Microsoft Graph Application.ReadWrite.OwnedBy with the updater identity added as an OWNER of the app registration (or Application.ReadWrite.All, tenant-wide -- not recommended)'
    $t = New-Object System.Collections.Generic.List[object]
    foreach ($a in @(@{ id = 'managerApp'; what = 'the Manager''s sign-in app registration'; old = 'PIM4EntraPS Manager' },
                     @{ id = 'engineApp';  what = 'the engine app registration (installs with an engine app)'; old = 'PIM4EntraPS Engine' },
                     @{ id = 'deployApp';  what = 'the deploy app registration (installs deployed by an application)'; old = 'PIM4EntraPS Deploy' })) {
        [void]$t.Add([pscustomobject]@{ id = $a.id; kind = 'application'; what = $a.what; oldName = $a.old; newName = (ConvertTo-PimNewDisplayName $a.old)
                                        permission = $appPerm; readPermission = 'Microsoft Graph Application.Read.All' })
    }
    $g = 'PIM4EntraPS Manager users (members, no guests)'
    [void]$t.Add([pscustomobject]@{ id = 'membersGroup'; kind = 'group'; what = 'the Manager''s sign-in group (every member, no guests)'; oldName = $g; newName = (ConvertTo-PimNewDisplayName $g)
                                    permission = 'Microsoft Graph Group.ReadWrite.All (mailNickname is kept)'; readPermission = 'Microsoft Graph Group.Read.All' })
    $s = "$SenderMailbox".Trim()
    if ($s -match '^[^@\s]+@[^@\s]+$') {
        $m = 'PIM4EntraPS Engine (notifications)'
        [void]$t.Add([pscustomobject]@{ id = 'senderMailbox'; kind = 'user'; what = "the sender mailbox's display name ($s; the ADDRESS is kept)"; oldName = $m; newName = (ConvertTo-PimNewDisplayName $m)
                                        address = $s; permission = 'Microsoft Graph User.ReadWrite.All (the display name only; the address, alias and the Exchange scope stay)'
                                        readPermission = 'Microsoft Graph User.Read.All' })
    }
    return @($t.ToArray())
}

function Get-PimDisplayNameRenameDecision {
    <#
      PURE. What to do for ONE target, from what the lookups found:
        -OldHits (objects whose display name is the old one) / -NewHits (the new one) / -Mailbox (the sender's user object)
        rename     exactly one object carries the old name (the mailbox: its display name is the old one)
        current    nothing carries the old name and the new one is there -- done before (idempotent)
        ambiguous  more than one object carries the old name -- never guessed
        absent     neither name is there (or the mailbox carries a name the customer chose -- kept)
      Returns @{ action; objectId; before }.
    #>
    param([Parameter(Mandatory)][object]$Target, [object[]]$OldHits = @(), [object[]]$NewHits = @(), [AllowNull()][object]$Mailbox = $null)
    if ("$($Target.kind)" -eq 'user') {
        if (-not $Mailbox -or -not "$($Mailbox.id)".Trim()) { return @{ action = 'absent'; objectId = ''; before = '' } }
        $dn = "$($Mailbox.displayName)".Trim()
        if ($dn -ieq "$($Target.newName)") { return @{ action = 'current'; objectId = "$($Mailbox.id)"; before = $dn } }
        if ($dn -ieq "$($Target.oldName)") { return @{ action = 'rename'; objectId = "$($Mailbox.id)"; before = $dn } }
        return @{ action = 'absent'; objectId = "$($Mailbox.id)"; before = $dn }
    }
    $old = @(@($OldHits) | Where-Object { $_ -and "$($_.id)".Trim() -and "$($_.displayName)".Trim() -ieq "$($Target.oldName)" })
    $new = @(@($NewHits) | Where-Object { $_ -and "$($_.id)".Trim() -and "$($_.displayName)".Trim() -ieq "$($Target.newName)" })
    if ($old.Count -gt 1) { return @{ action = 'ambiguous'; objectId = ''; before = "$($Target.oldName)" } }
    if ($old.Count -eq 1) { return @{ action = 'rename'; objectId = "$($old[0].id)"; before = "$($old[0].displayName)" } }
    if ($new.Count) { return @{ action = 'current'; objectId = "$($new[0].id)"; before = "$($new[0].displayName)" } }
    return @{ action = 'absent'; objectId = ''; before = '' }
}

function Test-PimDisplayNameRefusal {
    # PURE. Is this error a refusal for want of a permission (HTTP 401 / 403, Authorization_RequestDenied, ...)?
    param([AllowEmptyString()][string]$Message)
    return [bool]("$Message" -match '(?i)\b40[13]\b|Forbidden|Unauthorized|Authorization_RequestDenied|Insufficient privileges|AccessDenied')
}

function Invoke-PimDisplayNameRenames {
    <#
      CR5 item 5 -- run by the updater. -Enabled = Test-PimRenameDisplayNamesSwitch (the caller reads the switch: the store
      setting first, then the job's variable). Off -> nothing is read, nothing is written. Never throws.
      Returns @{ ran; renamed; current; cannot[] (@{ id; what; permission }); lines[] (@{ level; text }); results[] }.
    #>
    param([bool]$Enabled = $false, [AllowEmptyString()][string]$SenderMailbox = '', [scriptblock]$Graph, [scriptblock]$Audit)
    $out = @{ ran = $false; renamed = 0; current = 0; cannot = @(); lines = @(); results = @() }
    $lines = New-Object System.Collections.Generic.List[object]
    $cannot = New-Object System.Collections.Generic.List[object]
    $results = New-Object System.Collections.Generic.List[object]
    $say = { param($lvl, $txt) [void]$lines.Add(@{ level = $lvl; text = $txt }) }
    if (-not $Enabled) {
        & $say 'info' 'display names: not renamed -- PIM_Update_RenameDisplayNames is off (the owner switches it on)'
        $out.lines = @($lines.ToArray()); return $out
    }
    if (-not $Graph) { $Graph = { param($m, $p, $b) if ($null -ne $b) { Invoke-PimGraph -Method $m -Path $p -Body $b } else { Invoke-PimGraph -Method $m -Path $p } } }
    $out.ran = $true
    try {
        foreach ($t in @(Get-PimDisplayNameRenameTargets -SenderMailbox $SenderMailbox)) {
            $r = [ordered]@{ id = $t.id; what = $t.what; from = $t.oldName; to = $t.newName; action = ''; detail = '' }
            try {
                $mailbox = $null; $oldHits = @(); $newHits = @()
                if ("$($t.kind)" -eq 'user') {
                    $mailbox = & $Graph 'GET' "/users/$([uri]::EscapeDataString("$($t.address)"))?`$select=id,displayName" $null
                } else {
                    $col = if ("$($t.kind)" -eq 'application') { 'applications' } else { 'groups' }
                    foreach ($pair in @(@('old', $t.oldName), @('new', $t.newName))) {
                        $f = [uri]::EscapeDataString("displayName eq '$("$($pair[1])".Replace("'", "''"))'")
                        $hits = @(@((& $Graph 'GET' "/$col`?`$select=id,displayName&`$filter=$f" $null).value) | Where-Object { $_ })
                        if ($pair[0] -eq 'old') { $oldHits = $hits } else { $newHits = $hits }
                    }
                }
            } catch {
                $m = "$($_.Exception.Message)"
                $r.action = $(if (Test-PimDisplayNameRefusal $m) { 'cannot' } else { 'failed' })
                $r.detail = $(if ($r.action -eq 'cannot') { "could not be READ by the updater's identity -- it needs $($t.readPermission) to look, and $($t.permission) to rename" } else { "lookup failed: $(($m -split "`n")[0])" })
                if ($r.action -eq 'cannot') { [void]$cannot.Add(@{ id = $t.id; what = $t.what; permission = $t.permission }) }
                [void]$results.Add([pscustomobject]$r); & $say 'warn' "display name: $($t.what) -- $($r.detail)"; continue
            }
            $d = Get-PimDisplayNameRenameDecision -Target $t -OldHits $oldHits -NewHits $newHits -Mailbox $mailbox
            $r.action = $d.action
            switch ($d.action) {
                'current'   { $out.current++; $r.detail = "already '$($t.newName)'"; & $say 'info' "display name: $($t.what) -- already '$($t.newName)'" }
                'absent'    { $r.detail = $(if ("$($d.before)") { "carries '$($d.before)' (not a name PIM gave it) -- kept" } else { 'not in this tenant' }); & $say 'info' "display name: $($t.what) -- $($r.detail)" }
                'ambiguous' { $r.detail = "more than one object is named '$($t.oldName)' -- none renamed (never guessed)"; & $say 'warn' "display name: $($t.what) -- $($r.detail)" }
                'rename' {
                    $path = $(switch ("$($t.kind)") { 'application' { "/applications/$($d.objectId)" } 'group' { "/groups/$($d.objectId)" } default { "/users/$($d.objectId)" } })
                    try {
                        [void](& $Graph 'PATCH' $path @{ displayName = "$($t.newName)" })
                        $back = "$((& $Graph 'GET' "$path`?`$select=id,displayName" $null).displayName)".Trim()
                        if ($back -ieq "$($t.newName)") {
                            $out.renamed++; $r.detail = "renamed '$($d.before)' -> '$back' (read back)"
                            & $say 'changed' "display name: $($t.what) -- $($r.detail)"
                            if ($Audit) { try { [void](& $Audit "$($t.id)" @{ displayName = "$($d.before)" } @{ displayName = $back }) } catch { & $say 'warn' "display name: $($t.what) -- renamed, but the audit record could not be written: $(("$($_.Exception.Message)" -split "`n")[0])" } }
                        } else {
                            $r.action = 'failed'; $r.detail = "the write was accepted but reads back '$back', not '$($t.newName)'"
                            & $say 'warn' "display name: $($t.what) -- $($r.detail)"
                        }
                    } catch {
                        $m = "$($_.Exception.Message)"
                        if (Test-PimDisplayNameRefusal $m) {
                            $r.action = 'cannot'; $r.detail = "the updater's identity may not rename it -- it needs $($t.permission)"
                            [void]$cannot.Add(@{ id = $t.id; what = $t.what; permission = $t.permission })
                        } else { $r.action = 'failed'; $r.detail = "rename failed: $(($m -split "`n")[0])" }
                        & $say 'warn' "display name: $($t.what) -- $($r.detail)"
                    }
                }
            }
            [void]$results.Add([pscustomobject]$r)
        }
    } catch { & $say 'warn' "display names: not checked -- $(("$($_.Exception.Message)" -split "`n")[0])" }
    $out.cannot = @($cannot.ToArray()); $out.lines = @($lines.ToArray()); $out.results = @($results.ToArray())
    return $out
}
