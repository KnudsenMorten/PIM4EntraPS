#Requires -Version 5.1
<#
  PIM-AdminExistingAccount.ps1 -- ADMIN-EXISTING-ACCOUNT (owner 2026-11-11, docs/REQUIREMENTS.md).

  An ADMIN TYPE "Existing account (office user)" (AdminType = 'existing-account'): a person who holds low (L4-L5)
  delegations on their normal office account. PIM manages the DELEGATIONS of such an admin (PIM-Assignments-Admins
  memberships: eligible / active, extend, remove) and NEVER the account itself: no create, rename, attribute patch,
  disable, enable, delete, TAP, password, session revoke or AutoDisableDate offboard of the account. An end date removes
  the PIM memberships only. The account is found by its EXACT UPN (one read each), never by a name pattern or a domain
  read (BUG-12).

  PURE, offline, PS 5.1-safe, NO dependencies -- dot-sourced by PIM-Naming.ps1, the engine providers, the queue
  actions, the inactivity sweep, the session-revoke guard, the REST account writer, the hybrid AD planner and the
  Manager, so every lifecycle write path asks the SAME predicate.
#>
Set-StrictMode -Off

function Get-PimExistingAccountAdminTypeKey {
    # The canonical AdminType value of the type (literal; the prefix map does not carry it -- its name is the existing UPN).
    'existing-account'
}

function Get-PimExistingAccountAdminTypeLabel {
    # What the Manager shows for the type.
    param([switch]$Short)
    if ($Short) { return 'Existing account' }
    return 'Existing account (office user)'
}

function ConvertTo-PimExistingAccountTypeKey {
    # PURE. An AdminType value -> 'existing-account' when it names this type (any spelling the wizard / a CSV may use),
    # else ''. Kept here (not only in Resolve-PimAdminTypeKey) so a host without PIM-Naming.ps1 reads it the same way.
    param([AllowNull()][string]$AdminType)
    $t = "$AdminType".Trim().ToLowerInvariant() -replace '[\s_]+', '-'
    $t = $t -replace '[()]', '' -replace '-+', '-'
    if ($t -in @('existing-account', 'existing', 'existingaccount', 'office-user', 'existing-office-user', 'existing-account-office-user')) { return 'existing-account' }
    return ''
}

function Test-PimAdminIsExistingAccount {
    <#
      PURE. Is this Account-Definitions-Admins row of the type "Existing account (office user)"? Reads the row's AdminType
      (hashtable / ordered / PSCustomObject). A row without the column is NOT (every other admin keeps its lifecycle).
    #>
    param([AllowNull()][object]$Row)
    if ($null -eq $Row) { return $false }
    $v = ''
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains('AdminType')) { $v = "$($Row['AdminType'])" } }
    elseif ($Row.PSObject -and $Row.PSObject.Properties['AdminType']) { $v = "$($Row.AdminType)" }
    return ((ConvertTo-PimExistingAccountTypeKey -AdminType $v) -eq 'existing-account')
}

function Get-PimExistingAccountRowUpn {
    # PURE. The exact UPN an existing-account row names (UserPrincipalName, else a UserName that is a UPN). '' when none.
    param([AllowNull()][object]$Row)
    if ($null -eq $Row) { return '' }
    foreach ($n in @('UserPrincipalName', 'userPrincipalName', 'UPN', 'UserName', 'Username')) {
        $v = ''
        if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { $v = "$($Row[$n])" } }
        elseif ($Row.PSObject -and $Row.PSObject.Properties[$n]) { $v = "$($Row.$n)" }
        $v = $v.Trim()
        if ($v -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') { return $v }
    }
    return ''
}

function Get-PimExistingAccountLookupPath {
    <#
      PURE. THE Graph read that finds an existing account: GET /users/<exact UPN> -- one object, by its exact name.
      Never a $filter with startswith / endswith, never a domain or population read (BUG-12).
    #>
    param([Parameter(Mandatory)][string]$Upn, [string]$Select = 'id,userPrincipalName,displayName,accountEnabled')
    return ("/users/{0}?`$select={1}" -f [uri]::EscapeDataString("$Upn".Trim()), $Select)
}

function Find-PimExistingAccount {
    <#
      Look ONE existing account up by its EXACT UPN (Get-PimExistingAccountLookupPath). -Graph is the reader
      (scriptblock param($path) -> object; default Invoke-PimGraph). Returns @{ found; id; upn; displayName; error }.
        found=$true   the directory answered with that account
        found=$false  error '' -> no user with that name in this tenant (404); error set -> it could not be read
      Never creates anything.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Upn, [scriptblock]$Graph, [string]$Select = 'id,userPrincipalName,displayName')
    $o = [ordered]@{ found = $false; id = ''; upn = "$Upn".Trim(); displayName = ''; error = '' }
    if ($o.upn -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { $o.error = "'$($o.upn)' is not a user principal name (name@domain)"; return [pscustomobject]$o }
    $reader = $Graph
    if (-not $reader) {
        if (-not (Get-Command Invoke-PimGraph -ErrorAction SilentlyContinue)) { $o.error = 'no connection to Microsoft Entra ID in this process'; return [pscustomobject]$o }
        $reader = { param($p) Invoke-PimGraph -Path $p }
    }
    $u = $null
    try { $u = & $reader (Get-PimExistingAccountLookupPath -Upn $o.upn -Select $Select) }
    catch {
        $m = "$($_.Exception.Message)"
        if ($m -match '(?i)\b404\b|Request_ResourceNotFound|ResourceNotFound|does not exist|not found') { return [pscustomobject]$o }
        $o.error = "the account could not be read: $m"; return [pscustomobject]$o
    }
    $u = @($u) | Select-Object -First 1
    if ($null -eq $u -or -not "$($u.id)".Trim()) { return [pscustomobject]$o }
    # The answer must BE the account asked for (a UPN is case-insensitive) -- never a near match.
    if ("$($u.userPrincipalName)".Trim() -and "$($u.userPrincipalName)".Trim() -ine $o.upn) { $o.error = "the directory answered with '$($u.userPrincipalName)', not '$($o.upn)'"; return [pscustomobject]$o }
    $o.found = $true; $o.id = "$($u.id)".Trim(); $o.displayName = "$($u.displayName)".Trim()
    return [pscustomobject]$o
}

function Get-PimExistingAccountNotFoundText {
    # The ONE plain line for a refused existing-account row (owner 2026-11-11).
    param([string]$Upn)
    return ("'{0}': no user with that name in this tenant -- an existing account must already exist; PIM never creates it." -f "$Upn".Trim())
}

function Select-PimExistingAccountImportRows {
    <#
      ADMIN-EXISTING-ACCOUNT (a): an IMPORT looks every existing-account admin row up by its EXACT UPN first. A row whose
      account is not there is REFUSED -- that row only; the rest of the import goes on. Other admin types pass untouched.
      -Lookup: scriptblock param($upn) -> Find-PimExistingAccount result. No lookup (no directory in this process) = the
      row is KEPT and said so: the engine still never creates the account (Admins.ApplyCreate refuses this type).
      Returns @{ keep; refused = @( @{ upn; reason } ); notChecked = @(upn) }.
    #>
    param([object[]]$Rows = @(), [scriptblock]$Lookup)
    $keep = New-Object System.Collections.Generic.List[object]
    $refused = New-Object System.Collections.Generic.List[object]
    $notChecked = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        if (-not (Test-PimAdminIsExistingAccount -Row $r)) { [void]$keep.Add($r); continue }
        $upn = Get-PimExistingAccountRowUpn -Row $r
        if (-not $upn) { [void]$refused.Add([pscustomobject]@{ upn = ''; reason = 'an existing account row needs the exact UPN of the account (UserPrincipalName)' }); continue }
        if (-not $Lookup) { [void]$notChecked.Add($upn); [void]$keep.Add($r); continue }
        $f = $null
        try { $f = & $Lookup $upn } catch { $f = [pscustomobject]@{ found = $false; error = "$($_.Exception.Message)" } }
        if ($f -and $f.found) { [void]$keep.Add($r); continue }
        $why = if ($f -and "$($f.error)".Trim()) { "'$upn': the account could not be checked ($($f.error)) -- the row is not imported" } else { Get-PimExistingAccountNotFoundText -Upn $upn }
        [void]$refused.Add([pscustomobject]@{ upn = $upn; reason = $why })
    }
    return [pscustomobject]@{ keep = $keep.ToArray(); refused = $refused.ToArray(); notChecked = $notChecked.ToArray() }
}

# ---------------------------------------------------------------------------------------------------------------------
# LEVEL GUARD = WARN ONLY (owner wizard 2026-11-11). A delegation ABOVE L4-L5 to an existing account is ALLOWED and shown
# as a WARNING (amber, no number, no dot -- the menu rule) on the admin and on Home.
#   "above L4-L5" = a group whose name carries L0-L3, or -- for a group with no L marker -- T0 / T1. L4 / L5 and lower
#   never warn (a group named ...-L4-T1-... is L4: the L marker decides when there is one).
#   A role group (no marker) is judged by the permission groups it is nested into (PIM-Assignments-Groups, source ->
#   target), the most privileged one wins.
# ---------------------------------------------------------------------------------------------------------------------
function Get-PimDelegationTagPrivilege {
    # PURE. @{ level; tier } from a group tag / name's -L<n>- / -T<n>- markers; $null where absent.
    param([AllowNull()][string]$Tag)
    $s = "$Tag"
    $lvl = $null; $tier = $null
    if ($s -match '(?i)(^|[-_.\s])L([0-9])([-_.\s]|$)') { $lvl = [int]$Matches[2] }
    if ($s -match '(?i)(^|[-_.\s])T([0-2])([-_.\s]|$)') { $tier = [int]$Matches[2] }
    return [pscustomobject]@{ level = $lvl; tier = $tier }
}

function Test-PimDelegationAboveExistingAccountLimit {
    # PURE. Is this tag's privilege above L4-L5? (see the block comment above). Returns @{ above; level; tier; why }.
    param([AllowNull()][string]$Tag)
    $p = Get-PimDelegationTagPrivilege -Tag $Tag
    if ($null -ne $p.level) { return [pscustomobject]@{ above = ($p.level -le 3); level = $p.level; tier = $p.tier; why = "L$($p.level)" } }
    if ($null -ne $p.tier)  { return [pscustomobject]@{ above = ($p.tier -le 1); level = $null; tier = $p.tier; why = "T$($p.tier)" } }
    return [pscustomobject]@{ above = $false; level = $null; tier = $null; why = '' }
}

function Get-PimExistingAccountLevelWarnings {
    <#
      PURE. One warning per (existing-account admin, delegation) whose reach is above L4-L5. -AdminRows =
      Account-Definitions-Admins, -AssignmentRows = PIM-Assignments-Admins (Username + GroupTag; Action=Remove skipped),
      -NestingRows = PIM-Assignments-Groups (SourceGroupTag -> TargetGroupTag; Action=Remove skipped).
      Returns @( @{ upn; groupTag; via; privilege; text } ). Never an error and never a block: the delegation stays allowed.
    #>
    param([object[]]$AdminRows = @(), [object[]]$AssignmentRows = @(), [object[]]$NestingRows = @())
    $get = { param($r, [string[]]$names) foreach ($n in $names) { if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { return "$($r[$n])".Trim() } } elseif ($r.PSObject.Properties[$n]) { return "$($r.$n)".Trim() } }; '' }
    $ex = @{}
    foreach ($a in @($AdminRows)) {
        if (-not (Test-PimAdminIsExistingAccount -Row $a)) { continue }
        $upn = Get-PimExistingAccountRowUpn -Row $a
        if (-not $upn) { continue }
        $ex[$upn.ToLowerInvariant()] = $upn
        $un = & $get $a @('UserName')
        if ($un) { $ex[$un.ToLowerInvariant()] = $upn }
    }
    $out = New-Object System.Collections.Generic.List[object]
    if ($ex.Count -eq 0) { return $out.ToArray() }
    $targets = @{}
    foreach ($n in @($NestingRows)) {
        if ($null -eq $n -or (& $get $n @('Action')) -match '(?i)^remove') { continue }
        $s = (& $get $n @('SourceGroupTag')).ToLowerInvariant(); $t = & $get $n @('TargetGroupTag')
        if (-not $s -or -not $t) { continue }
        if (-not $targets.ContainsKey($s)) { $targets[$s] = New-Object System.Collections.Generic.List[string] }
        [void]$targets[$s].Add($t)
    }
    $seenPair = @{}
    foreach ($r in @($AssignmentRows)) {
        if ($null -eq $r -or (& $get $r @('Action')) -match '(?i)^remove') { continue }
        $u = (& $get $r @('Username', 'UserName', 'UserPrincipalName')).ToLowerInvariant()
        if (-not $u -or -not $ex.ContainsKey($u)) { continue }
        $tag = & $get $r @('GroupTag')
        if (-not $tag) { continue }
        # the tag itself, then every group it reaches through nesting (breadth-first, cycle-safe, depth <= 6)
        $best = $null; $via = ''
        $queue = New-Object System.Collections.Generic.Queue[object]; $queue.Enqueue(@($tag, '', 0)); $visited = @{}
        while ($queue.Count) {
            $cur = $queue.Dequeue(); $ct = "$($cur[0])"; $path = "$($cur[1])"; $depth = [int]$cur[2]
            if ($visited.ContainsKey($ct.ToLowerInvariant())) { continue }; $visited[$ct.ToLowerInvariant()] = $true
            $v = Test-PimDelegationAboveExistingAccountLimit -Tag $ct
            if ($v.above) {
                $rank = if ($null -ne $v.level) { $v.level } else { $v.tier }
                $bestRank = if ($null -eq $best) { 99 } elseif ($null -ne $best.level) { $best.level } else { $best.tier }
                if ($rank -lt $bestRank) { $best = $v; $via = $(if ($path) { "$path -> $ct" } else { '' }) }
            }
            if ($depth -lt 6 -and $targets.ContainsKey($ct.ToLowerInvariant())) {
                foreach ($nx in $targets[$ct.ToLowerInvariant()]) { $queue.Enqueue(@($nx, $(if ($path) { "$path -> $ct" } else { $ct }), ($depth + 1))) }
            }
        }
        if ($null -eq $best) { continue }
        $upnOut = $ex[$u]
        $pk = "$($upnOut.ToLowerInvariant())|$($tag.ToLowerInvariant())"
        if ($seenPair.ContainsKey($pk)) { continue }; $seenPair[$pk] = $true
        $through = if ($via) { " (through $via)" } else { '' }
        [void]$out.Add([pscustomobject]@{ upn = $upnOut; groupTag = $tag; via = $via; privilege = $best.why
            text = ("{0} is an existing (office) account with a delegation above L4-L5: {1} reaches {2}{3}. Allowed -- consider a dedicated admin account for this level." -f $upnOut, $tag, $best.why, $through) })
    }
    return $out.ToArray()
}
