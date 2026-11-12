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

function Get-PimExistingAccountSourceText {
    <#
      PURE. EXISTING-ACCOUNT-NO-HYBRID (owner 2026-11-12: "they can live both in AD and cloud" / "synced to cloud if AD
      based"). Where the account lives, in plain words: 'synced from AD' (onPremisesSyncEnabled = true), 'cloud' (false or
      not set on a readable answer), 'not known' (-Readable $false: the sync flag could not be read). Either way PIM reaches
      it through its Entra object only and the hybrid worker never touches it.
    #>
    param([AllowNull()][object]$OnPremisesSyncEnabled, [bool]$Readable = $true)
    if (-not $Readable) { return 'not known' }
    if ("$OnPremisesSyncEnabled".Trim() -ieq 'True') { return 'synced from AD' }
    return 'cloud'
}

function Get-PimExistingAccountHybridNote {
    # The ONE plain line a hybrid AD job writes for an existing account it leaves alone (owner 2026-11-12).
    param([string]$Upn)
    return ("existing account {0}: not supported by the hybrid worker -- nothing done in AD" -f "$Upn".Trim())
}

function Get-PimExistingAccountHybridKeys {
    <#
      PURE. EXISTING-ACCOUNT-NO-HYBRID (a): every name the hybrid AD jobs could know an existing account by -> its UPN.
      Keys (lower-case): the exact UPN, its local part (an office user's sAMAccountName / mailNickname is normally that), the
      row's UserName and SamAccountName / MailNickname when present (and their local parts). Every existing-account row
      counts, whatever its TargetPlatform or Action: PIM never does anything in AD for such an account.
    #>
    param([object[]]$AdminRows = @())
    $map = @{}
    $get = { param($r, $n) if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { return "$($r[$n])".Trim() } } elseif ($r.PSObject.Properties[$n]) { return "$($r.$n)".Trim() }; '' }
    foreach ($r in @($AdminRows)) {
        if ($null -eq $r -or -not (Test-PimAdminIsExistingAccount -Row $r)) { continue }
        $upn = Get-PimExistingAccountRowUpn -Row $r
        $names = @($upn) + @(foreach ($n in @('UserName', 'Username', 'SamAccountName', 'sAMAccountName', 'MailNickname', 'mailNickname')) { & $get $r $n })
        if (-not $upn) { $upn = @($names | Where-Object { $_ })[0] }
        if (-not $upn) { continue }
        foreach ($n in $names) {
            $v = "$n".Trim().ToLowerInvariant()
            if (-not $v) { continue }
            $map[$v] = $upn
            $at = $v.IndexOf('@'); if ($at -gt 0) { $map[$v.Substring(0, $at)] = $upn }
        }
    }
    return $map
}

# ---------------------------------------------------------------------------------------------------------------------
# EXISTING-ACCOUNT-NO-HYBRID + NO-OVERWRITE (b) (owner 2026-11-12: "we must not impact overwrite existing"). A NORMAL admin
# row (any type but existing-account) whose UPN already names an account PIM did not create must never be PATCHed or
# otherwise changed. "PIM created it" is decided by, in order: the account is in PIM's own record of the accounts it created
# (-CreatedByPim, the engine's 'AdminAccountsCreatedByPim' record, written at create since 2026-11-12); the row is a central
# admin (created in this tenant by PIM from the managing tenant's baseline); the name is an admin name of this install (the
# recognised admin names -- starts / ends -- or the admin name patterns). Anything else = not PIM's = refused.
# ---------------------------------------------------------------------------------------------------------------------
function Test-PimAdminAccountNameIsPims {
    <#
      Does this UPN carry an ADMIN name of this install? $true / $false, or $null when no admin naming is known in this
      process (then the caller cannot decide by name). -Prefixes / -Suffixes with -NamingGiven are the test seam; by default
      the recognised starts + endings (Get-PimAdminAccountPrefixes / -Suffixes) of the hydrated settings AND the shipped
      defaults, plus the admin name patterns (Test-PimIsAdminAccountName -UseNamePatterns).
    #>
    param([AllowEmptyString()][string]$Upn, [string[]]$Prefixes = @(), [string[]]$Suffixes = @(), [switch]$NamingGiven)
    $u = "$Upn".Trim().ToLowerInvariant()
    if (-not $u) { return $null }
    $pre = New-Object System.Collections.Generic.List[string]; $suf = New-Object System.Collections.Generic.List[string]
    $addTo = { param($list, $vals) foreach ($x in @($vals)) { $s = "$x".Trim().ToLowerInvariant(); if ($s -and -not $s.StartsWith('-') -and -not $list.Contains($s)) { [void]$list.Add($s) } } }
    if ($NamingGiven) { & $addTo $pre $Prefixes; foreach ($x in @($Suffixes)) { $s = "$x".Trim().ToLowerInvariant(); if ($s -and -not $suf.Contains($s)) { [void]$suf.Add($s) } } }
    else {
        $shipped = $null
        if (Get-Command Get-PimShippedNamingConventions -ErrorAction SilentlyContinue) { try { $shipped = Get-PimShippedNamingConventions } catch { $shipped = $null } }
        if (Get-Command Get-PimAdminAccountPrefixes -ErrorAction SilentlyContinue) {
            try { & $addTo $pre @(Get-PimAdminAccountPrefixes) } catch { }
            if ($shipped) { try { & $addTo $pre @(Get-PimAdminAccountPrefixes -NamingConventions $shipped) } catch { } }
        }
        if (Get-Command Get-PimAdminAccountSuffixes -ErrorAction SilentlyContinue) {
            foreach ($nc in @($null, $shipped)) {
                $vals = @(); try { $vals = if ($nc) { @(Get-PimAdminAccountSuffixes -NamingConventions $nc) } else { @(Get-PimAdminAccountSuffixes) } } catch { $vals = @() }
                foreach ($x in $vals) { $s = "$x".Trim().ToLowerInvariant(); if ($s -and -not $suf.Contains($s)) { [void]$suf.Add($s) } }
            }
        }
        if (-not (Get-Command Get-PimAdminAccountPrefixes -ErrorAction SilentlyContinue)) {
            # a host without the guard library (the Manager): the literal 'Recognised admin names' entries -- 'Admin-' /
            # 'Admin-*' = a start, '*-a-id' = an ending; {AdminWord} filled in; anything else is ignored
            foreach ($nc in @($global:PIM_NamingConventions, $shipped)) {
                if ($null -eq $nc) { continue }
                $word = 'Admin'; try { if ("$($nc.AdminWord)".Trim()) { $word = "$($nc.AdminWord)".Trim() } } catch { }
                $ents = $null; try { $ents = $nc.AdminAccountPatterns } catch { $ents = $null }
                foreach ($e in @($ents)) {
                    $s = "$e".Trim().Replace('{AdminWord}', $word).ToLowerInvariant()
                    if (-not $s -or $s.Contains('{')) { continue }
                    if ($s.StartsWith('*') -and $s.Length -gt 1 -and -not $s.Substring(1).Contains('*')) { $x = $s.Substring(1); if (-not $suf.Contains($x)) { [void]$suf.Add($x) } }
                    elseif (-not $s.TrimEnd('*').Contains('*')) { & $addTo $pre @($s.TrimEnd('*')) }
                }
            }
        }
    }
    $local = $u; $at = $local.IndexOf('@'); if ($at -ge 0) { $local = $local.Substring(0, $at) }
    if (Get-Command Test-PimIsAdminAccountName -ErrorAction SilentlyContinue) {
        if (Test-PimIsAdminAccountName -Name $u -Prefixes $pre.ToArray() -Suffixes $suf.ToArray() -UseNamePatterns:(-not $NamingGiven)) { return $true }
    } else {
        foreach ($p in $pre) { if ($u.StartsWith($p)) { return $true } }
        foreach ($s in $suf) { if ($local.Length -gt $s.Length -and $local.EndsWith($s)) { return $true } }
    }
    # the admin name patterns (AdminAccountPattern / -HighPriv) of the naming in effect
    $patKnown = $false
    if (-not $NamingGiven -and (Get-Command Test-PimAdminName -ErrorAction SilentlyContinue) -and (Get-Command Get-PimNamingConvention -ErrorAction SilentlyContinue)) {
        $c = $null; try { $c = Get-PimNamingConvention } catch { $c = $null }
        if ($c -and ("$($c.AdminAccountPattern)".Trim() -or "$($c.AdminAccountPatternHighPriv)".Trim())) {
            $patKnown = $true
            try { if (Test-PimAdminName -Name $local) { return $true } } catch { }
        }
    }
    if ($pre.Count -eq 0 -and $suf.Count -eq 0 -and -not $patKnown) { return $null }
    return $false
}

function Test-PimAdminRowAccountIsForeign {
    <#
      Is the account this NORMAL admin row names one PIM did NOT create (see the block above)? $true = refuse every write to
      it. An existing-account row is never "foreign" here (it has its own rule: delegations only). -Upn = the live account's
      UPN (default: the row's). -CreatedByPim = PIM's record of created accounts (UPN lower-case -> anything). A name that
      cannot be judged (no naming known) is not foreign: the caller keeps today's behaviour.
    #>
    param([AllowNull()][object]$Row, [string]$Upn = '', [hashtable]$CreatedByPim = $null)
    if ($null -eq $Row) { return $false }
    if (Test-PimAdminIsExistingAccount -Row $Row) { return $false }
    $src = ''
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains('AdminSource')) { $src = "$($Row['AdminSource'])" } } elseif ($Row.PSObject.Properties['AdminSource']) { $src = "$($Row.AdminSource)" }
    if ($src.Trim() -ieq 'central') { return $false }
    $u = "$Upn".Trim()
    if (-not $u) {
        foreach ($n in @('UserPrincipalName', 'userPrincipalName', 'UPN')) {
            $v = ''
            if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { $v = "$($Row[$n])" } } elseif ($Row.PSObject.Properties[$n]) { $v = "$($Row.$n)" }
            if ($v.Trim()) { $u = $v.Trim(); break }
        }
    }
    if (-not $u) { return $false }
    if ($CreatedByPim -and $CreatedByPim.ContainsKey($u.ToLowerInvariant())) { return $false }
    return ((Test-PimAdminAccountNameIsPims -Upn $u) -eq $false)
}

function Get-PimAdminForeignAccountText {
    # The ONE plain line for a refused normal admin row whose account exists and is not PIM's (owner 2026-11-12).
    param([string]$Upn)
    return ("{0} already exists and was not created by PIM -- not changed; mark it AdminType=existing-account to give it delegations" -f "$Upn".Trim())
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
        if (-not $upn) {
            $nm = ''; foreach ($n in @('UserPrincipalName', 'UserName', 'Username')) { if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n) -and "$($r[$n])".Trim()) { $nm = "$($r[$n])".Trim(); break } } elseif ($r.PSObject.Properties[$n] -and "$($r.$n)".Trim()) { $nm = "$($r.$n)".Trim(); break } }
            [void]$refused.Add([pscustomobject]@{ upn = ''; name = $nm; reason = ("existing account '{0}': no valid UPN (name@domain) -- the row is not imported; an existing account row needs the exact UPN of the account (UserPrincipalName)" -f $nm) }); continue
        }
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
