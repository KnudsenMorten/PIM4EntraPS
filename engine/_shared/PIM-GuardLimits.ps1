#Requires -Version 5.1
<#
.SYNOPSIS
  PIM 100.119 (owner 2026-10-13: "drop the percentage in the guards and focus alone on amounts like 5" / "Approved,
  SuperAdmin sets them"): THE LIMIT OF A GUARD. Counts only -- there is no percentage in any guard's rule.

.DESCRIPTION
  Three guards have a limit a SuperAdmin can set on Operations > Guards, each inside a FLOOR and a CEILING that are
  literals in this file (Get-PimGuardLimitCatalog) and are stated on the page:

    manager.commit-removal   rows of ONE list removed in ONE commit before a SuperAdmin must approve   5 .. 25 .. 200
    engine.remove-budget     removals in one scope in one engine run before the run holds them          1 ..  5 ..  25
    engine.disable-guard     accounts disabled in one engine run before the run holds them              1 ..  3 ..  25
                             (the default is 3 since the owner's decision of 2026-10-13, after the review; it was 5)

  The value lives in the SQL store: pim.Settings 'GuardLimits' = { limits: { <guardId>: { value, by, atUtc } } }.
  The code that owns a guard asks Get-PimGuardLimit. What it returns is ALWAYS a number inside floor..ceiling:
    * nothing stored                      -> the default
    * a stored value outside floor..ceiling, not a whole number, or a setting that cannot be parsed -> the default
    * the store cannot be read            -> the default
  It never returns "no limit", and no guard can be switched off here: there is no such value.

  Every number is a literal returned by a function -- never a $script: variable (a $script: variable is $null in a child
  script scope behind a Get-Command load guard, and "-gt $null" is TRUE: BUG-79-6b).

  Test seam: $global:PIM_GuardReleaseStore = @{} (setting name -> JSON text) replaces SQL, as in PIM-GuardRelease.ps1.
#>

Set-StrictMode -Off

function Get-PimGuardLimitSettingName { 'GuardLimits' }

function Get-PimGuardLimitCatalog {
    <# PURE. LITERALS. One entry per guard that has a settable limit: floor, default, ceiling, the unit and why. #>
    @(
        [pscustomobject]@{ guardId = 'manager.commit-removal'; floor = 5; default = 25; ceiling = 200
            unit = 'rows of one list in one commit'
            why = 'Floor 5: lower and every routine clean-up of a few rows would need a SuperAdmin. Ceiling 200: higher and the check would never ask in a normal list; a commit that keeps none of a list''s rows, or only a few of them, always asks, whatever this number is.'
            bounds = @('rows taken out of one list in one commit (a commit, a restore from a backup, the departments save)') }
        # PIM 100.119 B5: ONE number, SEVEN actions -- every caller of Get-PimRemoveBudget / Test-PimRemoveBudgetAllowed. The
        # page, the confirmation and "More info" list them, so nobody raises it for one and gets the other six.
        [pscustomobject]@{ guardId = 'engine.remove-budget'; floor = 1; default = 5; ceiling = 25
            unit = 'removals per scope per run'
            why = 'Floor 1: 0 would stop every single removal, which is switching removal off and not a limit. Ceiling 25: more than that in one run is "many" (the commit check asks from 25); a larger removal goes through the approval of its exact list, which has no ceiling.'
            bounds = @(
                'removals a row asks for (Action = Remove), per kind of assignment'
                'the clean-up of leftovers PIM Manager manages (a full run with prune)'
                'removals by the daily reconcile, where it is set to enforce'
                'groups deleted because their definition is marked Retire'
                'groups deleted from the change queue (a DELETE chosen on the Drift page)'
                'admin accounts offboarded in one run (disabled, memberships removed)'
                'in a managed tenant: central admins the managing tenant withdraws in one pull') }
        [pscustomobject]@{ guardId = 'engine.disable-guard'; floor = 1; default = 3; ceiling = 25
            unit = 'accounts per run'
            why = 'Floor 1: 0 would stop every disable, including the one a row asks for. Ceiling 25: a real offboarding is a handful of accounts; a larger one is released for exactly its list of accounts, which has no ceiling.'
            bounds = @(
                'admin accounts disabled because their row says so (AccountStatus, a passed disable date)'
                'admin accounts disabled by an offboarding in one run'
                'admin accounts disabled by the inactivity sweep, where it is set to enforce') }
    )
}

function Get-PimCommitGuardFewLeftRows {
    <# PURE. LITERAL, not settable. The commit removal check asks when a commit would leave THIS MANY rows or fewer of the
       rows a list has now (PIM 100.119 A1 (iii), owner 2026-10-13)... #>
    2
}

function Get-PimCommitGuardFewLeftMinList {
    <# PURE. LITERAL, not settable. ...in a list that has MORE than this many rows (so 2 of 3 removed does not ask). #>
    5
}

function Test-PimGuardSuperAdminRole {
    <#
      PURE. THE one answer to "is this role SuperAdmin" for every guard approval and every limit (PIM 100.119 B4). The SAME
      rule the Manager's route gate applies (Test-PimManagerRoleAtLeast ranks the role by name, whatever its case, and
      does not trim it): the role is the word SuperAdmin in any case -- nothing more, nothing less. 'superadmin' and
      'SUPERADMIN' are SuperAdmin (a tenant whose only SuperAdmin is stored in lower case must be able to approve);
      'Admin', '', 'SuperAdmin ' and a role that merely contains the word are not.
    #>
    param([AllowNull()][string]$Role)
    if ($null -eq $Role) { return $false }
    return [string]::Equals("$Role", 'SuperAdmin', [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-PimGuardSignedInSuperAdmin {
    <# PURE. A SuperAdmin WITH a signed-in identity: the role rule above, and an identity that is neither empty nor the
       unauthenticated placeholder. #>
    param([AllowNull()][string]$Role, [AllowNull()][string]$Identity)
    if (-not (Test-PimGuardSuperAdminRole -Role $Role)) { return $false }
    $i = "$Identity".Trim()
    return [bool]($i -and $i -ne '<unauthenticated>')
}

function Get-PimGuardLimitSpec {
    <# PURE. The catalog entry of one guard, or $null when that guard has no settable limit. #>
    param([string]$GuardId)
    $id = "$GuardId".Trim().ToLowerInvariant()
    if (-not $id) { return $null }
    foreach ($s in @(Get-PimGuardLimitCatalog)) { if ("$($s.guardId)" -eq $id) { return $s } }
    return $null
}

function Get-PimGuardLimitDefault {
    <# PURE. The default of one guard as a literal fallback; -Fallback when the guard has no limit entry. #>
    param([string]$GuardId, [int]$Fallback = 5)
    $s = Get-PimGuardLimitSpec -GuardId $GuardId
    if ($s) { return [int]$s.default }
    return [int]$Fallback
}

function Test-PimGuardLimitValue {
    <#
      PURE. May -Value be the limit of -GuardId? @{ ok; value; reason }. A whole number inside floor..ceiling of a guard
      that HAS a limit. A never-releasable guard, a guard without a limit and an unknown guard are refused: they have no
      number to set.
    #>
    param([string]$GuardId, [AllowNull()][object]$Value)
    $id = "$GuardId".Trim().ToLowerInvariant()
    if (-not $id) { return [pscustomobject]@{ ok = $false; value = $null; reason = 'no guard named' } }
    if ((Get-Command Get-PimGuardNeverReleasable -ErrorAction SilentlyContinue) -and ($id -in @(Get-PimGuardNeverReleasable))) {
        return [pscustomobject]@{ ok = $false; value = $null; reason = "the guard '$id' is LOCKED: it has no limit and can never be exempted or switched off" }
    }
    $s = Get-PimGuardLimitSpec -GuardId $id
    if (-not $s) { return [pscustomobject]@{ ok = $false; value = $null; reason = "the guard '$id' has no limit that can be set" } }
    if ($null -eq $Value -or $Value -is [bool]) { return [pscustomobject]@{ ok = $false; value = $null; reason = 'the limit must be a whole number' } }
    $t = "$Value".Trim()
    if ($t -notmatch '^\d{1,6}$') { return [pscustomobject]@{ ok = $false; value = $null; reason = "'$t' is not a whole number (a count; there is no percentage)" } }
    $n = [int]$t
    if ($n -lt [int]$s.floor -or $n -gt [int]$s.ceiling) {
        return [pscustomobject]@{ ok = $false; value = $null; reason = ("{0} is outside {1} to {2} ({3})" -f $n, $s.floor, $s.ceiling, $s.unit) }
    }
    return [pscustomobject]@{ ok = $true; value = $n; reason = '' }
}

# ------------------------------------------------------------------------------------------------------------------------
# Store access (pim.Settings). The reader THROWS only when a configured store fails; Get-PimGuardLimit never throws.
# ------------------------------------------------------------------------------------------------------------------------
function Get-PimGuardLimitStoreCs {
    try { if (Get-Command Get-PimManagerSettingCs -ErrorAction SilentlyContinue) { $c = Get-PimManagerSettingCs; if ("$c".Trim()) { return "$c" } } } catch { }
    if ("$($global:PIM_EngineSqlCs)".Trim()) { return "$($global:PIM_EngineSqlCs)" }
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $c = Get-PimSqlSettingsConnectionString; if ("$c".Trim()) { return "$c" } } catch { } }
    return $null
}

function Get-PimGuardLimitStoreText {
    <# The stored JSON text of 'GuardLimits', or $null (nothing stored / no store). THROWS when a configured store fails. #>
    $name = Get-PimGuardLimitSettingName
    if ($global:PIM_GuardReleaseStore -is [hashtable]) { $v = $global:PIM_GuardReleaseStore[$name]; if ($null -eq $v) { return $null }; return "$v" }
    $cs = Get-PimGuardLimitStoreCs
    if ($cs -and (Get-Command Get-PimSqlSettingRaw -ErrorAction SilentlyContinue)) { return (Get-PimSqlSettingRaw -ConnectionString $cs -Name $name) }
    return $null
}

function Set-PimGuardLimitStoreText {
    <# Write 'GuardLimits' ONLY IF the stored text is still -Expected (compare-and-set). 1 = written, 0 = somebody wrote
       in between. THROWS when there is no store or it rejects the write. #>
    param([Parameter(Mandatory)][string]$Json, [AllowNull()][string]$Expected)
    $name = Get-PimGuardLimitSettingName
    if ($global:PIM_GuardReleaseStore -is [hashtable]) {
        if ("$($global:PIM_GuardReleaseStore[$name])" -cne "$Expected") { return 0 }
        $global:PIM_GuardReleaseStore[$name] = $Json; return 1
    }
    $cs = Get-PimGuardLimitStoreCs
    if (-not $cs -or -not (Get-Command Set-PimSqlSettingIfUnchanged -ErrorAction SilentlyContinue)) { throw 'REFUSED -- there is no settings store to write the limit to. Nothing was changed.' }
    return [int](Set-PimSqlSettingIfUnchanged -ConnectionString $cs -Name $name -NewValueJson $Json -ExpectedValueJson $Expected)
}

function ConvertFrom-PimGuardLimitsText {
    <#
      PURE. The stored text -> @{ limits = @{ <guardId> = @{ value; by; atUtc } }; refused = @{ <guardId> = <why> }; error }.
      Only values Test-PimGuardLimitValue accepts are in 'limits'; every other entry is in 'refused' with the reason.
      Text that is not JSON = error set, nothing in limits.
    #>
    param([AllowNull()][string]$Text)
    $out = @{ limits = @{}; refused = @{}; error = '' }
    if ($null -eq $Text -or "$Text".Trim() -eq '') { return $out }
    $o = $null
    try { $o = "$Text" | ConvertFrom-Json } catch { $out.error = "the stored limits are not readable ($($_.Exception.Message))"; return $out }
    if ($null -eq $o -or -not $o.PSObject.Properties['limits'] -or $null -eq $o.limits) { return $out }
    foreach ($p in @($o.limits.PSObject.Properties)) {
        $id = "$($p.Name)".Trim().ToLowerInvariant()
        $e = $p.Value
        $val = $null; $by = ''; $at = ''
        # REVIEW FIXES 2026-10-13: an entry is { value, by, atUtc } -- what the Guards page writes (Set-PimGuardLimit), always
        # with who set it and when. A bare number, or an entry without who / when, was written around the page: it is NOT
        # usable and the default applies. (No released version ever wrote 'GuardLimits': the setting is new with 100.119.)
        $shaped = ($null -ne $e -and -not ($e -is [string]) -and -not ($e -is [ValueType]) -and [bool]$e.PSObject.Properties['value'])
        if (-not $shaped) { $out.refused[$id] = 'the entry is not a limit the Guards page wrote (a value with who set it and when)'; continue }
        $val = $e.value; $by = "$($e.by)".Trim(); $at = $(if ($e.atUtc -is [datetime]) { $e.atUtc.ToUniversalTime().ToString('o') } else { "$($e.atUtc)".Trim() })
        $t = Test-PimGuardLimitValue -GuardId $id -Value $val
        if (-not $t.ok) { $out.refused[$id] = "$($t.reason)"; continue }
        $when = [datetime]::MinValue
        $atOk = [bool]$at -and [datetime]::TryParse($at, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$when)
        if (-not $by -or $by -eq '<unauthenticated>' -or -not $atOk) { $out.refused[$id] = 'the entry does not say who set the limit and when -- a limit is set on the Guards page only'; continue }
        $out.limits[$id] = @{ value = [int]$t.value; by = $by; atUtc = $at }
    }
    return $out
}

function Get-PimGuardLimitsParsed {
    <#
      The parsed stored limits. NEVER throws: a store that cannot be read gives error set and no limits (so every guard
      falls back to its default). Cached 30 s per process (the engine asks once per scope); -Fresh reads again.
    #>
    param([switch]$Fresh)
    if (-not ($global:PIM_GuardReleaseStore -is [hashtable]) -and -not $Fresh) {
        $c = $global:PIM_GuardLimitsCache
        if ($c -is [hashtable] -and $c['at'] -is [datetime] -and ([datetime]::UtcNow - $c['at']).TotalSeconds -lt 30 -and $c['parsed'] -is [hashtable]) { return $c['parsed'] }
    }
    $parsed = $null
    try { $parsed = ConvertFrom-PimGuardLimitsText -Text (Get-PimGuardLimitStoreText) }
    catch { $parsed = @{ limits = @{}; refused = @{}; error = "the limits could not be read ($($_.Exception.Message))" } }
    # Review fixes 2026-10-13: a stored entry that is not usable is SAID -- once per guard and reason in a process (the
    # engine asks once per scope). The default applies; the Guards page shows the same reason on the guard's row.
    try {
        if ($parsed.refused -is [hashtable] -and $parsed.refused.Count) {
            if (-not ($global:PIM_GuardLimitWarned -is [hashtable])) { $global:PIM_GuardLimitWarned = @{} }
            foreach ($rk in @($parsed.refused.Keys)) {
                $wk = "$rk|$($parsed.refused[$rk])"
                if ($global:PIM_GuardLimitWarned.ContainsKey($wk)) { continue }
                $global:PIM_GuardLimitWarned[$wk] = $true
                Write-Warning ("[guards] the stored limit of '{0}' is not usable ({1}) -- the default applies." -f $rk, $parsed.refused[$rk])
            }
        }
    } catch { }
    if (-not ($global:PIM_GuardReleaseStore -is [hashtable])) { $global:PIM_GuardLimitsCache = @{ at = [datetime]::UtcNow; parsed = $parsed } }
    return $parsed
}

function Get-PimGuardLimitState {
    <#
      What one guard's limit IS and where it comes from. NEVER throws. $null when the guard has no settable limit.
        @{ guardId; value; default; floor; ceiling; unit; why; source = 'set' | 'default'; note; setBy; setUtc }
      note says why the default applies when something WAS stored (refused / unreadable).
    #>
    param([string]$GuardId, [switch]$Fresh)
    $s = Get-PimGuardLimitSpec -GuardId $GuardId
    if (-not $s) { return $null }
    $id = "$($s.guardId)"
    $st = [ordered]@{ guardId = $id; value = [int]$s.default; default = [int]$s.default; floor = [int]$s.floor; ceiling = [int]$s.ceiling
                      unit = "$($s.unit)"; why = "$($s.why)"; bounds = @($s.bounds); source = 'default'; note = ''; setBy = ''; setUtc = '' }
    $p = Get-PimGuardLimitsParsed -Fresh:$Fresh
    if ($p.error) { $st.note = "$($p.error) -- the default applies"; return [pscustomobject]$st }
    if ($p.limits.ContainsKey($id)) {
        $e = $p.limits[$id]
        $st.value = [int]$e.value; $st.source = 'set'; $st.setBy = "$($e.by)"; $st.setUtc = "$($e.atUtc)"
    } elseif ($p.refused.ContainsKey($id)) {
        $st.note = "the stored value was refused ($($p.refused[$id])) -- the default applies"
    }
    return [pscustomobject]$st
}

function Get-PimGuardLimit {
    <#
      THE number the guard's own code uses. NEVER throws, never returns "no limit": the stored value when it is a whole
      number inside floor..ceiling, else the default (a literal). A guard without a limit entry returns -Fallback.
    #>
    param([Parameter(Mandatory)][string]$GuardId, [int]$Fallback = 5, [switch]$Fresh)
    $def = Get-PimGuardLimitDefault -GuardId $GuardId -Fallback $Fallback
    try {
        $st = Get-PimGuardLimitState -GuardId $GuardId -Fresh:$Fresh
        if ($null -eq $st) { return [int]$def }
        $n = [int]$st.value
        if ($n -lt [int]$st.floor -or $n -gt [int]$st.ceiling) { return [int]$def }
        return $n
    } catch { return [int]$def }
}

function Set-PimGuardLimit {
    <#
      A SuperAdmin sets the limit of one guard. THROWS 'REFUSED -- ...' on every rule it breaks (not a SuperAdmin, no
      person, a guard without a limit / a locked guard, a value outside floor..ceiling) and when the store rejects the
      write. Returns @{ guardId; before; after; floor; ceiling; default } -- the caller audits it.
      -Value $null with -Reset puts the guard back on its default (the stored entry is removed).
    #>
    param([Parameter(Mandatory)][string]$GuardId, [AllowNull()][object]$Value, [Parameter(Mandatory)][string]$By, [string]$Role = '', [switch]$Reset, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not (Test-PimGuardSuperAdminRole -Role $Role)) { throw 'REFUSED -- only a SuperAdmin may set the limit of a guard.' }
    if (-not "$By".Trim() -or "$By".Trim() -eq '<unauthenticated>') { throw 'REFUSED -- the person setting the limit is unknown.' }
    $id = "$GuardId".Trim().ToLowerInvariant()
    $spec = Get-PimGuardLimitSpec -GuardId $id
    $new = $null
    if ($Reset) {
        $probe = Test-PimGuardLimitValue -GuardId $id -Value $(if ($spec) { $spec.default } else { 0 })
        if (-not $probe.ok) { throw "REFUSED -- $($probe.reason)." }
    } else {
        $t = Test-PimGuardLimitValue -GuardId $id -Value $Value
        if (-not $t.ok) { throw "REFUSED -- $($t.reason). Nothing was changed." }
        $new = [int]$t.value
    }
    # PIM 100.119 B6: read, change ONE entry, write only if nobody wrote in between (compare-and-set), else read again --
    # two SuperAdmins saving different guards at the same moment both keep their entry.
    $before = $null; $written = $false
    for ($try = 0; $try -lt 4 -and -not $written; $try++) {
        $text = Get-PimGuardLimitStoreText
        $parsed = ConvertFrom-PimGuardLimitsText -Text $text
        if ($parsed.error) { throw "REFUSED -- $($parsed.error). Nothing was changed." }
        if ($null -eq $before) { $before = Get-PimGuardLimitState -GuardId $id -Fresh }
        $next = [ordered]@{}
        foreach ($k in @($parsed.limits.Keys | Sort-Object)) { if ($k -ne $id) { $next[$k] = [ordered]@{ value = [int]$parsed.limits[$k].value; by = "$($parsed.limits[$k].by)"; atUtc = "$($parsed.limits[$k].atUtc)" } } }
        if (-not $Reset) { $next[$id] = [ordered]@{ value = $new; by = "$By".Trim(); atUtc = $NowUtc.ToUniversalTime().ToString('o') } }
        $json = ConvertTo-Json -InputObject ([ordered]@{ limits = $next }) -Depth 6 -Compress
        $written = ([int](Set-PimGuardLimitStoreText -Json $json -Expected $text) -eq 1)
    }
    if (-not $written) { throw 'REFUSED -- the limits kept changing while this one was saved. Nothing was changed; reload the Guards page and set it again.' }
    $global:PIM_GuardLimitsCache = $null
    $after = Get-PimGuardLimitState -GuardId $id -Fresh
    if ([int]$after.value -ne $(if ($Reset) { [int]$spec.default } else { $new })) { throw 'REFUSED -- the limit was written but did not read back; the default applies. Reload the Guards page.' }
    return [pscustomobject]@{ guardId = $id; before = $before; after = $after; floor = [int]$spec.floor; ceiling = [int]$spec.ceiling; default = [int]$spec.default }
}
