<#
  PIM-DownlinkIntents.ps1 -- REQ-REV-DOWN-1 + the downlink half of REQ-REN-1 (operator, 2026-09-22).

    "if a group, admin, permissions delegation assignment is replicated downlink and it is being
     revoked centrally, then we need a way to prompt super user if it should be revoked downlink as
     well. If yes, then it goes into the queue. these changes should be auto-committed so we dont
     have to approve 25 tenants (commit)"
    "change must be reflected downlink if it is replicated ... Maybe consider to do the acutual
     rename in downlinks first and lock the central"

  WHY A NEW CONCEPT WAS NEEDED, instead of just publishing the new desired set.
  The slave applies what it pulls BY KEY, and it is deliberately report-first about anything that
  disappears: a row the master no longer sends is recorded as "would remove" and is removed only
  with -AllowRetraction, inside a removal budget (Invoke-PimDownlinkAssignmentApply). That rule
  exists because "the master revoked it" and "the master failed to publish it" look identical from
  the slave, and the safe reading is the second. It is right, and it must stay.
  So the two things the operator asked for cannot be expressed by absence:
    * a REVOKE that must reach the managed tenants is an ABSENCE the slave is told to trust;
    * a RENAME published as a new key is an ABSENCE (the old key) plus a CREATE (the new one), which
      a report-first slave turns into a DUPLICATE -- exactly the hazard behind "rename in the
      downlinks first and lock the central".
  An INTENT says which absence is authorised, by whom and why. It travels inside the signed bundle,
  so a slave acts on a withdrawal only when the master really published it -- the whole point of
  report-first is preserved for everything that is NOT named.

  AUTO-COMMITTED BY DESIGN (the operator's "so we dont have to approve 25 tenants"): the human
  decision is the central one. An intent is the record of that decision; no managed tenant asks
  again. What an intent can NEVER do is widen: it only authorises removing or renaming a row the
  master already owns (Owner=MSP), and it names exactly one key.

  PURE. Every function here is input -> output; the store I/O is injected by the caller, so the
  tests drive the real logic with no SQL and no tenant. ASCII only; PS 5.1 + 7.
#>
Set-StrictMode -Off

$script:PimDownlinkIntentOps      = @('withdraw', 'rename', 'revoke-sessions')   # §79.6: revoke-sessions
$script:PimDownlinkIntentMaxAgeDays = 30     # an intent nobody pulled in a month is stale, not pending

function New-PimDownlinkIntent {
    <#
      One authorised downlink intent.
        -Op withdraw : remove this row in the managed tenants (the central revoke reached them)
        -Op rename   : the row whose key was -Key is now -To (rename in place, never re-create)
      Returns $null for an unusable request rather than a half-formed record -- a malformed intent
      that reaches a slave is worse than none.
    #>
    param(
        # §79.6 (operator 2026-09-25: "verify that a reset sessions centrally in msp mode for an admin also resets the sessions
        # in all slaves. important if person leaves msp"): -Op revoke-sessions -- every managed tenant revokes the sign-in
        # sessions of ITS account for this central admin (Entity Account-Definitions-Admins, Key = the admin's UserName).
        [Parameter(Mandatory)][ValidateSet('withdraw', 'rename', 'revoke-sessions')][string]$Op,
        [Parameter(Mandatory)][string]$Entity,
        [Parameter(Mandatory)][string]$Key,
        [string]$To = '',
        [string]$By = '',
        [string]$Reason = '',
        # §79.6: the managed tenants (tenant ids) this intent is for; EMPTY = every tenant that pulls the bundle.
        [string[]]$Tenants = @(),
        [datetime]$NowUtc = [datetime]::UtcNow
    )
    $e = "$Entity".Trim(); $k = "$Key".Trim(); $t = "$To".Trim()
    if (-not $e -or -not $k) { return $null }
    if ($Op -eq 'rename' -and (-not $t -or $t -ieq $k)) { return $null }   # a rename to itself is not a rename
    if ($Op -eq 'revoke-sessions' -and $e -notin @('Account-Definitions-Admins', 'Account-Definitions-Admins-Central')) { return $null }
    $o = [ordered]@{
        op      = "$Op"
        entity  = $e
        key     = $k
        to      = $(if ($Op -eq 'rename') { $t } else { '' })
        by      = "$By"
        reason  = "$Reason"
        utc     = $NowUtc.ToUniversalTime().ToString('o')
    }
    # 🔴 R25-12: a SUPPLIED tenant list with any entry that is not a tenant id is refused (unusable intent -> $null). It used
    # to drop the bad entries -- and with ALL of them bad (a domain name typed for a tenant id) the intent carried no list
    # and so reached EVERY managed tenant. Narrowing that silently widens is the wrong direction to fail.
    $given = @(@($Tenants) | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Where-Object { $_ })
    $tn = @($given | Where-Object { $_ -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' } | Sort-Object -Unique)
    if ($given.Count -and @($given | Where-Object { $_ -notmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' }).Count) { return $null }
    if ($tn.Count) { $o['tenants'] = $tn }
    return $o
}

function Add-PimDownlinkIntent {
    <#
      PURE list merge: the new list, with $Intent added or replacing the one it supersedes.
      Same entity+key+op = the later one wins (a row revoked twice is one intent, and a rename that
      is corrected before the next publish must not leave the first hop behind).
      A WITHDRAW supersedes a pending RENAME of the same key: the row is going away either way.
    #>
    param([object[]]$Existing = @(), [Parameter(Mandatory)][object]$Intent)
    if (-not $Intent) { return @($Existing) }
    $e = "$($Intent.entity)".ToLowerInvariant(); $k = "$($Intent.key)".ToLowerInvariant()
    $keep = New-Object System.Collections.Generic.List[object]
    foreach ($x in @($Existing)) {
        if (-not $x) { continue }
        $sameRow = ("$($x.entity)".ToLowerInvariant() -eq $e -and "$($x.key)".ToLowerInvariant() -eq $k)
        # A withdraw supersedes a pending RENAME only -- never a session revoke (§79.6): "revoke, then withdraw" is exactly the
        # person-leaves sequence, and dropping the revoke would leave their sessions alive in every managed tenant.
        if ($sameRow -and ("$($x.op)" -eq "$($Intent.op)" -or ("$($Intent.op)" -eq 'withdraw' -and "$($x.op)" -eq 'rename'))) { continue }
        $keep.Add($x) | Out-Null
    }
    $keep.Add($Intent) | Out-Null
    return @($keep.ToArray())
}

function Select-PimDownlinkIntents {
    <#
      The intents that still apply, for the bundle. Drops anything older than -MaxAgeDays (a tenant
      that never pulled in a month has a bigger problem than one stale withdrawal, and an intent
      that lingers forever is a trap waiting for a tenant to be re-onboarded).
      Returns @{ intents; dropped } -- dropped is REPORTED, never silently discarded.
    #>
    param([object[]]$Intents = @(), [datetime]$NowUtc = [datetime]::UtcNow, [int]$MaxAgeDays = 0)
    # 🔴 §79.6 live E2E 2026-09-25 (RIDE, 2.4.435): EVERY intent -- one recorded a minute earlier included -- was dropped as
    # "older than the intent lifetime". The limit came from $script:PimDownlinkIntentMaxAgeDays, and `$age -gt $null` is
    # TRUE for any age. Why $null: downlink-job-entry.ps1 dot-sources this file (setting the variable in ITS script scope),
    # then runs setup/Invoke-PimScenarioRun.ps1 -- a child script, a NEW script scope -- whose PIM-ScenarioProfile.ps1 skips
    # re-loading this file because the functions are already visible (Get-Command guard). Inside the function $script: is
    # then the CHILD's scope, where the variable was never set. The literal 30 is the floor now; a limit is never $null.
    if ($MaxAgeDays -le 0) { $MaxAgeDays = [int]$script:PimDownlinkIntentMaxAgeDays }
    if ($MaxAgeDays -le 0) { $MaxAgeDays = 30 }
    $live = New-Object System.Collections.Generic.List[object]
    $old  = New-Object System.Collections.Generic.List[object]
    foreach ($i in @($Intents)) {
        if (-not $i -or -not "$($i.entity)".Trim() -or -not "$($i.key)".Trim()) { continue }
        $age = $null
        # pwsh 7's ConvertFrom-Json hands 'utc' over as a [datetime]; never round-trip it through culture text.
        try {
            $t = if ($i.utc -is [datetime]) { $i.utc } else { [datetime]::Parse("$($i.utc)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
            $age = ($NowUtc.ToUniversalTime() - $t.ToUniversalTime()).TotalDays
        } catch { $age = $null }
        if ($null -ne $age -and $age -gt $MaxAgeDays) { $old.Add($i) | Out-Null; continue }
        $live.Add($i) | Out-Null
    }
    return @{ intents = @($live.ToArray()); dropped = @($old.ToArray()) }
}

function Get-PimDownlinkWithdrawalKeys {
    # The keys a slave is AUTHORISED to remove for one entity, lower-cased for matching.
    # §79.5: an intent with a 'tenants' list (the master's "pick") applies ONLY in those tenants; -TenantId is this one.
    # An intent without the list applies everywhere (unchanged). A scoped intent never matches an unknown own id.
    param([object[]]$Intents = @(), [Parameter(Mandatory)][string]$Entity, [string]$TenantId = '')
    $e = "$Entity".Trim().ToLowerInvariant()
    $tid = "$TenantId".Trim().ToLowerInvariant()
    $out = @{}
    foreach ($i in @($Intents)) {
        if (-not $i) { continue }
        if ("$($i.op)" -ne 'withdraw') { continue }
        if ("$($i.entity)".Trim().ToLowerInvariant() -ne $e) { continue }
        $tn = @(@($i.tenants) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
        if ($tn.Count -and -not ($tid -and ($tn -contains $tid))) { continue }
        $out["$($i.key)".Trim().ToLowerInvariant()] = $i
    }
    return $out
}

function Get-PimDownlinkSessionRevokes {
    <#
      §79.6 PURE. The session revokes THIS tenant must carry out: op revoke-sessions, for this tenant (no 'tenants' list, or
      one naming -TenantId), not already done (-Applied: the "key|utc" ids this tenant recorded). A later revoke of the same
      admin is a NEW revoke (its utc differs) and applies again -- a person can be revoked twice. Returns [ { key; utc; id } ].
    #>
    param([object[]]$Intents = @(), [string]$TenantId = '', [string[]]$Applied = @())
    $tid = "$TenantId".Trim().ToLowerInvariant()
    $done = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($a in @($Applied)) { if ("$a".Trim()) { [void]$done.Add("$a".Trim()) } }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($i in @($Intents)) {
        if (-not $i -or "$($i.op)" -ne 'revoke-sessions' -or -not "$($i.key)".Trim()) { continue }
        $tn = @(@($i.tenants) | Where-Object { "$_".Trim() })
        if ($tn.Count -and -not ($tid -and (@($tn | ForEach-Object { "$_".Trim().ToLowerInvariant() }) -contains $tid))) { continue }
        # The id's time is ROUND-TRIP UTC whatever the payload parser made of it: pwsh 7's ConvertFrom-Json turns the ISO
        # string into a [datetime], and "$([datetime])" is culture text -- the same intent would get another id per edition.
        $u = $i.utc
        $uStr = if ($u -is [datetime]) { $u.ToUniversalTime().ToString('o') } else {
            try { [datetime]::Parse("$u".Trim(), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime().ToString('o') } catch { "$u".Trim() } }
        $id = ("{0}|{1}" -f "$($i.key)".Trim().ToLowerInvariant(), $uStr)
        if ($done.Contains($id)) { continue }
        $out.Add([pscustomobject]@{ key = "$($i.key)".Trim(); utc = $uStr; id = $id; by = "$($i.by)"; reason = "$($i.reason)" }) | Out-Null
    }
    return @($out.ToArray())
}

function Select-PimDownlinkSessionRevokeTargets {
    <#
      PURE. 🔴 R25-31 -- which of -Revokes (Get-PimDownlinkSessionRevokes) this slave may carry out. A revoke names a
      CENTRAL admin by UserName; the slave revokes '<key>@<its domain>'. That is right only when the key IS a central admin
      this slave holds for the master (Account-Definitions-Admins-Central, Owner = -Owner) and no LOCAL admin of the
      customer has the same UserName (the local row wins that name, PIM-EngineCore Get-PimDesiredRows) -- otherwise the
      customer's own admin had their sessions ended, auto-committed. Returns @{ revoke = @(...); skipped = @({ key; id; why }) }.
    #>
    param([object[]]$Revokes = @(), [object[]]$CentralRows = @(), [object[]]$LocalRows = @(), [string]$Owner = 'MSP')
    $val = { param($r, $k) if ($null -eq $r) { '' } elseif ($r -is [System.Collections.IDictionary]) { "$($r[$k])" } else { $p = $r.PSObject.Properties[$k]; if ($p) { "$($p.Value)" } else { '' } } }
    $central = @{}; foreach ($c in @($CentralRows)) { $n = (& $val $c 'UserName').Trim().ToLowerInvariant(); if ($n -and (& $val $c 'Owner') -eq $Owner) { $central[$n] = $true } }
    $local = @{}; foreach ($l in @($LocalRows)) { $n = (& $val $l 'UserName').Trim().ToLowerInvariant(); if ($n) { $local[$n] = $true } }
    $ok = New-Object System.Collections.Generic.List[object]; $skip = New-Object System.Collections.Generic.List[object]
    foreach ($rv in @($Revokes)) {
        if ($null -eq $rv) { continue }
        $k = "$($rv.key)".Trim().ToLowerInvariant()
        if ($local.ContainsKey($k)) { $skip.Add([pscustomobject]@{ key = "$($rv.key)"; id = "$($rv.id)"; why = "this tenant has its OWN admin named '$($rv.key)' -- that account is the customer's, not the central admin's; NOT revoked" }) | Out-Null; continue }
        if (-not $central.ContainsKey($k)) { $skip.Add([pscustomobject]@{ key = "$($rv.key)"; id = "$($rv.id)"; why = "'$($rv.key)' is not a central admin this tenant holds for $Owner -- NOT revoked" }) | Out-Null; continue }
        $ok.Add($rv) | Out-Null
    }
    return @{ revoke = @($ok.ToArray()); skipped = @($skip.ToArray()) }
}

function Get-PimDownlinkRenameMap {
    # from-key -> to-key for one entity (lower-cased keys, original-cased target).
    # R25-12: an intent with a 'tenants' list applies ONLY in those tenants (-TenantId is this one), exactly as a withdrawal
    # does; a scoped rename never matches an unknown own id.
    param([object[]]$Intents = @(), [Parameter(Mandatory)][string]$Entity, [string]$TenantId = '')
    $e = "$Entity".Trim().ToLowerInvariant()
    $tid = "$TenantId".Trim().ToLowerInvariant()
    $map = @{}
    foreach ($i in @($Intents)) {
        if (-not $i) { continue }
        if ("$($i.op)" -ne 'rename') { continue }
        if ("$($i.entity)".Trim().ToLowerInvariant() -ne $e) { continue }
        $tn = @(@($i.tenants) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim().ToLowerInvariant() })
        if ($tn.Count -and -not ($tid -and ($tn -contains $tid))) { continue }
        $from = "$($i.key)".Trim(); $to = "$($i.to)".Trim()
        if (-not $from -or -not $to) { continue }
        $map[$from.ToLowerInvariant()] = $to
    }
    return $map
}

function Resolve-PimDownlinkRenamePlan {
    <#
      PURE. What a rename means for the rows a slave already holds.
      -Rows      the slave's current rows for -Entity
      -RenameMap from-key(lower) -> to-key   (Get-PimDownlinkRenameMap)
      -KeyColumn the column holding the key in THIS entity (GroupTag / TargetGroupTag / ...)
      Returns @{ updates = @(@{ index; column; from; to }); collisions = @(...) }.
      A rename onto a key the slave ALREADY has is a COLLISION, reported and NOT applied: merging
      two rows silently is indistinguishable from losing one.
    #>
    param(
        [object[]]$Rows = @(),
        [hashtable]$RenameMap = @{},
        [Parameter(Mandatory)][string]$KeyColumn
    )
    $updates = New-Object System.Collections.Generic.List[object]
    $collisions = New-Object System.Collections.Generic.List[object]
    if (-not $RenameMap -or $RenameMap.Count -eq 0) { return @{ updates = @(); collisions = @() } }
    $have = @{}
    for ($i = 0; $i -lt @($Rows).Count; $i++) {
        $v = "$(Get-PimDownlinkValue -Object $Rows[$i] -Key $KeyColumn)".Trim()
        if ($v) { $have[$v.ToLowerInvariant()] = $i }
    }
    for ($i = 0; $i -lt @($Rows).Count; $i++) {
        $v = "$(Get-PimDownlinkValue -Object $Rows[$i] -Key $KeyColumn)".Trim()
        if (-not $v) { continue }
        $lk = $v.ToLowerInvariant()
        if (-not $RenameMap.ContainsKey($lk)) { continue }
        $to = "$($RenameMap[$lk])".Trim()
        if ($have.ContainsKey($to.ToLowerInvariant()) -and $have[$to.ToLowerInvariant()] -ne $i) {
            $collisions.Add([ordered]@{ index = $i; column = $KeyColumn; from = $v; to = $to
                reason = "the managed tenant already holds a row keyed '$to' -- renaming '$v' onto it would merge two rows into one" }) | Out-Null
            continue
        }
        $updates.Add([ordered]@{ index = $i; column = $KeyColumn; from = $v; to = $to }) | Out-Null
    }
    return @{ updates = @($updates.ToArray()); collisions = @($collisions.ToArray()) }
}

function Get-PimDownlinkIntentSummary {
    # One readable line per intent, for the publish log, the pull log and the Replication overview.
    param([object[]]$Intents = @())
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($i in @($Intents)) {
        if (-not $i) { continue }
        if ("$($i.op)" -eq 'rename') {
            $out.Add(("rename {0}: '{1}' -> '{2}'{3}" -f $i.entity, $i.key, $i.to, $(if ("$($i.by)") { " (by $($i.by))" } else { '' }))) | Out-Null
        } elseif ("$($i.op)" -eq 'revoke-sessions') {
            $tn = @(@($i.tenants) | Where-Object { "$_".Trim() })
            $out.Add(("revoke sign-in sessions of '{0}' in {1}{2}" -f $i.key, $(if ($tn.Count) { "$($tn.Count) chosen tenant(s)" } else { 'every managed tenant' }), $(if ("$($i.by)") { " (by $($i.by))" } else { '' }))) | Out-Null
        } else {
            $out.Add(("withdraw {0}: '{1}'{2}{3}" -f $i.entity, $i.key,
                $(if ("$($i.by)") { " (by $($i.by))" } else { '' }),
                $(if ("$($i.reason)") { " -- $($i.reason)" } else { '' }))) | Out-Null
        }
    }
    return @($out.ToArray())
}
