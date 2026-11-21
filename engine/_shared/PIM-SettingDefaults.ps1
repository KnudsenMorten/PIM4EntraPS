#Requires -Version 5.1
<#
.SYNOPSIS
    PIM REQUIREMENTS 100.40 (f) / framework 12.16 CONVERGE-DEFAULTS for SETTINGS PAGES -- a page saved once no longer
    freezes every product default. A settings row stores only what a PERSON set; a read is the product default with the
    person-set keys laid over it, so a later product default change reaches every install whose page was saved.

.DESCRIPTION
    WHY (framework 12.16): Alerting, MailNotifications and EmailControls were saved as the WHOLE object -- every event
    switch, every per-recipient report switch, the kill switch -- so the first save copied the product defaults of that
    day into the row, and a later default change never reached that install.

    THE MODEL
      * Default tree (Get-PimSettingDefaultTree): the keys of a setting that HAVE a product default, with their value
        today. Every other key is the person's data (recipients, webhook, redirect, allowlist) and is always stored.
      * Stored row = the person-set keys only, plus the marker  defaultsModel = 'person-set-1'.
        ConvertTo-PimSettingStoredValue builds it from the full value a page saves: a key equal to the current default
        is NOT stored -- unless the person had already set it to that same value (their choice is kept, so a later
        default move does not change it under them). A top-level key only the stored row has (a field an older page
        does not know, e.g. Alerting throttledAfterRuns) is kept.
      * Read = default tree overlaid with the person-set keys (Get-PimSettingEffective).

    MIGRATION RULE for a row saved before this (no marker = the old WHOLE object; nothing is rewritten in bulk):
      a value EQUAL to the product default of the release that wrote it (the FROZEN 3.1.53 baseline,
      Get-PimSettingLegacyBaseline -- equal to today's default) was the default, not a choice: it follows the product
      default from now on. A value that DIFFERS is the person's choice and is kept. The row is rewritten in the new form
      on its next save. The baseline is frozen on purpose: an install that skips releases still compares its old row
      with the defaults of the day it was written, never with a later default (that would turn every old default into
      a "choice" and freeze it again). Limit: a person who deliberately chose a value equal to the 3.1.53 default cannot
      be told apart -- that value follows the default.

    A row written in the new form is read the same by an older reader (absent key = the default it already uses), so a
    mixed ring (an older engine next to a newer Manager) sends the same mail.
    PURE. PS 5.1 + 7, no modules. Never throws on a malformed row (it reads as "nothing person-set").
#>
Set-StrictMode -Off


function Get-PimAlertEventDefaults {
    # The Alerting event switches and their PRODUCT default (all ON today). One list for the Manager, the scheduler and
    # the installer; a NEW event added here defaults to what this says on every install, saved page or not.
    [ordered]@{
        'engine-failure' = $true; 'drift' = $true; 'expiring-access' = $true; 'break-glass' = $true; 'sessions-revoked' = $true
        'coverage' = $true; 'target-missing' = $true; 'pending-uncommitted' = $true
    }
}

function Get-PimMailRecipientDefaults {
    # PURE. The product default of ONE recipient's notification preference (MailNotifications.recipients[]): every report
    # and alert ON, audience manager, severity floor info. -ReportTypes / -AlertTypes default to the live catalog.
    param([string[]]$ReportTypes, [string[]]$AlertTypes)
    if ($null -eq $ReportTypes -or $null -eq $AlertTypes) {
        $cat = @(); if (Get-Command Get-PimMailReportCatalog -ErrorAction SilentlyContinue) { $cat = @(Get-PimMailReportCatalog) }
        if ($null -eq $ReportTypes) { $ReportTypes = @($cat | Where-Object { $_.kind -eq 'report' } | ForEach-Object { "$($_.type)" }) }
        if ($null -eq $AlertTypes) { $AlertTypes = @($cat | Where-Object { $_.kind -eq 'alert' } | ForEach-Object { "$($_.type)" }) }
    }
    $rep = [ordered]@{}; foreach ($t in @($ReportTypes)) { $rep["$t"] = $true }
    $al = [ordered]@{}; foreach ($t in @($AlertTypes)) { $al["$t"] = $true }
    [ordered]@{ audience = 'manager'; severityFloor = 'info'; reports = $rep; alerts = $al }
}

function Get-PimSettingDefaultTree {
    # PURE. The keys of a setting that carry a PRODUCT default, with today's value. Unknown name = no defaults (every key
    # is the person's data, stored as given).
    param([Parameter(Mandatory)][string]$Name)
    switch ($Name) {
        'Alerting'      { return [ordered]@{ events = (Get-PimAlertEventDefaults) } }
        'EmailControls' { return [ordered]@{ killSwitch = $false } }
        'MailNotifications' {
            $rt = @(); if (Get-Command Get-PimMailReportCatalog -ErrorAction SilentlyContinue) { $rt = @(Get-PimMailReportCatalog | Where-Object { $_.kind -eq 'report' } | ForEach-Object { "$($_.type)" }) }
            $r = [ordered]@{}; foreach ($t in $rt) { $r[$t] = [ordered]@{ attach = 'link' } }
            return [ordered]@{ reports = $r }
        }
        default { return [ordered]@{} }
    }
}

function Get-PimSettingLegacyBaseline {
    <#
      PURE. FROZEN -- NEVER EDIT. The product defaults as they were when settings were still saved as the whole object
      (up to 3.1.53). A row WITHOUT the marker is compared with THIS, not with today's defaults (see the migration rule).
      -Part 'recipient' = one MailNotifications recipient.
    #>
    param([Parameter(Mandatory)][string]$Name, [string]$Part = '')
    $rep = @('daily-summary', 'tier-report', 'get-started', 'pending-approvals')
    $alr = @('engine-failure', 'break-glass', 'drift', 'coverage', 'target-missing', 'sessions-revoked', 'expiring-access', 'pending-uncommitted')
    if ($Name -eq 'MailNotifications' -and $Part -eq 'recipient') { return (Get-PimMailRecipientDefaults -ReportTypes $rep -AlertTypes $alr) }
    switch ($Name) {
        'Alerting' {
            $ev = [ordered]@{}; foreach ($e in @('engine-failure', 'drift', 'expiring-access', 'break-glass', 'sessions-revoked', 'coverage', 'target-missing', 'pending-uncommitted')) { $ev[$e] = $true }
            return [ordered]@{ events = $ev }
        }
        'EmailControls' { return [ordered]@{ killSwitch = $false } }
        'MailNotifications' { $r = [ordered]@{}; foreach ($t in $rep) { $r[$t] = [ordered]@{ attach = 'link' } }; return [ordered]@{ reports = $r } }
        default { return [ordered]@{} }
    }
}

function ConvertTo-PimSettingTree {
    # PURE. A stored value (JSON text at the TOP level, PSCustomObject, dictionary, list, scalar) as nested [ordered]
    # dictionaries + object[] lists, so it can be compared and merged. A nested string is never parsed.
    param([AllowNull()][object]$Value, [switch]$Top)
    $v = $Value
    if ($Top -and $v -is [string]) {
        $s = "$v".Trim()
        if (-not $s) { return $null }
        try { $v = $s | ConvertFrom-Json } catch { return $null }
        if ($v -is [string]) { try { $v = "$v" | ConvertFrom-Json } catch { return $null } }   # SQL may hold a JSON string of JSON
    }
    if ($null -eq $v) { return $null }
    if ($v -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}; foreach ($k in @($v.Keys)) { $o["$k"] = ConvertTo-PimSettingTree -Value $v[$k] }
        return $o
    }
    if ($v -is [string] -or $v -is [ValueType]) { return $v }
    if ($v -is [System.Collections.IEnumerable]) {
        $list = @(foreach ($x in $v) { , (ConvertTo-PimSettingTree -Value $x) })
        return , $list
    }
    if ($v -is [System.Management.Automation.PSCustomObject]) {
        $o = [ordered]@{}; foreach ($p in @($v.PSObject.Properties)) { $o["$($p.Name)"] = ConvertTo-PimSettingTree -Value $p.Value }
        return $o
    }
    return $v
}

function Test-PimSettingEqual {
    # PURE. Deep equality of two setting trees: dictionaries by key (order-free), lists by position, bools strictly,
    # everything else by its text.
    param([AllowNull()][object]$A, [AllowNull()][object]$B)
    $aD = $A -is [System.Collections.IDictionary]; $bD = $B -is [System.Collections.IDictionary]
    if ($aD -or $bD) {
        if (-not ($aD -and $bD)) { return $false }
        if ($A.Count -ne $B.Count) { return $false }
        foreach ($k in @($A.Keys)) { if (-not $B.Contains($k)) { return $false }; if (-not (Test-PimSettingEqual -A $A[$k] -B $B[$k])) { return $false } }
        return $true
    }
    $aL = ($A -is [System.Collections.IList]); $bL = ($B -is [System.Collections.IList])
    if ($aL -or $bL) {
        if (-not ($aL -and $bL)) { return $false }
        if ($A.Count -ne $B.Count) { return $false }
        for ($i = 0; $i -lt $A.Count; $i++) { if (-not (Test-PimSettingEqual -A $A[$i] -B $B[$i])) { return $false } }
        return $true
    }
    if ($null -eq $A -or $null -eq $B) { return ($null -eq $A -and $null -eq $B) }
    if ($A -is [bool] -or $B -is [bool]) { return ($A -is [bool] -and $B -is [bool] -and $A -eq $B) }
    return ("$A" -ceq "$B")
}

function Get-PimSettingDelta {
    <#
      PURE. The person-set part of -Value (a tree): every key WITHOUT a product default (data), and every defaulted key whose
      value differs from -Default. A defaulted key EQUAL to the default is left out -- unless -Prior (the person-set part
      stored before) holds that same value: the person had chosen it, and it stays theirs. Nested dictionaries recurse.
    #>
    param([AllowNull()][object]$Value, [AllowNull()][object]$Default, [AllowNull()][object]$Prior)
    $out = [ordered]@{}
    if (-not ($Value -is [System.Collections.IDictionary])) { return $out }
    foreach ($k in @($Value.Keys)) {
        if ("$k" -eq 'defaultsModel') { continue }
        $v = $Value[$k]
        $hasD = ($Default -is [System.Collections.IDictionary]) -and $Default.Contains($k)
        $hasP = ($Prior -is [System.Collections.IDictionary]) -and $Prior.Contains($k)
        if (-not $hasD) { $out[$k] = $v; continue }
        $d = $Default[$k]
        if ($d -is [System.Collections.IDictionary] -and $v -is [System.Collections.IDictionary]) {
            $sub = Get-PimSettingDelta -Value $v -Default $d -Prior $(if ($hasP) { $Prior[$k] } else { $null })
            if ($sub.Count) { $out[$k] = $sub }
            continue
        }
        if (-not (Test-PimSettingEqual -A $v -B $d)) { $out[$k] = $v; continue }
        if ($hasP -and (Test-PimSettingEqual -A $Prior[$k] -B $v)) { $out[$k] = $v }
    }
    return $out
}

function Merge-PimSettingOverDefault {
    # PURE. -Default with -PersonSet laid over it (nested dictionaries merge; anything else replaces). Never the marker.
    param([AllowNull()][object]$Default, [AllowNull()][object]$PersonSet)
    $out = [ordered]@{}
    if ($Default -is [System.Collections.IDictionary]) { foreach ($k in @($Default.Keys)) { $out[$k] = ConvertTo-PimSettingTree -Value $Default[$k] } }
    if ($PersonSet -is [System.Collections.IDictionary]) {
        foreach ($k in @($PersonSet.Keys)) {
            if ("$k" -eq 'defaultsModel') { continue }
            $p = $PersonSet[$k]
            if ($out.Contains($k) -and $out[$k] -is [System.Collections.IDictionary] -and $p -is [System.Collections.IDictionary]) { $out[$k] = Merge-PimSettingOverDefault -Default $out[$k] -PersonSet $p }
            else { $out[$k] = $p }
        }
    }
    return $out
}

function Test-PimSettingPersonSetRow {
    # PURE. Is a stored row in the person-set form (it carries the marker)?
    param([AllowNull()][object]$Stored)
    $t = ConvertTo-PimSettingTree -Value $Stored -Top
    return [bool](($t -is [System.Collections.IDictionary]) -and $t.Contains('defaultsModel') -and "$($t['defaultsModel'])" -eq 'person-set-1')
}

function Resolve-PimSettingPersonSet {
    <#
      PURE. What a PERSON set in a stored row, as a tree (never the marker):
        a person-set row (marker)  -> the row as stored;
        an old whole object        -> the migration rule: every defaulted key equal to the FROZEN baseline is dropped;
        nothing / malformed        -> an empty tree.
      MailNotifications: each recipient entry is resolved the same way against the recipient defaults.
    #>
    param([Parameter(Mandatory)][string]$Name, [AllowNull()][object]$Stored)
    $t = ConvertTo-PimSettingTree -Value $Stored -Top
    if (-not ($t -is [System.Collections.IDictionary])) { return [ordered]@{} }
    if (Test-PimSettingPersonSetRow -Stored $t) {
        $o = [ordered]@{}; foreach ($k in @($t.Keys)) { if ("$k" -ne 'defaultsModel') { $o[$k] = $t[$k] } }
        return $o
    }
    $o = Get-PimSettingDelta -Value $t -Default (Get-PimSettingLegacyBaseline -Name $Name) -Prior $null
    if ($Name -eq 'MailNotifications' -and $o.Contains('recipients')) {
        $base = Get-PimSettingLegacyBaseline -Name $Name -Part 'recipient'
        $o['recipients'] = @(foreach ($e in @($o['recipients'])) { if ($e -is [System.Collections.IDictionary]) { , (Get-PimSettingDelta -Value $e -Default $base -Prior $null) } elseif ($null -ne $e) { , $e } })
    }
    return $o
}

function Get-PimSettingEffective {
    # PURE. The value a reader acts on: the product default tree with what a person set laid over it.
    # -Default: the default tree to use (tests; a caller with its own catalog) -- else Get-PimSettingDefaultTree.
    param([Parameter(Mandatory)][string]$Name, [AllowNull()][object]$Stored, [AllowNull()][object]$Default)
    $d = if ($null -ne $Default) { ConvertTo-PimSettingTree -Value $Default } else { Get-PimSettingDefaultTree -Name $Name }
    return (Merge-PimSettingOverDefault -Default $d -PersonSet (Resolve-PimSettingPersonSet -Name $Name -Stored $Stored))
}

function ConvertTo-PimSettingStoredValue {
    <#
      PURE. The row to STORE when a page saves the full -Value: the marker + only what a person set (see the model above).
      -Stored: the row stored before (raw; its person-set part is the -Prior of the delta, and its top-level keys that
      -Value does not carry are kept). -Default / -RecipientDefault: override the default trees (tests).
      MailNotifications: each recipient is stored with its address + only the preferences that are not the default.
    #>
    param([Parameter(Mandatory)][string]$Name, [AllowNull()][object]$Value, [AllowNull()][object]$Stored,
          [AllowNull()][object]$Default, [AllowNull()][object]$RecipientDefault)
    $prior = Resolve-PimSettingPersonSet -Name $Name -Stored $Stored
    $v = ConvertTo-PimSettingTree -Value $Value -Top:($Value -is [string])
    if (-not ($v -is [System.Collections.IDictionary])) { $v = [ordered]@{} }
    $d = if ($null -ne $Default) { ConvertTo-PimSettingTree -Value $Default } else { Get-PimSettingDefaultTree -Name $Name }
    $delta = Get-PimSettingDelta -Value $v -Default $d -Prior $prior
    if ($Name -eq 'MailNotifications' -and $delta.Contains('recipients')) {
        $rd = if ($null -ne $RecipientDefault) { ConvertTo-PimSettingTree -Value $RecipientDefault } else { Get-PimMailRecipientDefaults }
        $priorBy = @{}
        foreach ($pe in @($prior['recipients'])) { if ($pe -is [System.Collections.IDictionary] -and "$($pe['address'])".Trim()) { $priorBy["$($pe['address'])".Trim().ToLowerInvariant()] = $pe } }
        $delta['recipients'] = @(foreach ($e in @($delta['recipients'])) {
                if (-not ($e -is [System.Collections.IDictionary])) { continue }
                $key = "$($e['address'])".Trim().ToLowerInvariant()
                , (Get-PimSettingDelta -Value $e -Default $rd -Prior $(if ($priorBy.ContainsKey($key)) { $priorBy[$key] } else { $null }))
            })
    }
    foreach ($k in @($prior.Keys)) { if (-not $v.Contains($k)) { $delta[$k] = $prior[$k] } }
    $out = [ordered]@{}; $out['defaultsModel'] = 'person-set-1'
    foreach ($k in @($delta.Keys)) { $out[$k] = $delta[$k] }
    return $out
}
