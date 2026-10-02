# =====================================================================================================================
# REQ 91.2 / REQ 91.3 (operator 2026-10-02: "It must be possible to define (add/remove) the names of the rings and add/remove rows
# in the gui" / "The dropdown ... with rings must come from the rings defined in settings").
#
# Until now every ring check was hard-coded 0..2. The deployment rings are now DEFINED (pim.Settings['DeploymentRings'] on the
# managing tenant, carried in the signed bundle to managed tenants): rings 0..9 may be defined, and a ring is valid only up to
# the highest DEFINED ring. The reach rule is unchanged -- a row on ring N reaches tenants whose own ring is N or lower.
# 🔒 FAIL CLOSED is unchanged too: a ring above the highest defined one is "not a ring" and reaches NOTHING (with
# "tenant ring <= row ring", a stray 5 would otherwise reach every tenant). Defaults 0 Dev / 1 Test / 2 Broad.
# =====================================================================================================================
# rings 0..9 at most -- written as the LITERAL 9 in every function: a $script: constant is $null when a child script calls
# these functions after a Get-Command load guard skipped the dot-source (memory: script-scope-default-null-in-child)

function Get-PimRingMax {
    # The highest DEFINED ring. $global:PIM_RingMax is set by whoever knows the definitions (the Manager after reading/saving
    # them, the downlink when a bundle carries them); otherwise it is read once from pim.Settings when a reader is loaded.
    $g = $global:PIM_RingMax
    if ($null -eq $g -or "$g" -eq '') {
        $g = 2
        try {
            $raw = $null
            if (Get-Command Get-PimManagerSetting -ErrorAction SilentlyContinue) { $raw = Get-PimManagerSetting -Name 'DeploymentRings' }
            elseif (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { $raw = Get-PimSetting -Name 'DeploymentRings' }
            if ($null -ne $raw) { $m = Get-PimRingMaxFromDefinitions -Value $raw; if ($null -ne $m) { $g = $m } }
        } catch { $g = 2 }
        $global:PIM_RingMax = $g
    }
    $n = 2; if (-not [int]::TryParse("$g", [ref]$n)) { $n = 2 }
    return [math]::Max(0, [math]::Min(9, $n))
}

function Get-PimRingMaxFromDefinitions {
    # The highest ring in a DeploymentRings value ({ rings: [ {ring,...} ], defined } or the bare list, JSON text allowed).
    # A value the ring editor saved carries defined=true and means EXACTLY its rings; any other value (written before REQ 91.2,
    # or a bare list) means at least 0..2 -- so nothing stored before reads differently. $null = nothing usable.
    param([object]$Value)
    $v = $Value
    for ($i = 0; $i -lt 2 -and $v -is [string]; $i++) { if (-not "$v".Trim()) { return $null }; try { $v = $v | ConvertFrom-Json } catch { return $null } }
    if ($null -eq $v) { return $null }
    $explicit = $false
    if ($v -is [System.Collections.IDictionary]) { $explicit = ($v.Contains('defined') -and [bool]$v['defined']) }
    elseif ($v.PSObject.Properties['defined']) { $explicit = [bool]$v.defined }
    $list = if ($v -is [System.Collections.IDictionary] -and $v.Contains('rings')) { @($v['rings']) } elseif ($v -isnot [System.Collections.IDictionary] -and $v.PSObject.Properties['rings']) { @($v.rings) } else { @($v) }
    $max = $null
    foreach ($e in $list) {
        if ($null -eq $e) { continue }
        $r = if ($e -is [System.Collections.IDictionary]) { $e['ring'] } else { $e.ring }
        $n = 0
        if ([int]::TryParse("$r".Trim(), [ref]$n) -and $n -ge 0 -and $n -le 9) { if ($null -eq $max -or $n -gt $max) { $max = $n } }
    }
    if ($null -eq $max) { return $null }
    if (-not $explicit -and $max -lt 2) { return 2 }
    return $max
}

function Set-PimRingMaxFromRings {
    # Record the highest ring of a ConvertTo-PimDeploymentRings list. An EMPTY or unusable list changes NOTHING -- "[int]$null"
    # is 0, and a max of 0 would silently make every ring above 0 "not a ring" for the rest of the process.
    param([object[]]$Rings = @())
    $max = $null
    foreach ($r in @($Rings)) {
        if ($null -eq $r) { continue }
        $v = if ($r -is [System.Collections.IDictionary]) { $r['ring'] } else { $r.ring }
        $n = 0
        if ([int]::TryParse("$v".Trim(), [ref]$n) -and $n -ge 0 -and $n -le 9) { if ($null -eq $max -or $n -gt $max) { $max = $n } }
    }
    if ($null -ne $max) { $global:PIM_RingMax = $max }
}

function Test-PimRingValue {
    # Is $Value a ring (a whole number 0..highest defined ring)? Text '' / 'two' / '5' with rings 0..2 defined = NOT a ring.
    param([object]$Value, [int]$Max = -1)
    $s = "$Value".Trim()
    if ($s -notmatch '^[0-9]$') { return $false }
    $m = if ($Max -ge 0) { $Max } else { Get-PimRingMax }
    return ([int]$s -le $m)
}

function Get-PimRingRangeText {
    # For messages: "0 (dev), 1 (test) or 2 (broad)" with the defaults, "0..4" otherwise.
    $m = Get-PimRingMax
    if ($m -eq 2) { return '0 (dev), 1 (test) or 2 (broad)' }
    return "0..$m (the defined deployment rings)"
}
