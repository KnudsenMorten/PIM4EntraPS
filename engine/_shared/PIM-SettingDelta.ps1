#Requires -Version 5.1
<#
  PIM-SettingDelta.ps1 -- PIM REQUIREMENTS OPEN-19, framework section 12.16 CONVERGE-DEFAULTS (a changed install default reaches
  EXISTING installs the customer did not change).

  THE GAP (Invardia 2026-11, verified in code 2026-11-06): a Manager settings PAGE posts every field of its form, and the
  save wrote the WHOLE object -- the fields the customer changed AND every untouched field at its then-current default
  (OperationalPolicy: Set-PimOperationalPolicy stored the fully normalised policy; PendingReminders: the PUT filled every
  hour field from the effective config; AutoExtendPolicy: leadDays + defaultOn always). The readers already merge a
  stored field over its shipped default field by field (ConvertTo-PimNormalizedOperationalPolicy,
  ConvertTo-PimPendingReminderConfig, ConvertTo-PimAutoExtendPolicy), so the frozen copy of a default was the only thing
  keeping a later default change from reaching that install.

  THE FIX: a page save stores only the fields whose value DIFFERS from the shipped default (Get-PimSettingCustomerDelta).
  A field equal to the default is not written, so the reader falls back to the default -- today's value, and tomorrow's
  if the default changes. Fields with no default (who saved, when) are always kept. Nothing at an install is rewritten
  by this change: a stored row is cleaned the next time its page is saved.

  PURE, PS 5.1 compatible (no ?. / ??), IDictionary and PSCustomObject both read.
#>

function Get-PimSettingDeltaField {
    # PURE. Null-safe property read across IDictionary / PSCustomObject; @{ has; value }.
    param([AllowNull()][object]$Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object -or $Object -is [string] -or $Object -is [ValueType]) { return @{ has = $false; value = $null } }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return @{ has = $true; value = $Object[$Name] } }
        return @{ has = $false; value = $null }
    }
    $p = $Object.PSObject.Properties[$Name]
    if ($p) { return @{ has = $true; value = $p.Value } }
    return @{ has = $false; value = $null }
}

function Test-PimSettingDeltaIsMap {
    # PURE. A dictionary or a PSCustomObject (a nested settings group), not a scalar or a list.
    param([AllowNull()][object]$Value)
    return ($Value -is [System.Collections.IDictionary] -or $Value -is [System.Management.Automation.PSCustomObject])
}

function Get-PimSettingDeltaNames {
    # PURE. The field names of a map, in order.
    param([AllowNull()][object]$Value)
    if ($Value -is [System.Collections.IDictionary]) { return @($Value.Keys | ForEach-Object { "$_" }) }
    if ($Value -is [System.Management.Automation.PSCustomObject]) { return @($Value.PSObject.Properties | ForEach-Object { $_.Name }) }
    return @()
}

function Test-PimSettingValueEqual {
    # PURE. Two stored values are the same: compared as their compact JSON (so 4 and [long]4, $true and $true, two equal
    # lists, two maps with the same fields in the same order are equal; "4" and 4 are not).
    param([AllowNull()][object]$A, [AllowNull()][object]$B)
    if ($null -eq $A -and $null -eq $B) { return $true }
    if ($null -eq $A -or $null -eq $B) { return $false }
    $ja = ConvertTo-Json -InputObject $A -Compress -Depth 20
    $jb = ConvertTo-Json -InputObject $B -Compress -Depth 20
    return ($ja -ceq $jb)
}

function Get-PimSettingCustomerDelta {
    <#
      PURE. OPEN-19: the part of a settings object a page save STORES -- only the customer's own values.
        -Value     the object the page would store (every field of the form)
        -Defaults  the SHIPPED defaults of that setting (the same function the reader merges over)
        -Keep      fields always kept whatever their value (e.g. 'by', 'atUtc': who saved it and when)
      A field whose value equals its default is left out; a nested group (a map in both) is compared field by field and
      left out when nothing in it differs; a field the defaults do not know is kept (there is no default to converge to).
      Returns an [ordered] map (empty = every value is the default: the reader gives the defaults).
    #>
    param([AllowNull()][object]$Value, [AllowNull()][object]$Defaults, [string[]]$Keep = @())
    $out = [ordered]@{}
    if (-not (Test-PimSettingDeltaIsMap $Value)) { return $out }
    foreach ($n in @(Get-PimSettingDeltaNames $Value)) {
        $v = (Get-PimSettingDeltaField $Value $n).value
        if ($Keep -contains $n) { $out[$n] = $v; continue }
        $d = Get-PimSettingDeltaField $Defaults $n
        if (-not $d.has) { $out[$n] = $v; continue }
        if ((Test-PimSettingDeltaIsMap $v) -and (Test-PimSettingDeltaIsMap $d.value)) {
            $sub = Get-PimSettingCustomerDelta -Value $v -Defaults $d.value
            if ($sub.Count -gt 0) { $out[$n] = $sub }
            continue
        }
        if (-not (Test-PimSettingValueEqual $v $d.value)) { $out[$n] = $v }
    }
    return $out
}
