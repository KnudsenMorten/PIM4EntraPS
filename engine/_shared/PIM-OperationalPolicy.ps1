# =============================================================================
# PIM-OperationalPolicy.ps1 -- operational-policy settings (REQUIREMENTS [M7]).
#
# PURE normalize / validate / default helpers for the Settings config surface
# that did NOT exist before: expiry-policy defaults, the MFA-on-activation
# toggle, and the connection-sanity config. (Notification / alert config is a
# SEPARATE, already-shipped surface -- see Get-/Set-PimAlertingConfig in
# tools/pim-manager/Open-PimManager.ps1; do NOT duplicate it here.)
#
# These functions hold NO I/O: they take a raw stored value (from pim.Settings
# / the manager-settings file -- whatever the SINGLE store handed back) and
# return a normalized, clamped, default-applied object, plus a validator that
# rejects bad input instead of silently dropping it. The Manager's
# Get-/Set-PimOperationalPolicy wrappers do the persistence through the SAME
# Get-/Set-PimManagerSetting store the engine + jobs read, so a GUI edit and a
# runtime read see one identical value.
#
# PS 5.1 COMPATIBLE: no ?. / ??, no RSA.ImportFromPem, null-guarded property
# access (no $null.Prop NRE), IDictionary-vs-PSCustomObject dual reads (a value
# round-tripped in-process is a hashtable; one round-tripped through JSON is a
# PSCustomObject -- PSObject.Properties does NOT see dictionary keys).
# =============================================================================

# ISO-8601 duration whitelist the engine policy bodies already speak
# (ConvertTo-PimExpirationRuleBodies emits PnD / PTnH). Keep this list aligned
# with what the PIM activation-policy surface actually accepts.
$script:PimActivationDurationCatalog = @('PT1H','PT2H','PT4H','PT8H','PT12H','P1D','P2D','P3D')
$script:PimMaxEligibilityCatalog     = @('P30D','P90D','P180D','P365D')

function Get-PimOperationalPolicyDefaults {
    # The shipped, NON-per-tenant-infra defaults. (No SMTP host / domain / port
    # here -- those are customer-env and belong in custom config, never a shipped
    # default. Connection-sanity defaults are generic timeouts only.)
    return [ordered]@{
        expiry = [ordered]@{
            defaultActivationDuration = 'PT8H'   # default time-bound activation length
            maxActivationDuration     = 'P1D'    # hard ceiling an activation may request
            maxEligibilityDuration    = 'P365D'  # ceiling for an eligible assignment
        }
        mfaOnActivation = $true                  # require MFA when activating (secure default)
        connectionSanity = [ordered]@{
            sqlTimeoutSeconds   = 15             # SQL connectivity probe timeout
            graphTimeoutSeconds = 30             # Graph/tenant connectivity probe timeout
            requireSql          = $true          # a failed SQL probe is a hard failure
            requireGraph        = $true          # a failed Graph probe is a hard failure
        }
    }
}

function Get-PimOperationalPolicyValue {
    # Null-safe property read across hashtable / IDictionary / PSCustomObject.
    param([object]$Object, [Parameter(Mandatory)][string]$Key)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Key)) { return $Object[$Key] }
        return $null
    }
    $p = $Object.PSObject.Properties[$Key]
    if ($p) { return $p.Value }
    return $null
}

function Test-PimActivationDuration {
    param([string]$Value)
    return (@($script:PimActivationDurationCatalog) -contains "$Value")
}

function Test-PimEligibilityDuration {
    param([string]$Value)
    return (@($script:PimMaxEligibilityCatalog) -contains "$Value")
}

function Get-PimActivationDurationCatalog { return @($script:PimActivationDurationCatalog) }
function Get-PimEligibilityDurationCatalog { return @($script:PimMaxEligibilityCatalog) }

function ConvertTo-PimNormalizedOperationalPolicy {
    # Take a raw stored object (any shape, possibly partial / null) and return a
    # fully-populated, validated, CLAMPED policy. Out-of-range / unknown values
    # fall back to the default for that field -- never silently propagate garbage.
    # Returns @{ value=<ordered>; warnings=<string[]> }.
    param([object]$Raw)

    $def = Get-PimOperationalPolicyDefaults
    $warnings = New-Object System.Collections.Generic.List[string]

    $raw = $Raw
    if ($raw -is [string]) {
        $s = "$raw".Trim()
        if ($s) { try { $raw = $s | ConvertFrom-Json } catch { $raw = $null } } else { $raw = $null }
    }

    # ---- expiry ----------------------------------------------------------
    $expiryRaw = Get-PimOperationalPolicyValue -Object $raw -Key 'expiry'
    $defAct = "$($def.expiry.defaultActivationDuration)"
    $maxAct = "$($def.expiry.maxActivationDuration)"
    $maxElig = "$($def.expiry.maxEligibilityDuration)"

    $vDefAct = "$([string](Get-PimOperationalPolicyValue -Object $expiryRaw -Key 'defaultActivationDuration'))".Trim()
    if ($vDefAct) {
        if (Test-PimActivationDuration $vDefAct) { $defAct = $vDefAct }
        else { $warnings.Add("defaultActivationDuration '$vDefAct' is not an allowed value; kept default $defAct.") }
    }
    $vMaxAct = "$([string](Get-PimOperationalPolicyValue -Object $expiryRaw -Key 'maxActivationDuration'))".Trim()
    if ($vMaxAct) {
        if (Test-PimActivationDuration $vMaxAct) { $maxAct = $vMaxAct }
        else { $warnings.Add("maxActivationDuration '$vMaxAct' is not an allowed value; kept default $maxAct.") }
    }
    $vMaxElig = "$([string](Get-PimOperationalPolicyValue -Object $expiryRaw -Key 'maxEligibilityDuration'))".Trim()
    if ($vMaxElig) {
        if (Test-PimEligibilityDuration $vMaxElig) { $maxElig = $vMaxElig }
        else { $warnings.Add("maxEligibilityDuration '$vMaxElig' is not an allowed value; kept default $maxElig.") }
    }

    # The default activation duration must never exceed the max activation
    # duration; clamp it down (a config-time invariant the engine relies on).
    $defMinutes = ConvertTo-PimDurationMinutes $defAct
    $maxMinutes = ConvertTo-PimDurationMinutes $maxAct
    if ($defMinutes -gt $maxMinutes) {
        $warnings.Add("defaultActivationDuration ($defAct) exceeds maxActivationDuration ($maxAct); clamped to $maxAct.")
        $defAct = $maxAct
    }

    # ---- mfaOnActivation -------------------------------------------------
    $mfaRaw = Get-PimOperationalPolicyValue -Object $raw -Key 'mfaOnActivation'
    $mfa = [bool]$def.mfaOnActivation
    if ($null -ne $mfaRaw) { $mfa = [bool]$mfaRaw }

    # ---- connectionSanity ------------------------------------------------
    $csRaw = Get-PimOperationalPolicyValue -Object $raw -Key 'connectionSanity'
    $sqlTo   = [int]$def.connectionSanity.sqlTimeoutSeconds
    $graphTo = [int]$def.connectionSanity.graphTimeoutSeconds
    $reqSql   = [bool]$def.connectionSanity.requireSql
    $reqGraph = [bool]$def.connectionSanity.requireGraph

    $vSqlTo = Get-PimOperationalPolicyValue -Object $csRaw -Key 'sqlTimeoutSeconds'
    if ($null -ne $vSqlTo -and "$vSqlTo".Trim()) {
        $n = 0
        if ([int]::TryParse("$vSqlTo", [ref]$n)) {
            if ($n -ge 1 -and $n -le 300) { $sqlTo = $n }
            else { $warnings.Add("sqlTimeoutSeconds '$vSqlTo' out of range 1-300; clamped."); $sqlTo = [Math]::Max(1, [Math]::Min(300, $n)) }
        } else { $warnings.Add("sqlTimeoutSeconds '$vSqlTo' is not a number; kept default $sqlTo.") }
    }
    $vGraphTo = Get-PimOperationalPolicyValue -Object $csRaw -Key 'graphTimeoutSeconds'
    if ($null -ne $vGraphTo -and "$vGraphTo".Trim()) {
        $n = 0
        if ([int]::TryParse("$vGraphTo", [ref]$n)) {
            if ($n -ge 1 -and $n -le 300) { $graphTo = $n }
            else { $warnings.Add("graphTimeoutSeconds '$vGraphTo' out of range 1-300; clamped."); $graphTo = [Math]::Max(1, [Math]::Min(300, $n)) }
        } else { $warnings.Add("graphTimeoutSeconds '$vGraphTo' is not a number; kept default $graphTo.") }
    }
    $vReqSql = Get-PimOperationalPolicyValue -Object $csRaw -Key 'requireSql'
    if ($null -ne $vReqSql) { $reqSql = [bool]$vReqSql }
    $vReqGraph = Get-PimOperationalPolicyValue -Object $csRaw -Key 'requireGraph'
    if ($null -ne $vReqGraph) { $reqGraph = [bool]$vReqGraph }

    $value = [ordered]@{
        expiry = [ordered]@{
            defaultActivationDuration = $defAct
            maxActivationDuration     = $maxAct
            maxEligibilityDuration    = $maxElig
        }
        mfaOnActivation = $mfa
        connectionSanity = [ordered]@{
            sqlTimeoutSeconds   = $sqlTo
            graphTimeoutSeconds = $graphTo
            requireSql          = $reqSql
            requireGraph        = $reqGraph
        }
    }
    return @{ value = $value; warnings = @($warnings.ToArray()) }
}

function ConvertTo-PimDurationMinutes {
    # ISO-8601 duration (subset: PnD / PTnH / PTnM) -> minutes. Pure, locale-safe.
    # Returns 0 for an unparseable value (callers compare with defaults).
    param([string]$Iso)
    $s = "$Iso".Trim().ToUpperInvariant()
    if (-not $s -or $s[0] -ne 'P') { return 0 }
    $minutes = 0
    # Split date part vs time part on 'T'.
    $datePart = $s.Substring(1)
    $timePart = ''
    $tIdx = $datePart.IndexOf('T')
    if ($tIdx -ge 0) {
        $timePart = $datePart.Substring($tIdx + 1)
        $datePart = $datePart.Substring(0, $tIdx)
    }
    if ($datePart -match '(\d+)D') { $minutes += [int]$Matches[1] * 24 * 60 }
    if ($timePart -match '(\d+)H') { $minutes += [int]$Matches[1] * 60 }
    if ($timePart -match '(\d+)M') { $minutes += [int]$Matches[1] }
    return $minutes
}
