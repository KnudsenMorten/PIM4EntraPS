# =============================================================================
# PIM-OperationalPolicy.ps1 -- operational-policy settings (REQUIREMENTS [M7]).
#
# The Settings > Operational policy card: three FLOORS the engine applies on top of
# every policy template it writes to Entra (Groups / Entra roles / Azure roles):
#   * mfaOnActivation         -- ON = every activation the engine writes requires MFA
#                                (or a Conditional Access authentication context)
#   * maxActivationDuration   -- the longest activation the engine lets a template allow
#   * maxEligibilityDuration  -- the longest eligible assignment the engine lets a
#                                template allow (only where the template requires an end)
#
# OPPOL-1 (owner-approved fix 2026-10-09, PIM REQUIREMENTS §100.3): these values used to be
# stored and shown but applied by NOTHING -- "Require MFA on activation" switched off removed no MFA
# and switched on added none. They are now applied through the ONE engine template accessor
# (Get-PimEnginePolicyTemplates, PIM-EngineProviders.ps1), so every policy provider -- with its
# plan, guards (policy mass-change breaker) and apply path -- sees the floored template, and only
# on the objects a definition row names (the engine touches only defined objects).
# A floor only ever TIGHTENS: it never removes MFA a template asks for, never lengthens a duration.
#
# REMOVED (OPPOL-1, no sensible engine meaning): defaultActivationDuration (Entra has no
# "default activation length" in a policy -- the person picks the length up to the maximum; the
# PIM Activator's default is its own managed setting) and the four connectionSanity values
# (sqlTimeoutSeconds / graphTimeoutSeconds / requireSql / requireGraph: no connection probe exists;
# PIM v2 always needs its SQL store and Graph). A stored legacy value of any of them is ignored.
#
# PS 5.1 COMPATIBLE: no ?. / ??, null-guarded property access, IDictionary-vs-PSCustomObject
# dual reads. The functions here hold NO I/O except Get-PimEngineOperationalPolicy (a read of
# the already-hydrated setting).
# =============================================================================

# ISO-8601 duration whitelist the engine policy bodies already speak
# (ConvertTo-PimExpirationRuleBodies emits PnD / PTnH).
$script:PimActivationDurationCatalog = @('PT1H','PT2H','PT4H','PT8H','PT12H','P1D','P2D','P3D')
$script:PimMaxEligibilityCatalog     = @('P30D','P90D','P180D','P365D')

function Get-PimOperationalPolicyDefaults {
    # The shipped defaults. Each one equals what Entra allows at most anyway (24 h activation, 365 days
    # eligibility), so on upgrade the floors change no shipped template; MFA is on in every shipped template.
    return [ordered]@{
        expiry = [ordered]@{
            maxActivationDuration  = 'P1D'    # hard ceiling an activation may request
            maxEligibilityDuration = 'P365D'  # ceiling for an eligible assignment (template requires an end)
        }
        mfaOnActivation = $true               # require MFA when activating (secure default)
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
    # Take a raw stored object (any shape, possibly partial / null / a legacy value carrying the removed
    # keys) and return a fully-populated, validated policy. Unknown values fall back to the default for
    # that field -- never silently propagate garbage. Returns @{ value=<ordered>; warnings=<string[]> }.
    param([object]$Raw)

    $def = Get-PimOperationalPolicyDefaults
    $warnings = New-Object System.Collections.Generic.List[string]

    $raw = $Raw
    if ($raw -is [string]) {
        $s = "$raw".Trim()
        if ($s) { try { $raw = $s | ConvertFrom-Json } catch { $raw = $null } } else { $raw = $null }
    }

    $expiryRaw = Get-PimOperationalPolicyValue -Object $raw -Key 'expiry'
    $maxAct = "$($def.expiry.maxActivationDuration)"
    $maxElig = "$($def.expiry.maxEligibilityDuration)"
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

    $mfaRaw = Get-PimOperationalPolicyValue -Object $raw -Key 'mfaOnActivation'
    $mfa = [bool]$def.mfaOnActivation
    if ($null -ne $mfaRaw) {
        if ($mfaRaw -is [string]) { $mfa = ("$mfaRaw".Trim() -match '^(?i)(true|1|yes|on)$') } else { $mfa = [bool]$mfaRaw }
    }

    $value = [ordered]@{
        expiry = [ordered]@{
            maxActivationDuration  = $maxAct
            maxEligibilityDuration = $maxElig
        }
        mfaOnActivation = $mfa
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

function Get-PimEngineOperationalPolicy {
    <#
      The normalized operational policy for an ENGINE process: $global:PIM_OperationalPolicy (test seam / a host that
      already knows), else the hydrated pim.Settings['OperationalPolicy'] ($global:PIM_NamingConventions -- the engine,
      scheduler and Manager all hydrate every setting there), else Get-PimSetting. Nothing stored = the shipped defaults.
    #>
    $raw = $null
    if ($null -ne $global:PIM_OperationalPolicy) { $raw = $global:PIM_OperationalPolicy }
    elseif ($global:PIM_NamingConventions -is [System.Collections.IDictionary] -and $global:PIM_NamingConventions.Contains('OperationalPolicy')) { $raw = $global:PIM_NamingConventions['OperationalPolicy'] }
    elseif (Get-Command Get-PimSetting -ErrorAction SilentlyContinue) { try { $raw = Get-PimSetting -Name 'OperationalPolicy' } catch { $raw = $null } }
    return (ConvertTo-PimNormalizedOperationalPolicy -Raw $raw).value
}

function ConvertTo-PimOpPolicyMap {
    # PURE. One level of an object / dictionary -> a NEW hashtable (never the caller's object: the template cache
    # holds the raw store objects, and a floor must not leak into the next read).
    param([AllowNull()][object]$Value)
    $h = @{}
    if ($null -eq $Value) { return $h }
    if ($Value -is [System.Collections.IDictionary]) { foreach ($k in @($Value.Keys)) { $h["$k"] = $Value[$k] } }
    else { foreach ($p in $Value.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    return $h
}

function Get-PimOpPolicyFlooredExpiration {
    # PURE. The template's Expiration with the activation / eligibility ceilings applied. Returns @{ value; changes }.
    param([AllowNull()][object]$Expiration, [string]$MaxActivation, [string]$MaxEligibility)
    $changes = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Expiration) { return @{ value = $null; changes = @() } }
    $capAct = ConvertTo-PimDurationMinutes $MaxActivation
    $capElig = ConvertTo-PimDurationMinutes $MaxEligibility
    if ($Expiration -is [string]) {
        $m = ConvertTo-PimDurationMinutes $Expiration
        if ($capAct -gt 0 -and $m -gt $capAct) { $changes.Add("activation at most $Expiration -> $MaxActivation"); return @{ value = $MaxActivation; changes = @($changes.ToArray()) } }
        return @{ value = $Expiration; changes = @() }
    }
    $out = ConvertTo-PimOpPolicyMap -Value $Expiration
    foreach ($t in @(@{ key = 'EndUser_Assignment'; cap = $capAct; capText = $MaxActivation; what = 'activation at most'; onlyRequired = $false },
                     @{ key = 'Admin_Eligibility'; cap = $capElig; capText = $MaxEligibility; what = 'eligibility at most'; onlyRequired = $true })) {
        if (-not $out.ContainsKey($t.key) -or $null -eq $out[$t.key]) { continue }
        $val = $out[$t.key]
        $dur = ''; $req = $true; $isText = $false
        if ($val -is [string]) { $dur = "$val"; $isText = $true }
        else {
            $dur = "$(Get-PimOperationalPolicyValue -Object $val -Key 'maximumDuration')"
            $r = Get-PimOperationalPolicyValue -Object $val -Key 'isExpirationRequired'
            if ($null -ne $r) { $req = [bool]$r }
        }
        if ($t.onlyRequired -and -not $req) { continue }      # a template that allows a permanent eligibility keeps it
        $m = ConvertTo-PimDurationMinutes $dur
        if ($t.cap -le 0 -or $m -le $t.cap) { continue }
        $changes.Add(("{0} {1} -> {2}" -f $t.what, $dur, $t.capText))
        if ($isText) { $out[$t.key] = $t.capText }
        else { $nv = ConvertTo-PimOpPolicyMap -Value $val; $nv['maximumDuration'] = $t.capText; $nv['isExpirationRequired'] = $req; $out[$t.key] = $nv }
    }
    return @{ value = $out; changes = @($changes.ToArray()) }
}

function Test-PimOpPolicyAuthContextOn {
    # PURE. Does this rule block ask for a Conditional Access authentication context on activation? (Then the MFA floor is
    # met: an authentication context is the stronger check, and Entra does not take MFA and a context together.)
    param([System.Collections.IDictionary]$Block, [string[]]$ActivationChecks = @())
    if (@($ActivationChecks) -contains 'AuthenticationContext') { return $true }
    foreach ($k in @('AuthenticationContext', 'AuthenticationContext_EndUser_Assignment')) {
        if (-not $Block.Contains($k) -or $null -eq $Block[$k]) { continue }
        $on = Get-PimOperationalPolicyValue -Object $Block[$k] -Key 'isEnabled'
        if ($null -eq $on -or [bool]$on) { return $true }
    }
    return $false
}

function Get-PimOpPolicyFlooredBlock {
    # PURE. One rule block (the template's rules, or its Owner block) with the floors applied. Returns @{ block; changes; notes }.
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Block, [Parameter(Mandatory)][object]$Policy)
    $b = @{}; foreach ($k in @($Block.Keys)) { $b["$k"] = $Block[$k] }
    $changes = New-Object System.Collections.Generic.List[string]; $notes = New-Object System.Collections.Generic.List[string]
    $exp = Get-PimOperationalPolicyValue -Object $Policy -Key 'expiry'
    if ($b.ContainsKey('Expiration') -and $null -ne $b['Expiration']) {
        $fe = Get-PimOpPolicyFlooredExpiration -Expiration $b['Expiration'] -MaxActivation "$(Get-PimOperationalPolicyValue -Object $exp -Key 'maxActivationDuration')" -MaxEligibility "$(Get-PimOperationalPolicyValue -Object $exp -Key 'maxEligibilityDuration')"
        if (@($fe.changes).Count) { $b['Expiration'] = $fe.value; foreach ($c in $fe.changes) { $changes.Add($c) } }
    }
    $mfaOn = [bool](Get-PimOperationalPolicyValue -Object $Policy -Key 'mfaOnActivation')
    if ($mfaOn) {
        $hasStructured = ($b.ContainsKey('Enablement') -and $null -ne $b['Enablement'])
        $en = if ($hasStructured) { ConvertTo-PimOpPolicyMap -Value $b['Enablement'] } else { @{} }
        if ($hasStructured -and $en.ContainsKey('EndUser_Assignment')) {
            $list = @(@($en['EndUser_Assignment']) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
            if ($list -notcontains 'MultiFactorAuthentication' -and -not (Test-PimOpPolicyAuthContextOn -Block $b -ActivationChecks $list)) {
                $en['EndUser_Assignment'] = @($list + 'MultiFactorAuthentication')
                $b['Enablement'] = $en
                $changes.Add('MFA added to the activation checks')
            }
        } elseif (-not $hasStructured -and $b.ContainsKey('Member_Enablement_EndUser_Assignment_enabledRules') -and $null -ne $b['Member_Enablement_EndUser_Assignment_enabledRules']) {
            $list = @(@($b['Member_Enablement_EndUser_Assignment_enabledRules']) | Where-Object { "$_".Trim() } | ForEach-Object { "$_".Trim() })
            if ($list -notcontains 'MultiFactorAuthentication' -and -not (Test-PimOpPolicyAuthContextOn -Block $b -ActivationChecks $list)) {
                $b['Member_Enablement_EndUser_Assignment_enabledRules'] = @($list + 'MultiFactorAuthentication')
                $changes.Add('MFA added to the activation checks')
            }
        } else {
            # The template does not set the activation checks at all, so the engine does not manage them on that policy
            # (writing MFA alone would REMOVE a justification Entra may have) -- said, never silently skipped.
            $notes.Add('sets no activation checks, so MFA on activation is not managed on its policies (set the activation checks in the template)')
        }
    }
    return @{ block = $b; changes = @($changes.ToArray()); notes = @($notes.ToArray()) }
}

function ConvertTo-PimOperationalFloorRules {
    <#
      PURE. A template's merged rules (hashtable: Expiration / Enablement / legacy key / Owner / ...) with the operational
      floors applied to the MEMBER block and to the Owner block. Returns @{ rules = <new hashtable>; changes; notes }.
      The input is never modified. Every change names what it did, so the engine log says why a policy differs from the
      template text.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Rules, [Parameter(Mandatory)][object]$Policy)
    $r = Get-PimOpPolicyFlooredBlock -Block $Rules -Policy $Policy
    $out = $r.block
    $changes = New-Object System.Collections.Generic.List[string]; foreach ($c in $r.changes) { $changes.Add($c) }
    $notes = New-Object System.Collections.Generic.List[string]; foreach ($n in $r.notes) { $notes.Add($n) }
    if ($out.ContainsKey('Owner') -and $null -ne $out['Owner']) {
        $ob = ConvertTo-PimOpPolicyMap -Value $out['Owner']
        $ro = Get-PimOpPolicyFlooredBlock -Block $ob -Policy $Policy
        if (@($ro.changes).Count) { $out['Owner'] = $ro.block; foreach ($c in $ro.changes) { $changes.Add("owner: $c") } }
    }
    return @{ rules = $out; changes = @($changes.ToArray()); notes = @($notes.ToArray()) }
}
