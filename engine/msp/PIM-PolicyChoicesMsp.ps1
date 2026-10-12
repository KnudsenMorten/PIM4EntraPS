#Requires -Version 5.1
<#
  PIM Manager -- PIM 100.93 POLICY CHOICES ACROSS TENANTS (the MSP part).

  Owner decision (2026-10-12): "MSP default, tenant may override" -- the MANAGING tenant's policy choices are the default
  in a MANAGED tenant; a managed tenant's SuperAdmin can choose single settings itself; a later pull never overwrites
  those local choices. And: "super admin per tenant must approve mass changes. never me as dev".

  WHAT TRAVELS (the artifact 'policyChoices' inside the signed bundle the managed tenant PULLS -- no second transport, no
  secret; class capability 'msp-policies', which the customer can block in its own manifest like the other msp-* classes):
    * the managing tenant's OWN choices per policy type and setting: the choice (microsoft | recommendation | keep), the
      advisory number it was made on, whether the managing tenant itself still stands on that number ('current'), when;
    * an override for a single object ONLY where the object key means the same thing in a managed tenant:
        directoryRole   always (the key is the role's name; built-in roles are named the same in every tenant)
        groupMember /
        groupOwner      only for a group whose definition is in the same bundle (the key is the group's name), and each
                        managed tenant keeps it only for the groups it actually takes from the managing tenant
        azureRole       NEVER (the key holds the managing tenant's own Azure scope, which does not exist elsewhere)
    * 'basis': per setting, what the managing tenant's advisory number rests on (Get-PimPolicyFieldAdvisoryBasis).
  WHAT NEVER TRAVELS: who chose (a person of the managing tenant), a policy VALUE (the managed tenant works out Microsoft's
  default and the recommendation from its own shipped files and its own templates), a change set, a hold, an APPROVAL.

  THE PULL replaces pim.Settings['PolicyChoices'].managingTenant and nothing else: local `types` / `overrides` are written
  back as they were read (compare-and-swap on the stored text, so a choice saved in the Manager at the same moment is not
  lost). A bundle WITHOUT the artifact (an older managing tenant) leaves the block as it is. A blocked class empties it.

  ADVISORY SAFETY. An advisory number counts the changes ONE tenant has seen, so the managing tenant's number cannot be
  compared with the managed tenant's as it is. A pulled choice is therefore stored as CURRENT (this tenant's own current
  number) only when (a) the managing tenant itself still stands on it and (b) what its number rests on equals what this
  tenant's number rests on, for every template both know. Everything else is stored on number 0 = "asked again": the
  resolver then freezes the setting exactly like a local choice on an older number -- nothing is written for it.

  THE GUARD is untouched and knows nothing of where a choice came from: every change set is held until a SuperAdmin of
  THIS tenant approves its plan hash in THIS tenant's own store (Test-PimPolicyBreaker). Nothing here writes an approval.

  PS 5.1 and pwsh 7; ASCII only (no BOM).
#>

if ($PSScriptRoot) {
    # FILE scope, not inside a function: a dot-source inside a function vanishes when it returns.
    if (-not (Get-Command ConvertTo-PimPolicyChoicesStore -ErrorAction SilentlyContinue)) {
        $__pcLib = Join-Path $PSScriptRoot '..\_shared\PIM-PolicyChoices.ps1'
        if (Test-Path -LiteralPath $__pcLib) { . $__pcLib }
    }
}

function Get-PimPolicyChoicesArtifactName { 'policyChoices' }       # the key in the signed bundle's payload
function Get-PimPolicyChoicesCapabilityName { 'msp-policies' }      # the class capability a customer can block
function Get-PimPolicyChoicesArtifactSchema { 1 }

function Test-PimPolicyChoiceOverrideTravels {
    <# PURE. May an override stored under '<type>|<object key>' go to / be kept in a managed tenant? @{ travels; reason }.
       -GroupNames = the group names the override may be about (publish: the groups defined in the bundle; pull: the
       groups THIS tenant takes from the managing tenant). #>
    param([string]$Key, [AllowEmptyCollection()][string[]]$GroupNames = @())
    $k = "$Key"; $i = $k.IndexOf('|')
    if ($i -lt 1) { return @{ travels = $false; reason = "it has no '<policy type>|<object>' key" } }
    $t = $k.Substring(0, $i); $obj = $k.Substring($i + 1).Trim().ToLowerInvariant()
    if (-not $obj) { return @{ travels = $false; reason = 'it names no object' } }
    switch ($t) {
        'directoryRole' { return @{ travels = $true; reason = '' } }
        'azureRole'     { return @{ travels = $false; reason = 'an Azure scope of the managing tenant does not exist in a managed tenant' } }
        { $_ -in 'groupMember', 'groupOwner' } {
            foreach ($g in @($GroupNames)) { if ("$g".Trim().ToLowerInvariant() -eq $obj) { return @{ travels = $true; reason = '' } } }
            return @{ travels = $false; reason = 'the group is not one the managing tenant sends' }
        }
    }
    return @{ travels = $false; reason = "'$t' is not a policy type" }
}

function Test-PimPolicyAdvisoryBasisMatch {
    <# PURE. Does the managing tenant's advisory number for a setting rest on the same shipped values as this tenant's?
       Both sides are Get-PimPolicyFieldAdvisoryBasis maps. TRUE only when both have something, they share at least one
       key, and every key BOTH know carries the same hash. A template only one side knows is left out: the first sight of
       a template never asks anybody again (the same rule as Update-PimPolicyAdvisories). Unknown on either side = FALSE
       = "asked again" -- never a guess. #>
    param([AllowNull()][object]$Theirs, [AllowNull()][object]$Mine)
    $tn = @(Get-PimPcNames $Theirs); $mn = @(Get-PimPcNames $Mine)
    if (-not $tn.Count -or -not $mn.Count) { return $false }
    $common = 0
    foreach ($k in $mn) {
        $tk = @($tn | Where-Object { "$_" -ieq "$k" } | Select-Object -First 1)
        if (-not $tk.Count) { continue }
        $common++
        if ("$(Get-PimPcProp $Theirs $tk[0])".Trim() -cne "$(Get-PimPcProp $Mine $k)".Trim()) { return $false }
    }
    return [bool]($common -gt 0)
}

# ---------------------------------------------------------------------------------------------------------------------
# PUBLISH (the managing tenant)
# ---------------------------------------------------------------------------------------------------------------------
function New-PimPolicyChoicesBundleSet {
    <#
      PURE. The managing tenant's stored PolicyChoices -> what goes into the signed bundle.
        -Choices     pim.Settings['PolicyChoices'] as stored (JSON text / object). Only its LOCAL `types` / `overrides` are
                     read: a block this tenant itself pulled from somebody else is never passed on.
        -Advisories  pim.Settings['PolicyAdvisories'] as stored (may be empty: every choice then travels without a basis,
                     and a managed tenant asks again rather than guess).
        -GroupNames  the names of the groups defined in the same bundle.
      Returns @{ set = [ordered]@{ schema; types; overrides; basis }; settings; notPublished = @( @{ key; reason } ) }.
      No choices = an EMPTY set (types {} / overrides {}): "the managing tenant gives no default", never "delete".
      Deterministic: policy types and settings in catalog order, override keys in ordinal order.
    #>
    param([AllowNull()][object]$Choices, [AllowNull()][object]$Advisories, [AllowEmptyCollection()][string[]]$GroupNames = @())
    $store = ConvertTo-PimPolicyChoicesStore -Value $Choices
    $types = [ordered]@{}; $overrides = [ordered]@{}; $basis = [ordered]@{}
    $notPublished = New-Object System.Collections.Generic.List[object]
    $count = 0
    $entryOf = {
        param($t, $fid, $e)
        $cur = Get-PimPolicyFieldAdvisory -Advisories $Advisories -Type $t -FieldId $fid
        [ordered]@{ choice = "$($e.choice)"; advisory = [int]$e.advisory; current = [bool]([int]$e.advisory -ge [int]$cur); utc = "$($e.utc)" }
    }
    $noteBasis = {
        param($t, $fid)
        if (-not $basis.Contains($t)) { $basis[$t] = [ordered]@{} }
        if (-not $basis[$t].Contains($fid)) { $basis[$t][$fid] = (Get-PimPolicyFieldAdvisoryBasis -Advisories $Advisories -Type $t -FieldId $fid) }
    }
    foreach ($t in @(Get-PimPolicyChoiceTypes)) {
        if (-not $store.types.ContainsKey($t)) { continue }
        $o = [ordered]@{}
        foreach ($fd in @(Get-PimPolicyFieldsForType -Type $t)) {
            $e = $store.types[$t]["$($fd.id)"]; if ($null -eq $e) { continue }
            $o["$($fd.id)"] = (& $entryOf $t "$($fd.id)" $e); & $noteBasis $t "$($fd.id)"; $count++
        }
        if ($o.Count) { $types[$t] = $o }
    }
    $keys = [string[]]@($store.overrides.Keys | ForEach-Object { "$_" }); [Array]::Sort($keys, [StringComparer]::Ordinal)
    foreach ($k in $keys) {
        $v = Test-PimPolicyChoiceOverrideTravels -Key $k -GroupNames $GroupNames
        if (-not $v.travels) { $notPublished.Add([ordered]@{ key = $k; reason = "$($v.reason)" }); continue }
        $t = $k.Substring(0, $k.IndexOf('|'))
        $o = [ordered]@{}
        foreach ($fd in @(Get-PimPolicyFieldsForType -Type $t)) {
            $e = $store.overrides[$k]["$($fd.id)"]; if ($null -eq $e) { continue }
            $o["$($fd.id)"] = (& $entryOf $t "$($fd.id)" $e); & $noteBasis $t "$($fd.id)"; $count++
        }
        if ($o.Count) { $overrides[$k] = $o }
    }
    @{ set = [ordered]@{ schema = (Get-PimPolicyChoicesArtifactSchema); types = $types; overrides = $overrides; basis = $basis }
       settings = $count; notPublished = @($notPublished.ToArray()) }
}

# ---------------------------------------------------------------------------------------------------------------------
# PULL (the managed tenant)
# ---------------------------------------------------------------------------------------------------------------------
function ConvertTo-PimManagingTenantPolicyChoices {
    <#
      PURE. The pulled artifact -> the `managingTenant` block this tenant stores.
        -Set         payload.policyChoices from the VERIFIED bundle
        -Advisories  THIS tenant's pim.Settings['PolicyAdvisories']
        -GroupNames  the groups THIS tenant takes from the managing tenant (an override for any other group is dropped)
      Every entry is translated to this tenant's advisory scale (see ADVISORY SAFETY in the file header) and then goes
      through the library's own validation (ConvertTo-PimPolicyChoicesStore): an unknown policy type, an unknown setting,
      a setting that does not apply to the type and an invalid choice are DROPPED and listed. Only choice / when / advisory
      are taken from an entry -- anything else in it is ignored. 'by' is always the words 'managing tenant'.
      Returns @{ understood; block = @{ types; overrides; receivedUtc }; settings; askedAgain; dropped = @(text) }.
      understood = $false: the artifact is of a shape this version does not know -- the caller leaves the block as it is.
    #>
    param([AllowNull()][object]$Set, [AllowNull()][object]$Advisories, [AllowEmptyCollection()][string[]]$GroupNames = @(), [datetime]$ReceivedUtc = [datetime]::UtcNow)
    $dropped = New-Object System.Collections.Generic.List[string]
    $empty = @{ types = @{}; overrides = @{}; receivedUtc = $ReceivedUtc.ToUniversalTime().ToString('o') }
    $schema = 0; [void][int]::TryParse("$(Get-PimPcProp $Set 'schema')", [ref]$schema)
    if ($null -eq $Set -or $Set -is [string] -or $Set -is [ValueType] -or $schema -ne (Get-PimPolicyChoicesArtifactSchema)) {
        return @{ understood = $false; block = $empty; settings = 0; askedAgain = 0; dropped = @("the policy choices in this bundle have a shape this version does not know (schema '$(Get-PimPcProp $Set 'schema')')") }
    }
    $basisIn = Get-PimPcProp $Set 'basis'
    $translate = {
        param($t, $fid, $e)
        $cur = Get-PimPolicyFieldAdvisory -Advisories $Advisories -Type $t -FieldId $fid
        $flag = Get-PimPcProp $e 'current'
        $fresh = $false
        if ($flag -is [bool] -and $flag) {
            $fresh = Test-PimPolicyAdvisoryBasisMatch -Theirs (Get-PimPcProp (Get-PimPcProp $basisIn $t) $fid) -Mine (Get-PimPolicyFieldAdvisoryBasis -Advisories $Advisories -Type $t -FieldId $fid)
        }
        @{ choice = "$(Get-PimPcProp $e 'choice')"; by = 'managing tenant'; utc = (ConvertTo-PimPcUtcText (Get-PimPcProp $e 'utc')); advisory = $(if ($fresh) { [int]$cur } else { 0 }); source = 'managing-tenant' }
    }
    $cand = @{ types = @{}; overrides = @{} }
    $srcTypes = Get-PimPcProp $Set 'types'
    foreach ($t in @(Get-PimPcNames $srcTypes)) {
        $cand.types["$t"] = @{}
        foreach ($f in @(Get-PimPcNames (Get-PimPcProp $srcTypes $t))) { $cand.types["$t"]["$f"] = (& $translate "$t" "$f" (Get-PimPcProp (Get-PimPcProp $srcTypes $t) $f)) }
    }
    $srcOvr = Get-PimPcProp $Set 'overrides'
    foreach ($k in @(Get-PimPcNames $srcOvr)) {
        $v = Test-PimPolicyChoiceOverrideTravels -Key "$k" -GroupNames $GroupNames
        if (-not $v.travels) { $dropped.Add("managing tenant override '$k': $($v.reason)"); continue }
        $t = "$k".Substring(0, "$k".IndexOf('|'))
        $cand.overrides["$k"] = @{}
        foreach ($f in @(Get-PimPcNames (Get-PimPcProp $srcOvr $k))) { $cand.overrides["$k"]["$f"] = (& $translate $t "$f" (Get-PimPcProp (Get-PimPcProp $srcOvr $k) $f)) }
    }
    $norm = ConvertTo-PimPolicyChoicesStore -Value @{ managingTenant = $cand } -Dropped $dropped
    $block = @{ types = $norm.managingTenant.types; overrides = $norm.managingTenant.overrides; receivedUtc = $ReceivedUtc.ToUniversalTime().ToString('o') }
    $n = 0; $asked = 0
    foreach ($m in @($block.types, $block.overrides)) {
        foreach ($k in @($m.Keys)) { foreach ($f in @($m[$k].Keys)) { $n++; if ([int]$m[$k][$f].advisory -lt 1) { $asked++ } } }
    }
    @{ understood = $true; block = $block; settings = $n; askedAgain = $asked; dropped = @($dropped.ToArray()) }
}

function Compare-PimManagingTenantPolicyChoices {
    <# PURE. Two `managingTenant` blocks -> @{ settings (entries in -After); differ (entries added, taken away, or with
       another choice / another advisory standing than before); changed }. receivedUtc is not compared. #>
    param([AllowNull()][object]$Before, [AllowNull()][object]$After)
    $lines = {
        param($blk)
        $o = @{}
        foreach ($part in 'types', 'overrides') {
            $m = Get-PimPcProp $blk $part
            foreach ($k in @(Get-PimPcNames $m)) {
                $inner = Get-PimPcProp $m $k
                foreach ($f in @(Get-PimPcNames $inner)) {
                    $e = Get-PimPcProp $inner $f
                    $a = 0; [void][int]::TryParse("$(Get-PimPcProp $e 'advisory')", [ref]$a)
                    $o["$part/$k/$f".ToLowerInvariant()] = ("{0}|{1}" -f "$(Get-PimPcProp $e 'choice')", $a)
                }
            }
        }
        $o
    }
    $b = & $lines $Before; $a2 = & $lines $After
    $differ = 0
    foreach ($k in @($a2.Keys)) { if (-not $b.ContainsKey($k) -or "$($b[$k])" -ne "$($a2[$k])") { $differ++ } }
    foreach ($k in @($b.Keys)) { if (-not $a2.ContainsKey($k)) { $differ++ } }
    @{ settings = [int]$a2.Count; differ = [int]$differ; changed = [bool]($differ -gt 0) }
}

function Format-PimManagingTenantPolicyChoiceAuditText {
    # PURE. The one plain sentence the audit list shows for a pull that changed what the managing tenant gives this tenant.
    param([int]$Settings = 0, [int]$Differ = 0, [switch]$Blocked)
    $s = { param($n) if ([int]$n -eq 1) { '' } else { 's' } }
    if ($Blocked) {
        return ("The managing tenant's policy choices are not used in this tenant, because this tenant blocks them: {0} setting{1} taken away" -f $Differ, (& $s $Differ))
    }
    ("The managing tenant's policy choices were updated: {0} setting{1}; {2} now differ{3} from before" -f $Settings, (& $s $Settings), $Differ, $(if ([int]$Differ -eq 1) { 's' } else { '' }))
}

function Get-PimDownlinkPolicyChoicesPlan {
    <#
      PURE. What ONE managed tenant does with the artifact of a VERIFIED bundle (called by Get-PimDownlinkPlan).
        -Payload            the verified payload
        -ClassAllowed       Test-PimDownlinkClassAllowed -Class 'policies' (the customer's own blockCapabilities)
        -ReplicatedGroups   the group definitions THIS tenant takes from the managing tenant ($plan.definitions.create)
      Returns $null when there is nothing to do (no artifact, class not blocked): the stored block is left as it is.
      Otherwise @{ present; held; reason; set; groupNames; settings }:
        held = $true  the customer blocks 'msp-policies' -> this tenant has NO managing-tenant defaults (the block is emptied)
        else          the set replaces the block.
    #>
    param([AllowNull()][object]$Payload, [AllowNull()][object]$ClassAllowed, [AllowNull()][object[]]$ReplicatedGroups)
    $set = Get-PimPcProp $Payload (Get-PimPolicyChoicesArtifactName)
    $present = [bool]($null -ne $set)
    $allowed = $true; $why = ''
    if ($null -ne $ClassAllowed) { $allowed = [bool](Get-PimPcProp $ClassAllowed 'allowed'); $why = "$(Get-PimPcProp $ClassAllowed 'reason')" }
    if (-not $present -and $allowed) { return $null }
    $n = 0
    if ($present) {
        foreach ($part in 'types', 'overrides') { $m = Get-PimPcProp $set $part; foreach ($k in @(Get-PimPcNames $m)) { $n += @(Get-PimPcNames (Get-PimPcProp $m $k)).Count } }
    }
    if (-not $allowed) { return @{ present = $present; held = $true; reason = $why; set = $null; groupNames = @(); settings = $n } }
    $names = @(@($ReplicatedGroups) | Where-Object { $null -ne $_ } | ForEach-Object { "$(Get-PimPcProp $_ 'GroupName')".Trim() } | Where-Object { $_ })
    @{ present = $true; held = $false; reason = ''; set = $set; groupNames = $names; settings = $n }
}

function Invoke-PimDownlinkPolicyChoicesApply {
    <#
      The managed tenant's apply: pim.Settings['PolicyChoices'].managingTenant := what the bundle gives (or empty when the
      customer blocks the class). Local `types` / `overrides` are written back as they were read. Nothing is written when
      nothing differs (so a pull that brings the same choices leaves no trace and receivedUtc stays the time the present
      content first arrived). One plain audit row when it did change. NEVER writes a policy, a hold or an approval.
        -PolicyPlan   Get-PimDownlinkPolicyChoicesPlan's result ($plan.policyChoices); $null = nothing to do
      Seams (tests; defaults use the tenant's own store through -ConnectionString):
        -ReadRaw           { } -> the stored PolicyChoices TEXT (or $null)
        -WriteIfUnchanged  { param($expectedText, $newText) } -> 1 when written, 0 when the stored text changed meanwhile
        -ReadAdvisories    { } -> the stored PolicyAdvisories
        -Audit             { param($action, $target, $before, $after) }
      Returns [pscustomobject]@{ ok; changed; present; held; whatIf; settings; differ; askedAgain; dropped; text; detail }.
    #>
    [CmdletBinding()]
    param(
        [string]$ConnectionString,
        [AllowNull()][object]$PolicyPlan,
        [int64]$BundleVersion = 0,
        [datetime]$NowUtc = [datetime]::UtcNow,
        [switch]$WhatIfMode,
        [scriptblock]$ReadRaw, [scriptblock]$WriteIfUnchanged, [scriptblock]$ReadAdvisories, [scriptblock]$Audit
    )
    $res = [ordered]@{ ok = $true; changed = $false; present = $false; held = $false; whatIf = [bool]$WhatIfMode; settings = 0; differ = 0; askedAgain = 0; dropped = @(); text = ''; detail = '' }
    if ($null -eq $PolicyPlan) {
        $res.detail = 'the managing tenant sends no policy choices in this bundle -- what this tenant holds from it is left as it is'
        return [pscustomobject]$res
    }
    $res.present = [bool](Get-PimPcProp $PolicyPlan 'present'); $res.held = [bool](Get-PimPcProp $PolicyPlan 'held')
    $name = Get-PimPolicyChoicesSettingName
    $cs = "$ConnectionString".Trim()
    if (-not $ReadRaw)          { if (-not $cs) { throw 'policy choices (managing tenant): no store to read (-ConnectionString)' }; $ReadRaw = { Get-PimSqlSettingRaw -ConnectionString $cs -Name $name } }
    if (-not $WriteIfUnchanged) { if (-not $cs) { throw 'policy choices (managing tenant): no store to write (-ConnectionString)' }; $WriteIfUnchanged = { param($expected, $new) Set-PimSqlSettingIfUnchanged -ConnectionString $cs -Name $name -NewValueJson $new -ExpectedValueJson $expected } }
    if (-not $ReadAdvisories)   { if (-not $cs) { throw 'policy choices (managing tenant): no store to read (-ConnectionString)' }; $ReadAdvisories = { Get-PimSqlSetting -ConnectionString $cs -Name (Get-PimPolicyAdvisoriesSettingName) } }
    if (-not $Audit) {
        $Audit = {
            param($action, $target, $before, $after)
            if ($cs -and (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue)) {
                Write-PimSqlAuditEvent -ConnectionString $cs -Actor 'msp-downlink' -ActorSource 'downlink' -Action $action -Target $target -Before $before -After $after
            }
        }
    }
    $advisories = $null
    if (-not $res.held) { $advisories = & $ReadAdvisories }
    $beforeBlock = $null; $newBlock = $null; $cmp = $null
    $written = $false
    foreach ($attempt in 1..3) {
        $raw = & $ReadRaw
        $rawText = if ($null -eq $raw) { $null } else { "$raw" }
        $store = ConvertTo-PimPolicyChoicesStore -Value $rawText
        $beforeBlock = $store.managingTenant
        if ($res.held) {
            $newBlock = @{ types = @{}; overrides = @{}; receivedUtc = $NowUtc.ToUniversalTime().ToString('o') }
        } else {
            $conv = ConvertTo-PimManagingTenantPolicyChoices -Set (Get-PimPcProp $PolicyPlan 'set') -Advisories $advisories -GroupNames @(Get-PimPcProp $PolicyPlan 'groupNames') -ReceivedUtc $NowUtc
            $res.dropped = @($conv.dropped)
            if (-not $conv.understood) {
                $res.detail = "$(@($conv.dropped) -join '; ') -- what this tenant holds from the managing tenant is left as it is"
                return [pscustomobject]$res
            }
            $newBlock = $conv.block; $res.askedAgain = [int]$conv.askedAgain
        }
        $cmp = Compare-PimManagingTenantPolicyChoices -Before $beforeBlock -After $newBlock
        $res.settings = [int]$cmp.settings; $res.differ = [int]$cmp.differ
        if (-not $cmp.changed) {
            $res.detail = $(if ($res.held) { "this tenant blocks the managing tenant's policy choices ($(Get-PimPolicyChoicesCapabilityName)) -- none are held here" }
                            else { "the managing tenant's policy choices are unchanged ($($cmp.settings) setting$(if ($cmp.settings -eq 1) { '' } else { 's' }))" })
            return [pscustomobject]$res
        }
        $res.text = Format-PimManagingTenantPolicyChoiceAuditText -Settings $cmp.settings -Differ $cmp.differ -Blocked:([bool]$res.held)
        if ($WhatIfMode) {
            $res.detail = "WOULD record: $($res.text) (what-if: nothing written)"
            return [pscustomobject]$res
        }
        $json = ConvertTo-Json -InputObject ([ordered]@{ schema = 1; types = $store.types; overrides = $store.overrides; managingTenant = $newBlock }) -Depth 8 -Compress
        $won = 0; [void][int]::TryParse("$(@(& $WriteIfUnchanged $rawText $json)[-1])", [ref]$won)
        if ($won -ge 1) { $written = $true; break }
    }
    if (-not $written) {
        $res.ok = $false
        $res.detail = "the managing tenant's policy choices could NOT be stored: the policy choices of this tenant were being saved at the same moment (three attempts) -- nothing was changed, the next pull tries again"
        return [pscustomobject]$res
    }
    $res.changed = $true
    if (Get-Command Reset-PimPolicyChoiceCache -ErrorAction SilentlyContinue) { Reset-PimPolicyChoiceCache }
    $count = { param($blk) $n = 0; foreach ($part in 'types', 'overrides') { $m = Get-PimPcProp $blk $part; foreach ($k in @(Get-PimPcNames $m)) { $n += @(Get-PimPcNames (Get-PimPcProp $m $k)).Count } }; $n }
    try {
        & $Audit 'policy.choices.managing-tenant' 'policychoices:managing-tenant' `
            ([ordered]@{ settings = (& $count $beforeBlock) }) `
            ([ordered]@{ settings = [int]$cmp.settings; differ = [int]$cmp.differ; askedAgain = [int]$res.askedAgain; blocked = [bool]$res.held; bundleVersion = [int64]$BundleVersion; text = "$($res.text)" }) | Out-Null
    } catch { Write-Warning "  [downlink] the managing tenant's policy choices were stored but NOT written to the audit trail: $($_.Exception.Message)" }
    $res.detail = "$($res.text)$(if ($res.askedAgain) { " ($($res.askedAgain) asked again in this tenant: made on another advisory than this tenant stands on)" })$(if (@($res.dropped).Count) { "; $(@($res.dropped).Count) not understood and left out" })"
    [pscustomobject]$res
}
