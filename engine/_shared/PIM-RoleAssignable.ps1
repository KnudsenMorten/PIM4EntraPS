#Requires -Version 5.1
<#
.SYNOPSIS
  REQUIREMENTS 95.2c / 100.15 -- ONE rule for "is this PIM group role-assignable?" (operator approved 2026-10-07,
  "Tier 0 only"). Used by the engine's group create (PIM-EngineProviders.ps1, Groups provider), the Manager's
  validator (tools/pim-manager/_validator.ps1, PIM-RA-003..006) and mirrored 1:1 by the page's
  pimRoleAssignableDefault() (tools/pim-manager/pim-manager.html) -- tests/Test-PimRoleAssignableDefault.ps1 runs both
  over the same matrix, so the two cannot drift.

.DESCRIPTION
  Microsoft (Learn: groups-concept, concept-pim-for-groups): isAssignableToRole is REQUIRED only for a group that is
  itself assigned an Entra role; it is IMMUTABLE (set at creation, never changed), limited to 500 per tenant, assigned
  membership only, and allows no ACTIVE group nesting (eligible nesting only). Microsoft also RECOMMENDS it for a group
  that gives access to sensitive resources (only Global / Privileged Role Administrators and owners can then change its
  members).

  THE RULE (first match wins):
    1. the group itself holds an Entra ID role (a PIM-Assignments-Roles-Groups / -Roles-AUs row names it)
         -> TRUE, LOCKED (Entra refuses the role otherwise)
    2. a DIRECT group (job role / department / organisation / project / cross-org) nested into a permission group that
       holds a TIER-0 Entra ID role -> TRUE (Microsoft: protect sensitive access)
    3. a DIRECT group on Tier 0 -> TRUE (the flag cannot be added later; a Tier-0 direct group is where a Tier-0
       nesting will land)
    4. everything else -> FALSE (a permission group without an Entra role; a Tier 1 / Tier 2 direct group)
  An EXPLICIT TRUE / FALSE on the definition always wins over the rule (Resolve-PimRoleAssignableForCreate); a blank
  value takes the rule -- it NEVER defaults to TRUE on its own.

  PURE: no Graph, no SQL, no globals. PS 5.1 + 7. ASCII only.
#>
Set-StrictMode -Off

function Get-PimRoleAssignableGroupLimit { return 500 }

function Get-PimDirectGroupEntities {
    # The definition entities whose groups people are assigned to DIRECTLY (section 66 / 70.22).
    return @('PIM-Definitions-Roles', 'PIM-Definitions-Departments', 'PIM-Definitions-Organization', 'PIM-Definitions-Projects', 'PIM-Definitions-CrossOrg')
}

function Test-PimDirectGroupEntity {
    param([string]$Entity)
    $e = "$Entity".Trim()
    foreach ($d in @(Get-PimDirectGroupEntities)) { if ($d -ieq $e) { return $true } }
    return $false
}

function ConvertTo-PimRoleAssignableFlag {
    <# PURE. 'TRUE' / 'FALSE' for an EXPLICIT value (true/yes/1, false/no/0, any case), '' for blank or unreadable.
       A blank is NOT false here: it means "the definition did not say", and the rule decides. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { if ($Value) { return 'TRUE' } else { return 'FALSE' } }
    $v = "$Value".Trim()
    if ($v -match '^(?i)(true|yes|y|1)$') { return 'TRUE' }
    if ($v -match '^(?i)(false|no|n|0)$') { return 'FALSE' }
    return ''
}

function ConvertTo-PimTierNumber {
    param([AllowNull()][object]$Tier)
    $m = [regex]::Match("$Tier", '(?i)^\s*T?(\d+)\s*$')
    if ($m.Success) { return [int]$m.Groups[1].Value }
    return $null
}

function Get-PimRoleAssignableDefault {
    <#
      PURE. The 95.2c default for ONE group.
        -HoldsEntraRole            the group itself is assigned an Entra ID role
        -DirectGroup               a direct group (job role / department / organisation / project / cross-org)
        -TierLevel                 the group's TierLevel ('T0' / 'T1' / 'T2' / '0' ...)
        -NestsIntoTier0EntraRole   (direct group) it is nested into a permission group holding a Tier-0 Entra ID role
      Returns [pscustomobject]@{ Value = 'TRUE'|'FALSE'; Locked = bool; Rule = 'entra-role'|'tier0-nesting'|'tier0'|'default';
                                 Reason = one line an operator can read }
    #>
    param([switch]$HoldsEntraRole, [switch]$DirectGroup, [AllowNull()][string]$TierLevel, [switch]$NestsIntoTier0EntraRole)
    if ($HoldsEntraRole) {
        return [pscustomobject]@{ Value = 'TRUE'; Locked = $true; Rule = 'entra-role'
            Reason = 'Yes, locked: the group holds an Entra ID role, and Entra assigns a role only to a role-assignable group.' }
    }
    $tn = ConvertTo-PimTierNumber $TierLevel
    if ($DirectGroup -and $NestsIntoTier0EntraRole) {
        return [pscustomobject]@{ Value = 'TRUE'; Locked = $false; Rule = 'tier0-nesting'
            Reason = 'Yes: it nests into a permission group holding a Tier-0 Entra ID role -- Microsoft recommends role-assignable for groups that reach sensitive access.' }
    }
    if ($DirectGroup -and $tn -eq 0) {
        return [pscustomobject]@{ Value = 'TRUE'; Locked = $false; Rule = 'tier0'
            Reason = 'Yes: a Tier-0 group -- only Global / Privileged Role Administrators and owners can then change its members (the flag cannot be added later).' }
    }
    $why = if ($DirectGroup) { "No: a Tier $(if ($null -ne $tn) { $tn } else { '1/2' }) group that does not reach a Tier-0 Entra ID role -- role-assignable is not needed, and it would use one of the tenant's 500." }
           else { "No: this permission group holds no Entra ID role -- role-assignable is required only for a group that is assigned an Entra role (and uses one of the tenant's 500)." }
    return [pscustomobject]@{ Value = 'FALSE'; Locked = $false; Rule = 'default'; Reason = $why }
}

function Get-PimRoleAssignableFacts {
    <#
      PURE. The facts the rule needs, per group tag (lower-case key), from the definition + assignment rows.
        -Definitions   rows with GroupTag + TierLevel and either SourceEntity, or use -EntityOf (a scriptblock row -> entity)
        -RoleBindings  rows of PIM-Assignments-Roles-Groups / -Roles-AUs (GroupTag)
        -Nestings      rows of PIM-Assignments-Groups: TargetGroupTag is the MEMBER, SourceGroupTag the CONTAINER
      Returns @{ '<tag lower>' = [pscustomobject]@{ Tag; Tier; Direct; HoldsEntraRole; NestsIntoTier0EntraRole; Tier0Containers } }
    #>
    param([object[]]$Definitions = @(), [object[]]$RoleBindings = @(), [object[]]$Nestings = @(), [scriptblock]$EntityOf)
    $get = {
        param($r, [string]$n)
        if ($null -eq $r) { return '' }
        if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { return "$($r[$n])".Trim() } else { return '' } }
        $p = $r.PSObject.Properties[$n]; if ($p) { return "$($p.Value)".Trim() } else { return '' }
    }
    $facts = @{}
    foreach ($d in @($Definitions)) {
        $tag = & $get $d 'GroupTag'; if (-not $tag) { continue }
        $k = $tag.ToLowerInvariant(); if ($facts.ContainsKey($k)) { continue }
        $ent = if ($EntityOf) { "$(& $EntityOf $d)" } else { & $get $d 'SourceEntity' }
        $facts[$k] = [pscustomobject]@{ Tag = $tag; Tier = (& $get $d 'TierLevel'); Direct = (Test-PimDirectGroupEntity $ent)
            HoldsEntraRole = $false; NestsIntoTier0EntraRole = $false; Tier0Containers = @() }
    }
    foreach ($b in @($RoleBindings)) {
        $tag = & $get $b 'GroupTag'; if (-not $tag) { continue }
        $k = $tag.ToLowerInvariant()
        if ($facts.ContainsKey($k)) { $facts[$k].HoldsEntraRole = $true }
    }
    foreach ($n in @($Nestings)) {
        $member = & $get $n 'TargetGroupTag'; $container = & $get $n 'SourceGroupTag'
        if (-not $member -or -not $container) { continue }
        $mk = $member.ToLowerInvariant(); $ck = $container.ToLowerInvariant()
        if (-not $facts.ContainsKey($mk) -or -not $facts.ContainsKey($ck)) { continue }
        $c = $facts[$ck]
        if ($c.HoldsEntraRole -and (ConvertTo-PimTierNumber $c.Tier) -eq 0) {
            $facts[$mk].NestsIntoTier0EntraRole = $true
            $facts[$mk].Tier0Containers = @($facts[$mk].Tier0Containers) + @($c.Tag)
        }
    }
    return $facts
}

function Get-PimRoleAssignableDefaultForTag {
    <# PURE. The 95.2c default for a tag from -Facts (Get-PimRoleAssignableFacts). An unknown tag gets the safe default
       (FALSE, the rule's last line) -- never TRUE. #>
    param([string]$Tag, [hashtable]$Facts, [string]$TierLevel, [switch]$DirectGroup)
    $f = $null
    if ($Facts -and "$Tag".Trim()) { $k = "$Tag".Trim().ToLowerInvariant(); if ($Facts.ContainsKey($k)) { $f = $Facts[$k] } }
    if ($f) {
        return Get-PimRoleAssignableDefault -HoldsEntraRole:([bool]$f.HoldsEntraRole) -DirectGroup:([bool]$f.Direct) -TierLevel "$($f.Tier)" -NestsIntoTier0EntraRole:([bool]$f.NestsIntoTier0EntraRole)
    }
    return Get-PimRoleAssignableDefault -DirectGroup:$DirectGroup -TierLevel $TierLevel
}

function Resolve-PimRoleAssignableForCreate {
    <#
      PURE. The isAssignableToRole a NEW group is created with. An explicit IsRoleAssignable on the definition wins;
      a blank one takes the 95.2c rule (Get-PimRoleAssignableDefaultForTag) -- it never defaults to TRUE by itself.
      Never used for an EXISTING group: the flag is immutable in Entra and the engine never changes it.
      Returns [pscustomobject]@{ Assignable = bool; Source = 'definition'|'rule'; Reason }
    #>
    param([Parameter(Mandatory)][object]$Row, [hashtable]$Facts)
    $get = { param($r, [string]$n) if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { "$($r[$n])" } else { '' } } else { $p = $r.PSObject.Properties[$n]; if ($p) { "$($p.Value)" } else { '' } } }
    $explicit = ConvertTo-PimRoleAssignableFlag (& $get $Row 'IsRoleAssignable')
    if ($explicit) { return [pscustomobject]@{ Assignable = ($explicit -eq 'TRUE'); Source = 'definition'; Reason = "IsRoleAssignable=$explicit on the definition" } }
    $d = Get-PimRoleAssignableDefaultForTag -Tag (& $get $Row 'GroupTag') -Facts $Facts -TierLevel (& $get $Row 'TierLevel') -DirectGroup:(Test-PimDirectGroupEntity (& $get $Row 'SourceEntity'))
    return [pscustomobject]@{ Assignable = ($d.Value -eq 'TRUE'); Source = 'rule'; Reason = "IsRoleAssignable blank on the definition -- 95.2c: $($d.Reason)" }
}
