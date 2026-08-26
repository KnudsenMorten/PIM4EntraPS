<#
.SYNOPSIS
  The PURE spec for the MSP PAIR simulation -- a synthetic MASTER estate plus TWO
  synthetic MANAGED estates. NO param() block, so it is SAFE to dot-source at any
  scope (a script param() block would clobber same-named caller variables).

  WHY A PAIR AND NOT A SINGLE ESTATE. Everything the downlink does (MSP-2 control #2,
  BUG-59 group standing-up, MSP-4 targeting/gating) has so far only been provable
  against the LIVE estate, because there was nowhere else to prove it -- which is
  backwards for a feature that writes privilege into a customer tenant. This spec is
  the other side of that: a master with a real delegation model, and two managed
  tenants that differ in exactly the ways that change the decision.

  THE TWO MANAGED TENANTS ARE DELIBERATELY ASYMMETRIC:

    A  ring 2, tagged 'retail'  -- EMPTY on day one (the real day-one shape: both live
       managed tenants measured zero rows). Proves the baseline can STAND UP the model.
       Its relationship policy DENIES the SecurityLead role group, which nests Global
       Administrator -- so this tenant also proves the closure property: denying the
       MEMBERSHIP must remove the GA group AND its Entra role binding, not just the row.

    B  ring 1, tagged 'finance;vip' -- ALREADY OWNS a group carrying one of the master's
       tags, plus a local admin of its own. Proves the yielding half of the rule: we
       defer to the customer's group, never write a nesting or a role binding into it,
       and never touch their local rows. Its ring (1) also excludes the master's ring-2
       admin, so the ring gate is proven to narrow PER TENANT rather than fleet-wide.

  The master's delegation model itself is the rich estate from PIM-ScenarioSeedSpec.ps1
  -- reused on purpose, so the pair simulation cannot drift from the single-tenant one.

  Returns plain hashtables/arrays. PURE: no I/O, no globals, no SQL.
#>

# ---------------------------------------------------------------------------
# The MASTER's platform registry: which admins are MSP-owned baseline, which
# tenants we manage, and what each relationship is allowed to project.
#
# Ring semantics are the engine's, and they are the easy thing to get backwards:
# an admin reaches a tenant when admin.Ring <= tenant.Ring, so ring 0 is BROADEST.
# The three rings below are chosen so the two tenants get DIFFERENT admin sets.
# ---------------------------------------------------------------------------
function Get-PimMspRegistrySpec {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantAId,
        [Parameter(Mandatory)][string]$TenantBId,
        [string]$Marker = 'PIMSCENARIO-',
        # The master's own domain. The registry UPN is a placeholder by design: the
        # real UPN is rebuilt per slave as <UserName>@<slave default domain>.
        [string]$MasterDomain = 'msp-master.invalid'
    )
    $m = $Marker

    # The three MSP-owned admins. The fourth seed admin (Offboarding) is DELIBERATELY
    # absent: it exists in the master's delegation model but not in the central
    # registry, which is how a master's own local admin looks. The producer must skip
    # its assignment rows -- "belonged to non-MSP admins, not published".
    # The fourth one exists for MSP-4: ring 0 (so the RING lets it everywhere) but TARGETED at
    # a tag only one of the two tenants carries. That separation is the point -- if targeting
    # were tested on an admin the ring already narrowed, a broken target filter would still
    # look correct. It deliberately holds no delegation, which also proves an admin with no
    # memberships syncs cleanly.
    $admins = @(
        @{ UserName = "${m}Admin-BG-L0-T0-ID";  DisplayName = "${m}Admin Break Glass (scenario)";   Ring = 0; Template = 'break-glass';    FirstName = 'Break';  LastName = 'Glass';    Initials = 'BG'; UsageLocation = 'DK'; Purpose = 'Service'; Target = '' }
        @{ UserName = "${m}Admin-CE-L1-T1-ID";  DisplayName = "${m}Admin Cloud Engineer (scenario)"; Ring = 1; Template = 'cloud-engineer'; FirstName = 'Cloud';  LastName = 'Engineer'; Initials = 'CE'; UsageLocation = 'DK'; Purpose = 'Day2Day'; Target = '' }
        @{ UserName = "${m}Admin-CS-L2-T1-ID";  DisplayName = "${m}Admin Consultant (scenario)";     Ring = 2; Template = 'consultant';     FirstName = 'Connie'; LastName = 'Sultant';  Initials = 'CS'; UsageLocation = 'DK'; Purpose = 'Day2Day'; Target = '' }
        @{ UserName = "${m}Admin-VIP-L0-T1-ID"; DisplayName = "${m}Admin VIP Duty (scenario)";       Ring = 0; Template = 'consultant';     FirstName = 'Vera';   LastName = 'Ipsum';    Initials = 'VI'; UsageLocation = 'DK'; Purpose = 'Day2Day'; Target = 'vip' }
    )
    foreach ($a in $admins) { $a['Upn'] = "$($a.UserName.ToLower())@$MasterDomain" }

    $tenants = @(
        @{ TenantId = $TenantAId; DisplayName = 'Scenario Managed A (empty on day one)';    Ring = 2; Tags = @('retail') }
        @{ TenantId = $TenantBId; DisplayName = 'Scenario Managed B (owns its own model)';  Ring = 1; Tags = @('finance', 'vip') }
    )

    # Per-relationship projection policy (pim.TenantRoleProjection).
    #   A: deny the SecurityLead role group -- it nests Global Administrator, so
    #      projecting it would mint GA in a customer tenant unattended (SEC-10 in
    #      practice). This is the same deny the live estate carries.
    #   B: an allow-LIST of exactly one tag, so everything else is subtracted by
    #      omission rather than by an explicit deny. Both modes therefore run.
    $projection = @(
        @{ TenantId = $TenantAId; Mode = 'deny';  GroupTag = "${m}ROLE-SecurityLead"; Notes = 'nests Global Administrator -- never projected unattended' }
        @{ TenantId = $TenantBId; Mode = 'allow'; GroupTag = "${m}ROLE-CloudEngineer"; Notes = 'this customer bought day-to-day cloud engineering only' }
    )

    return @{
        admins     = $admins
        tenants    = $tenants
        projection = $projection
    }
}

# ---------------------------------------------------------------------------
# What managed tenant B ALREADY HAS before the first sync. Two independent
# things the sync must respect, and they fail differently:
#   1. a GROUP carrying one of the master's tags -- the customer owns it, so the
#      downlink defers and must not add nestings or Entra roles into it.
#   2. a LOCAL admin with a LOCAL membership row -- unstamped (no Owner), because
#      the customer's rows predate the sync. A full-set replace would delete
#      their entire delegation on the first run; these rows prove it does not.
# Tenant A gets nothing -- an empty store is the day-one shape.
# ---------------------------------------------------------------------------
function Get-PimMspSlaveOwnEstate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DefaultDomain,
        [string]$Marker = 'PIMSCENARIO-',
        [string]$LocalPrefix = 'CUSTB-'
    )
    $m = $Marker; $p = $LocalPrefix
    $localUpn = "$($p.ToLower())admin-local-id@$DefaultDomain"

    return [ordered]@{
        # The customer's OWN group -- same tag as the master's CloudEngineer role
        # group, different name and description. The tag is the contract; who owns
        # the group is not.
        'PIM-Definitions-Roles' = @(
            [pscustomobject]@{
                GroupName = "${p}PIM-ROLE-CloudEngineer"; GroupTag = "${m}ROLE-CloudEngineer"
                GroupDescription = 'Customer-owned cloud engineer role group (predates the MSP relationship)'
                IsRoleAssignable = 'TRUE'; Department = ''; SponsorUpn = ''; PolicyTemplate = ''
            }
        )
        'Account-Definitions-Admins' = @(
            [pscustomobject]@{
                FirstName = 'Local'; LastName = 'Admin'; Initials = 'LA'; TargetUsage = 'Cloud'; TargetPlatform = 'ID'
                UserType = 'Member'; UserName = "${p}Admin-LOCAL-ID"; DisplayName = 'Customer local admin (scenario)'
                UserPrincipalName = $localUpn; UsageLocation = 'DK'; AccountStatus = 'Enabled'; CreateTAP = 'FALSE'
                Purpose = 'Day2Day'; Department = ''
            }
        )
        'PIM-Assignments-Admins' = @(
            [pscustomobject]@{
                Username = $localUpn; GroupTag = "${m}ROLE-CloudEngineer"; AssignmentType = 'Eligible'
                Action = 'Assign'; AutoExtend = 'TRUE'; NumOfDaysWhenExpire = '365'; Permanent = 'FALSE'
            }
        )
    }
}

# ---------------------------------------------------------------------------
# The EXPECTED downlink outcome per tenant, derived here rather than restated in
# the assertions -- so the spec and the expectation cannot drift apart.
# Ring rule: admin.Ring <= tenant.Ring.
# ---------------------------------------------------------------------------
function Get-PimMspExpectedForTenant {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Registry,
        [Parameter(Mandatory)][string]$TenantId
    )
    $tenant = @(@($Registry.tenants) | Where-Object { "$($_.TenantId)" -eq "$TenantId" })[0]
    if (-not $tenant) { throw "Get-PimMspExpectedForTenant: tenant $TenantId is not in the registry spec" }
    $ring = [int]$tenant.Ring
    $tags = @(@($tenant.Tags) | ForEach-Object { "$_".Trim().ToLowerInvariant() })
    # Two independent narrowings, and they compose: the RING says how far a version of this
    # admin has been promoted, the TARGET says which customers the admin is for at all.
    $byRing   = @(@($Registry.admins) | Where-Object { [int]$_.Ring -le $ring })
    $reach    = @(); $offTarget = @()
    foreach ($a in $byRing) {
        $t = "$($a.Target)".Trim().ToLowerInvariant()
        $hit = (-not $t) -or ($t -eq '*') -or ($tags -contains $t)
        if ($hit) { $reach += "$($a.UserName)" } else { $offTarget += "$($a.UserName)" }
    }
    return @{
        ring            = $ring
        tags            = @($tenant.Tags)
        adminNames      = $reach
        adminCount      = @($reach).Count
        notTargetedNames = $offTarget
        policy          = @(@($Registry.projection) | Where-Object { "$($_.TenantId)" -eq "$TenantId" })
    }
}
