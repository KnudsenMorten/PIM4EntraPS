#Requires -Version 5.1
<#
.SYNOPSIS
  OFFLINE Pester tests for the PURE reachability planners
  (engine/_shared/PIM-Reachability.ps1) -- the three things a deployed environment
  needs in order to be REACHABLE and not AZURE-BLIND, and which the deploy path
  did not create: VNet peering (BUG-49), private DNS for the ACA default domain
  (BUG-49), and an ARM role for each workload identity (BUG-51).
  NOTHING touches az / Azure / SQL / HTTP -- az is never invoked.

  Covers:
    * peering: BOTH directions always emitted, named by the convention the tenant
      already uses (vnet-platform + vnet-pim-x -> platform-to-pim-x / pim-x-to-platform)
    * peering: refuses a VNet peered to itself, and refuses OVERLAPPING address
      spaces by name instead of letting az refuse them mid-deploy
    * peering: cross-subscription is detected and flagged (rights on both sides)
    * CIDR overlap: true/false/unknown -- unknown is NOT "no overlap"
    * private DNS: apex + wildcard + `*.internal` A records at the env static IP
    * private DNS: refuses an empty/garbage domain or a non-IPv4 static IP, warns
      on a non-RFC1918 IP (the zone would SHADOW a public name), warns on no links
    * private DNS: VNet links are de-duplicated and named for the VNet
    * Azure RBAC: Reader at the subscription by default; a management group is
      opt-in and its absence is warned about (managementGroups list 403s without it)
    * Azure RBAC: refuses Owner/Contributor for a workload identity; refuses a
      principal with no objectId rather than emitting a PARTIAL plan
    * the deploy path actually WIRES all three (Setup-PimContainers +
      Invoke-PimDeployAll) -- the defect was never the helpers, it was the
      front door being unable to reach them

  Run: Invoke-Pester -Path tests\Test-PimReachability.ps1   (or via tests\Run-AllPimTests.ps1)
#>
[CmdletBinding()] param()

BeforeAll {
    $script:here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $script:sol  = Split-Path -Parent $script:here
    . (Join-Path $script:sol 'engine\_shared\PIM-Reachability.ps1')
    $script:setupContainers = Join-Path $script:sol 'tools\setup\Setup-PimContainers.ps1'
    $script:deployAll       = Join-Path $script:sol 'tools\setup\Invoke-PimDeployAll.ps1'
    $script:setupShared     = Join-Path $script:sol 'tools\setup\_PimSetupShared.ps1'
}

Describe 'PIM-Reachability: VNet short names (the existing tenant convention)' {
    It 'strips a leading vnet- so the pair names match what the tenant already had' {
        Get-PimVnetShortName -VnetName 'vnet-platform' | Should -Be 'platform'
        Get-PimVnetShortName -VnetName 'vnet-pim-mfnpr' | Should -Be 'pim-mfnpr'
    }
    It 'strips a trailing -vnet and lower-cases' {
        Get-PimVnetShortName -VnetName 'Platform-VNet' | Should -Be 'platform'
    }
    It 'leaves a name with no vnet affix alone' {
        Get-PimVnetShortName -VnetName 'hub' | Should -Be 'hub'
    }
}

Describe 'PIM-Reachability: CIDR overlap' {
    It 'detects a contained range as overlapping' {
        Test-PimCidrOverlap -CidrA '10.220.8.0/21' -CidrB '10.220.0.0/16' | Should -Be $true
    }
    It 'reports disjoint ranges as not overlapping' {
        Test-PimCidrOverlap -CidrA '10.221.8.0/21' -CidrB '10.100.0.0/16' | Should -Be $false
    }
    It 'treats an unparseable or absent CIDR as UNKNOWN (null), never as "no overlap"' {
        # The distinction matters: a caller that reads null as $false would proceed on a
        # guess. Null means "the fact could not be read" -- Azure remains the backstop.
        Test-PimCidrOverlap -CidrA '' -CidrB '10.0.0.0/8' | Should -Be $null
        Test-PimCidrOverlap -CidrA 'not-a-cidr' -CidrB '10.0.0.0/8' | Should -Be $null
        Test-PimCidrOverlap -CidrA '10.0.0.0/33' -CidrB '10.0.0.0/8' | Should -Be $null
        Test-PimCidrOverlap -CidrA '10.0.0.999/8' -CidrB '10.0.0.0/8' | Should -Be $null
    }
    It 'handles a /0 without the shift-count trap (0xFFFFFFFF << 32 is a no-op in .NET)' {
        Test-PimCidrOverlap -CidrA '0.0.0.0/0' -CidrB '10.100.0.0/16' | Should -Be $true
    }
    It 'treats adjacent-but-not-touching ranges as disjoint' {
        Test-PimCidrOverlap -CidrA '10.0.0.0/24' -CidrB '10.0.1.0/24' | Should -Be $false
    }
}

Describe 'PIM-Reachability: peering plan (BUG-49)' {
    BeforeAll {
        $script:plan = Get-PimPeeringPlan -SpokeVnetName 'vnet-pim-x' -SpokeResourceGroup 'rg-pim' `
                          -SpokeSubscriptionId 'sub-a' -HubVnetName 'vnet-platform' -HubResourceGroup 'rg-net'
    }
    It 'always emits BOTH directions -- a one-sided peering reads Initiated and carries no traffic' {
        $plan.ok | Should -Be $true
        @($plan.pairs).Count | Should -Be 2
        @($plan.pairs | ForEach-Object { $_.direction }) | Should -Contain 'hub-to-spoke'
        @($plan.pairs | ForEach-Object { $_.direction }) | Should -Contain 'spoke-to-hub'
    }
    It 'names the pairs by the convention already present in the tenant' {
        @($plan.pairs | ForEach-Object { $_.name }) | Should -Contain 'platform-to-pim-x'
        @($plan.pairs | ForEach-Object { $_.name }) | Should -Contain 'pim-x-to-platform'
    }
    It 'points each direction at the OTHER VNet resource id' {
        $hubSide   = @($plan.pairs | Where-Object { $_.direction -eq 'hub-to-spoke' })[0]
        $spokeSide = @($plan.pairs | Where-Object { $_.direction -eq 'spoke-to-hub' })[0]
        $hubSide.remoteVnetId   | Should -Be $plan.spokeVnetId
        $spokeSide.remoteVnetId | Should -Be $plan.hubVnetId
        $hubSide.vnetName   | Should -Be 'vnet-platform'
        $spokeSide.vnetName | Should -Be 'vnet-pim-x'
    }
    It 'defaults the hub subscription to the spoke subscription' {
        $plan.crossSubscription | Should -Be $false
        $plan.hubVnetId | Should -BeLike '/subscriptions/sub-a/*'
    }
    It 'flags a cross-subscription peering (rights are needed on BOTH sides)' {
        $x = Get-PimPeeringPlan -SpokeVnetName 'vnet-pim-x' -SpokeResourceGroup 'rg-pim' -SpokeSubscriptionId 'sub-a' `
                -HubVnetName 'vnet-platform' -HubResourceGroup 'rg-net' -HubSubscriptionId 'sub-b'
        $x.ok | Should -Be $true
        $x.crossSubscription | Should -Be $true
        $x.reason | Should -BeLike '*CROSS-SUBSCRIPTION*'
    }
    It 'REFUSES peering a VNet to itself and says which VNet' {
        $x = Get-PimPeeringPlan -SpokeVnetName 'vnet-pim-x' -SpokeResourceGroup 'rg-pim' -SpokeSubscriptionId 'sub-a' `
                -HubVnetName 'vnet-pim-x' -HubResourceGroup 'rg-pim' -HubSubscriptionId 'sub-a'
        $x.ok | Should -Be $false
        $x.reason | Should -BeLike '*SAME VNet*'
        @($x.pairs).Count | Should -Be 0
    }
    It 'REFUSES overlapping address spaces up front, naming both ranges' {
        $x = Get-PimPeeringPlan -SpokeVnetName 'vnet-pim-x' -SpokeResourceGroup 'rg-pim' -SpokeSubscriptionId 'sub-a' `
                -HubVnetName 'vnet-platform' -HubResourceGroup 'rg-net' `
                -SpokeAddressSpace '10.220.8.0/21' -HubAddressSpace '10.220.0.0/16'
        $x.ok | Should -Be $false
        $x.reason | Should -BeLike '*OVERLAP*'
        $x.reason | Should -BeLike '*10.220.8.0/21*'
        $x.reason | Should -BeLike '*10.220.0.0/16*'
    }
    It 'proceeds when the address spaces could not be read (unknown is not a refusal)' {
        $x = Get-PimPeeringPlan -SpokeVnetName 'vnet-pim-x' -SpokeResourceGroup 'rg-pim' -SpokeSubscriptionId 'sub-a' `
                -HubVnetName 'vnet-platform' -HubResourceGroup 'rg-net' -SpokeAddressSpace '' -HubAddressSpace ''
        $x.ok | Should -Be $true
    }
}

Describe 'PIM-Reachability: private DNS plan (BUG-49, the other half)' {
    BeforeAll {
        $script:dns = Get-PimPrivateDnsPlan -EnvDomain 'blackgrass-1a2b3c.westeurope.azurecontainerapps.io' `
                        -StaticIp '10.221.8.38' -ResourceGroup 'rg-connectivity' `
                        -LinkVnetIds @('/subscriptions/s/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet-platform',
                                       '/subscriptions/s/resourceGroups/rg-pim/providers/Microsoft.Network/virtualNetworks/vnet-pim-x') `
                        -ManagerFqdn 'ca-pim-manager.blackgrass-1a2b3c.westeurope.azurecontainerapps.io'
    }
    It 'names the zone for the ACA default domain' {
        $dns.ok | Should -Be $true
        $dns.zoneName | Should -Be 'blackgrass-1a2b3c.westeurope.azurecontainerapps.io'
    }
    It 'publishes apex + wildcard + *.internal, all at the env static IP' {
        @($dns.records | ForEach-Object { $_.name }) | Should -Contain '@'
        @($dns.records | ForEach-Object { $_.name }) | Should -Contain '*'
        # A wildcard matches ONE label, so `*` alone leaves <app>.internal.<domain> unresolvable.
        @($dns.records | ForEach-Object { $_.name }) | Should -Contain '*.internal'
        foreach ($r in $dns.records) { $r.ipv4Address | Should -Be '10.221.8.38'; $r.type | Should -Be 'A' }
    }
    It 'links every VNet given, named for the VNet, with auto-registration OFF' {
        @($dns.links).Count | Should -Be 2
        @($dns.links | ForEach-Object { $_.name }) | Should -Contain 'link-vnet-platform'
        @($dns.links | ForEach-Object { $_.name }) | Should -Contain 'link-vnet-pim-x'
        foreach ($l in $dns.links) { $l.registrationEnabled | Should -Be $false }
    }
    It 'de-duplicates repeated VNet ids (case-insensitively) and skips blanks' {
        $x = Get-PimPrivateDnsPlan -EnvDomain 'e.westeurope.azurecontainerapps.io' -StaticIp '10.1.2.3' `
                -ResourceGroup 'rg' -LinkVnetIds @('/subscriptions/s/x/VNET-A', '/subscriptions/s/x/vnet-a', '', '   ')
        @($x.links).Count | Should -Be 1
    }
    It 'REFUSES an empty default domain -- it means the environment read failed' {
        $x = Get-PimPrivateDnsPlan -EnvDomain '  ' -StaticIp '10.1.2.3' -ResourceGroup 'rg'
        $x.ok | Should -Be $false
        $x.reason | Should -BeLike '*defaultDomain*'
    }
    It 'REFUSES a non-IPv4 static IP rather than publishing a record pointing at nothing' {
        (Get-PimPrivateDnsPlan -EnvDomain 'e.io' -StaticIp 'not-an-ip' -ResourceGroup 'rg').ok | Should -Be $false
        (Get-PimPrivateDnsPlan -EnvDomain 'e.io' -StaticIp '10.1.2.999' -ResourceGroup 'rg').ok | Should -Be $false
    }
    It 'WARNS when the static IP is not RFC1918 -- a private zone would SHADOW the public name' {
        $x = Get-PimPrivateDnsPlan -EnvDomain 'e.westeurope.azurecontainerapps.io' -StaticIp '20.31.2.3' `
                -ResourceGroup 'rg' -LinkVnetIds @('/subscriptions/s/x/vnet-a')
        $x.ok | Should -Be $true                       # a valid shape, just not an internal one
        ($x.warnings -join ' ') | Should -BeLike '*SHADOW*'
    }
    It 'accepts the whole of the 172.16-31 private range and rejects 172.32 as public' {
        (Get-PimPrivateDnsPlan -EnvDomain 'e.io' -StaticIp '172.16.0.1' -ResourceGroup 'rg' -LinkVnetIds @('/x/v')).warnings.Count | Should -Be 0
        (Get-PimPrivateDnsPlan -EnvDomain 'e.io' -StaticIp '172.31.255.254' -ResourceGroup 'rg' -LinkVnetIds @('/x/v')).warnings.Count | Should -Be 0
        (($(Get-PimPrivateDnsPlan -EnvDomain 'e.io' -StaticIp '172.32.0.1' -ResourceGroup 'rg' -LinkVnetIds @('/x/v')).warnings) -join ' ') | Should -BeLike '*SHADOW*'
    }
    It 'WARNS when there is nothing to link -- a zone nobody can resolve is not reachability' {
        $x = Get-PimPrivateDnsPlan -EnvDomain 'e.westeurope.azurecontainerapps.io' -StaticIp '10.1.2.3' -ResourceGroup 'rg'
        $x.ok | Should -Be $true
        ($x.warnings -join ' ') | Should -BeLike '*resolve for nobody*'
    }
}

Describe 'PIM-Reachability: Azure RBAC plan (BUG-51)' {
    BeforeAll {
        $script:rbac = Get-PimAzureRbacPlan -Principals @(@{ name='ca-pim-tick'; objectId='oid-1' },
                                                          @{ name='ca-pim-manager'; objectId='oid-2' }) `
                          -SubscriptionId 'sub-a'
    }
    It 'grants Reader at the subscription by default' {
        $rbac.ok | Should -Be $true
        @($rbac.assignments).Count | Should -Be 2
        foreach ($a in $rbac.assignments) {
            $a.role      | Should -Be 'Reader'
            $a.scope     | Should -Be '/subscriptions/sub-a'
            $a.scopeKind | Should -Be 'subscription'
        }
    }
    It 'WARNS that management-group enumeration will 403 without a management-group scope' {
        # This is the measured residual: Reader at the SUBSCRIPTION fixed azure-scopes=0 and
        # left `ARM managementGroups list failed ... 403` in place. Widen deliberately.
        ($rbac.warnings -join ' ') | Should -BeLike '*managementGroups*'
    }
    It 'adds the management-group scope when asked, for every principal' {
        $x = Get-PimAzureRbacPlan -Principals @(@{ name='t'; objectId='oid-1' }) -SubscriptionId 'sub-a' -ManagementGroupId 'mg-root'
        @($x.assignments).Count | Should -Be 2
        @($x.assignments | ForEach-Object { $_.scope }) | Should -Contain '/providers/Microsoft.Management/managementGroups/mg-root'
        ($x.warnings -join ' ') | Should -Not -BeLike '*managementGroups*'
    }
    It 'accepts User Access Administrator by name (assigning roles needs it) without a warning' {
        $x = Get-PimAzureRbacPlan -Principals @(@{ name='t'; objectId='o' }) -SubscriptionId 's' -Roles @('User Access Administrator')
        $x.ok | Should -Be $true
        ($x.warnings -join ' ') | Should -Not -BeLike "*outside the intended set*"
    }
    It 'REFUSES Owner and Contributor for a workload identity' {
        foreach ($r in @('Owner','Contributor')) {
            $x = Get-PimAzureRbacPlan -Principals @(@{ name='t'; objectId='o' }) -SubscriptionId 's' -Roles @($r)
            $x.ok | Should -Be $false
            $x.reason | Should -BeLike "*'$r' is refused*"
        }
    }
    It 'warns on a role outside the intended set but still emits it (asked for by name)' {
        $x = Get-PimAzureRbacPlan -Principals @(@{ name='t'; objectId='o' }) -SubscriptionId 's' -Roles @('Monitoring Reader')
        $x.ok | Should -Be $true
        ($x.warnings -join ' ') | Should -BeLike '*outside the intended set*'
    }
    It 'REFUSES a principal with no objectId rather than emitting a PARTIAL plan' {
        # A silently-dropped identity is the hardest shape of this bug to spot: one workload
        # ends up Azure-blind while its siblings work.
        $x = Get-PimAzureRbacPlan -Principals @(@{ name='ca-pim-tick'; objectId='oid-1' }, @{ name='ca-pim-manager'; objectId='' }) -SubscriptionId 's'
        $x.ok | Should -Be $false
        $x.reason | Should -BeLike '*ca-pim-manager*'
        @($x.assignments).Count | Should -Be 0
    }
    It 'refuses an empty role list and an empty subscription' {
        (Get-PimAzureRbacPlan -Principals @(@{ name='t'; objectId='o' }) -SubscriptionId 's' -Roles @('','  ')).ok | Should -Be $false
        (Get-PimAzureRbacPlan -Principals @(@{ name='t'; objectId='o' }) -SubscriptionId '  ').ok | Should -Be $false
    }
    It 'reads a PSCustomObject principal as well as a hashtable' {
        $x = Get-PimAzureRbacPlan -Principals @([pscustomobject]@{ name='t'; objectId='oid-9' }) -SubscriptionId 's'
        $x.ok | Should -Be $true
        $x.assignments[0].principalId | Should -Be 'oid-9'
    }
}

Describe 'PIM-Reachability: the deploy path actually WIRES it (the real defect)' {
    # BUG-49/BUG-51 were never missing helpers -- `-DnsServer` and Write-PimDnsRecord already
    # existed. The defect was that the front door could not reach any of it. These pin the
    # passthrough, because a passthrough is exactly what silently regresses.
    It 'Setup-PimContainers takes a hub VNet and calls the peering helper' {
        $t = Get-Content -LiteralPath $script:setupContainers -Raw
        $t | Should -BeLike '*$HubVnetName*'
        $t | Should -BeLike '*Set-PimVnetPeering*'
    }
    It 'Setup-PimContainers publishes the ACA default domain in a private DNS zone' {
        (Get-Content -LiteralPath $script:setupContainers -Raw) | Should -BeLike '*Set-PimPrivateDnsZone*'
    }
    It 'Setup-PimContainers grants Azure RBAC to BOTH the worker apps and the tick Job' {
        $t = Get-Content -LiteralPath $script:setupContainers -Raw
        ([regex]::Matches($t, 'Grant-PimMiAzureRbac')).Count | Should -BeGreaterOrEqual 2
    }
    It 'Setup-PimContainers WARNS (not Notes) when no hub is given -- a quiet skip reads as a deploy' {
        $t = Get-Content -LiteralPath $script:setupContainers -Raw
        $t | Should -BeLike '*NO HUB VNET GIVEN*'
    }
    It 'Invoke-PimDeployAll exposes the reachability parameters and splats them into INFRA' {
        $t = Get-Content -LiteralPath $script:deployAll -Raw
        $t | Should -BeLike '*$HubVnetName*'
        $t | Should -BeLike '*$DnsServer*'
        $t | Should -BeLike '*$AzureRbacRoles*'
        $t | Should -BeLike '*@reach*'
    }
    It 'the INFRA readiness probe tests peering and ARM rights, not just the Graph grant' {
        # BUG-46's lesson: the probe must test the LAST thing the step does. Without this, the
        # first re-run of an environment deployed before these existed reports "already
        # current" and skips the only step that could create them.
        $t = Get-Content -LiteralPath $script:deployAll -Raw
        $t | Should -BeLike '*network vnet peering show*'
        $t | Should -BeLike '*role assignment list*'
    }
    It 'the private-DNS link probe matches on the VNET ID, not the link NAME' {
        # MEASURED against the live production zone 2026-08-10: the existing link was named
        # `cae-pim-mfnpr-dnslink`, the probe looked for `link-<vnet>`, concluded "missing", tried
        # to create it, and Azure refused with `Conflict: ... already linked to the virtual
        # network ...` -- failing the deploy over a desired state that was ALREADY SATISFIED.
        # The link name is arbitrary metadata; only "is SOME link pointing at this VNet" matters.
        $t = Get-Content -LiteralPath $script:setupShared -Raw
        $t | Should -BeLike '*link vnet list*'
        $t | Should -BeLike '*virtualNetwork.id*'
        $t | Should -Not -BeLike '*link vnet show*'
    }
    It 'the private-DNS record write is a NO-OP when the record already matches' {
        # delete-then-add is required to converge a MOVED ip, but on an already-correct
        # environment it would briefly remove the record the Manager is reached through.
        (Get-Content -LiteralPath $script:setupShared -Raw) | Should -BeLike '*already correct*'
    }
    It 'the shared setup module dot-sources the pure core rather than re-implementing it' {
        (Get-Content -LiteralPath $script:setupShared -Raw) | Should -BeLike '*PIM-Reachability.ps1*'
    }
    It 'every touched script parses clean in PowerShell 5.1 syntax' {
        foreach ($f in @($script:setupContainers, $script:deployAll, $script:setupShared,
                         (Join-Path $script:sol 'engine\_shared\PIM-Reachability.ps1'))) {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$errors) | Out-Null
            @($errors).Count | Should -Be 0 -Because "$f must parse clean"
        }
    }
}
