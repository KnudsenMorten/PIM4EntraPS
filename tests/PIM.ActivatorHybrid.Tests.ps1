#Requires -Version 5.1
<#
    Pester suite for the PIM Activator HYBRID (on-prem / standalone) deploy
    (tools/pim-activator/Deploy-PimActivatorHybrid.ps1 + its pure builder
    _PimActivatorHybridPolicy.ps1).

    Pure, offline unit tests: validate the multi-tenant UNC-JSON config, prove
    the registry plan matches Deploy-PimActivatorIntune.ps1's managed config
    (parity), and confirm the plan shape. NO Graph / DC / admin / network.
    Documented in docs/TESTS.md (lockstep with this file).

    Run:  Invoke-Pester -Path tests\PIM.ActivatorHybrid.Tests.ps1
#>
BeforeAll {
    $script:Root      = Split-Path -Parent $PSScriptRoot
    $script:Activator = Join-Path $Root 'tools\pim-activator'
    $script:Builder   = Join-Path $Activator '_PimActivatorHybridPolicy.ps1'
    $script:Intune    = Join-Path $Activator 'Deploy-PimActivatorIntune.ps1'
    $script:Deploy    = Join-Path $Activator 'Deploy-PimActivatorHybrid.ps1'
    $script:Sample    = Join-Path $Activator 'pim-activator-hybrid-tenants.sample.json'
    . $script:Builder

    $script:ExtId  = 'eheocihmlppcophaeakmdenhgcookkab'
    $script:UpdUrl = 'https://knudsenmorten.github.io/PIM4EntraPS/updates.xml'
    $script:SrcPat = 'https://knudsenmorten.github.io/*'

    $parsed         = Get-Content -LiteralPath $script:Sample -Raw -Encoding UTF8 | ConvertFrom-Json
    $script:Catalog = New-PaHybridConfig -InputObject $parsed -MaxTenants 25
}

Describe 'PIM Activator Hybrid: multi-tenant UNC-JSON config' {
    It 'parses the 25-tenant synthetic sample (object-wrapped)' {
        @($script:Catalog).Count | Should -Be 25
    }
    It 'normalises 25 unique tenantIds' {
        (@($script:Catalog.tenantId | Select-Object -Unique)).Count | Should -Be 25
    }
    It 'parses the bare-array config form too' {
        $bare = (Get-Content -LiteralPath $script:Sample -Raw | ConvertFrom-Json).tenants
        @(New-PaHybridConfig -InputObject $bare).Count | Should -Be 25
    }
    It 'rejects an empty config' {
        { New-PaHybridConfig -InputObject @() } | Should -Throw
    }
    It 'rejects more than 25 tenants' {
        $big = 1..26 | ForEach-Object { @{ name="T$_"; tenantId=("aaaaaaaa-bbbb-cccc-dddd-0000000000{0:x2}" -f $_); clientId=("11111111-2222-3333-4444-5555555555{0:x2}" -f $_) } }
        { New-PaHybridConfig -InputObject $big -MaxTenants 25 } | Should -Throw
    }
    It 'rejects a missing required field' {
        { New-PaHybridConfig -InputObject @(@{ name='NoIds' }) } | Should -Throw
    }
    It 'rejects a malformed GUID' {
        { New-PaHybridConfig -InputObject @(@{ name='Bad'; tenantId='not-a-guid'; clientId='11111111-2222-3333-4444-555555555501' }) } | Should -Throw
    }
    It 'rejects a duplicate tenantId' {
        $dup = @(
            @{ name='D1'; tenantId='aaaaaaaa-bbbb-cccc-dddd-000000000001'; clientId='11111111-2222-3333-4444-555555555501' }
            @{ name='D2'; tenantId='aaaaaaaa-bbbb-cccc-dddd-000000000001'; clientId='11111111-2222-3333-4444-555555555502' }
        )
        { New-PaHybridConfig -InputObject $dup } | Should -Throw
    }
}

Describe 'PIM Activator Hybrid: parity with Deploy-PimActivatorIntune.ps1' {
    It 'ExtensionSettings JSON is byte-identical to the Intune deploy' {
        $intune = (@{ $script:ExtId = @{
            installation_mode     = 'force_installed'
            update_url            = $script:UpdUrl
            runtime_allowed_hosts = @('<all_urls>')
        }} | ConvertTo-Json -Depth 5 -Compress)
        (New-PaHybridExtensionSettingsJson -ExtensionId $script:ExtId -UpdateUrl $script:UpdUrl) | Should -BeExactly $intune
    }
    It 'forcelist row is byte-identical to the Intune deploy' {
        (New-PaHybridForcelistValue -ExtensionId $script:ExtId -UpdateUrl $script:UpdUrl) | Should -BeExactly "$($script:ExtId);$($script:UpdUrl)"
    }
    It 'tenantCatalog JSON is byte-identical to the Intune deploy' {
        $intune = ConvertTo-Json -InputObject @($script:Catalog) -Depth 10 -Compress
        (ConvertTo-PaHybridCatalogJson -Catalog $script:Catalog) | Should -BeExactly $intune
    }
    It 'Intune source still defines the same managed-config expressions (no drift)' {
        $src = Get-Content -LiteralPath $script:Intune -Raw
        $src | Should -Match "runtime_allowed_hosts\s*=\s*@\('<all_urls>'\)"
        $src | Should -Match '\$forcelistValue\s*=\s*"\$ExtensionId;\$UpdateUrl"'
        $src | Should -Match 'ConvertTo-Json\s+-InputObject\s+@\(\$catalog\)\s+-Depth\s+10\s+-Compress'
    }
}

Describe 'PIM Activator Hybrid: registry plan shape' {
    BeforeAll {
        $script:Plan = Get-PaHybridRegistryPlan -Catalog $script:Catalog -Browser Both -ExtensionId $script:ExtId -UpdateUrl $script:UpdUrl -SourcePattern $script:SrcPat
    }
    It 'has 8 entries (2 browsers x 4 policies)' {
        $script:Plan.Entries.Count | Should -Be 8
    }
    It 'writes the Edge forcelist to the correct HKLM key' {
        $e = $script:Plan.Entries | Where-Object { $_.Browser -eq 'Edge' -and $_.Policy -eq 'Forcelist' } | Select-Object -First 1
        $e.Key | Should -Be 'SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist'
    }
    It 'writes the Chrome tenantCatalog to the 3rdparty extension policy key' {
        $e = $script:Plan.Entries | Where-Object { $_.Browser -eq 'Chrome' -and $_.Policy -eq 'Catalog' } | Select-Object -First 1
        $e.Key       | Should -Be "SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$($script:ExtId)\policy"
        $e.ValueName | Should -Be 'tenantCatalog'
    }
    It '-Browser Edge yields 4 Edge-only entries' {
        $p = Get-PaHybridRegistryPlan -Catalog $script:Catalog -Browser Edge -ExtensionId $script:ExtId -UpdateUrl $script:UpdUrl -SourcePattern $script:SrcPat
        $p.Entries.Count | Should -Be 4
        @($p.Entries | Where-Object { $_.Browser -eq 'Chrome' }).Count | Should -Be 0
    }
}

Describe 'PIM Activator Hybrid: activation-default override (-DefaultJustification / -DefaultDurationHours)' {
    # Drives the REAL Deploy-PimActivatorHybrid.ps1 -Target Json (no admin / no
    # network) and reads the override back out of the emitted managed-config
    # artifact's tenantCatalog -- proving the override lands on every tenant
    # entry on the actual surface the script writes, not just on the builder.
    BeforeAll {
        function Read-PaArtifactCatalog {
            param([string]$ArtifactPath, [string]$BrowserKey = 'Edge')
            $a = Get-Content -LiteralPath $ArtifactPath -Raw | ConvertFrom-Json
            return ($a.$BrowserKey.managedConfig.tenantCatalog | ConvertFrom-Json)
        }
        function Invoke-PaHybridJson {
            param([hashtable]$Extra = @{})
            $out = Join-Path ([IO.Path]::GetTempPath()) ("pa-ovr-{0}.json" -f [guid]::NewGuid().ToString('N'))
            $splat = @{ TenantConfigJsonPath = $script:Sample; Target = 'Json'; OutputPath = $out } + $Extra
            & $script:Deploy @splat | Out-Null
            return $out
        }
    }

    It 'OVERWRITES defaultJustification + defaultDurationHours on ALL 25 tenant entries (both browsers)' {
        $out = Invoke-PaHybridJson -Extra @{ DefaultJustification = 'Approved change / incident work'; DefaultDurationHours = 4 }
        try {
            foreach ($bk in 'Edge','Chrome') {
                $cat = Read-PaArtifactCatalog -ArtifactPath $out -BrowserKey $bk
                @($cat).Count | Should -Be 25
                @($cat | ForEach-Object { $_.defaultJustification } | Select-Object -Unique) | Should -Be @('Approved change / incident work')
                @($cat | ForEach-Object { [int]$_.defaultDurationHours } | Select-Object -Unique) | Should -Be @(4)
            }
        } finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }

    It 'absent => the catalog default values are kept unchanged (opt-in)' {
        $out = Invoke-PaHybridJson
        try {
            $cat = Read-PaArtifactCatalog -ArtifactPath $out
            @($cat | ForEach-Object { $_.defaultJustification } | Select-Object -Unique) | Should -Be @('Change in infrastructure')
            @($cat | ForEach-Object { [int]$_.defaultDurationHours } | Select-Object -Unique) | Should -Be @(8)
        } finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }

    It 'only -DefaultJustification overrides justification, leaves duration untouched' {
        $out = Invoke-PaHybridJson -Extra @{ DefaultJustification = 'JustOnly' }
        try {
            $cat = Read-PaArtifactCatalog -ArtifactPath $out
            @($cat | ForEach-Object { $_.defaultJustification } | Select-Object -Unique) | Should -Be @('JustOnly')
            @($cat | ForEach-Object { [int]$_.defaultDurationHours } | Select-Object -Unique) | Should -Be @(8)
        } finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }

    It 'only -DefaultDurationHours overrides duration, leaves justification untouched' {
        $out = Invoke-PaHybridJson -Extra @{ DefaultDurationHours = 3 }
        try {
            $cat = Read-PaArtifactCatalog -ArtifactPath $out
            @($cat | ForEach-Object { $_.defaultJustification } | Select-Object -Unique) | Should -Be @('Change in infrastructure')
            @($cat | ForEach-Object { [int]$_.defaultDurationHours } | Select-Object -Unique) | Should -Be @(3)
        } finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }

    It 'rejects an out-of-range -DefaultDurationHours (ValidateRange 1..24)' {
        { & $script:Deploy -TenantConfigJsonPath $script:Sample -Target Json -DefaultDurationHours 25 -WhatIf } | Should -Throw
    }

    It 'both deploy paths expose the two opt-in params (Hybrid + Intune parity)' {
        foreach ($scriptPath in @($script:Deploy, $script:Intune)) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
            $names = $ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }
            $names | Should -Contain 'DefaultJustification'
            $names | Should -Contain 'DefaultDurationHours'
        }
    }
}
