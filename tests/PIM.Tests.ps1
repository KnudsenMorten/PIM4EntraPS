#Requires -Version 5.1
<#
    Pester job for PIM4EntraPS -- reruns every offline flow + framework checks.
    Run:  Invoke-Pester -Path tests\PIM.Tests.ps1
    Or:   tests\Run-AllPimTests.ps1   (also drives this)
    The three functional suites are executed as child processes (clean assembly
    state) and asserted green; the workload-connector framework is tested in-proc.
#>
BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:Tests = $PSScriptRoot
    $global:PIM_ConfigVariant = 'test'
    Import-Module (Join-Path $Root 'engine\_shared\PIM-Functions.psm1') -Force -DisableNameChecking
    function Invoke-Suite([string]$name) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $script:Tests $name) | Out-Null
        $LASTEXITCODE
    }
}

Describe 'Functional suites (child-process, asserted green)' {
    It 'Test-PimFeatures.ps1 exits 0'          { Invoke-Suite 'Test-PimFeatures.ps1'         | Should -Be 0 }
    It 'Test-PimManagerEndpoints.ps1 exits 0'  { Invoke-Suite 'Test-PimManagerEndpoints.ps1' | Should -Be 0 }
    It 'Test-PimScenarios.ps1 exits 0'         { Invoke-Suite 'Test-PimScenarios.ps1'        | Should -Be 0 }
}

Describe 'Workload-connector framework' {
    It 'Get-PimNestedProp reads dotted paths' {
        Get-PimNestedProp ([pscustomobject]@{ a = [pscustomobject]@{ b = [pscustomobject]@{ c = 'v' } } }) 'a.b.c' | Should -Be 'v'
        Get-PimNestedProp ([pscustomobject]@{ a = $null }) 'a.b' | Should -Be $null
    }
    It 'Get-PimWorkloadToken prefers the launcher-supplied token' {
        $global:PIM_WorkloadTokens = @{ arm = 'token-123' }
        Get-PimWorkloadToken -Connector ([pscustomobject]@{ id='t'; auth='arm'; api=[pscustomobject]@{ baseUrl='https://x' } }) | Should -Be 'token-123'
        $global:PIM_WorkloadTokens = $null
    }
    It 'Get-PimWorkloadToken throws for an unknown adapter with no override' {
        { Get-PimWorkloadToken -Connector ([pscustomobject]@{ id='t'; auth='mystery'; api=[pscustomobject]@{ baseUrl='https://x' } }) } | Should -Throw
    }
    It 'every connector JSON is valid + has required ops + known auth' {
        $knownAuth = 'graph','arm','powerbi','devops','businesscentral','dataverse'
        $files = Get-ChildItem (Join-Path $Root 'workloads\connectors') -Filter '*.connector.json'
        $files.Count | Should -BeGreaterThan 0
        foreach ($f in $files) {
            $c = Get-Content $f.FullName -Raw | ConvertFrom-Json   # throws -> It fails, which is the JSON-validity assertion
            $c.id   | Should -Not -BeNullOrEmpty
            $c.auth | Should -BeIn $knownAuth -Because "$($f.Name) auth must be a known adapter"
            $c.api.assign | Should -Not -BeNullOrEmpty -Because "$($f.Name) needs an assign op"
            $c.api.remove | Should -Not -BeNullOrEmpty -Because "$($f.Name) needs a remove op"
            # a connector must list roles via API or carry a static roles array
            ($null -ne $c.api.listRoles -or $null -ne $c.roles) | Should -BeTrue -Because "$($f.Name) needs listRoles or a static roles array"
        }
    }
    It 'Get-PimWorkloadRoles returns the static roles for a no-listRoles connector (powerbi)' {
        $pbi = Get-Content (Join-Path $Root 'workloads\connectors\powerbi.connector.json') -Raw | ConvertFrom-Json
        $roles = @(Get-PimWorkloadRoles -Connector $pbi)
        $roles.Count | Should -Be 4
        ($roles | ForEach-Object { $_.name }) | Should -Contain 'Member'
    }
}

Describe 'Offline feature spot-checks (in-proc)' {
    It 'date expression resolves'      { (Resolve-PimDateExpression -Expression 'FirstWorkdayNextMonth@08:00') | Should -Not -BeNullOrEmpty }
    It 'license status resolves'       { (Get-PimLicense -Refresh).Status | Should -Not -BeNullOrEmpty }
    It 'random password has 4 classes' { $p = New-PimRandomPassword; ($p -cmatch '[A-Z]' -and $p -cmatch '[a-z]' -and $p -match '\d') | Should -BeTrue }
    It 'HighPriv name matches marker'  { 'Admin-X-L0-T0-ID' -match '(?i)(^|[-_.])(L0|T0)([-_.]|$)' | Should -BeTrue }
    It 'Day2Day name does not match'   { 'Admin-X-ID' -match '(?i)(^|[-_.])(L0|T0)([-_.]|$)' | Should -BeFalse }
}
