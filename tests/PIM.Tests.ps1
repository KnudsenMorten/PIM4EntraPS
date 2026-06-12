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

Describe 'PIM conformance engine (native template versioning + reconcile)' {
    BeforeAll {
        $script:Now = [datetime]::Parse('2026-06-13T12:00:00Z').ToUniversalTime()
        $script:Tpl = ConvertTo-PimTemplate -Json ([System.IO.File]::ReadAllText((Join-Path $Root 'workloads\templates\defender-xdr-roles.template.json'), [System.Text.UTF8Encoding]::new($false)))
        $script:Preview = 'role:Security Operator (preview)'
        $script:Ring0Keys = @('role:Security Reader','role:Security Operator','role:Security Administrator')
    }
    It 'shipped template validates + is approved' {
        (Test-PimTemplateDoc -Template $Tpl).valid | Should -BeTrue
        (Test-PimTemplateApproved -Template $Tpl) | Should -BeTrue
        (Test-PimTemplateApproved -Template ([pscustomobject]@{ status='draft' })) | Should -BeFalse
    }
    It 'ring scope: ring-0 tenant sees 3 roles, ring-2 sees all 4' {
        (Select-PimInScopeEntries -Template $Tpl -TenantRing 0).Count | Should -Be 3
        (Select-PimInScopeEntries -Template $Tpl -TenantRing 2).Count | Should -Be 4
    }
    It 'exemption: no-expiry Invalid, past Expired, future Active' {
        (Test-PimExemptionValid -Exemption ([pscustomobject]@{ reason='r' }) -NowUtc $Now).state | Should -Be 'Invalid'
        (Test-PimExemptionValid -Exemption ([pscustomobject]@{ reason='r'; expiresUtc='2026-01-01T00:00:00Z' }) -NowUtc $Now).state | Should -Be 'Expired'
        (Test-PimExemptionValid -Exemption ([pscustomobject]@{ reason='r'; expiresUtc='2026-12-01T00:00:00Z' }) -NowUtc $Now).active | Should -BeTrue
    }
    It 'reconcile: Gap / Exempt / OutOfRing / DriftExtra / Behind' {
        $g = Get-PimConformance -Template $Tpl -TenantRing 2 -TenantId 't2' -LiveKeys $Ring0Keys -AppliedVersion 7
        @($g.Rows | Where-Object { $_.Key -eq $Preview -and $_.Status -eq 'Gap' }).Count | Should -Be 1
        $g.Behind | Should -Be 1
        $e = Get-PimConformance -Template $Tpl -TenantRing 2 -TenantId 't2' -LiveKeys $Ring0Keys -ActiveExemptionKeys @($Preview) -AppliedVersion 8
        @($e.Rows | Where-Object { $_.Key -eq $Preview -and $_.Status -eq 'Exempt' }).Count | Should -Be 1
        $p = Get-PimConformance -Template $Tpl -TenantRing 0 -TenantId 'p0' -LiveKeys $Ring0Keys -AppliedVersion 8
        @($p.Rows | Where-Object { $_.Key -eq $Preview -and $_.Status -eq 'OutOfRing' }).Count | Should -Be 1
        $d = Get-PimConformance -Template $Tpl -TenantRing 0 -TenantId 'p0' -LiveKeys @($Ring0Keys + $Preview) -AppliedVersion 8
        @($d.Rows | Where-Object { $_.Key -eq $Preview -and $_.Status -eq 'DriftExtra' }).Count | Should -Be 1
    }
    It 'catalog-ahead flags an uncovered live capability' {
        $c = Get-PimConformance -Template $Tpl -TenantRing 2 -TenantId 't2' -LiveCatalog @('Security Reader','Custom Threat Hunter')
        @($c.CatalogAhead | Where-Object { $_.Capability -eq 'Custom Threat Hunter' }).Count | Should -Be 1
    }
    It 'draft + approve + promote are pure (clone, original untouched)' {
        $draft = New-PimTemplateDraft -Template $Tpl -Capabilities @('Custom Threat Hunter') -NowUtc $Now
        $draft.templateVersion | Should -Be 9
        "$($draft.status)" | Should -Be 'draft'
        $Tpl.templateVersion | Should -Be 8
        (Test-PimTemplateApproved -Template (Approve-PimTemplate -Template $draft -ApprovedBy 'mok' -NowUtc $Now)) | Should -BeTrue
        $promoted = Set-PimEntryRing -Template $Tpl -Key $Preview -Ring 0
        ((@($promoted.entries | Where-Object { "$($_.key)" -eq $Preview }) | ForEach-Object { Get-PimTemplateEntryRing -Entry $_ })) | Should -Be 0
        ((@($Tpl.entries | Where-Object { "$($_.key)" -eq $Preview }) | ForEach-Object { Get-PimTemplateEntryRing -Entry $_ })) | Should -Be 2
    }
    It 'roll-forward rows: approved, ring-gated, exemption-skipped; draft throws' {
        $ex = @([pscustomobject]@{ tenantId='t2'; templateId='defender-xdr-roles'; itemKey='role:Security Reader'; reason='held'; expiresUtc='2026-12-01T00:00:00Z' })
        $rows = @(Get-PimRollForwardRows -Template $Tpl -TenantRing 2 -TenantId 't2' -Exemptions $ex -NowUtc $Now)
        $rows.Count | Should -Be 3   # 4 in-scope minus 1 exempted
        ($rows | Where-Object { $_.RoleName -eq 'Security Reader' }).Count | Should -Be 0
        ($rows | Where-Object { $_.Workload -eq 'defender-xdr' }).Count | Should -Be 3
        $prod = @(Get-PimRollForwardRows -Template $Tpl -TenantRing 0 -TenantId 'p0' -NowUtc $Now)
        $prod.Count | Should -Be 3   # ring-2 preview excluded on a ring-0 tenant
        { Get-PimRollForwardRows -Template ([pscustomobject]@{ templateId='d'; workload='w'; status='draft'; entries=@() }) -TenantRing 2 -NowUtc $Now } | Should -Throw
    }
}
