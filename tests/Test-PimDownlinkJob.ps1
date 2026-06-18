#Requires -Version 5.1
<#
.SYNOPSIS
  OFFLINE Pester tests for the §31.3 CLOUD-NATIVE downlink as an Azure Container
  Apps scheduled JOB (cron). Asserts the PURE plan brain (engine/_shared/
  PIM-DownlinkJob.ps1) builds the correct `az containerapp job create/update/delete/
  start` arg set + the entrypoint composes downlink->engine in the right order.
  NOTHING touches az / Azure / SQL / HTTP -- az is never invoked.

  Covers:
    * placement: S5 -> central env + multi-tenant SPN ; S6 -> local env + local SPN
    * cron validation: 5-field required; blank/wrong-count rejected
    * create arg set: Schedule trigger + cron + image + command (invokes the
      downlink entrypoint) + identity (MI) + env + NO public ingress + NO inline secret
    * idempotent re-deploy: Exists=$true => `update` (not a second `create`)
    * unregister: `delete --yes`
    * on-demand start: `start`
    * the container command composes the entrypoint with scenario/tenant/ring/baseline
    * env set carries SQL MI coords (no password) + the scenario sync root
    * the entrypoint script parses clean + invokes the scenario runner (downlink then engine)
    * execution verdict: distinguishes "job exists, never ran" from a real
      pulled+synced+applied success

  Run: Invoke-Pester -Path tests\Test-PimDownlinkJob.ps1   (or via tests\Run-AllPimTests.ps1)
#>
[CmdletBinding()] param()

BeforeAll {
    $script:here = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $script:sol  = Split-Path -Parent $script:here
    . (Join-Path $script:sol 'engine\_shared\PIM-DownlinkJob.ps1')
    $script:entry      = Join-Path $script:sol 'tools\pim-engine\downlink-job-entry.ps1'
    $script:deploy     = Join-Path $script:sol 'tools\setup\Deploy-PimDownlinkJob.ps1'

    # join a flat arg array into a single string for substring asserts.
    function ArgStr { param([string[]]$ArgList) return (@($ArgList) -join ' ') }
    # index of a flag, then the value right after it (for "--x value" pairs).
    function ValAfter { param([string[]]$ArgList,[string]$Flag)
        for ($i=0; $i -lt $ArgList.Count; $i++) { if ($ArgList[$i] -eq $Flag) { if ($i+1 -lt $ArgList.Count) { return $ArgList[$i+1] } } }
        return $null
    }
}

Describe 'PIM-DownlinkJob: placement (S5 central / S6 local)' {
    It 'S5 -> central env + multi-tenant SPN + central sync files' {
        $p = Get-PimDownlinkJobPlacement -Scenario S5
        $p.placement | Should -Be 'central'
        $p.spnModel  | Should -Be 'multi-tenant-spn'
        $p.syncFileLocation | Should -Be 'central-msp'
    }
    It 'S6 -> local env + local SPN + local sync files' {
        $p = Get-PimDownlinkJobPlacement -Scenario S6
        $p.placement | Should -Be 'local'
        $p.spnModel  | Should -Be 'local-spn'
        $p.syncFileLocation | Should -Be 'local-slave'
    }
}

Describe 'PIM-DownlinkJob: cron validation' {
    It 'a 5-field cron is valid' {
        (Test-PimDownlinkJobCron -Cron '0 3 * * *').ok | Should -BeTrue
    }
    It 'blank cron is rejected' {
        (Test-PimDownlinkJobCron -Cron '   ').ok | Should -BeFalse
    }
    It 'a 6-field expression is rejected (ACA uses 5-field)' {
        (Test-PimDownlinkJobCron -Cron '0 0 3 * * *').ok | Should -BeFalse
    }
}

Describe 'PIM-DownlinkJob: container command composes the downlink entrypoint' {
    It 'invokes pwsh -File the entrypoint with scenario/tenant/ring/baseline' {
        $cmd = Get-PimDownlinkJobCommand -Scenario S5 -TenantId 'tid-123' -SlaveRing 1 -BaselineUrl 'https://priv/baseline.json'
        $cmd[0] | Should -Be 'pwsh'
        (ArgStr $cmd) | Should -Match 'downlink-job-entry\.ps1'
        (ValAfter $cmd '-Scenario') | Should -Be 'S5'
        (ValAfter $cmd '-TenantId') | Should -Be 'tid-123'
        (ValAfter $cmd '-SlaveRing') | Should -Be '1'
        (ValAfter $cmd '-BaselineUrl') | Should -Be 'https://priv/baseline.json'
    }
    It 'uses -BaselineDocPath when given a mounted file' {
        $cmd = Get-PimDownlinkJobCommand -Scenario S6 -TenantId 'tid' -BaselineDocPath '/sync/baseline.json'
        (ValAfter $cmd '-BaselineDocPath') | Should -Be '/sync/baseline.json'
        (ArgStr $cmd) | Should -Not -Match '-BaselineUrl'
    }
}

Describe 'PIM-DownlinkJob: env set (SQL MI coords, no secret, scenario sync root)' {
    It 'S5 carries the central sync root + SQL coords (no password)' {
        $env = Get-PimDownlinkJobEnv -Scenario S5 -TenantId 'tid' -SqlServerFqdn 'sql.x.net' -SqlDatabase 'PimPlatform'
        ($env -join ' ') | Should -Match 'PIM_StorageBackend=sql'
        ($env -join ' ') | Should -Match 'PIM_SqlServer=sql\.x\.net'
        ($env -join ' ') | Should -Match 'PIM_SyncRootCentral='
        ($env -join ' ') | Should -Not -Match '(?i)password='
    }
    It 'S6 carries the local sync root' {
        $env = Get-PimDownlinkJobEnv -Scenario S6 -TenantId 'tid'
        ($env -join ' ') | Should -Match 'PIM_SyncRootLocal='
        ($env -join ' ') | Should -Not -Match 'PIM_SyncRootCentral='
    }
}

Describe 'PIM-DownlinkJob: az containerapp job create arg set' {
    BeforeAll {
        $cmd = Get-PimDownlinkJobCommand -Scenario S5 -TenantId 'tid' -SlaveRing 1 -BaselineUrl 'https://priv/b.json'
        $env = Get-PimDownlinkJobEnv -Scenario S5 -TenantId 'tid' -SqlServerFqdn 'sql.x.net'
        $script:created = Build-PimDownlinkJobArgs -Action create -JobName 'ca-pim-downlink-s5' -ResourceGroup 'rg-pim' `
            -EnvName 'cae-pim' -Image 'acr.azurecr.io/pim-manager:1.2.3' -AcrServer 'acr.azurecr.io' `
            -Cron '0 3 * * *' -Command $cmd -EnvVars $env
        $script:s = ArgStr $script:created.args
    }
    It 'is a containerapp job create' { $script:s | Should -Match '^containerapp job create' }
    It 'sets the Schedule trigger type' { (ValAfter $script:created.args '--trigger-type') | Should -Be 'Schedule' }
    It 'sets the cron expression' { (ValAfter $script:created.args '--cron-expression') | Should -Be '0 3 * * *' }
    It 'targets the env' { (ValAfter $script:created.args '--environment') | Should -Be 'cae-pim' }
    It 'runs the image' { (ValAfter $script:created.args '--image') | Should -Be 'acr.azurecr.io/pim-manager:1.2.3' }
    It 'command invokes the downlink entrypoint' { $script:s | Should -Match 'downlink-job-entry\.ps1' }
    It 'attaches a managed identity (system, no user MI given)' { $script:s | Should -Match '--mi-system-assigned' }
    It 'pulls the registry via MI (no creds)' {
        (ValAfter $script:created.args '--registry-identity') | Should -Be 'system'
        $script:s | Should -Not -Match '--registry-password'
    }
    It 'has NO public ingress (a Job is not an app -- no --ingress at all)' {
        $script:s | Should -Not -Match '--ingress'
        $script:created.private | Should -BeTrue
    }
    It 'has NO inline secret' {
        $script:created.hasInlineSecret | Should -BeFalse
        $script:s | Should -Not -Match '(?i)(password=|client[_-]?secret=|accountkey=)'
    }
    It 'attaches a USER-assigned MI when supplied' {
        $u = Build-PimDownlinkJobArgs -Action create -JobName 'j' -ResourceGroup 'rg' -EnvName 'cae' `
            -Image 'a/i:t' -AcrServer 'a' -Cron '0 3 * * *' -IdentityResourceId '/subscriptions/.../umi'
        (ArgStr $u.args) | Should -Match '--mi-user-assigned'
        (ValAfter $u.args '--mi-user-assigned') | Should -Be '/subscriptions/.../umi'
    }
    It 'rejects a bad cron' {
        (Build-PimDownlinkJobArgs -Action create -JobName 'j' -ResourceGroup 'rg' -EnvName 'cae' -Image 'a/i:t' -AcrServer 'a' -Cron 'nope').ok | Should -BeFalse
    }
}

Describe 'PIM-DownlinkJob: idempotent re-deploy + unregister + start' {
    It 'Exists=$false => create' {
        $p = Get-PimDownlinkJobDeployPlan -Scenario S5 -TenantId 'tid' -JobName 'j' -ResourceGroup 'rg' `
            -EnvName 'cae' -Image 'a/i:t' -AcrServer 'a' -Cron '0 3 * * *' -Exists $false
        $p.action | Should -Be 'create'
        (ArgStr $p.jobArgs.args) | Should -Match '^containerapp job create'
    }
    It 'Exists=$true => update (not a second create)' {
        $p = Get-PimDownlinkJobDeployPlan -Scenario S5 -TenantId 'tid' -JobName 'j' -ResourceGroup 'rg' `
            -EnvName 'cae' -Image 'a/i:t' -AcrServer 'a' -Cron '0 3 * * *' -Exists $true
        $p.action | Should -Be 'update'
        (ArgStr $p.jobArgs.args) | Should -Match '^containerapp job update'
        (ValAfter $p.jobArgs.args '--cron-expression') | Should -Be '0 3 * * *'
    }
    It 'unregister => delete --yes' {
        $d = Build-PimDownlinkJobArgs -Action delete -JobName 'ca-pim-downlink-s5' -ResourceGroup 'rg'
        (ArgStr $d.args) | Should -Match '^containerapp job delete'
        (ArgStr $d.args) | Should -Match '--yes'
    }
    It 'start => one on-demand execution' {
        $st = Build-PimDownlinkJobArgs -Action start -JobName 'ca-pim-downlink-s5' -ResourceGroup 'rg'
        (ArgStr $st.args) | Should -Match '^containerapp job start'
    }
}

Describe 'PIM-DownlinkJob: execution verdict (job exists != a run happened)' {
    It 'no execution => NOT verified (job exists but never ran)' {
        $v = Get-PimDownlinkJobExecutionVerdict -Status '' -LogText ''
        $v.ran | Should -BeFalse
        $v.verified | Should -BeFalse
        $v.reason | Should -Match 'never run'
    }
    It 'Succeeded but no downlink evidence => NOT verified' {
        $v = Get-PimDownlinkJobExecutionVerdict -Status 'Succeeded' -LogText 'container started'
        $v.succeeded | Should -BeTrue
        $v.verified  | Should -BeFalse
    }
    It 'Failed status => NOT verified' {
        $v = Get-PimDownlinkJobExecutionVerdict -Status 'Failed' -LogText 'baseline: loaded; staged files: written; engine-apply'
        $v.verified | Should -BeFalse
    }
    It 'Succeeded + pulled + synced + applied evidence => VERIFIED' {
        $log = @(
            '[downlink-job] baseline: loaded from /sync/baseline.json'
            'DOWNLINK APPLIED: 3 admins reach slave ring 1'
            '  staged files: written:admins.sync.json'
            '  step [OK] engine-apply -- engine ran'
            'SCENARIO RUN S5: OK'
        ) -join "`n"
        $v = Get-PimDownlinkJobExecutionVerdict -Status 'Succeeded' -LogText $log
        $v.pulled | Should -BeTrue
        $v.synced | Should -BeTrue
        $v.applied | Should -BeTrue
        $v.verified | Should -BeTrue
    }
}

Describe 'PIM-DownlinkJob: entrypoint + deploy scripts parse + compose correctly' {
    It 'downlink-job-entry.ps1 parses clean' {
        $errs = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script:entry, [ref]$null, [ref]$errs) | Out-Null
        @($errs).Count | Should -Be 0
    }
    It 'Deploy-PimDownlinkJob.ps1 parses clean' {
        $errs = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script:deploy, [ref]$null, [ref]$errs) | Out-Null
        @($errs).Count | Should -Be 0
    }
    It 'the entrypoint invokes the scenario runner (downlink-sync then engine-apply)' {
        $txt = Get-Content -LiteralPath $script:entry -Raw
        $txt | Should -Match 'Invoke-PimScenarioRun\.ps1'
        # runner composes downlink first then engine (its own doc + Get-PimScenarioRunPlan order).
        $txt | Should -Match 'downlink'
        $txt | Should -Match 'engine'
    }
    It 'the entrypoint defaults to APPLY (WhatIfMode is a switch, off by default for a scheduled run)' {
        $txt = Get-Content -LiteralPath $script:entry -Raw
        $txt | Should -Match '\[switch\]\$WhatIfMode'
        $txt | Should -Not -Match '\$WhatIfMode\s*=\s*\$true'
    }
    It 'the deploy script never emits --ingress for the Job' {
        $txt = Get-Content -LiteralPath $script:deploy -Raw
        $txt | Should -Not -Match "'--ingress'"
    }
}
