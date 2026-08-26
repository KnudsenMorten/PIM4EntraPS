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

    # CODE-ONLY view of a script: parse it and drop every Comment token.
    # 🪤 Written because the recorded trap bit before: a source-scanning assert matched the COMMENT
    # that explained the defect, so documenting a fix is what broke its own test. Any assert that
    # claims "the code does X" must run through this, never over the raw file text.
    function script:Get-PimCodeOnly {
        param([Parameter(Mandatory)][string]$Path)
        $tokens = $null; $errs = $null
        [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs) | Out-Null
        return ((@($tokens) | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' ')
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

Describe 'PIM-DownlinkJob: az containerapp job create -- YAML deploy (BUG-38)' {
    # 🪤 These assertions used to read --trigger-type / --cron-expression / --environment / --image
    # / --command off the ARGUMENT ARRAY, and they all passed -- on an arg set the CLI would have
    # REFUSED. `az containerapp job create --command pwsh -NoProfile -File x` fails with
    # "unrecognized arguments", because the parser reads any '-'-prefixed token as an OPTION, and
    # every downlink command is exactly that shape. Asserting the array we build proves nothing
    # about what az accepts, so the shape now asserted is the YAML the worker apps and the
    # ESTATE-06 tick Job already deploy with.
    BeforeAll {
        $cmd = Get-PimDownlinkJobCommand -Scenario S5 -TenantId 'tid' -SlaveRing 1 -BaselineUrl 'https://priv/b.json'
        $env = Get-PimDownlinkJobEnv -Scenario S5 -TenantId 'tid' -SqlServerFqdn 'sql.x.net'
        $script:created = Build-PimDownlinkJobArgs -Action create -JobName 'ca-pim-downlink-s5' -ResourceGroup 'rg-pim' `
            -EnvName 'cae-pim' -Image 'acr.azurecr.io/pim-manager:1.2.3' -AcrServer 'acr.azurecr.io' `
            -Cron '0 3 * * *' -Command $cmd -EnvVars $env `
            -YamlPath 'C:\tmp\job.yaml' -Location 'swedencentral' -EnvironmentId '/subscriptions/s/resourceGroups/rg-pim/providers/Microsoft.App/managedEnvironments/cae-pim'
        $script:s = ArgStr $script:created.args
        $script:y = "$($script:created.yaml)"
    }
    It 'is a containerapp job create' { $script:s | Should -Match '^containerapp job create' }
    It 'deploys via --yaml, NOT --command (the CLI cannot parse dashed args)' {
        $script:s | Should -Match '--yaml'
        $script:s | Should -Not -Match '--command'
    }
    It 'passes the yaml PATH on the command line and returns the yaml TEXT' {
        (ValAfter $script:created.args '--yaml') | Should -Be 'C:\tmp\job.yaml'
        $script:y | Should -Not -BeNullOrEmpty
    }
    It 'yaml sets the Schedule trigger type' { $script:y | Should -Match 'triggerType:\s*Schedule' }
    It 'yaml sets the cron expression' { $script:y | Should -Match 'cronExpression:\s*"0 3 \* \* \*"' }
    It 'yaml targets the environment by ARM id' { $script:y | Should -Match 'environmentId:\s*/subscriptions/s/.*/managedEnvironments/cae-pim' }
    It 'yaml runs the image' { $script:y | Should -Match 'image:\s*acr\.azurecr\.io/pim-manager:1\.2\.3' }
    It 'yaml splits command from args so a leading dash is a VALUE, not an option' {
        # This split IS the fix: `command: [pwsh]` + a separate quoted args array.
        $script:y | Should -Match 'command:\s*\[pwsh\]'
        $script:y | Should -Match 'args:\s*\["-NoProfile"'
    }
    It 'command invokes the downlink entrypoint' { $script:y | Should -Match 'downlink-job-entry\.ps1' }
    It 'yaml carries the scenario/tenant/ring through to the entrypoint' {
        $script:y | Should -Match '"-Scenario","S5"'
        $script:y | Should -Match '"-TenantId","tid"'
        $script:y | Should -Match '"-SlaveRing","1"'
    }
    It 'attaches a managed identity (system, no user MI given)' { $script:y | Should -Match 'identity:\s*\{\s*type:\s*SystemAssigned' }
    It 'pulls the registry via MI (no creds)' {
        $script:y | Should -Match 'registries:\s*\[\s*\{\s*server:\s*acr\.azurecr\.io,\s*identity:\s*"system"'
        $script:y | Should -Not -Match '(?i)passwordSecretRef|registry-password'
    }
    It 'BUG-42: with a user-assigned MI attached, THAT identity pulls -- not system' {
        # A system identity cannot pull the FIRST image: it does not exist until the job does.
        # Defaulting the registry identity to "system" beside a UAMI told ACA to pull with the one
        # identity that could not, and nothing granted the system identity AcrPull in that branch.
        $u = Build-PimDownlinkJobArgs -Action create -JobName 'j' -ResourceGroup 'rg' -EnvName 'cae' `
            -Image 'a/i:t' -AcrServer 'acr.azurecr.io' -Cron '0 3 * * *' -IdentityResourceId '/subs/umi' `
            -YamlPath 'C:\tmp\j.yaml' -Location 'swedencentral' -EnvironmentId '/subs/x'
        "$($u.yaml)" | Should -Match 'registries:\s*\[\s*\{\s*server:\s*acr\.azurecr\.io,\s*identity:\s*"/subs/umi"'
    }
    It 'BUG-42: with NO user-assigned MI, the system identity still pulls' {
        $s2 = Build-PimDownlinkJobArgs -Action create -JobName 'j' -ResourceGroup 'rg' -EnvName 'cae' `
            -Image 'a/i:t' -AcrServer 'acr.azurecr.io' -Cron '0 3 * * *' `
            -YamlPath 'C:\tmp\j.yaml' -Location 'swedencentral' -EnvironmentId '/subs/x'
        "$($s2.yaml)" | Should -Match 'identity:\s*"system"'
    }
    It 'BUG-42: an EXPLICIT -RegistryIdentity still wins (auto is a default, not a policy)' {
        $e = Build-PimDownlinkJobArgs -Action create -JobName 'j' -ResourceGroup 'rg' -EnvName 'cae' `
            -Image 'a/i:t' -AcrServer 'acr.azurecr.io' -Cron '0 3 * * *' -IdentityResourceId '/subs/umi' `
            -RegistryIdentity 'system' -YamlPath 'C:\tmp\j.yaml' -Location 'swedencentral' -EnvironmentId '/subs/x'
        "$($e.yaml)" | Should -Match 'identity:\s*"system"'
    }
    It 'has NO public ingress (a Job is not an app -- no ingress at all)' {
        $script:s | Should -Not -Match '--ingress'
        $script:y | Should -Not -Match 'ingress:'
        $script:created.private | Should -BeTrue
    }
    It 'has NO inline secret -- and the guard reads the YAML, where the env now lives' {
        $script:created.hasInlineSecret | Should -BeFalse
        $script:y | Should -Not -Match '(?i)(password=|client[_-]?secret=|accountkey=)'
    }
    It 'DETECTS an inline secret that is now carried in the yaml, not the args' {
        # Moving env into the YAML must not disarm the secret guard -- the arg scan alone would
        # report "clean" forever once nothing sensitive rides on the command line.
        $bad = Build-PimDownlinkJobArgs -Action create -JobName 'j' -ResourceGroup 'rg' -EnvName 'cae' `
            -Image 'a/i:t' -AcrServer 'a' -Cron '0 3 * * *' -EnvVars @('PIM_CS=Server=x;Password=hunter2') `
            -YamlPath 'C:\tmp\j.yaml' -Location 'swedencentral' -EnvironmentId '/subs/x'
        $bad.hasInlineSecret | Should -BeTrue
    }
    It 'attaches a USER-assigned MI when supplied' {
        $u = Build-PimDownlinkJobArgs -Action create -JobName 'j' -ResourceGroup 'rg' -EnvName 'cae' `
            -Image 'a/i:t' -AcrServer 'a' -Cron '0 3 * * *' -IdentityResourceId '/subscriptions/.../umi' `
            -YamlPath 'C:\tmp\j.yaml' -Location 'swedencentral' -EnvironmentId '/subs/x'
        "$($u.yaml)" | Should -Match 'userAssignedIdentities:\s*\{\s*"/subscriptions/\.\.\./umi"'
    }
    It 'QUOTES a combined identity type (an unquoted comma silently degrades it)' {
        $b = Build-PimDownlinkJobArgs -Action create -JobName 'j' -ResourceGroup 'rg' -EnvName 'cae' `
            -Image 'a/i:t' -AcrServer 'a' -Cron '0 3 * * *' -IdentityResourceId '/subs/umi' -SystemAssigned `
            -YamlPath 'C:\tmp\j.yaml' -Location 'swedencentral' -EnvironmentId '/subs/x'
        "$($b.yaml)" | Should -Match 'type:\s*"SystemAssigned, UserAssigned"'
    }
    It 'rejects a bad cron' {
        (Build-PimDownlinkJobArgs -Action create -JobName 'j' -ResourceGroup 'rg' -EnvName 'cae' -Image 'a/i:t' -AcrServer 'a' -Cron 'nope' `
            -YamlPath 'C:\tmp\j.yaml' -Location 'swedencentral' -EnvironmentId '/subs/x').ok | Should -BeFalse
    }
    It 'REFUSES to build without the facts the YAML needs (no silent half-deploy)' {
        (Build-PimDownlinkJobArgs -Action create -JobName 'j' -ResourceGroup 'rg' -EnvName 'cae' -Image 'a/i:t' -Cron '0 3 * * *' `
            -Location 'swedencentral' -EnvironmentId '/subs/x').ok | Should -BeFalse   # no -YamlPath
        (Build-PimDownlinkJobArgs -Action create -JobName 'j' -ResourceGroup 'rg' -EnvName 'cae' -Image 'a/i:t' -Cron '0 3 * * *' `
            -YamlPath 'C:\tmp\j.yaml' -EnvironmentId '/subs/x').ok | Should -BeFalse    # no -Location
        (Build-PimDownlinkJobArgs -Action create -JobName 'j' -ResourceGroup 'rg' -EnvName 'cae' -Image 'a/i:t' -Cron '0 3 * * *' `
            -YamlPath 'C:\tmp\j.yaml' -Location 'swedencentral').ok | Should -BeFalse   # no -EnvironmentId
    }
    It 'accepts a DIGEST-pinned image reference (BUG-40)' {
        $d = Build-PimDownlinkJobArgs -Action create -JobName 'j' -ResourceGroup 'rg' -EnvName 'cae' `
            -Image ('acr.azurecr.io/pim-manager@sha256:' + ('a' * 64)) -AcrServer 'acr.azurecr.io' -Cron '0 3 * * *' `
            -YamlPath 'C:\tmp\j.yaml' -Location 'swedencentral' -EnvironmentId '/subs/x'
        "$($d.yaml)" | Should -Match 'image:\s*acr\.azurecr\.io/pim-manager@sha256:a{64}'
    }
}

Describe 'PIM-DownlinkJob: idempotent re-deploy + unregister + start' {
    It 'Exists=$false => create' {
        $p = Get-PimDownlinkJobDeployPlan -Scenario S5 -TenantId 'tid' -JobName 'j' -ResourceGroup 'rg' `
            -EnvName 'cae' -Image 'a/i:t' -AcrServer 'a' -Cron '0 3 * * *' -Exists $false `
            -YamlPath 'C:\tmp\j.yaml' -Location 'swedencentral' -EnvironmentId '/subs/x'
        $p.action | Should -Be 'create'
        (ArgStr $p.jobArgs.args) | Should -Match '^containerapp job create'
    }
    It 'Exists=$true => update (not a second create), and the cron stays current' {
        $p = Get-PimDownlinkJobDeployPlan -Scenario S5 -TenantId 'tid' -JobName 'j' -ResourceGroup 'rg' `
            -EnvName 'cae' -Image 'a/i:t' -AcrServer 'a' -Cron '0 3 * * *' -Exists $true `
            -YamlPath 'C:\tmp\j.yaml' -Location 'swedencentral' -EnvironmentId '/subs/x'
        $p.action | Should -Be 'update'
        (ArgStr $p.jobArgs.args) | Should -Match '^containerapp job update'
        # the cron moved into the YAML with the rest of the spec -- an update re-sends the whole
        # document, so re-scheduling on re-deploy still works.
        "$($p.jobArgs.yaml)" | Should -Match 'cronExpression:\s*"0 3 \* \* \*"'
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
    It 'BUG-43: no helper takes a parameter named $Args (an automatic variable binds NOTHING)' {
        # `param([string[]]$Args)` does not fail -- it silently binds nothing, so the caller's
        # array is discarded and `& az @Args` runs BARE az, which prints help and exits 0. Every
        # az call in this script therefore did nothing while reporting success. Measured live.
        $src = Get-Content (Join-Path $PSScriptRoot '..\tools\setup\Deploy-PimDownlinkJob.ps1') -Raw
        # anchored to a real declaration at line start -- the comment above the fix quotes the
        # broken form deliberately, and must not trip its own guard.
        $src | Should -Not -Match '(?m)^\s*param\(\s*\[string\[\]\]\$Args\b'
        $src | Should -Match 'Invoke-Az -AzArgs'
    }
    It 'BUG-43: Invoke-Az REFUSES an empty arg set instead of running bare az' {
        $src = Get-Content (Join-Path $PSScriptRoot '..\tools\setup\Deploy-PimDownlinkJob.ps1') -Raw
        $src | Should -Match 'refusing to run bare az and report success'
    }
    It 'BUG-43: a param named $Args really does bind nothing (the mechanism, proven)' {
        function script:__probe { param([string[]]$Args) return @($Args).Count }
        (script:__probe -Args @('a','b','c')) | Should -Be 0
        function script:__probe2 { param([string[]]$AzArgs) return @($AzArgs).Count }
        (script:__probe2 -AzArgs @('a','b','c')) | Should -Be 3
    }
    # -----------------------------------------------------------------------
    # BUG-71 -- the create that produces a job which can never run.
    # 🪤 THESE ASSERTIONS READ CODE, NOT COMMENTS. The recorded trap: a source-scanning assert
    # matched the comment that EXPLAINED a defect, so the fixed file failed its own test. The
    # tokenizer drops Comment tokens, which means the long BUG-71 comment block in the deploy
    # script cannot satisfy any assert below -- only the executable text can.
    # -----------------------------------------------------------------------
    It 'BUG-71: the comment-stripper really does drop comments (the mechanism, proven first)' {
        $tmp = Join-Path $TestDrive 'strip-probe.ps1'
        Set-Content -LiteralPath $tmp -Value "# az identity list -- only in a comment`n`$x = 1" -Encoding utf8
        $code = script:Get-PimCodeOnly $tmp
        $code | Should -Not -Match 'az identity list'
        $code | Should -Match '\$x'
    }
    It 'BUG-71: a create with no -IdentityResourceId auto-resolves the user-assigned MI' {
        # The unattended path. Without this the deploy silently falls back to the system identity,
        # which BUG-42 already established cannot pull the FIRST image -- so the job lands Failed.
        $code = script:Get-PimCodeOnly $script:deploy
        $code | Should -Match 'az identity list'
        $code | Should -Match '\$IdentityResourceId\s*=\s*"\$\(\$pick\[0\]\.id\)"'
    }
    It 'BUG-71: with NO user-assigned MI available the create is REFUSED, not attempted' {
        # Emitting the job anyway is what produced provisioningState=Failed + zero executions.
        $code = script:Get-PimCodeOnly $script:deploy
        $code | Should -Match 'REFUSING to create'
        $code | Should -Match 'cannot pull the first image'
    }
    It 'BUG-71d: the identity auto-resolve is NOT limited to create (an update re-renders the whole YAML)' {
        # Measured: guarding this with `-and -not $exists` meant an UPDATE re-rendered the YAML with
        # no identity, so ACA reverted the registry identity to 'system' and the pull broke on a job
        # that had been working ten minutes earlier. The YAML is a full document -- what it omits is
        # removed, not preserved.
        # 🪤 Compare with whitespace REMOVED: the tokenizer re-spaces source (`.Trim()` comes back
        # as `. Trim ( )`), so a literal regex over its output tests the tokenizer's formatting
        # rather than the code. Squeezing spaces out of both sides asserts the logic instead.
        $flat = (script:Get-PimCodeOnly $script:deploy) -replace '\s',''
        $flat | Should -Match '-not"\$IdentityResourceId"\.Trim\(\)-and-not\$WhatIfPreference\)'
        $flat | Should -Not -Match '-not"\$IdentityResourceId"\.Trim\(\)-and-not\$WhatIfPreference-and-not\$exists'
    }
    It 'BUG-71e: an IDENTITY change recreates the job (ACA cannot swap identity on update)' {
        # Without this, the deploy resolves the right MI, tries to apply it via update, and dies
        # with (FailedIdentityOperation) -- leaving the broken job in place. Resolving the identity
        # and being ABLE to apply it are two different fixes.
        $flat = (script:Get-PimCodeOnly $script:deploy) -replace '\s',''
        $flat | Should -Match 'deletejob\$JobName\(identitychange\)'
    }
    It 'BUG-71e: the identity check runs AFTER the auto-resolve, not before it' {
        # Ordering IS the fix here: placed first, the guard reads an empty $IdentityResourceId,
        # finds nothing to compare, and skips -- sending the deploy back to the failing update.
        $code = script:Get-PimCodeOnly $script:deploy
        $posResolve = $code.IndexOf('az identity list')
        $posCheck   = $code.IndexOf('identity change')
        $posResolve | Should -BeGreaterThan 0
        $posCheck   | Should -BeGreaterThan $posResolve
    }
    It 'BUG-71a: an existing FAILED job is DELETED and recreated, never updated' {
        # An update does not re-run the wiring that failed, so a re-run of the deploy against a
        # broken job would do nothing, successfully. Repairing it by hand is the step that must
        # not depend on an operator already knowing the answer.
        $code = script:Get-PimCodeOnly $script:deploy
        $code | Should -Match "-ne 'Succeeded'"
        $code | Should -Match 'delete failed job'
        $code | Should -Match '\$exists\s*=\s*\$false'
    }
    It 'BUG-71b: the deploy VERIFIES provisioningState and fails on anything but Succeeded' {
        # The image field matches even on a Failed job -- it records what ARM was asked to run.
        $code = script:Get-PimCodeOnly $script:deploy
        $code | Should -Match 'properties\.provisioningState'
        $code | Should -Match "-ne 'Succeeded'"
    }
    It 'BUG-71c: the post-create AcrPull grant reports failure instead of claiming success' {
        $code = script:Get-PimCodeOnly $script:deploy
        $code | Should -Match 'AcrPull grant to the Job''s system MI FAILED'
        # and it must not be silenced back into a swallowed call
        $code | Should -Not -Match '--role AcrPull --scope \$acrId -o none 2>\$null'
    }

    # -----------------------------------------------------------------------
    # BUG-72 (engine credential) + BUG-73 (SAS baseline URL). These run against the PURE
    # planner, so they prove the emitted document -- not just that the source mentions a flag.
    # -----------------------------------------------------------------------
    It 'BUG-72: an engine client id + secret emit PIM_ClientId as a VALUE and the secret as a REF' {
        $ev = Get-PimDownlinkJobEnv -Scenario S6 -TenantId 't1' -EngineClientId 'cid-123' -EngineSecretRef 'pim-engine-client-secret'
        (ArgStr $ev) | Should -Match 'PIM_ClientId=cid-123'
        (ArgStr $ev) | Should -Match 'AZURE_CLIENT_SECRET=secretref:pim-engine-client-secret'
        # the secret VALUE must never appear in an env entry
        (ArgStr $ev) | Should -Not -Match 'AZURE_CLIENT_SECRET=(?!secretref:)'
    }
    It 'BUG-72: NO cert thumbprint is ever emitted (a container has no cert store)' {
        # Copying the tick job's PIM_CertThumbprint would break the working MI path AND
        # authenticate nothing -- measured live on ca-pim-tick.
        $ev = Get-PimDownlinkJobEnv -Scenario S6 -TenantId 't1' -EngineClientId 'cid-123' -EngineSecretRef 'r'
        (ArgStr $ev) | Should -Not -Match 'CertThumbprint'
    }
    It 'BUG-72: with no engine identity the env stays MI-only (unchanged behaviour)' {
        $ev = Get-PimDownlinkJobEnv -Scenario S6 -TenantId 't1'
        (ArgStr $ev) | Should -Not -Match 'PIM_ClientId'
        (ArgStr $ev) | Should -Not -Match 'AZURE_CLIENT_SECRET'
    }
    It 'BUG-73: a SAS baseline URL goes to a SECRET + env ref, and NOT onto the command line' {
        $p = Get-PimDownlinkJobDeployPlan -Scenario S6 -TenantId 't1' -JobName 'j' -ResourceGroup 'rg' `
            -EnvName 'e' -Image 'img@sha256:abc' -AcrServer 'a.azurecr.io' -Cron '0 3 * * *' `
            -BaselineSasUrl 'https://acct.blob.core.windows.net/baselines/b.json?sv=2024-01-01&sig=SECRETSIG' `
            -YamlPath 'x.yaml' -Location 'swedencentral' -EnvironmentId '/envid'
        # the command must not carry it
        (ArgStr $p.command) | Should -Not -Match 'sig=SECRETSIG'
        (ArgStr $p.command) | Should -Not -Match '-BaselineUrl'
        # the env references it
        (ArgStr $p.envVars) | Should -Match 'PIM_BaselineUrl=secretref:pim-baseline-url'
        # the yaml renders it as a secretRef, and the value lives only in the secrets block
        $p.jobArgs.yaml | Should -Match 'name: PIM_BaselineUrl, secretRef: pim-baseline-url'
        $p.jobArgs.yaml | Should -Match 'secrets: \[ \{ name: pim-baseline-url'
    }
    It 'BUG-73: the guard now treats a SAS as a secret (it did not before)' {
        # A SAS carries no `client_secret=` / `accountkey=`, so the old pattern set missed it and a
        # SAS-bearing URL on the command line reported hasInlineSecret=$false.
        $bad = Build-PimDownlinkJobArgs -Action create -JobName 'j' -ResourceGroup 'rg' -EnvName 'e' `
            -Image 'img@sha256:abc' -AcrServer 'a.azurecr.io' -Cron '0 3 * * *' `
            -Command @('pwsh','-File','/x.ps1','-BaselineUrl','https://a.blob.core.windows.net/b.json?sv=2024&sig=LEAKED') `
            -YamlPath 'x.yaml' -Location 'l' -EnvironmentId '/e'
        $bad.hasInlineSecret | Should -BeTrue
    }
    It 'BUG-73: the sanctioned secrets block does NOT trip the guard (or the mechanism is unusable)' {
        $good = Get-PimDownlinkJobDeployPlan -Scenario S6 -TenantId 't1' -JobName 'j' -ResourceGroup 'rg' `
            -EnvName 'e' -Image 'img@sha256:abc' -AcrServer 'a.azurecr.io' -Cron '0 3 * * *' `
            -BaselineSasUrl 'https://acct.blob.core.windows.net/b.json?sv=2024&sig=OK' `
            -EngineClientId 'cid' -EngineClientSecret 'shhh' `
            -YamlPath 'x.yaml' -Location 'l' -EnvironmentId '/e'
        $good.jobArgs.hasInlineSecret | Should -BeFalse
    }
    It 'BUG-72/73: the deploy shreds the yaml, which now carries secret values' {
        $code = script:Get-PimCodeOnly $script:deploy
        $code | Should -Match 'Remove-Item -LiteralPath \$yamlPath'
        $code | Should -Match 'finally'
    }

    It 'the deploy script never emits --ingress for the Job' {
        $txt = Get-Content -LiteralPath $script:deploy -Raw
        $txt | Should -Not -Match "'--ingress'"
    }
}
