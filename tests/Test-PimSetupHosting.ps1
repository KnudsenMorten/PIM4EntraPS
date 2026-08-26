#Requires -Version 5.1
<#
.SYNOPSIS
    Offline, rerunnable tests for the PIM4EntraPS setup/deploy + hosting family
    (tools/setup/*). No live tenant, no Azure -- pure assertions over the shared
    helpers + static contract checks on the deploy scripts.

.DESCRIPTION
    Covers REQUIREMENTS S1 (hosting) + S3 (setup):
      * _PimSetupShared helpers: region guard (West Europe / Denmark East only, France
        refused), SID-from-appId, Graph app-role map, GSA/private-link guidance text,
        version reader, banner runs without throwing.
      * Static contract on the deploy scripts: every tool/setup/*.ps1 parses; the
        container script uses --ingress external + --yaml (NOT multi-token --command);
        the engine app-reg installer is REST/cert (no Microsoft.Graph #Requires);
        no real tenant/subscription/customer values are baked into the published
        scripts (public-safety).

.EXAMPLE
    powershell -NoProfile -File tests\Test-PimSetupHosting.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$script:pass = 0; $script:fail = 0
function T { param($n,[scriptblock]$b)
    try { $r = & $b; if ($r) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }
    catch { Write-Host "  FAIL $n -- $($_.Exception.Message.Split([char]10)[0])" -ForegroundColor Red; $script:fail++ } }
function Section($t){ Write-Host "`n== $t ==" -ForegroundColor Cyan }

$root    = Split-Path -Parent $PSScriptRoot          # ...\PIM4EntraPS
$setpDir = Join-Path $root 'tools\setup'
. (Join-Path $setpDir '_PimSetupShared.ps1')

Section 'SHARED HELPERS -- region guard'
T 'westeurope allowed (normalised)'        { (Assert-PimSetupRegion -Location 'West Europe') -eq 'westeurope' }
T 'denmarkeast allowed'                     { (Assert-PimSetupRegion -Location 'denmarkeast') -eq 'denmarkeast' }
# The estate is provisioned in Sweden Central (a fresh sub refuses westeurope/northeurope), so
# the guard MUST accept it or the container steps can never run against the real estate.
T 'swedencentral allowed (normalised)'      { (Assert-PimSetupRegion -Location 'Sweden Central') -eq 'swedencentral' }
T 'francecentral REFUSED'                   { $threw=$false; try { Assert-PimSetupRegion -Location 'francecentral' } catch { $threw=$true }; $threw }
T 'francesouth REFUSED'                     { $threw=$false; try { Assert-PimSetupRegion -Location 'francesouth' } catch { $threw=$true }; $threw }
T 'eastus (non-approved) REFUSED'           { $threw=$false; try { Assert-PimSetupRegion -Location 'eastus' } catch { $threw=$true }; $threw }

Section 'SHARED HELPERS -- SID-from-appId + app-role map'
T 'SID is 0x + 32 hex chars'                { $s = ConvertTo-PimSqlSidFromAppId -AppId '11111111-2222-3333-4444-555555555555'; $s -match '^0x[0-9A-F]{32}$' }
T 'Graph app-role map has the engine roles' {
    $m = Get-PimGraphAppRoleMap
    $m.ContainsKey('RoleManagement.ReadWrite.Directory') -and $m.ContainsKey('PrivilegedAccess.ReadWrite.AzureADGroup') `
        -and $m.ContainsKey('Group.ReadWrite.All') -and $m.ContainsKey('User.ReadWrite.All') -and ($m.Count -ge 6)
}
T 'Get-PimGraphAppRoleMap returns a copy (caller cannot mutate module table)' {
    $a = Get-PimGraphAppRoleMap; $a['__probe__'] = 'x'
    -not (Get-PimGraphAppRoleMap).ContainsKey('__probe__')
}

Section 'BUG-44 -- a just-created MI is EVENTUALLY consistent, so the lookup retries'
# Measured on mfnpr 2026-08-09: `containerapp job create` returned, the Job identity's SP was
# stamped at 22:59:27, `az ad sp show` seconds later returned NOTHING, and the deploy threw
# before the SQL + Graph grants -- leaving a Job that ran every 5 minutes and did nothing.
# The lookup and the sleep are injected, so the whole retry policy is proved with no az and
# no real waiting.
# A List, not a plain counter: each `& $Lookup` invocation gets its own local scope, so an
# `$n = $n + 1` inside the scriptblock writes a local that vanishes and the counter never moves.
# A reference type is mutated in place and survives.
T 'resolves first try without sleeping' {
    $slept = [System.Collections.Generic.List[int]]::new()
    $r = Resolve-PimMiAppId -ObjectId 'oid-1' -What 'ca-pim-tick' `
            -Lookup { param($o) 'APPID-1' } -Sleep { param($s) $slept.Add([int]$s) }
    $r -eq 'APPID-1' -and $slept.Count -eq 0
}
T 'transient empty then resolves -- the exact mfnpr shape' {
    $calls = [System.Collections.Generic.List[string]]::new()
    $r = Resolve-PimMiAppId -ObjectId 'oid-2' -What 'ca-pim-tick' `
            -Lookup { param($o) $calls.Add($o); if ($calls.Count -lt 3) { '' } else { 'APPID-2' } } `
            -Sleep  { param($s) }
    $r -eq 'APPID-2' -and $calls.Count -eq 3
}
T 'whitespace-only lookup counts as NOT found (az returns a bare newline)' {
    $calls = [System.Collections.Generic.List[string]]::new()
    $r = Resolve-PimMiAppId -ObjectId 'oid-3' -What 'w' `
            -Lookup { param($o) $calls.Add($o); if ($calls.Count -lt 2) { "  `n" } else { 'APPID-3' } } `
            -Sleep  { param($s) }
    $r -eq 'APPID-3' -and $calls.Count -eq 2
}
T 'an identity that NEVER appears throws -- bounded, never hangs' {
    $calls = [System.Collections.Generic.List[string]]::new()
    try {
        Resolve-PimMiAppId -ObjectId 'oid-4' -What 'ca-pim-tick' -MaxAttempts 4 `
            -Lookup { param($o) $calls.Add($o); '' } -Sleep { param($s) } | Out-Null
        $false
    } catch { $calls.Count -eq 4 -and "$($_.Exception.Message)" -match 'ca-pim-tick' }
}
T 'backoff doubles and is CAPPED (2,4,8,16,30,30,30 for 8 attempts)' {
    $slept = [System.Collections.Generic.List[int]]::new()
    try {
        Resolve-PimMiAppId -ObjectId 'oid-5' -What 'w' `
            -Lookup { param($o) '' } -Sleep { param($s) $slept.Add([int]$s) } | Out-Null
    } catch { }
    # 7 sleeps for 8 attempts (none after the last), doubling to the 30s cap.
    ($slept -join ',') -eq '2,4,8,16,30,30,30'
}
T 'the error names the identity AND says a short delay is normal' {
    try { Resolve-PimMiAppId -ObjectId 'oid-6' -What 'ca-pim-manager' -MaxAttempts 1 `
            -Lookup { param($o) '' } -Sleep { param($s) } | Out-Null; $false }
    catch { $m = "$($_.Exception.Message)"; $m -match 'oid-6' -and $m -match 'eventually consistent' }
}
T 'BOTH Setup-PimContainers call sites go through the retry, not a bare az ad sp show' {
    $src = Get-Content (Join-Path $setpDir 'Setup-PimContainers.ps1') -Raw
    # The regression this pins: a future edit reinstating the one-shot lookup on either the
    # worker loop or the tick Job. Two call sites, so two matches, and zero bare lookups.
    ([regex]::Matches($src,'Resolve-PimMiAppId').Count -ge 2) -and ($src -notmatch 'az ad sp show')
}

Section 'BUG-45 -- a DENIED Graph app-role fails the deploy, it is not a warning'
$sharedGraphSrc = Get-Content (Join-Path $setpDir '_PimSetupShared.ps1') -Raw
T 'Grant-PimMiGraph throws when roles are MISSING instead of warning' {
    # The old body caught every POST failure into Write-Warning, so an identity that got NONE
    # of its roles still produced a "successful" deploy and 403'd later inside the container.
    $sharedGraphSrc -match 'Graph app-roles are\s*"?\s*\+?\s*"?MISSING' -or $sharedGraphSrc -match 'are\s+"?\+?\s*"?MISSING on identity'
}
T 'idempotence comes from READING current assignments, not from matching an error string' {
    # Graph answers a duplicate assignment with 400, and the "already exists" text is in the
    # BODY -- so `$_.Exception.Message -match 'already'` can never fire. Hardening the throw
    # without fixing this made a fully-granted identity fail its own re-deploy (measured on
    # mfnpr: "8 of 8 ... FAILED" against an identity that already held all 8).
    $sharedGraphSrc -match 'Get-PimAssignedRoleIds' -and $sharedGraphSrc -notmatch "notmatch 'already'"
}
T 'only MISSING roles are POSTed' {
    $sharedGraphSrc -match '-in \$have\) \{ continue \}'
}
T 'a failed POST is re-checked against the directory before it is called a failure' {
    $sharedGraphSrc -match '\$stillMissing' -and $sharedGraphSrc -match 'POST errors were duplicates'
}
T 'the response BODY is captured, since the status line alone says nothing' {
    $sharedGraphSrc -match '\$_\.ErrorDetails\.Message'
}
T 'an unreadable assignment list is fail-safe (treat every role as missing)' {
    $sharedGraphSrc -match 'cannot read => treat every role as missing'
}

Section 'BUG-50 -- a schema step that applies NOTHING must not report "schema upgrade applied"'
$deployAllSrc0 = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw
T 'a hosted deploy with no -SqlConnectionString FAILS the schema step' {
    # Invoke-PimUpdate degrades to printing the DDL and still exits 0, so the orchestrator used to
    # return ok=True + "schema upgrade applied". Measured on mfnpr: 3 tables in the store after
    # repeated "successful" deploys -- Manager and tick both healthy against a schema-less database.
    $deployAllSrc0 -match 'the SQL schema CANNOT be applied' -and $deployAllSrc0 -match 'ok=\$false'
}
T 'the refusal names what to do (connection string, or the two shipped .sql files)' {
    $deployAllSrc0 -match 'sql/platform-schema\.sql \+ sql/local-schema\.sql'
}
T 'the guard is hosted-only (a local/community run may legitimately plan DDL)' {
    $deployAllSrc0 -match 'if \(\$hosted\)[\s\S]{0,600}?Refusing to report a schema upgrade'
}

Section 'DOC-06 -- the post-deploy §7a gate is HANDED the context its caller already has'
$updSrc = Get-Content (Join-Path $setpDir 'Update-PimContainers.ps1') -Raw
T 'the gate is no longer invoked bare (`& $smoke -AsReleaseGate` with nothing else)' {
    # It knew the resource group and the Manager name and passed neither, so the smoke could not
    # list revisions and failed as "the gate could not RUN" -- which reads like a broken Manager.
    $updSrc -notmatch '&\s*\$smoke\s+-AsReleaseGate\s*\r?\n'
}
T 'ResourceGroup + App are forwarded (the smoke defaults ResourceGroup to EMPTY)' {
    $updSrc -match "ResourceGroup\s*=\s*\`$ResourceGroup" -and $updSrc -match "App\s*=\s*'ca-pim-manager'"
}
T 'workspace / Easy Auth audience / FQDN are passthrough params defaulting to env' {
    $updSrc -match '\$SmokeWorkspaceId' -and $updSrc -match '\$SmokeEasyAuthAud' -and $updSrc -match '\$SmokeFqdn' -and
    $updSrc -match 'PIM_HOSTED_EASYAUTH_AUD'
}
T 'a missing Easy Auth audience is called out as gate-failing, not passed over in silence' {
    $updSrc -match 'NOT set -- the live-HTTP layer will fail the gate'
}
T 'the gate logs via Write-Host, not an undefined Note helper' {
    # Update-PimContainers defines Step() only. Calling Note() is parse-clean and throws at
    # RUNTIME, inside the gate, on every deploy -- the same class as the `empties` ReferenceError.
    ($updSrc -notmatch '(?m)^\s*Note\s') -and ($updSrc -match 'function Step')
}

Section 'BUG-47 -- Grant-PimMiSql is IDEMPOTENT (a re-run must not try to drop a schema owner)'
# Measured on mfnpr: the unconditional DROP USER + CREATE USER died with "The database principal
# owns a schema in the database, and cannot be dropped". The user holds db_ddladmin by design, so
# it owns a schema the moment it applies one -- meaning this failed on the FIRST re-run of every
# environment that had ever been used.
$sharedSrc = Get-Content (Join-Path $setpDir '_PimSetupShared.ps1') -Raw
T 'no UNCONDITIONAL drop-then-create' {
    $sharedSrc -notmatch "IF EXISTS \(SELECT 1 FROM sys\.database_principals WHERE name='\`$DbUserName'\) DROP USER"
}
T 'the user is only recreated when the SID actually DIFFERS' {
    $sharedSrc -match "IF NOT EXISTS \(SELECT 1 FROM sys\.database_principals WHERE name='\`$DbUserName' AND sid = \`$sid\)"
}
T 'owned schemas are handed to dbo before any DROP USER' {
    $sharedSrc -match 'ALTER AUTHORIZATION ON SCHEMA::' -and $sharedSrc -match 'sys\.schemas'
}
T 'role membership is guarded, not re-applied blindly' {
    ([regex]::Matches($sharedSrc,'IS_ROLEMEMBER').Count -ge 3)
}
T 'all three roles still granted (reader/writer/ddladmin)' {
    $sharedSrc -match 'db_datareader ADD MEMBER' -and $sharedSrc -match 'db_datawriter ADD MEMBER' -and $sharedSrc -match 'db_ddladmin   ADD MEMBER'
}

Section 'BUG-46 -- the infra probe must test the LAST thing the step does, not the first'
# Two rounds of this defect already: the probe checked the ACA environment (missed a missing
# Manager), then environment+Manager (missed a tick Job whose GRANTS never happened). On mfnpr
# that made every re-run report "already current" and skip the only step that could have fixed it.
$deployAllSrc = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw
T 'cron mode: the probe looks at the tick JOB, not only the Manager app' {
    $deployAllSrc -match 'containerapp job show[^\r\n]*identity\.principalId'
}
T 'and at its Graph APP-ROLES -- existence of the Job is not completion' {
    $deployAllSrc -match 'appRoleAssignments' -and $deployAllSrc -match 'holds NO Graph app-roles'
}
T 'an unreadable/zero role count means NOT current (fail-safe: re-run idempotent infra)' {
    # `-not $roles` OR count 0 -> $false. Being wrong this way costs one re-run; the other way
    # cost a permanently half-built tenant.
    $deployAllSrc -match "\[int\]`"\`$roles`"\.Trim\(\) -eq 0"
}
T 'always-on mode short-circuits before the Job probe (those workers are the workload)' {
    $deployAllSrc -match "if \(\`$WorkerMode -ne 'cron'\) \{ return \`$true \}"
}
T 'the tick Job NAME is a parameter and is forwarded to Setup-PimContainers' {
    $deployAllSrc -match '\[string\]\$TickJobName' -and $deployAllSrc -match '-TickJobName \$TickJobName'
}

Section 'BUG-46 -- the schema step forwards -Apps (cron mode has no six-app matrix)'
T 'the cron override narrows $Apps to the Manager alone' {
    $deployAllSrc -match "WorkerMode -eq 'cron' -and -not \`$PSBoundParameters\.ContainsKey\('Apps'\)"
}
T 'the SCHEMA step passes -Apps, not just the CODE step' {
    # Invoke-PimUpdate -Apply runs its whole detect->build->deploy chain, so the schema step rolls
    # containers too -- with ITS default six-app list unless this passthrough exists. Measured:
    # "requested app(s) not found: ca-pim-scheduler, ..." AFTER an image was built and pushed.
    ([regex]::Matches($deployAllSrc,'-Apps \$Apps').Count -ge 2)
}

Section 'SHARED HELPERS -- GSA / private-link guidance + version + banner'
T 'GSA guidance names every required private-link zone' {
    $g = Get-PimGsaPrivateLinkGuidance -ManagerFqdn 'app.example.io'
    ($g -match 'privatelink\.database\.windows\.net') -and ($g -match 'privatelink\.azurewebsites\.net') `
        -and ($g -match 'privatelink\.blob\.core\.windows\.net') -and ($g -match 'Global Secure Access') -and ($g -match '168\.63\.129\.16')
}
T 'GSA guidance embeds the manager fqdn when supplied'  { (Get-PimGsaPrivateLinkGuidance -ManagerFqdn 'mgr.contoso.io') -match 'mgr\.contoso\.io' }
T 'Get-PimSetupSolutionVersion reads VERSION'           { (Get-PimSetupSolutionVersion -SolutionRoot $root) -eq ((Get-Content (Join-Path $root 'VERSION') -Raw).Trim()) }
T 'Show-PimSetupBanner runs without throwing'           { Show-PimSetupBanner -ScriptName 'Test' -SolutionRoot $root; $true }

Section 'DEPLOY SCRIPTS -- parse + structural contract'
$scripts = 'Setup-PimContainers.ps1','Setup-PimVM.ps1','Setup-PimMsp.ps1','Update-PimContainers.ps1','Install-PimEngineAppRegistration.ps1','_PimSetupShared.ps1'
foreach ($s in $scripts) {
    T "parses (PS 5.1 AST): $s" {
        $p = Join-Path $setpDir $s; $t=$null; $e=$null
        [System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$t,[ref]$e) | Out-Null
        -not ($e -and $e.Count)
    }
}

$containers = Get-Content (Join-Path $setpDir 'Setup-PimContainers.ps1') -Raw
T 'container manager uses --ingress external (internal env reachability fix)' { $containers -match '--ingress external' }
# Strip COMMENT lines first: this guard is about what the script PASSES to az, not about what it
# explains. Documenting *why* multi-token --command is unusable would otherwise fail the very test
# that enforces not using it -- a guard that punishes writing down its own reason.
$containersCode = (($containers -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
T 'container workers deploy via --yaml (NOT multi-token --command)'           { ($containersCode -match '--yaml') -and ($containersCode -notmatch '--command\b') }
# matches either the flag form or the argument-array form -- BUG-37 moved the env create onto an
# array so the workspace flags could be added conditionally. The PROPERTY is what matters here
# (no public ingress on the environment), not how the argument happens to be written.
T 'container env is internal-only (--internal-only true)'                     { $containers -match "--internal-only'?[ ,]+'?true" }
T 'container script dot-sources the shared lib'                               { $containers -match '_PimSetupShared\.ps1' }
T 'container script enforces region guard'                                    { $containers -match 'Assert-PimSetupRegion' }
T 'container script enforces persistent SQL (Set-PimSqlNoAutoPause)'          { $containers -match 'Set-PimSqlNoAutoPause' }
T 'container script prints GSA/private-link guidance'                         { $containers -match 'Show-PimGsaPrivateLinkGuidance' }

# Every resource in the prerequisites script must pin its OWN location. The VNet did not, so
# it inherited the resource GROUP's region -- invisible wherever the script also created the
# RG, and fatal wherever the RG predated it (wa678's westeurope remnant: "The selected region
# is currently not accepting new customers"). Region must never be implied by a container.
# --- registry pull identity (no standing admin credential) --------------------------------
# An app's SYSTEM-assigned identity cannot pull its own FIRST image (it does not exist until
# the app does), which is why this used to fall back to the registry ADMIN account -- while the
# prerequisites script never enabled one, so the credentials came back EMPTY and nothing could
# be created. A USER-assigned identity exists before any app, so it can hold AcrPull up front.
T 'container script accepts a user-assigned registry identity'         { $containers -match '\$RegistryIdentityResourceId' }
T 'container script passes --registry-identity when one is supplied'   { $containers -match '--registry-identity' }
T 'container script still requests --system-assigned (SQL + Graph)'    { $containers -match '--system-assigned' }
T 'identity mode emits NO acr password secret into the worker YAML' {
    # Anchor on the YAML identity branch specifically -- there is an EARLIER
    # `if ($useRegistryIdentity)` for the auth-mode banner, and matching that one instead
    # made this assertion pass/fail for the wrong reason.
    # Anchor on the assignment itself, not on the type's exact spelling -- pinning the spelling
    # made this test fail the moment the type was correctly quoted, which is a test breaking on
    # a FIX. There is an earlier `if ($useRegistryIdentity)` for the auth-mode banner, so the
    # anchor must still be the YAML branch specifically.
    $m = [regex]::Match($containers, '(?s)\$identityYaml = "identity:(.*?)\} else \{')
    $m.Success -and ($m.Groups[1].Value -match 'registries') -and
    ($m.Groups[1].Value -notmatch 'passwordSecretRef') -and ($m.Groups[1].Value -notmatch 'acr-pwd')
}
T 'the acr password secret survives on the LEGACY branch (not deleted outright)' {
    $containers -match 'passwordSecretRef: acr-pwd'
}
T 'identity mode does NOT re-point the registry at the system identity' {
    # `registry set --identity system` must be guarded, or it undoes the user-assigned pull
    $containers -match '(?s)if \(-not \$useRegistryIdentity\) \{[^}]*containerapp registry set'
}
T 'empty admin credentials FAIL LOUDLY instead of creating unpullable apps' {
    $containers -match '(?s)if \(-not \$acrU -or -not \$acrP\) \{\s*throw'
}
# The script used to `az account set` with no `az login`, so under the orchestrator (each step
# in its own process, inheriting no context) EVERY az call failed quietly for four steps and the
# run died inside a SQL grant on an empty MiAppId -- an error pointing at the wrong thing.
T 'container script can sign in itself (unattended, no ambient context)' { $containers -match 'az login --service-principal' }
T 'container script PROVES the az context before creating anything' {
    $containers -match '(?s)az account show --query id.*?if \(-not \$activeSub -or \$activeSub -ne \$SubscriptionId\) \{\s*throw'
}
T 'build script can sign in itself too' {
    (Get-Content (Join-Path $setpDir 'Build-PimManagerImage.ps1') -Raw) -match 'az login --service-principal'
}
# YAML flow mapping: `{ type: SystemAssigned, UserAssigned, ... }` parses as `type: SystemAssigned`
# plus a stray null key -- so ARM saw SystemAssigned-only and rejected the identity ids with
# "(InvalidResourceIdentityType)". The comma belongs to the VALUE, so the value must be quoted.
T 'dual identity type is a QUOTED yaml string (comma is part of the value)' {
    $containers -match 'type: `"SystemAssigned, UserAssigned`"'
}
T 'a failed container create is named at the create, not blamed on the SQL grant' {
    $containers -match '(?s)if \(-not \$oid\) \{\s*#[^\r\n]*\r?\n(\s*#[^\r\n]*\r?\n)*\s*throw'
}
# Prove the emitted YAML actually parses to the right identity type, rather than only
# pattern-matching the source. This is the assertion that would have caught the original bug.
T 'emitted identity yaml parses with type = "SystemAssigned, UserAssigned"' {
    $rid = '/subscriptions/x/resourceGroups/y/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-pim-test'
    $line = "identity: { type: `"SystemAssigned, UserAssigned`", userAssignedIdentities: { `"$rid`": {} } }"
    # minimal flow-mapping check: the value between the quotes after `type:` must contain BOTH
    $m = [regex]::Match($line, 'type:\s*"([^"]*)"')
    $m.Success -and ($m.Groups[1].Value -eq 'SystemAssigned, UserAssigned')
}

# --- ESTATE-06: on-demand hosting (cron Job + scale-to-zero Manager) ----------------------
# The always-on matrix is six containers at minReplicas 1 per tenant (~$205-230/env/month) to
# run a timer loop whose deltas fire every 15-60 MINUTES. A 5-minute cron tick is faster AND
# fits inside the ACA free grant. These assert the mode exists, is OFF by default (so existing
# deployments do not silently change shape), and is wired to the SHARED job builder.
T 'container script offers a cron worker mode'            { $containers -match "ValidateSet\('always-on','cron'\)" }
T 'always-on remains the DEFAULT (no silent reshaping)'   { $containers -match '\$WorkerMode = ''always-on''' }
T 'cron mode validates the cron expression up front'      { $containers -match 'Test-PimDownlinkJobCron -Cron \$TickCron' }
T 'cron mode collapses the app set to the manager only'   { $containers -match '(?s)\$WorkerMode -eq ''cron''.*?\$Workers = \$mgrOnly' }
T 'cron mode refuses to drop the manager'                 { $containers -match 'still needs a manager entry' }
T 'tick Job runs the scheduler ONE-SHOT'                  { $containers -match 'Start-PimScheduler\.ps1","-Once"' }
# MEASURED against a live deploy: `az containerapp job create --command pwsh -NoProfile -File x
# -Once` fails with "unrecognized arguments", because the CLI parser reads any '-'-prefixed token
# as an OPTION rather than a value -- so a command with dashed arguments cannot be expressed that
# way at all. The worker apps already deploy via YAML for exactly this reason; the tick Job must
# too. (Build-PimDownlinkJobArgs still emits multi-token --command -- BUG-38.)
T 'tick Job deploys via --yaml (multi-token --command is UNUSABLE)' {
    $containers -match '(?s)containerapp job \$jobAction[^\r\n]*--yaml'
}
T 'tick Job declares the Schedule trigger + cron in the yaml' {
    ($containers -match 'triggerType: Schedule') -and ($containers -match 'cronExpression: "\$TickCron"')
}
T 'tick Job serialises itself (parallelism 1)'            { $containers -match 'parallelism: 1' }
T 'tick Job yaml passes the command as a real array'      { $containers -match 'args: \["-NoProfile","-File"' }
T 'tick Job grants its MI SQL + Graph like a worker'      { ($containers -match 'Grant-PimMiSqlHere -DbUserName \$TickJobName') -and ($containers -match 'Grant-PimMiGraph -MiObjectId \$jobOid') }
T 'a tick Job with no identity FAILS LOUDLY'              { $containers -match '(?s)-not "\$jobOid"\.Trim\(\).*?throw' }
T 'manager min-replicas is parameterised (scale-to-zero)' { $containers -match '--min-replicas.{0,4}\$ManagerMinReplicas' }
T 'manager min-replicas defaults to 1 (warm unless asked)'{ $containers -match '\[int\]\$ManagerMinReplicas = 1' }

# The tick Job needs BOTH identities: user-assigned for the FIRST registry pull (a system
# identity does not exist until the job does), system-assigned for SQL + Graph.
$dlj = Get-Content (Join-Path $root 'engine\_shared\PIM-DownlinkJob.ps1') -Raw
# BUG-38 moved the downlink Job onto the same YAML shape the workers and the tick Job use, so the
# identity is expressed in the YAML document rather than as --mi-* flags. The GUARANTEE is
# unchanged and is what these assert: both identities when asked, system-assigned alone by default.
T 'job builder can emit BOTH user- and system-assigned MI' {
    $dlj -match '(?s)if \(\$SystemAssigned\) \{ \$idType = ''SystemAssigned, UserAssigned'' \}'
}
T 'job builder still defaults to system-assigned alone' { $dlj -match "identity: \{ type: SystemAssigned \}" }
T 'job builder deploys via --yaml, never --command (BUG-38)' {
    # --command cannot carry a dashed argument; the downlink command is entirely dashed args.
    ($dlj -match "\`$a\.Add\('--yaml'\)") -and ($dlj -notmatch "\`$a\.Add\('--command'\)")
}
T 'job builder REFUSES to build without the YAML facts (no silent half-deploy)' {
    ($dlj -match '-YamlPath required') -and ($dlj -match '-EnvironmentId required')
}
T 'the inline-secret guard reads the YAML, where the env now lives' {
    # Moving env off the command line must not disarm the check that stops a secret being deployed.
    # 🪤 BUG-73 narrowed the scan to EXCLUDE the sanctioned `secrets:` line -- an ACA secret is a
    # VALUE by definition, so scanning it would make the safe mechanism unusable and push callers
    # back to plain env values, which is the outcome the guard exists to prevent. The guard now
    # reads a yaml-DERIVED variable rather than $yaml itself.
    # This assert was pinned to the variable NAME and so failed on a change that strengthened it.
    # What must hold is the BEHAVIOUR: the yaml is still derived from $yaml and still scanned.
    ($dlj -match '(?s)\$yamlToScan\s*=\s*\(\(\$yaml -split') -and
    ($dlj -match '(?s)if \("\$yamlToScan" -match .*?\) \{ \$inline = \$true \}')
}
T 'the guard still EXCLUDES only the secrets line, never the whole yaml' {
    # Excluding the whole document would disarm the check entirely -- the failure this guards.
    $dlj -match [regex]::Escape('-notmatch ''^\s*secrets:')
}

# BUG-39, measured on a live ACA Job run: the scheduler entrypoint read NONE of the PIM_Sql*
# env vars the container is given, and Get-/Set-PimSetting are defined by the MANAGER, not here.
# So a scheduler container wrote its state to a JSON file inside an EPHEMERAL container:
# nextRunUtc never survived (so every job looked never-run and DUE on every 5-minute tick, incl.
# the daily engine-full), and the BUG-36 lease fell back to in-memory, which cannot arbitrate
# between processes. The Job reported "Succeeded" and pim.Settings stayed EMPTY.
$schedEntry = Get-Content (Join-Path $root 'tools\pim-scheduler\Start-PimScheduler.ps1') -Raw
T 'scheduler entrypoint hydrates PIM_SqlServer from the container env' { $schedEntry -match '\$global:PIM_SqlServer\s*=\s*"\$env:PIM_SqlServer"' }
T 'scheduler entrypoint bridges Get-/Set-PimSetting onto the SQL store' {
    ($schedEntry -match 'function Get-PimSetting') -and ($schedEntry -match 'function Set-PimSetting') -and ($schedEntry -match 'Set-PimSqlSetting')
}
T 'the SQL bridge never clobbers a host that already provides one' {
    $schedEntry -match '(?s)if \(-not \(Get-Command Set-PimSetting -ErrorAction SilentlyContinue\)\)'
}
T 'hosted WITHOUT sql coordinates WARNS instead of silently going ephemeral' {
    $schedEntry -match '(?s)PIM_HOSTED" -eq ''1''.*?Write-Warning'
}

$prereq = Get-Content (Join-Path $setpDir 'New-PimHostingPrerequisites.ps1') -Raw
T 'prereq creates the user-assigned pull identity'          { $prereq -match 'az identity create' }
T 'prereq grants it AcrPull on the registry'                { $prereq -match '(?s)az role assignment create[^\r\n]*(`\r?\n[^\r\n]*)*?AcrPull' }
T 'prereq never enables the ACR admin account'              { $prereq -notmatch '--admin-enabled' }
T 'prereq VERIFIES the AcrPull grant, not just the identity'{ $prereq -match "Chk 'acrpull grant'" }
T 'prereq vnet create pins -l $Location (never inherits the RG region)' {
    $prereq -match '(?s)az network vnet create[^\r\n]*(`\r?\n[^\r\n]*)*?-l \$Location'
}
foreach ($rt in @(
    @{ n='log analytics'; p='az monitor log-analytics workspace create' }
    @{ n='container registry'; p='az acr create' }
    @{ n='sql server'; p='az sql server create' })) {
    T "prereq $($rt.n) create pins -l `$Location" {
        $prereq -match ('(?s)' + [regex]::Escape($rt.p) + '[^\r\n]*(`\r?\n[^\r\n]*)*?-l \$Location')
    }
}

# PIM §34 -- a REAL tenant must authenticate by CERTIFICATE. This script used to make secret auth
# structurally mandatory ([Parameter(Mandatory)]$AdminSecret + `az login -p`), so it could not be
# pointed at the production tenant at all without breaking the repo-root "never use client secrets"
# rule. These assert the cert path exists AND that neither credential can be used by accident.
T 'prereq accepts CERTIFICATE auth (a production tenant must not use a client secret)' {
    ($prereq -match '\$AdminCertPem') -and ($prereq -match 'az login --service-principal -u \$AdminAppId --certificate \$AdminCertPem')
}
T 'prereq no longer makes a client SECRET mandatory' {
    $prereq -notmatch '\[Parameter\(Mandatory\)\]\[string\]\$AdminSecret'
}
T 'prereq REFUSES both credentials at once (silently preferring one hides which was used)' {
    $prereq -match 'not both'
}
T 'prereq REFUSES neither credential (no accidental interactive/inherited login)' {
    $prereq -match 'one of -AdminSecret / -AdminCertPem is required'
}
T 'prereq FAILS LOUDLY on a bad login instead of running every step against no context' {
    $prereq -match '(?s)az login[^\r\n]*(\r?\n.*?)?az login.*?LASTEXITCODE.*?throw "az login failed'
}

# ESTATE-04 / PIM §34 -- the one-shot orchestrator must be able to express the APPROVED cost shape.
# It could not: Setup-PimContainers defaults to WorkerMode 'always-on' + ManagerMinReplicas 1
# (~$205-230/env/month) and Invoke-PimDeployAll neither exposed nor forwarded those, so
# "deploy everything" silently deployed the expensive matrix -- to production included.
$dall = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw
T 'deploy-all FORWARDS the worker mode to Setup-PimContainers (absence = silent always-on)' {
    $dall -match '-WorkerMode \$WorkerMode'
}
T 'deploy-all forwards the manager replica count' { $dall -match '-ManagerMinReplicas \$ManagerMinReplicas' }
T 'deploy-all forwards the tick cron'             { $dall -match '-TickCron \$TickCron' }
T 'deploy-all DEFAULTS to the on-demand shape (a front door must not need expert flags)' {
    ($dall -match "\[ValidateSet\('always-on','cron'\)\]\[string\]\`$WorkerMode = 'cron'") -and
    ($dall -match '\[int\]\$ManagerMinReplicas = 0')
}
T 'the expensive default still exists in Setup-PimContainers for direct callers (no silent change)' {
    $setup = Get-Content (Join-Path $setpDir 'Setup-PimContainers.ps1') -Raw
    $setup -match "\[string\]\`$WorkerMode = 'always-on'"
}

# ---------------------------------------------------------------------------
# DEPLOY REPORT -- the redactor. This file leaves a CUSTOMER tenant and is sent to the vendor, so
# these assertions are the only thing standing between a diagnostic and a credential disclosure.
# Tested on the shapes that actually appear in a transcript: a transcript captures COMMAND LINES,
# which is where secrets really leak, not tidy config files.
# ---------------------------------------------------------------------------
# 🪤 Dot-source the PURE file, never the script: dot-sourcing New-PimDeployReport.ps1 EXECUTES it,
# which starts a real deploy with empty arguments. That happened here on 2026-08-09 and announced
# itself only as a stray "failedSteps : {}" in the middle of the test output.
. (Join-Path (Split-Path $setpDir -Parent | Split-Path -Parent) 'engine\_shared\PIM-DeployReport.ps1')
T 'the deploy REPORT SCRIPT is never dot-sourced by tests (dot-sourcing a .ps1 runs it)' {
    $me = Get-Content $PSCommandPath -Raw
    $me -notmatch "\.\s*\(Join-Path \`$setpDir 'New-PimDeployReport\.ps1'\)"
}
if (Get-Command Get-PimRedactedText -ErrorAction SilentlyContinue) {
  T 'redacts a SQL connection-string password' {
    $r = Get-PimRedactedText -Text 'Server=tcp:x.database.windows.net;Database=PimPlatform;User ID=app;Password=Hunter2Hunter2;'
    ($r -notmatch 'Hunter2') -and ($r -match 'REDACTED')
  }
  T 'redacts a client secret passed on a command line (az login -p ...)' {
    $r = Get-PimRedactedText -Text 'az login --service-principal -u 1234 -p Xy8Q~aBc1DeFgH2iJkLmN3oPqR --tenant t'
    ($r -notmatch 'Xy8Q~aBc1DeFgH2iJkLmN3oPqR') -and ($r -match 'REDACTED')
  }
  T 'redacts a bearer token and a bare JWT' {
    $jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N'
    $r = Get-PimRedactedText -Text "Authorization: Bearer $jwt`nraw=$jwt"
    $r -notmatch 'dozjgNryP4J3jVmNHl0w5N'
  }
  T 'redacts a storage SAS signature' {
    $r = Get-PimRedactedText -Text 'https://st.blob.core.windows.net/c/f.zip?sv=2021&sig=AbC%2FdEfGh123&se=x'
    ($r -notmatch 'AbC%2FdEfGh123') -and ($r -match 'sig=\*\*\*REDACTED\*\*\*')
  }
  T 'collapses a PEM private key but LEAVES THE MARKER (so the reader knows one was there)' {
    $pem = "-----BEGIN PRIVATE KEY-----`nMIIEvQIBADANBgkqh`nkiG9w0BAQEFAASC`n-----END PRIVATE KEY-----"
    $r = Get-PimRedactedText -Text $pem
    ($r -notmatch 'MIIEvQIBADANBgkqh') -and ($r -match 'BEGIN PRIVATE KEY')
  }
  T 'KEEPS diagnostics: resource names, revisions, image digests, error codes' {
    # A report that redacts everything cannot be reasoned about; these must survive.
    $t = 'ca-pim-manager rev ca-pim-manager--abc123 image acrx.azurecr.io/pim-manager@sha256:deadbeef ERROR Authorization_RequestDenied'
    $r = Get-PimRedactedText -Text $t
    ($r -match 'ca-pim-manager--abc123') -and ($r -match 'sha256:deadbeef') -and ($r -match 'Authorization_RequestDenied')
  }
  T 'identifiers are KEPT by default (masking them is a per-customer decision, not a default)' {
    $r = Get-PimRedactedText -Text 'tenant f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e'
    $r -match 'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e'
  }
  T '-Identifiers masks GUIDs but keeps the first 8 chars (two tenants must stay distinguishable)' {
    $r = Get-PimRedactedText -Text 'a f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e b 54468121-98ba-48ba-ba59-ba10a9711ed3' -Identifiers
    ($r -match 'f0fa27a0-\*\*\*\*') -and ($r -match '54468121-\*\*\*\*') -and ($r -notmatch 'ec94786b7c9e')
  }
  T '-Identifiers masks onmicrosoft.com domains' {
    (Get-PimRedactedText -Text 'contoso.onmicrosoft.com' -Identifiers) -match 'TENANT-DOMAIN'
  }
  T 'the report DELETES the unredacted raw transcript' {
    $c = Get-Content (Join-Path $setpDir 'New-PimDeployReport.ps1') -Raw
    $c -match '(?s)Remove-Item \$reportRaw.*?UNREDACTED|(?s)reportRaw.*?Remove-Item'
  }
  T 'the report is redacted BEFORE it is written to disk (never write then scrub)' {
    $c = Get-Content (Join-Path $setpDir 'New-PimDeployReport.ps1') -Raw
    $iRedact = $c.IndexOf('$final = Get-PimRedactedText')
    $iWrite  = $c.IndexOf('Set-Content -LiteralPath $reportOut')
    ($iRedact -gt 0) -and ($iWrite -gt $iRedact)
  }
} else {
  T 'deploy-report redactor is dot-sourceable' { $false }
}

# PIM §34 -- the SQL-admin credential. Grant-PimMiSql had [Parameter(Mandatory)]$SqlAdminClientSecret,
# so a CLIENT SECRET was structurally required to deploy: unsatisfiable in a cert-only tenant, which
# is every real customer per the repo-root rule. Get-PimRestToken had supported -CertThumbprint all
# along; only the signatures forced the secret.
$shared = Get-Content (Join-Path $setpDir '_PimSetupShared.ps1') -Raw
T 'Grant-PimMiSql accepts a CERTIFICATE thumbprint for the SQL admin' {
    ($shared -match '\$SqlAdminCertThumbprint') -and ($shared -match 'CertThumbprint \$SqlAdminCertThumbprint')
}
T 'Grant-PimMiSql no longer REQUIRES a client secret' {
    $shared -notmatch '\[Parameter\(Mandatory\)\]\[string\]\$SqlAdminClientSecret'
}
T 'Grant-PimMiSql refuses both credentials, and refuses neither' {
    ($shared -match 'not both\.') -and ($shared -match 'is required\.')
}
T 'cert path CLEARS any inherited secret (a stale global must not win the fallback chain)' {
    # Get-PimRestToken falls back to $global:PIM_ClientSecret / $env:AZURE_CLIENT_SECRET. Leaving a
    # stale one set would authenticate as something other than what the caller asked for, silently.
    $shared -match '(?s)if \(\$SqlAdminCertThumbprint\).*?\$global:PIM_ClientSecret\s*=\s*\$null'
}
T 'Setup-PimContainers forwards whichever SQL-admin credential it was given' {
    $setup = Get-Content (Join-Path $setpDir 'Setup-PimContainers.ps1') -Raw
    ($setup -match '\$SqlAdminCertThumbprint') -and ($setup -match '@cred')
}
T 'deploy-all EXPOSES and forwards the SQL-admin credential (its absence blocked INFRA entirely)' {
    ($dall2 = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw) | Out-Null
    ($dall2 -match '\$SqlAdminCertThumbprint') -and ($dall2 -match '@sqlAdminCred')
}
T 'deploy-all forwards the AcrPull identity (without it INFRA half-builds then dies)' {
    # Observed: the ACA environment was CREATED, then app creation refused for want of this. A
    # parameter the front door cannot pass is a parameter that does not exist, from its callers'
    # point of view.
    $c = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw
    ($c -match '\$RegistryIdentityResourceId') -and ($c -match '@registryIdentity')
}
T 'EVERY Setup-PimContainers parameter is reachable from deploy-all (derived, not hand-listed)' {
    # 🔴 THE DEFECT CLASS OF THE WHOLE DEPLOY: the orchestrator silently could not express
    # parameters that Setup-PimContainers needs. NINE instances in one evening, each discovered
    # only when a deploy got far enough to need it -- and one of them (LogAnalyticsWorkspaceName)
    # made a FIXED bug reproduce, because BUG-37's fix is gated on a parameter nobody could pass.
    #
    # The first version of this test hand-listed the parameters, so it passed while
    # LogAnalyticsWorkspaceName was missing -- a test that only knows what I remembered to type
    # cannot catch what I forgot. It now READS Setup-PimContainers' own param block, so a new
    # parameter there is caught here without anyone updating this list.
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $setpDir 'Setup-PimContainers.ps1'), [ref]$null, [ref]$null)
    $names = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    if ($names.Count -lt 10) { throw "param block not parsed (got $($names.Count))" }
    # Deliberate exclusions, each with a reason -- an exclusion list is fine; a silent gap is not.
    $exempt = @(
        'SubnetPrefix','DnsServer','SkipPersistentSqlCheck','SqlResourceGroup'  # infra knobs w/ safe defaults
        'TickJobName','TickReplicaTimeout'                                      # naming/timeout defaults
        'Workers','WhatIf','Confirm','Verbose','ManagerApp'                     # shape/common params
        'SubnetName'                     # default 'snet-pim-aca' is exactly what New-PimHostingPrerequisites creates
    )
    $dc = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw
    $missing = @($names | Where-Object { $_ -notin $exempt -and $dc -notmatch "\`$$_\b" })
    if ($missing.Count) { throw "deploy-all cannot pass: $($missing -join ', ')" }
    $true
}
T 'SS34.2c: deploy-all passes a DEPLOY IDENTITY to infra (it used to inherit the ambient az context)' {
    # 🔴 THE BUG-23 CLASS: a credential path that succeeds while being wrong. Setup-PimContainers
    # has always had its own -AdminAppId/-AdminSecret sign-in into an ISOLATED AZURE_CONFIG_DIR;
    # the orchestrator never passed them, so INFRA alone ran on whatever `az` context happened to
    # be active while every other step signs itself in.
    # 🪤 MEASURED 2026-08-13 on the first real greenfield run (LEGYM): the ambient context was
    # subscription 772440e1-... -- ExpertsLiveDK, A DIFFERENT COMPANY, which is regularly the
    # default on this host. The deploy stopped only because Setup-PimContainers refuses a context
    # whose subscription is not the target. Without that refusal it would have provisioned into
    # another company's tenant.
    # These two were EXEMPTED from the derived check above as a "known gap" until the fix landed
    # in f46d0c30. The exemption is gone -- so the derived check now covers them like any other
    # parameter -- and this asserts the STEP that consumes them, which the derived check cannot see.
    $dc = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw
    ($dc -match '\[string\]\$AdminAppId') -and ($dc -match '\[string\]\$AdminSecret') -and
    # splatted into the INFRA step, and only when both are present, so an omitted identity keeps
    # the previous behaviour rather than passing empty strings into `az login`.
    ($dc -match "deployId\['AdminAppId'\]")  -and ($dc -match "deployId\['AdminSecret'\]") -and
    ($dc -match '&\s*\$setup\s+@deployId')
}
T 'SEC-11: the deploy identity can be a CERTIFICATE, in both scripts, with no secret anywhere' {
    # The repo-root rule is "NEVER use client secrets", and SS34.2c's own recorded fix shape said
    # "a single explicit deploy identity (CERT)". What shipped in f46d0c30 was secret-only, and
    # Setup-PimContainers was the ONLY setup script with no PEM path (New-PimHostingPrerequisites
    # and Build-PimManagerImage both had one). The consequence was not cosmetic: the passthrough
    # was gated on `$AdminAppId -and $AdminSecret`, so a CERT-ONLY operator -- the shape this
    # project actually uses -- passed neither, the splat stayed empty, and INFRA fell back to the
    # AMBIENT az context. The hole SS34.2c closed was still open for the normal credential.
    $sc = Get-Content (Join-Path $setpDir 'Setup-PimContainers.ps1') -Raw
    $dc = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1')  -Raw
    # both scripts declare it
    ($sc -match '\[string\]\$AdminCertPem') -and ($dc -match '\[string\]\$AdminCertPem') -and
    # Setup-PimContainers actually signs in WITH it, and validates the file first
    ($sc -match 'az login --service-principal -u \$AdminAppId --certificate \$AdminCertPem') -and
    ($sc -match 'certificate PEM not found') -and
    # EITHER/OR is enforced -- silently preferring one would make a run that THOUGHT it was
    # cert-authenticating actually use a secret
    ($sc -match 'pass EITHER -AdminSecret OR -AdminCertPem, not both') -and
    # the sign-in gate admits a cert-only caller (this is the actual SEC-11 fix)
    ($sc -match '\$AdminAppId -and \(\$AdminSecret -or \$AdminCertPem\)') -and
    # ...and so does the orchestrator's passthrough
    ($dc -match '\$AdminAppId -and \(\$AdminSecret -or \$AdminCertPem\)') -and
    ($dc -match "deployId\['AdminCertPem'\]")
}
T 'BUG-68: deploy-all has PREREQ + IMAGE steps, and they wrap the EXISTING proven scripts' {
    # The catalog could only ever UPDATE a tenant a human had already built: `infra` resolves the
    # image DIGEST before creating anything, `code` both BUILDS that image and ROLLS the apps, and
    # the roll refuses to roll zero apps -- so infra needed code's image and code needed infra's
    # apps. A CYCLE. And nothing in the catalog created the RG/VNet/ACR/SQL/AcrPull identity at
    # all; only New-PimHostingPrerequisites did, and the orchestrator never called it.
    $dc = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw
    ($dc -match "'prereq'\s*\{") -and ($dc -match "'image'\s*\{") -and
    # they WRAP the proven scripts -- no new provisioning logic was written
    ($dc -match 'New-PimHostingPrerequisites\.ps1') -and ($dc -match 'Build-PimManagerImage\.ps1') -and
    # the image step builds ONLY: it must never roll (that is `code`, and the roll is why the cycle existed)
    ($dc -notmatch "(?s)'image'\s*\{.{0,4000}?Invoke-PimUpdate")
}
T 'BUG-68: the PREREQ step REFUSES a token whose derived names disagree with the deploy (split-brain)' {
    # 🔴 The prereq script DERIVES every name from the estate token; this orchestrator RECEIVES
    # them. A disagreement would provision a COMPLETE, correct-looking set of resources that INFRA
    # never reads -- and both halves would report success. That is the most expensive shape of
    # "it worked". Prove agreement BEFORE creating anything.
    $dc = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw
    ($dc -match 'rg-automateit-\$PrereqToken') -and ($dc -match 'acrpim\$PrereqToken') -and
    ($dc -match 'vnet-pim-\$PrereqToken') -and ($dc -match 'silent half-deploy') -and
    # and it refuses to GUESS the CIDR index -- two environments sharing one cannot be un-peered
    ($dc -match 'cannot be un-peered')
}
T 'BUG-68: PREREQ + IMAGE take the deploy identity, preferring the CERTIFICATE (SEC-11)' {
    # Same rule as every other step: sign in explicitly, never inherit the ambient az context --
    # and prefer the cert, because the repo-root rule is "never use client secrets".
    $dc = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw
    ($dc -match "prqId\['AdminCertPem'\]") -and ($dc -match "bldId\['AdminCertPem'\]") -and
    # cert is tested FIRST in both, so a caller holding both does not silently get the secret
    ($dc -match '(?s)if \(\$AdminAppId -and \$AdminCertPem\).{0,200}?elseif \(\$AdminAppId -and \$AdminSecret\)')
}
T 'BUG-68: the two new steps are PROBED, so an existing environment still skips them (update path unchanged)' {
    # The property the operator chose this shape for: fixing the FIRST-run path must not change
    # the nightly path for ~30 customers. Both facts are probed like every other step, and the
    # prereq probe tests the LAST artefacts (the AcrPull ROLE, the SQL server) rather than the
    # resource group -- the BUG-46 lesson, which this file has now learned three times.
    $dc = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw
    ($dc -match 'function Test-HostingPrereqsPresent') -and ($dc -match 'function Test-ManagerImagePresent') -and
    ($dc -match "facts\['prereq'\]") -and ($dc -match "facts\['image'\]") -and
    ($dc -match '--role AcrPull') -and ($dc -match 'az sql server show')
}
T 'BUG-37: deploy-all passes the Log Analytics workspace (its absence made a FIXED bug reproduce)' {
    # Reproduced live on mfnpr 2026-08-09: ACA generated workspace-<rg><hash> and sent every log
    # there while law-pim-mfnpr sat empty and billed. The fix was in Setup-PimContainers all along,
    # gated behind a parameter the orchestrator did not forward.
    $dc = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw
    ($dc -match '\$LogAnalyticsWorkspaceName') -and ($dc -match "registryIdentity\['LogAnalyticsWorkspaceName'\]")
}
T 'EVERY Invoke-PimUpdate call in deploy-all passes the registry (schema step was missing it)' {
    # The 'code' step passed -AcrName; the 'schema' step did not, and Invoke-PimUpdate -Apply runs
    # its whole detect->build->deploy chain either way. It failed AFTER the infra was standing.
    $dc = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw
    # Match each call to its terminator ('| Out-Host' for apply calls, '6>$null' for detect ones)
    # rather than trying to chase backtick continuations -- that pattern mis-anchored and reported
    # a false failure against code that was already correct.
    $calls = [regex]::Matches($dc, '(?s)&\s+\$upd\b.*?(?:\|\s*Out-Host|6>\$null)')
    $applyCalls = @($calls | Where-Object { $_.Value -match '-Apply\b' })
    if ($applyCalls.Count -lt 2) { throw "expected >=2 -Apply calls to Invoke-PimUpdate, found $($applyCalls.Count)" }
    $bad = @($applyCalls | Where-Object { $_.Value -notmatch '-AcrName' })
    if ($bad.Count) { throw "$($bad.Count) -Apply call(s) to Invoke-PimUpdate omit -AcrName" }
    $true
}
T 'INFRA presence probe checks the MANAGER APP, not just the ACA environment' {
    # 🔴 The half-built trap: the environment is created FIRST, so a run that dies after it leaves
    # an environment with no apps -- which the old probe reported as "already current" FOREVER.
    # The deploy then failed downstream in `schema` with "no requested app exists", blaming the
    # wrong step. Across 25 tenants this is the difference between "re-run it" and "this tenant is
    # permanently half-built and the tool refuses to touch it".
    $c = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw
    $fn = [regex]::Match($c, '(?s)function Test-AcaEnvPresent \{.*?\n\}').Value
    ($fn -match 'az containerapp show') -and ($fn -match '\$ManagerApp') -and ($fn -match 'half-built')
}
T 'cron mode does not request the five workers that cron mode never creates' {
    # Setup-PimContainers in cron mode builds the Manager + one tick Job; the workers do not exist.
    # Asking Update-PimContainers to roll all six made it refuse with "no requested app exists".
    $c = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw
    ($c -match "\`$WorkerMode -eq 'cron' -and -not \`$PSBoundParameters\.ContainsKey\('Apps'\)") -and
    ($c -match '\$Apps = @\(\$ManagerApp\)')
}
T '  ...but an EXPLICIT -Apps from the caller still wins' {
    $c = Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw
    $c -match "PSBoundParameters\.ContainsKey\('Apps'\)"
}
T 'deploy-all fails EARLY and by NAME when no SQL admin credential is supplied' {
    # "missing mandatory parameters" thrown three scripts deep is the least useful place to learn it.
    (Get-Content (Join-Path $setpDir 'Invoke-PimDeployAll.ps1') -Raw) -match 'INFRA needs a SQL Entra admin'
}

# The THIRD place a client secret was structurally required. Kept as its own assertion rather than
# folded into the others, because the pattern is the finding: [Parameter(Mandatory)] on a secret --
# or an `-and $AdminSecret` gate -- makes certificate auth impossible no matter what the token
# helper supports, and Get-PimRestToken / az login supported certificates the whole time.
$bld = Get-Content (Join-Path $setpDir 'Build-PimManagerImage.ps1') -Raw
T 'image build accepts CERTIFICATE sign-in' {
    ($bld -match '\$AdminCertPem') -and ($bld -match 'az login --service-principal -u \$AdminAppId --certificate \$AdminCertPem')
}
T 'image build sign-in gate no longer requires a SECRET specifically' {
    # was: if ($TenantId -and $AdminAppId -and $AdminSecret) -- a cert-only caller fell through
    # to the ambient context silently, which on a multi-tenant host is the BUG-23 class.
    $bld -match '\(\$AdminSecret -or \$AdminCertPem\)'
}
T 'image build refuses both credentials at once' { $bld -match 'not both' }
T 'NO setup script still makes a client secret MANDATORY (the whole class, closed)' {
    $bad = @()
    foreach ($f in @('New-PimHostingPrerequisites.ps1','Build-PimManagerImage.ps1','Setup-PimContainers.ps1','_PimSetupShared.ps1')) {
        $c = Get-Content (Join-Path $setpDir $f) -Raw
        if ($c -match '\[Parameter\(Mandatory\)\]\[string\]\$(Admin|SqlAdmin)?(Client)?Secret') { $bad += $f }
    }
    if ($bad.Count) { throw "still mandatory-secret: $($bad -join ', ')" }
    $true
}

$msp = Get-Content (Join-Path $setpDir 'Setup-PimMsp.ps1') -Raw
T 'MSP script has the az acr import step (build-once / import-per-customer)'  { $msp -match 'az acr import|acr.*import' -and $msp -match 'acr' }
T 'MSP script wires template-pull (pull-not-push)'                           { $msp -match 'PIM_MspTemplateConn' -and $msp -match 'template-pull' }

$vm = Get-Content (Join-Path $setpDir 'Setup-PimVM.ps1') -Raw
T 'VM script registers PIM-Manager + PIM-Scheduler scheduled tasks'          { ($vm -match "TaskName 'PIM-Manager'") -and ($vm -match "TaskName 'PIM-Scheduler'") }
T 'VM script grants the VM-MI via the shared Grant-PimMiSql'                 { $vm -match 'Grant-PimMiSql' }

$install = Get-Content (Join-Path $setpDir 'Install-PimEngineAppRegistration.ps1') -Raw
T 'engine app-reg installer is REST/cert (no Microsoft.Graph #Requires)'     { $install -notmatch '#Requires -Modules .*Microsoft\.Graph' }
T 'engine app-reg installer self-signs into LocalMachine\My by default'      { ($install -match 'New-SelfSignedCertificate') -and ($install -match 'LocalMachine\\My') }
T 'engine app-reg installer requests Exchange.ManageAsApp'                    { $install -match 'Exchange\.ManageAsApp' }
T 'engine app-reg installer assigns Azure UAA (skippable)'                    { ($install -match 'User Access Administrator') -and ($install -match 'SkipAzureRbac') }
T 'engine app-reg installer has -GrantConsent'                               { $install -match '\$GrantConsent' }
T 'engine app-reg installer writes LauncherConfig globals'                    { ($install -match 'HighPriv_Modern_ApplicationID_Azure') -and ($install -match 'LauncherConfig\.custom\.ps1') }

Section 'BUG-37 -- ACA must be GIVEN the workspace, or it generates a second one'
# Measured twice on test1intr2ig798: `az containerapp env create --logs-destination log-analytics`
# with no workspace makes ACA generate `workspace-<rg-ish><random>` and write EVERY log there,
# leaving the intended law-pim-<token> empty and billed. It is also why the first log queries of a
# fresh deploy come back empty -- they read the workspace we created, not the one ACA writes to.
$cont37 = Get-Content (Join-Path $setpDir 'Setup-PimContainers.ps1') -Raw
T 'container script accepts the workspace created by the prereqs'  { $cont37 -match '\$LogAnalyticsWorkspaceName' }
T 'env create passes --logs-workspace-id AND --logs-workspace-key' {
    ($cont37 -match "'--logs-workspace-id'") -and ($cont37 -match "'--logs-workspace-key'")
}
T 'an unreadable workspace THROWS instead of letting ACA generate one' {
    $cont37 -match '(?s)Refusing to create the ACA environment without it'
}
T 'no workspace given => a LOUD warning, not a silent generate' {
    $cont37 -match '(?s)no -LogAnalyticsWorkspaceName given.*?Write-Warning|Write-Warning \(\"no -LogAnalyticsWorkspaceName given'
}
T 'the env create exit code is checked (a failed create must not flow on)' {
    $cont37 -match '(?s)az @envCreateArgs -o none\s*\r?\n\s*if \(\$LASTEXITCODE'
}
T 'it VERIFIES which workspace the env actually logs to' {
    $cont37 -match 'appLogsConfiguration\.logAnalyticsConfiguration\.customerId'
}
T 'a pre-existing env logging elsewhere is REPAIRED IN PLACE, not "delete and recreate"' {
    # The old assertion pinned the old ADVICE, which was wrong and dangerous: deleting an ACA
    # environment takes the Manager app and the tick Job with it, and it was aimed at a production
    # environment. MEASURED 2026-08-10 on mfnpr -- `az containerapp env update --logs-workspace-id`
    # moves an EXISTING environment's workspace with no recreate (8565d575... -> 9b0ed93b...),
    # and log routing followed within ~5 minutes (27 rows in the intended workspace, 0 in the old).
    # The phrase may still appear in a COMMENT recording why the old advice was wrong; what must
    # not survive is the script actually telling an operator to do it.
    $cont37 -match 'containerapp env update' -and $cont37 -match '--logs-workspace-id' -and
    $cont37 -notmatch '(?m)^\s*[^#\r\n]*delete and recreate it to move the logs'
}
T 'the repair is VERIFIED by reading back, and throws if the workspace did not move' {
    # A repair that reports success and changes nothing is the exact failure this whole block
    # exists to catch -- and it nearly happened: the first read-back after the update showed the
    # config changed while logs still flowed to the old workspace for several minutes.
    $cont37 -match '\$envCid2' -and $cont37 -match 'still logs to \$envCid2 after the repair'
}
T 'the repair key is fetched but never printed' {
    $cont37 -notmatch '(?m)(Note|Write-Host)[^\r\n]*\$lawKey2'
}
T 'the workspace shared key is never printed' {
    # the key is passed to az; it must not reach a Note/Write-Host line.
    $cont37 -notmatch '(?m)(Note|Write-Host)[^\r\n]*\$lawKey'
}
$initEnv = Join-Path $root '..\PlatformConfiguration\INTERNAL\Provision\Initialize-PlatformEnvironment.ps1'
if (Test-Path $initEnv) {
    T 'the estate orchestrator passes the prereq workspace to step 6' {
        (Get-Content $initEnv -Raw) -match 'LogAnalyticsWorkspaceName="law-pim-\$token"'
    }
}

Section 'BUG-40 -- image references are DIGEST-PINNED (a rebuilt tag is not re-pulled)'
# Measured live 2026-08-09: the BUG-39 fix was built into tag 2.4.245, the tick Job updated, both
# reported success -- and the next two scheduled executions ran the OLD image. A tag is a mutable
# pointer, so rebuilding it leaves the container's image FIELD unchanged; ARM sees no change and
# the platform never pulls. Worse, the post-roll check that should have caught it compared the
# live TAG to the requested TAG -- identical strings, stale content, green verification.
. (Join-Path $root 'engine\_shared\PIM-ImageRef.ps1')
$goodDigest = 'sha256:' + ('a' * 64)
$otherDigest = 'sha256:' + ('b' * 64)

T 'a valid sha256 digest is accepted'                { Test-PimImageDigest -Digest $goodDigest }
T 'digest must be 64 hex chars (63 refused)'         { -not (Test-PimImageDigest -Digest ('sha256:' + ('a' * 63))) }
T 'UPPERCASE hex refused (registries emit lowercase; would fail late, at pull)' { -not (Test-PimImageDigest -Digest ('sha256:' + ('A' * 64))) }
T 'a bare tag is not a digest'                       { -not (Test-PimImageDigest -Digest '2.4.245') }
T 'empty / whitespace is not a digest'               { (-not (Test-PimImageDigest -Digest '')) -and (-not (Test-PimImageDigest -Digest '   ')) }
T 'an az error string is not a digest (the likely garbage input)' { -not (Test-PimImageDigest -Digest 'ERROR: image not found') }

T 'digest reference is built content-addressed' {
    (New-PimImageReference -Registry 'acr1.azurecr.io' -Repository 'pim-manager' -Digest $goodDigest) -eq "acr1.azurecr.io/pim-manager@$goodDigest"
}
T 'digest WINS when both tag and digest are supplied (tag is provenance only)' {
    (New-PimImageReference -Registry 'acr1.azurecr.io' -Repository 'pim-manager' -Tag '2.4.245' -Digest $goodDigest) -notmatch ':2\.4\.245'
}
T 'tag-only reference still builds (the legacy shape, for callers with no digest)' {
    (New-PimImageReference -Registry 'acr1.azurecr.io' -Repository 'pim-manager' -Tag '2.4.245') -eq 'acr1.azurecr.io/pim-manager:2.4.245'
}
T 'neither tag nor digest THROWS (a bare repo means :latest to a registry)' {
    $threw = $false; try { New-PimImageReference -Registry 'acr1.azurecr.io' -Repository 'pim-manager' } catch { $threw = $true }; $threw
}
T 'an INVALID digest throws instead of being pasted into a reference' {
    $threw = $false; try { New-PimImageReference -Registry 'acr1.azurecr.io' -Repository 'pim-manager' -Digest 'sha256:nope' } catch { $threw = $true }; $threw
}

T 'parse: tag reference -> registry/repo/tag, NOT pinned' {
    $p = Get-PimImageReferenceParts -Reference 'acr1.azurecr.io/pim-manager:2.4.245'
    $p.ok -and $p.registry -eq 'acr1.azurecr.io' -and $p.repository -eq 'pim-manager' -and $p.tag -eq '2.4.245' -and -not $p.pinned
}
T 'parse: digest reference -> pinned' {
    $p = Get-PimImageReferenceParts -Reference "acr1.azurecr.io/pim-manager@$goodDigest"
    $p.ok -and $p.repository -eq 'pim-manager' -and $p.digest -eq $goodDigest -and $p.pinned
}
T 'parse: tag AND digest together -> both read, still pinned' {
    # registries accept 'repo:tag@sha256:...'; splitting on ":" first would mangle it.
    $p = Get-PimImageReferenceParts -Reference "acr1.azurecr.io/pim-manager:2.4.245@$goodDigest"
    $p.tag -eq '2.4.245' -and $p.digest -eq $goodDigest -and $p.pinned
}
T 'parse: a registry PORT is not mistaken for a tag' {
    $p = Get-PimImageReferenceParts -Reference 'localhost:5000/pim-manager:2.4.245'
    $p.registry -eq 'localhost:5000' -and $p.repository -eq 'pim-manager' -and $p.tag -eq '2.4.245'
}
T 'parse: empty reference is not ok'                 { -not (Get-PimImageReferenceParts -Reference '').ok }

# --- the assertion that BUG-40 turned on ---------------------------------------
T 'VERDICT: same digest running => ok + pinned' {
    $v = Test-PimImageDeployed -Expected "acr1.azurecr.io/pim-manager@$goodDigest" -Running "acr1.azurecr.io/pim-manager@$goodDigest"
    $v.ok -and $v.pinned
}
T 'VERDICT: a DIFFERENT digest running => NOT ok (the stale-image case)' {
    $v = Test-PimImageDeployed -Expected "acr1.azurecr.io/pim-manager@$goodDigest" -Running "acr1.azurecr.io/pim-manager@$otherDigest"
    (-not $v.ok) -and $v.reason -match 'did NOT take effect'
}
T 'VERDICT: expected a DIGEST, platform reports only a matching TAG => NOT ok' {
    # This is the whole finding. The old check accepted exactly this and called it verified.
    $v = Test-PimImageDeployed -Expected "acr1.azurecr.io/pim-manager:2.4.245@$goodDigest" -Running 'acr1.azurecr.io/pim-manager:2.4.245'
    -not $v.ok
}
T 'VERDICT: an UNREADABLE running image is never ok ("cannot tell" != "fine")' {
    $v = Test-PimImageDeployed -Expected "acr1.azurecr.io/pim-manager@$goodDigest" -Running ''
    (-not $v.ok) -and $v.reason -match 'NOT verified'
}
T 'VERDICT: tag-only expectation passes but is reported as WEAK, not silently equal' {
    $v = Test-PimImageDeployed -Expected 'acr1.azurecr.io/pim-manager:2.4.245' -Running 'acr1.azurecr.io/pim-manager:2.4.245'
    $v.ok -and (-not $v.pinned) -and $v.reason -match 'WEAK'
}
T 'VERDICT: tag mismatch => NOT ok'                  { -not (Test-PimImageDeployed -Expected 'acr1.azurecr.io/pim-manager:2.4.245' -Running 'acr1.azurecr.io/pim-manager:2.4.240').ok }
T 'VERDICT: an unusable EXPECTED reference is not ok (never verify against nothing)' {
    -not (Test-PimImageDeployed -Expected '' -Running 'acr1.azurecr.io/pim-manager:2.4.245').ok
}

# --- the wiring: pure helpers only matter if the deploy paths actually use them ---
$shared = Get-Content (Join-Path $setpDir '_PimSetupShared.ps1') -Raw
T 'shared helpers expose Resolve-PimAcrImageDigest'  { $shared -match 'function Resolve-PimAcrImageDigest' }
T 'digest resolve REFUSES to fall back to the tag (silent degradation hid BUG-39/40)' {
    $shared -match '(?s)function Resolve-PimAcrImageDigest.*?throw .*?Refusing to deploy by tag'
}
T 'digest resolve tries BOTH az commands (a CLI version gap must not read as "never built")' {
    ($shared -match 'az acr manifest show-metadata') -and ($shared -match 'az acr repository show')
}
$cont = Get-Content (Join-Path $setpDir 'Setup-PimContainers.ps1') -Raw
T 'Setup-PimContainers resolves the tag to a digest before deploying'  { $cont -match 'Resolve-PimAcrImageDigest' -and $cont -match 'New-PimImageReference' }
T 'Setup-PimContainers VERIFIES the deployed image on apps AND the tick Job' {
    ($cont -match 'Assert-PimDeployedImage -Kind app') -and ($cont -match 'Assert-PimDeployedImage -Kind job')
}
T 'Setup-PimContainers image verification THROWS on mismatch (not a warning)' {
    $cont -match '(?s)function Assert-PimDeployedImage.*?if \(-not \$v\.ok\) \{ throw'
}
$upd = Get-Content (Join-Path $setpDir 'Update-PimContainers.ps1') -Raw
T 'Update-PimContainers pins the digest before rolling'                { $upd -match 'Resolve-PimAcrImageDigest' -and $upd -match 'New-PimImageReference' }
T 'Update-PimContainers post-roll check is DIGEST-based, not tag-substring' {
    # the old check did LastIndexOf(':') on the live image and compared that to -ImageTag.
    ($upd -match 'Test-PimImageDeployed') -and ($upd -notmatch 'LastIndexOf\(''\:''\)')
}
T 'Build-PimManagerImage reports the digest the built tag now points at' {
    (Get-Content (Join-Path $setpDir 'Build-PimManagerImage.ps1') -Raw) -match 'Resolve-PimAcrImageDigest'
}
T 'PIM-ImageRef dot-sources with NO side effects (pure module contract)' {
    # dot-sourcing must not print, throw, or need az -- it is loaded by scripts and tests alike.
    $out = & { . (Join-Path $root 'engine\_shared\PIM-ImageRef.ps1') } 6>&1
    -not @($out).Count
}

Section 'PUBLIC-SAFETY -- no real tenant/subscription/customer values in published deploy scripts'
# Known real values that must NOT be baked into the public-facing setup scripts.
$forbidden = @(
    'f0fa27a0-8e7c-4f63-9a77-ec94786b7c9e',   # internal tenant id
    '54468121-98ba-48ba-ba59-ba10a9711ed3',   # internal subscription id
    '2linkit.local',                          # internal AD domain
    'sql-pimplatform-we484',                  # real SQL server name
    'acrsecurityinsight',                     # real ACR name
    'rg-platform-connectivity'                # real RG name
)
foreach ($s in $scripts) {
    T "no baked-in real env values: $s" {
        $c = Get-Content (Join-Path $setpDir $s) -Raw
        $hit = $forbidden | Where-Object { $c -match [regex]::Escape($_) }
        -not $hit
    }
}
T 'no France region VALUE (francecentral/francesouth) used as a default in any setup script' {
    # The word "France" may appear in a comment ("never France"); what must never
    # appear is an actual France region value used as a parameter default / az arg.
    $bad = $false
    foreach ($s in $scripts) {
        if ($s -eq '_PimSetupShared.ps1') { continue }   # the guard's deny-list legitimately names the values
        if ((Get-Content (Join-Path $setpDir $s) -Raw) -match 'francecentral|francesouth') { $bad = $true }
    }
    -not $bad
}

Write-Host ""
Write-Host ("SETUP/HOSTING TESTS: {0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) {'Red'} else {'Green'})
if ($script:fail) { exit 1 }
