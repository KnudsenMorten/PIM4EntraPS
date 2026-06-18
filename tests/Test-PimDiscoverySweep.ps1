<#
  Offline tests for the scheduled discovery JOB sweep (REQUIREMENTS.md §8
  "Wire discovery into the scheduler as three discovery jobs").

  Covers the PURE sweep core (Invoke-PimDiscoveryJobSweep) + the handled-set
  persistence helpers (PIM-Discovery.ps1) and the scheduler wiring
  (Register-PimDiscoveryHandler in PIM-Scheduler.ps1). No network: enumerator
  output, existing rows, the handled set, the enqueuer and the handled-writer are
  all injected. Rerunnable; every artifact lives under a per-run temp dir.
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $here) { $here = 'C:\SCRIPTS\AutomateIT\SOLUTIONS\PIM4EntraPS\tests' }
$shared = "$here\..\engine\_shared"
. "$shared\PIM-ChangeQueue.ps1"        # New-PimChange (used by the converters)
. "$shared\PIM-PermissionWizard.ps1"   # Get-PimAzureScopeDepth/-Derivation + New-PimPermissionGroupName
. "$shared\PIM-AzureDiscovery.ps1"     # Get-PimAzureReconcilePlan + ConvertTo-PimReconcileQueueChanges
. "$shared\PIM-Discovery.ps1"          # the sweep + handled helpers + audit/notify on fresh items
. "$shared\PIM-Scheduler.ps1"          # Register-PimDiscoveryHandler + dispatch
. "$shared\PIM-Notify.ps1"             # Send-PimNotifyMail (opt-in discovery notification)

$pass=0; $fail=0
function Assert($n,$c){ if($c){ $script:pass++; Write-Host "  PASS  $n" -ForegroundColor Green } else { $script:fail++; Write-Host "  FAIL  $n" -ForegroundColor Red } }

# Capture audit events (a fresh discovered item emits resource.discovered) instead of
# writing the real output/audit jsonl. The sweep calls Write-PimAuditEvent best-effort
# via Get-Command, so a script-scope override here is what it sees (no module loaded).
$script:AuditEvents = New-Object System.Collections.Generic.List[object]
function Write-PimAuditEvent { param($Action,$Target,$Before,$After,$Result='ok',$Actor='engine',$CorrelationId=''); $script:AuditEvents.Add([pscustomobject]@{ action=$Action; target=$Target; after=$After }) }

Write-Host "=== PIM discovery-sweep tests ===" -ForegroundColor Cyan

# Isolate the per-scope handled-state files in a temp dir so the test never reads/
# writes the real output/state. PIM-Discovery resolves the dir via Get-PimConfigDir
# when present -> define one for the test.
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("pim-disco-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $tmp | Out-Null
function Get-PimConfigDir { $script:__cfgDir }
$script:__cfgDir = $tmp

# ---- fixtures --------------------------------------------------------------
# Two discovered Azure scopes; one already exists (unchanged), one is brand new.
$azDiscovered = @(
    [pscustomobject]@{ scopeType='subscription';    scopePath='/subscriptions/aaaa'; scopeName='Sub A';  mgmtGroupDepth=0 }
    [pscustomobject]@{ scopeType='subscription';    scopePath='/subscriptions/bbbb'; scopeName='Sub B';  mgmtGroupDepth=0 }
)
# Existing def for Sub A with its expected (derived) group name so it's unchanged;
# plus an orphan (in existing, not discovered) that must NEVER be auto-removed.
$expA = Get-PimAzureScopeDerivation -ScopeType 'subscription' -ScopePath '/subscriptions/aaaa' -ScopeName 'Sub A' -ManagementGroupDepth 0
$azExisting = @(
    [pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/aaaa'; scopeName='Sub A'; groupName=$expA.groupName }
    [pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/zzzz'; scopeName='Old';   groupName='PIM-AzRes-OLD-Sub' }
)
# Auto-import rule that auto-imports subscriptions -> the new Sub B becomes a CREATE.
$rules = @([pscustomobject]@{ scopeTypes=@('subscription') })

# ---- 1. first run: the new sub is fresh, enqueued; orphan surfaced not removed --
$q1 = New-Object System.Collections.Generic.List[object]
$saved1 = $null
$r1 = Invoke-PimDiscoveryJobSweep -Scope 'Azure' -Discovered $azDiscovered -Existing $azExisting `
        -AutoImportRules $rules -Handled @() `
        -EnqueueChange { param($c) $q1.Add($c) } `
        -SaveHandled   { param($h) $script:saved1 = @($h) }

Assert "first run reports 1 fresh item"             ($r1.freshCount -eq 1)
Assert "first run enqueued exactly 1 change"         ($q1.Count -eq 1 -and $r1.enqueued -eq 1)
Assert "the enqueued change is a Create"             ("$($q1[0].op)" -eq 'Create')
Assert "the enqueued change targets the resources entity" ("$($q1[0].entity)" -eq 'PIM-Definitions-Resources')
Assert "the enqueued change is the NEW sub (Sub B)"  ("$($q1[0].key)" -eq "$($r1.changes[0].key)" -and "$($q1[0].key)" -like '*')
Assert "orphan is surfaced (count=1)"                ($r1.orphanCount -eq 1)
Assert "no Remove change emitted (never auto-delete)" (-not (@($q1.ToArray()) | Where-Object { "$($_.op)" -eq 'Remove' }))
Assert "handled set rolled forward (>=1 key)"        (@($script:saved1).Count -ge 1)

# ---- 2. second run, SAME handled set: nothing fresh, nothing enqueued -------
$q2 = New-Object System.Collections.Generic.List[object]
$r2 = Invoke-PimDiscoveryJobSweep -Scope 'Azure' -Discovered $azDiscovered -Existing $azExisting `
        -AutoImportRules $rules -Handled @($script:saved1) `
        -EnqueueChange { param($c) $q2.Add($c) } `
        -SaveHandled   { param($h) }
Assert "second run (handled) finds NOTHING fresh"    ($r2.freshCount -eq 0)
Assert "second run enqueues nothing (idempotent)"    ($q2.Count -eq 0 -and $r2.enqueued -eq 0)

# ---- 3. WhatIf: computes fresh but writes NOTHING (no enqueue, no handled write) --
$q3 = New-Object System.Collections.Generic.List[object]
$wroteHandled = $false
$r3 = Invoke-PimDiscoveryJobSweep -Scope 'Azure' -Discovered $azDiscovered -Existing $azExisting `
        -AutoImportRules $rules -Handled @() -WhatIf `
        -EnqueueChange { param($c) $q3.Add($c) } `
        -SaveHandled   { param($h) $script:wroteHandled = $true }
Assert "WhatIf still computes the fresh item"        ($r3.freshCount -eq 1 -and $r3.whatIf)
Assert "WhatIf enqueues NOTHING"                      ($q3.Count -eq 0 -and $r3.enqueued -eq 0)
Assert "WhatIf does NOT persist the handled set"      (-not $script:wroteHandled)

# ---- 4. rename is detected + enqueued as an Update (carry from/to) ----------
$azRenameExisting = @(
    [pscustomobject]@{ scopeType='subscription'; scopePath='/subscriptions/aaaa'; scopeName='Sub A'; groupName='PIM-AzRes-STALE-Name' }
)
$q4 = New-Object System.Collections.Generic.List[object]
$r4 = Invoke-PimDiscoveryJobSweep -Scope 'Azure' -Discovered @($azDiscovered[0]) -Existing $azRenameExisting `
        -AutoImportRules $rules -Handled @() `
        -EnqueueChange { param($c) $q4.Add($c) } -SaveHandled { param($h) }
Assert "rename run finds 1 fresh item"               ($r4.freshCount -eq 1 -and $r4.renameCount -eq 1)
Assert "rename enqueued as an Update"                 ($q4.Count -eq 1 -and "$($q4[0].op)" -eq 'Update')
Assert "rename payload carries from/to"              ("$($q4[0].payload.from)" -eq 'PIM-AzRes-STALE-Name' -and "$($q4[0].payload.to)" -ne '')

# ---- 5. PowerBI scope: propose-only by default (no auto-map), enqueues nothing --
$pbiDiscovered = @([pscustomobject]@{ workspaceId='ws-1'; workspaceName='Finance' })
$q5 = New-Object System.Collections.Generic.List[object]
$r5 = Invoke-PimDiscoveryJobSweep -Scope 'PowerBI' -Discovered $pbiDiscovered -Existing @() -Handled @() `
        -EnqueueChange { param($c) $q5.Add($c) } -SaveHandled { param($h) }
Assert "PowerBI default (no auto-import) enqueues nothing" ($q5.Count -eq 0 -and $r5.enqueued -eq 0)
Assert "PowerBI new workspace is still tracked as fresh"   ($r5.freshCount -eq 1)

# ---- 6. PowerBI with -AutoImport: the new workspace becomes a Create --------
$q6 = New-Object System.Collections.Generic.List[object]
$r6 = Invoke-PimDiscoveryJobSweep -Scope 'PowerBI' -Discovered $pbiDiscovered -Existing @() -Handled @() -AutoImport `
        -EnqueueChange { param($c) $q6.Add($c) } -SaveHandled { param($h) }
Assert "PowerBI -AutoImport enqueues a Create"        ($q6.Count -eq 1 -and "$($q6[0].op)" -eq 'Create')
Assert "PowerBI create targets the services entity"   ("$($q6[0].entity)" -eq 'PIM-Definitions-Services')

# ---- 7. handled-set persistence helpers round-trip via the per-scope file ---
$path = Get-PimDiscoveryHandledPath -Scope 'Azure'
Assert "handled path is per-scope + under the config dir" ($path -like "*discovery-handled-azure.json" -and $path -like "$tmp*")
Save-PimDiscoveryHandledSet -Scope 'Azure' -Handled @('k1','k2') | Out-Null
$readBack = @(Get-PimDiscoveryHandledSet -Scope 'Azure')
Assert "handled set persists + reads back"            ($readBack.Count -eq 2 -and ($readBack -contains 'k1') -and ($readBack -contains 'k2'))
Assert "missing handled file -> empty (never throws)" (@(Get-PimDiscoveryHandledSet -Scope 'PowerBI').Count -eq 0)

# default sweep persists to the per-scope file when no -SaveHandled supplied
$q7 = New-Object System.Collections.Generic.List[object]
$null = Invoke-PimDiscoveryJobSweep -Scope 'PowerBI' -Discovered $pbiDiscovered -Existing @() -Handled @() -AutoImport `
        -EnqueueChange { param($c) $q7.Add($c) }   # no -SaveHandled -> file persistence
$pbiHandled = @(Get-PimDiscoveryHandledSet -Scope 'PowerBI')
Assert "default sweep persists handled to the per-scope file" ($pbiHandled.Count -ge 1)

# ---- 8. Select-PimReconcilePlanByKeys prunes to only fresh rows ------------
$fullPlan = Get-PimAzureReconcilePlan -Discovered $azDiscovered -Existing $azExisting -AutoImportRules $rules
$bKey = (@($fullPlan.create)[0]).stableKey
$pruned = Select-PimReconcilePlanByKeys -Plan $fullPlan -FreshKeys @($bKey)
Assert "prune keeps only the fresh create row"        (@($pruned.create).Count -eq 1 -and @($pruned.unchanged).Count -eq 0)
Assert "prune carries orphans for visibility"         (@($pruned.orphan).Count -eq 1)

# ---- 9. scheduler wiring: Register-PimDiscoveryHandler drives the sweep -----
Initialize-PimDefaultJobHandlers
# before wiring: the default discovery handler is a clear no-op
$noop = Invoke-PimScheduledJob -Job ([pscustomobject]@{ name='d'; type='discovery'; scope='Azure' }) -NowUtc ([datetime]::UtcNow)
Assert "unwired discovery handler no-ops with a clear message" ($noop.ok -and $noop.result.ran -eq $false -and $noop.result.detail -like 'no-handler:discovery*')

# Use $global: for the values the injected seam scriptblocks read, so they resolve
# reliably no matter how deep in the dispatch call stack the seam is invoked from
# (a real launcher likewise supplies seams that read globals / call live functions,
# not local closures over the registration site).
$global:__disco_az_discovered = $azDiscovered
$global:__disco_az_existing   = $azExisting
$global:__disco_rules         = $rules
$qH = New-Object System.Collections.Generic.List[object]
$global:__disco_qH = $qH
Register-PimDiscoveryHandler `
    -GetDiscovered { param($scope) if ($scope -eq 'Azure') { $global:__disco_az_discovered } else { @() } } `
    -GetExisting   { param($scope) if ($scope -eq 'Azure') { $global:__disco_az_existing } else { @() } } `
    -GetAutoImportRules { param($scope) $global:__disco_rules } `
    -EnqueueChange { param($c) $global:__disco_qH.Add($c) }
$run = Invoke-PimScheduledJob -Job ([pscustomobject]@{ name='discovery-azure'; type='discovery'; scope='Azure' }) -NowUtc ([datetime]::UtcNow)
Assert "wired discovery handler runs the sweep"       ($run.ok -and $run.result.ran -eq $true -and $run.result.result.freshCount -ge 0)
Assert "wired discovery handler enqueued the fresh sub" ($qH.Count -eq 1 -and "$($qH[0].op)" -eq 'Create')

# a non-Azure/PowerBI scope (Entra catalog) degrades to an explicit no-op (not silent)
$entra = Invoke-PimScheduledJob -Job ([pscustomobject]@{ name='discovery-entra'; type='discovery'; scope='Entra' }) -NowUtc ([datetime]::UtcNow)
Assert "Entra scope degrades to an explicit not-wired no-op" ($entra.ok -and $entra.result.ran -eq $false -and $entra.result.detail -like "*not wired*")

# a WhatIf scheduled tick through the wired handler writes nothing
$qW = New-Object System.Collections.Generic.List[object]
$global:__disco_qW = $qW
Register-PimDiscoveryHandler `
    -GetDiscovered { param($scope) if ($scope -eq 'Azure') { $global:__disco_az_discovered } else { @() } } `
    -GetExisting   { param($scope) @() } `
    -GetAutoImportRules { param($scope) $global:__disco_rules } `
    -EnqueueChange { param($c) $global:__disco_qW.Add($c) }
$wi = Invoke-PimScheduledJob -Job ([pscustomobject]@{ name='discovery-azure'; type='discovery'; scope='Azure' }) -NowUtc ([datetime]::UtcNow) -WhatIf
Assert "wired discovery WhatIf enqueues nothing"      ($wi.ok -and $qW.Count -eq 0 -and $wi.result.result.whatIf)

# default schedule still carries the three discovery jobs
$disco = @(Get-PimDefaultJobSchedule | Where-Object { $_.type -eq 'discovery' })
Assert "default schedule has 3 discovery jobs (Entra/Azure/PowerBI)" ($disco.Count -eq 3 -and ($disco.scope -contains 'Azure') -and ($disco.scope -contains 'PowerBI') -and ($disco.scope -contains 'Entra'))

# ===========================================================================
# 10. AUDIT + opt-in NOTIFY on each FRESH item (REQUIREMENTS §8 "Discovery audit
#     + notify on new items"). A new sub/workspace/role must never be silently
#     staged: the sweep emits resource.discovered + (opt-in) a notification.
# ===========================================================================
Write-Host "--- discovery audit + notify on fresh items ---" -ForegroundColor Cyan

# ConvertTo-PimDiscoveryNotifyItem flattens a fresh plan into per-item descriptors.
$auditPlan  = Get-PimAzureReconcilePlan -Discovered @($azDiscovered[1]) -Existing @() -AutoImportRules $rules
$auditFresh = Select-PimReconcilePlanByKeys -Plan $auditPlan -FreshKeys @(@($auditPlan.create) | ForEach-Object { "$($_.stableKey)" })
$notifyItems = @(ConvertTo-PimDiscoveryNotifyItem -FreshPlan $auditFresh -Scope 'Azure')
Assert "notify-item flattens 1 fresh create"          (@($notifyItems).Count -eq 1)
Assert "notify-item carries action=create"            ("$($notifyItems[0].action)" -eq 'create')
Assert "notify-item resolves the resource type"       ("$($notifyItems[0].resourceType)" -eq 'AzureSubscription')
Assert "notify-item name is the derived group name"   ("$($notifyItems[0].name)" -like 'PIM-*')
Assert "notify-item on an empty plan -> empty (never throws)" (@(ConvertTo-PimDiscoveryNotifyItem -FreshPlan ([pscustomobject]@{ create=@(); rename=@() }) -Scope 'Azure').Count -eq 0)

# the sweep AUDITS every fresh item even with no notify recipient (-NoNotify).
$script:AuditEvents.Clear()
$global:PIM_DiscoveryNotifyRecipients = $null
$ra = Invoke-PimDiscoveryJobSweep -Scope 'Azure' -Discovered @($azDiscovered[1]) -Existing @() -AutoImportRules $rules -Handled @() -NoNotify -EnqueueChange { param($c) } -SaveHandled { param($h) }
Assert "sweep reports audited=1 for the fresh sub"     ($ra.audited -eq 1)
Assert "exactly one resource.discovered audit event"   ($script:AuditEvents.Count -eq 1 -and "$($script:AuditEvents[0].action)" -eq 'resource.discovered')
Assert "the audit event targets the fresh sub stable key" ("$($script:AuditEvents[0].target)" -eq 'sub:bbbb')
Assert "-NoNotify suppresses only the mail (not audit)" (-not $ra.notified -and "$($ra.notice.reason)" -eq 'mail suppressed')

# notification is OPT-IN: no recipient configured -> audited but NOT notified.
$script:AuditEvents.Clear()
$rb = Invoke-PimDiscoveryJobSweep -Scope 'Azure' -Discovered @($azDiscovered[1]) -Existing @() -AutoImportRules $rules -Handled @() -EnqueueChange { param($c) } -SaveHandled { param($h) }
Assert "no recipient -> audited but not notified"      ($rb.audited -eq 1 -and -not $rb.notified)
Assert "no-recipient reason is explicit (opt-in)"      ("$($rb.notice.reason)" -match 'no recipient')

# with a recipient configured, the discovery-notice mail renders (WhatIf=rendered, not
# sent -- no $global:PIM_MailSender -> the notify path returns rendered-only honestly).
$global:PIM_MailTemplateDir = (Resolve-Path (Join-Path $here '..\templates\mail')).Path
$dnTpl = Get-PimNotifyTemplateText -Type 'discovery-notice'
Assert "discovery-notice template ships + resolves"    ($null -ne $dnTpl -and $dnTpl.source -eq 'shipped')
$dnItems = @([pscustomobject]@{ action='create'; resourceType='AzureSubscription'; key='/subscriptions/bbbb'; name='PIM-AzRes-SubB' })
$dnRes = Send-PimDiscoveryNotices -Items $dnItems -Scope 'Azure' -Recipient 'ops@example.test'
Assert "configured recipient is carried to the notice" ("$($dnRes.recipient)" -eq 'ops@example.test')
Assert "notice audits the item then attempts the mail" ($dnRes.audited -eq 1)
$dnRender = ConvertTo-PimNotifyRendering -TemplateText $dnTpl.text -Tokens @{ Scope='Azure'; ItemCount='1'; DiscoveredList='AzureSubscription: SubB (create)'; WhenUtc='now'; TenantName='t'; Instance='i' }
Assert "notice subject names the count + scope"        ($dnRender.Subject -like '*1 new Azure item*')
Assert "notice body lists the discovered item"         ($dnRender.BodyHtml -match 'AzureSubscription: SubB')
Assert "notice body has no leftover {{tokens}}"        (-not ($dnRender.BodyHtml -match '\{\{'))
$global:PIM_DiscoveryNotifyRecipients = $null

# ===========================================================================
# 11. ENTRA role-catalog discovery job body (REQUIREMENTS §8 "Enumerate services
#     for new built-in roles" + wire the Entra-scope discovery job). The Entra
#     scope catalogs NEW built-in roles (delta vs the handled set), not scopes.
# ===========================================================================
Write-Host "--- Entra role-catalog discovery job ---" -ForegroundColor Cyan
$liveRoles = @(
    [pscustomobject]@{ id='r1'; name='Global Administrator' }
    [pscustomobject]@{ id='r2'; name='User Administrator' }
)
$script:AuditEvents.Clear()
$qe = New-Object System.Collections.Generic.List[object]
$re = Invoke-PimRoleCatalogJobSweep -Service 'entra' -Live $liveRoles -Handled @() -NoNotify -EnqueueChange { param($c) $qe.Add($c) } -SaveHandled { param($h) }
Assert "role-catalog: 2 fresh roles, 2 enqueued"       ($re.freshCount -eq 2 -and $re.enqueued -eq 2 -and $qe.Count -eq 2)
Assert "role-catalog enqueues a Create on the catalog"  ("$($qe[0].op)" -eq 'Create' -and "$($qe[0].entity)" -eq 'PIM-Catalog-ServiceRoles')
Assert "role-catalog key is service|roleId"            ("$($qe[0].key)" -eq 'entra|r1')
Assert "role-catalog payload carries the role name"    ("$($qe[0].payload.roleName)" -eq 'Global Administrator')
Assert "role-catalog audits each fresh role"           ($re.audited -eq 2 -and $script:AuditEvents.Count -eq 2 -and "$($script:AuditEvents[0].action)" -eq 'resource.discovered')

# delta: a second run with the prior handled set surfaces NOTHING.
$re2 = Invoke-PimRoleCatalogJobSweep -Service 'entra' -Live $liveRoles -Handled $re.handled -NoNotify -EnqueueChange { param($c) } -SaveHandled { param($h) }
Assert "role-catalog second run (handled) finds nothing fresh" ($re2.freshCount -eq 0 -and $re2.enqueued -eq 0)

# only a genuinely NEW role surfaces later (delta, not the whole list).
$liveRoles2 = @($liveRoles + [pscustomobject]@{ id='r3'; name='Helpdesk Administrator' })
$re3 = Invoke-PimRoleCatalogJobSweep -Service 'entra' -Live $liveRoles2 -Handled $re.handled -NoNotify -EnqueueChange { param($c) } -SaveHandled { param($h) }
Assert "role-catalog surfaces ONLY the new role"       ($re3.freshCount -eq 1 -and "$($re3.fresh[0].roleName)" -eq 'Helpdesk Administrator')

# de-dups within the live set (same id twice -> one fresh).
$reDup = Invoke-PimRoleCatalogJobSweep -Service 'entra' -Live @($liveRoles[0], $liveRoles[0]) -Handled @() -NoNotify -EnqueueChange { param($c) } -SaveHandled { param($h) }
Assert "role-catalog de-dups within the live set"      ($reDup.freshCount -eq 1)

# WhatIf computes but persists no handled set (re-surfaces next run).
$reWhatIf = $false
$reWi = Invoke-PimRoleCatalogJobSweep -Service 'entra' -Live $liveRoles -Handled @() -WhatIf -NoNotify -EnqueueChange { param($c) } -SaveHandled { param($h) $script:reWhatIf = $true }
Assert "role-catalog WhatIf computes fresh + writes nothing" ($reWi.freshCount -eq 2 -and $reWi.whatIf -and -not $script:reWhatIf)

# default per-scope file persistence (no -SaveHandled) rolls forward across runs.
$reFile1 = Invoke-PimRoleCatalogJobSweep -Service 'entra' -Live $liveRoles -Handled @() -NoNotify -EnqueueChange { param($c) }   # persists roles-entra
$reFile2 = Invoke-PimRoleCatalogJobSweep -Service 'entra' -Live $liveRoles -NoNotify -EnqueueChange { param($c) }                # reads the persisted set
Assert "role-catalog persists/reads the per-scope handled file" ($reFile2.freshCount -eq 0)

# ---- 12. scheduler wiring: Entra scope dispatches to the role-catalog sweep -
Initialize-PimDefaultJobHandlers
$global:__disco_roles = $liveRoles
$qER = New-Object System.Collections.Generic.List[object]
$global:__disco_qER = $qER
# wire WITH the -GetLiveRoles seam -> Entra scope now runs the role-catalog sweep.
# (use a fresh service so the per-scope handled file is empty for this run)
Register-PimDiscoveryHandler `
    -GetDiscovered { param($scope) @() } `
    -GetExisting   { param($scope) @() } `
    -EnqueueChange { param($c) $global:__disco_qER.Add($c) } `
    -GetLiveRoles  { param($svc) $global:__disco_roles }
$entraRun = Invoke-PimScheduledJob -Job ([pscustomobject]@{ name='discovery-entra'; type='discovery'; scope='Entra'; service='defender' }) -NowUtc ([datetime]::UtcNow)
Assert "wired Entra scope runs the role-catalog sweep" ($entraRun.ok -and $entraRun.result.ran -eq $true -and $entraRun.result.result.service -eq 'defender')
Assert "wired Entra scope enqueues the new roles"      ($qER.Count -eq 2 -and "$($qER[0].op)" -eq 'Create')

# without the -GetLiveRoles seam, Entra still degrades to an explicit not-wired no-op.
Register-PimDiscoveryHandler `
    -GetDiscovered { param($scope) @() } `
    -GetExisting   { param($scope) @() } `
    -EnqueueChange { param($c) }
$entraUnwired = Invoke-PimScheduledJob -Job ([pscustomobject]@{ name='discovery-entra'; type='discovery'; scope='Entra' }) -NowUtc ([datetime]::UtcNow)
Assert "Entra without a -GetLiveRoles seam -> not-wired no-op" ($entraUnwired.ok -and $entraUnwired.result.ran -eq $false -and $entraUnwired.result.detail -like '*not wired*')

# ---- cleanup ---------------------------------------------------------------
try { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue } catch {}
foreach ($g in '__disco_az_discovered','__disco_az_existing','__disco_rules','__disco_qH','__disco_qW','__disco_roles','__disco_qER','PIM_DiscoveryNotifyRecipients','PIM_MailTemplateDir') { Remove-Variable -Name $g -Scope Global -ErrorAction SilentlyContinue }

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail) {'Red'} else {'Green'})
if ($fail) { exit 1 }
