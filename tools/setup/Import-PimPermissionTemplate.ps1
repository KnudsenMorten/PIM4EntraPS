#Requires -Version 5.1
<#
.SYNOPSIS
    REQ-U (IaC import) -- import permission template packs (templates\<id>.template.json) into ONE environment's store,
    by script: the same rows the Manager's Templates card offers, committed the way Review & Save commits them.

.DESCRIPTION
    Operator, 2026-09-19: "can you import with script. we need to be able to do this via script" / "iac" / "so 25 tenants
    can be prepped". tools\setup\Invoke-PimTenantPrep.ps1 drives this script across many environments.

    PLAN (engine\_shared\PIM-TemplatePacks.ps1 -- the planning logic of GET /api/templates, proven identical by
    tests\Test-PimTemplateImport.ps1):
      * the rows of each pack this environment does not have yet, NAMED BY THIS TENANT: the group pattern is read from
        the store exactly as the Manager reads it (pim.Settings 'NamingConventions' over the shipped defaults);
      * a group definition and its workload binding row(s) are ONE unit; -Only narrows to some groups and is always
        WIDENED to whole units -- never a group without its workload role, never a role without its group;
      * a row carrying the all-zero subscription is a placeholder and never imported (REQ 70.13).
    COMMIT, per entity, definitions first (the Manager's Invoke-PimManagerSafeCommit shape):
      snapshot (New-PimCommitSnapshot + Save-PimSqlBackupSnapshot) -> Set-PimSqlEntityRowsTransactional with the CURRENT
      rows + the new ones (never -AllowEmpty: this only ever ADDS) -> restore the snapshot on failure
      (Invoke-PimCommitTransaction) -> prune to the last 10 snapshots.
      A failure in a later entity ALSO restores the entities of that pack already written, so a pack never lands half
      (a group without its binding is the orphan units exist to prevent).
      Refused BEFORE any write: an added row whose STORE key collides with another row of the entity (the store keys
      workload bindings on GroupTag alone -- BUG-204 -- so the add would overwrite an existing binding).
    THEN every planned row is READ BACK by its key, and the import is audited (pim.AuditEvents, action 'template.import',
    target 'template:<id>', with the counts).

    IDEMPOTENT: a pack whose rows are all present adds nothing, writes nothing (no snapshot, no audit) and says
    "already imported". -WhatIf prints the plan and writes nothing.

    WORKLOAD PREREQUISITES ARE NEVER A REFUSAL. Operator rule (REQ-W): groups are always deployable; only the workload
    ROLE ASSIGNMENT waits. Per pack workload (Get-PimWorkloadPrereqTemplateMap) the state recorded by
    tools\setup\Initialize-PimWorkloadPrereqs.ps1 (pim.Settings 'WorkloadPrereqs') is reported, and a not-green workload
    is named as HELD by the engine, with the command that makes it green.

    Identity: a CERTIFICATE identity (-ClientId + -CertThumbprint, cert in LocalMachine\My) or -UseSignedInAccount (the
    signed-in az user) -- a member of the store's SQL admin group. Never a client secret. Run under Windows PowerShell
    5.1 (System.Data.SqlClient; the same code under pwsh 7 was measured failing login against Azure SQL).

    Exit: 0 = done (including nothing to do), 1 = an error (a pack failed, or the store could not be reached / read).

.EXAMPLE
    .\tools\setup\Import-PimPermissionTemplate.ps1 -Template intune,defender-xdr -TenantId <tenant> `
        -SqlServerFqdn <server>.database.windows.net -ClientId <management-app-id> -CertThumbprint <thumb>

.EXAMPLE
    # every pack not disabled on the Governance page, plan only:
    .\tools\setup\Import-PimPermissionTemplate.ps1 -Template all-active -TenantId <tenant> -SqlServerFqdn <server> -UseSignedInAccount -WhatIf

.EXAMPLE
    # two groups of the Defender pack (tag or tenant group name), each with its workload role:
    .\tools\setup\Import-PimPermissionTemplate.ps1 -Template defender-xdr -Only Defender-XDR-SecurityOperations-Operator-L3 ... -PassThru
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Pack ids (templates\<id>.template.json), or 'all-active' = every shipped pack not disabled in this environment's
    # pim.Settings 'TemplateState' (the Governance page's enable/disable).
    [Parameter(Mandatory)][string[]]$Template,
    [string]$SqlServerFqdn,
    [string]$SqlDatabase = 'PimPlatform',
    [string]$TenantId,
    # Certificate identity -- OR -UseSignedInAccount.
    [string]$ClientId,
    [string]$CertThumbprint,
    [switch]$UseSignedInAccount,
    # A store reached by connection string instead (a local store; the offline tests). Not combined with -SqlServerFqdn.
    [string]$ConnectionString,
    # Group tags (or tenant group names) to import; widened to whole units. Empty = the whole pack.
    [string[]]$Only = @(),
    [switch]$PassThru,
    # TEST SEAM (tests\Test-PimTemplateImport.ps1): fail the apply of this entity mid-transaction, to prove the restore.
    # Never set in production.
    [string]$TestFailApplyEntity
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '_PimSetupSql.ps1')      # Connect-PimSetupStore / Write-PimSetupAudit (+ PIM-Rest, PIM-SqlStore)
$solRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $solRoot 'engine\_shared\PIM-CommitBackup.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-Naming.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-TemplatePacks.ps1')
. (Join-Path $solRoot 'engine\_shared\PIM-WorkloadPrereqs.ps1')
function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Note($m) { Write-Host "    $m" -ForegroundColor DarkGray }
$backupKeep = 10   # the Manager's $script:PimBackupKeep

$result = [ordered]@{ ok = $false; tenantId = "$TenantId".Trim(); whatIf = [bool]$WhatIfPreference; addedTotal = 0; packs = @(); errors = @() }
$packResults = New-Object System.Collections.Generic.List[object]
$errors = New-Object System.Collections.Generic.List[string]

function Get-PimImportEntityOrder {
    # Definitions before assignments: a failure in a binding entity then restores the definitions already written.
    param([string[]]$Bases)
    @(@($Bases | Where-Object { $_ -like '*-Definitions-*' }) + @($Bases | Where-Object { $_ -notlike '*-Definitions-*' }))
}

function Get-PimImportHeader {
    # The snapshot's header: every column of the rows it holds (the Manager passes its grid header; informational).
    param([object[]]$Rows)
    $h = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows)) { if ($null -eq $r) { continue }; foreach ($p in $r.PSObject.Properties) { if (-not $h.Contains($p.Name)) { $h.Add($p.Name) } } }
    return @($h.ToArray())
}

try {
    # --- the store ---------------------------------------------------------------------------------------------------
    if ("$ConnectionString".Trim()) {
        if ("$SqlServerFqdn".Trim() -or "$ClientId".Trim() -or "$CertThumbprint".Trim() -or $UseSignedInAccount) { throw 'give -ConnectionString OR -SqlServerFqdn with an identity, not both.' }
        $cs = "$ConnectionString"
        if (-not "$($global:PIM_ClientId)".Trim() -and -not "$($global:PIM_SetupActor)".Trim()) {
            $global:PIM_SetupActor = try { [System.Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { "$env:USERNAME" }
        }
    } else {
        if (-not "$SqlServerFqdn".Trim()) { throw 'give -SqlServerFqdn (with -TenantId and an identity) or -ConnectionString.' }
        if ("$TenantId".Trim() -notmatch '^[0-9a-fA-F-]{36}$') { throw "-TenantId must be the tenant GUID (got '$TenantId')." }
        $cs = Connect-PimSetupStore -SqlServerFqdn $SqlServerFqdn -SqlDatabase $SqlDatabase -TenantId $TenantId -ClientId $ClientId -CertThumbprint $CertThumbprint -UseSignedInAccount:$UseSignedInAccount
    }
    $actor = if ("$($global:PIM_ClientId)".Trim()) { "$($global:PIM_ClientId)" } else { "$($global:PIM_SetupActor)" }

    # --- which packs ---------------------------------------------------------------------------------------------------
    $tplDir = Join-Path $solRoot 'templates'
    $shipped = [ordered]@{}
    foreach ($f in @(Get-ChildItem -LiteralPath $tplDir -Filter '*.template.json' -File | Sort-Object Name)) { $shipped[($f.Name -replace '\.template\.json$', '')] = $f.FullName }
    $disabled = @{}
    $wantAll = @($Template | Where-Object { "$_".Trim() -ieq 'all-active' }).Count -gt 0
    # The Governance page's enable/disable map (id -> disabled). Read whenever it decides anything: 'all-active' needs it,
    # and an explicitly named disabled pack is imported with a warning.
    $ts = Get-PimSqlSetting -ConnectionString $cs -Name 'TemplateState'
    if ($ts -is [System.Management.Automation.PSCustomObject]) { foreach ($p in $ts.PSObject.Properties) { if ([bool]$p.Value) { $disabled["$($p.Name)"] = $true } } }
    $ids = New-Object System.Collections.Generic.List[string]
    if ($wantAll) { foreach ($k in @($shipped.Keys)) { if (-not $disabled.ContainsKey($k)) { $ids.Add($k) } } }
    foreach ($t in @($Template)) {
        $t = "$t".Trim(); if (-not $t -or $t -ieq 'all-active') { continue }
        $k = @($shipped.Keys | Where-Object { $_ -ieq $t })
        if (-not $k.Count) { throw "unknown template '$t' (shipped: $((@($shipped.Keys)) -join ', '))." }
        if ($disabled.ContainsKey($k[0])) { Write-Warning "template '$($k[0])' is DISABLED in this environment's Governance state -- importing it because it was named explicitly." }
        if (-not $ids.Contains($k[0])) { $ids.Add($k[0]) }
    }
    if ($wantAll -and $disabled.Count) { Note "all-active: skipping disabled pack(s) $((@($disabled.Keys) | Sort-Object) -join ', ')" }

    # --- the tenant's naming + the workload prerequisite view (read once) ------------------------------------------------
    $tenantPattern = Get-PimTemplateTenantGroupPattern -Stored (Get-PimSqlSetting -ConnectionString $cs -Name 'NamingConventions') `
                        -LockedConfigPath (Join-Path $solRoot 'config\PIM4EntraPS.NamingConventions.locked.ps1')
    Step "Permission templates: $($ids -join ', ') (group pattern '$tenantPattern')"
    $prStored = $null; $prErr = ''
    try { $prStored = Get-PimSqlSetting -ConnectionString $cs -Name 'WorkloadPrereqs' } catch { $prErr = "$($_.Exception.Message)" }
    $envVals = @{ tenantId = "$TenantId".Trim(); sqlServerFqdn = "$SqlServerFqdn".Trim(); sqlDatabase = "$SqlDatabase".Trim() }
    try { $tj = ConvertFrom-PimTickJobId -Id "$(Get-PimSqlSetting -ConnectionString $cs -Name 'SchedulerTickJobId')".Trim().Trim('"') } catch { $tj = $null }
    if ($tj) { $envVals.subscriptionId = $tj.subscriptionId; $envVals.resourceGroup = $tj.resourceGroup; $envVals.tickJobName = $tj.jobName }
    $prView = @(Get-PimWorkloadPrereqView -Stored $prStored -Env $envVals -NowUtc ([datetime]::UtcNow) -StaleDays (Get-PimWorkloadPrereqStaleDays))
    if ($prErr) { foreach ($v in $prView) { $v.state = 'unreadable'; $v.chip = 'amber' } }

    $onlyMiss = @{}   # -Only entry -> in how many packs it is NOT a group (warned once, when it is in none)
    foreach ($id in $ids) {
        $pr = [ordered]@{ id = $id; name = ''; version = $null; status = ''; addedCount = 0; added = [ordered]@{}; units = 0; unitTags = @()
                          placeholderSkipped = 0; widenedTags = @(); unmatched = @(); snapshots = @(); prereqs = @(); held = @(); adopted = @(); error = '' }
        $applied = New-Object System.Collections.Generic.List[object]   # @{ base; snapshot } written so far (for the pack rollback)
        try {
            $pack = Read-PimTemplatePack -Path $shipped[$id]
            $pr.name = "$($pack.name)"; $pr.version = $pack.version
            # 1) PLAN against the entities this pack touches, read now.
            $current = @{}
            foreach ($b in @(Get-PimTemplatePackBases -Pack $pack)) { $current[$b] = @(Get-PimSqlRows -ConnectionString $cs -Entity $b) }
            # EVERY group definition entity, so a pack group the store already defines -- under another tag, or in
            # another definition entity -- is ADOPTED instead of defined a second time (measured on internal 2026-09-19).
            $allDefs = New-Object System.Collections.Generic.List[object]
            foreach ($db in @(Get-PimTemplatePackKnownBases | Where-Object { "$_" -like 'PIM-Definitions-*' -and "$_" -ne 'PIM-Definitions-AU' })) {
                $rowsDb = if ($current.ContainsKey($db)) { @($current[$db]) } else { @(Get-PimSqlRows -ConnectionString $cs -Entity $db) }
                foreach ($r in $rowsDb) { if ($null -ne $r) { $allDefs.Add($r) } }
            }
            $plan = Get-PimTemplatePackPlan -Pack $pack -CurrentRowsByBase $current -TenantGroupPattern $tenantPattern -ExistingDefinitionRows @($allDefs.ToArray())
            foreach ($a in @($plan.adopted)) { if ("$($a.by)" -eq 'name' -or "$($a.packTag)" -cne "$($a.storeTag)") { Note "  adopts existing group $($a.groupName) (store tag '$($a.storeTag)', pack tag '$($a.packTag)') -- not defined again" } }
            $pr.adopted = @(@($plan.adopted) | Where-Object { "$($_.by)" -eq 'name' -or "$($_.packTag)" -cne "$($_.storeTag)" } | ForEach-Object { "$($_.groupName)" })
            if (@($Only | Where-Object { "$_".Trim() }).Count) {
                $plan = Select-PimTemplatePackPlanSubset -Plan $plan -Only $Only
                $pr.widenedTags = @($plan.widenedTags); $pr.unmatched = @($plan.unmatched)
                if (@($plan.widenedTags).Count) { Note "-Only widened to whole unit(s): $(@($plan.widenedTags) -join ', ') (a group and its workload role are imported together)" }
            }
            $pr.placeholderSkipped = [int]$plan.placeholderSkipped
            $pr.units = @($plan.units).Count; $pr.unitTags = @(@($plan.units) | ForEach-Object { "$($_.tag)" })
            Step "template '$id' v$($pack.version): $($plan.missingCount) row(s) to add, $(@($plan.units).Count) unit(s)$(if ($plan.placeholderSkipped) { ", $($plan.placeholderSkipped) placeholder row(s) skipped (all-zero subscription)" })"
            foreach ($b in @($plan.missing.Keys)) { Note ("{0,-34} +{1}" -f $b, @($plan.missing[$b]).Count); $pr.added[$b] = @($plan.missing[$b]).Count }
            foreach ($u in @($plan.units)) { Note "  unit $($u.groupName) <- $((@($u.bindings) | ForEach-Object { $_.base }) -join ', ')" }

            # An -Only entry that selects nothing is either already imported (its group is in the store) or not in this pack.
            $notInPack = @()
            if (@($pr.unmatched).Count) {
                $packTags = @{}
                $packPat = if ("$($pack.groupNamePattern)".Trim()) { "$($pack.groupNamePattern)" } else { 'PIM-{Role}' }
                foreach ($b in @(Get-PimTemplatePackBases -Pack $pack)) {
                    foreach ($r in @($pack.rows.$b)) { if ($null -ne $r) { foreach ($t in @(Get-PimTemplatePlanRowTags -Base $b -Row (ConvertTo-PimTemplatePackRow -Base $b -Row $r -PackPattern $packPat -TenantPattern $tenantPattern))) { $packTags[$t] = $true } } }
                }
                $notInPack = @(@($pr.unmatched) | Where-Object { -not $packTags.ContainsKey("$_") })
                foreach ($o in $notInPack) { if ($onlyMiss.ContainsKey($o)) { $onlyMiss[$o]++ } else { $onlyMiss[$o] = 1 } }
            }
            if ([int]$plan.missingCount -eq 0) {
                if ($notInPack.Count -and $notInPack.Count -eq @($Only | Where-Object { "$_".Trim() }).Count) {
                    $pr.status = 'nothingSelected'
                    Write-Host "    nothing selected in '$id' by -Only -- nothing written." -ForegroundColor DarkYellow
                } else {
                    $pr.status = 'alreadyImported'
                    Write-Host "    already imported: every row of '$id'$(if (@($Only | Where-Object { "$_".Trim() }).Count) { ' selected by -Only' }) is in the store -- nothing written." -ForegroundColor Green
                }
            } else {
                # 2) REFUSE a store-key collision before any write (the full-set replace would merge the two rows into one).
                $collide = New-Object System.Collections.Generic.List[string]
                foreach ($b in @($plan.missing.Keys)) {
                    foreach ($d in @(Get-PimDuplicateStoreKeys -Base $b -Rows (@($current[$b]) + @($plan.missing[$b])))) { $collide.Add("$b key '$($d.key)' x$($d.count)") }
                }
                if ($collide.Count) {
                    throw ("REFUSED before any write: $($collide.Count) added row(s) share a store key with another row, so saving would OVERWRITE a row that is already there " +
                           "(the store keeps one workload binding per group -- BUG-204): $($collide -join '; '). Import the other groups with -Only, or change the existing row first.")
                }
                if (-not $PSCmdlet.ShouldProcess("template:$id ($($plan.missingCount) row(s) in $(@($plan.missing.Keys) -join ', '))", 'import')) {
                    $pr.status = 'whatIf'
                } else {
                    # 3) COMMIT per entity: snapshot -> transactional apply (current + new; adds only) -> restore on failure -> prune.
                    try { Initialize-PimBackupStore -ConnectionString $cs } catch { Write-Warning "  [backup] init store failed: $($_.Exception.Message)" }
                    foreach ($b in (Get-PimImportEntityOrder -Bases @($plan.missing.Keys))) {
                        # Re-read right before the write: the smallest window for a row someone else added meanwhile.
                        $fresh = @(Get-PimSqlRows -ConnectionString $cs -Entity $b)
                        $have = @{}
                        foreach ($r in $fresh) { $k = Get-PimTemplateRowKey -Base $b -Row $r; if ($k) { $have[$k.ToLowerInvariant()] = $true } }
                        $new = @(@($plan.missing[$b]) | Where-Object { -not $have.ContainsKey("$(Get-PimTemplateRowKey -Base $b -Row $_)".ToLowerInvariant()) })
                        $rowsOut = @($fresh) + @($new)
                        $snap = New-PimCommitSnapshot -Entity $b -Base $b -Rows $fresh -Header (Get-PimImportHeader -Rows $rowsOut) -By "$actor" -Reason "template import: $id v$($pack.version)"
                        $failAfter = if ("$TestFailApplyEntity".Trim() -and "$TestFailApplyEntity" -eq $b) { 1 } else { -1 }
                        # Plain script blocks, NOT .GetNewClosure(): a closure is bound to a dynamic module whose parent is the
                        # GLOBAL scope, so the store functions dot-sourced into this script would not resolve inside it.
                        $save    = { param($s) Save-PimSqlBackupSnapshot -ConnectionString $cs -Snapshot $s }
                        $apply   = {
                            $r = Set-PimSqlEntityRowsTransactional -ConnectionString $cs -Entity $b -Base $b -Rows $rowsOut -FailAfter $failAfter
                            # This import only ever ADDS. A row removed means a row appeared between the read and the write.
                            if ([int]$r.removed -gt 0) { throw "the apply removed $($r.removed) row(s) of '$b' -- a row was added by someone else meanwhile; re-run" }
                            [pscustomobject]$r
                        }
                        # -AllowEmpty on the RESTORE only (as the Manager's): rolling back to a snapshot of an entity that held no rows.
                        $restore = { param($s) $p = Get-PimSnapshotRestorePlan -Snapshot $s; Set-PimSqlEntityRowsTransactional -ConnectionString $cs -Entity $p.entity -Base $p.base -Rows @($p.rows) -AllowEmpty }
                        $prune   = { [void](Invoke-PimSqlBackupRetention -ConnectionString $cs -Entity $b -Keep $backupKeep) }
                        $tx = Invoke-PimCommitTransaction -Snapshot $snap -ApplyScript $apply -RestoreScript $restore -SaveSnapshotScript $save -PruneScript $prune
                        $applied.Add(@{ base = $b; snapshot = $snap })
                        $pr.snapshots = @($pr.snapshots) + @("$($tx.snapshotId)")
                        $pr.added[$b] = @($new).Count
                        Note ("committed {0}: +{1} (snapshot {2})" -f $b, @($new).Count, $tx.snapshotId)
                    }
                    # 4) READ BACK every planned row by its key.
                    $lost = New-Object System.Collections.Generic.List[string]
                    foreach ($b in @($plan.missing.Keys)) {
                        $back = @{}
                        foreach ($r in @(Get-PimSqlRows -ConnectionString $cs -Entity $b)) { $k = Get-PimTemplateRowKey -Base $b -Row $r; if ($k) { $back[$k.ToLowerInvariant()] = $true } }
                        foreach ($r in @($plan.missing[$b])) { $k = "$(Get-PimTemplateRowKey -Base $b -Row $r)"; if (-not $back.ContainsKey($k.ToLowerInvariant())) { $lost.Add("$b '$k'") } }
                    }
                    if ($lost.Count) { throw "read-back FAILED: $($lost.Count) planned row(s) are not in the store: $($lost -join '; ')" }
                    $pr.addedCount = [int](@($pr.added.Values) | Measure-Object -Sum).Sum
                    $pr.status = 'imported'
                    $before = [ordered]@{}
                    foreach ($e in $applied) { $before[$e.base] = [int]$e.snapshot.rowCount }
                    Write-PimSetupAudit -ConnectionString $cs -Action 'template.import' -Target "template:$id" `
                        -Before ([ordered]@{ rowsPerEntity = $before }) `
                        -After ([ordered]@{ version = $pack.version; added = $pr.added; addedCount = $pr.addedCount; units = $pr.units; only = @($Only); widened = @($pr.widenedTags); placeholderSkipped = $pr.placeholderSkipped; snapshots = @($pr.snapshots) })
                    Write-Host "    imported: +$($pr.addedCount) row(s) of '$id', read back and audited (template.import)." -ForegroundColor Green
                }
            }
        } catch {
            $pr.status = 'error'; $pr.error = "$($_.Exception.Message)"
            # A pack never lands half: restore what this pack already wrote, newest first.
            for ($x = $applied.Count - 1; $x -ge 0; $x--) {
                $e = $applied[$x]
                try {
                    $p = Get-PimSnapshotRestorePlan -Snapshot $e.snapshot
                    [void](Set-PimSqlEntityRowsTransactional -ConnectionString $cs -Entity $p.entity -Base $p.base -Rows @($p.rows) -AllowEmpty)
                    Note "rolled back $($e.base) to snapshot $($e.snapshot.id)"
                } catch { $pr.error += " | rollback of $($e.base) FAILED -- restore snapshot $($e.snapshot.id) by hand: $($_.Exception.Message)" }
            }
            $errors.Add("${id}: $($pr.error)")
            Write-Host "    ERROR ($id): $($pr.error)" -ForegroundColor Red
        }

        # 5) the workload prerequisites of this pack: reported, never a refusal.
        $map = Get-PimWorkloadPrereqTemplateMap
        $ws = @(); if ($map.Contains($id)) { $ws = @($map[$id]) }
        $lead = switch ($pr.status) { 'imported' { 'rows imported' } 'alreadyImported' { 'already imported' } 'whatIf' { 'rows would be imported (WhatIf)' } default { "import $($pr.status)" } }
        foreach ($w in $ws) {
            $v = @($prView | Where-Object { "$($_.workload)" -eq $w })[0]
            $g = Get-PimWorkloadAssignmentGate -Workload $w -View $prView -StoreError $prErr
            $state = if ($v) { "$($v.state)" } else { 'notRun' }
            $pr.prereqs = @($pr.prereqs) + @([pscustomobject]@{ workload = $w; state = $state; held = [bool]$g.held; command = "$($g.command)" })
            if ($g.held) {
                $pr.held = @($pr.held) + @($w)
                Write-Host "    ${lead}; the $w role assignments are HELD by the engine until its prerequisites are green (run: $($g.command))" -ForegroundColor Yellow
                if ($g.reason) { Note "  $($g.reason)" }
            } else {
                Note "workload $w prerequisites: $state$(if ((Get-PimWorkloadPrereqUngated) -contains $w) { ' (never held)' })"
            }
        }
        $packResults.Add([pscustomobject]$pr)
    }
    $nowhere = @(@($onlyMiss.Keys) | Where-Object { $onlyMiss[$_] -ge $ids.Count } | Sort-Object)
    if ($nowhere.Count) { Write-Warning "-Only: $($nowhere -join ', ') is not a group of any pack imported here ($($ids -join ', ')) -- nothing was selected by it." }
} catch {
    $errors.Add("$($_.Exception.Message)")
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
}

$result.packs = @($packResults.ToArray())
$result.addedTotal = [int](@($packResults | ForEach-Object { [int]$_.addedCount }) | Measure-Object -Sum).Sum
$result.errors = @($errors.ToArray())
$result.ok = ($errors.Count -eq 0)
if ($PassThru) { [pscustomobject]$result }
if (-not $result.ok) { exit 1 }
exit 0
