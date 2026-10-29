#Requires -Version 5.1
<#
.SYNOPSIS
  PIM REQUIREMENTS s98.3 -- NIGHTLY BASELINE RESTORE of the live demo environment (job 'demo-baseline-restore').

.DESCRIPTION
  Owner-approved 2026-10-29. With demo mode on, visitors write nothing (s98.2), so the demo store only drifts by the
  operator's own changes or the engine's. Once a day this job puts the configuration back to the BASELINE: the CONFIG-1
  configuration backup (s96.3) the operator PINNED and LABELLED 'demo-baseline' (the backup's note, set on Backups &
  restore when it is taken or pinned).

  WHEN IT DOES ANYTHING AT ALL -- every gate below ends the run with "nothing to do" and writes nothing:
    1. pim.Settings 'DemoMode' is ON (Test-PimDemoModeValue: only an explicit "on" spelling). Off = "demo mode off --
       nothing to do". This is the first thing read; with it off nothing else is read.
    2. the daily slot: the first run at or after <atHourUtc>:00 UTC (default 02:00) that has not acted on that slot yet
       (pim.Settings 'DemoBaselineRestoreState'; the job row runs hourly, so a tick missed at 02:00 acts at 03:00).
    3. THE DEMO PROOF (Get-PimDemoEnvironmentProof, PIM-DemoProof.ps1 -- the SAME proof the demo setup scripts use):
       a recorded update ring 0 or 1 AND a valid internal / demo licence. A customer environment with DemoMode set by
       mistake is REFUSED here (a warning run, nothing read past the proof, nothing written) -- no other environment can
       ever be reset by this job.
    4. a pinned backup labelled 'demo-baseline'. None = "no baseline -- nothing to do".
    5. a difference: Compare-PimConfigBackupSnapshot (baseline vs now). None = done.

  HOW IT PUTS THINGS BACK -- never a direct pim.Rows write:
    * rows: one restore plan per entity (New-PimConfigBackupRestoreRowPlan), committed by
      Invoke-PimConfigBackupRestoreCommit as the SYSTEM actor 'system:demo-baseline-restore' -- the same store path the
      Manager's restore commit uses (full-set replace per entity, journal Source 'restore', one commit id, audited
      config.restore, the engine asked to reconcile). THE MASS-CHANGE BREAKER STAYS IN FORCE: the commit removal check is
      evaluated for every entity before any write; a hold = the run is HELD, nothing is written (rows or settings), and a
      SuperAdmin restores it by hand. The job never forces.
    * settings: Invoke-PimConfigBackupSettingsRestore, ONLY for settings that CHANGED or were REMOVED since the baseline,
      and NEVER DemoMode, DemoGuestGroup, ManagerAccess, EnvironmentName, this job's own state, or anything on the backup
      deny list (secrets, identity, runtime state) or with its own route (the break-glass list, the emergency override).
      A setting ADDED since the baseline is left in place (an unattended restore never clears a setting) and reported.
    * MSP tables (platform.Tenants, pim.CentralAdmins) are shown in the run's detail, never restored here.

  Windows PowerShell 5.1 + pwsh 7. ASCII only. No modules. Offline tests: tests/Test-PimDemoBaselineRestore.ps1.
#>
Set-StrictMode -Off

# The libraries this job needs, loaded only when the process does not have them yet (the scheduler loads the store, the
# configuration backup and the licence model itself).
foreach ($__dbrDep in @(
        @{ fn = 'Test-PimDemoModeValue';             file = 'PIM-DemoMode.ps1' },
        @{ fn = 'Get-PimDemoEnvironmentProof';       file = 'PIM-DemoProof.ps1' },
        @{ fn = 'Read-PimUpdateState';               file = 'PIM-UpdateState.ps1' },
        @{ fn = 'Test-PimCommitDeltaGuard';          file = 'PIM-ManagerWriteGuards.ps1' },
        @{ fn = 'Invoke-PimConfigBackupRestoreCommit'; file = 'PIM-ConfigBackup.ps1' })) {
    if (-not (Get-Command $__dbrDep.fn -ErrorAction SilentlyContinue)) {
        $__dbrPath = Join-Path $PSScriptRoot $__dbrDep.file
        if (Test-Path -LiteralPath $__dbrPath) { . $__dbrPath }
    }
}

function Get-PimDemoBaselineLabel { 'demo-baseline' }
function Get-PimDemoBaselineActor { 'system:demo-baseline-restore' }
function Get-PimDemoBaselineStateName { 'DemoBaselineRestoreState' }
function Get-PimDemoBaselineDefaultHourUtc { 2 }

function Get-PimDemoBaselineProtectedSettings {
    <# PURE. The settings the nightly restore NEVER writes, whatever the baseline holds (on top of the backup deny list). #>
    @('DemoMode', 'DemoGuestGroup', 'ManagerAccess', 'EnvironmentName', (Get-PimDemoBaselineStateName))
}

function Test-PimDemoBaselineProtectedSetting {
    <# PURE. True for a setting the nightly restore never writes: the protected list, or anything the backup deny list keeps out. #>
    param([Parameter(Mandatory)][string]$Name)
    foreach ($p in @(Get-PimDemoBaselineProtectedSettings)) { if ([string]::Equals("$p", $Name, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
    return [bool](Test-PimConfigBackupSettingExcluded -Name $Name).excluded
}

function ConvertTo-PimDemoBaselineUtc {
    <# PURE. A stored stamp (ISO text or [datetime]) -> UTC [datetime], or $null when it cannot be read. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) } else { return $Value.ToUniversalTime() } }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    $d = [datetime]::MinValue
    $st = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, $st, [ref]$d)) { return $d }
    return $null
}

function Get-PimDemoBaselineRestoreHour {
    <# PURE. The UTC hour of the daily slot: the job row's atHourUtc (0..23), else 2. #>
    param([AllowNull()][object]$Job)
    if ($Job -and $Job.PSObject.Properties['atHourUtc']) {
        $h = 0
        if ([int]::TryParse("$($Job.atHourUtc)".Trim(), [ref]$h) -and $h -ge 0 -and $h -le 23) { return $h }
    }
    return (Get-PimDemoBaselineDefaultHourUtc)
}

function Test-PimDemoBaselineRestoreDue {
    <#
      PURE. Is the daily slot due? The slot is today at -HourUtc:00 UTC (yesterday's while it is earlier than that). Due when
      the job has not acted since that slot (-LastUtc older than it, or never). Returns @{ due; slotUtc; nextUtc; reason }.
    #>
    param([Parameter(Mandatory)][datetime]$NowUtc, [AllowNull()][object]$LastUtc, [int]$HourUtc = 2)
    if ($HourUtc -lt 0 -or $HourUtc -gt 23) { $HourUtc = 2 }
    $now = $NowUtc.ToUniversalTime()
    $slot = [datetime]::SpecifyKind($now.Date, [DateTimeKind]::Utc).AddHours($HourUtc)
    if ($now -lt $slot) { $slot = $slot.AddDays(-1) }
    $next = $slot.AddDays(1)
    $last = ConvertTo-PimDemoBaselineUtc -Value $LastUtc
    if ($null -eq $last -or $last -lt $slot) { return @{ due = $true; slotUtc = $slot; nextUtc = $next; reason = ('the {0:HH}:00 UTC slot of {0:yyyy-MM-dd} is due' -f $slot) } }
    return @{ due = $false; slotUtc = $slot; nextUtc = $next
              reason = ('already checked at {0:yyyy-MM-dd HH:mm} UTC -- the next check is after {1:yyyy-MM-dd HH:mm} UTC' -f $last, $next) }
}

function Select-PimDemoBaselineBackup {
    <#
      PURE. The baseline: the NEWEST backup that is PINNED and whose note is exactly the label 'demo-baseline' (trimmed, any
      case). -Backups: the header rows (Get-PimConfigBackupList). Returns @{ backup ($null = none); candidates }.
    #>
    param([object[]]$Backups = @())
    $label = Get-PimDemoBaselineLabel
    $tsOf = { param($b) $t = ConvertTo-PimDemoBaselineUtc -Value $b.TakenUtc; if ($null -eq $t) { [datetime]::MinValue } else { $t } }
    $c = @($Backups | Where-Object { $_ -and "$($_.BackupId)".Trim() -and [bool]$_.Pinned -and [string]::Equals("$($_.Note)".Trim(), $label, [StringComparison]::OrdinalIgnoreCase) } |
           Sort-Object -Property @{ Expression = { & $tsOf $_ }; Descending = $true }, @{ Expression = { "$($_.BackupId)" }; Descending = $true })
    return @{ backup = $(if ($c.Count) { $c[0] } else { $null }); candidates = $c.Count }
}

function Get-PimDemoBaselineSettingPlan {
    <#
      PURE. Which settings the nightly restore writes, from the 'pim.Settings' entity of the diff: CHANGED and REMOVED since
      the baseline, minus every protected / deny-listed name and every name with its own route. ADDED since the baseline is
      never cleared (reported). Returns @{ names = @(); skipped = @(@{ name; reason }) }.
    #>
    param([AllowNull()][object]$Diff)
    $names = New-Object System.Collections.Generic.List[string]; $skipped = New-Object System.Collections.Generic.List[object]
    if (-not $Diff) { return @{ names = @(); skipped = @() } }
    $consider = @(@($Diff.changed | Where-Object { $_ } | ForEach-Object { "$($_.key)" }) + @($Diff.removed | Where-Object { $_ } | ForEach-Object { "$($_.key)" }))
    foreach ($n in $consider) {
        if (-not "$n".Trim()) { continue }
        if (Test-PimDemoBaselineProtectedSetting -Name $n) { $skipped.Add(@{ name = $n; reason = 'protected -- the nightly restore never writes it' }); continue }
        if ((Get-PimConfigBackupSettingRestoreRoute -Name $n) -ne 'direct') { $skipped.Add(@{ name = $n; reason = 'has its own approval route (restored by hand only)' }); continue }
        if (-not $names.Contains($n)) { $names.Add($n) }
    }
    foreach ($a in @($Diff.added | Where-Object { $_ })) {
        $skipped.Add(@{ name = "$($a.key)"; reason = 'added since the baseline -- an unattended restore never clears a setting' })
    }
    return @{ names = @($names.ToArray()); skipped = @($skipped.ToArray()) }
}

function Save-PimDemoBaselineRestoreState {
    # The slot this job acted on (never on -WhatIf). A failed write is a warning only: the next hourly run checks again.
    param([string]$ConnectionString, [datetime]$NowUtc, [string]$Outcome, [string]$BackupId = '', [string]$CommitId = '')
    try {
        $v = [ordered]@{ lastUtc = $NowUtc.ToUniversalTime().ToString('o'); outcome = "$Outcome"; backupId = "$BackupId"; commitId = "$CommitId" }
        Set-PimSqlSetting -ConnectionString $ConnectionString -Name (Get-PimDemoBaselineStateName) -ValueJson (ConvertTo-Json -InputObject $v -Compress)
    } catch { Write-Warning "[demo-baseline-restore] the run state could not be saved: $($_.Exception.Message) -- the next run checks again" }
}

function Invoke-PimDemoBaselineRestoreJob {
    <#
      The scheduled 'demo-baseline-restore' job (s98.3). See the file header for every gate. A restore that FAILED part-way
      THROWS (the run fails; the slot is not marked, so the next hourly run starts again from the diff). -WhatIf: every
      gate and the plan, nothing written.
    #>
    param([object]$Job = $null, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [string]$ConnectionString = '')
    $wi = if ($WhatIf) { ' (what-if)' } else { '' }
    $mk = {
        param([hashtable]$h)
        $o = [ordered]@{ ran = $false; whatIf = [bool]$WhatIf; restored = $false; detail = '' }
        foreach ($k in @($h.Keys)) { $o[$k] = $h[$k] }
        [pscustomobject]$o
    }
    $cs = $ConnectionString
    if (-not $cs -and (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue)) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = '' } }
    if (-not $cs) { return (& $mk @{ detail = 'no SQL store -- demo mode cannot be on, nothing to do' }) }

    # 1) demo mode -- the FIRST read; off = nothing else is read
    $dm = $null
    try { $dm = Get-PimSqlSetting -ConnectionString $cs -Name 'DemoMode' }
    catch { return (& $mk @{ warning = $true; detail = "the DemoMode setting could not be read ($($_.Exception.Message)) -- nothing was done" }) }
    if (-not (Test-PimDemoModeValue -Value $dm)) { return (& $mk @{ detail = 'demo mode off -- nothing to do' }) }

    # 2) the daily slot
    $hour = Get-PimDemoBaselineRestoreHour -Job $Job
    $st = $null; try { $st = Get-PimSqlSetting -ConnectionString $cs -Name (Get-PimDemoBaselineStateName) } catch { $st = $null }
    if ($st -is [string]) { try { $st = $st | ConvertFrom-Json } catch { $st = $null } }
    $last = if ($st -and $st.PSObject.Properties['lastUtc']) { $st.lastUtc } else { $null }
    $due = Test-PimDemoBaselineRestoreDue -NowUtc $NowUtc -LastUtc $last -HourUtc $hour
    if (-not $due.due) { return (& $mk @{ detail = "demo mode on: $($due.reason)" }) }

    # 3) THE DEMO PROOF -- a customer environment with DemoMode set by mistake stops here, nothing read or written past it
    if (-not (Get-Command Get-PimDemoEnvironmentProof -ErrorAction SilentlyContinue)) {
        return (& $mk @{ warning = $true; refused = $true; detail = 'REFUSED: the demo-environment proof (PIM-DemoProof.ps1) is not loaded -- unsure, so nothing was restored' })
    }
    $proof = Get-PimDemoEnvironmentProof -ConnectionString $cs
    if (-not $proof.allowed) {
        return (& $mk @{ warning = $true; refused = $true
            detail = ("REFUSED: DemoMode is on, but this is not the demo environment -- {0}. Nothing was restored. Switch demo mode off on this environment (Settings > Features & edition > Demo mode)." -f (@($proof.reasons) -join '; ')) })
    }

    # 4) the baseline
    $ready = Confirm-PimConfigBackupStoreReady -ConnectionString $cs
    if (-not $ready.ok) { throw "[demo-baseline-restore] $($ready.detail)" }
    $pick = Select-PimDemoBaselineBackup -Backups @(Get-PimConfigBackupList -ConnectionString $cs)
    if (-not $pick.backup) {
        if (-not $WhatIf) { Save-PimDemoBaselineRestoreState -ConnectionString $cs -NowUtc $NowUtc -Outcome 'no-baseline' }
        return (& $mk @{ ran = $true; detail = ("demo mode on, but no pinned backup is labelled '{0}' -- nothing to do{1}. Pin the backup to return to on Backups & restore with the note '{0}'." -f (Get-PimDemoBaselineLabel), $wi) })
    }
    $bid = "$($pick.backup.BackupId)"
    $bk = Get-PimConfigBackupContent -ConnectionString $cs -BackupId $bid
    if (-not $bk) { return (& $mk @{ warning = $true; backupId = $bid; detail = "the baseline backup $bid could not be read -- nothing was restored" }) }

    # 5) the difference
    $cur = Get-PimConfigBackupCurrentSnapshot -ConnectionString $cs
    $diff = @(Compare-PimConfigBackupSnapshot -Backup $bk -Current $cur)
    $cnt = { param($d) @($d.added).Count + @($d.removed).Count + @($d.changed).Count }
    $rowDiffs = @($diff | Where-Object { "$($_.kind)" -eq 'rows' -and (Test-PimConfigBackupEntityIncluded -Entity "$($_.entity)") -and (& $cnt $_) -gt 0 })
    $tableDiffs = @($diff | Where-Object { "$($_.kind)" -eq 'table' -and (& $cnt $_) -gt 0 } | ForEach-Object { "$($_.entity)" })
    $sp = Get-PimDemoBaselineSettingPlan -Diff (@($diff | Where-Object { "$($_.kind)" -eq 'settings' }) | Select-Object -First 1)
    $notes = New-Object System.Collections.Generic.List[string]
    if ($tableDiffs.Count) { $notes.Add("MSP tables differ and are not restored here: $($tableDiffs -join ', ')") }
    if (@($sp.skipped).Count) { $notes.Add("settings left as they are: $(@($sp.skipped | ForEach-Object { $_.name }) -join ', ')") }
    $noteText = if ($notes.Count) { ' (' + ($notes -join '; ') + ')' } else { '' }
    if (-not $rowDiffs.Count -and -not @($sp.names).Count) {
        if (-not $WhatIf) { Save-PimDemoBaselineRestoreState -ConnectionString $cs -NowUtc $NowUtc -Outcome 'no-difference' -BackupId $bid }
        return (& $mk @{ ran = $true; backupId = $bid; detail = "no difference from the baseline $bid -- nothing to do$wi$noteText" })
    }

    # 6) the rows: one plan per entity, committed as the system actor; the breaker decides before any write
    $plans = @(foreach ($rd in $rowDiffs) {
        $be = $bk.entities["$($rd.entity)"]
        New-PimConfigBackupRestoreRowPlan -Diff $rd -LiveItems @(Get-PimConfigBackupLiveRowItems -ConnectionString $cs -Entity "$($rd.entity)") `
            -BackupItems @($(if ($be) { $be.items } else { @() })) -BackupRedacted @($(if ($be) { $be.redacted } else { @() }))
    })
    $cr = Invoke-PimConfigBackupRestoreCommit -ConnectionString $cs -Plans $plans -BackupId $bid -Actor (Get-PimDemoBaselineActor) -ActorSource 'scheduler' -WhatIf:$WhatIf
    if (@($cr.refused).Count) {
        if (-not $WhatIf) { Save-PimDemoBaselineRestoreState -ConnectionString $cs -NowUtc $NowUtc -Outcome 'refused' -BackupId $bid }
        return (& $mk @{ warning = $true; backupId = $bid; detail = "the baseline $bid was NOT restored: $(@($cr.refused) -join '; ') -- restore it by hand on Backups & restore$wi" })
    }
    if ($cr.held) {
        if (-not $WhatIf) { Save-PimDemoBaselineRestoreState -ConnectionString $cs -NowUtc $NowUtc -Outcome 'held' -BackupId $bid }
        $hs = @($cr.holds | ForEach-Object { "$($_.entity): $($_.reason)" }) -join ' | '
        return (& $mk @{ held = $true; backupId = $bid; holds = @($cr.holds)
            detail = "HELD by the mass-change check -- nothing was restored (rows or settings)$wi. $hs A SuperAdmin restores the baseline $bid by hand on Backups & restore." })
    }
    if (@($cr.errors).Count) {
        throw ("[demo-baseline-restore] the rows of the baseline $bid were restored only in part (commit $($cr.commitId)): " + (@($cr.errors | ForEach-Object { "$($_.entity): $($_.error)" }) -join '; '))
    }
    $rowText = @($cr.written | ForEach-Object { "$($_.entity) (+$($_.adds) ~$($_.modifies) -$($_.removes))" }) -join ', '
    if ($WhatIf) {
        return (& $mk @{ ran = $true; backupId = $bid; plannedRows = @($cr.written); plannedSettings = @($sp.names)
            detail = "what-if: the baseline $bid would put back rows [$rowText] and settings [$(@($sp.names) -join ', ')]$noteText" })
    }

    # 7) the settings -- never a protected or deny-listed one (Get-PimDemoBaselineSettingPlan + the restore's own route check)
    # Invoked by Invoke-PimConfigBackupSettingsRestore from inside this function, so they see $csW / $bidW (dynamic scope;
    # never .GetNewClosure() -- a closure cannot see the functions a script dot-sourced into its own scope).
    $csW = $cs; $bidW = $bid
    $sr = @{ written = @(); skipped = @(); errors = @() }
    if (@($sp.names).Count) {
        $sr = Invoke-PimConfigBackupSettingsRestore -Backup $bk -Names @($sp.names) `
            -Reader { param($n) Get-PimSqlSetting -ConnectionString $csW -Name $n } `
            -Writer { param($n, $j) if ($null -eq $j) { Set-PimSqlSetting -ConnectionString $csW -Name $n -Value $null } else { Set-PimSqlSetting -ConnectionString $csW -Name $n -ValueJson $j } } `
            -Audit { param($n, $b, $a) Write-PimConfigBackupAudit -ConnectionString $csW -Actor (Get-PimDemoBaselineActor) -ActorSource 'scheduler' -Action 'config.restore' -Target "settings:$n" -Before @{ value = $b } -After @{ value = $a; backupId = $bidW } }
    }
    if (@($sr.errors).Count) {
        throw ("[demo-baseline-restore] the settings of the baseline $bid were restored only in part: " + (@($sr.errors | ForEach-Object { "$($_.name): $($_.error)" }) -join '; '))
    }
    Write-PimConfigBackupAudit -ConnectionString $cs -Actor (Get-PimDemoBaselineActor) -ActorSource 'scheduler' -Action 'demo.baseline-restore' -Target "pim.ConfigBackups:$bid" `
        -After ([ordered]@{ backupId = $bid; commitId = "$($cr.commitId)"; rows = @($cr.written); settings = @($sr.written); settingsSkipped = @(@($sp.skipped) + @($sr.skipped) | ForEach-Object { "$($_.name)" }); tablesNotRestored = @($tableDiffs) })
    Save-PimDemoBaselineRestoreState -ConnectionString $cs -NowUtc $NowUtc -Outcome 'restored' -BackupId $bid -CommitId "$($cr.commitId)"
    return (& $mk @{ ran = $true; restored = $true; backupId = $bid; commitId = "$($cr.commitId)"; rows = @($cr.written); settings = @($sr.written)
        detail = "the baseline $bid was put back: rows [$rowText] (commit $($cr.commitId), journal Source restore), settings [$(@($sr.written) -join ', ')]$noteText" })
}
