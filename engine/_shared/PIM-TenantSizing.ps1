#Requires -Version 5.1
<#
.SYNOPSIS
    PIM REQUIREMENTS 100.31 / framework DOCS/REQUIREMENTS.md 12.15 TENANT-SIZING-1 -- PIM's engine jobs are sized for
    the tenant, by the ONE rule every product uses (SI ships it as Get-SITenantSizedJobResources; mirrored here, never
    imported -- isolation beats DRY between solutions).

.DESCRIPTION
    WHY (2026-10-09, live on a production tenant of ~10.8k identity objects: 1,640 users, 4,476 groups, 4,705 service
    principals): ca-pim-tick ran at 0.5 CPU / 1 GiB and the active-assignments snapshot died with
    "Exception of type 'System.OutOfMemoryException' was thrown." The job had the size every tenant got.

    THE RULE (per job, on that job's object count; Azure Container Apps Consumption pairs only):
        <  5,000 objects  -> the job's default        (tick: 0.5 CPU / 1.0Gi)
        5,000 - 14,999    -> 2.0 CPU / 4.0Gi
        >= 15,000         -> 4.0 CPU / 8.0Gi   (the largest Consumption pair -- the cap)
      * THE RUN LIMIT IS NOT SIZED (framework 12.24 JOB-RUN-LIMIT, owner 2026-10-15: *"job limit must be ... 7 days ... we
        can not limit cap session runtime"*): every job's replicaTimeout is Azure's maximum, $script:PimJobRunLimitSeconds
        (604,800 s = 7 days), at every band, on every update, whatever was set before. PIM_Bootstrap_ReplicaTimeout_<Job> is
        ignored with a note. A dead run is found by its lease / execution status, never by the timeout.
      * It only ever RAISES: never below the job's default, never below what the job already runs.
      * A size the customer set wins: PIM_Bootstrap_Cpu_<Job> / PIM_Bootstrap_Memory_<Job>
        (<Job> as Get-PimJobSettingSuffix spells it: ca-pim-tick -> Tick). An invalid value is ignored with a note.
      * PIM's engine jobs (ca-pim-tick, and the active-assignments snapshot that runs INSIDE the tick) count
        users + groups + service principals.
      * Counts: Microsoft Graph $count (ConsistencyLevel: eventual), read at install and on every update; when that read
        fails, the counts RECORDED on the job (its pim-sizing-* tags) stand.
      * SELF-CORRECT: a job whose execution ran out of memory or hit its time limit since it was last sized is raised ONE
        band by the next update (its replicaTimeout is already the 7-day maximum).

    THE MANAGER WEB APP AND THE DATABASE (owner 2026-10-12, framework 12.15 "CHANGED FOR PIM", PIM REQUIREMENTS 100.114):
    the rule above sized JOBS only -- the product's web app was sized by nothing. Two product defaults, defined HERE and
    read by every creator (the installer) and by the updater (framework 12.16 CONVERGE-DEFAULTS):
        the Manager web app (ca-pim-manager)  4.0 CPU / 8.0Gi   ($script:PimManagerAppSizeDefault)
        the main database                     S3, 250 GB max    ($script:PimSqlTierDefault / $script:PimSqlMaxSizeBytesDefault)
      * RAISE ONLY: a Manager below 4 / 8 is raised, one at or above it is untouched; a database below S3 is raised to S3,
        one at or above it is untouched. Automation never lowers either.
      * A size the customer set wins: PIM_Bootstrap_Cpu_Manager / PIM_Bootstrap_Memory_Manager (the installer's or the
        update job's environment; recorded on the app as its pim-sizing-override tag so a later update keeps it).
      * A database tagged pim-sql-tier-pin keeps its tier. The tag holds only a tier name -- it cannot tell "the customer
        pinned it" from "it was pinned at the product's earlier default" -- so a pin is NEVER overridden; a pin below the
        default is REPORTED ("database is pinned at <tier>, the new default is S3 - not changed") for support to act on.
      * Every Standard database has a 250 GB max size (100.37; never lowered).

    Everything here is PURE except Get-PimTenantObjectCounts, whose Graph read is a scriptblock seam. PS 5.1 + 7, no modules.
#>

Set-StrictMode -Off

# framework 12.24 JOB-RUN-LIMIT (owner 2026-10-15): EVERY PIM Container Apps job runs with Azure's maximum run limit, 7 days.
# No product-chosen cap -- the installer, every job definition and the updater (Invoke-PimJobRunLimitUpdate) use this one value.
$script:PimJobRunLimitSeconds = 604800
$script:PimJobSizeDefaults = @{
    Tick = @{ Cpu = '0.5'; Memory = '1.0Gi'; ReplicaTimeout = $script:PimJobRunLimitSeconds }
}
# THE MANAGER WEB APP'S DEFAULT SIZE. Owner 2026-10-12: "4 CPU / 8 GB at all ring 1+2 installs" -- "lets give everyone a
# good experience for now" -- "we can always lower it". Why: at 0.5 CPU / 1 GiB the Manager ran out of memory reading a
# large tenant's stored snapshot (100.112). A person lowers it (PIM_Bootstrap_Cpu_Manager / _Memory_Manager); automation never.
$script:PimManagerAppSizeDefault = @{ Cpu = '4.0'; Memory = '8.0Gi' }
$script:PimManagerSizeSuffix = 'Manager'     # the <Job> part of PIM_Bootstrap_Cpu_<Job> / PIM_Bootstrap_Memory_<Job> for the web app
# THE DATABASE'S DEFAULT TIER. Owner 2026-10-12: "S3 at every ring 1+2 install" (same decision, same words as above).
# Standard, with the 250 GB max size of every Standard database (100.37). Raise only; a pinned database keeps its tier.
$script:PimSqlTierDefault = 'S3'
$script:PimSqlMaxSizeBytesDefault = [int64]268435456000     # 250 GB
# The bands, in order. Band 0 = the job's default.
$script:PimJobSizeBands = @(
    [pscustomobject]@{ Band = 1; MinObjects = 5000;  Cpu = '2.0'; Memory = '4.0Gi'; ReplicaTimeout = $script:PimJobRunLimitSeconds }
    [pscustomobject]@{ Band = 2; MinObjects = 15000; Cpu = '4.0'; Memory = '8.0Gi'; ReplicaTimeout = $script:PimJobRunLimitSeconds }
)
$script:PimJobSizeMaxCpu = 4.0
$script:PimJobSizeMaxMemoryGi = 8.0
$script:PimTenantSizingTagPrefix = 'pim-sizing-'

function Get-PimJobSettingSuffix {
    <# PURE. The per-job suffix of a PIM_Bootstrap_*_<Job> setting: ca-pim-tick -> Tick, ca-pim-downlink-s6 -> DownlinkS6, Tick -> Tick. #>
    param([Parameter(Mandatory)][string]$Job)
    # CR5 step 1 (PIM 100.149): THIS install's engine job is 'Tick' whatever it is named (ca-pim-tick today, ca-pim-engine
    # at a new install) -- its stored size settings keep their keys
    if ((Get-Command Get-PimInstallName -ErrorAction SilentlyContinue) -and "$Job".Trim() -ieq (Get-PimInstallName -Role engine)) { return 'Tick' }
    # CR5 step 2: THIS install's managed-tenant pull job keeps its DownlinkS6 keys whatever it is named (caj-pim-downlink at
    # a new install); a caj-pim-<purpose> job loses its prefix like a ca-pim-<purpose> one
    if ((Get-Command Get-PimInstallName -ErrorAction SilentlyContinue) -and "$Job".Trim() -ieq (Get-PimInstallName -Role downlink)) { return 'DownlinkS6' }
    $j = "$Job".Trim() -replace '^(?i)caj?-pim-', ''
    $parts = @(($j -split '[-_]') | Where-Object { $_ } | ForEach-Object { $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1).ToLowerInvariant() })
    return ($parts -join '')
}

function ConvertTo-PimJobCpu {
    <# PURE. '0.5' / 1 / '2.0' -> [double]; $null when it is not a number. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $c = 0.0
    if ([double]::TryParse(("$Value".Trim()), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$c)) { return $c }
    return $null
}

function ConvertTo-PimJobMemoryGi {
    <# PURE. '1Gi' / '1.0Gi' / '4.0Gi' / 2 -> [double] GiB; $null when unreadable. #>
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    $s = ("$Value".Trim() -replace '(?i)\s*gi$', '')
    $m = 0.0
    if ([double]::TryParse($s, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$m)) { return $m }
    return $null
}

function Format-PimJobCpu { param([double]$Cpu) $Cpu.ToString('0.0#', [Globalization.CultureInfo]::InvariantCulture) }
function Format-PimJobMemory { param([double]$Gi) ('{0}Gi' -f $Gi.ToString('0.0#', [Globalization.CultureInfo]::InvariantCulture)) }

function Get-PimTenantObjectTotal {
    <# PURE. The object count PIM's engine jobs are sized on: users + groups + service principals (a missing count is 0). #>
    param([AllowNull()]$Counts)
    if ($null -eq $Counts) { return 0L }
    $g = {
        param($k)
        $v = $null
        if ($Counts -is [System.Collections.IDictionary]) { if ($Counts.Contains($k)) { $v = $Counts[$k] } }
        elseif ($Counts.PSObject.Properties[$k]) { $v = $Counts.$k }
        $n = 0L; if ($null -ne $v -and [long]::TryParse("$v", [ref]$n) -and $n -gt 0) { return $n }
        return 0L
    }
    return ((& $g 'Users') + (& $g 'Groups') + (& $g 'ServicePrincipals'))
}

function Get-PimTenantSizedJobResources {
    <#
      PURE. A PIM engine job's size for THIS tenant -- the framework 12.15 rule (SI: Get-SITenantSizedJobResources).
      -Counts: Users, Groups, ServicePrincipals ($count). Returns $null below 5,000 objects (the job's default stands),
      else @{ Cpu; Memory; ReplicaTimeout; Band; Objects }.
    #>
    param([string]$Job = 'ca-pim-tick', [AllowNull()]$Counts)
    $n = Get-PimTenantObjectTotal -Counts $Counts
    $hit = $null
    foreach ($b in $script:PimJobSizeBands) { if ($n -ge $b.MinObjects) { $hit = $b } }
    if (-not $hit) { return $null }
    return [pscustomobject]@{ Cpu = $hit.Cpu; Memory = $hit.Memory; ReplicaTimeout = $hit.ReplicaTimeout; Band = $hit.Band; Objects = $n }
}

function Get-PimJobBandOf {
    <# PURE. The band a size is in: 0 below band 1's CPU AND memory, else the highest band both reach. #>
    param([double]$Cpu, [double]$MemoryGi)
    $band = 0
    foreach ($b in $script:PimJobSizeBands) { if ($Cpu -ge [double]$b.Cpu -and $MemoryGi -ge (ConvertTo-PimJobMemoryGi $b.Memory)) { $band = $b.Band } }
    return $band
}

function Get-PimJobDefaultSize {
    <# PURE. The default of a job kind (Tick), with -DefaultReplicaTimeout overriding the default timeout (the install's -TickReplicaTimeout). #>
    param([string]$Job = 'ca-pim-tick', [int]$DefaultReplicaTimeout = 0)
    $sfx = Get-PimJobSettingSuffix -Job $Job
    $d = if ($script:PimJobSizeDefaults.ContainsKey($sfx)) { $script:PimJobSizeDefaults[$sfx] } else { $script:PimJobSizeDefaults['Tick'] }
    # framework 12.24: the timeout is never below the 7-day run limit -- a shorter -DefaultReplicaTimeout is not a cap.
    $t = [Math]::Max([int]$DefaultReplicaTimeout, [int]$script:PimJobRunLimitSeconds)
    return [pscustomobject]@{ Cpu = "$($d.Cpu)"; Memory = "$($d.Memory)"; ReplicaTimeout = $t }
}

# =====================================================================================================================
# THE MANAGER WEB APP + THE DATABASE DEFAULT (owner 2026-10-12; framework 12.15 "CHANGED FOR PIM"; PIM 100.114).
# The values live in $script:PimManagerAppSizeDefault / $script:PimSqlTierDefault at the top of this file. The getters
# carry a literal floor ONLY because a $script: variable reads $null when this file was loaded in another scope than the
# caller's (BUG-79-6b) -- a null default must never become "0 CPU" or "no tier".
# =====================================================================================================================
function Get-PimManagerAppDefaultSize {
    <# PURE. The Manager web app's product size: @{ Cpu = '4.0'; Memory = '8.0Gi' } (owner 2026-10-12). #>
    $d = $script:PimManagerAppSizeDefault
    $c = '4.0'; $m = '8.0Gi'
    if ($d -and "$($d.Cpu)".Trim() -and "$($d.Memory)".Trim()) { $c = "$($d.Cpu)".Trim(); $m = "$($d.Memory)".Trim() }
    return [pscustomobject]@{ Cpu = $c; Memory = $m }
}

function Get-PimSqlDefaultTier {
    <# PURE. The main database's product tier: 'S3' (owner 2026-10-12). #>
    $t = "$($script:PimSqlTierDefault)".Trim()
    if ($t -notmatch '^(?i)S\d+$') { $t = 'S3' }
    return $t.ToUpperInvariant()
}

function Get-PimSqlDefaultMaxSizeBytes {
    <# PURE. The max size of every Standard database: 250 GB (100.37). #>
    $b = [int64]0
    if ($null -ne $script:PimSqlMaxSizeBytesDefault) { [void][int64]::TryParse("$($script:PimSqlMaxSizeBytesDefault)", [ref]$b) }
    if ($b -le 0) { $b = [int64]268435456000 }
    return $b
}

function Get-PimManagerAppResources {
    <#
      PURE. THE ONE DECISION for the Manager web app's CPU and memory (creators and the updater both ask here):
        1. the product size (Get-PimManagerAppDefaultSize: 4.0 CPU / 8.0Gi)
        2. -Current (@{ Cpu; Memory }: what the app runs now) -- RAISE ONLY: below the product size in CPU or memory ->
           raised to it; at or above it -> untouched (a bigger app is never lowered)
        3. the customer's PIM_Bootstrap_Cpu_Manager / PIM_Bootstrap_Memory_Manager (-Settings: name -> value) WINS, as for
           the jobs (also below the product size). One of the two alone sets the other to its Consumption pair
           (memory = 2 x CPU). An invalid value is ignored with a note.
      Returns @{ Cpu; Memory; Source ('default'|'raised'|'kept'|'customer'); Changed; Have; Notes; Override }.
      Changed is $true only when -Current was READ and differs from the result: an unread size is never written over.
    #>
    param([AllowNull()]$Current, [hashtable]$Settings = @{})
    $notes = New-Object System.Collections.Generic.List[string]
    $d = Get-PimManagerAppDefaultSize
    $dc = [double](ConvertTo-PimJobCpu $d.Cpu); $dm = [double](ConvertTo-PimJobMemoryGi $d.Memory)
    $cpu = $dc; $mem = $dm; $source = 'default'
    $cc = $null; $cm = $null
    if ($null -ne $Current) {
        $gc = { param($n) if ($Current -is [System.Collections.IDictionary]) { if ($Current.Contains($n)) { $Current[$n] } } elseif ($Current.PSObject.Properties[$n]) { $Current.$n } }
        $rc = & $gc 'Cpu'; $rm = & $gc 'Memory'
        if ("$rc".Trim()) { $cc = ConvertTo-PimJobCpu $rc }
        if ("$rm".Trim()) { $cm = ConvertTo-PimJobMemoryGi $rm }
    }
    $haveCur = ($null -ne $cc -and $null -ne $cm -and $cc -gt 0 -and $cm -gt 0)
    $have = ''
    if ($haveCur) {
        $have = ('{0} CPU / {1}' -f (Format-PimJobCpu $cc), (Format-PimJobMemory $cm))
        if ($cc -ge $dc -and $cm -ge $dm) {
            $cpu = $cc; $mem = $cm
            if ($cc -gt $dc -or $cm -gt $dm) { $source = 'kept'; $notes.Add(("the Manager web app already runs {0} -- kept (never lowered)" -f $have)) }
        } else {
            $cpu = [Math]::Max($dc, $cc); $mem = [Math]::Max($dm, $cm); $source = 'raised'
            $notes.Add(("the Manager web app runs {0}, below the product size {1} CPU / {2} -- raised (never lowered)" -f $have, $d.Cpu, $d.Memory))
        }
    }
    # 3. the customer's own size wins
    $sfx = "$($script:PimManagerSizeSuffix)".Trim(); if (-not $sfx) { $sfx = 'Manager' }
    $gv = { param($n) if ($Settings -and $Settings.ContainsKey($n) -and -not [string]::IsNullOrWhiteSpace([string]$Settings[$n])) { "$($Settings[$n])".Trim() } else { $null } }
    $override = [ordered]@{}
    $oc = $null; $om = $null
    $n = 'PIM_Bootstrap_Cpu_{0}' -f $sfx; $v = & $gv $n
    if ($null -ne $v) {
        $c = ConvertTo-PimJobCpu $v
        if ($null -ne $c -and $c -ge 0.25 -and $c -le 4 -and (($c * 4) % 1) -eq 0) { $oc = $c }
        else { $notes.Add(("{0} = '{1}' is not a CPU size (0.25 to 4, in steps of 0.25) -- ignored" -f $n, $v)) }
    }
    $n = 'PIM_Bootstrap_Memory_{0}' -f $sfx; $v = & $gv $n
    if ($null -ne $v) {
        $m = ConvertTo-PimJobMemoryGi $v
        if ($null -ne $m -and $m -ge 0.5 -and $m -le 8 -and (($m * 2) % 1) -eq 0) { $om = $m }
        else { $notes.Add(("{0} = '{1}' is not a memory size (0.5Gi to 8Gi, in steps of 0.5Gi) -- ignored" -f $n, $v)) }
    }
    if ($null -ne $oc -or $null -ne $om) {
        if ($null -eq $om) { $om = $oc * 2; $notes.Add(("PIM_Bootstrap_Memory_{0} is not set -- memory follows the CPU: {1}" -f $sfx, (Format-PimJobMemory $om))) }
        if ($null -eq $oc) { $oc = $om / 2; $notes.Add(("PIM_Bootstrap_Cpu_{0} is not set -- CPU follows the memory: {1}" -f $sfx, (Format-PimJobCpu $oc))) }
        $cpu = $oc; $mem = $om; $source = 'customer'
        $override['Cpu'] = (Format-PimJobCpu $oc); $override['Memory'] = (Format-PimJobMemory $om)
        $notes.Add(("the customer's size wins: PIM_Bootstrap_Cpu_{0}={1}, PIM_Bootstrap_Memory_{0}={2}" -f $sfx, $override['Cpu'], $override['Memory']))
    }
    $changed = ($haveCur -and ($cc -ne $cpu -or $cm -ne $mem))
    return [pscustomobject]@{ Cpu = (Format-PimJobCpu $cpu); Memory = (Format-PimJobMemory $mem); Source = $source; Changed = [bool]$changed
                              Have = $have; Notes = @($notes.ToArray()); Override = $override }
}

function Get-PimManagerSizingTags {
    <# PURE. The tags that RECORD the Manager web app's sizing on the app (the override so a later update keeps the customer's choice). #>
    param([Parameter(Mandatory)][object]$Size, [datetime]$NowUtc = [datetime]::UtcNow)
    $p = $script:PimTenantSizingTagPrefix; if (-not $p) { $p = 'pim-sizing-' }
    $t = [ordered]@{}
    $t["${p}size"] = ('{0}/{1}' -f $Size.Cpu, $Size.Memory)
    $t["${p}source"] = "$($Size.Source)"
    $ov = $Size.Override
    # 'Cpu:2.0+Memory:4.0Gi' -- the same shape the jobs use (ConvertFrom-PimTenantSizingTags reads it back)
    $t["${p}override"] = $(if ($ov -and $ov.Count) { (@($ov.Keys | ForEach-Object { "$($_):$($ov[$_])" }) -join '+') } else { '' })
    $t["${p}utc"] = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    return $t
}

function Get-PimManagerAppResize {
    <#
      PURE. What ONE write of the Manager web app must carry for its size -- the -Resize answer of Set-PimAcaAppImage /
      Invoke-PimAcaRoll (engine/_shared/PIM-ArmContainerApps.ps1) and of Invoke-PimManagerAppSizeUpdate below.
      -Container: the app's container as ARM returned it (resources.cpu / resources.memory). -App: the app (its tags carry a
      recorded customer override). -Environment: name -> value (PIM_Bootstrap_Cpu_Manager / PIM_Bootstrap_Memory_Manager).
      Returns @{ change; Cpu; Memory; Tags; detail; notes; size }. change = $false -> the write must leave the resources
      exactly as they are. Tags (only when change) = the app's OWN tags plus the pim-sizing-* record, for the SAME write.
    #>
    param([AllowNull()][object]$Container, [AllowNull()][object]$App, [hashtable]$Environment = @{}, [datetime]$NowUtc = [datetime]::UtcNow)
    $cur = $null
    $res = $null; if ($Container) { $res = $Container.resources }
    if ($res -and "$($res.cpu)".Trim() -and "$($res.memory)".Trim()) { $cur = @{ Cpu = "$($res.cpu)"; Memory = "$($res.memory)" } }
    $appTags = $null; if ($App) { $appTags = $App.tags }
    $rec = ConvertFrom-PimTenantSizingTags -Tags $appTags -Job 'Manager'
    $settings = Get-PimJobSizingSettings -Environment $Environment -Recorded $rec.settings
    $size = Get-PimManagerAppResources -Current $cur -Settings $settings
    # CR7 (framework 12.11g, live 2026-10-18 on the ring-1 test install: ContainerAppInvalidResourceTotal): behind the sign-in
    # front the app's containers SHARE the Consumption maximum (4.0 CPU / 8.0Gi) -- the Manager gets what the front leaves
    # (3.75 / 7.5Gi beside a 0.25 / 0.5Gi front). Every resize path (the updater's roll, the size update, setup) asks here,
    # so no update ever raises the Manager past what the app may hold. Without a front: exactly as before.
    $sfc = $null; if ($App -and $App.properties -and $App.properties.template) { $sfc = @(@($App.properties.template.containers) | Where-Object { $_ -and "$($_.name)" -eq 'signin-front' })[0] }
    if ($sfc -and $sfc.resources) {
        $fcCpu = ConvertTo-PimJobCpu $sfc.resources.cpu; $fcMem = ConvertTo-PimJobMemoryGi $sfc.resources.memory
        if ($null -ne $fcCpu -and $null -ne $fcMem) {
            $roomCpu = [double]$script:PimJobSizeMaxCpu - [double]$fcCpu; $roomMem = (2 * [double]$script:PimJobSizeMaxCpu) - [double]$fcMem
            $wCpu = [double](ConvertTo-PimJobCpu $size.Cpu); $wMem = [double](ConvertTo-PimJobMemoryGi $size.Memory)
            if ($wCpu -gt $roomCpu -or $wMem -gt $roomMem) {
                $nCpu = [Math]::Min($wCpu, $roomCpu); $nMem = [Math]::Min($wMem, $roomMem)
                $size.Cpu = Format-PimJobCpu $nCpu; $size.Memory = Format-PimJobMemory $nMem
                $haveC = $null; $haveM = $null; if ($cur) { $haveC = ConvertTo-PimJobCpu $cur.Cpu; $haveM = ConvertTo-PimJobMemoryGi $cur.Memory }
                $size.Changed = [bool]($null -ne $haveC -and ($haveC -ne $nCpu -or $haveM -ne $nMem))
                $size.Notes = @(@($size.Notes) + ("behind the sign-in front ({0} CPU / {1}) the Manager may hold at most {2} CPU / {3} -- the app's total is capped at {4} CPU" -f (Format-PimJobCpu $fcCpu), (Format-PimJobMemory $fcMem), $size.Cpu, $size.Memory, (Format-PimJobCpu $script:PimJobSizeMaxCpu)))
            }
        }
    }
    $tags = $null
    if ($size.Changed) {
        $tags = @{}
        if ($appTags) {
            if ($appTags -is [System.Collections.IDictionary]) { foreach ($k in @($appTags.Keys)) { $tags["$k"] = "$($appTags[$k])" } }
            else { foreach ($tp in @($appTags.PSObject.Properties)) { $tags["$($tp.Name)"] = "$($tp.Value)" } }
        }
        $mine = Get-PimManagerSizingTags -Size $size -NowUtc $NowUtc
        foreach ($k in @($mine.Keys)) { if ("$($mine[$k])".Trim()) { $tags["$k"] = "$($mine[$k])" } elseif ($tags.ContainsKey("$k")) { $tags.Remove("$k") } }
    }
    $detail = ''
    if ($null -eq $cur) { $detail = 'the Manager web app''s size could not be read -- not changed' }
    elseif ($size.Changed) { $detail = ('the Manager web app: {0} -> {1} CPU / {2} ({3})' -f $size.Have, $size.Cpu, $size.Memory, $size.Source) }
    else { $detail = ('the Manager web app: {0} -- unchanged ({1})' -f $size.Have, $size.Source) }
    return [pscustomobject]@{ change = [bool]$size.Changed; Cpu = $size.Cpu; Memory = $size.Memory; Tags = $tags; detail = $detail; notes = @($size.Notes); size = $size }
}

function Test-PimManagerAppUndersized {
    <#
      PURE. Is the Manager web app below its size? @{ readable; undersized; have; want; source; reason; fix }.
      want = Get-PimManagerAppResources for what it runs (-Cpu / -Memory) and the override recorded on it (-Tags), so a
      customer's own smaller size is NOT flagged. An unread size is not judged.
    #>
    param([AllowNull()][object]$Cpu, [AllowNull()][object]$Memory, [AllowNull()]$Tags, [string]$AppName = 'ca-pim-manager')
    $d = Get-PimManagerAppDefaultSize
    $rec = ConvertFrom-PimTenantSizingTags -Tags $Tags -Job 'Manager'
    $cur = $null; if ("$Cpu".Trim() -and "$Memory".Trim()) { $cur = @{ Cpu = "$Cpu"; Memory = "$Memory" } }
    $size = Get-PimManagerAppResources -Current $cur -Settings $rec.settings
    $want = ('{0} CPU / {1}' -f $size.Cpu, $size.Memory)
    if (-not "$($size.Have)".Trim()) { return [pscustomobject]@{ readable = $false; undersized = $false; have = ''; want = $want; source = $size.Source; fix = ''; reason = 'the Manager web app''s size could not be read' } }
    $hc = [double](ConvertTo-PimJobCpu $Cpu); $hm = [double](ConvertTo-PimJobMemoryGi $Memory)
    $low = ($hc -lt [double](ConvertTo-PimJobCpu $size.Cpu) -or $hm -lt [double](ConvertTo-PimJobMemoryGi $size.Memory))
    $what = $(if ($size.Source -eq 'customer') { 'the size the customer set' } else { 'the product size' })
    $reason = $(if ($low) { ('the Manager web app runs {0}; {1} is {2}' -f $size.Have, $what, $want) } else { ('the Manager web app runs {0} ({1} {2} CPU / {3})' -f $size.Have, $(if ($size.Source -eq 'customer') { 'the customer''s size; the product size is' } else { 'the product size is' }), $d.Cpu, $d.Memory) })
    $fix = $(if ($low) { ("Azure portal > Container app $AppName > Containers > Edit and deploy: CPU {0}, memory {1} (the next update raises it by itself)" -f $size.Cpu, $size.Memory) } else { '' })
    return [pscustomobject]@{ readable = $true; undersized = [bool]$low; have = $size.Have; want = $want; source = $size.Source; fix = $fix; reason = $reason }
}

function Test-PimSqlTierBelowDefault {
    <#
      PURE. Is the main database below the product tier? @{ readable; below; pinned; current; want; reason; fix }, from THE plan
      (Get-PimSqlTierPlan): below = the plan would raise it, OR it is pinned below the default (reported, never changed).
      Premium / vCore / an elastic pool / an unread tier are not judged.
    #>
    param([AllowNull()][string]$Current, [AllowNull()][string]$Pin, [AllowNull()][string]$ElasticPool, [AllowNull()][object]$CurrentMaxSizeBytes = $null, [string]$Database = 'PimPlatform')
    $plan = Get-PimSqlTierPlan -Current $Current -Pin $Pin -ElasticPool $ElasticPool -CurrentMaxSizeBytes $CurrentMaxSizeBytes
    $c = "$Current".Trim()
    if (-not $c) { return [pscustomobject]@{ readable = $false; below = $false; pinned = [bool]$plan.pinned; current = ''; want = $plan.defaultTier; fix = ''; reason = 'the database tier could not be read' } }
    $below = ($plan.action -eq 'raise' -or [bool]$plan.pinnedBelowDefault -or $plan.maxSizeAction -eq 'set')
    $reason = $(if ($plan.pinnedBelowDefault) { "$($plan.pinNote)" } else { "database $Database`: $($plan.reason)" })
    $fix = ''
    if ($plan.pinnedBelowDefault) { $fix = "Set-PimSqlTier.ps1 -Tier $($plan.defaultTier) -Pin moves a pinned database (https://invardia.com/support/pim/Set-PimSqlTier.ps1); leave it when the pin is the customer's choice" }
    elseif ($below) { $fix = 'Set-PimSqlTier.ps1 applies it now (https://invardia.com/support/pim/Set-PimSqlTier.ps1); the next update does it by itself' }
    return [pscustomobject]@{ readable = $true; below = [bool]$below; pinned = [bool]$plan.pinned; current = $c; want = $plan.defaultTier; fix = $fix; reason = $reason }
}

function Test-PimJobRunOutOfResources {
    <#
      PURE. Is this run record evidence the job ran OUT of memory or time? Returns '' (no), 'memory' or 'timeout'.
      Evidence (the job-lane causes, PIM-JobLanes Get-PimInterruptedRunVerdict, and the failure catalog):
        memory  -- the run's text classifies ENGINE-OUT-OF-MEMORY (PIM-FailureCatalog), or names OutOfMemoryException /
                   OOMKilled / exit code 137, or the execution 'ended in Failed ... (out of memory or a crash)' ('crashed')
        timeout -- 'stopped at the execution time limit' ('time-limit'), or the platform's replica timeout text
    #>
    param([AllowNull()][object]$Run)
    if ($null -eq $Run) { return '' }
    $st = "$($Run.status)".Trim()
    if ($Run.PSObject.Properties['ok'] -and [bool]$Run.ok -and $st -ne 'failed') { return '' }
    $txt = "$($Run.detail) $($Run.error) $($Run.cause)"
    if ($txt -match '(?i)stopped at the execution time limit|\btime-limit\b|replica ?timeout|exceeded (the )?(replica )?timeout|DeadlineExceeded') { return 'timeout' }
    $code = ''
    if (Get-Command Get-PimFailureClassification -ErrorAction SilentlyContinue) { try { $code = "$((Get-PimFailureClassification -Message $txt).code)" } catch { $code = '' } }
    if ($code -eq 'ENGINE-OUT-OF-MEMORY' -or $txt -match '(?i)OutOfMemoryException|\bOOMKilled\b|exit code 137\b|out of memory or a crash|\bcrashed\b') { return 'memory' }
    return ''
}

function Get-PimJobSelfCorrection {
    <#
      PURE. The self-correction an update makes for ONE job: any run (from pim.Settings JobRunHistory, newest first) that
      started after -SinceUtc (when the job was last sized) and ran out of memory or time.
      Returns @{ raise; kind ('memory'|'timeout'|''); evidence[]; reason }.
      -JobRunNames: the run names that ran IN this job (default: all -- every scheduled job of the tick runs in ca-pim-tick).
    #>
    param([object[]]$Runs = @(), [AllowNull()][object]$SinceUtc, [string[]]$JobRunNames = @())
    $since = $null
    if ($SinceUtc) { try { $since = ([datetime]"$SinceUtc").ToUniversalTime() } catch { $since = $null } }
    $ev = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Runs | Where-Object { $_ })) {
        if ($JobRunNames.Count -and ($JobRunNames -notcontains "$($r.name)")) { continue }
        $at = $null; try { if ("$($r.startedUtc)".Trim()) { $at = ([datetime]"$($r.startedUtc)").ToUniversalTime() } } catch { $at = $null }
        if ($since -and $at -and $at -le $since) { continue }
        $k = Test-PimJobRunOutOfResources -Run $r
        if ($k) { $ev.Add([pscustomobject]@{ kind = $k; name = "$($r.name)"; startedUtc = "$($r.startedUtc)"; detail = ("$($r.detail)" -replace '\s+', ' ').Substring(0, [Math]::Min(200, ("$($r.detail)" -replace '\s+', ' ').Length)) }) }
    }
    if (-not $ev.Count) { return [pscustomobject]@{ raise = $false; kind = ''; evidence = @(); reason = 'no run ran out of memory or time since the job was last sized' } }
    $kind = if (@($ev | Where-Object { $_.kind -eq 'memory' }).Count) { 'memory' } else { 'timeout' }
    $first = $ev[0]
    return [pscustomobject]@{ raise = $true; kind = $kind; evidence = @($ev.ToArray())
        reason = ("{0} run(s) ran out of {1} since the job was last sized (latest: '{2}' at {3})" -f $ev.Count, $(if ($kind -eq 'memory') { 'memory' } else { 'time' }), $first.name, $first.startedUtc) }
}

function Step-PimJobSize {
    <# PURE. One band up (capped at 4 CPU / 8 GiB); the replicaTimeout is always the 7-day run limit (framework 12.24). #>
    param([Parameter(Mandatory)][double]$Cpu, [Parameter(Mandatory)][double]$MemoryGi, [int]$ReplicaTimeout = 0)
    $band = Get-PimJobBandOf -Cpu $Cpu -MemoryGi $MemoryGi
    $next = @($script:PimJobSizeBands | Where-Object { $_.Band -eq ($band + 1) }) | Select-Object -First 1
    $c = $Cpu; $m = $MemoryGi
    if ($next) { $c = [Math]::Max($Cpu, [double]$next.Cpu); $m = [Math]::Max($MemoryGi, (ConvertTo-PimJobMemoryGi $next.Memory)) }
    $t = [int]$script:PimJobRunLimitSeconds
    return [pscustomobject]@{ Cpu = [Math]::Min($c, $script:PimJobSizeMaxCpu); MemoryGi = [Math]::Min($m, $script:PimJobSizeMaxMemoryGi); ReplicaTimeout = $t
                              Band = (Get-PimJobBandOf -Cpu ([Math]::Min($c, $script:PimJobSizeMaxCpu)) -MemoryGi ([Math]::Min($m, $script:PimJobSizeMaxMemoryGi))) }
}

function Get-PimContainerJobResources {
    <#
      PURE. THE ONE DECISION: a PIM engine job's CPU, memory and replicaTimeout.
        1. the job's default (-DefaultReplicaTimeout = the install's -TickReplicaTimeout)
        2. the tenant tier for -Counts (raise only)
        3. -Current: what the job runs now -- never lowered (an update never shrinks a job someone raised)
        4. -SelfCorrect (Get-PimJobSelfCorrection): one band + one timeout step up
        5. the customer's PIM_Bootstrap_Cpu/Memory/ReplicaTimeout_<Job> (-Settings: name -> value; env, the update job's env,
           or the override RECORDED on the job) WINS, also downwards. Invalid -> ignored with a note.
      Capped at 4.0 CPU / 8.0Gi. Returns @{ Cpu; Memory; ReplicaTimeout; Band; Objects; Source; Notes; Override }.
    #>
    param([string]$Job = 'ca-pim-tick', [AllowNull()]$Counts, [hashtable]$Settings = @{}, [AllowNull()]$Current, [AllowNull()]$SelfCorrect,
          [int]$DefaultReplicaTimeout = 0)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $notes = New-Object System.Collections.Generic.List[string]
    $d = Get-PimJobDefaultSize -Job $Job -DefaultReplicaTimeout $DefaultReplicaTimeout
    $cpu = [double](ConvertTo-PimJobCpu $d.Cpu); $mem = [double](ConvertTo-PimJobMemoryGi $d.Memory); $to = [int]$d.ReplicaTimeout
    $source = 'default'
    $objects = Get-PimTenantObjectTotal -Counts $Counts
    $sized = Get-PimTenantSizedJobResources -Job $Job -Counts $Counts
    if ($sized) {
        $sc = [double](ConvertTo-PimJobCpu $sized.Cpu); $sm = [double](ConvertTo-PimJobMemoryGi $sized.Memory)
        if ($sm -gt $mem -or $sc -gt $cpu) { $cpu = [Math]::Max($cpu, $sc); $mem = [Math]::Max($mem, $sm); $source = 'tenant-size' }
        if ([int]$sized.ReplicaTimeout -gt $to) { $to = [int]$sized.ReplicaTimeout }
        $notes.Add(('sized for this tenant: {0:N0} objects (users + groups + service principals) -> {1} CPU / {2}, replicaTimeout {3} s' -f $objects, (Format-PimJobCpu $sc), (Format-PimJobMemory $sm), $sized.ReplicaTimeout))
    } elseif ($null -ne $Counts) {
        $notes.Add(('{0:N0} objects (under 5,000) -> the job default {1} CPU / {2}' -f $objects, $d.Cpu, $d.Memory))
    }
    if ($null -ne $Current) {
        $gc = { param($n) if ($Current -is [System.Collections.IDictionary]) { if ($Current.Contains($n)) { $Current[$n] } } elseif ($Current.PSObject.Properties[$n]) { $Current.$n } }
        $cc = ConvertTo-PimJobCpu (& $gc 'Cpu'); $cm = ConvertTo-PimJobMemoryGi (& $gc 'Memory'); $ct = 0; [void][int]::TryParse("$(& $gc 'ReplicaTimeout')", [ref]$ct)
        if ($null -ne $cc -and $null -ne $cm -and ($cm -gt $mem -or $cc -gt $cpu)) { $cpu = [Math]::Max($cpu, $cc); $mem = [Math]::Max($mem, $cm); $source = 'kept'; $notes.Add(('the job already runs {0} CPU / {1} -- kept (never lowered)' -f (Format-PimJobCpu $cc), (Format-PimJobMemory $cm))) }
        if ($ct -gt $to) { $to = $ct }
    }
    if ($SelfCorrect -and [bool]$SelfCorrect.raise) {
        $s = Step-PimJobSize -Cpu $cpu -MemoryGi $mem -ReplicaTimeout $to
        $notes.Add(('self-correct: {0} -> {1} CPU / {2}, replicaTimeout {3} s' -f $SelfCorrect.reason, (Format-PimJobCpu $s.Cpu), (Format-PimJobMemory $s.MemoryGi), $s.ReplicaTimeout))
        $cpu = $s.Cpu; $mem = $s.MemoryGi; $to = $s.ReplicaTimeout; $source = 'self-correct'
    }
    $cpu = [Math]::Min($cpu, $script:PimJobSizeMaxCpu); $mem = [Math]::Min($mem, $script:PimJobSizeMaxMemoryGi)

    # 5. the customer's own size wins
    $sfx = Get-PimJobSettingSuffix -Job $Job
    $gv = { param($n) if ($Settings -and $Settings.ContainsKey($n) -and -not [string]::IsNullOrWhiteSpace([string]$Settings[$n])) { "$($Settings[$n])".Trim() } else { $null } }
    $override = [ordered]@{}
    # framework 12.24 JOB-RUN-LIMIT: the run limit is always Azure's maximum -- a customer value is not a size and is ignored.
    $n = 'PIM_Bootstrap_ReplicaTimeout_{0}' -f $sfx; $v = & $gv $n
    if ($null -ne $v) { $notes.Add(("{0} = '{1}' is ignored -- every PIM job runs with the 7-day maximum run limit ({2} s)" -f $n, $v, $script:PimJobRunLimitSeconds)) }
    $to = [Math]::Max([int]$to, [int]$script:PimJobRunLimitSeconds)
    $n = 'PIM_Bootstrap_Cpu_{0}' -f $sfx; $v = & $gv $n
    if ($null -ne $v) {
        $c = ConvertTo-PimJobCpu $v
        if ($null -ne $c -and $c -ge 0.25 -and $c -le 4 -and (($c * 4) % 1) -eq 0) { $cpu = $c; $override['Cpu'] = (Format-PimJobCpu $c); $source = 'customer' }
        else { $notes.Add(("{0} = '{1}' is not a CPU size (0.25 to 4, in steps of 0.25) -- using {2}" -f $n, $v, (Format-PimJobCpu $cpu))) }
    }
    $n = 'PIM_Bootstrap_Memory_{0}' -f $sfx; $v = & $gv $n
    if ($null -ne $v) {
        $m = ConvertTo-PimJobMemoryGi $v
        if ($null -ne $m -and $m -ge 0.5 -and $m -le 8 -and (($m * 2) % 1) -eq 0) { $mem = $m; $override['Memory'] = (Format-PimJobMemory $m); $source = 'customer' }
        else { $notes.Add(("{0} = '{1}' is not a memory size (0.5Gi to 8Gi, in steps of 0.5Gi) -- using {2}" -f $n, $v, (Format-PimJobMemory $mem))) }
    }
    if ($override.Count) { $notes.Add(('the customer''s size wins: {0}' -f (@($override.Keys | ForEach-Object { "PIM_Bootstrap_$($_)_$sfx=$($override[$_])" }) -join ', '))) }
    return [pscustomobject]@{ Cpu = (Format-PimJobCpu $cpu); Memory = (Format-PimJobMemory $mem); ReplicaTimeout = $to; Band = (Get-PimJobBandOf -Cpu $cpu -MemoryGi $mem)
                              Objects = $objects; Source = $source; Notes = @($notes.ToArray()); Override = $override }
}

function Get-PimJobSizingSettings {
    <#
      PURE. The customer's PIM_Bootstrap_Cpu/Memory/ReplicaTimeout_* settings: -Environment (name -> value; the installer's or
      the update job's environment) over -Recorded (the override recorded on the job at its last sizing, so an update without
      the variable keeps what the customer chose). Non-empty values only.
    #>
    param([hashtable]$Environment = @{}, [hashtable]$Recorded = @{})
    $out = @{}
    foreach ($src in @($Recorded, $Environment)) {
        if (-not $src) { continue }
        foreach ($k in @($src.Keys)) { if ("$k" -match '^(?i)PIM_Bootstrap_(Cpu|Memory|ReplicaTimeout)_[A-Za-z0-9]+$' -and -not [string]::IsNullOrWhiteSpace([string]$src[$k])) { $out["$k"] = "$($src[$k])".Trim() } }
    }
    return $out
}

function Get-PimJobSizeCommand {
    <# PURE. The exact az command that sets a job to a size. #>
    param([string]$SubscriptionId, [string]$ResourceGroup, [string]$JobName = 'ca-pim-tick', [Parameter(Mandatory)][string]$Cpu, [Parameter(Mandatory)][string]$Memory, [int]$ReplicaTimeout = 0)
    $m = ConvertTo-PimJobMemoryGi $Memory
    $ms = if ($null -ne $m) { ('{0}Gi' -f $m.ToString('0.##', [Globalization.CultureInfo]::InvariantCulture)) } else { $Memory }
    $c = ConvertTo-PimJobCpu $Cpu; $cs = if ($null -ne $c) { Format-PimJobCpu $c } else { $Cpu }
    $sub = if ("$SubscriptionId".Trim()) { " --subscription $SubscriptionId" } else { '' }
    $rg = if ("$ResourceGroup".Trim()) { $ResourceGroup } else { '<resource group>' }
    $t = if ($ReplicaTimeout -gt 0) { " --replica-timeout $ReplicaTimeout" } else { '' }
    return ("az containerapp job update$sub -g $rg -n $JobName --cpu $cs --memory $ms$t")
}

function Test-PimJobUndersized {
    <#
      PURE. Is the job below the tier for its RECORDED object count? @{ undersized; objects; want; have; command; reason }.
      want = the tier (Get-PimTenantSizedJobResources); a job at or above it in CPU, memory AND replicaTimeout is sized.
      A tenant under 5,000 objects, or no recorded count, is never undersized (nothing to compare with).
    #>
    param([AllowNull()]$Counts, [AllowNull()][object]$Cpu, [AllowNull()][object]$Memory, [int]$ReplicaTimeout = 0,
          [string]$SubscriptionId, [string]$ResourceGroup, [string]$JobName = 'ca-pim-tick')
    $objects = Get-PimTenantObjectTotal -Counts $Counts
    $tier = Get-PimTenantSizedJobResources -Job $JobName -Counts $Counts
    $hc = ConvertTo-PimJobCpu $Cpu; $hm = ConvertTo-PimJobMemoryGi $Memory
    $have = ('{0} CPU / {1}, replicaTimeout {2} s' -f $(if ($null -ne $hc) { Format-PimJobCpu $hc } else { '?' }), $(if ($null -ne $hm) { Format-PimJobMemory $hm } else { '?' }), $ReplicaTimeout)
    if (-not $tier) { return [pscustomobject]@{ undersized = $false; objects = $objects; want = $null; have = $have; command = ''; reason = $(if ($objects -gt 0) { ('{0:N0} objects -- under 5,000, the default size is right' -f $objects) } else { 'no recorded tenant size' }) } }
    $want = ('{0} CPU / {1}, replicaTimeout {2} s' -f $tier.Cpu, $tier.Memory, $tier.ReplicaTimeout)
    $low = ($null -eq $hc -or $null -eq $hm -or $hc -lt [double](ConvertTo-PimJobCpu $tier.Cpu) -or $hm -lt [double](ConvertTo-PimJobMemoryGi $tier.Memory) -or ($ReplicaTimeout -gt 0 -and $ReplicaTimeout -lt [int]$tier.ReplicaTimeout))
    $cmd = Get-PimJobSizeCommand -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -JobName $JobName -Cpu $tier.Cpu -Memory $tier.Memory -ReplicaTimeout $tier.ReplicaTimeout
    return [pscustomobject]@{ undersized = [bool]$low; objects = $objects; want = $want; have = $have; command = $(if ($low) { $cmd } else { '' })
        reason = $(if ($low) { ('{0:N0} objects needs {1}; the job runs {2}' -f $objects, $want, $have) } else { ('{0:N0} objects; the job runs {1} (tier {2})' -f $objects, $have, $want) }) }
}

function Get-PimTenantSizingTags {
    <# PURE. The tags that RECORD a sizing on the job (Azure resource tags: the update, the verify and the environment report read them). #>
    param([AllowNull()]$Counts, [Parameter(Mandatory)][object]$Size, [string]$CountSource = 'graph', [datetime]$NowUtc = [datetime]::UtcNow)
    $g = { param($k) $v = $null; if ($Counts -is [System.Collections.IDictionary]) { if ($Counts.Contains($k)) { $v = $Counts[$k] } } elseif ($Counts -and $Counts.PSObject.Properties[$k]) { $v = $Counts.$k }; if ($null -eq $v) { '' } else { "$v" } }
    $p = $script:PimTenantSizingTagPrefix
    $t = [ordered]@{}
    $t["${p}users"] = & $g 'Users'; $t["${p}groups"] = & $g 'Groups'; $t["${p}sps"] = & $g 'ServicePrincipals'
    $t["${p}objects"] = $(if ($null -ne $Counts) { "$(Get-PimTenantObjectTotal -Counts $Counts)" } else { '' })
    $t["${p}counted"] = "$CountSource"
    $t["${p}size"] = ('{0}/{1}/{2}' -f $Size.Cpu, $Size.Memory, $Size.ReplicaTimeout)
    $t["${p}source"] = "$($Size.Source)"
    $ov = $Size.Override
    $t["${p}override"] = $(if ($ov -and $ov.Count) { (@($ov.Keys | ForEach-Object { "$($_):$($ov[$_])" }) -join '+') } else { '' })
    $t["${p}utc"] = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    return $t
}

function ConvertFrom-PimTenantSizingTags {
    <# PURE. The recorded sizing from a job's tags: @{ recorded; counts @{Users;Groups;ServicePrincipals}; objects; size; source; counted; sizedUtc; settings }. #>
    param([AllowNull()]$Tags, [string]$Job = 'ca-pim-tick')
    $p = $script:PimTenantSizingTagPrefix
    $gt = { param($k) $v = $null; if ($null -eq $Tags) { return '' }; if ($Tags -is [System.Collections.IDictionary]) { if ($Tags.Contains($k)) { $v = $Tags[$k] } } elseif ($Tags.PSObject.Properties[$k]) { $v = $Tags.$k }; if ($null -eq $v) { '' } else { "$v".Trim() } }
    $num = { param($s) $n = 0L; if ([long]::TryParse("$s", [ref]$n)) { $n } else { $null } }
    $u = & $num (& $gt "${p}users"); $gr = & $num (& $gt "${p}groups"); $sp = & $num (& $gt "${p}sps")
    $recorded = ($null -ne $u -or $null -ne $gr -or $null -ne $sp)
    $counts = if ($recorded) { @{ Users = [long]$u; Groups = [long]$gr; ServicePrincipals = [long]$sp } } else { $null }
    $settings = @{}
    $ov = & $gt "${p}override"
    if ($ov) {
        $sfx = Get-PimJobSettingSuffix -Job $Job
        # 'Cpu:2.0+Memory:4.0Gi' -- no ';' ',' '=' or '&': the tags go through az.cmd, where cmd.exe splits on those
        foreach ($kv in @($ov -split '\+' | Where-Object { $_ -match ':' })) { $k, $v = $kv -split ':', 2; $settings[('PIM_Bootstrap_{0}_{1}' -f $k.Trim(), $sfx)] = $v.Trim() }
    }
    return [pscustomobject]@{ recorded = $recorded; counts = $counts; objects = $(if ($recorded) { Get-PimTenantObjectTotal -Counts $counts } else { $null })
        size = (& $gt "${p}size"); source = (& $gt "${p}source"); counted = (& $gt "${p}counted"); sizedUtc = (& $gt "${p}utc"); settings = $settings }
}

function Get-PimTenantObjectCounts {
    <#
      The tenant's users, groups and service principals by Microsoft Graph $count (ConsistencyLevel: eventual).
      -GraphGet { param($Path) } returns the raw answer (an integer, or text) for '/users/$count' etc. -- the caller mints the
      token and sends the ConsistencyLevel header. Never throws: @{ ok; Users; Groups; ServicePrincipals; Objects; error }.
    #>
    param([Parameter(Mandatory)][scriptblock]$GraphGet)
    $out = [ordered]@{ ok = $false; Users = $null; Groups = $null; ServicePrincipals = $null; Objects = $null; error = '' }
    try {
        foreach ($pair in @(@('Users', '/users/$count'), @('Groups', '/groups/$count'), @('ServicePrincipals', '/servicePrincipals/$count'))) {
            $raw = & $GraphGet $pair[1]
            $n = 0L
            if (-not [long]::TryParse(("$raw".Trim().Trim([char]0xFEFF)), [ref]$n)) { throw ("{0} did not answer a number ('{1}')" -f $pair[1], "$raw".Trim()) }
            $out[$pair[0]] = $n
        }
        $out.Objects = Get-PimTenantObjectTotal -Counts $out
        $out.ok = $true
    } catch { $out.error = (("$($_.Exception.Message)" -split "`n")[0]).Trim() }
    return [pscustomobject]$out
}

function Resolve-PimSqlServiceObjective {
    <#
      PURE. A database's REAL service objective from an ARM GET. TRAP (measured live 2026-10-09): for a DTU database
      sku.name is the TIER name ("Standard", "Basic"), not "S0"/"S1" -- comparing on it reads every Standard database as an
      unknown tier. Order: properties.currentServiceObjectiveName; else sku.name when it IS an objective (S0, P1, GP_Gen5_2);
      else sku.tier/sku.name 'Basic' -> Basic; else a Standard sku.capacity in DTU (10 S0, 20 S1, 50 S2, 100 S3, 200 S4,
      400 S6, 800 S7, 1600 S9, 3000 S12); else '' (unknown -- the plan changes nothing).
    #>
    param([AllowNull()][object]$Database)
    if ($null -eq $Database) { return '' }
    $so = "$($Database.properties.currentServiceObjectiveName)".Trim()
    if ($so) { return $so }
    $sn = "$($Database.sku.name)".Trim(); $st = "$($Database.sku.tier)".Trim()
    if ($sn -and $sn -notmatch '^(?i)(Standard|Basic|Premium|GeneralPurpose|BusinessCritical|Hyperscale)$') { return $sn }
    if ($sn -match '^(?i)basic$' -or $st -match '^(?i)basic$') { return 'Basic' }
    if ($sn -match '^(?i)standard$' -or $st -match '^(?i)standard$') {
        $map = @{ 10 = 'S0'; 20 = 'S1'; 50 = 'S2'; 100 = 'S3'; 200 = 'S4'; 400 = 'S6'; 800 = 'S7'; 1600 = 'S9'; 3000 = 'S12' }
        $cap = 0; if ([int]::TryParse("$($Database.sku.capacity)", [ref]$cap) -and $map.ContainsKey($cap)) { return $map[$cap] }
    }
    return ''
}

function Get-PimSqlTierPlan {
    <#
      PURE. The SQL main database's tier + max size (PIM REQUIREMENTS 100.31 / 100.37 / 100.114; owner 2026-10-12: "S3 at
      every ring 1+2 install" -- PIM's database is S3 (Standard) with a 250 GB max size, for every edition; the earlier
      S0 default and the "Pro = S2" rule before it are gone).
      TIER, raise only:  Basic, S0, S1, S2 -> S3 (-Target; default = the product default).  S3 and every higher Standard
        tier -> kept (never lowered, never raised).
        Premium (P*), vCore (GP_*, BC_*, HS_*), serverless, an elastic pool, or unknown -> none (not ours to change)
        PINNED (-Pin = the database's 'pim-sql-tier-pin' tag, e.g. S0): the tier is NEVER changed (not even Basic -> S3).
        The tag holds a tier name only: nothing in it tells a customer's pin from one written at the product's earlier
        default, so a pin BELOW the default is not overridden -- it is reported: pinnedBelowDefault = $true and pinNote =
        "database is pinned at <tier>, the new default is S3 - not changed" (support moves it: Set-PimSqlTier -Tier S3 -Pin).
      MAX SIZE: every Standard S-tier database (incl. the one this plan raises, and a pinned one) below 250 GB
      (268435456000 bytes) -> maxSizeAction 'set'. A tier raise does NOT grow the max size by itself (measured: an S2 with
      Basic's 2 GB limit filled up -> "has reached its size quota" on every write), so a raise FROM Basic always includes it.
      Never lowered; never on Basic staying Basic, Premium, vCore or a pool; an unread max size (not raised from Basic) ->
      not changed. -Pro is accepted and ignored (kept for callers; there is no Pro tier rule any more).
      Returns @{ action ('raise'|'none'); target; current; pinned; reason; maxSizeAction ('set'|'none'); maxSizeBytes;
                 currentMaxSizeBytes; defaultTier; pinnedBelowDefault; pinNote }.
    #>
    param([AllowNull()][string]$Current, [bool]$Pro, [string]$Target = '', [AllowNull()][string]$ElasticPool,
          [AllowNull()][object]$CurrentMaxSizeBytes = $null, [AllowNull()][string]$Pin = $null)
    $c = "$Current".Trim()
    $pinV = "$Pin".Trim()
    if (-not "$Target".Trim()) { $Target = Get-PimSqlDefaultTier }
    $Target = "$Target".Trim().ToUpperInvariant()
    $maxWant = Get-PimSqlDefaultMaxSizeBytes
    $pinLow = $false; $pinNote = ''
    $curMax = $null; $tmp = 0L; if ($null -ne $CurrentMaxSizeBytes -and [int64]::TryParse("$CurrentMaxSizeBytes", [ref]$tmp) -and $tmp -gt 0) { $curMax = $tmp }
    $out = { param($act, $tgt, $why)
        # the max size for the tier the database ends on
        $end = $(if ($act -eq 'raise') { $tgt } else { $c })
        $ms = 'none'; $mwhy = ''
        if (-not "$ElasticPool".Trim() -and $end -match '^(?i)S\d+$') {
            if ($null -ne $curMax) {
                if ($curMax -lt $maxWant) { $ms = 'set'; $mwhy = ("max size {0:N0} GB -> 250 GB (every Standard database; never lowered)" -f ($curMax / 1GB)) }
                else { $mwhy = ("max size {0:N0} GB -- kept (never lowered)" -f ($curMax / 1GB)) }
            } elseif ($act -eq 'raise' -and $c -match '^(?i)basic$') { $ms = 'set'; $mwhy = 'max size -> 250 GB (a raise from Basic keeps Basic''s 2 GB limit otherwise)' }
            else { $mwhy = 'max size not read -- not changed' }
        }
        $r = $why; if ($mwhy) { $r = "$why; $mwhy" }
        [pscustomobject]@{ action = $act; target = $tgt; current = $c; pinned = [bool]$pinV; reason = $r; maxSizeAction = $ms; maxSizeBytes = $(if ($ms -eq 'set') { $maxWant } else { $curMax }); currentMaxSizeBytes = $curMax
                           defaultTier = $Target; pinnedBelowDefault = [bool]$pinLow; pinNote = "$pinNote" }
    }
    if ("$ElasticPool".Trim()) { return (& $out 'none' $c "in the elastic pool '$ElasticPool' -- not changed") }
    $rank = { param($s) if ($s -match '^(?i)basic$') { return 0 }; if ($s -match '^(?i)S(\d+)$') { return (1 + [int]$Matches[1]) }; return -1 }
    $have = & $rank $c; $want = & $rank $Target
    if ($pinV) {
        # A pin is never overridden (the tag cannot say WHO pinned it). Below the default it is reported, in these words.
        if ($have -ge 0 -and $have -lt $want) {
            $pinLow = $true
            $pinNote = "database is pinned at $c, the new default is $Target - not changed"
            return (& $out 'none' $c "pinned at $c (pim-sql-tier-pin = '$pinV'), the new default is $Target - not changed (a pinned tier is never changed; to move it: Set-PimSqlTier.ps1 -Tier $Target -Pin)")
        }
        return (& $out 'none' $c "tier pinned to '$pinV' (pim-sql-tier-pin) -- the tier is never changed")
    }
    if ($have -lt 0) { return (& $out 'none' $c $(if ($c) { "'$c' is not a Basic/Standard objective -- not changed (never lowered)" } else { 'the current size could not be read -- not changed' })) }
    if ($have -ge $want) { return (& $out 'none' $c "$c is already at or above $Target -- kept (never lowered)") }
    return (& $out 'raise' $Target "$c -> $Target (the product default; never Basic; raise only)")
}

# =====================================================================================================================
# THE UPDATE'S HALF (ca-pim-update, tools/pim-engine/update-job-entry.ps1). Seams: -Arm { param($Method, $Path, $Body) }
# returns the parsed ARM answer (the updater passes Invoke-PimArm); -Graph { param($Path) } returns a $count answer.
# Both NEVER throw: they return @{ ok; changed; detail; log[] } so a sizing problem never turns a good roll red.
# =====================================================================================================================
$script:PimTenantSizingAcaApi = '2024-03-01'
$script:PimTenantSizingSqlApi = '2021-11-01'

function Invoke-PimJobSizingUpdate {
    <#
      Size ONE job on an update, by the same rule as the install:
        counts   -- Graph $count (-Graph), else the counts RECORDED on the job (pim-sizing-* tags), else none (default size)
        evidence -- -Runs (pim.Settings JobRunHistory) since the job was last sized: a run that ran out of memory or time
                    raises the job one band + one timeout step (Get-PimJobSelfCorrection)
        settings -- -Environment (the update job's env: PIM_Bootstrap_*_<Job>) over the override recorded on the job
      Writes ONLY when the size changes: one PATCH of the job (resources of its containers + configuration.replicaTimeout),
      then the sizing tags (Merge). Returns @{ ok; changed; size; detail; log[] }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [string]$JobName = 'ca-pim-tick',
          [Parameter(Mandatory)][scriptblock]$Arm, [scriptblock]$Graph, [object[]]$Runs = @(), [hashtable]$Environment = @{},
          [datetime]$NowUtc = [datetime]::UtcNow,
          # 2.4.544: the counts the TICK recorded (pim.Settings 'TenantObjectCounts') -- used when the updater's own Graph
          # count is refused (its identity has no directory read right: HTTP 403 on every environment, 2026-10-09).
          [AllowNull()][object]$StoredCounts = $null,
          # 100.50: the job PATCH and the tags PATCH wait out "HTTP 409 ContainerAppsJobOperationInProgress" (the tick roll
          # one step earlier is still provisioning) through Invoke-PimArmBusyRetry (PIM-ArmContainerApps.ps1). -Sleep: test seam.
          [int[]]$BusyWaits = @(20, 20, 20, 20, 20, 20), [scriptblock]$Sleep)
    $log = New-Object System.Collections.Generic.List[string]
    $jobWho = $(if ($JobName -eq 'ca-pim-tick') { 'the tick job' } else { "the job $JobName" })
    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs/$JobName"
    try {
        $job = & $Arm 'GET' "$path`?api-version=$($script:PimTenantSizingAcaApi)" $null
        if (-not $job) { return [pscustomobject]@{ ok = $false; changed = $false; size = $null; detail = "job '$JobName' not found"; log = @() } }
        $containers = @($job.properties.template.containers)
        $r0 = $containers[0].resources
        $cur = @{ Cpu = "$($r0.cpu)"; Memory = "$($r0.memory)"; ReplicaTimeout = "$($job.properties.configuration.replicaTimeout)" }
        $rec = ConvertFrom-PimTenantSizingTags -Tags $job.tags -Job $JobName
        $counts = $null; $countSrc = 'none'
        if ($Graph) {
            $cnt = Get-PimTenantObjectCounts -GraphGet $Graph
            if ($cnt.ok) { $counts = @{ Users = $cnt.Users; Groups = $cnt.Groups; ServicePrincipals = $cnt.ServicePrincipals }; $countSrc = 'graph' }
            elseif ("$($cnt.error)" -match '\b403\b|Authorization_RequestDenied|Insufficient privileges') { $log.Add('the updater identity may not count tenant objects (Graph 403) -- using the counts the engine recorded') }
            else { $log.Add("Graph count failed ($($cnt.error))") }
        }
        if (-not $counts -and $StoredCounts -and $null -ne $StoredCounts.Users -and $null -ne $StoredCounts.Groups -and $null -ne $StoredCounts.ServicePrincipals) {
            $counts = @{ Users = [long]$StoredCounts.Users; Groups = [long]$StoredCounts.Groups; ServicePrincipals = [long]$StoredCounts.ServicePrincipals }; $countSrc = 'engine'
            $log.Add("counts recorded by the engine ($($StoredCounts.recordedUtc)): $($counts.Users) users, $($counts.Groups) groups, $($counts.ServicePrincipals) service principals")
        }
        if (-not $counts -and $rec.recorded) { $counts = $rec.counts; $countSrc = 'recorded'; $log.Add("using the counts recorded on the job ($($rec.sizedUtc))") }
        $sc = Get-PimJobSelfCorrection -Runs $Runs -SinceUtc $rec.sizedUtc
        $settings = Get-PimJobSizingSettings -Environment $Environment -Recorded $rec.settings
        $size = Get-PimContainerJobResources -Job $JobName -Counts $counts -Current $cur -SelfCorrect $sc -Settings $settings
        foreach ($n in @($size.Notes)) { $log.Add($n) }
        $same = ((ConvertTo-PimJobCpu $cur.Cpu) -eq (ConvertTo-PimJobCpu $size.Cpu) -and (ConvertTo-PimJobMemoryGi $cur.Memory) -eq (ConvertTo-PimJobMemoryGi $size.Memory) -and "$($cur.ReplicaTimeout)" -eq "$($size.ReplicaTimeout)")
        $tags = Get-PimTenantSizingTags -Counts $counts -Size $size -CountSource $countSrc -NowUtc $NowUtc
        if ($same) {
            # Unchanged: the tags are refreshed only when nothing is recorded yet, so the self-correct window ('pim-sizing-utc')
            # keeps meaning "since the job was last RESIZED" and old evidence is not counted twice.
            if (-not $rec.recorded -and $counts) { try { [void](Invoke-PimArmBusyRetry -Waits $BusyWaits -Sleep $Sleep -Write { & $Arm 'PATCH' "$path/providers/Microsoft.Resources/tags/default?api-version=2021-04-01" @{ operation = 'Merge'; properties = @{ tags = $tags } } }) } catch { $log.Add("tags not recorded: $($_.Exception.Message)") } }
            return [pscustomobject]@{ ok = $true; changed = $false; size = $size; selfCorrect = $sc
                detail = ("{0}: {1} CPU / {2}, replicaTimeout {3} s -- unchanged ({4}; counts: {5})" -f $JobName, $size.Cpu, $size.Memory, $size.ReplicaTimeout, $size.Source, $countSrc); log = @($log.ToArray()) }
        }
        # The PATCH body from a job object: its containers' resources + configuration.replicaTimeout, configuration WITHOUT its
        # secrets (a GET returns them without values, and sending them back would blank them).
        $sizeBody = {
            param($j)
            foreach ($c in @($j.properties.template.containers)) {
                if ($null -eq $c.resources) { $c | Add-Member -NotePropertyName resources -NotePropertyValue ([pscustomobject]@{}) -Force }
                $c.resources | Add-Member -NotePropertyName cpu -NotePropertyValue ([double](ConvertTo-PimJobCpu $size.Cpu)) -Force
                $c.resources | Add-Member -NotePropertyName memory -NotePropertyValue "$($size.Memory)" -Force
            }
            $cfg = [ordered]@{}
            foreach ($p in @($j.properties.configuration.PSObject.Properties)) { if ($p.Name -ne 'secrets') { $cfg[$p.Name] = $p.Value } }
            $cfg['replicaTimeout'] = [int]$size.ReplicaTimeout
            @{ properties = @{ configuration = $cfg; template = $j.properties.template } }
        }
        # 100.50: the tick was rolled one step earlier, so its provisioning is often still running -- wait it out, bounded.
        # After a wait the job is READ AGAIN: a template read before the roll finished must never be written back over it.
        $sizeTry = @{ n = 0 }
        [void](Invoke-PimArmBusyRetry -Waits $BusyWaits -Sleep $Sleep -Write {
            $sizeTry.n++
            $jw = $job; if ($sizeTry.n -gt 1) { $fresh = & $Arm 'GET' "$path`?api-version=$($script:PimTenantSizingAcaApi)" $null; if ($fresh) { $jw = $fresh } }
            & $Arm 'PATCH' "$path`?api-version=$($script:PimTenantSizingAcaApi)" (& $sizeBody $jw) })
        try { [void](Invoke-PimArmBusyRetry -Waits $BusyWaits -Sleep $Sleep -Write { & $Arm 'PATCH' "$path/providers/Microsoft.Resources/tags/default?api-version=2021-04-01" @{ operation = 'Merge'; properties = @{ tags = $tags } } }) } catch { $log.Add("tags not recorded: $($_.Exception.Message)") }
        return [pscustomobject]@{ ok = $true; changed = $true; size = $size; selfCorrect = $sc
            detail = ("{0}: {1} CPU / {2}, replicaTimeout {3} s -> {4} CPU / {5}, replicaTimeout {6} s ({7}; counts: {8})" -f $JobName, $cur.Cpu, $cur.Memory, $cur.ReplicaTimeout, $size.Cpu, $size.Memory, $size.ReplicaTimeout, $size.Source, $countSrc)
            log = @($log.ToArray()) }
    } catch {
        # 100.50: still busy after the bounded wait = a plain note, never "not sized: <ARM error>" and never a failed update.
        if ("$($_.Exception.Message)" -match '(?i)OperationInProgress|active provisioning operation') {
            return [pscustomobject]@{ ok = $false; changed = $false; busy = $true; size = $null; detail = "$jobWho was busy; sizing retried next update"; log = @($log.ToArray()) }
        }
        return [pscustomobject]@{ ok = $false; changed = $false; size = $null; detail = "$JobName not sized: $((("$($_.Exception.Message)") -split "`n")[0])"; log = @($log.ToArray()) }
    }
}

function Invoke-PimJobRunLimitUpdate {
    <#
      framework 12.24 JOB-RUN-LIMIT (owner 2026-10-15): EVERY PIM Container Apps job in this install's resource group gets
      Azure's maximum run limit ($script:PimJobRunLimitSeconds = 7 days) on every update -- the tick, the updater itself (its
      NEXT execution), pull / publish, db-init, support SQL, as-built. Raise only: a job already at the limit is not written.
      A job is PIM's when its name carries 'pim' (the install's own resource group; nothing else is touched).
      One PATCH per job: its configuration WITHOUT secrets (a GET returns them without values; sending them back would blank
      them) + its template as read, replicaTimeout set. Busy (OperationInProgress) is waited out, then left for the next
      update. Never throws. Returns @{ ok; changed[]; unchanged[]; failed[]; detail; log[] }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          [Parameter(Mandatory)][scriptblock]$Arm, [int[]]$BusyWaits = @(20, 20, 20, 20, 20, 20), [scriptblock]$Sleep)
    $limit = [int]$script:PimJobRunLimitSeconds
    $log = New-Object System.Collections.Generic.List[string]
    $changed = New-Object System.Collections.Generic.List[string]; $same = New-Object System.Collections.Generic.List[string]; $failed = New-Object System.Collections.Generic.List[string]
    $base = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/jobs"
    try { $list = & $Arm 'GET' "$base`?api-version=$($script:PimTenantSizingAcaApi)" $null }
    catch { return [pscustomobject]@{ ok = $false; changed = @(); unchanged = @(); failed = @(); detail = "run limit: the jobs could not be listed ($((("$($_.Exception.Message)") -split "`n")[0]))"; log = @() } }
    $jobs = @(@($list.value) | Where-Object { $_ -and "$($_.name)" -match '(?i)pim' })
    foreach ($j in $jobs) {
        $name = "$($j.name)"
        $cur = 0; [void][int]::TryParse("$($j.properties.configuration.replicaTimeout)", [ref]$cur)
        if ($cur -ge $limit) { $same.Add($name); continue }
        $path = "$base/$name`?api-version=$($script:PimTenantSizingAcaApi)"
        $body = {
            param($jo)
            $cfg = [ordered]@{}
            foreach ($p in @($jo.properties.configuration.PSObject.Properties)) { if ($p.Name -ne 'secrets') { $cfg[$p.Name] = $p.Value } }
            $cfg['replicaTimeout'] = $limit
            @{ properties = @{ configuration = $cfg; template = $jo.properties.template } }
        }
        $try = @{ n = 0 }
        try {
            [void](Invoke-PimArmBusyRetry -Waits $BusyWaits -Sleep $Sleep -Write {
                $try.n++
                # The full job is read for the write (a list item may be abridged), and read AGAIN after a busy wait.
                $jw = & $Arm 'GET' $path $null
                if (-not $jw) { throw "job '$name' not found" }
                & $Arm 'PATCH' $path (& $body $jw) })
            $changed.Add($name); $log.Add(("{0}: replicaTimeout {1} s -> {2} s" -f $name, $cur, $limit))
        } catch {
            $m = (("$($_.Exception.Message)") -split "`n")[0]
            $failed.Add($name)
            $log.Add($(if ($m -match '(?i)OperationInProgress|active provisioning operation') { "${name}: busy -- raised on the next update" } else { "${name}: not raised ($m)" }))
        }
    }
    $detail = ('run limit {0} s (7 days): {1} raised{2}, {3} already at it{4}' -f $limit, $changed.Count,
        $(if ($changed.Count) { " ($($changed -join ', '))" } else { '' }), $same.Count, $(if ($failed.Count) { "; NOT raised: $($failed -join ', ')" } else { '' }))
    return [pscustomobject]@{ ok = (-not $failed.Count); changed = @($changed.ToArray()); unchanged = @($same.ToArray()); failed = @($failed.ToArray()); detail = $detail; log = @($log.ToArray()) }
}

function Invoke-PimManagerAppSizeUpdate {
    <#
      The update's half of the Manager web app's size (framework 12.16 CONVERGE-DEFAULTS; PIM 100.114), for a run that did
      NOT roll the Manager (an environment ahead of its ring, or already on the target image). A run that DOES roll it
      carries the size in the roll's own write (Invoke-PimAcaRoll -Resize) -- this function then finds nothing to change.
      GET the app -> Get-PimManagerAppResize (raise only; the customer's PIM_Bootstrap_*_Manager wins) -> when the size
      changes: ONE PATCH of the whole template that came back (read-modify-write; every env var, probe and scale rule
      stays) with the app's tags + the sizing record, a busy app waited out (Invoke-PimArmBusyRetry; the app is read AGAIN
      after a wait), then the app READ BACK. A raise makes a new revision: the Manager restarts once.
      Never throws. Returns @{ ok; changed; detail; log[]; size }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup, [string]$AppName = 'ca-pim-manager',
          [string]$ContainerName, [Parameter(Mandatory)][scriptblock]$Arm, [hashtable]$Environment = @{}, [datetime]$NowUtc = [datetime]::UtcNow,
          [int[]]$BusyWaits = @(20, 20, 20, 20, 20, 20), [scriptblock]$Sleep, [int]$ReadBackAttempts = 6, [int]$ReadBackDelaySec = 10)
    $log = New-Object System.Collections.Generic.List[string]
    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.App/containerApps/$AppName"
    $api = $script:PimTenantSizingAcaApi; if (-not $api) { $api = '2024-03-01' }
    $pick = {
        param($a)
        $cs = @($a.properties.template.containers)
        if ("$ContainerName".Trim()) { return (@($cs | Where-Object { "$($_.name)" -eq "$ContainerName".Trim() }) | Select-Object -First 1) }
        if ($cs.Count -eq 1) { return $cs[0] }
        return $null
    }
    try {
        $app = & $Arm 'GET' "$path`?api-version=$api" $null
        if (-not $app) { return [pscustomobject]@{ ok = $false; changed = $false; size = $null; detail = "the Manager web app '$AppName' was not found -- its size was not checked"; log = @() } }
        $target = & $pick $app
        if (-not $target) { return [pscustomobject]@{ ok = $false; changed = $false; size = $null; detail = "the Manager web app '$AppName' has $(@($app.properties.template.containers).Count) containers and none was named -- its size was not changed"; log = @() } }
        $rz = Get-PimManagerAppResize -Container $target -App $app -Environment $Environment -NowUtc $NowUtc
        foreach ($n in @($rz.notes)) { $log.Add($n) }
        if (-not $rz.change) { return [pscustomobject]@{ ok = $true; changed = $false; size = $rz.size; detail = "$($rz.detail)"; log = @($log.ToArray()) } }
        $mgrTry = @{ n = 0 }
        [void](Invoke-PimArmBusyRetry -Waits $BusyWaits -Sleep $Sleep -Write {
            $mgrTry.n++
            $aw = $app
            if ($mgrTry.n -gt 1) { $fresh = & $Arm 'GET' "$path`?api-version=$api" $null; if ($fresh) { $aw = $fresh } }
            $tw = & $pick $aw
            $rw = Get-PimManagerAppResize -Container $tw -App $aw -Environment $Environment -NowUtc $NowUtc
            if (-not $rw.change) { return $null }     # someone else sized it while this run waited
            if ($null -eq $tw.resources) { $tw | Add-Member -NotePropertyName resources -NotePropertyValue ([pscustomobject]@{}) -Force }
            $tw.resources | Add-Member -NotePropertyName cpu -NotePropertyValue ([double](ConvertTo-PimJobCpu $rw.Cpu)) -Force
            $tw.resources | Add-Member -NotePropertyName memory -NotePropertyValue "$($rw.Memory)" -Force
            $body = @{ properties = @{ template = $aw.properties.template } }
            if ($rw.Tags) { $body['tags'] = $rw.Tags }
            & $Arm 'PATCH' "$path`?api-version=$api" $body })
        # read back: the size the app declares now (a GET right after the PATCH answers the new template at once)
        $backCpu = $null; $backMem = $null
        for ($ra = 1; $ra -le [Math]::Max(1, $ReadBackAttempts); $ra++) {
            try {
                $b = & $Arm 'GET' "$path`?api-version=$api" $null
                $bt = & $pick $b
                if ($bt -and $bt.resources) { $backCpu = ConvertTo-PimJobCpu $bt.resources.cpu; $backMem = ConvertTo-PimJobMemoryGi $bt.resources.memory }
                if ($null -ne $backCpu -and $null -ne $backMem) { break }
            } catch { }
            if ($ra -lt $ReadBackAttempts -and $ReadBackDelaySec -gt 0) { Start-Sleep -Seconds $ReadBackDelaySec }
        }
        $okBack = ($null -ne $backCpu -and $null -ne $backMem -and $backCpu -eq (ConvertTo-PimJobCpu $rz.Cpu) -and $backMem -eq (ConvertTo-PimJobMemoryGi $rz.Memory))
        return [pscustomobject]@{ ok = [bool]$okBack; changed = $true; size = $rz.size; log = @($log.ToArray())
            detail = ("{0} -- one write; it restarts once{1}" -f $rz.detail, $(if ($okBack) { '; read back' } else { ' -- the size did NOT read back; the next update tries again' })) }
    } catch {
        if ("$($_.Exception.Message)" -match '(?i)OperationInProgress|active provisioning operation') {
            return [pscustomobject]@{ ok = $false; changed = $false; busy = $true; size = $null; detail = 'the Manager web app was busy; its size is set by the next update'; log = @($log.ToArray()) }
        }
        return [pscustomobject]@{ ok = $false; changed = $false; size = $null; detail = "the Manager web app's size was not checked: $((("$($_.Exception.Message)") -split "`n")[0])"; log = @($log.ToArray()) }
    }
}

function Invoke-PimSqlTierUpdate {
    <#
      The update's half of the database rules, on EVERY update: read the main database over ARM and apply Get-PimSqlTierPlan
      -- below S3 -> S3 (raise only; owner 2026-10-12; never on a database tagged 'pim-sql-tier-pin') and the 250 GB max size
      of every Standard database (100.37): ONE PATCH carrying the sku and/or properties.maxSizeBytes, then the database read
      back and the max size before/after logged. A database PINNED below the default is not changed and is REPORTED:
      pinnedBelowDefault = $true and the detail starts "database is pinned at <tier>, the new default is S3 - not changed".
      -Server is the FQDN or name (searched in the subscription). -Pro is ignored. Never throws.
      Returns @{ ok; changed; detail; maxSizeBefore; maxSizeAfter; pinnedBelowDefault; tierBefore; tierAfter }.
    #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][AllowEmptyString()][string]$Server, [string]$Database = 'PimPlatform',
          [bool]$Pro, [Parameter(Mandatory)][scriptblock]$Arm, [int]$ReadBackAttempts = 6, [int]$ReadBackDelaySec = 10)
    $name =("$Server".Trim() -replace '^tcp:', '' -replace ',\d+$', '').Split('.')[0].ToLowerInvariant()
    if (-not $name) { return [pscustomobject]@{ ok = $false; changed = $false; detail = 'no SQL server name -- database size not checked' } }
    try {
        $list = & $Arm 'GET' "/subscriptions/$SubscriptionId/providers/Microsoft.Sql/servers?api-version=$($script:PimTenantSizingSqlApi)" $null
        $srv = @(@($list.value) | Where-Object { "$($_.name)".ToLowerInvariant() -eq $name }) | Select-Object -First 1
        if (-not $srv) { return [pscustomobject]@{ ok = $false; changed = $false; detail = "SQL server '$name' is not visible to the updater -- database size not checked" } }
        $dbPath = "$($srv.id)/databases/$Database"
        $db = & $Arm 'GET' "$dbPath`?api-version=$($script:PimTenantSizingSqlApi)" $null
        $curSo = Resolve-PimSqlServiceObjective -Database $db
        $pin = $null
        if ($db.tags) { if ($db.tags -is [System.Collections.IDictionary]) { if ($db.tags.Contains('pim-sql-tier-pin')) { $pin = "$($db.tags['pim-sql-tier-pin'])" } } elseif ($db.tags.PSObject.Properties['pim-sql-tier-pin']) { $pin = "$($db.tags.'pim-sql-tier-pin')" } }
        $plan = Get-PimSqlTierPlan -Current $curSo -ElasticPool "$($db.properties.elasticPoolId)" -CurrentMaxSizeBytes $db.properties.maxSizeBytes -Pin $pin
        $before = $plan.currentMaxSizeBytes
        # A pin below the default: never overridden, said in the owner's words so support can act (the tag cannot say who pinned it).
        $pinLow = [bool]$plan.pinnedBelowDefault
        $what = $(if ($pinLow) { "$($plan.pinNote) (database $Database, tag pim-sql-tier-pin = '$pin'; to move it: Set-PimSqlTier.ps1 -Tier $($plan.defaultTier) -Pin)" } else { "database $Database`: $($plan.reason)" })
        if ($plan.action -ne 'raise' -and $plan.maxSizeAction -ne 'set') { return [pscustomobject]@{ ok = $true; changed = $false; detail = $what; maxSizeBefore = $before; maxSizeAfter = $before; pinnedBelowDefault = $pinLow; tierBefore = $curSo; tierAfter = $curSo } }
        $body = @{}
        if ($plan.action -eq 'raise') { $body['sku'] = @{ name = $plan.target; tier = 'Standard' } }
        if ($plan.maxSizeAction -eq 'set') { $body['properties'] = @{ maxSizeBytes = [int64]$plan.maxSizeBytes } }
        [void](& $Arm 'PATCH' "$dbPath`?api-version=$($script:PimTenantSizingSqlApi)" $body)
        # read back: the max size before -> after (a tier change is online and can take minutes; the max size is immediate).
        # A GET right after a tier PATCH can answer 404 ResourceNotFound for a few seconds while the scale runs (measured
        # live 2026-10-09) -- transient: retried -ReadBackAttempts times, -ReadBackDelaySec apart.
        $after = $null; $tierAfter = ''
        for ($ra = 1; $ra -le [Math]::Max(1, $ReadBackAttempts); $ra++) {
            try {
                $db2 = & $Arm 'GET' "$dbPath`?api-version=$($script:PimTenantSizingSqlApi)" $null
                $t2 = 0L; if ($db2 -and [int64]::TryParse("$($db2.properties.maxSizeBytes)", [ref]$t2)) { $after = $t2 }
                if ($db2) { $tierAfter = Resolve-PimSqlServiceObjective -Database $db2 }
                break
            } catch {
                if ("$($_.Exception.Message)" -notmatch '(?i)\b404\b|ResourceNotFound|NotFound') { break }
                if ($ra -lt $ReadBackAttempts -and $ReadBackDelaySec -gt 0) { Start-Sleep -Seconds $ReadBackDelaySec }
            }
        }
        $fmt = { param($b) if ($null -eq $b) { 'unknown' } else { '{0:N0} GB' -f ($b / 1GB) } }
        $ms = " (max size {0} -> {1}, read back)" -f (& $fmt $before), (& $fmt $after)
        $okMax = ($plan.maxSizeAction -ne 'set' -or ($null -ne $after -and $after -ge [int64]$plan.maxSizeBytes))
        return [pscustomobject]@{ ok = $okMax; changed = $true; maxSizeBefore = $before; maxSizeAfter = $after; pinnedBelowDefault = $pinLow; tierBefore = $curSo; tierAfter = $tierAfter
            detail = "$what$ms$(if ($plan.action -eq 'raise') { " (tier change online; takes effect in minutes$(if ($tierAfter) { "; the database reads $tierAfter now" }))" })$(if (-not $okMax) { ' -- the max size did NOT read back as 250 GB; the next update tries again' })" }
    } catch {
        return [pscustomobject]@{ ok = $false; changed = $false; detail = "database size not checked: $((("$($_.Exception.Message)") -split "`n")[0])" }
    }
}
