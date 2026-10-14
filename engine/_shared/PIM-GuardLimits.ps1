#Requires -Version 5.1
<#
.SYNOPSIS
  PIM 100.119 (owner 2026-10-13: "drop the percentage in the guards and focus alone on amounts like 5" / "Approved,
  SuperAdmin sets them"): THE LIMIT OF A GUARD. Counts only -- there is no percentage in any guard's rule.

.DESCRIPTION
  Five guards have a limit a SuperAdmin can set on Operations > Guards, each inside a FLOOR and a CEILING that are
  literals in this file (Get-PimGuardLimitCatalog) and are stated on the page (CODE REVIEW 2, 2026-10-13, added
  manager.bulk-revoke 1..5..25 and engine.admin-delete 1..5..25):

    manager.commit-removal   rows of ONE list removed in ONE commit before a SuperAdmin must approve   5 .. 25 .. 200
    engine.remove-budget     removals in one scope in one engine run before the run holds them          1 ..  5 ..  25
    engine.disable-guard     accounts disabled in one engine run before the run holds them              1 ..  3 ..  25
                             (the default is 3 since the owner's decision of 2026-10-13, after the review; it was 5)

  The value lives in the SQL store: pim.Settings 'GuardLimits' = { limits: { <guardId>: { value, by, atUtc } } }.
  The code that owns a guard asks Get-PimGuardLimit. What it returns is ALWAYS a number inside floor..ceiling:
    * nothing stored                      -> the default
    * a stored value outside floor..ceiling, not a whole number, or a setting that cannot be parsed -> the default
    * the store cannot be read            -> the default
  It never returns "no limit", and no guard can be switched off here: there is no such value.

  Every number is a literal returned by a function -- never a $script: variable (a $script: variable is $null in a child
  script scope behind a Get-Command load guard, and "-gt $null" is TRUE: BUG-79-6b).

  Test seam: $global:PIM_GuardReleaseStore = @{} (setting name -> JSON text) replaces SQL, as in PIM-GuardRelease.ps1.
#>

Set-StrictMode -Off

function Get-PimGuardLimitSettingName { 'GuardLimits' }

function Get-PimGuardLimitCatalog {
    <# PURE. LITERALS. One entry per guard that has a settable limit: floor, default, ceiling, the unit and why. #>
    @(
        [pscustomobject]@{ guardId = 'manager.commit-removal'; floor = 5; default = 25; ceiling = 200
            unit = 'rows of one list in one commit'
            why = 'Floor 5: lower and every routine clean-up of a few rows would need a SuperAdmin. Ceiling 200: higher and the check would never ask in a normal list; a commit that keeps none of a list''s rows, or only a few of them, always asks, whatever this number is.'
            bounds = @('rows taken out of one list in one commit (a commit, a restore from a backup, the departments save)') }
        # PIM 100.119 B5: ONE number, SEVEN actions -- every caller of Get-PimRemoveBudget / Test-PimRemoveBudgetAllowed. The
        # page, the confirmation and "More info" list them, so nobody raises it for one and gets the other six.
        [pscustomobject]@{ guardId = 'engine.remove-budget'; floor = 1; default = 5; ceiling = 25
            unit = 'removals per scope per run'
            why = 'Floor 1: 0 would stop every single removal, which is switching removal off and not a limit. Ceiling 25: more than that in one run is "many" (the commit check asks from 25); a larger removal goes through the approval of its exact list, which has no ceiling.'
            bounds = @(
                'removals a row asks for (Action = Remove), per kind of assignment'
                'the clean-up of leftovers PIM Manager manages (a full run with prune)'
                'removals by the daily reconcile, where it is set to enforce'
                'groups deleted because their definition is marked Retire'
                'groups deleted from the change queue (a DELETE chosen on the Drift page)'
                'admin accounts offboarded in one run (disabled, memberships removed)'
                'in a managed tenant: central admins the managing tenant withdraws in one pull') }
        [pscustomobject]@{ guardId = 'engine.disable-guard'; floor = 1; default = 3; ceiling = 25
            unit = 'accounts per run'
            why = 'Floor 1: 0 would stop every disable, including the one a row asks for. Ceiling 25: a real offboarding is a handful of accounts; a larger one is released for exactly its list of accounts, which has no ceiling.'
            bounds = @(
                'admin accounts disabled because their row says so (AccountStatus, a passed disable date)'
                'admin accounts disabled by an offboarding in one run'
                'admin accounts disabled by the inactivity sweep, where it is set to enforce') }
        # CODE REVIEW 2 FIXES 2026-10-13 (lane review2, owner decision 60): the bulk revoke's two checks -- the typed
        # count and the approval -- read ONE number, set here. It used to be the literal 5 in two places and a $global:
        # knob that could RAISE it without a ceiling.
        [pscustomobject]@{ guardId = 'manager.bulk-revoke'; floor = 1; default = 5; ceiling = 25
            unit = 'assignments revoked in one batch'
            why = 'Floor 1: 0 would ask for an approval of every single revoke. Ceiling 25: more than that in one batch is "many"; a larger batch is approved on the Approvals page by a person with permission over every assignment in it, or a SuperAdmin.'
            bounds = @(
                'the count of assignments a bulk revoke must be confirmed with (typed by the person who revokes)'
                'the size of a bulk revoke above which it needs an approved request on the Approvals page') }
        # CODE REVIEW 2 FIXES 2026-10-13 (lane review2, owner decision 60): admin ACCOUNT deletes per engine run (the
        # operator's Delete account, AccountStatus = Deleted). It was $script:PimAdminDeleteMaxPerRun = 5.
        [pscustomobject]@{ guardId = 'engine.admin-delete'; floor = 1; default = 5; ceiling = 25
            unit = 'account deletes per run'
            why = 'Floor 1: 0 would stop every account delete the operator asked for. Ceiling 25: an account delete cannot be undone by the next run (Entra keeps it restorable for 30 days); more than that in one run waits for the next run.'
            bounds = @('admin accounts deleted in one engine run because their row says AccountStatus = Deleted (the rest wait for the next run)') }
    )
}

function Get-PimGuardLimitKnob {
    <#
      PURE. LITERAL. The SERVER SETTING that may LOWER a guard's limit in one process ($global:<name>, then the process
      environment when env = $true), or $null when the guard has none (CODE REVIEW 2, owner decision 59: "Show it, keep 0
      possible" -- a server setting only lowers a limit, 0 stops every one, and the Guards page shows the EFFECTIVE number
      and why). Nothing here can raise a limit.
    #>
    param([string]$GuardId)
    switch ("$GuardId".Trim().ToLowerInvariant()) {
        'engine.remove-budget'   { return @{ name = 'PIM_RemoveMaxCount'; env = $true } }
        'engine.disable-guard'   { return @{ name = 'PIM_DisableMaxCount'; env = $true } }
        'manager.commit-removal' { return @{ name = 'PIM_CommitMaxRemoveAbs'; env = $false } }
        'manager.bulk-revoke'    { return @{ name = 'PIM_RevokeApprovalThreshold'; env = $false } }
    }
    return $null
}

function Get-PimGuardEffectiveLimit {
    <#
      The number a guard USES right now in THIS process, and why. NEVER throws. $null when the guard has no limit.
        @{ guardId; stored (the Guards-page value or the default); effective; knob; knobValue; lowered; ignored; note }
      * the server setting (Get-PimGuardLimitKnob) is a whole number below the stored value -> effective = that number,
        0 included (0 = nothing gets through; a full stop stays possible -- owner decision 59);
      * a negative number counts as 0 (the stricter reading);
      * at or above the stored value, or not a number -> ignored (a server setting can never raise a limit), said in note.
    #>
    param([Parameter(Mandatory)][string]$GuardId, [switch]$Fresh)
    $st = $null
    try { $st = Get-PimGuardLimitState -GuardId $GuardId -Fresh:$Fresh } catch { $st = $null }
    if ($null -eq $st) { return $null }
    $stored = [int](Get-PimGuardLimit -GuardId $GuardId -Fallback ([int]$st.default))
    $o = [ordered]@{ guardId = "$($st.guardId)"; stored = $stored; effective = $stored; knob = ''; knobValue = ''; lowered = $false; ignored = $false; note = '' }
    $k = Get-PimGuardLimitKnob -GuardId $GuardId
    if (-not $k) { return (Add-PimGuardStrictToEffective -Effective $o) }
    $o.knob = "$($k.name)"
    $v = Get-Variable -Name $k.name -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    # The process environment is read by the ONE knob reader of the engine (Get-PimSafetyKnob, PIM-DisableGuard.ps1) -- never
    # here: this file decides limits and approvals, and nothing in it reads an environment variable (H34).
    if (($null -eq $v -or "$v".Trim() -eq '') -and $k.env -and (Get-Command Get-PimSafetyKnob -ErrorAction SilentlyContinue)) { $v = Get-PimSafetyKnob -Name "$($k.name)" }
    if ($null -eq $v -or "$v".Trim() -eq '') { return (Add-PimGuardStrictToEffective -Effective $o) }
    $o.knobValue = "$v".Trim()
    $n = 0
    if (-not [int]::TryParse("$v".Trim(), [ref]$n)) {
        $o.ignored = $true; $o.note = ("the server setting {0}='{1}' is not a whole number -- ignored, {2} applies" -f $k.name, $o.knobValue, $stored)
        return (Add-PimGuardStrictToEffective -Effective $o)
    }
    if ($n -lt 0) { $n = 0 }
    if ($n -lt $stored) {
        $o.effective = $n; $o.lowered = $true
        $o.note = $(if ($n -eq 0) { "the server setting $($k.name)=0 stops every one of them in this process (a server setting can only lower the limit of $stored)" }
                    else { "lowered to $n by the server setting $($k.name) in this process (a server setting can only lower the limit of $stored)" })
    } elseif ($n -gt $stored) {
        $o.ignored = $true; $o.note = ("the server setting {0}={1} is above the limit of {2} -- ignored: a server setting can only lower a limit; a SuperAdmin raises it here" -f $k.name, $n, $stored)
    }
    return (Add-PimGuardStrictToEffective -Effective $o)
}

# =====================================================================================================================
# GUARD-STRICT -- framework DOCS/REQUIREMENTS.md §12.11b (CR4, owner + Thomas approved 2026-10-14; PIM REQUIREMENTS
# 100.144): for 24 h after a release that changed ENGINE code, every guard with a number uses HALF its configured value:
# effective = max(1, floor(configured x 0.5)). It never raises anything, never lowers what a SuperAdmin approved for one
# run (an approval / release exempts its exact items and never reads the limit), and a SuperAdmin may end it early with a
# reason (audited). pim.Settings 'GuardStrict' = { sinceUtc; untilUtc; version; fingerprint; previousFingerprint;
# endedBy; endedUtc; endedReason }. It STARTS only when the ENGINE JOB itself sees its engine code change (pim.Settings
# 'EngineFingerprint', Update-PimGuardStrictFromEngine): an install with no stored fingerprint only records it -- no
# customer goes Strict because this feature arrives, and an older version never reads any of it.
# =====================================================================================================================
function Get-PimGuardStrictSettingName { 'GuardStrict' }
function Get-PimEngineFingerprintSettingName { 'EngineFingerprint' }
function Get-PimGuardStrictHours { 24 }

function Get-PimGuardStrictGuardIds {
    # PURE. LITERAL. The guards with a number that Strict halves (the hybrid server batch is halved by its own reader,
    # Get-PimHybridAdServerDiscoverySettings; the policy breaker holds every change set already; the MSP central delete is 1).
    return @('manager.commit-removal', 'engine.remove-budget', 'engine.disable-guard', 'manager.bulk-revoke', 'engine.admin-delete')
}

function Get-PimGuardStrictHalf {
    # PURE. The strict number of a configured limit: max(1, floor(configured x 0.5)). A limit of 1 stays 1; 0 stays 0 (a
    # server setting that stops everything is never raised).
    param([int]$Configured)
    if ($Configured -le 0) { return 0 }
    return [int][Math]::Max(1, [Math]::Floor($Configured * 0.5))
}

function ConvertFrom-PimGuardStrictText {
    <# PURE. The stored 'GuardStrict' text -> @{ known; sinceUtc; untilUtc; version; endedBy; endedUtc; endedReason } (dates as
       UTC [datetime] or $null). Text that is not JSON -> known = $false. #>
    param([AllowNull()][string]$Text)
    $o = @{ known = $false; sinceUtc = $null; untilUtc = $null; version = ''; endedBy = ''; endedUtc = $null; endedReason = ''; fingerprint = '' }
    if ($null -eq $Text -or "$Text".Trim() -eq '') { $o.known = $true; return $o }
    $j = $null; try { $j = "$Text" | ConvertFrom-Json } catch { return $o }
    if ($j -is [string]) { try { $j = $j | ConvertFrom-Json } catch { return $o } }
    if ($null -eq $j) { $o.known = $true; return $o }
    $d = { param($v) if ($null -eq $v -or "$v".Trim() -eq '') { return $null }; if ($v -is [datetime]) { return $v.ToUniversalTime() }; try { return ([datetimeoffset]::Parse("$v", [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime } catch { return $null } }
    $o.known = $true
    $o.sinceUtc = & $d $j.sinceUtc; $o.untilUtc = & $d $j.untilUtc; $o.endedUtc = & $d $j.endedUtc
    $o.version = "$($j.version)".Trim(); $o.endedBy = "$($j.endedBy)".Trim(); $o.endedReason = "$($j.endedReason)".Trim(); $o.fingerprint = "$($j.fingerprint)".Trim()
    return $o
}

function Test-PimGuardStrictActive {
    # PURE. Strict is active when it started, has not reached its end and was not ended early.
    param([AllowNull()]$State, [datetime]$NowUtc = [datetime]::UtcNow)
    if ($null -eq $State -or -not $State.known -or $null -eq $State.sinceUtc -or $null -eq $State.untilUtc) { return $false }
    if ($null -ne $State.endedUtc) { return $false }
    $n = $NowUtc.ToUniversalTime()
    return ($n -ge $State.sinceUtc -and $n -lt $State.untilUtc)
}

function Get-PimGuardSettingText {
    # The stored JSON text of one guard setting (same store + seam as 'GuardLimits'), or $null. THROWS when a store fails.
    param([Parameter(Mandatory)][string]$Name)
    if ($global:PIM_GuardReleaseStore -is [hashtable]) { $v = $global:PIM_GuardReleaseStore[$Name]; if ($null -eq $v) { return $null }; return "$v" }
    $cs = Get-PimGuardLimitStoreCs
    if ($cs -and (Get-Command Get-PimSqlSettingRaw -ErrorAction SilentlyContinue)) { return (Get-PimSqlSettingRaw -ConnectionString $cs -Name $Name) }
    return $null
}

function Set-PimGuardSettingText {
    # Write one guard setting ONLY IF its stored text is still -Expected (compare-and-set). 1 = written, 0 = lost the race.
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Json, [AllowNull()][string]$Expected)
    if ($global:PIM_GuardReleaseStore -is [hashtable]) {
        if ("$($global:PIM_GuardReleaseStore[$Name])" -cne "$Expected") { return 0 }
        $global:PIM_GuardReleaseStore[$Name] = $Json; return 1
    }
    $cs = Get-PimGuardLimitStoreCs
    if (-not $cs -or -not (Get-Command Set-PimSqlSettingIfUnchanged -ErrorAction SilentlyContinue)) { throw 'REFUSED -- there is no settings store. Nothing was changed.' }
    return [int](Set-PimSqlSettingIfUnchanged -ConnectionString $cs -Name $Name -NewValueJson $Json -ExpectedValueJson $Expected)
}

function Get-PimGuardStrictState {
    <#
      Strict mode NOW in this process. NEVER throws. Cached 30 s (like the limits); -Fresh reads again.
        @{ active; sinceUtc; untilUtc; version; endedBy; endedUtc; endedReason; readError }
      A store that cannot be read = NOT active (said in readError): the configured limits apply, as before CR4.
    #>
    param([switch]$Fresh, [datetime]$NowUtc = [datetime]::UtcNow)
    $st = $null
    if (-not ($global:PIM_GuardReleaseStore -is [hashtable]) -and -not $Fresh) {
        $c = $global:PIM_GuardStrictCache
        if ($c -is [hashtable] -and $c['at'] -is [datetime] -and ([datetime]::UtcNow - $c['at']).TotalSeconds -lt 30) { $st = $c['state'] }
    }
    $err = ''
    if ($null -eq $st) {
        try { $st = ConvertFrom-PimGuardStrictText -Text (Get-PimGuardSettingText -Name (Get-PimGuardStrictSettingName)) }
        catch { $st = @{ known = $false }; $err = "the guard mode could not be read ($($_.Exception.Message))" }
        if (-not ($global:PIM_GuardReleaseStore -is [hashtable])) { $global:PIM_GuardStrictCache = @{ at = [datetime]::UtcNow; state = $st } }
    }
    return [pscustomobject]@{
        active = (Test-PimGuardStrictActive -State $st -NowUtc $NowUtc)
        sinceUtc = $(if ($st.sinceUtc) { $st.sinceUtc.ToString('o') } else { '' }); untilUtc = $(if ($st.untilUtc) { $st.untilUtc.ToString('o') } else { '' })
        version = "$($st.version)"; endedBy = "$($st.endedBy)"; endedUtc = $(if ($st.endedUtc) { $st.endedUtc.ToString('o') } else { '' }); endedReason = "$($st.endedReason)"
        readError = $err
    }
}

function Get-PimGuardStrictNote {
    # PURE. The calm words for a strict limit: "Strict after the update to 2.4.630 until 2026-10-15 17:33 UTC: half of the
    # configured 5".
    param([int]$Configured, [int]$Effective, [string]$Version = '', [string]$UntilUtc = '')
    $u = ''; try { if ("$UntilUtc".Trim()) { $u = ([datetimeoffset]::Parse("$UntilUtc", [Globalization.CultureInfo]::InvariantCulture)).UtcDateTime.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC' } } catch { $u = '' }
    return ("Strict for 24 hours after the update{0}{1}: {2} instead of the configured {3}" -f $(if ($Version) { " to $Version" } else { '' }), $(if ($u) { ", until $u" } else { '' }), $Effective, $Configured)
}

function Get-PimEngineCodeFingerprint {
    <#
      The SHA-256 of THIS install's engine code: "<relative path> <file SHA-256>" of every file under engine/,
      tools/pim-engine, tools/pim-scheduler and sql/ (the same folders the publish call's engineChanged compares), sorted.
      '' when the folders cannot be read (then nothing is decided).
    #>
    param([Parameter(Mandatory)][string]$SolutionRoot)
    try {
        $lines = New-Object System.Collections.Generic.List[string]
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            foreach ($d in 'engine', 'tools/pim-engine', 'tools/pim-scheduler', 'sql') {
                $p = Join-Path $SolutionRoot $d
                if (-not (Test-Path -LiteralPath $p)) { continue }
                foreach ($f in @(Get-ChildItem -LiteralPath $p -Recurse -File -ErrorAction Stop)) {
                    $rel = $f.FullName.Substring($SolutionRoot.TrimEnd('\', '/').Length).TrimStart('\', '/') -replace '\\', '/'
                    $h = -join ($sha.ComputeHash([IO.File]::ReadAllBytes($f.FullName)) | ForEach-Object { $_.ToString('x2') })
                    $lines.Add("$rel $h")
                }
            }
            if (-not $lines.Count) { return '' }
            $all = (@($lines.ToArray()) | Sort-Object -CaseSensitive) -join "`n"
            return (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($all)) | ForEach-Object { $_.ToString('x2') }))
        } finally { $sha.Dispose() }
    } catch { return '' }
}

function Get-PimGuardStrictStartPlan {
    <#
      PURE. What the engine job does with its fingerprint: @{ action = record | none | strict; reason; fingerprint }.
        nothing stored                 -> record (the first run with this feature: NOT strict -- no customer goes Strict
                                          because CR4 arrives)
        the same fingerprint           -> none
        a different fingerprint        -> strict (the engine code changed: 24 h Strict) + record
    #>
    param([AllowNull()][string]$Current, [AllowNull()][string]$StoredText)
    $cur = "$Current".Trim().ToLowerInvariant()
    if (-not $cur) { return @{ action = 'none'; reason = 'the engine code could not be read'; previous = '' } }
    $prev = ''
    if ("$StoredText".Trim()) { try { $j = "$StoredText" | ConvertFrom-Json; if ($j -is [string]) { $j = $j | ConvertFrom-Json }; $prev = "$($j.fingerprint)".Trim().ToLowerInvariant() } catch { $prev = '' } }
    if (-not $prev) { return @{ action = 'record'; reason = 'first fingerprint of this install -- recorded, not strict'; previous = '' } }
    if ($prev -eq $cur) { return @{ action = 'none'; reason = 'the engine code is unchanged'; previous = $prev } }
    return @{ action = 'strict'; reason = 'the engine code changed'; previous = $prev }
}

function Update-PimGuardStrictFromEngine {
    <#
      Run by the ENGINE JOB once per execution (Start-PimScheduler, the container's tick only -- never the hybrid worker,
      whose code is updated separately and would flip the record). NEVER throws. Returns @{ action; reason }.
      'strict' writes GuardStrict { sinceUtc = now; untilUtc = now + 24 h; version; fingerprint; previousFingerprint } --
      compare-and-set on EngineFingerprint first, so two executions seeing the same change start it once.
    #>
    param([Parameter(Mandatory)][string]$SolutionRoot, [string]$Version = '', [datetime]$NowUtc = [datetime]::UtcNow, [string]$Fingerprint = '')
    try {
        $fp = if ("$Fingerprint".Trim()) { "$Fingerprint".Trim().ToLowerInvariant() } else { Get-PimEngineCodeFingerprint -SolutionRoot $SolutionRoot }
        $fpName = Get-PimEngineFingerprintSettingName
        $storedText = Get-PimGuardSettingText -Name $fpName
        $plan = Get-PimGuardStrictStartPlan -Current $fp -StoredText $storedText
        if ($plan.action -eq 'none') { return @{ action = 'none'; reason = $plan.reason } }
        $now = $NowUtc.ToUniversalTime()
        $fpJson = ([pscustomobject]@{ fingerprint = $fp; version = "$Version"; recordedUtc = $now.ToString('o') } | ConvertTo-Json -Compress)
        if ((Set-PimGuardSettingText -Name $fpName -Json $fpJson -Expected $storedText) -ne 1) { return @{ action = 'none'; reason = 'another execution recorded the fingerprint first' } }
        if ($plan.action -eq 'record') { return @{ action = 'record'; reason = $plan.reason } }
        $sName = Get-PimGuardStrictSettingName
        $sPrev = Get-PimGuardSettingText -Name $sName
        $rec = [pscustomobject]@{ sinceUtc = $now.ToString('o'); untilUtc = $now.AddHours((Get-PimGuardStrictHours)).ToString('o'); version = "$Version"
                                  fingerprint = $fp; previousFingerprint = "$($plan.previous)"; endedBy = ''; endedUtc = ''; endedReason = '' }
        [void](Set-PimGuardSettingText -Name $sName -Json ($rec | ConvertTo-Json -Compress) -Expected $sPrev)
        $global:PIM_GuardStrictCache = $null
        if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) { try { Write-PimAuditEvent -Action 'guard.strict.start' -Target 'guards' -After $rec -Result 'ok' } catch { } }
        return @{ action = 'strict'; reason = "the engine code changed -- every guard with a number uses half its limit until $($rec.untilUtc)" }
    } catch { return @{ action = 'none'; reason = "the guard mode was not checked: $($_.Exception.Message)" } }
}

function Stop-PimGuardStrict {
    <#
      A SuperAdmin ends Strict early, with a reason of at least 10 characters (framework §12.11b item 3). Audited.
      Returns @{ ok; status (200 / 400 / 403 / 409); error; state }.
    #>
    param([Parameter(Mandatory)][string]$By, [AllowNull()][string]$Role, [AllowNull()][string]$Reason, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not (Test-PimGuardSuperAdminRole -Role $Role)) { return @{ ok = $false; status = 403; error = 'Only a SuperAdmin ends Strict mode early.' } }
    $why = "$Reason".Trim()
    if ($why.Length -lt 10) { return @{ ok = $false; status = 400; error = 'Say why Strict mode ends early (at least 10 characters) -- it is recorded.' } }
    $name = Get-PimGuardStrictSettingName
    $text = Get-PimGuardSettingText -Name $name
    $st = ConvertFrom-PimGuardStrictText -Text $text
    if (-not (Test-PimGuardStrictActive -State $st -NowUtc $NowUtc)) { return @{ ok = $false; status = 409; error = 'Strict mode is not active.' } }
    $j = "$text" | ConvertFrom-Json; if ($j -is [string]) { $j = $j | ConvertFrom-Json }
    $j | Add-Member -NotePropertyName endedBy -NotePropertyValue "$By" -Force
    $j | Add-Member -NotePropertyName endedUtc -NotePropertyValue $NowUtc.ToUniversalTime().ToString('o') -Force
    $j | Add-Member -NotePropertyName endedReason -NotePropertyValue $why -Force
    if ((Set-PimGuardSettingText -Name $name -Json ($j | ConvertTo-Json -Compress) -Expected $text) -ne 1) { return @{ ok = $false; status = 409; error = 'The guard mode changed meanwhile -- reload and try again.' } }
    $global:PIM_GuardStrictCache = $null
    if (Get-Command Write-PimAuditEvent -ErrorAction SilentlyContinue) { try { Write-PimAuditEvent -Action 'guard.strict.end' -Target 'guards' -Before $text -After $j -Result 'ok' -Actor $By } catch { } }
    return @{ ok = $true; status = 200; error = ''; state = (Get-PimGuardStrictState -Fresh -NowUtc $NowUtc) }
}

function Add-PimGuardStrictToEffective {
    <#
      The last step of Get-PimGuardEffectiveLimit: while Strict is active, a guard in Get-PimGuardStrictGuardIds uses half
      its CONFIGURED value (stored), or less when a server setting already lowered it further (the smaller wins -- Strict
      never raises). Adds strict / strictUntilUtc / strictVersion / configured; the note says it in calm words. NEVER throws.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Effective)
    $Effective['strict'] = $false; $Effective['strictUntilUtc'] = ''; $Effective['strictVersion'] = ''
    try {
        if ((Get-PimGuardStrictGuardIds) -contains "$($Effective['guardId'])".ToLowerInvariant()) {
            $s = Get-PimGuardStrictState
            if ($s.active) {
                $half = Get-PimGuardStrictHalf -Configured ([int]$Effective['stored'])
                if ($half -lt [int]$Effective['effective']) {
                    $Effective['effective'] = $half; $Effective['lowered'] = $true
                    $Effective['strict'] = $true; $Effective['strictUntilUtc'] = "$($s.untilUtc)"; $Effective['strictVersion'] = "$($s.version)"
                    $n = Get-PimGuardStrictNote -Configured ([int]$Effective['stored']) -Effective $half -Version "$($s.version)" -UntilUtc "$($s.untilUtc)"
                    $Effective['note'] = $(if ("$($Effective['note'])".Trim()) { "$n; $($Effective['note'])" } else { $n })
                }
            }
        }
    } catch { }
    return [pscustomobject]$Effective
}

function Get-PimGuardStrictTripText {
    <#
      The calm sentence a trip mail adds while Strict halved this guard's limit (framework §12.11b item 4: "a strict trip
      behaves like any trip ... worded calmly with strict + configured + effective"); '' when Strict did not lower it.
      Also @{ strict; configured; effective } for the trip record's Thresholds. NEVER throws.
    #>
    param([Parameter(Mandatory)][string]$GuardId)
    $out = @{ text = ''; strict = $false; configured = 0; effective = 0 }
    try {
        $e = Get-PimGuardEffectiveLimit -GuardId $GuardId
        if ($e -and $e.PSObject.Properties['strict'] -and $e.strict) {
            $out.strict = $true; $out.configured = [int]$e.stored; $out.effective = [int]$e.effective
            $out.text = ("Strict mode is on after a recent update: for 24 hours this limit is {0} instead of your configured {1}, so a larger change waits for a SuperAdmin or for Strict mode to end." -f $out.effective, $out.configured)
        }
    } catch { }
    return $out
}

function Get-PimBulkRevokeLimit {
    <# The bulk revoke's number (manager.bulk-revoke), effective in this process: the typed count AND the approval
       threshold. NEVER throws; the literal default 5 when the library cannot answer. #>
    try { $e = Get-PimGuardEffectiveLimit -GuardId 'manager.bulk-revoke'; if ($e) { return [int]$e.effective } } catch { }
    return 5
}

function Get-PimAdminDeleteLimit {
    <# Admin account deletes per engine run (engine.admin-delete), EFFECTIVE (CR4: half while Strict). NEVER throws; the
       literal default 5 on any failure. #>
    try { $e = Get-PimGuardEffectiveLimit -GuardId 'engine.admin-delete'; if ($e) { return [int]$e.effective } } catch { }
    try { return [int](Get-PimGuardLimit -GuardId 'engine.admin-delete' -Fallback 5) } catch { return 5 }
}

function Get-PimCommitGuardFewLeftRows {
    <# PURE. LITERAL, not settable. The commit removal check asks when a commit would leave THIS MANY rows or fewer of the
       rows a list has now (PIM 100.119 A1 (iii), owner 2026-10-13)... #>
    2
}

function Get-PimCommitGuardFewLeftMinList {
    <# PURE. LITERAL, not settable. ...in a list that has MORE than this many rows (so 2 of 3 removed does not ask). #>
    5
}

function Test-PimGuardSuperAdminRole {
    <#
      PURE. THE one answer to "is this role SuperAdmin" for every guard approval and every limit (PIM 100.119 B4). The SAME
      rule the Manager's route gate applies (Test-PimManagerRoleAtLeast ranks the role by name, whatever its case, and
      does not trim it): the role is the word SuperAdmin in any case -- nothing more, nothing less. 'superadmin' and
      'SUPERADMIN' are SuperAdmin (a tenant whose only SuperAdmin is stored in lower case must be able to approve);
      'Admin', '', 'SuperAdmin ' and a role that merely contains the word are not.
    #>
    param([AllowNull()][string]$Role)
    if ($null -eq $Role) { return $false }
    return [string]::Equals("$Role", 'SuperAdmin', [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-PimGuardSignedInSuperAdmin {
    <# PURE. A SuperAdmin WITH a signed-in identity: the role rule above, and an identity that is neither empty nor the
       unauthenticated placeholder. #>
    param([AllowNull()][string]$Role, [AllowNull()][string]$Identity)
    if (-not (Test-PimGuardSuperAdminRole -Role $Role)) { return $false }
    $i = "$Identity".Trim()
    return [bool]($i -and $i -ne '<unauthenticated>')
}

function Get-PimGuardLimitSpec {
    <# PURE. The catalog entry of one guard, or $null when that guard has no settable limit. #>
    param([string]$GuardId)
    $id = "$GuardId".Trim().ToLowerInvariant()
    if (-not $id) { return $null }
    foreach ($s in @(Get-PimGuardLimitCatalog)) { if ("$($s.guardId)" -eq $id) { return $s } }
    return $null
}

function Get-PimGuardLimitDefault {
    <# PURE. The default of one guard as a literal fallback; -Fallback when the guard has no limit entry. #>
    param([string]$GuardId, [int]$Fallback = 5)
    $s = Get-PimGuardLimitSpec -GuardId $GuardId
    if ($s) { return [int]$s.default }
    return [int]$Fallback
}

function Test-PimGuardLimitValue {
    <#
      PURE. May -Value be the limit of -GuardId? @{ ok; value; reason }. A whole number inside floor..ceiling of a guard
      that HAS a limit. A never-releasable guard, a guard without a limit and an unknown guard are refused: they have no
      number to set.
    #>
    param([string]$GuardId, [AllowNull()][object]$Value)
    $id = "$GuardId".Trim().ToLowerInvariant()
    if (-not $id) { return [pscustomobject]@{ ok = $false; value = $null; reason = 'no guard named' } }
    if ((Get-Command Get-PimGuardNeverReleasable -ErrorAction SilentlyContinue) -and ($id -in @(Get-PimGuardNeverReleasable))) {
        return [pscustomobject]@{ ok = $false; value = $null; reason = "the guard '$id' is LOCKED: it has no limit and can never be exempted or switched off" }
    }
    $s = Get-PimGuardLimitSpec -GuardId $id
    if (-not $s) { return [pscustomobject]@{ ok = $false; value = $null; reason = "the guard '$id' has no limit that can be set" } }
    if ($null -eq $Value -or $Value -is [bool]) { return [pscustomobject]@{ ok = $false; value = $null; reason = 'the limit must be a whole number' } }
    $t = "$Value".Trim()
    if ($t -notmatch '^\d{1,6}$') { return [pscustomobject]@{ ok = $false; value = $null; reason = "'$t' is not a whole number (a count; there is no percentage)" } }
    $n = [int]$t
    if ($n -lt [int]$s.floor -or $n -gt [int]$s.ceiling) {
        return [pscustomobject]@{ ok = $false; value = $null; reason = ("{0} is outside {1} to {2} ({3})" -f $n, $s.floor, $s.ceiling, $s.unit) }
    }
    return [pscustomobject]@{ ok = $true; value = $n; reason = '' }
}

# ------------------------------------------------------------------------------------------------------------------------
# Store access (pim.Settings). The reader THROWS only when a configured store fails; Get-PimGuardLimit never throws.
# ------------------------------------------------------------------------------------------------------------------------
function Get-PimGuardLimitStoreCs {
    try { if (Get-Command Get-PimManagerSettingCs -ErrorAction SilentlyContinue) { $c = Get-PimManagerSettingCs; if ("$c".Trim()) { return "$c" } } } catch { }
    if ("$($global:PIM_EngineSqlCs)".Trim()) { return "$($global:PIM_EngineSqlCs)" }
    if (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue) { try { $c = Get-PimSqlSettingsConnectionString; if ("$c".Trim()) { return "$c" } } catch { } }
    return $null
}

function Get-PimGuardLimitStoreText {
    <# The stored JSON text of 'GuardLimits', or $null (nothing stored / no store). THROWS when a configured store fails. #>
    $name = Get-PimGuardLimitSettingName
    if ($global:PIM_GuardReleaseStore -is [hashtable]) { $v = $global:PIM_GuardReleaseStore[$name]; if ($null -eq $v) { return $null }; return "$v" }
    $cs = Get-PimGuardLimitStoreCs
    if ($cs -and (Get-Command Get-PimSqlSettingRaw -ErrorAction SilentlyContinue)) { return (Get-PimSqlSettingRaw -ConnectionString $cs -Name $name) }
    return $null
}

function Set-PimGuardLimitStoreText {
    <# Write 'GuardLimits' ONLY IF the stored text is still -Expected (compare-and-set). 1 = written, 0 = somebody wrote
       in between. THROWS when there is no store or it rejects the write. #>
    param([Parameter(Mandatory)][string]$Json, [AllowNull()][string]$Expected)
    $name = Get-PimGuardLimitSettingName
    if ($global:PIM_GuardReleaseStore -is [hashtable]) {
        if ("$($global:PIM_GuardReleaseStore[$name])" -cne "$Expected") { return 0 }
        $global:PIM_GuardReleaseStore[$name] = $Json; return 1
    }
    $cs = Get-PimGuardLimitStoreCs
    if (-not $cs -or -not (Get-Command Set-PimSqlSettingIfUnchanged -ErrorAction SilentlyContinue)) { throw 'REFUSED -- there is no settings store to write the limit to. Nothing was changed.' }
    return [int](Set-PimSqlSettingIfUnchanged -ConnectionString $cs -Name $name -NewValueJson $Json -ExpectedValueJson $Expected)
}

function ConvertFrom-PimGuardLimitsText {
    <#
      PURE. The stored text -> @{ limits = @{ <guardId> = @{ value; by; atUtc } }; refused = @{ <guardId> = <why> }; error }.
      Only values Test-PimGuardLimitValue accepts are in 'limits'; every other entry is in 'refused' with the reason.
      Text that is not JSON = error set, nothing in limits.
    #>
    param([AllowNull()][string]$Text)
    $out = @{ limits = @{}; refused = @{}; error = '' }
    if ($null -eq $Text -or "$Text".Trim() -eq '') { return $out }
    $o = $null
    try { $o = "$Text" | ConvertFrom-Json } catch { $out.error = "the stored limits are not readable ($($_.Exception.Message))"; return $out }
    if ($null -eq $o -or -not $o.PSObject.Properties['limits'] -or $null -eq $o.limits) { return $out }
    foreach ($p in @($o.limits.PSObject.Properties)) {
        $id = "$($p.Name)".Trim().ToLowerInvariant()
        $e = $p.Value
        $val = $null; $by = ''; $at = ''
        # REVIEW FIXES 2026-10-13: an entry is { value, by, atUtc } -- what the Guards page writes (Set-PimGuardLimit), always
        # with who set it and when. A bare number, or an entry without who / when, was written around the page: it is NOT
        # usable and the default applies. (No released version ever wrote 'GuardLimits': the setting is new with 100.119.)
        $shaped = ($null -ne $e -and -not ($e -is [string]) -and -not ($e -is [ValueType]) -and [bool]$e.PSObject.Properties['value'])
        if (-not $shaped) { $out.refused[$id] = 'the entry is not a limit the Guards page wrote (a value with who set it and when)'; continue }
        $val = $e.value; $by = "$($e.by)".Trim(); $at = $(if ($e.atUtc -is [datetime]) { $e.atUtc.ToUniversalTime().ToString('o') } else { "$($e.atUtc)".Trim() })
        $t = Test-PimGuardLimitValue -GuardId $id -Value $val
        if (-not $t.ok) { $out.refused[$id] = "$($t.reason)"; continue }
        $when = [datetime]::MinValue
        $atOk = [bool]$at -and [datetime]::TryParse($at, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$when)
        if (-not $by -or $by -eq '<unauthenticated>' -or -not $atOk) { $out.refused[$id] = 'the entry does not say who set the limit and when -- a limit is set on the Guards page only'; continue }
        $out.limits[$id] = @{ value = [int]$t.value; by = $by; atUtc = $at }
    }
    return $out
}

function Get-PimGuardLimitsParsed {
    <#
      The parsed stored limits. NEVER throws: a store that cannot be read gives error set and no limits (so every guard
      falls back to its default). Cached 30 s per process (the engine asks once per scope); -Fresh reads again.
    #>
    param([switch]$Fresh)
    if (-not ($global:PIM_GuardReleaseStore -is [hashtable]) -and -not $Fresh) {
        $c = $global:PIM_GuardLimitsCache
        if ($c -is [hashtable] -and $c['at'] -is [datetime] -and ([datetime]::UtcNow - $c['at']).TotalSeconds -lt 30 -and $c['parsed'] -is [hashtable]) { return $c['parsed'] }
    }
    $parsed = $null
    try { $parsed = ConvertFrom-PimGuardLimitsText -Text (Get-PimGuardLimitStoreText) }
    catch { $parsed = @{ limits = @{}; refused = @{}; error = "the limits could not be read ($($_.Exception.Message))" } }
    # Review fixes 2026-10-13: a stored entry that is not usable is SAID -- once per guard and reason in a process (the
    # engine asks once per scope). The default applies; the Guards page shows the same reason on the guard's row.
    try {
        if ($parsed.refused -is [hashtable] -and $parsed.refused.Count) {
            if (-not ($global:PIM_GuardLimitWarned -is [hashtable])) { $global:PIM_GuardLimitWarned = @{} }
            foreach ($rk in @($parsed.refused.Keys)) {
                $wk = "$rk|$($parsed.refused[$rk])"
                if ($global:PIM_GuardLimitWarned.ContainsKey($wk)) { continue }
                $global:PIM_GuardLimitWarned[$wk] = $true
                Write-Warning ("[guards] the stored limit of '{0}' is not usable ({1}) -- the default applies." -f $rk, $parsed.refused[$rk])
            }
        }
    } catch { }
    if (-not ($global:PIM_GuardReleaseStore -is [hashtable])) { $global:PIM_GuardLimitsCache = @{ at = [datetime]::UtcNow; parsed = $parsed } }
    return $parsed
}

function Get-PimGuardLimitState {
    <#
      What one guard's limit IS and where it comes from. NEVER throws. $null when the guard has no settable limit.
        @{ guardId; value; default; floor; ceiling; unit; why; source = 'set' | 'default'; note; setBy; setUtc }
      note says why the default applies when something WAS stored (refused / unreadable).
    #>
    param([string]$GuardId, [switch]$Fresh)
    $s = Get-PimGuardLimitSpec -GuardId $GuardId
    if (-not $s) { return $null }
    $id = "$($s.guardId)"
    $st = [ordered]@{ guardId = $id; value = [int]$s.default; default = [int]$s.default; floor = [int]$s.floor; ceiling = [int]$s.ceiling
                      unit = "$($s.unit)"; why = "$($s.why)"; bounds = @($s.bounds); source = 'default'; note = ''; setBy = ''; setUtc = '' }
    $p = Get-PimGuardLimitsParsed -Fresh:$Fresh
    if ($p.error) { $st.note = "$($p.error) -- the default applies"; return [pscustomobject]$st }
    if ($p.limits.ContainsKey($id)) {
        $e = $p.limits[$id]
        $st.value = [int]$e.value; $st.source = 'set'; $st.setBy = "$($e.by)"; $st.setUtc = "$($e.atUtc)"
    } elseif ($p.refused.ContainsKey($id)) {
        $st.note = "the stored value was refused ($($p.refused[$id])) -- the default applies"
    }
    return [pscustomobject]$st
}

function Get-PimGuardLimit {
    <#
      THE number the guard's own code uses. NEVER throws, never returns "no limit": the stored value when it is a whole
      number inside floor..ceiling, else the default (a literal). A guard without a limit entry returns -Fallback.
    #>
    param([Parameter(Mandatory)][string]$GuardId, [int]$Fallback = 5, [switch]$Fresh)
    $def = Get-PimGuardLimitDefault -GuardId $GuardId -Fallback $Fallback
    try {
        $st = Get-PimGuardLimitState -GuardId $GuardId -Fresh:$Fresh
        if ($null -eq $st) { return [int]$def }
        $n = [int]$st.value
        if ($n -lt [int]$st.floor -or $n -gt [int]$st.ceiling) { return [int]$def }
        return $n
    } catch { return [int]$def }
}

function Set-PimGuardLimit {
    <#
      A SuperAdmin sets the limit of one guard. THROWS 'REFUSED -- ...' on every rule it breaks (not a SuperAdmin, no
      person, a guard without a limit / a locked guard, a value outside floor..ceiling) and when the store rejects the
      write. Returns @{ guardId; before; after; floor; ceiling; default } -- the caller audits it.
      -Value $null with -Reset puts the guard back on its default (the stored entry is removed).
    #>
    param([Parameter(Mandatory)][string]$GuardId, [AllowNull()][object]$Value, [Parameter(Mandatory)][string]$By, [string]$Role = '', [switch]$Reset, [datetime]$NowUtc = [datetime]::UtcNow)
    if (-not (Test-PimGuardSuperAdminRole -Role $Role)) { throw 'REFUSED -- only a SuperAdmin may set the limit of a guard.' }
    if (-not "$By".Trim() -or "$By".Trim() -eq '<unauthenticated>') { throw 'REFUSED -- the person setting the limit is unknown.' }
    $id = "$GuardId".Trim().ToLowerInvariant()
    $spec = Get-PimGuardLimitSpec -GuardId $id
    $new = $null
    if ($Reset) {
        $probe = Test-PimGuardLimitValue -GuardId $id -Value $(if ($spec) { $spec.default } else { 0 })
        if (-not $probe.ok) { throw "REFUSED -- $($probe.reason)." }
    } else {
        $t = Test-PimGuardLimitValue -GuardId $id -Value $Value
        if (-not $t.ok) { throw "REFUSED -- $($t.reason). Nothing was changed." }
        $new = [int]$t.value
    }
    # PIM 100.119 B6: read, change ONE entry, write only if nobody wrote in between (compare-and-set), else read again --
    # two SuperAdmins saving different guards at the same moment both keep their entry.
    $before = $null; $written = $false
    for ($try = 0; $try -lt 4 -and -not $written; $try++) {
        $text = Get-PimGuardLimitStoreText
        $parsed = ConvertFrom-PimGuardLimitsText -Text $text
        if ($parsed.error) { throw "REFUSED -- $($parsed.error). Nothing was changed." }
        if ($null -eq $before) { $before = Get-PimGuardLimitState -GuardId $id -Fresh }
        $next = [ordered]@{}
        foreach ($k in @($parsed.limits.Keys | Sort-Object)) { if ($k -ne $id) { $next[$k] = [ordered]@{ value = [int]$parsed.limits[$k].value; by = "$($parsed.limits[$k].by)"; atUtc = "$($parsed.limits[$k].atUtc)" } } }
        if (-not $Reset) { $next[$id] = [ordered]@{ value = $new; by = "$By".Trim(); atUtc = $NowUtc.ToUniversalTime().ToString('o') } }
        $json = ConvertTo-Json -InputObject ([ordered]@{ limits = $next }) -Depth 6 -Compress
        $written = ([int](Set-PimGuardLimitStoreText -Json $json -Expected $text) -eq 1)
    }
    if (-not $written) { throw 'REFUSED -- the limits kept changing while this one was saved. Nothing was changed; reload the Guards page and set it again.' }
    $global:PIM_GuardLimitsCache = $null
    $after = Get-PimGuardLimitState -GuardId $id -Fresh
    if ([int]$after.value -ne $(if ($Reset) { [int]$spec.default } else { $new })) { throw 'REFUSED -- the limit was written but did not read back; the default applies. Reload the Guards page.' }
    return [pscustomobject]@{ guardId = $id; before = $before; after = $after; floor = [int]$spec.floor; ceiling = [int]$spec.ceiling; default = [int]$spec.default }
}
