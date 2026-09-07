#Requires -Version 5.1
<#
.SYNOPSIS
    SEC-16 / §36.2 -- the audit trail's STORE. Offline: static asserts over the shipped writer,
    reader and DDL, plus the SQL shaping functions driven for real against a stub connection.
    No tenant, no live SQL, no writes to any store.

    Two defects, in one 18-line function, both measured on 2026-08-31:

      (a) IT DID NOT SURVIVE A DEPLOY. The trail was appended to
          output/audit/pim-audit-YYYYMM.jsonl and the hosted app mounts NO persistent volume
          (volumes=null, mounts=null) -- so every revision roll destroyed it. The audit trail is
          the one record that must OUTLIVE the thing it audits: desired state is already in SQL,
          the tenant cache rebuilds, engine logs are copied to Log Analytics. "Who granted
          privileged access" had no second home.

      (b) IT NAMED THE WRONG ACTOR. $who came from [WindowsIdentity]::GetCurrent().Name, which in
          a Linux container is the PROCESS user -- so every entry read the same thing regardless
          of who signed in. An audit trail that cannot attribute is a log.

    📌 Audit is a STANDARD feature of every topology (operator: "audit exist also for single
    tenant ... it is a standard feature for all scenarios"), so the table must be created by the
    COMMON store initialiser, not the MSP-only platform schema.

    Run standalone (exit 0 green / 1 red) or via Run-AllPimTests.ps1.
#>
[CmdletBinding()] param()

$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
function T($n, $c) { if ($c) { Write-Host "  PASS $n" -ForegroundColor Green; $script:pass++ } else { Write-Host "  FAIL $n" -ForegroundColor Red; $script:fail++ } }

# Static assertions below are scoped to the FUNCTION they name, not to a guessed character
# window around it. See tests\_shared\PimSourceScope.ps1 for why a bounded window rots in BOTH
# directions -- and note this suite is where that was first measured.
. "$PSScriptRoot\_shared\PimSourceScope.ps1"

$root  = Split-Path -Parent $PSScriptRoot
$sqlP  = Join-Path $root 'engine\_shared\PIM-SqlStore.ps1'
$srvP  = Join-Path $root 'tools\pim-manager\Open-PimManager.ps1'
$platP = Join-Path $root 'sql\platform-schema.sql'
T 'PIM-SqlStore.ps1 present'    (Test-Path -LiteralPath $sqlP)
T 'Open-PimManager.ps1 present' (Test-Path -LiteralPath $srvP)
if ($fail) { Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor Red; exit 1 }

$sqlRaw = Get-Content -LiteralPath $sqlP -Raw
$srvRaw = Get-Content -LiteralPath $srvP -Raw
# Comments stripped -- a source-scan must read CODE. Both files' own prose names the defects
# they fix, so a naive scan matches the documentation of the rule (the Test-PimAdminTapReset trap).
$sql = $sqlRaw -replace '(?m)^\s*#.*$', ''
$srv = $srvRaw -replace '(?m)^\s*#.*$', ''
T 'the comment-stripper removed prose' ($sqlRaw.Length -gt $sql.Length -and $srvRaw.Length -gt $srv.Length)

# === (a) durability: the table exists, in the COMMON schema ==================
Write-Host "`n-- the trail has a home that survives a deploy --" -ForegroundColor Cyan
T 'pim.AuditEvents is defined'              ($sql -match "OBJECT_ID\('pim\.AuditEvents'\)")
# The headline for "standard feature of all scenarios": it must be created by the same
# initialiser as pim.Rows / pim.Settings, NOT by the MSP-only platform schema.
$initIdx  = $sql.IndexOf('function Initialize-PimSqlStore')
$auditIdx = $sql.IndexOf("OBJECT_ID('pim.AuditEvents')")
$rowsIdx  = $sql.IndexOf("OBJECT_ID('pim.Rows')")
T 'it is created by Initialize-PimSqlStore' ($initIdx -ge 0 -and $auditIdx -gt $initIdx)
T '   ...in the same DDL as pim.Rows'       ($rowsIdx -gt $initIdx -and [Math]::Abs($auditIdx - $rowsIdx) -lt 3000)
T 'it is in the pim schema, not platform'   ($sql -notmatch "OBJECT_ID\('platform\.AuditEvents'\)")
# The pre-existing platform.AuditEvents is MSP-master-only and nothing writes to it. Assert we
# did NOT reuse it -- a single-tenant deployment never creates the platform schema at all.
if (Test-Path -LiteralPath $platP) {
    T 'the MSP-only platform.AuditEvents still has no writer' ((Get-Content -LiteralPath $srvP -Raw) -notmatch 'platform\.AuditEvents')
}
T 'the trail is indexed by time (it is read newest-first)' ($sql -match 'IX_pim_AuditEvents_Ts')

Write-Host "`n-- append-only BY CONSTRUCTION --" -ForegroundColor Cyan
# The value of an audit trail is that it cannot be tidied. The cheapest way to keep a capability
# from being used by accident is not to write it, so there is deliberately no update/delete helper.
T 'a SQL audit WRITER exists'   ($sql -match 'function Write-PimSqlAuditEvent')
T 'a SQL audit READER exists'   ($sql -match 'function Get-PimSqlAuditEvents')
T 'NO update helper exists'     ($sql -notmatch 'function (Set|Update)-PimSqlAuditEvent')
T 'NO delete helper exists'     ($sql -notmatch 'function (Remove|Clear)-PimSqlAuditEvent')
# 🪤 These two were bounded by a hard-coded .{0,1200} window and §36.3 phase 1b's -Ts support
# pushed the INSERT past it -- the positive assertion failed for a writer that was still correct.
# The negative one is the worse half: a notmatch whose window is too short passes VACUOUSLY, so
# it would have gone green while an UPDATE sat just outside the window. Isolate the body instead
# and assert against ALL of it; the guard then cannot be defeated by the function's length.
$wsIdx  = $sql.IndexOf('function Write-PimSqlAuditEvent')
$wsEnd  = $sql.IndexOf('function Get-PimSqlAuditEvents')
$wsBody = if ($wsIdx -ge 0 -and $wsEnd -gt $wsIdx) { $sql.Substring($wsIdx, $wsEnd - $wsIdx) } else { '' }
T 'the SQL writer body was isolated' ($wsBody.Length -gt 200)
T 'the writer only INSERTs'     ($wsBody -match 'INSERT INTO pim\.AuditEvents')
T '   ...and never UPDATEs/DELETEs' ($wsBody -notmatch '(UPDATE pim\.AuditEvents|DELETE FROM pim\.AuditEvents)')

# === (b) attribution ========================================================
Write-Host "`n-- it records WHO, not the container --" -ForegroundColor Cyan
T 'the writer resolves the signed-in principal' ((Get-PimSourceFunctionBody -Text $srv -Name 'Write-PimManagerAuditEvent') -match 'Get-PimManagerRole')
T 'the event carries an actorSource'            ($srv -match 'actorSource')
T 'the table stores ActorSource'                ($sql -match 'ActorSource')
# The process identity is still a legitimate LAST resort -- but recording it unlabelled is
# exactly how the original defect hid for as long as it did.
T 'a process-identity fallback is LABELLED as such' ($srv -match 'process-identity \(NO signed-in principal resolved\)')
T 'WindowsIdentity is no longer the primary source' ($srv -match '(?s)Get-PimManagerRole.{0,900}?WindowsIdentity')

# === a failed audit is LOUD =================================================
Write-Host "`n-- an unrecorded privileged action is not silent --" -ForegroundColor Cyan
# It used to be Write-Warning on every path, so a privileged action whose audit failed still
# succeeded quietly -- and on the hosted app the file it fell back to dies at the next roll.
T 'a hosted audit miss raises an ERROR'      ($srv -match 'AUDIT NOT RECORDED')
T '   ...and says the fallback will not survive' ($srv -match 'does not survive a revision roll')
T 'a both-stores failure errors too'         ($srv -match 'audit write failed on BOTH SQL and file')

# === reader/writer agree on the store =======================================
Write-Host "`n-- reader and writer must agree which store answered --" -ForegroundColor Cyan
T 'a SQL-first reader exists'                ($srv -match 'function Get-PimManagerAuditEvents')
T 'the endpoints use it'                     (([regex]::Matches($srv, 'Get-PimManagerAuditEvents -Months')).Count -ge 2)
# 🔑 A SQL read failure must NOT quietly fall through to the file: on a hosted deployment that is
# a different and shorter-lived trail, so showing it would present partial history as complete.
T 'a failed SQL read THROWS, never falls back' ($srv -match '(?s)audit read from SQL failed.{0,200}?throw')
# The month count drives the window selector. Counting FILES when SQL is the store would report
# "0 months of history" for a populated trail.
T 'the month count is source-aware'          ($srv -match 'function Get-PimManagerAuditMonthCount')
T '   ...backed by a distinct-month query'   ($sql -match 'function Get-PimSqlAuditMonthCount')
T '   ...and the endpoint no longer counts files' ($srv -notmatch 'monthsAvail')

# === the shaping functions, driven for real =================================
Write-Host "`n-- row shaping round-trips (driven, not scanned) --" -ForegroundColor Cyan
. $sqlP
# Stub the one SQL primitive so the reader can be exercised with no database.
function Invoke-PimSqlQuery {
    param($ConnectionString, $Sql, $Parameters)
    @([pscustomobject]@{
        Ts = [datetime]'2026-08-31T10:00:00Z'; RunId = 'r1'; CorrelationId = ''
        Actor = 'mok@2linkit.net'; ActorSource = 'env PIM_SuperAdmins'
        Action = 'sessions.revoke'; Target = 'Admin-JDO-ID@x.io'
        BeforeJson = $null; AfterJson = '{"userId":"11"}'; Result = 'ok'; WhatIf = $false
    })
}
$evts = @(Get-PimSqlAuditEvents -ConnectionString 'stub')
T 'one event returned'                       ($evts.Count -eq 1)
T 'actor is the PERSON, not the process'     ($evts[0].actor -eq 'mok@2linkit.net')
T 'actorSource is carried'                   ($evts[0].actorSource -eq 'env PIM_SuperAdmins')
T 'ts is an ISO round-trip string'           ($evts[0].ts -match '^\d{4}-\d{2}-\d{2}T')
T 'after JSON is parsed back to an object'   ("$($evts[0].after.userId)" -eq '11')
T 'a null before stays null'                 ($null -eq $evts[0].before)
T 'whatIf is a bool'                         ($evts[0].whatIf -is [bool])
# The shape must match what the existing query layer consumes, or moving the store silently
# breaks the Audit tab's filters and CSV export.
foreach ($k in 'ts','runId','correlationId','actor','action','target','before','after','result','whatIf') {
    T ("shape carries '$k' (matches the jsonl reader)") (@($evts[0].PSObject.Properties.Name) -contains $k)
}

# === the ENGINE half: one trail, not two ====================================
Write-Host "`n-- the engine writes to the SAME table --" -ForegroundColor Cyan
$fnP = Join-Path $root 'engine\_shared\PIM-Functions.psm1'
if (Test-Path -LiteralPath $fnP) {
    $fn = (Get-Content -LiteralPath $fnP -Raw) -replace '(?m)^\s*#.*$', ''
    # The engine's writer was never LOSING data (VisualCron's filesystem persists) and it already
    # names a real actor. What it shared was a different defect: the Manager wrote one audit file
    # and the engine wrote another, so "who granted this access" needed you to know which
    # component did it first. One question with two half-answers is not an audit trail.
    T 'the engine writer reaches the SQL sink' ((Get-PimSourceFunctionBody -Text $fn -Name 'Write-PimAuditEvent') -match 'Write-PimSqlAuditEvent')
    T '   ...tagged as actorSource=engine'     ($fn -match "ActorSource 'engine'")
    T '   ...carrying whatIf through'          ($fn -match '(?s)Write-PimSqlAuditEvent.{0,400}?-WhatIf \(\[bool\]\$global:WhatIfMode\)')
    T '   ...and the correlation id'           ($fn -match '(?s)Write-PimSqlAuditEvent.{0,500}?-CorrelationId')
    # 🔒 An engine APPLY must never fail because the audit sink is down -- but the failure must
    # not be hidden either, and the file write still runs so the event is never lost.
    T 'a SQL sink failure warns, does not throw' ($fn -match '(?s)Write-PimSqlAuditEvent.{0,900}?catch \{.{0,300}?Write-Warning')
    T '   ...and the file write still happens'   ($fn -match '(?s)catch \{.{0,400}?SQL sink failed.{0,400}?AppendAllText')
} else { T 'PIM-Functions.psm1 present' $false }

# === ONE audit writer, not two (SEC-16, second pass) ========================
Write-Host "`n-- there is exactly ONE audit writer in the Manager --" -ForegroundColor Cyan
# 🪤 The first SEC-16 fix repaired one writer and left another. `Write-PimMutationLog` had its own
# INLINE jsonl append with its own actor, and it emits `config.csv.save` -- the record that
# somebody COMMITTED A CHANGE TO DESIRED STATE, arguably the most consequential event this product
# produces. It was file-only (died with the container) and attributed to the container's process
# user. Fixing the reported instance is not the same as fixing the defect.
$srvAll = Get-Content -LiteralPath $srvP -Raw
$srvNC  = $srvAll -replace '(?m)^\s*#.*$', ''
# Only ONE place may append to the audit jsonl: the fallback inside Write-PimManagerAuditEvent.
$appends = @([regex]::Matches($srvNC, 'pim-audit-\{0\}\.jsonl'))
T 'only ONE audit-file writer remains'        ($appends.Count -eq 1)
# The old bound was .{0,3000} over a 969-character function, so two thirds of what these two
# "proved" was about whatever FOLLOWED Write-PimMutationLog: moving the call out of the
# function entirely would have failed neither of them.
$bMut = Get-PimSourceFunctionBody -Text $srvNC -Name 'Write-PimMutationLog'
T 'the mutation log routes through the shared writer' ($bMut -match "Write-PimManagerAuditEvent -Action 'config\.csv\.save'")
T '   ...and no longer builds its own event'  ($bMut -notmatch "action\s*=\s*'config\.csv\.save'")

Write-Host "`n-- 'who did it' is the operator everywhere it is EVIDENCE --" -ForegroundColor Cyan
# The commit snapshot's By and the restore response's by are evidence too: "who committed this"
# and "who rolled it back". Both recorded the container before this.
# Bound is 300 because the measured gap is 224 chars (the resolve line plus its fallback line).
# Kept tight on purpose: a generous .{0,5000} would match ANY Get-PimManagerRole anywhere in the
# file and pass whether or not this call site was fixed.
T 'commit snapshot By uses the signed-in principal'  ($srvNC -match "(?s)Get-PimManagerRole.{0,300}?New-PimCommitSnapshot")
T 'restore reports the signed-in principal'          ($srvNC -match "(?s)\`$ro = Get-PimManagerRole.{0,400}?Write-PimMutationLog")
# 🔒 The process identity remains a legitimate LAST resort in each case -- what is not acceptable
# is it being the FIRST choice, or being recorded unlabelled.
T 'a process-identity fallback still exists (local/dev)' ($srvNC -match 'WindowsIdentity\]::GetCurrent')

# === break-glass: the store both sides can see (§36.3 phase 3) ==============
Write-Host "`n-- break-glass override lives where the ENGINE can read it --" -ForegroundColor Cyan
# 🔑 This was never just "sensitive state in a file". The MANAGER writes the override and the
# ENGINE reads it -- and on a hosted deployment those are different machines (ca-pim-manager vs
# VisualCron on mgmt1 / ca-pim-tick). Same path, different filesystem. So activation wrote a file
# the engine would never see: break-glass silently did NOTHING at the one moment it was relied on.
# And in the other direction, expiresAtUtc is the ONLY record of when to restore -- lose it and
# the scoped groups keep approval disabled indefinitely while the Manager reports inactive.
$fnP2 = Join-Path $root 'engine\_shared\PIM-Functions.psm1'
if ((Test-Path -LiteralPath $fnP2) -and (Test-Path -LiteralPath $srvP)) {
    $fn2 = (Get-Content -LiteralPath $fnP2 -Raw) -replace '(?m)^\s*#.*$', ''
    $sv2 = (Get-Content -LiteralPath $srvP  -Raw) -replace '(?m)^\s*#.*$', ''
    T 'the engine reads the override from SQL first'  ($fn2 -match '(?s)function Get-PimEmergencyOverride\b.{0,1500}?Get-PimSqlSetting')
    T 'the engine has a shared-store WRITER'          ($fn2 -match 'function Set-PimEmergencyOverride')
    T 'the Manager reads from the shared store'       ($sv2 -match 'function Get-PimManagerEmergencyOverride')
    T 'the Manager writes to the shared store'        ($sv2 -match 'function Set-PimManagerEmergencyOverride')
    # Both sides must agree on the key or they are still two stores wearing one name.
    T 'both sides use the SAME setting name'          ($fn2 -match "'EmergencyOverride'" -and $sv2 -match "'EmergencyOverride'")
    # 🔒 An activation the engine cannot see must FAIL, not silently write a file and report
    # success -- telling an operator break-glass is on when it is not is worse than refusing.
    T 'a failed SQL write THROWS rather than falling back to a file' ((Get-PimSourceFunctionBody -Text $sv2 -Name 'Set-PimManagerEmergencyOverride') -match '(?s)the engine will NOT see this override.{0,120}?throw')
    T 'activate returns 500 when it cannot be recorded'  ($sv2 -match 'could not record the emergency override')
    T '   ...and says nothing was activated'             ($sv2 -match 'Nothing was activated')
    # The restore path used to swallow every failure in `catch {}` and still report success.
    T 'restore no longer swallows its failure'          ($sv2 -match 'could not expire the emergency override')
    T '   ...and warns the override may still be ACTIVE' ($sv2 -match 'may still be ACTIVE')
    # Expiry has to retire the override in the store that HOLDS it. Move-Item on a file did
    # nothing on a SQL deployment, so every later run would re-restore the same expired override.
    T 'expiry clears the override in the store, not by moving a file' ($fn2 -match '(?s)Emergency override EXPIRED.{0,1200}?Set-PimEmergencyOverride -Override')
    T '   ...and only archives the FILE when the file was the store'  ($fn2 -match "(?s)if \(\`$where -eq 'file'\).{0,400}?Move-Item")
    # 🪤 The Manager must NOT depend on the engine module here: PIM-Functions.psm1 is imported
    # LAZILY ("so the Manager works without the engine"), so an unguarded call returns nothing
    # when it is not loaded -- and the tile would read "inactive" over a live override.
    T 'the Manager does not call the engine override fn directly' ($sv2 -notmatch '=\s*Get-PimEmergencyOverride\s*$')
} else { T 'PIM-Functions.psm1 + Open-PimManager.ps1 present' $false }

# === phase 3 completed: warning overrides + conformance exemptions ==========
Write-Host "`n-- the last two file-backed Manager stores --" -ForegroundColor Cyan
$valP = Join-Path $root 'tools\pim-manager\_validator.ps1'
$ovrP = Join-Path $root 'engine\_shared\PIM-WarningOverrides.ps1'
$conP = Join-Path $root 'engine\_shared\PIM-Conformance.ps1'
$smpP = Join-Path $root 'config\exemptions.sample.json'
if ((Test-Path -LiteralPath $valP) -and (Test-Path -LiteralPath $ovrP) -and (Test-Path -LiteralPath $conP)) {
    $_strip = { param($t) ($t -replace '(?s)<#.*?#>', '') -replace '(?m)^\s*#.*$', '' }
    $sv3 = & $_strip (Get-Content -LiteralPath $srvP -Raw)
    $val = & $_strip (Get-Content -LiteralPath $valP -Raw)

    T 'the Manager has a warning-override store reader' ($sv3 -match 'function Get-PimManagerWarningOverrides')
    T 'the Manager has a warning-override store writer' ($sv3 -match 'function Set-PimManagerWarningOverrides')
    T 'the Manager has an exemption store reader'       ($sv3 -match 'function Get-PimManagerConformanceExemptions')
    T 'the Manager has an exemption store writer'       ($sv3 -match 'function Set-PimManagerConformanceExemptions')
    T 'the two stores use DISTINCT setting names'       ($sv3 -match "'WarningOverrides'" -and $sv3 -match "'ConformanceExemptions'")

    # Same rule as break-glass: a configured SQL store that rejects the write must not be
    # demoted to a file the operator will never look at.
    T 'a failed override SQL write THROWS'  ((Get-PimSourceFunctionBody -Text $sv3 -Name 'Set-PimManagerWarningOverrides') -match '(?s)was NOT saved.{0,120}?throw')
    T 'a failed exemption SQL write THROWS' ((Get-PimSourceFunctionBody -Text $sv3 -Name 'Set-PimManagerConformanceExemptions') -match '(?s)was NOT saved.{0,120}?throw')

    # The refusal that never fired where it was aimed: hosted DOES have a configRoot (the
    # container's own), so "overrides are a CSV-mode feature" did not block anything -- it just
    # sent the acknowledgement to a disk that dies on the next revision roll.
    T 'the override writer no longer refuses in SQL mode' ($sv3 -notmatch 'overrides are a CSV-mode feature')

    Write-Host "`n-- SEC-17: the shipped SAMPLE is no longer live waiver state --" -ForegroundColor Cyan
    T 'nothing READS exemptions.sample.json at runtime' ($sv3 -notmatch 'exemptions\.sample\.json')
    T 'the sample still exists as documentation'        (Test-Path -LiteralPath $smpP)
    T 'the exemption reader is the ONE way in'          ($sv3 -match '\$readEx = \{ @\(Get-PimManagerConformanceExemptions\) \}')
    # Both halves of the register, or the migration splits one store across two backends: a
    # revoke would "succeed" against a file nothing reads while the waiver stayed live in SQL.
    T 'ADD goes through the store writer'    ($sv3 -match '(?s)\$list\.Add\(\$cand\).{0,400}?Set-PimManagerConformanceExemptions')
    T 'REVOKE goes through the store writer' ($sv3 -match 'Set-PimManagerConformanceExemptions -Exemptions @\(\$r\.Kept\)')
    T 'the old file path variable is gone entirely' ($sv3 -notmatch '\$confExFile')

    # 🪤 Negative verification of the FINDING, not just the fix: prove the sample would really
    # have suppressed a control. If this ever stops reproducing, SEC-17 was overstated and the
    # record should be corrected -- not quietly left standing.
    . $conP
    $smp = $null
    try { $smp = (Get-Content -LiteralPath $smpP -Raw -Encoding UTF8 | ConvertFrom-Json).exemptions } catch {}
    if ($smp) {
        $asOf = [datetime]::Parse('2026-08-31T00:00:00Z').ToUniversalTime()
        $live = @(Get-PimActiveExemptionKeys -Exemptions @($smp) -TenantId 'local' -TemplateId 'defender-xdr-roles' -NowUtc $asOf -WarningAction SilentlyContinue)
        T 'the sample carried a waiver that was ACTIVE, not expired' ($live.Count -ge 1)
        T '   ...suppressing a real control (Security Administrator)' ($live -contains 'role:Security Administrator')
        # ...and the scope limit that keeps this out of production, asserted so the severity
        # in REQUIREMENTS stays honest: hosted labels the instance sql:<db>, which never matches.
        $prod = @(Get-PimActiveExemptionKeys -Exemptions @($smp) -TenantId 'sql:pimdb' -TemplateId 'defender-xdr-roles' -NowUtc $asOf -WarningAction SilentlyContinue)
        T '   ...but NOT under a hosted instance name (tenantId is exact-match)' ($prod.Count -eq 0)
    } else { T 'sample exemptions readable for the negative check' $false }
    # The safe direction, stated as an assertion: no exemptions means nothing is waived.
    $none = @(Get-PimActiveExemptionKeys -Exemptions @() -TenantId 'local' -TemplateId 'defender-xdr-roles' -NowUtc ([datetime]::UtcNow) -WarningAction SilentlyContinue)
    T 'an EMPTY exemption set waives nothing (the safe default)' ($none.Count -eq 0)

    Write-Host "`n-- the CONSUMER moved too (the half that makes it real) --" -ForegroundColor Cyan
    # 🔴 SEC-16's first fix migrated a writer and left its reader behind. Break-glass failed the
    # same way across two machines. Here the validator is what actually downgrades a finding to
    # 'acknowledged' -- leave it on the file and every acknowledgement looks accepted and does
    # nothing on the next preflight.
    T 'the validator reads the SQL-aware store' ($val -match 'Apply-PimWarningOverrides -Findings \$finalViolations -Config \(Get-PimManagerWarningOverrides\)')
    T '   ...guarded, so a standalone dot-source still works' ($val -match "Get-Command Get-PimManagerWarningOverrides -ErrorAction SilentlyContinue")
    T '   ...and keeps the -Path fallback for that case'      ($val -match 'Apply-PimWarningOverrides -Findings \$finalViolations -Path \$ovrPath')

    # The library seam this relies on: -Config must actually beat -Path. Exercised for real,
    # because "the parameter exists" is not the same as "the parameter is honoured".
    . $ovrP
    $find = @([pscustomobject]@{ Severity = 'warning'; Code = 'PIM-TEST-001'; Csv = 'Admins'; Row = 1; Column = 'X'; Message = 'm' })
    $cfg  = @{ overrides = @(@{ code = 'PIM-TEST-001'; reason = 'unit test'; noExpiry = $true }) }
    $res  = Apply-PimWarningOverrides -Findings $find -Config $cfg -Path 'C:\does\not\exist.json'
    T '-Config is honoured and beats -Path'      ($res -and [int]$res.acknowledged -eq 1)
    T '   ...the finding is downgraded, not dropped' (@($res.findings).Count -eq 1 -and "$(@($res.findings)[0].Severity)" -eq 'acknowledged')
} else { T '_validator.ps1 + override/conformance libs present' $false }

# === §36.3 PHASE 1b: the FILE path is retired on hosted =====================
Write-Host "`n-- hosted no longer writes, reads or counts the file trail --" -ForegroundColor Cyan
# 🔑 Phase 1 put the trail in SQL but left the file as a hosted "fallback", which it never was:
# the container mounts no volume, so it survived only to the next revision roll; the append
# returned success, so the failure looked handled; and the SQL-first reader deliberately refuses
# to merge the two, so every line written there was by construction unreadable. A store with no
# reader is not a fallback. Phase 1b removes it from all three paths, and the three MUST agree --
# a writer that stops while the reader keeps rendering files is how "partial history shown as
# complete" comes back through the other door.
T 'one shared hosted probe exists' ($srvNC -match 'function Test-PimManagerHostedDeployment')

# Ordering, not mere presence: `return` has to land BETWEEN the loud error and the file append,
# or the branch reads as fixed while still writing. A .{0,N} regex cannot express "before".
$wIdx  = $srvNC.IndexOf('function Write-PimManagerAuditEvent')
$wEnd  = $srvNC.IndexOf('function Get-PimManagerAuditEvents')
$wBody = if ($wIdx -ge 0 -and $wEnd -gt $wIdx) { $srvNC.Substring($wIdx, $wEnd - $wIdx) } else { '' }
$iErr  = $wBody.IndexOf('AUDIT NOT RECORDED')
$iRet  = if ($iErr -ge 0) { $wBody.IndexOf('return', $iErr) } else { -1 }
$iFile = $wBody.IndexOf('pim-audit-{0}.jsonl')
T 'the writer body was isolated'                  ($wBody.Length -gt 200)
T 'the writer asks the shared probe'              ($wBody -match 'Test-PimManagerHostedDeployment')
T 'a hosted miss still raises the loud error'     ($iErr -ge 0)
T '   ...and RETURNS before the file append'      ($iRet -gt $iErr -and $iFile -gt $iRet)
T '   ...saying the file is no longer written'    ($wBody -match 'no longer written at all')
# The local/dev file path must still exist -- an instance with no SQL at all has nowhere else
# to record to, and deleting it would be a data-loss fix for a data-loss defect.
T 'the local/dev file append still exists'        ($iFile -gt 0)

$rIdx  = $srvNC.IndexOf('function Get-PimManagerAuditEvents')
$rEnd  = $srvNC.IndexOf('function Get-PimEmergencyOverrideStoreName')
$rBody = if ($rIdx -ge 0 -and $rEnd -gt $rIdx) { $srvNC.Substring($rIdx, $rEnd - $rIdx) } else { '' }
$iRH   = $rBody.IndexOf('Test-PimManagerHostedDeployment')
$iRT   = if ($iRH -ge 0) { $rBody.IndexOf('throw', $iRH) } else { -1 }
$iRF   = $rBody.IndexOf('Read-PimAuditEvents')
T 'the reader body was isolated'                  ($rBody.Length -gt 200)
T 'the reader refuses the file when hosted'       ($iRH -ge 0 -and $iRT -gt $iRH)
T '   ...before it would reach the file reader'   ($iRF -gt $iRT -and $iRT -gt 0)
T '   ...and still reads files when NOT hosted'   ($iRF -gt 0)

$mIdx  = $srvNC.IndexOf('function Get-PimManagerAuditMonthCount')
$mEnd  = $srvNC.IndexOf('function Get-PimWarningOverrideStoreName')
$mBody = if ($mIdx -ge 0 -and $mEnd -gt $mIdx) { $srvNC.Substring($mIdx, $mEnd - $mIdx) } else { '' }
$iMH   = $mBody.IndexOf('Test-PimManagerHostedDeployment')
$iML   = $mBody.IndexOf('Get-PimAuditMonthList')
T 'the month count body was isolated'             ($mBody.Length -gt 100)
T 'the month count skips files when hosted'       ($iMH -ge 0 -and $iML -gt $iMH)
# It used to `return 0` on a SQL failure, which reports "no history" for a populated trail --
# the exact miscount its own note says counting files would cause.
T '   ...and no longer swallows a SQL failure'    ($mBody -match 'audit month count from SQL failed')

Write-Host "`n-- Ts is bound ONLY for an import (driven) --" -ForegroundColor Cyan
# The live writer must leave Ts on its column DEFAULT; only the importer supplies one. Binding
# "now" for an import would stamp the whole imported history with the minute it ran and destroy
# the ordering that makes the trail evidence. Driven against a capturing stub, because "the
# parameter exists" is not the same as "the parameter changes the statement".
$script:capSql = ''; $script:capPar = $null
function Invoke-PimSqlNonQuery { param($ConnectionString, $Sql, $Parameters) $script:capSql = "$Sql"; $script:capPar = $Parameters; 1 }
Write-PimSqlAuditEvent -ConnectionString 'stub' -Actor 'a@b.c' -Action 'x.y' -Target 't'
T 'a live write does NOT name Ts'          ($script:capSql -notmatch '\bTs\b' -and -not $script:capPar.ContainsKey('ts'))
T '   ...so the column DEFAULT applies'    ($sql -match 'DF_PimAudit_Ts')
$when = [datetime]::SpecifyKind([datetime]'2026-07-04T09:30:00', 'Utc')
Write-PimSqlAuditEvent -ConnectionString 'stub' -Actor 'a@b.c' -Action 'x.y' -Target 't' -Ts $when
T 'an import DOES name Ts'                 ($script:capSql -match 'INSERT INTO pim\.AuditEvents \(Ts,')
T '   ...and binds the ORIGINAL instant'   ($script:capPar['ts'] -eq $when)
T '   ...with the column order still aligned' ($script:capSql -match '(?s)\(Ts, RunId,.*?VALUES \(@ts, @run,')
# A caller holding a local-time value must not shift the trail by the host's UTC offset.
$local = [datetime]::SpecifyKind([datetime]'2026-07-04T09:30:00', 'Local')
Write-PimSqlAuditEvent -ConnectionString 'stub' -Actor 'a@b.c' -Action 'x.y' -Target 't' -Ts $local
T '   ...normalising a local time to UTC'  ($script:capPar['ts'] -eq $local.ToUniversalTime())

Write-Host "`n-- the importer that makes retirement non-lossy --" -ForegroundColor Cyan
# Retiring the file path on hosted costs nothing (those files were already ephemeral), but a
# LOCAL instance that later gains SQL would watch its trail vanish from the Audit tab -- the
# reader is SQL-first and refuses to merge. The importer is the only way that history survives.
$impP = Join-Path $root 'tools\pim-manager\Import-PimAuditFileTrail.ps1'
T 'the importer ships'                     (Test-Path -LiteralPath $impP)
if (Test-Path -LiteralPath $impP) {
    $impRaw = Get-Content -LiteralPath $impP -Raw
    $imp    = ($impRaw -replace '(?s)<#.*?#>', '') -replace '(?m)^\s*#.*$', ''
    $ie = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($impP, [ref]$null, [ref]$ie)
    T '   ...and parses'                       (-not $ie -or $ie.Count -eq 0)
    T '   ...preserving each event''s own time' ($imp -match 'Write-PimSqlAuditEvent -ConnectionString \$ConnectionString -Ts \$ts')
    # 🪤 Idempotency is the ARCHIVE, not a de-dupe query: pim.AuditEvents has no delete helper
    # by intent, and adding one so a re-run could clean up would hand everyone the DELETE the
    # trail is supposed not to have.
    T '   ...archiving the source so a re-run is a no-op' ($imp -match 'Rename-Item -LiteralPath \$f\.FullName')
    T '   ...and warning that -KeepFiles re-imports'      ($imp -match 'A SECOND run WILL re-import it')
    T '   ...supporting -WhatIf before it touches SQL'    ($imp -match 'SupportsShouldProcess' -and $imp -match '\$PSCmdlet\.ShouldProcess')
    # It parses the jsonl itself: Read-PimAuditEvents shapes for DISPLAY (ts to a string, plus
    # category/change), none of which are columns, so routing through it only has to be undone.
    T '   ...parsing the jsonl rather than the display reader' ($imp -notmatch 'Read-PimAuditEvents')
    # A malformed line must not strand the rest of a month -- the file reader's long-standing rule.
    T '   ...skipping an unparseable line, never aborting' ($imp -match '(?s)ConvertFrom-Json \} catch \{ \$bad\+\+; continue \}')
    T '   ...and refusing to run with nowhere to import TO' ($imp -match 'nowhere to import TO')
}

# === the @($list) trap, pinned so it does not come back ======================
Write-Host "`n-- the List-wrapping trap this cost an hour --" -ForegroundColor Cyan
# Wrapping a System.Collections.Generic.List in @() throws "Argument types do not match" in this
# environment -- on BOTH powershell.exe and pwsh 7, and even for a list of plain strings. An
# ArrayList is unaffected. Nothing else in this solution hits it because the other List users pipe
# through Sort-Object/Where-Object and therefore wrap a PIPELINE result, not the list object.
$trapHit = $false
try { $l = New-Object System.Collections.Generic.List[object]; $l.Add('x'); $null = @($l) } catch { $trapHit = $true }
if ($trapHit) {
    # The old .{0,2000} window cleared this 1907-character body by just 93 characters: about five
    # more lines and the -notmatch would have passed VACUOUSLY -- green while the @($list) it
    # forbids sat just outside the window. That is the shape of defect this scoping removes.
    $bRd = Get-PimSourceFunctionBody -Text $sql -Name 'Get-PimSqlAuditEvents'
    T 'the reader does NOT wrap its List in @()' ($bRd -notmatch 'return @\(\$out\)')
    T '   ...it uses .ToArray() instead'          ($bRd -match 'return \$out\.ToArray\(\)')
} else {
    # If a future host stops throwing, say so rather than silently passing a check that no longer
    # tests anything -- a guard that cannot fail is not a guard.
    T 'the @(List) trap no longer reproduces on this host (assertion now vacuous -- review it)' $true
}

Write-Host "`n RESULT: $pass pass, $fail fail" -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $(if ($fail) { 1 } else { 0 })
