#Requires -Version 5.1
<#
.SYNOPSIS
    §36.3 phase 1b -- ONE-SHOT import of the retired filesystem audit trail
    (output/audit/pim-audit-<yyyyMM>.jsonl) into pim.AuditEvents, then archive the files.

.DESCRIPTION
    SEC-16 moved the Manager's audit trail into SQL. Phase 1b finishes the job by taking the
    filesystem path out of service: the hosted Manager no longer WRITES it, no longer READS it,
    and no longer counts its months (Open-PimManager.ps1). The file path now survives ONLY as
    the local/dev store, for an instance that has no SQL at all.

    That leaves one honest gap, and this script is it: a LOCAL instance that later gains a SQL
    store would otherwise see its existing trail disappear from the Audit tab -- not because the
    events were deleted, but because the reader is SQL-first by design and deliberately refuses
    to merge the two (showing a partial trail as if it were complete is the failure this whole
    chapter is about). Importing the files is the only way to keep that history visible.

    What it does, per month file:
      1. Parses each JSON line. A malformed line is COUNTED and skipped, never fatal -- the same
         rule the file reader has always used; one bad line must not strand the rest of a month.
      2. Inserts it with its ORIGINAL timestamp (Write-PimSqlAuditEvent -Ts). Without that the
         whole imported history would carry the minute the import ran, which destroys the
         ordering that makes an audit trail evidence rather than a list.
      3. Renames the file to <name>.imported-<yyyyMMdd-HHmmss> once the whole file is in.

    Step 3 IS the idempotency. pim.AuditEvents is append-only by intent -- there is no update or
    delete helper, and adding one to de-duplicate a re-run would hand everyone a DELETE the trail
    is supposed not to have. Archiving the source file instead means a second run has nothing
    left to import. -KeepFiles opts out of that protection: running twice with it then DOUBLES
    the imported events, and the only way back is a manual DELETE against the table.

    It parses the jsonl directly rather than going through Read-PimAuditEvents. That reader
    shapes events for DISPLAY -- it normalises ts to a culture-invariant STRING and stamps
    `category`/`change`, none of which are columns. The store needs a [datetime] and the raw
    fields, so the display shaping would only have to be undone again.

.PARAMETER AuditDir
    The directory holding pim-audit-<yyyyMM>.jsonl. Defaults to the solution's output/audit.

.PARAMETER ConnectionString
    Target store. Defaults to whatever Get-PimSqlConnectionString resolves (the same resolution
    the Manager itself uses -- never a connection string read from a config file).

.PARAMETER KeepFiles
    Leave the source files in place after importing. See the note above before using it.

.EXAMPLE
    # Dry run first -- reports what WOULD be imported, touching neither store.
    .\Import-PimAuditFileTrail.ps1 -WhatIf

.EXAMPLE
    .\Import-PimAuditFileTrail.ps1
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $AuditDir,
    [string] $ConnectionString,
    [switch] $KeepFiles
)

$ErrorActionPreference = 'Stop'

$solutionRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $AuditDir) { $AuditDir = Join-Path $solutionRoot 'output\audit' }

if (-not (Test-Path -LiteralPath $AuditDir)) {
    Write-Host "No audit directory at '$AuditDir' -- nothing to import." -ForegroundColor Yellow
    return
}

# Resolve the store the SAME way the Manager does. A connection string is never read from a
# file here either (SEC-03 / Get-PimSqlConnectionString's own contract).
$sqlLib = Join-Path $solutionRoot 'engine\_shared\PIM-SqlStore.ps1'
if (-not (Test-Path -LiteralPath $sqlLib)) { throw "PIM-SqlStore.ps1 not found at '$sqlLib'." }
. $sqlLib
if (-not $ConnectionString) {
    try { $ConnectionString = Get-PimSqlConnectionString } catch { $ConnectionString = $null }
}
if (-not $ConnectionString) {
    throw ("No SQL store resolved, so there is nowhere to import TO. Set the same connection the " +
           "Manager uses (PIM_SqlConnectionString / PIM_SqlServer + PIM_SqlDatabase, or the Key " +
           "Vault pointer), or pass -ConnectionString.")
}

$files = @(Get-ChildItem -LiteralPath $AuditDir -Filter 'pim-audit-*.jsonl' -File -ErrorAction SilentlyContinue |
           Sort-Object Name)   # oldest month first, so a partial run leaves the OLD end done
if (-not $files.Count) {
    Write-Host "No pim-audit-*.jsonl files in '$AuditDir' -- nothing to import." -ForegroundColor Yellow
    return
}

# The table is created by the COMMON initialiser (audit is a standard feature of every topology,
# not an MSP extra), and it is idempotent -- so make sure it exists before inserting, rather than
# failing on the first row of somebody's first import.
if ($PSCmdlet.ShouldProcess('the configured PIM store', 'ensure pim.AuditEvents exists')) {
    try { Initialize-PimSqlStore -ConnectionString $ConnectionString }
    catch { throw "Could not initialise the SQL store: $($_.Exception.Message)" }
}

# A dry run must not report events as "imported" -- this whole chapter is about not claiming
# something was recorded when it was not, and a summary line is exactly where that slips through.
$verb = if ($WhatIfPreference) { 'would be imported' } else { 'imported' }

$totalOk = 0; $totalBad = 0; $filesDone = 0
# 🪤 The CultureInfo is spelled out AT THE CALL SITE below, not hoisted into a variable here.
# Test-PimDateSafe's anti-regression sweep reads line by line and exempts a parse only if the
# SAME line names a CultureInfo -- an alias makes a correct call look like a bare ambient-culture
# parse and fails the suite. Which is the sweep behaving correctly: a reviewer reading one line
# cannot tell what `$inv` holds either. PIM-AuditQuery.ps1's own reader spells it out for the
# same reason.
$styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal

foreach ($f in $files) {
    Write-Host "`n-- $($f.Name)" -ForegroundColor Cyan
    $ok = 0; $bad = 0
    foreach ($line in @(Get-Content -LiteralPath $f.FullName -Encoding UTF8)) {
        if (-not "$line".Trim()) { continue }
        $evt = $null
        try { $evt = $line | ConvertFrom-Json } catch { $bad++; continue }
        if ($null -eq $evt) { $bad++; continue }

        # ts: the file may hold an ISO string OR (via an earlier ConvertFrom-Json round-trip) a
        # [datetime]. Parse invariantly and assume UTC -- the writer only ever wrote UtcNow('o').
        $ts = $null
        if ($evt.ts -is [datetime]) {
            $ts = ([datetime]$evt.ts).ToUniversalTime()
        } else {
            $parsed = [datetime]::MinValue
            if ([datetime]::TryParse("$($evt.ts)", [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) { $ts = $parsed }
        }
        if (-not $ts) { $bad++; continue }

        # Actor/Action/Target are NOT NULL. An event that lost one is still evidence that
        # something happened, so label the gap rather than dropping the row.
        $actor  = if ("$($evt.actor)".Trim())  { "$($evt.actor)".Trim() }  else { '(unrecorded)' }
        $action = if ("$($evt.action)".Trim()) { "$($evt.action)".Trim() } else { '(unrecorded)' }
        $target = if ("$($evt.target)".Trim()) { "$($evt.target)".Trim() } else { '(unrecorded)' }
        $result = if ("$($evt.result)".Trim()) { "$($evt.result)".Trim() } else { 'ok' }

        if ($PSCmdlet.ShouldProcess("$action on $target at $($ts.ToString('o'))", 'import audit event')) {
            Write-PimSqlAuditEvent -ConnectionString $ConnectionString -Ts $ts `
                -Actor $actor -ActorSource "$($evt.actorSource)" `
                -Action $action -Target $target `
                -Before $evt.before -After $evt.after -Result $result `
                -RunId "$($evt.runId)" -CorrelationId "$($evt.correlationId)" `
                -WhatIf ([bool]$evt.whatIf)
        }
        $ok++
    }
    $totalOk += $ok; $totalBad += $bad; $filesDone++
    Write-Host ("   {0} event(s) {1}, {2} unparseable line(s) skipped" -f $ok, $verb, $bad)

    if ($KeepFiles) {
        Write-Host "   -KeepFiles: source left in place. A SECOND run WILL re-import it." -ForegroundColor Yellow
    } else {
        $archived = "$($f.Name).imported-$([datetime]::UtcNow.ToString('yyyyMMdd-HHmmss'))"
        if ($PSCmdlet.ShouldProcess($f.FullName, "archive as $archived")) {
            Rename-Item -LiteralPath $f.FullName -NewName $archived
            Write-Host "   archived as $archived"
        }
    }
}

Write-Host ("`nRESULT: {0} file(s), {1} event(s) {2}, {3} line(s) skipped" -f $filesDone, $totalOk, $verb, $totalBad) -ForegroundColor Green
if ($totalBad) {
    Write-Host "Skipped lines were unparseable JSON or had no usable timestamp; they are still in the archived file." -ForegroundColor Yellow
}
