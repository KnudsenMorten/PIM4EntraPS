<#
  AUDIT-1.3 (framework DOCS/REQUIREMENTS.md, operator 2026-10-04: "an audit trail in si and invardia, similar to in pim"):
  the audit trail is APPEND-ONLY, and rows leave only through a documented retention job that is itself audited.

  * Append-only is enforced IN THE DATABASE, not by convention: an INSTEAD OF UPDATE, DELETE trigger on pim.AuditEvents.
      - UPDATE is refused for every identity, always.
      - DELETE is refused unless the session carries the retention marker (SESSION_CONTEXT 'pim_audit_retention_months',
        at least 13) AND every row it touches is older than that many months. Only Invoke-PimAuditRetentionJob sets it.
    Why a trigger and not "DENY UPDATE, DELETE": the runtime identities hold db_datareader + db_datawriter + db_ddladmin
    (Initialize-PimTenantStore.ps1, IMP-49) and cannot GRANT or DENY; ddladmin CAN create the trigger, so the runtime
    store initialisation applies it on every environment at its next start, with no setup re-run.
    Honest limit: a principal with schema rights (ddladmin) can still DROP the trigger or TRUNCATE the table -- a trigger
    does not fire on TRUNCATE. It closes every UPDATE / DELETE path in the product and in ordinary DML, not a determined
    schema owner.
  * Retention: pim.Settings 'AuditRetentionMonths'. Empty / 0 = keep every row forever (the default, what PIM always did).
    A value from 13 up = the 'audit-retention' job deletes rows older than that, at most 50,000 per run, and records
    'audit.retention' (cutoff, deleted, remaining) in the trail it just pruned. 1..12 is refused (the contract minimum).
#>

$script:PimAuditRetentionMinMonths = 13
$script:PimAuditRetentionBatch = 50000

function Get-PimAuditAppendOnlyTriggerSql {
    # CREATE OR ALTER keeps it idempotent; it must be the only statement in its batch.
    @"
CREATE OR ALTER TRIGGER pim.TR_AuditEvents_AppendOnly ON pim.AuditEvents
INSTEAD OF UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    IF EXISTS (SELECT 1 FROM inserted)
        THROW 51000, 'pim.AuditEvents is append-only: an audit row is never updated (AUDIT-1.3).', 1;
    DECLARE @months INT = TRY_CONVERT(INT, SESSION_CONTEXT(N'pim_audit_retention_months'));
    IF @months IS NULL OR @months < $($script:PimAuditRetentionMinMonths)
        THROW 51001, 'pim.AuditEvents is append-only: rows leave only through the audit retention job (AUDIT-1.3).', 1;
    IF EXISTS (SELECT 1 FROM deleted WHERE Ts >= DATEADD(MONTH, -@months, SYSUTCDATETIME()))
        THROW 51002, 'the audit retention job may delete only rows older than the retention period (AUDIT-1.3).', 1;
    DELETE a FROM pim.AuditEvents a INNER JOIN deleted d ON d.Id = a.Id;
END
"@
}

function Initialize-PimAuditAppendOnly {
    <# Applies the append-only trigger. Never throws (a store must still open); the result says whether it is in place. #>
    param([Parameter(Mandatory)][string]$ConnectionString, [scriptblock]$Exec = $null)
    try {
        if ($Exec) { & $Exec (Get-PimAuditAppendOnlyTriggerSql) } else { [void](Invoke-PimSqlNonQuery -ConnectionString $ConnectionString -Sql (Get-PimAuditAppendOnlyTriggerSql)) }
        return [pscustomobject]@{ ok = $true; detail = 'append-only trigger in place' }
    } catch {
        $m = "$($_.Exception.Message)"
        Write-Warning "[audit] the append-only guard on pim.AuditEvents could not be applied: $m"
        return [pscustomobject]@{ ok = $false; detail = "append-only trigger NOT applied: $m" }
    }
}

function ConvertTo-PimAuditRetentionMonths {
    <# '' / $null / 0 -> 0 (keep forever). 13..1200 -> that. Anything else -> throws with the reason. #>
    param([object]$Value)
    $s = "$Value".Trim().Trim('"')
    if (-not $s -or $s -eq '0') { return 0 }
    $n = 0
    if (-not [int]::TryParse($s, [ref]$n)) { throw "audit retention must be a whole number of months, or 0 to keep every row (got '$s')" }
    if ($n -lt 0 -or $n -gt 1200) { throw "audit retention must be 0 (keep every row) or $($script:PimAuditRetentionMinMonths) to 1200 months (got $n)" }
    if ($n -gt 0 -and $n -lt $script:PimAuditRetentionMinMonths) { throw "audit retention must be at least $($script:PimAuditRetentionMinMonths) months (AUDIT-1.3), or 0 to keep every row (got $n)" }
    return $n
}

function Get-PimAuditRetentionMonths {
    param([Parameter(Mandatory)][string]$ConnectionString)
    $raw = $null
    try { $raw = Get-PimSqlSetting -ConnectionString $ConnectionString -Name 'AuditRetentionMonths' } catch { $raw = $null }
    try { return (ConvertTo-PimAuditRetentionMonths $raw) } catch { Write-Warning "[audit-retention] stored setting ignored: $($_.Exception.Message)"; return 0 }
}

function Get-PimAuditRetentionSql {
    # ONE batch: SESSION_CONTEXT lives on the connection, and each Invoke-PimSqlQuery opens its own.
    @"
DECLARE @cut DATETIME2 = DATEADD(MONTH, -@m, SYSUTCDATETIME());
DECLARE @candidates BIGINT = (SELECT COUNT_BIG(*) FROM pim.AuditEvents WHERE Ts < @cut);
EXEC sp_set_session_context N'pim_audit_retention_months', @m;
DELETE TOP ($($script:PimAuditRetentionBatch)) FROM pim.AuditEvents WHERE Ts < @cut;
EXEC sp_set_session_context N'pim_audit_retention_months', NULL;
SELECT @candidates AS candidates, (SELECT COUNT_BIG(*) FROM pim.AuditEvents WHERE Ts < @cut) AS remaining, @cut AS cutoffUtc;
"@
}

function Invoke-PimAuditRetentionJob {
    <#
      The 'audit-retention' job. Keep-forever (the default) does nothing and says so. Otherwise it deletes the rows older
      than the retention period (at most 50,000 per run; the rest on the next run) and records audit.retention.
      -WhatIf counts what it would delete. A failed delete THROWS (the run fails; it is never reported as done).
    #>
    param([object]$Job = $null, [datetime]$NowUtc = [datetime]::UtcNow, [switch]$WhatIf, [string]$ConnectionString = '', [scriptblock]$Query = $null)
    $cs = $ConnectionString
    if (-not $cs -and (Get-Command Get-PimSqlSettingsConnectionString -ErrorAction SilentlyContinue)) { try { $cs = Get-PimSqlSettingsConnectionString } catch { $cs = '' } }
    if (-not $cs -and -not $Query) { throw '[audit-retention] no SQL store -- the audit trail cannot be read' }
    $months = if ($Query) { & $Query 'months' $null } else { Get-PimAuditRetentionMonths -ConnectionString $cs }
    if (-not $months) {
        return [pscustomobject]@{ ran = $true; deleted = 0; months = 0; whatIf = [bool]$WhatIf
            detail = 'audit retention: keep every row (AuditRetentionMonths not set) -- nothing deleted' }
    }
    if ($WhatIf) {
        $sql = 'SELECT COUNT_BIG(*) AS candidates, DATEADD(MONTH, -@m, SYSUTCDATETIME()) AS cutoffUtc FROM pim.AuditEvents WHERE Ts < DATEADD(MONTH, -@m, SYSUTCDATETIME());'
        $r = if ($Query) { & $Query 'count' $months } else { @(Invoke-PimSqlQuery -ConnectionString $cs -Sql $sql -Parameters @{ m = $months })[0] }
        return [pscustomobject]@{ ran = $true; deleted = 0; months = $months; whatIf = $true
            detail = ("audit retention (what-if): {0} row(s) older than {1} months would be deleted" -f [int64]$r.candidates, $months) }
    }
    $r = if ($Query) { & $Query 'delete' $months } else { @(Invoke-PimSqlQuery -ConnectionString $cs -Sql (Get-PimAuditRetentionSql) -Parameters @{ m = $months })[0] }
    $deleted = [int64]$r.candidates - [int64]$r.remaining
    $after = [ordered]@{ months = $months; cutoffUtc = "$($r.cutoffUtc)"; deleted = $deleted; remaining = [int64]$r.remaining }
    try {
        if ($Query) { [void](& $Query 'audit' $after) }
        else { Write-PimSqlAuditEvent -ConnectionString $cs -Actor 'audit-retention' -ActorSource 'scheduler' -Action 'audit.retention' -Target 'pim.AuditEvents' -After $after }
    } catch { Write-Warning "[audit-retention] the retention run could not be recorded in the trail: $($_.Exception.Message)" }
    [pscustomobject]@{ ran = $true; deleted = $deleted; remaining = [int64]$r.remaining; months = $months; whatIf = $false
        detail = ("audit retention: deleted {0} row(s) older than {1} months{2}" -f $deleted, $months, $(if ([int64]$r.remaining -gt 0) { " ($([int64]$r.remaining) left for the next run)" } else { '' })) }
}
