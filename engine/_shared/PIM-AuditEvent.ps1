# PIM4EntraPS -- the ENGINE's audit writer (Write-PimAuditEvent), module-free.
#
# REQ 100.42 (owner 2026-10-09: no PowerShell modules; "we dont use that legacy code"): this function lived in the v1-era
# library engine/_shared/PIM-Functions.psm1, which is deleted. It is the one function from that file that v2 code CALLS
# (32 guarded call sites: EngineCore, EngineProviders, ApprovalGate, DisableGuard, Guard, License, Discovery, RfaSync,
# InvardiaEnrollment, ...), so it moved here verbatim -- except: the run id is a process-wide global (it was a module-load
# $script: id) and the AzLogDcrIngestPS module push is gone (the Send-PimLaAuditRecord hook stays).
# ! BUG fixed with this move (owner 2026-10-09): the module was never loaded by a v2 entry point, so every guarded engine
# audit call was a silent no-op. tools\pim-engine\Invoke-PimEngineCore.ps1 and tools\pim-scheduler\Start-PimScheduler.ps1
# now dot-source this file right after PIM-SqlStore.ps1 (tests\Test-PimEngineAudit.ps1 holds both to it). The Manager
# keeps its own writer (Write-PimManagerAuditEvent, actor = the signed-in principal).
#
# Unified audit (LIFECYCLE-GOVERNANCE phase 6): every engine transaction emits one row to SQL pim.AuditEvents -- the SAME
# table the Manager writes (actor manager:<user>). PIM v2 is SQL-only: no output/audit/*.jsonl trail (2026-09-13). Audit
# writes are best-effort by design -- a logging failure must never break provisioning -- but an unrecorded event is
# reported, never hidden. Needs PIM-SqlStore.ps1 (Get-PimSqlConnectionString / Write-PimSqlAuditEvent). PS 5.1 + 7.
Set-StrictMode -Off
function Write-PimAuditEvent {
    param(
        [Parameter(Mandatory)][string]$Action,   # e.g. account.create | tap.create | policy.apply | mail.send
        [Parameter(Mandatory)][string]$Target,
        [object]$Before = $null,
        [object]$After = $null,
        [string]$Result = 'ok',
        [string]$Actor = 'engine',
        [string]$CorrelationId = ''
    )
    # AUDIT-1 (2026-10-05): an event written inside a scheduled job run carries that run -- account.create / tap.create
    # had neither a run id nor a correlation id, so they could not be joined to the job (or the commit) that made them.
    if (-not "$CorrelationId".Trim() -and "$($global:PIM_JobCorrelationId)".Trim()) { $CorrelationId = "$($global:PIM_JobCorrelationId)" }
    # The JOB run when there is one: the process-wide run id is set once per PROCESS, so in the long-lived tick every run
    # shared one id.
    if (-not "$($global:PIM_AuditRunId)".Trim()) { $global:PIM_AuditRunId = [guid]::NewGuid().ToString('N') }   # one id per process (the module-load id it replaced)
    $runIdEff = if ("$($global:PIM_JobCorrelationId)".Trim()) { "$($global:PIM_JobCorrelationId)" } else { "$($global:PIM_AuditRunId)" }
    try {
        $evt = [ordered]@{
            ts            = [datetime]::UtcNow.ToString('o')
            runId         = $runIdEff
            correlationId = $CorrelationId
            actor         = $Actor
            action        = $Action
            target        = $Target
            before        = $Before
            after         = $After
            result        = $Result
            whatIf        = [bool]$global:WhatIfMode
        }

        # SEC-16 (REQ 36.2) -- the ENGINE half. Unlike the Manager's writer this one was not
        # LOSING data (it runs under VisualCron / the tick, where the filesystem persists) and it
        # already names a real actor. The defect it shares is different and just as awkward:
        # IT WAS A SECOND TRAIL IN A SECOND PLACE. The Manager wrote one audit file and the
        # engine wrote another, so "who granted this access?" could not be answered without first
        # knowing WHICH COMPONENT did it -- and the two were never merged anywhere. One question,
        # two half-answers, is not an audit trail.
        # Both now append to the SAME pim.AuditEvents table -- and ONLY there (SQL-only, 2026-09-13).
        $sqlOk = $false
        $sqlErr = ''
        try {
            if (Get-Command Write-PimSqlAuditEvent -ErrorAction SilentlyContinue) {
                # The engine's resolved store first (the same order Write-PimEngineChangeAudit used when this writer was
                # absent): the run's connection string, then the configured one, then a fresh resolve.
                $cs = $null
                if ("$($global:PIM_EngineSqlCs)".Trim()) { $cs = "$($global:PIM_EngineSqlCs)" }
                elseif ("$($global:PIM_SqlConnectionString)".Trim()) { $cs = "$($global:PIM_SqlConnectionString)" }
                elseif (Get-Command Get-PimSqlConnectionString -ErrorAction SilentlyContinue) { try { $cs = Get-PimSqlConnectionString } catch { $cs = $null } }
                if ($cs) {
                    Write-PimSqlAuditEvent -ConnectionString $cs -Actor $Actor -ActorSource 'engine' `
                        -Action $Action -Target $Target -Before $Before -After $After `
                        -Result $Result -WhatIf ([bool]$global:WhatIfMode) `
                        -RunId $runIdEff -CorrelationId $CorrelationId
                    $sqlOk = $true
                }
            }
        } catch { $sqlErr = "$($_.Exception.Message)" }
        if (-not $sqlOk) {
            # Never fail an engine APPLY because the audit sink is down -- but do not hide it. There
            # is no file trail to fall back to (SQL-only), so the event is NOT recorded: say exactly that.
            Write-Warning ("  [audit] AUDIT NOT RECORDED for '{0}' on '{1}' -- {2}" -f $Action, $Target,
                $(if ($sqlErr) { "the SQL sink failed: $sqlErr" } else { 'no SQL store is configured (PIM v2 keeps the audit trail in SQL only)' }))
        }

        # Optional Log Analytics sink (REQUIREMENTS REQ 13/REQ 23 "Audit to Log Analytics").
        # OFF by default; opt in by setting $global:PIM_AuditLogAnalytics with the DCR
        # ingestion target. SQL pim.AuditEvents is the source of truth; the LA push is
        # best-effort and never blocks the engine.
        if ($global:PIM_AuditLogAnalytics -and (Get-Command ConvertTo-PimLaAuditRecord -ErrorAction SilentlyContinue)) {
            try {
                $la = $global:PIM_AuditLogAnalytics
                $rec = ConvertTo-PimLaAuditRecord -Event $evt
                if (Get-Command Send-PimLaAuditRecord -ErrorAction SilentlyContinue) {
                    # Custom hook (lets a host inject its own transport / batching).
                    Send-PimLaAuditRecord -Record $rec -Config $la
                }
            } catch {
                Write-Warning "audit Log Analytics push failed (engine NOT blocked; SQL audit unaffected): $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Warning "audit write failed (engine NOT blocked): $($_.Exception.Message)"
    }
}
