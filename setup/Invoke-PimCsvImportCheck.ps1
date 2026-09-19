#Requires -Version 5.1
<#
.SYNOPSIS
    Validate a folder of v1 PIM CSV definition files BEFORE anything is imported (REQ-G).
    PURE and OFFLINE: no SQL, no network. Reads the files; writes nothing.

.DESCRIPTION
    Runs engine/_shared/PIM-CsvImportCheck.ps1 (Invoke-PimCsvImportCheck) over -Path and reports:
      * every finding -- file, row, line, column, code, severity (error / warning / info), message;
      * a summary per file (rows, errors, warnings) and an overall verdict;
      * the replication report: the effective Replicate of every replicable row and what an MSP master
        would publish to its managed tenants, with and without -ForceLocal, and the exact values
        -ForceLocal would set.
    The row-level rules are the Manager's own validator (tools/pim-manager/_validator.ps1), called --
    not copied. setup/Migrate-PimToSql.ps1 runs the same check before it writes anything.

    Exit code: 0 when there are no errors (warnings and infos are allowed), 1 otherwise.

.PARAMETER Path
    The folder holding the v1 CSV files (e.g. PIM-Definitions-Roles.csv, Account-Definitions-Admins.csv).
    *_Delta.csv / *_LastApplied.csv (the engine's state files) are skipped and reported.

.PARAMETER ForceLocal
    Check the rows as -ForceLocal would import them: Replicate=No on every replicable row, and
    ManagementMode=local on every admin, unless the file sets the value explicitly. Without it, the
    report still lists what -ForceLocal would change.

.PARAMETER NotMspMaster
    The target is a single or managed tenant, not an MSP master (replication fields mean nothing there).

.PARAMETER DefaultDomain
    The target's default UPN domain, so admin rows without a UserPrincipalName resolve as the engine does.

.PARAMETER AsJson
    Emit ONE machine-readable JSON object on stdout (nothing else): verdict, counts, files, findings,
    replication.

.PARAMETER ShowAll
    List every warning and info (the default lists 5 examples per code).

.EXAMPLE
    .\Invoke-PimCsvImportCheck.ps1 -Path C:\tmp\efif\pimv1-definitions
.EXAMPLE
    .\Invoke-PimCsvImportCheck.ps1 -Path C:\tmp\efif\pimv1-definitions -ForceLocal -AsJson > check.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$ForceLocal,
    [switch]$NotMspMaster,
    [string]$DefaultDomain,
    [switch]$AsJson,
    [switch]$ShowAll
)
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'engine\_shared\PIM-CsvImportCheck.ps1')

$result = Invoke-PimCsvImportCheck -Path $Path -ForceLocal:$ForceLocal -NotMspMaster:$NotMspMaster -DefaultDomain $DefaultDomain
if ($AsJson) {
    ConvertTo-Json -InputObject (ConvertTo-PimCsvImportReportObject -Result $result) -Depth 10
} else {
    Write-PimCsvImportReport -Result $result -ShowAll:$ShowAll
}
exit $(if ($result.errors -gt 0) { 1 } else { 0 })
