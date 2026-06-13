#Requires -Version 5.1
<#
.SYNOPSIS
    Offline tests for the locked-schema + data conformance preflight
    (engine/_shared/PIM-SchemaConformance.ps1): plan, row repair incl. the
    TierLevel->Purpose data migration + column drop, idempotency, SQL DDL
    generation, and the CSV preflight against a temp dir. No DB, no tenant.

        powershell -NoProfile -File .\tests\Test-PimSchemaConformance.ps1
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $root 'engine\_shared\PIM-Functions.psm1') -Force -DisableNameChecking *> $null

$fail = New-Object System.Collections.Generic.List[string]; $pass = 0
function A($cond, $name) { if ($cond) { $script:pass++; Write-Host "  [PASS] $name" -ForegroundColor Green } else { $script:fail.Add($name); Write-Host "  [FAIL] $name" -ForegroundColor Red } }

$schema = Get-PimLockedSchema
$admSpec = $schema['Account-Definitions-Admins']

Write-Host "P: plan" -ForegroundColor Cyan
$plan = Get-PimSchemaConformancePlan -ActualColumns @('UserName','DisplayName','TierLevel') -Spec $admSpec
A ($plan.ToDrop -contains 'TierLevel') 'plan drops deprecated TierLevel'
A ($plan.ToAdd -contains 'Purpose') 'plan adds missing required Purpose'
A (-not $plan.Conformant) 'plan reports not conformant'
$plan2 = Get-PimSchemaConformancePlan -ActualColumns @('UserName','DisplayName','Purpose','ProvisionDate','TAPLifetimeHours','Template','OffboardDate','DeleteAfterDays') -Spec $admSpec
A ($plan2.Conformant) 'already-locked columns -> conformant'

Write-Host "R: row repair + TierLevel->Purpose migration + drop" -ForegroundColor Cyan
$rows = @(
    [pscustomobject]@{ UserName='Admin-AA-L0-T0-ID'; DisplayName='AA'; Purpose='';         TierLevel='Tier0' }
    [pscustomobject]@{ UserName='Admin-BB-ID';       DisplayName='BB'; Purpose='';         TierLevel='Tier2' }
    [pscustomobject]@{ UserName='Admin-CC-ID';       DisplayName='CC'; Purpose='HighPriv'; TierLevel='Tier2' }
)
$res = Repair-PimRowsToSchema -Rows $rows -Spec $admSpec
A ($res.columns -notcontains 'TierLevel') 'repaired columns have no TierLevel'
A ($res.columns -contains 'Purpose') 'repaired columns include Purpose'
A ($res.rows[0].Purpose -eq 'HighPriv') 'Tier0 + blank Purpose -> HighPriv'
A ($res.rows[1].Purpose -eq 'Day2Day') 'Tier2 + blank Purpose -> Day2Day'
A ($res.rows[2].Purpose -eq 'HighPriv') 'explicit Purpose preserved (blank-guard, not clobbered)'
A (-not ($res.rows[0].PSObject.Properties.Name -contains 'TierLevel')) 'TierLevel column physically removed from rows'
A ($res.rows[0].PSObject.Properties.Name -contains 'DeleteAfterDays') 'missing required column added (blank)'

Write-Host "I: idempotent" -ForegroundColor Cyan
$res2 = Repair-PimRowsToSchema -Rows $res.rows -Spec $admSpec
A (-not $res2.changed) 're-running repair on conformed rows -> no change'

Write-Host "G: generic base drops TierLevel, no migration" -ForegroundColor Cyan
$grows = @([pscustomobject]@{ GroupTag='X'; RoleDefinitionName='Reader'; TierLevel='Tier0' })
$gres = Repair-PimRowsToSchema -Rows $grows -Spec $schema['PIM-Assignments-Roles-Groups']
A ($gres.columns -notcontains 'TierLevel') 'generic base drops TierLevel'
A (-not ($gres.rows[0].PSObject.Properties.Name -contains 'Purpose')) 'generic base does NOT invent a Purpose column'

Write-Host "S: SQL DDL generation (idempotent, guarded)" -ForegroundColor Cyan
$sql = New-PimSqlConformanceDdl -Table 'pim.LocalAdmins' -Spec (Get-PimLockedSqlSchema)['pim.LocalAdmins'] -ActualColumns @('UserName','DisplayName','Purpose','TierLevel')
A ($sql.ddl -match "DROP COLUMN \[TierLevel\]") 'DDL drops the TierLevel column'
A ($sql.ddl -match "COL_LENGTH\('pim.LocalAdmins','TierLevel'\) IS NOT NULL") 'DROP is guarded (idempotent)'
A ($sql.ddl -match "UPDATE .*SET \[Purpose\] = CASE") 'DDL migrates TierLevel->Purpose before drop'
A ($sql.ddl -match "DROP CONSTRAINT") 'DDL drops bound default constraint before the column'
$sqlClean = New-PimSqlConformanceDdl -Table 'pim.LocalAdmins' -Spec (Get-PimLockedSqlSchema)['pim.LocalAdmins'] -ActualColumns @('UserName','DisplayName','Purpose')
A ($sqlClean.plan.Conformant) 'store without TierLevel -> conformant (DDL is a no-op body)'

Write-Host "F: CSV preflight against a temp dir" -ForegroundColor Cyan
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pimsc-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $csv = Join-Path $tmp 'Account-Definitions-Admins.custom.csv'
    Set-Content -LiteralPath $csv -Encoding UTF8 -Value @(
        'UserName;DisplayName;Purpose;TierLevel'
        'Admin-AA-L0-T0-ID;AA;;Tier0'
        'Admin-BB-ID;BB;;Tier2'
    )
    $rep = Invoke-PimSchemaConformancePreflight -ConfigDir $tmp
    $r = @($rep | Where-Object base -eq 'Account-Definitions-Admins')[0]
    A ($r.changed -and $r.applied) 'preflight reports + applies the change'
    A ($r.dropped -contains 'TierLevel') 'preflight dropped TierLevel'
    $after = @(Import-Csv -Path $csv -Delimiter ';' -Encoding UTF8)
    A (-not ($after[0].PSObject.Properties.Name -contains 'TierLevel')) 'rewritten CSV has no TierLevel column'
    A ($after[0].Purpose -eq 'HighPriv' -and $after[1].Purpose -eq 'Day2Day') 'rewritten CSV data migrated to Purpose'
    $rep2 = Invoke-PimSchemaConformancePreflight -ConfigDir $tmp
    A (-not (@($rep2 | Where-Object base -eq 'Account-Definitions-Admins')[0].changed)) 'second preflight is a no-op (idempotent)'
} finally { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue }

Write-Host ('=' * 70)
if ($fail.Count -eq 0) { Write-Host ("ALL {0} ASSERTIONS PASSED." -f $pass) -ForegroundColor Green; exit 0 }
else { Write-Host ("{0} passed, {1} FAILED:" -f $pass, $fail.Count) -ForegroundColor Red; $fail | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }; exit 1 }
