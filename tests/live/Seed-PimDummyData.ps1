<#
.SYNOPSIS
  Make the test/dummy dataset a persistent part of SQL so the engine can deploy it
  repeatedly. Group/AU names get a clear marker (PIMCOREENGINE-), every group inherits a
  dummy department's owners, and the GA group is flagged approval-required.

  Test cycle:
    .\Seed-PimDummyData.ps1                 # seed (idempotent) -- data persists in SQL
    .\Invoke-PimEngineCore.ps1 -Scope All   # engine deploys the dummy data (creates tenant objects)
    .\Seed-PimDummyData.ps1 -DeleteTenantObjects   # delete ONLY the created tenant objects (keep SQL)
    .\Invoke-PimEngineCore.ps1 -Scope All   # re-deploys from the persisted SQL data
    .\Seed-PimDummyData.ps1 -Revert         # full teardown: strip marker + remove dummy props/rows

  Owners must be REAL resolvable users (you can't own a group with a fake user); the
  DEPARTMENT names are dummy and removed by -Revert. Marker keeps prod-safe deletion.
#>
[CmdletBinding(DefaultParameterSetName = 'Seed')]
param(
    [Parameter(ParameterSetName = 'Seed')][switch]$Seed,
    [Parameter(ParameterSetName = 'DeleteTenantObjects')][switch]$DeleteTenantObjects,
    [Parameter(ParameterSetName = 'Revert')][switch]$Revert,
    [string]$Marker      = 'PIMCOREENGINE-',
    [Parameter(Mandatory)][string]$Owners,   # pipe-joined REAL owner UPN(s) resolvable in the target tenant
    [string]$SqlServer   = $env:PIM_SqlServer,
    [string]$SqlDatabase = $env:PIM_SqlDatabase
)
$ErrorActionPreference = 'Stop'
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$shared = Resolve-Path "$here\..\..\engine\_shared"
if (-not $SqlServer)   { throw "Set -SqlServer or `$env:PIM_SqlServer." }
if (-not $SqlDatabase) { throw "Set -SqlDatabase or `$env:PIM_SqlDatabase." }
$global:PIM_UseGraphSdk = $false; $global:PIM_SqlServer = $SqlServer; $global:PIM_SqlDatabase = $SqlDatabase
. "$shared\PIM-Rest.ps1"; . "$shared\PIM-SqlStore.ps1"
$cs = Get-PimSqlConnectionString
$grpEntities = @('PIM-Definitions-Roles', 'PIM-Definitions-Services', 'PIM-Definitions-Organization', 'PIM-Definitions-Tasks')
$nameField = @{ 'PIM-Definitions-AU' = 'AUDisplayName' }; foreach ($e in $grpEntities) { $nameField[$e] = 'GroupName' }

switch ($PSCmdlet.ParameterSetName) {
    'Seed' {
        foreach ($e in ($grpEntities + 'PIM-Definitions-AU')) {
            $f = $nameField[$e]
            $n = Invoke-PimSqlNonQuery -ConnectionString $cs -Sql "UPDATE pim.Rows SET DataJson=JSON_MODIFY(DataJson,'$.$f',@m+JSON_VALUE(DataJson,'$.$f')) WHERE Entity=@e AND JSON_VALUE(DataJson,'$.$f') IS NOT NULL AND JSON_VALUE(DataJson,'$.$f') NOT LIKE @ml" -Parameters @{ e = $e; m = $Marker; ml = "$Marker%" }
            Write-Host ("  marker {0,-30} +{1}" -f $e, $n)
        }
        Set-PimSqlRow -ConnectionString $cs -Entity 'PIM-Definitions-Departments' -Key 'IT'       -Data ([pscustomobject]@{ Department = 'IT';       Owners = $Owners; Mode = 'Serial' })
        Set-PimSqlRow -ConnectionString $cs -Entity 'PIM-Definitions-Departments' -Key 'Security'  -Data ([pscustomobject]@{ Department = 'Security'; Owners = $Owners; Mode = 'Serial' })
        foreach ($e in $grpEntities) { [void](Invoke-PimSqlNonQuery -ConnectionString $cs -Sql "UPDATE pim.Rows SET DataJson=JSON_MODIFY(DataJson,'$.Department','IT') WHERE Entity=@e" -Parameters @{ e = $e }) }
        [void](Invoke-PimSqlNonQuery -ConnectionString $cs -Sql "UPDATE pim.Rows SET DataJson=JSON_MODIFY(DataJson,'$.PolicyTemplate','approval-required') WHERE Entity='PIM-Definitions-Services' AND JSON_VALUE(DataJson,'$.GroupName') LIKE '%GlobalAdministrator%'")
        $mk = Invoke-PimSqlScalar -ConnectionString $cs -Sql "SELECT COUNT(*) FROM pim.Rows WHERE JSON_VALUE(DataJson,'$.GroupName') LIKE '$Marker%'"
        Write-Host "Seeded: $mk marked groups, dept IT/Security(owners), Department=IT on groups, GA approval-required." -ForegroundColor Green
    }
    'DeleteTenantObjects' {
        $h = @{ Authorization = "Bearer $((az account get-access-token --resource https://graph.microsoft.com -o json | ConvertFrom-Json).accessToken)" }
        $grps = @(); $u = "https://graph.microsoft.com/v1.0/groups?`$filter=startswith(displayName,'$Marker')&`$select=id&`$top=999"
        do { $r = Invoke-RestMethod -Headers $h -Uri $u; $grps += $r.value; $u = $r.'@odata.nextLink' } while ($u)
        $n = 0; foreach ($g in $grps) { try { Invoke-RestMethod -Method DELETE -Headers $h -Uri "https://graph.microsoft.com/v1.0/groups/$($g.id)" | Out-Null; $n++ } catch {} }
        $aus = @(Invoke-RestMethod -Headers $h -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits?`$select=id,displayName&`$top=999").value | Where-Object { $_.displayName -like "$Marker*" }
        $m = 0; foreach ($a in $aus) { try { Invoke-RestMethod -Method DELETE -Headers $h -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($a.id)" | Out-Null; $m++ } catch {} }
        Write-Host "Deleted tenant objects: groups=$n AUs=$m (SQL dummy data kept)." -ForegroundColor Green
    }
    'Revert' {
        foreach ($e in ($grpEntities + 'PIM-Definitions-AU')) {
            $f = $nameField[$e]
            [void](Invoke-PimSqlNonQuery -ConnectionString $cs -Sql "UPDATE pim.Rows SET DataJson=JSON_MODIFY(JSON_MODIFY(JSON_MODIFY(DataJson,'$.$f',STUFF(JSON_VALUE(DataJson,'$.$f'),1,LEN(@m),'')),'$.Department',NULL),'$.PolicyTemplate',NULL) WHERE Entity=@e AND JSON_VALUE(DataJson,'$.$f') LIKE @ml" -Parameters @{ e = $e; m = $Marker; ml = "$Marker%" })
        }
        $d = Invoke-PimSqlNonQuery -ConnectionString $cs -Sql "DELETE FROM pim.Rows WHERE Entity='PIM-Definitions-Departments'"
        Write-Host "Reverted: marker stripped, Department/PolicyTemplate cleared, dept rows removed=$d." -ForegroundColor Green
    }
}
