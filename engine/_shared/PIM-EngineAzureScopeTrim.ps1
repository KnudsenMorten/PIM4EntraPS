#Requires -Version 5.1
<#
.SYNOPSIS
    4.3 ENGINE UAA SCOPE TRIM (Invardia ruling 2026-11-08): the engine holds User Access Administrator ONLY at the top
    defined scopes. The ONE place a removal of the engine's UAA is planned and applied -- kept OUT of
    PIM-EngineAzureAccess.ps1, whose 95.2k converge never removes (tests C10). Load PIM-EngineAzureAccess.ps1 first.
    Run only as a recorded Support-app step (ops engine-uaa-scope.ps1), never by the updater. PS 5.1 + 7, REST seam, ASCII.
#>
Set-StrictMode -Off

function Get-PimEngineAzureScopeTrimPlan {
    <#
      PURE. 4.3 SCOPE TRIM (Invardia ruling 2026-11-08, owner "everything aligned today"): the engine holds User Access
      Administrator ONLY at the TOP defined scopes (a defined scope that no other defined scope covers). It is the ONE place
      a removal of the engine's UAA is planned -- the 95.2k converge above still never removes. Run as a recorded
      Support-app step (ops), never by the updater.
        tops    = the defined scopes no other defined scope covers; the tenant root when it is itself defined, or with
                  -IncludeRootUserAccessAdministrator (the install's SEC-34 opt-in) -- then the root alone.
        adds    = tops the engine does not hold UAA AT (exactly; an inherited grant is what the trim takes away)
        removes = the engine's UAA assignments at any scope that is not a top (above, outside or below)
        owner   = Owner assignments of the engine: listed, NEVER touched (a person gave them)
      No defined scope at all -> no top, every UAA of the engine is a remove (the engine touches only what is defined).
      -AllAssignments: every role assignment of the engine in the tenant (Read-PimEngineAzureAllAssignments); $null =
      unreadable -> nothing planned (state 'unknown').
    #>
    param([object[]]$Scopes = @(), [AllowNull()][object[]]$AllAssignments, [string]$TenantId = '', [switch]$IncludeRootUserAccessAdministrator)
    if ($null -eq $AllAssignments) { return [pscustomobject]@{ state = 'unknown'; tops = @(); adds = @(); removes = @(); owner = @(); summary = 'the engine''s role assignments could not be read -- nothing planned' } }
    $rootScope = if ("$TenantId".Trim()) { "/providers/Microsoft.Management/managementGroups/$("$TenantId".Trim())" } else { '' }
    $def = @($Scopes | Where-Object { $_ } | ForEach-Object { if ($_ -is [string]) { "$_".Trim().TrimEnd('/') } else { "$($_.scope)".Trim().TrimEnd('/') } } | Where-Object { $_ })
    $rootDefined = [bool]($rootScope -and @($def | Where-Object { $_ -ieq $rootScope }).Count)
    $tops = if ($rootScope -and ($rootDefined -or ($IncludeRootUserAccessAdministrator -and $def.Count))) { @($rootScope) } else {
        @($def | Where-Object { $c = $_; -not @($def | Where-Object { $_ -ine $c -and (Test-PimEngineAzurePathCovers -Parent $_ -Child $c -TenantId $TenantId) }).Count } | Sort-Object -Unique)
    }
    $facts = @($AllAssignments | Where-Object { $_ } | ForEach-Object { Get-PimEaaAssignmentFacts -Assignment $_ })
    $uaa = @($facts | Where-Object { $_.roleGuid -eq $script:PimEaaUaaGuid })
    $adds = @($tops | Where-Object { $t = $_; -not @($uaa | Where-Object { $_.scope.TrimEnd('/') -ieq $t }).Count })
    $removes = @($uaa | Where-Object { $s = $_.scope.TrimEnd('/'); -not @($tops | Where-Object { $_ -ieq $s }).Count } | ForEach-Object { [pscustomobject]@{ scope = $_.scope; id = $_.id } })
    $owner = @($facts | Where-Object { $_.roleGuid -eq $script:PimEaaOwnerGuid } | ForEach-Object { [pscustomobject]@{ scope = $_.scope; id = $_.id } })
    $summary = "UAA at $($tops.Count) top defined scope(s): $($adds.Count) to grant, $($removes.Count) to remove (above / outside / below), $($uaa.Count - $removes.Count) kept$(if ($owner.Count) { "; $($owner.Count) Owner assignment(s) listed, never touched" })"
    [pscustomobject]@{ state = $(if ($adds.Count -or $removes.Count) { 'trim' } else { 'ok' }); tops = @($tops); adds = $adds; removes = $removes; owner = $owner; summary = $summary }
}

function Invoke-PimEngineAzureScopeTrim {
    <#
      APPLY of Get-PimEngineAzureScopeTrimPlan (a recorded Support-app step). Order: every ADD first, each read back; only
      when ALL adds read back are the removes sent (never a gap in coverage), each read back as gone. -Apply:$false = plan
      only. A failure stops before any further write. Returns @{ ok; steps = @(@{ step; what; readBack; undo }); error }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][object]$Plan, [Parameter(Mandatory)][string]$EngineObjectId,
          [bool]$Apply = $false, [int]$ReadBackAttempts = 6, [int]$ReadBackDelaySeconds = 5, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $steps = New-Object System.Collections.Generic.List[object]
    $st = { param($s, $w, $rb, $u) $steps.Add([pscustomobject]@{ step = $s; what = $w; readBack = $rb; undo = $u }) }
    if ("$($Plan.state)" -ne 'trim') { return [pscustomobject]@{ ok = ("$($Plan.state)" -eq 'ok'); steps = @(); error = $(if ("$($Plan.state)" -eq 'unknown') { $Plan.summary } else { '' }) } }
    try {
        foreach ($sc in @($Plan.adds)) {
            $rq = New-PimEngineAzureAssignmentRequest -Scope $sc -EngineObjectId $EngineObjectId -Name ([guid]::NewGuid().ToString())
            if (-not $Apply) { & $st 'add' "would grant User Access Administrator at $sc" '' ''; continue }
            [void](& $Arm $rq.Method $rq.Path $rq.Body)
            $ok = $false
            for ($i = 1; $i -le [Math]::Max(1, $ReadBackAttempts); $i++) {
                if ($i -gt 1) { & $Sleep $ReadBackDelaySeconds }
                $b = $null; try { $b = & $Arm 'GET' $rq.Path $null } catch { $b = $null }
                if ($b -and "$((Get-PimEaaAssignmentFacts -Assignment $b).principalId)" -ieq "$EngineObjectId".Trim()) { $ok = $true; break }
            }
            if (-not $ok) { throw "User Access Administrator at $sc was sent but does not read back -- nothing removed" }
            & $st 'add' "granted User Access Administrator at $sc" 'read back' "Invoke-PimArm -Method DELETE -Path '$($rq.Path)'"
        }
        foreach ($r in @($Plan.removes)) {
            $p = "$("$($r.id)".Trim())?api-version=$($script:PimEaaApi)"
            if (-not $Apply) { & $st 'remove' "would remove User Access Administrator at $($r.scope)" '' ''; continue }
            [void](& $Arm 'DELETE' $p $null)
            $gone = $false
            for ($i = 1; $i -le [Math]::Max(1, $ReadBackAttempts); $i++) {
                if ($i -gt 1) { & $Sleep $ReadBackDelaySeconds }
                $b = $null; try { $b = & $Arm 'GET' $p $null } catch { if ("$($_.Exception.Message)" -match '(?i)\b404\b|NotFound|does not exist') { $b = $null } else { throw } }
                if (-not $b) { $gone = $true; break }
            }
            if (-not $gone) { throw "User Access Administrator at $($r.scope) was deleted but still reads back" }
            & $st 'remove' "removed User Access Administrator at $($r.scope)" 'read back: gone' "Invoke-PimArm -Method PUT -Path '$p' -Body @{ properties = @{ roleDefinitionId = '$(if ("$($r.scope)" -match '^(?i)/subscriptions/([0-9a-fA-F-]{36})') { "/subscriptions/$($Matches[1])" })/providers/Microsoft.Authorization/roleDefinitions/$($script:PimEaaUaaGuid)'; principalId = '$EngineObjectId'; principalType = 'ServicePrincipal' } }"
        }
        return [pscustomobject]@{ ok = $true; steps = @($steps.ToArray()); error = '' }
    } catch {
        return [pscustomobject]@{ ok = $false; steps = @($steps.ToArray()); error = "$($_.Exception.Message)" }
    }
}
